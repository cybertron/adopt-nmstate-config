#!/usr/bin/env python

# Copyright 2026 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Generate NodeNetworkConfigurationPolicy files for all of the machine-configs
# that contain NMState day one configurations.

# Usage: Set KUBECONFIG for access to the cluster, then run this script.
# It will collect all machine-configs containing NMState config and generate
# NNCPs from them.

# TODO:
# - Handle capture configs

import argparse
import base64
import ipaddress
import os
import subprocess
import tempfile
import textwrap
import urllib.parse
import yaml

import openshift_client as oc

base64_prefix = 'data:text/plain;charset=utf-8;base64,'
text_prefix = 'data:,'

nncp_template = lambda hostname, updated, selector: f'''apiVersion: nmstate.io/v1
kind: NodeNetworkConfigurationPolicy
metadata:
  name: {hostname}-br-ex
spec:
  nodeSelector:
    {selector}
{updated}
'''

def modify_plain(config, masqv4, masqv6):
    for interface in config['interfaces']:
        if interface['name'] == 'br-ex' and interface['type'] == 'ovs-interface':
            if interface['ipv4']['enabled']:
                if not 'address' in interface['ipv4']:
                    interface['ipv4']['address'] = []
                interface['ipv4']['address'].append(masqv4)
            if interface['ipv6']['enabled']:
                if not 'address' in interface['ipv6']:
                    interface['ipv6']['address'] = []
                interface['ipv6']['address'].append(masqv6)
    return {'desiredState': config}

def get_node_for_role(role):
    return oc.selector('nodes', labels={f'node-role.kubernetes.io/{role}': ''}).objects()[0]

# Deliberately not handling per-node capture configs because I don't think that use case makes sense
def modify_capture(mc, f, masqv4, masqv6):
    config = ''
    mctype = 'node'
    mctype = 'default'
    if f.path.endswith('cluster.yml'):
        mctype = 'cluster'
    if mctype == 'cluster':
        role = role_for_cluster(mc)
    elif mctype == 'default':
        role = role_for_default(mc)
    if role == 'machine-config-controller':
        return ''
    node = get_node_for_role(role)
    for a in node.model.status.addresses:
        if a['type'] == 'InternalIP':
            ip = a['address']
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(['scp', f'{ip}:/etc/nmstate/openshift/formatted', td])
        with open(os.path.join(td, 'formatted')) as f:
            config = yaml.safe_load(f)

    for interface in config['interfaces']:
        if interface['name'] == 'br-ex' and interface['type'] == 'ovs-interface':
            if interface['ipv4']['enabled']:
                if interface['ipv4']['dhcp'] or not 'address' in interface['ipv4']:
                    interface['ipv4']['address'] = []
                interface['ipv4']['address'].append(masqv4)
            if interface['ipv6']['enabled']:
                if interface['ipv6']['dhcp'] or not 'address' in interface['ipv6']:
                    interface['ipv6']['address'] = []
                interface['ipv6']['address'].append(masqv6)
    for route in config['routes']['config']:
        # This will be set to the node's IP, we need it to work on all nodes
        del route['source']

    return config

def modify_config(mc, f):
    capture = False
    if f.contents.source.startswith(base64_prefix):
        encoded = f.contents.source[len(base64_prefix):]
        decoded = base64.b64decode(encoded).decode('utf-8')
    else:
        encoded = f.contents.source[len(text_prefix):]
        decoded = urllib.parse.unquote(encoded)
    config = yaml.safe_load(decoded)
    if 'capture' in config:
        capture = True

    networks = oc.selector('networks.operator.openshift.io').object()

    cidrv4 = '169.254.0.0/17'
    if networks.model.spec.defaultNetwork.ovnKubernetesConfig.gatewayConfig.ipv4:
        cidrv4 = networks.model.spec.defaultNetwork.ovnKubernetesConfig.gatewayConfig.ipv4.internalMasqueradeSubnet
    netv4 = ipaddress.ip_network(cidrv4, strict=False)
    addrv4 = str(list(netv4.hosts())[1])
    maskv4 = netv4.prefixlen

    cidrv6 = 'fd69::/112'
    if networks.model.spec.defaultNetwork.ovnKubernetesConfig.gatewayConfig.ipv6:
        cidrv6 = networks.model.spec.defaultNetwork.ovnKubernetesConfig.gatewayConfig.ipv6.internalMasqueradeSubnet
    netv6 = ipaddress.ip_network(cidrv6, strict=False)
    addrv6 = str(list(netv6.hosts())[1])
    maskv6= netv6.prefixlen

    masqv4 = {'ip': addrv4, 'prefix-length': int(maskv4)}
    masqv6 = {'ip': addrv6, 'prefix-length': int(maskv6)}
    # When using nmpolicy we need very different processing
    if not capture:
        config = modify_plain(config, masqv4, masqv6)
    else:
        config = modify_capture(mc, f, masqv4, masqv6)
    return config

def is_fqdn(hostname):
    if hostname == 'cluster' or hostname == 'default':
        return False
    nodes = oc.selector('nodes').qnames()
    # Strip off the node/ prefix
    nodes = [n[5:] for n in nodes]
    if hostname in nodes:
        return False
    return True

def domain_name():
    return oc.selector('dns').object().model.spec.baseDomain

def role_for_cluster(mc):
    return mc.model.metadata.labels['machineconfiguration.openshift.io/role']

def role_for_default(mc):
    return mc.model.metadata.ownerReferences[0].name

def create_nncp(updated, path, mc, output_dir):
    hostname = os.path.splitext(os.path.basename(path))[0]
    # If the cluster is using FQDNs we need to reflect that in the node selector
    if is_fqdn(hostname):
        domain = domain_name()
        hostname = f'{hostname}.{domain}'
    selector = f'kubernetes.io/hostname: {hostname}'
    # The magic hostname of 'cluster' means to apply the config to every node in the role
    if hostname == 'cluster':
        role = role_for_cluster(mc)
        selector = f'node-role.kubernetes.io/{role}: ""'
        hostname = role
    # TODO: The 'default' name will change and this will need to be updated.
    if hostname == 'default':
        role = role_for_default(mc)
        print("Role", role)
        selector = f'node-role.kubernetes.io/{role}: ""'
        hostname = role
    # We don't want to process this mc.
    if hostname == 'machine-config-controller':
        return
    content = nncp_template(hostname, textwrap.indent(yaml.dump(updated), '  '), selector)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f'{hostname}.yaml')
        with open(output_path, 'w') as out:
            out.write(content)
        print(f'Wrote {output_path}')
    else:
        print(f'{hostname}.yml')
        print('-' * (len(hostname) + 5))
        print(content)

parser = argparse.ArgumentParser(
    description='Generate NodeNetworkConfigurationPolicy files from NMState machine-configs.')
parser.add_argument('-o', '--output-dir', metavar='DIR',
                    help='Directory to write output files to. If not specified, output is printed to stdout.')
args = parser.parse_args()

with oc.project('openshift-machine-config-operator'):
    for mc in oc.selector('machineconfigs').objects():
        #if mc.name().startswith('rendered'):
        #    continue
        print("MC Name")
        print(mc.name())
        for f in mc.model.spec.config.storage.files:
            if f.path.startswith('/etc/nmstate/openshift'):
                updated = modify_config(mc, f)
                create_nncp(updated, f.path, mc, args.output_dir)


