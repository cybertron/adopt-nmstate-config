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

# TODO:
# - Handle "default" capture config
# - Test if address append works with DHCP

import base64
import ipaddress
import os
import textwrap
import yaml

import openshift_client as oc

base64_prefix = 'data:text/plain;charset=utf-8;base64,'

nncp_template = lambda hostname, updated, selector: f'''apiVersion: nmstate.io/v1
kind: NodeNetworkConfigurationPolicy
metadata:
  name: {hostname}-br-ex
spec:
  nodeSelector:
    {selector}
  desiredState:
{updated}
'''

def modify_config(f):
    encoded = f.contents.source[len(base64_prefix):]
    decoded = base64.b64decode(encoded).decode('utf-8')
    config = yaml.safe_load(decoded)
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
    return config

def create_nncp(updated, path, mc):
    hostname = os.path.splitext(os.path.basename(path))[0]
    selector = f'kubernetes.io/hostname: {hostname}'
    # The magic hostname of 'cluster' means to apply the config to every node in the role
    if hostname == 'cluster':
        role = mc.model.metadata.labels['machineconfiguration.openshift.io/role']
        selector = f'node-role.kubernetes.io/{role}: ""'
        hostname = role
    print(f'{hostname}.yaml')
    print('-' * (len(hostname) + 5))
    print(nncp_template(hostname, textwrap.indent(yaml.dump(updated), '    '), selector))

with oc.project('openshift-machine-config-operator'):
    for mc in oc.selector('machineconfigs').objects():
        if mc.name().startswith('rendered'):
            continue
        for f in mc.model.spec.config.storage.files:
            if f.path.startswith('/etc/nmstate/openshift'):
                if f.contents.source.startswith(base64_prefix):
                    updated = modify_config(f)
                    create_nncp(updated, f.path, mc)


