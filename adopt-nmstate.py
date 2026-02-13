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

# TODO:
# - Retrieve masquerade address from API
# - Handle "default" capture config
# - Test if address append works with DHCP

import base64
import os
import textwrap
import yaml

import openshift_client as oc

base64_prefix = 'data:text/plain;charset=utf-8;base64,'

nncp_template = lambda hostname, updated: f'''apiVersion: nmstate.io/v1
kind: NodeNetworkConfigurationPolicy
metadata:
  name: {hostname}-br-ex
spec:
  nodeSelector:
    kubernetes.io/hostname: {hostname}
  desiredState:
{updated}
'''

def modify_config(f):
    encoded = f.contents.source[len(base64_prefix):]
    decoded = base64.b64decode(encoded).decode('utf-8')
    config = yaml.safe_load(decoded)
    masqv4 = [{'ip': '169.254.0.2', 'prefix-length': 17}]
    masqv6 = [{'ip': 'fd69::2', 'prefix-length': 112}]
    for interface in config['interfaces']:
        if interface['name'] == 'br-ex' and interface['type'] == 'ovs-interface':
            if interface['ipv4']['enabled']:
                interface['ipv4']['address'].append(masqv4)
    return config

def create_nncp(updated, path):
    hostname = os.path.splitext(os.path.basename(path))[0]
    print(f'{hostname}.yaml')
    print('-' * (len(hostname) + 5))
    print(nncp_template(hostname, textwrap.indent(yaml.dump(updated), '    ')))

with oc.project('openshift-machine-config-operator'):
    for mc in oc.selector('machineconfigs').objects():
        for f in mc.model.spec.config.storage.files:
            if f.path.startswith('/etc/nmstate/openshift'):
                if f.contents.source.startswith(base64_prefix):
                    updated = modify_config(f)
                    create_nncp(updated, f.path)


