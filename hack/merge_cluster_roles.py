#!/usr/bin/python
""" merge_cluster_roles.py - merge OpenShift cluster roles into one """
# Copyright (c) 2018 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import unicode_literals, print_function
import os.path
import sys
import yaml
import warnings


def main():
    base = ClusterRole()
    sources = [os.path.relpath(sys.argv[1])]
    with open(sys.argv[1], 'r') as f:
        base = ClusterRole(yaml.load(f, Loader=yaml.SafeLoader))

    manifests = sys.argv[2:]
    for manifest in sorted(manifests):
        with open(manifest, 'r') as f:
            y = yaml.load(f, Loader=yaml.SafeLoader)
            if y['kind'].endswith('RoleList'):
                for item in y['items']:
                    base.merge(ClusterRole(item))
            elif y['kind'].endswith('Role'):
                base.merge(ClusterRole(y))
            else:
                warnings.warn('unexpected resource kind: {}'.format(y['kind']))
                continue
        sources.append(os.path.relpath(manifest))

    print('---')
    print('# This is a generated file. DO NOT EDIT')
    print('# Run `make merge-cluster-roles` to generate.')
    print('# Sources: ')
    for source in sources:
        print('# \t' + source)
    print(yaml.dump(base.manifest, default_flow_style=False))


class ClusterRole(object):

    def __init__(self, manifest = {}):
        self.manifest = manifest
        # In theory this merges ClusterRoles.
        # If it happens to merge a regular Role, then log a warning
        # but do not raise an exception, as this behavior is needed.
        if 'kind' in self.manifest and self.manifest['kind'] != 'ClusterRole':
            warnings.warn('creating a ClusterRole from a {}'.format(self.manifest['kind']))
        self.rules = {}
        if 'rules' in self.manifest:
            for r in self.manifest['rules']:
                self.rules[rule_to_string(r)] = r
        else:
            self.manifest['rules'] = []

    # merge adds the rules of the passed ClusterRole to the list of rules.
    def merge(self, cr):
        for s, r in cr.rules.items():
            if s not in self.rules:
                self.rules[s] = r
                self.manifest['rules'].append(r)


# rule_to_string stably stringifies a rule so that rules can be
# deduplicated using a dict.
def rule_to_string(rule):
    ks = list(rule.keys())
    ks.sort()
    s = []
    for k in ks:
        v = rule[k]
        if isinstance(v, list):
            v.sort()
        s.append('{}:{}'.format(k, v))
    return ','.join(s)


if __name__ == "__main__":
    main()
