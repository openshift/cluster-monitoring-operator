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
    base_role = {}
    sources = [os.path.relpath(sys.argv[1])]
    with open(sys.argv[1], 'r') as f:
        base_role = yaml.load(f)

    def add_to_base_role(role):
        # In theory this merges ClusterRoles.
        # If it happens to merge a regular Role, then log a warning
        # but do not raise an exception, as this behavior is needed.
        if role['kind'] != 'ClusterRole':
            warnings.warn('appending a {} to the base ClusterRole'.format(role['kind']))
        if role['rules'] not in base_role['rules']:
            base_role['rules'] += role['rules']

    manifests = sys.argv[2:]
    for manifest in manifests:
        with open(manifest, 'r') as f:
            y = yaml.load(f)
            if y['kind'].endswith('RoleList'):
                for item in y['items']:
                    add_to_base_role(item)
            elif y['kind'].endswith('Role'):
                add_to_base_role(y)
            else:
                warnings.warn('unexpected resource kind: {}'.format(y['kind']))
                continue
        sources.append(os.path.relpath(manifest))

    print("---")
    print("# This is a generated file. DO NOT EDIT")
    print("# Run `make merge-cluster-roles` to generate.")
    print("# Sources: ")
    for source in sources:
        print("# \t" + source)
    print(yaml.dump(base_role))


if __name__ == "__main__":
    main()
