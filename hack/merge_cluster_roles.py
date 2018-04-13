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


def main():
    base_role = {}
    sources = [os.path.relpath(sys.argv[1])]
    with open(sys.argv[1], 'r') as f:
        base_role = yaml.load(f)

    manifests = sys.argv[2:]
    for manifest in manifests:
        sources.append(os.path.relpath(manifest))
        with open(manifest, 'r') as f:
            rules = yaml.load(f)['rules']
            if rules not in base_role['rules']:
                base_role['rules'] += rules

    print("---")
    print("# This is a generated file. DO NOT EDIT")
    print("# Run `make merge-cluster-roles` to generate.")
    print("# Sources: ")
    for source in sources:
        print("# \t" + source)
    print(yaml.dump(base_role))


if __name__ == "__main__":
    main()
