#!/usr/bin/env python

import argparse
import json
import shutil
import subprocess
import tempfile


def dependency_key(dependency):
    return json.dumps(dependency['source'], sort_keys=True)


def github_diff(remote, subdir, version1, version2):
    dir = tempfile.mkdtemp(prefix='jsonnet-lock-diff-')
    try:
        subprocess.check_call(['git', 'clone', '--quiet', remote, '.'], cwd=dir)
        log_bytes = subprocess.check_output(['git', 'log', '--oneline', '--no-merges', '{}..{}'.format(version1, version2), '--', subdir], cwd=dir)
        return log_bytes.decode('utf-8')
    finally:
        shutil.rmtree(path=dir)


def lock_diff(path):
    with open(path, 'r') as f:
        current = json.load(f)
    previous_bytes = subprocess.check_output(['git', 'cat-file', '-p', 'HEAD^:{}'.format(path)])
    previous = json.loads(previous_bytes.decode('utf-8'))
    previous_keyed = {dependency_key(dependency=dependency): dependency for dependency in previous.get('dependencies', [])}
    for dependency in current.get('dependencies', []):
        key = dependency_key(dependency=dependency)
        previous_dependency = previous_keyed.get(key)
        if dependency['version'] == previous_dependency['version']:
            continue
        if not previous_dependency:
            print('{} is new')
            continue
        if dependency.get('source', {}).get('git', {}):
            diff = github_diff(version1=previous_dependency['version'], version2=dependency['version'], **dependency['source']['git'])
        else:
            diff = 'unsupported source; cannot render diff'
        if diff.strip():
            print(key)
            print(diff)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pretty-print changes pulled in by a jsonnet bump.')
    parser.add_argument('path', nargs='+', help='Path to jsonnet lock file.')

    args = parser.parse_args()

    for path in args.path:
        lock_diff(path=path)
