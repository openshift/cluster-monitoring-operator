#!/usr/bin/env bash
set -e
set -x
# only exit with zero if all commands of the pipeline exit successfully
set -o pipefail

# Ensure that we use the binaries from the versions defined in hack/tools/go.mod.
PATH="$(pwd)/tmp/bin:${PATH}"

prefix="assets"

for file in ${prefix}/**/*; do
	go run hack/monitorgen/main.go --path $file
done
