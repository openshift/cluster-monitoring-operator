#!/bin/bash

set -euo pipefail

MANIFESTS_FILE="pkg/manifests/manifests.go"

code=0
for i in $(find assets/ -name '*.yaml' | sed 's/assets\///g'); do
	if ! grep -cq "$i" "$MANIFESTS_FILE"; then
		code=1
		echo "File is not included in $MANIFESTS_FILE: $i"
	fi
done

exit "$code"
