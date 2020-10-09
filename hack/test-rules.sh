#!/usr/bin/env bash
set -e
set -x
# only exit with zero if all commands of the pipeline exit successfully
set -o pipefail

# Ensure that we use the binaries from the versions defined in hack/tools/go.mod.
PATH="$(pwd)/tmp/bin:${PATH}"

TMP_RULE_FILE=$(mktemp tmp/tmp.XXXXXXXXXX.yaml)
trap 'rm -f "$TMP_RULE_FILE"' EXIT

for rule in ./test/rules/*.yaml; do
	echo ">> testing $rule <<";
	gojsontoyaml -yamltojson - < "$rule" | jq '.rule_files=["rules.yaml"]' | gojsontoyaml - > "$TMP_RULE_FILE"
	promtool test rules "$TMP_RULE_FILE"
done
