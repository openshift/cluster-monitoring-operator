#!/usr/bin/env bash
set -e

# find all rule groups and aggregate them
# returns a json list of groups

find assets/ -type f -name "*prometheus-rule.yaml" | while read -r f
do
    tmp/bin/gojsontoyaml -yamltojson < "$f" | jq .spec
done | jq -s '[.[]] | { groups: map(.groups[]) }'
