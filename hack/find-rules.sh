#!/usr/bin/env bash
set -e

# find all rule groups and aggregate them
# returns a json list of groups
find assets/ -type f -name "*.yaml" | while read -r f; do
    JSONIFIED=$(tmp/bin/gojsontoyaml -yamltojson <"$f")
    KIND=$(jq .kind <<<"$JSONIFIED")
    if [ "$KIND" != "\"PrometheusRule\"" ]; then
        continue
    fi
    jq .spec <<<"$JSONIFIED"
done | jq -s '[.[]] | { groups: map(.groups[]) }'
