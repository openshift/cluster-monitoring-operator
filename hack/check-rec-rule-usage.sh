#!/usr/bin/env bash
set -e

TMP=$(mktemp -d)
echo "Created temporary directory at $TMP"

findrules="$(cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )/find-rules.sh"

"$findrules" > "$TMP/rule-groups"
# extract recording rules
tmp/bin/gojsontoyaml -yamltojson <  "$TMP/rule-groups" | jq -s '.. | objects | select(.record) | .record' | tr -d '"' | sort -u > "$TMP/rec-rules"
# and alerting rules
tmp/bin/gojsontoyaml -yamltojson <  "$TMP/rule-groups" | jq -s '.. | objects | select(.alert) | .expr' | grep "\w\+{" -o | tr -d "{" | sort -u > "$TMP/alert-rules"
# the first grep outputs all recording rules that are not used in alerts
# and then greps for the remaining rules in the dashboard defs and outputs the ones that are not found
grep -Fxvf "$TMP/alert-rules" "$TMP/rec-rules" | while read -r r; do grep "$r" assets/grafana/dashboard-definitions.yaml -q || echo "$r"; done > "$TMP/unused-rules"

echo "Found $(wc -l < "$TMP/unused-rules") unused rules"
echo "Find the unused rules in $TMP/unused-rules"
