#!/usr/bin/env bash
set -e

TMP=$(mktemp -d)
echo "Created temporary directory at $TMP"

# This directory should be a local copy of github.com/openshift/console
CONSOLE_DIR="${1:-../console}"

if [ ! -d "$CONSOLE_DIR" ]; then
    echo "Couldn't find a local copy of github.com/openshift/console: directory $CONSOLE_DIR does not exist"
    exit 1
fi

findrules="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)/find-rules.sh"

"$findrules" >"$TMP/rule-groups"
# Extract recording rules
tmp/bin/gojsontoyaml -yamltojson <"$TMP/rule-groups" | jq -s '.. | objects | select(.record) | .record' | tr -d '"' | sort -u >"$TMP/rec-rules"

# Extract alerting rules
tmp/bin/gojsontoyaml -yamltojson <"$TMP/rule-groups" | jq -s '.. | objects | select(.alert) | .expr' | grep "\w\+{" -o | tr -d "{" | sort -u >"$TMP/used-rules"

# Extract recording rules which are used in other recording or alerting rules.
go run -mod=vendor hack/promql_rule/main.go "$TMP/rule-groups" >"$TMP/rule-expr-names"
grep -Fxf "$TMP/rec-rules" "$TMP/rule-expr-names" >>"$TMP/used-rules"

# Extract Telemetry Client's metrics
# Put plain text matching rule names into used-rules
tmp/bin/gojsontoyaml -yamltojson <manifests/*-config.yaml | jq '.data."metrics.yaml"' | sed "s;\\\\n;\n;g" | grep "^-\s'{__name__=\\\\\"" | sed -e "s/^- '{__name__=\\\\\"//" | sed -e "s/\\\\\"[^}]*}'//" | sort | uniq >>"$TMP/used-rules"
# Put regex pattern matching rule names into used-rules-regex
tmp/bin/gojsontoyaml -yamltojson <manifests/*-config.yaml | jq '.data."metrics.yaml"' | sed "s;\\\\n;\n;g" | grep "^-\s'{__name__=~\\\\\"" | sed -e "s/^- '{__name__=~\\\\\"//" | sed -e "s/\\\\\"[^}]*}'//" | sort | uniq >"$TMP/used-rules-regex"
# The first grep outputs all recording rules that are used neither in alerts nor telemetry metrics
# and then greps for the remaining rules in the dashboard defs and outputs the ones that are not found
grep -Fxvf "$TMP/used-rules" "$TMP/rec-rules" | while read -r r; do grep "$r" assets/grafana/dashboard-definitions.yaml -q || echo "$r"; done >"$TMP/unused-rules-fixstr"
grep -Exvf "$TMP/used-rules-regex" "$TMP/unused-rules-fixstr" >"$TMP/unused-rules-cmo"

# Find out the rules used in console. The console TypeScript codes contain reference to rule names by exact text matching.
find "${CONSOLE_DIR}" -type f -regex ".*\.ts[x]*" | while read -r filename; do
    grep -Ff "$TMP/unused-rules-cmo" "$filename" | { grep -Eo "[a-zA-Z_][a-zA-Z0-9_:]*" || true; } >>"$TMP/used-rules-console-tmp"
done
sort "$TMP/used-rules-console-tmp" | uniq | { grep -Fxf "$TMP/unused-rules-cmo" || true; } >"$TMP/used-rules-console"
# Eliminate rules used by console from unused rules in CMO.
# Now we get rules neither used in CMO nor in console.
grep -Fxvf "$TMP/used-rules-console" "$TMP/unused-rules-cmo" >"$TMP/unused-rules"

echo "Found $(wc -l <"$TMP/unused-rules") unused rules"
echo "Find the unused rules in $TMP/unused-rules"
