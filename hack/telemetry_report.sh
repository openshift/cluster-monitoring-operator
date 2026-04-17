#!/bin/bash

set -eu -o pipefail

readonly CURL_OPTS=( -sG --fail --connect-timeout 5 --max-time 30 )

if [[ $# -lt 2 ]]; then
  echo "usage: $0 http://host:port <selector> [...]"
  echo '  Example: '"$0"' http://localhost:9998 '"'"'{__name__="my_metric", label=~"a|b"}'"'"
  echo "  To access Prometheus, run: oc port-forward -n openshift-monitoring prometheus-k8s-0 9998:9090"
  echo "  Note: ensure metrics are enabled and the cluster is in a steady state so all expected timeseries are present."
  exit 1
fi

PROM="${1%/}"
shift

END=$(date +%s)
START=$((END - 86400)) # 24h

utc_from_epoch() {
  date -u -d "@$1" +"%Y-%m-%d %H:%M:%S UTC" 2>/dev/null || date -u -r "$1" +"%Y-%m-%d %H:%M:%S UTC"
}

echo "Telemetry selectors report"
echo "time window: $(utc_from_epoch "${START}") to $(utc_from_epoch "${END}") (24h)"
echo

for selector in "$@"; do
  if [[ "${selector}" != '{__name__="'* ]]; then
    echo "error: selector must start with '{__name__=\"...\"', got: ${selector}" >&2
    exit 1
  fi

  echo "selector: ${selector}"

  # Strip the '{__name__="' prefix validated above, then everything from the next '"'.
  metric="${selector#\{__name__=\"}"
  metric="${metric%%\"*}"

  rule=$(curl "${CURL_OPTS[@]}" "${PROM}/api/v1/rules" \
    --data-urlencode "type=record" \
    --data-urlencode "rule_name[]=${metric}")

  file=$(echo "${rule}" | jq -r '.data.groups[].file')
  rule_expr=$(echo "${rule}" | jq -r '.data.groups[].rules[].query')

  if [[ -n "${file}" ]]; then
    echo "metric is from a recording rule: yes"
    echo "file: ${file}"
    echo "metric rule expression:"
    echo "  ${rule_expr}"
  else
    echo "metric is not from a recording rule: no"
  fi

  # Timeseries count.
  count=$(curl "${CURL_OPTS[@]}" "${PROM}/api/v1/series" \
    --data-urlencode "match[]=${selector}" \
    --data-urlencode "start=${START}" \
    --data-urlencode "end=${END}" \
    | jq '.data | length')

  echo "timeseries count: ${count}"

  # Label names and distinct value counts.
  labels=$(curl "${CURL_OPTS[@]}" "${PROM}/api/v1/labels" \
    --data-urlencode "match[]=${selector}" \
    --data-urlencode "start=${START}" \
    --data-urlencode "end=${END}" \
    | jq -r '.data[] | select(. != "__name__")')

  if [[ -z "${labels}" ]]; then
    echo "labels: (none)"
  else
    echo "labels count:"
    while IFS= read -r l; do
      n=$(curl "${CURL_OPTS[@]}" "${PROM}/api/v1/label/${l}/values" \
        --data-urlencode "match[]=${selector}" \
        --data-urlencode "start=${START}" \
        --data-urlencode "end=${END}" \
        | jq '.data | length')
      echo "  ${l}: ${n}"
    done <<< "${labels}"
  fi

  echo
done
