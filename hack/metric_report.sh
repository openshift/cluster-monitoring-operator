#!/bin/bash

set -eu -o pipefail

readonly CURL_OPTS=( -sG --fail --connect-timeout 5 --max-time 30 )

if [[ $# -lt 2 ]]; then
  echo "usage: $0 http://host:port <metric> [...]"
  echo "  To access Prometheus, run: oc port-forward -n openshift-monitoring prometheus-k8s-0 9998:9090"
  echo "  Then: $0 http://localhost:9998 <metric> [...]"
  echo "  Note: ensure the metrics are enabled and the cluster is in a steady state so all expected series are present."
  exit 1
fi

PROM="${1%/}"
shift

END=$(date +%s)
START=$((END - 86400)) # 24h

utc_from_epoch() {
  date -u -d "@$1" +"%Y-%m-%d %H:%M:%S UTC" 2>/dev/null || date -u -r "$1" +"%Y-%m-%d %H:%M:%S UTC"
}

echo "Telemetry metrics report"
echo "time window: $(utc_from_epoch "${START}") to $(utc_from_epoch "${END}") (24h)"
echo

for metric in "$@"; do
  sel='{__name__="'"${metric}"'"}'

  echo "metric: ${metric}"

  # Is it a recording rule?
  rule=$(curl "${CURL_OPTS[@]}" "${PROM}/api/v1/rules" \
    --data-urlencode "type=record" \
    --data-urlencode "rule_name[]=${metric}")

  file=$(echo "${rule}" | jq -r '.data.groups[].file')
  expr=$(echo "${rule}" | jq -r '.data.groups[].rules[].query')

  if [[ -n "${file}" ]]; then
    echo "recording rule: yes"
    echo "file: ${file}"
    echo "expr:"
    echo "  ${expr}"
  else
    echo "recording rule: no"
  fi

  # Series count.
  count=$(curl "${CURL_OPTS[@]}" "${PROM}/api/v1/series" \
    --data-urlencode "match[]=${sel}" \
    --data-urlencode "start=${START}" \
    --data-urlencode "end=${END}" \
    | jq '.data | length')

  echo "series count: ${count}"

  # Label names and distinct value counts.
  labels=$(curl "${CURL_OPTS[@]}" "${PROM}/api/v1/labels" \
    --data-urlencode "match[]=${sel}" \
    --data-urlencode "start=${START}" \
    --data-urlencode "end=${END}" \
    | jq -r '.data[] | select(. != "__name__")')

  if [[ -z "${labels}" ]]; then
    echo "labels: (none)"
  else
    echo "labels count:"
    while IFS= read -r l; do
      n=$(curl "${CURL_OPTS[@]}" "${PROM}/api/v1/label/${l}/values" \
        --data-urlencode "match[]=${sel}" \
        --data-urlencode "start=${START}" \
        --data-urlencode "end=${END}" \
        | jq '.data | length')
      echo "  ${l}: ${n}"
    done <<< "${labels}"
  fi

  echo
done
