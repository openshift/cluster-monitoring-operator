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
  if [[ "${selector}" != "{"* ]]; then
    echo "error: selector must be a PromQL matcher like '{__name__=\"...\"}', got: ${selector}" >&2
    exit 1
  fi

  echo "selector: ${selector}"

  # Step 1: /series gives us metric names + count.
  series=$(curl "${CURL_OPTS[@]}" "${PROM}/api/v1/series" \
    --data-urlencode "match[]=${selector}" \
    --data-urlencode "start=${START}" \
    --data-urlencode "end=${END}")

  metrics=$(echo "${series}" | jq -r '.data | map(.__name__) | unique[]')
  count=$(echo "${series}" | jq '.data | length')

  echo "matched metrics:"
  if [[ -z "${metrics}" ]]; then
    echo "  (none)"
  else
    while IFS= read -r m; do echo "  - ${m}"; done <<< "${metrics}"
  fi

  echo "timeseries count: ${count}"

  # Step 2: /rules for each metric name from step 1.
  if [[ -n "${metrics}" ]]; then
    echo "recording rules:"
    while IFS= read -r m; do
      rule=$(curl "${CURL_OPTS[@]}" "${PROM}/api/v1/rules" \
        --data-urlencode "type=record" \
        --data-urlencode "rule_name[]=${m}")

      file=$(echo "${rule}" | jq -r '.data.groups[].file')
      rule_expr=$(echo "${rule}" | jq -r '.data.groups[].rules[].query')

      if [[ -n "${file}" ]]; then
        echo "  - ${m} (recording rule)"
        echo "    file: ${file}"
        echo "    expression: ${rule_expr}"
      else
        echo "  - ${m} (not a recording rule)"
      fi
    done <<< "${metrics}"
  fi

  # Step 3: label cardinality using the original selector.
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
