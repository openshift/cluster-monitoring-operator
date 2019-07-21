#!/bin/bash

PROMETHEUS=$1

cat <<-EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-$PROMETHEUS-rules
  labels:
    role: prometheus-rulefiles
    prometheus: $PROMETHEUS
data:
EOF

#shellcheck disable=SC2012,SC2086
for f in $(ls rules/${PROMETHEUS}/*.rules.yaml | sort -V)
do
  echo "  $(basename "$f"): |+"
  sed "s/^/    /g" "$f"
done
