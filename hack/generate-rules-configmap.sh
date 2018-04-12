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

for f in `ls rules/$PROMETHEUS/*.rules.yaml | sort -V`
do
  echo "  $(basename $f): |+"
  cat $f | sed "s/^/    /g"
done
