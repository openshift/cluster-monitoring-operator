#!/bin/bash

cat <<-EOF
apiVersion: v1
kind: Secret
metadata:
  name: alertmanager-main
  labels:
    k8s-app: alertmanager
data:
  alertmanager.yaml: $(base64 --wrap=0 examples/config/alertmanager/default.yaml)
EOF
