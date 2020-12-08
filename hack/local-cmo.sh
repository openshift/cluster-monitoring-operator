#!/usr/bin/env bash
# Script will:
# 1. Patch CVO to exclude CMO from being managed
# 2. Scale in-cluster CMO to 0
# 3. Try to run CMO locally (CMO needs to be built before starting)

set -eu

# Go to the root of the repo
cd "$(git rev-parse --show-cdup)"

if [ ! -f "operator" ]; then
	echo "Cannot find local operator binary. Try running 'make build' first."
	exit 1
fi

IMAGES=$(kubectl -n openshift-monitoring get deployment cluster-monitoring-operator -o yaml | grep -o "\-images.*" | tr '\n' ' ')

OVERRIDE='[{"group": "extensions/v1beta1", "kind": "Deployment", "name": "cluster-monitoring-operator", "namespace": "openshift-monitoring", "unmanaged": true}]'
kubectl patch clusterversion/version --type=json -p="[{\"op\": \"add\", \"path\": \"/spec/overrides\", \"value\": $OVERRIDE }]"

kubectl -n openshift-monitoring scale --replicas=0 deployment/cluster-monitoring-operator

# shellcheck disable=SC2002
cat manifests/0000_50_cluster-monitoring-operator_04-config.yaml | gojsontoyaml -yamltojson | jq -r '.data["metrics.yaml"]' > /tmp/telemetry-config.yaml

# shellcheck disable=SC2086
./operator ${IMAGES} -assets assets/ -telemetry-config /tmp/telemetry-config.yaml -kubeconfig "${KUBECONFIG}" -namespace=openshift-monitoring -configmap=cluster-monitoring-config -logtostderr=true -v=4 2>&1 | tee operator.log
