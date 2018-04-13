#!/usr/bin/env bash
# exit immediately when a command fails
set -e
# only exit with zero if all commands of the pipeline exit successfully
set -o pipefail
# error on unset variables
set -u
# print each command before executing it
set -x

CLUSTER="tpo-$(git rev-parse --short HEAD)-${BUILD_ID}"
CMO_REPO="/go/src/github.com/openshift/cluster-monitoring-operator"
KUBECONFIG="${TPO_REPO}/build/${CLUSTER}/generated/auth/kubeconfig"


echo $PULL_SECRET > pull-secret.json
docker run \
       -e TAG=${BUILD_ID} \
       -e REPO=quay.io/coreos/cluster-monitoring-operator-dev \
       -e KUBECONFIG=${KUBECONFIG} \
       -v $PWD:${CMO_REPO} \
       -w ${TPO_REPO} \
       golang:1.8 \
       /bin/bash -c "make test"

