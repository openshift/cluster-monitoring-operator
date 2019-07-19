#!/bin/bash

RANDTAG=$(LC_CTYPE=C tr -dc a-z0-9 < /dev/urandom | head -c 13 ; echo '')

echo "$RANDTAG"

eval "$(minikube docker-env)"
kubectl delete -f manifests/cluster-monitoring-operator.yaml
make container TAG="$RANDTAG"
manifest=$(cat manifests/cluster-monitoring-operator.yaml)
echo "$manifest" | "sed s/v.\\..\\../$RANDTAG/g"
echo "$manifest" | sed "s/v.\\..\\../$RANDTAG/g" | kubectl create -f -
