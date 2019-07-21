#!/bin/bash

# For local clusters with `oc cluster up` use the following:
#
# $ docker-machine create openshift --virtualbox-memory "4096" --engine-insecure-registry 172.30.0.0/16
#
# $ oc cluster up --docker-machine=openshift
#
# vi /var/lib/origin/openshift.local.config/node-localhost/node-config.yaml
#
#   max-pods:
#   - "40"
#   pods-per-core:
#   - "40"
#
# docker restart origin

oc create namespace openshift-monitoring
oc project openshift-monitoring
oc annotate ns/openshift-monitoring openshift.io/node-selector=
oc label ns/openshift-monitoring openshift.io/cluster-monitoring=true

oc apply -f manifests/01-namespace.yaml
oc apply -f manifests/02-role-binding.yaml
oc apply -f manifests/02-role.yaml
oc apply -f manifests/03-config.yaml
oc apply -f manifests/03-etcd-secret.yaml
oc apply -f manifests/04-deployment.yaml
