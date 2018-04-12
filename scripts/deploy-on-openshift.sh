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

oc apply -f manifests/cluster-monitoring-operator-role.yaml
oc apply -f manifests/cluster-monitoring-operator-role-binding.yaml
oc apply -f manifests/cluster-monitoring-config.yaml
oc apply -f manifests/cluster-monitoring-operator.yaml