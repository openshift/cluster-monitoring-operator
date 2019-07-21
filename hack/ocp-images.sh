#!/usr/bin/env bash
set -e
set -x
# only exit with zero if all commands of the pipeline exit successfully
set -o pipefail

#
# This script synchronizes OCP images into a cluster-local registry of an
# OpenShift cluster, and writes the appropriate configuration into the
# cluster-monitoring-operator manifests in `manifests/`.
#
# The `TAG` and `WHAT` environment variables are required.
#
# * `TAG` sets the OCP tag that should be used.
# * `WHAT` sets the dev cluster the images should be synced to. This is
#   typically the Red Hat kerberos user.
#

SRC_REGISTRY="registry.reg-aws.openshift.com/openshift3"
DST_REGISTRY="docker-registry-default.apps.${WHAT}.origin-gce.dev.openshift.com/openshift"
INTERNAL_REGISTRY="docker-registry.default.svc:5000/openshift"
IMAGES=(
    "ose-configmap-reloader"
    "ose-cluster-monitoring-operator"
    "ose-kube-state-metrics"
    "ose-kube-rbac-proxy"
    "ose-prometheus-config-reloader"
    "ose-prometheus-operator"
)

for i in "${IMAGES[@]}"; do
    docker pull "${SRC_REGISTRY}/${i}:${TAG}"
done

for i in "${IMAGES[@]}"; do
    docker tag "${SRC_REGISTRY}/${i}:${TAG}" "${DST_REGISTRY}/${i}:${TAG}"
done

for i in "${IMAGES[@]}"; do
    docker push "${DST_REGISTRY}/${i}:${TAG}"
done

cat << EOF > manifests/cluster-monitoring-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |+
    prometheusOperator:
      baseImage: ${INTERNAL_REGISTRY}/ose-prometheus-operator
      prometheusConfigReloaderBaseImage: ${INTERNAL_REGISTRY}/ose-prometheus-config-reloader
      configReloaderBaseImage: ${INTERNAL_REGISTRY}/ose-configmap-reloader
    prometheusK8s:
      baseImage: ${INTERNAL_REGISTRY}/prometheus
    alertmanagerMain:
      baseImage: ${INTERNAL_REGISTRY}/prometheus-alertmanager
    nodeExporter:
      baseImage: ${INTERNAL_REGISTRY}/prometheus-node-exporter
    kubeRbacProxy:
      baseImage: ${INTERNAL_REGISTRY}/ose-kube-rbac-proxy
    kubeStateMetrics:
      baseImage: ${INTERNAL_REGISTRY}/ose-kube-state-metrics
    grafana:
      baseImage: ${INTERNAL_REGISTRY}/ose-grafana
    auth:
      baseImage: ${INTERNAL_REGISTRY}/oauth-proxy
    etcd:
      enabled: true
      targets:
        selector:
          openshift.io/component: etcd
          openshift.io/control-plane: "true"
EOF

cat << EOF > manifests/cluster-monitoring-operator.yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: cluster-monitoring-operator
  namespace: openshift-monitoring
  labels:
    app: cluster-monitoring-operator
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cluster-monitoring-operator
  template:
    metadata:
      labels:
        app: cluster-monitoring-operator
    spec:
      serviceAccountName: cluster-monitoring-operator
      containers:
      - image: quay.io/coreos/cluster-monitoring-operator-dev:$(git rev-parse --short HEAD)
        name: cluster-monitoring-operator
        args:
        - "-namespace=openshift-monitoring"
        - "-configmap=cluster-monitoring-config"
        - "-logtostderr=true"
        - "-v=4"
        - "-tags=prometheus-operator=${TAG}"
        - "-tags=prometheus-config-reloader=${TAG}"
        - "-tags=config-reloader=${TAG}"
        #- "-tags=prometheus=${TAG}"
        #- "-tags=alertmanager=${TAG}"
        #- "-tags=grafana=${TAG}"
        #- "-tags=oauth-proxy=${TAG}"
        #- "-tags=node-exporter=${TAG}"
        - "-tags=kube-state-metrics=${TAG}"
        - "-tags=kube-rbac-proxy=${TAG}"
        ports:
        - containerPort: 8080
          name: http
        resources:
          limits:
            cpu: 20m
            memory: 50Mi
          requests:
            cpu: 20m
            memory: 50Mi
EOF
