#!/usr/bin/env bash
set -e
set -x
# only exit with zero if all commands of the pipeline exit successfully
set -o pipefail

NAMESPACE=openshift-kube-apiserver
APISERVERPODNAME="$(kubectl -n ${NAMESPACE} get pod -lapp=openshift-kube-apiserver -ojsonpath='{.items[0].metadata.name}')"

cat <<-EOF
apiVersion: v1
kind: Secret
metadata:
  name: kube-etcd-client-certs
  namespace: openshift-monitoring
type: Opaque
data:
  etcd-client-ca.crt: "$(oc rsh -n ${NAMESPACE} "${APISERVERPODNAME}" cat /etc/kubernetes/static-pod-resources/configmaps/etcd-serving-ca/ca-bundle.crt | base64 --wrap=0)"
  etcd-client.crt: "$(oc rsh -n ${NAMESPACE} "${APISERVERPODNAME}" cat /etc/kubernetes/static-pod-resources/secrets/etcd-client/tls.crt | base64 --wrap=0)"
  etcd-client.key: "$(oc rsh -n ${NAMESPACE} "${APISERVERPODNAME}" cat /etc/kubernetes/static-pod-resources/secrets/etcd-client/tls.key | base64 --wrap=0)"
EOF
