#!/usr/bin/env bash

cat <<-EOF
apiVersion: v1
data:
  etcd-client-ca.crt: "$(ssh -i ~/go/src/github.com/openshift/release/cluster/test-deploy/gcp-dev/ssh-privatekey cloud-user@35.237.160.60 sudo -E cat /etc/origin/master/master.etcd-ca.crt | base64 --wrap=0)"
  etcd-client.crt: "$(ssh -i ~/go/src/github.com/openshift/release/cluster/test-deploy/gcp-dev/ssh-privatekey cloud-user@35.237.160.60 sudo -E cat /etc/origin/master/master.etcd-client.crt | base64 --wrap=0)"
  etcd-client.key: "$(ssh -i ~/go/src/github.com/openshift/release/cluster/test-deploy/gcp-dev/ssh-privatekey cloud-user@35.237.160.60 sudo -E cat /etc/origin/master/master.etcd-client.key | base64 --wrap=0)"
kind: Secret
metadata:
  name: kube-etcd-client-certs
  namespace: openshift-monitoring
type: Opaque
EOF
