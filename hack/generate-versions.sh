#!/bin/bash
#
# A naive way to generate `jsonnet/versions.json` file from downstream forks
# It uses `VERSION` file located in each repository or a special function to figure out correct version
# 
# Script is based on https://github.com/prometheus-operator/kube-prometheus/blob/main/scripts/generate-versions.sh
#

get_version_from_file() {
  curl --retry 5 --silent --fail "https://raw.githubusercontent.com/${1}/master/VERSION"
}

# Fallback mechanism when VERSION file is empty or not found
get_version_from_user() {
    ver=""
    echo >&2 -n "Cannot determine version of ${1}. Please provide version manually (without alphabetical prefixes) and press ENTER: "
    read -r ver
    echo "$ver"
}

get_version() {
  component="${1}"
  v="$(get_version_from_file "${component}")"

  if [[ "$v" == "" ]]; then
     v="$(get_version_from_user "${component}")"
  fi
  echo "$v"
}


cat <<-EOF
{ 
  "alertmanager": "$(get_version "openshift/prometheus-alertmanager")",
  "prometheus": "$(get_version "openshift/prometheus")",
  "grafana": "$(get_version "openshift/grafana")",
  "kubeStateMetrics": "$(get_version "openshift/kube-state-metrics")",
  "nodeExporter": "$(get_version "openshift/node_exporter")",
  "prometheusAdapter": "$(get_version "openshift/k8s-prometheus-adapter")",
  "prometheusOperator": "$(get_version "openshift/prometheus-operator")",
  "promLabelProxy": "$(get_version "openshift/prom-label-proxy")",
  "kubeRbacProxy": "$(get_version "openshift/kube-rbac-proxy")",
  "thanos": "$(get_version "openshift/thanos")"
}
EOF
