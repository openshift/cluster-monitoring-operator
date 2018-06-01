#!/usr/bin/env bash
set -e
set -x
# only exit with zero if all commands of the pipeline exit successfully
set -o pipefail

prefix="assets"
rm -rf $prefix
mkdir $prefix

rm -rf tmp
mkdir tmp

jsonnet -J jsonnet/vendor jsonnet/main.jsonnet > tmp/main.json

mapfile -t files < <(jq -r 'keys[]' tmp/main.json)

for file in "${files[@]}"
do
	dir=$(dirname "${file}")
	path="${prefix}/${dir}"
	mkdir -p ${path}
    fullfile=$(echo "${file}" | awk '{
  while ( match($0, /(.*)([a-z0-9])([A-Z])(.*)/, cap))
      $0 = cap[1] cap[2] "-" tolower(cap[3]) cap[4];

    print
}')
    jq -r ".[\"${file}\"]" tmp/main.json | gojsontoyaml > "${prefix}/${fullfile}.yaml"
done

rm -rf "assets/prometheus-operator/0alertmanager-custom-resource-definition.yaml"
rm -rf "assets/prometheus-operator/0prometheus-custom-resource-definition.yaml"
rm -rf "assets/prometheus-operator/0servicemonitor-custom-resource-definition.yaml"
rm -rf "assets/prometheus-k8s/service-monitor-core-d-n-s.yaml"
rm -rf "assets/prometheus-k8s/service-monitor-kube-controller-manager.yaml"
rm -rf "assets/prometheus-k8s/service-monitor-kube-scheduler.yaml"
