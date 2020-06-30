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

# Replace mapfile with while loop so it works with previous bash versions (Mac included)
#mapfile -t files < <(jq -r 'keys[]' tmp/main.json)
while IFS= read -r line; do
    files+=("$line")
done < <(jq -r 'keys[]' tmp/main.json)

for file in "${files[@]}"
do
	dir=$(dirname "${file}")
	path="${prefix}/${dir}"
	mkdir -p "${path}"
    # convert file name from camelCase to snake-case
    fullfile=$(echo "${file}" | awk '{

  while ( match($0, /(.*)([a-z0-9])([A-Z])(.*)/, cap))
      $0 = cap[1] cap[2] "-" tolower(cap[3]) cap[4];

    print

}')
    jq -r ".[\"${file}\"]" tmp/main.json | gojsontoyaml > "${prefix}/${fullfile}.yaml"
done

# Produce dashboard definitions in format understandable by CVO (it doesn't accept ConfigMapList)
grep -E -v '^apiVersion: v1|^items:|^kind: ConfigMapList' "assets/grafana/console-dashboard-definitions.yaml" | sed 's/^\ \ //g;s/- apiVersion: v1/---\napiVersion: v1/g' > "manifests/0000_90_cluster_monitoring_operator_01-dashboards.yaml"
rm -f "assets/grafana/console-dashboard-definitions.yaml"

grep -H 'kind: CustomResourceDefinition' assets/prometheus-operator/* | cut -d: -f1 | while IFS= read -r f; do
  mv "$f" "manifests/0000_50_cluster_monitoring_operator_00_$(basename "$f")"
done
