#!/bin/bash

REPOS="prometheus prometheus-alertmanager node_exporter prometheus-operator kube-state-metrics kube-rbac-proxy k8s-prometheus-adapter thanos"

NOW=${1}
if [ "$NOW" == "" ]; then
        echo "You need to pass current release version"
        exit 1
fi

PREV="release-$(awk "BEGIN{printf \"%.1f\", ($NOW-0.1)}")"
NOW="release-${NOW}"

for r in ${REPOS}; do
        echo "$r: version update:"
        curl "https://github.com/openshift/$r/compare/${PREV}..${NOW}.diff" 2>/dev/null | grep "+++ b/VERSION" -A3 | tail -n2
        echo ""
done

echo "Version of openshift/grafana needs to be checked manually as there is no VERSION file in repository"
