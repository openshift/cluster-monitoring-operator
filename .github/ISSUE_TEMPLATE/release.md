---
name: Release Checklist
about: Create release checklist
---

# Feature freeze release checklist

## Golang projects and backports

- [ ] update downstream backport of [openshift/node_exporter](https://github.com/openshift/node_exporter)
  - [ ] bump [openshift/procfs](https://github.com/openshift/procfs) to the version used in the node_exporter's upstream version we want to bump to, including any downstream patch we may have
  - [ ] bump [openshift/node_exporter](https://github.com/openshift/node_exporter) to the upstream version replacing the procfs dependency by the downstream repo
- [ ] update downstream backport of [openshift/prometheus](https://github.com/openshift/prometheus)
- [ ] update downstream backport of [openshift/alertmanager](https://github.com/openshift/alertmanager)
- [ ] update downstream backport of [openshift/thanos](https://github.com/openshift/thanos)
- [ ] update downstream backport of [openshift/prometheus-operator](https://github.com/openshift/prometheus-operator)
- [ ] update downstream backport of [openshift/kube-state-metrics](https://github.com/openshift/kube-state-metrics)
- [ ] update downstream backport of [openshift/kube-rbac-proxy](https://github.com/openshift/kube-rbac-proxy)
- [ ] update downstream backport of [openshift/k8s-prometheus-adapter](https://github.com/openshift/k8s-prometheus-adapter)
- [ ] update downstream backport of [openshift/grafana](https://github.com/openshift/grafana)

## Jsonnet dependencies

- [ ] cut new release in [kubernetes-monitoring/kubernetes-mixin](https://github.com/kubernetes-monitoring/kubernetes-mixin)
- [ ] cut new release in [thanos-io/kube-thanos](https://github.com/thanos-io/kube-thanos)
- [ ] cut new release in [coreos/kube-prometheus](https://github.com/coreos/kube-prometheus)
  - update dependencies before doing release

## Cluster Monitoring Operator

- [ ] update and pin jsonnet dependencies in [jsonnet/jsonnetfile.json](https://github.com/openshift/cluster-monitoring-operator/blob/master/jsonnet/jsonnetfile.json).
  - example: https://github.com/openshift/cluster-monitoring-operator/blob/release-4.3/jsonnet/jsonnetfile.json
  - dependencies should be pinned to branches released in previous paragraph
- [ ] update golang dependencies in [go.mod](https://github.com/openshift/cluster-monitoring-operator/blob/master/go.mod) and [hack/tools/go.mod](https://github.com/openshift/cluster-monitoring-operator/blob/master/hack/tools/go.mod) files.
  - most important are dependencies on prometheus-operator and kubernetes components
  - update the tooling prometheus dependency to be in sync with the main one
