# Note: This CHANGELOG is only for the monitoring team to track all monitoring related changes. Please see OpenShift release notes for official changes.

## 4.6

- [#714](https://github.com/openshift/cluster-monitoring-operator/pull/714) Validate new/updated PrometheusRule custom resources against the prometheus-operator rule validation API.
- [#799](https://github.com/openshift/cluster-monitoring-operator/pull/799) Rules federation support.
- [#800](https://github.com/openshift/cluster-monitoring-operator/pull/800) Collect metrics and implement alerting rules for Thanos querier.
- [#804](https://github.com/openshift/cluster-monitoring-operator/pull/804) Allow user workload monitoring configuration ConfigMap to be created in openshift-user-workload-monitoring namespace.
- [#736](https://github.com/openshift/cluster-monitoring-operator/pull/800) Expose /api/v1/rules endpoint of Thanos Querier via the 9093 TCP port with multi-tenancy support.
- [#854](https://github.com/openshift/cluster-monitoring-operator/pull/854) Change KubeQuotaExceeded to KubeQuotaFullyUsed.
- [#859](https://github.com/openshift/cluster-monitoring-operator/pull/859) Remove the `hostport` parameter from the configuration.
- [#859](https://github.com/openshift/cluster-monitoring-operator/pull/865) Allow users to configure EnforcedSampleLimit for User workload monitoring Prometheus tenant.
- [#894](https://github.com/openshift/cluster-monitoring-operator/pull/894) Bump jsonnet depdencies:
  - kubernetes-mixin: https://github.com/kubernetes-monitoring/kubernetes-mixin/pull/475: alerts: adjust error message accrodingly to recent change
  - prometheus-operator: https://github.com/coreos/kube-prometheus/pull/610: Add PrometheusOperatorListErrors and fix PrometheusOperatorWatchErrors threshold
  - etcd: https://github.com/etcd-io/etcd/pull/12122: Documentation/etcd-mixin: Reformulate alerting rules to use `without` rather than `by`
  - kubelet: https://github.com/coreos/kube-prometheus/pull/623: Add scraping of endpoint for kubelet probe metrics
  - thanos: https://github.com/thanos-io/thanos/pull/2374: mixin: Added critical Rules alerts.
- [#898](https://github.com/openshift/cluster-monitoring-operator/pull/898) Bump jsonnet depdencies for kube-mixin:
  - Adjusts severity levels of many alerts from critical to warning as they were cause based alerts
  - Adjusts KubeStatefulSetUpdateNotRolledOut, KubeDaemonSetRolloutStuck
  - Removes KubeAPILatencyHigh and KubeAPIErrorsHigh
