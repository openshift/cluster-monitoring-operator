# Note: This CHANGELOG is only for the monitoring team to track all monitoring related changes. Please see OpenShift release notes for official changes.

## 4.7

- [#963](https://github.com/openshift/cluster-monitoring-operator/pull/963) bump mixins to include new etcd alerts
  - Added etcdBackendQuotaLowSpace, etcdExcessiveDatabaseGrowth, and etcdHighFsyncDurations critical alert.
  - Adjusted NodeClockNotSynchronising, NodeNetworkReceiveErrs, and NodeNetworkTransmitErrs alerts.
- [#962](https://github.com/openshift/cluster-monitoring-operator/pull/962) Enable namespace by pod and pod total networking Grafana dashboards.
- [#959](https://github.com/openshift/cluster-monitoring-operator/pull/959) Remove memory limits from prometheus-config-reloader in user workload monitoring
- [#969](https://github.com/openshift/cluster-monitoring-operator/pull/969) Bump Thanos v0.16.0
- [#970](https://github.com/openshift/cluster-monitoring-operator/pull/970) Bump prometheus-operator v0.43.0.
- [#971](https://github.com/openshift/cluster-monitoring-operator/pull/971) Enable `hwmon` in node-exporter for hardware sensor data collection

## 4.6

- [#936](https://github.com/openshift/cluster-monitoring-operator/pull/9936) Bump prometheus-operator 0.42.1
- [#928](https://github.com/openshift/cluster-monitoring-operator/pull/928) Bump prometheus-operator 0.42:
  - 0.42.0 changes: https://github.com/prometheus-operator/prometheus-operator/releases/tag/v0.42.0
  - 0.41.1 changes: https://github.com/prometheus-operator/prometheus-operator/releases/tag/v0.41.1
  - 0.41.0 changes: https://github.com/prometheus-operator/prometheus-operator/releases/tag/v0.41.0
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
