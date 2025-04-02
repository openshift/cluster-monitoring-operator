# Note: This CHANGELOG is only for the monitoring team to track all monitoring related changes. Please see OpenShift release notes for official changes.

## 4.19

- [#2339](https://github.com/openshift/cluster-monitoring-operator/pull/2339) Add support to sysctl node-exporter collector

## 4.18

- [#2503](https://github.com/openshift/cluster-monitoring-operator/issues/2503) Expose `scrapeInterval` setting for UWM Prometheus.
- [#2517](https://github.com/openshift/cluster-monitoring-operator/issues/2517) Expose `evaluationInterval` setting for UWM Prometheus and ThanosRuler.

## 4.17

- [#2409](https://github.com/openshift/cluster-monitoring-operator/issues/2409) Remove prometheus-adapter code from CMO

## 4.16

- [#2302](https://github.com/openshift/cluster-monitoring-operator/issues/2302) Enable feature `extra-scrape-metrics` in Prometheus user-workload
- [#2319](https://github.com/openshift/cluster-monitoring-operator/pull/2319) Allow read-only access to the Alertmanager API (use `monitoring-alertmanager-view`).
- [#2078](https://github.com/openshift/cluster-monitoring-operator/pull/2078) Support exporting VPA metrics from KSM.

## 4.15

- [#2022](https://github.com/openshift/cluster-monitoring-operator/pull/2022) Add support to switch to metrics server from prometheus-adapter when the `MetricsServer` feature gate is enabled.
- [#2161](https://github.com/openshift/cluster-monitoring-operator/pull/2161) Add `PrometheusRestrictedConfig.RemoteWrite[].SendExemplars`.
- [#2184](https://github.com/openshift/cluster-monitoring-operator/issues/2184) Allow to query alerts of application namespaces as an application user from command line.

## 4.14

- [#1937](https://github.com/openshift/cluster-monitoring-operator/pull/1937) Disables btrfs collector
- [#1910](https://github.com/openshift/cluster-monitoring-operator/pull/1910) Add new web console usage metrics
- [#1950](https://github.com/openshift/cluster-monitoring-operator/pull/1950) Disable CORS headers on Thanos querier by default and add a flag to enable them back.
- [#1963](https://github.com/openshift/cluster-monitoring-operator/pull/1963) Add nodeExporter settings for network devices list.
- [#2049](https://github.com/openshift/cluster-monitoring-operator/pull/2049) Remove Kube*QuotaOvercommit alerts.
- [#2067](https://github.com/openshift/cluster-monitoring-operator/pull/2067) Add options to specify resource requests and limits for all components.

## 4.13

- [#1785](https://github.com/openshift/cluster-monitoring-operator/pull/1785) Adds support for CollectionProfiles TechPreview
- [#1830](https://github.com/openshift/cluster-monitoring-operator/pull/1830) Add alert KubePodNotScheduled
- [#1843](https://github.com/openshift/cluster-monitoring-operator/pull/1843) Node Exporter ignores network interface under name "enP.*".
- [#1860](https://github.com/openshift/cluster-monitoring-operator/pull/1860) Adds runbook for PrometheusRuleFailures
- [#1868](https://github.com/openshift/cluster-monitoring-operator/pull/1868) In dashboards unstack diagrams with limit/quota/request.
- [#1855](https://github.com/openshift/cluster-monitoring-operator/pull/1855) Add nodeExporter.collectors.cpufreq settings.
- [#1882](https://github.com/openshift/cluster-monitoring-operator/issues/1882) Allow configuring secrets in alertmanager component (platform)
- [#1876](https://github.com/openshift/cluster-monitoring-operator/pull/1876) Add nodeExporter.collectors.tcpstat settings.
- [#1888](https://github.com/openshift/cluster-monitoring-operator/pull/1888) Add nodeExporter.collectors.netdev settings.
- [#1884](https://github.com/openshift/cluster-monitoring-operator/issues/1884) Allow configuring secrets in alertmanager component (UWM)
- [#1893](https://github.com/openshift/cluster-monitoring-operator/pull/1893) Add nodeExporter.collectors.netclass settings.
- [#1894](https://github.com/openshift/cluster-monitoring-operator/pull/1894) Add toggle netlink implementation of netclass collector in Node Exporter.
- [#1891](https://github.com/openshift/cluster-monitoring-operator/pull/1891) Add nodeExporter.collectors.buddyinfo settings.
- [#1895](https://github.com/openshift/cluster-monitoring-operator/pull/1895) Add nodeExporter.maxProcs setting.

## 4.12
- [#1624](https://github.com/openshift/cluster-monitoring-operator/pull/1624) Add option to specify TopologySpreadConstraints for Prometheus, Alertmanager, and ThanosRuler.
- [#1752](https://github.com/openshift/cluster-monitoring-operator/pull/1752) Add option to improve consistency of prometheus-adapter CPU and RAM time series.
- [#1803](https://github.com/openshift/cluster-monitoring-operator/pull/1803) Add alert TelemeterClientFailures
- [#1836](https://github.com/openshift/cluster-monitoring-operator/pull/1836) PVC configuration link points to document specific to the cluster version

## 4.11
- [#1652](https://github.com/openshift/cluster-monitoring-operator/pull/1652) Double scrape interval for all CMO controlled ServiceMonitors on single node deployments
- [#1567](https://github.com/openshift/cluster-monitoring-operator/pull/1567) Enable validating webhook for AlertmanagerConfig custom resources
- [#1557](https://github.com/openshift/cluster-monitoring-operator/pull/1557) Removing grafana from monitoring stack
- [#1578](https://github.com/openshift/cluster-monitoring-operator/pull/1578) Add temporary cluster id label to remotely write relabel configs.
- [#1350](https://github.com/openshift/cluster-monitoring-operator/pull/1350) Support label scrape limits in user-workload monitoring
- [#1601](https://github.com/openshift/cluster-monitoring-operator/pull/1601) Expose the /federate endpoint of UWM Prometheus as a service
- [#1617](https://github.com/openshift/cluster-monitoring-operator/pull/1617) Add Oauth2 setting to PrometheusK8s remoteWrite config
- [#1598](https://github.com/openshift/cluster-monitoring-operator/pull/1598) Expose Authorization settings for remote write in the CMO configuration
- [#1633](https://github.com/openshift/cluster-monitoring-operator/pull/1633) Expose the /federate endpoint of UWM Prometheus as a route
- [#1638](https://github.com/openshift/cluster-monitoring-operator/pull/1638) Expose sigv4 setting to Prometheus remoteWrite
- [#1579](https://github.com/openshift/cluster-monitoring-operator/pull/1579) Expose retention size settings for Platform Prometheus
- [#1630](https://github.com/openshift/cluster-monitoring-operator/pull/1630) Expose retention size settings for UWM Prometheus
- [#1640](https://github.com/openshift/cluster-monitoring-operator/pull/1640) Deploy standalone admission webhook for HA.
- [#1651](https://github.com/openshift/cluster-monitoring-operator/pull/1651) Allow retention to be configurable for Thanos-Ruler in UWM
- [#1467](https://github.com/openshift/cluster-monitoring-operator/pull/1467) Add bodysize limit for metric scraping
- [#1661](https://github.com/openshift/cluster-monitoring-operator/pull/1661) Support deployment of dedicated Alertmanager for user-defined alerts.
- [#1682](https://github.com/openshift/cluster-monitoring-operator/pull/1682) Support AlertmanagerConfig v1beta1.

## 4.10

- [#1509](https://github.com/openshift/cluster-monitoring-operator/pull/1509) add NLB usage metrics for network edge
- [#1299](https://github.com/openshift/cluster-monitoring-operator/pull/1299) Expose /api/v1/labels and /api/v1/labels/*/values endpoint on the Thanos query tenancy port.
- [#1529](https://github.com/openshift/cluster-monitoring-operator/pull/1299) Expose /api/v1/series endpoint on the Thanos query tenancy port.
- [#1402](https://github.com/openshift/cluster-monitoring-operator/pull/1402) Drop pod-centric cAdvisor metrics that are available at slice level.
- [#1399](https://github.com/openshift/cluster-monitoring-operator/pull/1399) Rename ThanosSidecarUnhealthy to ThanosSidecarNoConnectionToStartedPrometheus and make it resilient to WAL replays.
- [#1446](https://github.com/openshift/cluster-monitoring-operator/pull/1446) Bump Grafana version to 7.5.11
- [#1439](https://github.com/openshift/cluster-monitoring-operator/pull/1439) Expose PodDisruptionBudget labels from kube-state-metrics metrics.
- [#1377](https://github.com/openshift/cluster-monitoring-operator/pull/1377) Allow OpenShift users to configure audit logs for prometheus-adapter
- [#1481](https://github.com/openshift/cluster-monitoring-operator/pull/1481) Removing one of the AlertmanagerClusterFailedToSendAlerts alerts
- [#1373](https://github.com/openshift/cluster-monitoring-operator/pull/1373) Enable admins to toggle the [query_log_file](https://prometheus.io/docs/guides/query-log/#enable-the-query-log) setting for Prometheus.
- [#1491](https://github.com/openshift/cluster-monitoring-operator/pull/1491) Rename alerts `AggregatedAPIErrors to KubeAggregatedAPIErrors` and `AggregatedAPIDown to KubeAggregatedAPIDown`.
- [#1488](https://github.com/openshift/cluster-monitoring-operator/pull/1488) Removing the alert HighlyAvailableWorkloadIncorrectlySpread.
- [#1858](https://github.com/openshift/cluster-monitoring-operator/pull/1858) Allow suppression of storage alerts via PersistentVolumeClaim label
- [#1527](https://github.com/openshift/cluster-monitoring-operator/pull/1527) Enable user alerts via AlertManagerConfig to be forwarded to the existing Platform Alertmanager
- [#1543](https://github.com/openshift/cluster-monitoring-operator/pull/1543) Bump Grafana version to v8.3.4
- [#1545](https://github.com/openshift/cluster-monitoring-operator/pull/1545) Add ClusterRole to allow editing of AlertManagerConfig

## 4.9

- [#1312](https://github.com/openshift/cluster-monitoring-operator/pull/1312) Support label to exclude namespaces from user-workload monitoring.
- [#1308](https://github.com/openshift/cluster-monitoring-operator/pull/1308) Expose remote_write to user for in-cluster deployment and UWM.
- [#1241](https://github.com/openshift/cluster-monitoring-operator/pull/1241) Add config option to disable Grafana deployment.
- [#1278](https://github.com/openshift/cluster-monitoring-operator/pull/1278) Add EnforcedTargetLimit option for user-workload Prometheus.
- [#1291](https://github.com/openshift/cluster-monitoring-operator/pull/1291) Drop high cardinality cAdvisor metrics via [kube-prometheus #1250](https://github.com/prometheus-operator/kube-prometheus/pull/1250)
- [#1270](https://github.com/openshift/cluster-monitoring-operator/pull/1270) Show a message in the degraded condition when Platform Monitoring Prometheus runs without persistent storage.
- [#1241](https://github.com/openshift/cluster-monitoring-operator/pull/1241) Allow configuring additional Alertmanagers in User Workload Prometheus and Thanos Ruler.
- [#1293](https://github.com/openshift/cluster-monitoring-operator/pull/1270) Allow disabling the local Alertmanager.
- [#1310](https://github.com/openshift/cluster-monitoring-operator/pull/1310) Update Alert Configs, fewer critical alerts with more accurate triggering condition.
- [#1324](https://github.com/openshift/cluster-monitoring-operator/pull/1324) Allow filtering by job in 'Prometheus/Overview' dashboard.

## 4.8

- [#1087](https://github.com/openshift/cluster-monitoring-operator/pull/1087) Decrease alert severity to "warning" for ThanosQueryHttpRequestQueryErrorRateHigh and ThanosQueryHttpRequestQueryRangeErrorRateHigh alerts.
- [#1087](https://github.com/openshift/cluster-monitoring-operator/pull/1087) Increase "for" duration to 1 hour for all Thanos query alerts.
- [#1087](https://github.com/openshift/cluster-monitoring-operator/pull/1087) Remove ThanosQueryInstantLatencyHigh and ThanosQueryRangeLatencyHigh alerts.
- [#1090](https://github.com/openshift/cluster-monitoring-operator/pull/1090) Decrease alert severity to "warning" for all Thanos sidecar alerts.
- [#1090](https://github.com/openshift/cluster-monitoring-operator/pull/1090) Increase "for" duration to 1 hour for all Thanos sidecar alerts.
- [#1093](https://github.com/openshift/cluster-monitoring-operator/pull/1093) Bump kube-state-metrics to major new release v2.0.0-rc.1. This changes a lot of metrics and flags, see kube-state-metrics CHANGELOG for full changes.
- [#1126](https://github.com/openshift/cluster-monitoring-operator/pull/1126) Remove deprecated techPreviewUserWorkload field from CMO's configmap.
- [#1136](https://github.com/openshift/cluster-monitoring-operator/pull/1136) Add recording rule for builds by strategy
- [#1210](https://github.com/openshift/cluster-monitoring-operator/pull/1210) Bump Grafana version to 7.5.5

## 4.7

- [#963](https://github.com/openshift/cluster-monitoring-operator/pull/963) bump mixins to include new etcd alerts
  - Added etcdBackendQuotaLowSpace, etcdExcessiveDatabaseGrowth, and etcdHighFsyncDurations critical alert.
  - Adjusted NodeClockNotSynchronising, NodeNetworkReceiveErrs, and NodeNetworkTransmitErrs alerts.
- [#962](https://github.com/openshift/cluster-monitoring-operator/pull/962) Enable namespace by pod and pod total networking Grafana dashboards.
- [#959](https://github.com/openshift/cluster-monitoring-operator/pull/959) Remove memory limits from prometheus-config-reloader in user workload monitoring
- [#969](https://github.com/openshift/cluster-monitoring-operator/pull/969) Bump Thanos v0.16.0
- [#970](https://github.com/openshift/cluster-monitoring-operator/pull/970) Bump prometheus-operator v0.43.0.
- [#971](https://github.com/openshift/cluster-monitoring-operator/pull/971) Enable `hwmon` in node-exporter for hardware sensor data collection
- [#983](https://github.com/openshift/cluster-monitoring-operator/pull/983) Remove deprecated user workload configuration
- [#995](https://github.com/openshift/cluster-monitoring-operator/pull/995) Add logLevel config field to Thanos Query.
- [#993](https://github.com/openshift/cluster-monitoring-operator/pull/993) Add metrics + alerts for Thanos sidecars.
- [#1013](https://github.com/openshift/cluster-monitoring-operator/pull/1013) [#1018](https://github.com/openshift/cluster-monitoring-operator/pull/1018) Bump and pin jsonnet dependencies:
  - prometheus-operator v0.44.1
  - Thanos: v0.17.2
  - kube-prometheus: release-0.7

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
- [#894](https://github.com/openshift/cluster-monitoring-operator/pull/894) Bump jsonnet dependencies:
  - kubernetes-mixin: https://github.com/kubernetes-monitoring/kubernetes-mixin/pull/475: alerts: adjust error message accordingly to recent change
  - prometheus-operator: https://github.com/coreos/kube-prometheus/pull/610: Add PrometheusOperatorListErrors and fix PrometheusOperatorWatchErrors threshold
  - etcd: https://github.com/etcd-io/etcd/pull/12122: Documentation/etcd-mixin: Reformulate alerting rules to use `without` rather than `by`
  - kubelet: https://github.com/coreos/kube-prometheus/pull/623: Add scraping of endpoint for kubelet probe metrics
  - thanos: https://github.com/thanos-io/thanos/pull/2374: mixin: Added critical Rules alerts.
- [#898](https://github.com/openshift/cluster-monitoring-operator/pull/898) Bump jsonnet dependencies for kube-mixin:
  - Adjusts severity levels of many alerts from critical to warning as they were cause based alerts
  - Adjusts KubeStatefulSetUpdateNotRolledOut, KubeDaemonSetRolloutStuck
  - Removes KubeAPILatencyHigh and KubeAPIErrorsHigh
