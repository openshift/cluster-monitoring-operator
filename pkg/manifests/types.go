// Copyright 2022 The Cluster Monitoring Operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package manifests

import (
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	v1 "k8s.io/api/core/v1"
)

type CollectionProfile string
type CollectionProfiles []CollectionProfile

const (
	FullCollectionProfile    = "full"
	MinimalCollectionProfile = "minimal"
)

var SupportedCollectionProfiles = CollectionProfiles{FullCollectionProfile, MinimalCollectionProfile}

// The `ClusterMonitoringConfiguration` resource defines settings that
// customize the default platform monitoring stack through the
// `cluster-monitoring-config` config map in the `openshift-monitoring`
// namespace.
type ClusterMonitoringConfiguration struct {
	// `AlertmanagerMainConfig` defines settings for the
	// Alertmanager component in the `openshift-monitoring` namespace.
	AlertmanagerMainConfig *AlertmanagerMainConfig `json:"alertmanagerMain,omitempty"`
	// `UserWorkloadEnabled` is a Boolean flag that enables monitoring for user-defined projects.
	UserWorkloadEnabled *bool `json:"enableUserWorkload,omitempty"`
	// `UserWorkload` defines settings for the monitoring of user-defined projects.
	UserWorkload *UserWorkloadConfig `json:"userWorkload,omitempty"`
	// OmitFromDoc
	HTTPConfig *HTTPConfig `json:"http,omitempty"`
	// OmitFromDoc: `K8sPrometheusAdapter` defines settings for the Prometheus Adapter component.
	K8sPrometheusAdapter *K8sPrometheusAdapter `json:"k8sPrometheusAdapter,omitempty"`
	// `MetricsServer` defines settings for the MetricsServer component.
	MetricsServerConfig *MetricsServerConfig `json:"metricsServer,omitempty"`
	// `KubeStateMetricsConfig` defines settings for the `kube-state-metrics` agent.
	KubeStateMetricsConfig *KubeStateMetricsConfig `json:"kubeStateMetrics,omitempty"`
	// `PrometheusK8sConfig` defines settings for the Prometheus component.
	PrometheusK8sConfig *PrometheusK8sConfig `json:"prometheusK8s,omitempty"`
	// `PrometheusOperatorConfig` defines settings for the Prometheus Operator component.
	PrometheusOperatorConfig *PrometheusOperatorConfig `json:"prometheusOperator,omitempty"`
	// `PrometheusOperatorAdmissionWebhookConfig` defines settings for the Prometheus Operator's admission webhook component.
	PrometheusOperatorAdmissionWebhookConfig *PrometheusOperatorAdmissionWebhookConfig `json:"prometheusOperatorAdmissionWebhook,omitempty"`
	// `OpenShiftMetricsConfig` defines settings for the `openshift-state-metrics` agent.
	OpenShiftMetricsConfig *OpenShiftStateMetricsConfig `json:"openshiftStateMetrics,omitempty"`
	// `TelemeterClientConfig` defines settings for the Telemeter Client
	// component.
	TelemeterClientConfig *TelemeterClientConfig `json:"telemeterClient,omitempty"`
	// `ThanosQuerierConfig` defines settings for the Thanos Querier component.
	ThanosQuerierConfig *ThanosQuerierConfig `json:"thanosQuerier,omitempty"`
	// `NodeExporterConfig` defines settings for the `node-exporter` agent.
	NodeExporterConfig NodeExporterConfig `json:"nodeExporter,omitempty"`
	// `MonitoringPluginConfig` defines settings for the monitoring `console-plugin`.
	MonitoringPluginConfig *MonitoringPluginConfig `json:"monitoringPlugin,omitempty"`
}

// The `UserWorkloadConfig` resource defines settings for the monitoring of
// user-defined projects.
type UserWorkloadConfig struct {
	// A Boolean flag that enables or disables the ability to deploy
	// user-defined `PrometheusRules` objects for which the `namespace` label
	// isn't enforced to the namespace of the object. Such objects should be
	// created in a namespace configured under the
	// `namespacesWithoutLabelEnforcement` property of the
	// `UserWorkloadConfiguration` resource.
	// The default value is `true`.
	RulesWithoutLabelEnforcementAllowed *bool `json:"rulesWithoutLabelEnforcementAllowed,omitempty"`
}

// The `AlertmanagerMainConfig` resource defines settings for the
// Alertmanager component in the `openshift-monitoring` namespace.
type AlertmanagerMainConfig struct {
	// A Boolean flag that enables or disables the main Alertmanager instance
	// in the `openshift-monitoring` namespace.
	// The default value is `true`.
	Enabled *bool `json:"enabled,omitempty"`
	// A Boolean flag that enables or disables user-defined namespaces
	// to be selected for `AlertmanagerConfig` lookups. This setting only
	// applies if the user workload monitoring instance of Alertmanager
	// is not enabled.
	// The default value is `false`.
	EnableUserAlertManagerConfig bool `json:"enableUserAlertmanagerConfig,omitempty"`
	// Defines the log level setting for Alertmanager.
	// The possible values are: `error`, `warn`, `info`, `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines the nodes on which the Pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for the Alertmanager container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines a list of secrets that need to be mounted into the Alertmanager.
	// The secrets must reside within the same namespace as the Alertmanager object.
	// They will be added as volumes named secret-<secret-name> and mounted at
	// /etc/alertmanager/secrets/<secret-name> within the 'alertmanager' container of
	// the Alertmanager Pods.
	Secrets []string `json:"secrets,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Defines persistent storage for Alertmanager. Use this setting to
	// configure the persistent volume claim, including storage class, volume
	// size, and name.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// The `K8sPrometheusAdapter` resource defines settings for the Prometheus Adapter component.
// This is deprecated config, setting this has no effect and will be removed in a future version.
// TODO: Remove this in 4.19. We should block upgrades till config is been removed
type K8sPrometheusAdapter struct {
	// Defines the audit configuration used by the Prometheus Adapter instance.
	// Possible profile values are: `metadata`, `request`, `requestresponse`, and `none`.
	// The default value is `metadata`.
	Audit *Audit `json:"audit,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for the PrometheusAdapter container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// OmitFromDoc: Defines dedicated service monitors.
	DedicatedServiceMonitors *DedicatedServiceMonitors `json:"dedicatedServiceMonitors,omitempty"`
}

// The `MetricsServerConfig` resource defines settings for the Metrics Server component.
type MetricsServerConfig struct {
	// Defines the audit configuration used by the Metrics Server instance.
	// Possible profile values are: `metadata`, `request`, `requestresponse`, and `none`.
	// The default value is `metadata`.
	Audit *Audit `json:"audit,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines resource requests and limits for the Metrics Server container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// OmitFromDoc: This is deprecated and will be removed in a future version, setting it has no effect.
type DedicatedServiceMonitors struct {
	Enabled bool `json:"enabled,omitempty"`
}

// The `KubeStateMetricsConfig` resource defines settings for the
// `kube-state-metrics` agent.
type KubeStateMetricsConfig struct {
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for the KubeStateMetrics container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// The `PrometheusK8sConfig` resource defines settings for the Prometheus
// component.
type PrometheusK8sConfig struct {
	// Configures additional Alertmanager instances that receive alerts from
	// the Prometheus component. By default, no additional Alertmanager
	// instances are configured.
	AlertmanagerConfigs []AdditionalAlertmanagerConfig `json:"additionalAlertmanagerConfigs,omitempty"`
	// Enforces a body size limit for Prometheus scraped metrics. If a scraped
	// target's body response is larger than the limit, the scrape will fail.
	// The following values are valid:
	// an empty value to specify no limit,
	// a numeric value in Prometheus size format (such as `64MB`), or
	// the string `automatic`, which indicates that the limit will be
	// automatically calculated based on cluster capacity.
	// The default value is empty, which indicates no limit.
	EnforcedBodySizeLimit string `json:"enforcedBodySizeLimit,omitempty"`
	// Defines labels to be added to any time series or alerts when
	// communicating with external systems such as federation, remote storage,
	// and Alertmanager. By default, no labels are added.
	ExternalLabels map[string]string `json:"externalLabels,omitempty"`
	// Defines the log level setting for Prometheus.
	// The possible values are: `error`, `warn`, `info`, and `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Specifies the file to which PromQL queries are logged.
	// This setting can be either a filename, in which
	// case the queries are saved to an `emptyDir` volume
	// at `/var/log/prometheus`, or a full path to a location where
	// an `emptyDir` volume will be mounted and the queries saved.
	// Writing to `/dev/stderr`, `/dev/stdout` or `/dev/null` is supported, but
	// writing to any other `/dev/` path is not supported. Relative paths are
	// also not supported.
	// By default, PromQL queries are not logged.
	QueryLogFile string `json:"queryLogFile,omitempty"`
	// Defines the remote write configuration, including URL, authentication,
	// and relabeling settings.
	RemoteWrite []RemoteWriteSpec `json:"remoteWrite,omitempty"`
	// Defines resource requests and limits for the Prometheus container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines the duration for which Prometheus retains data.
	// This definition must be specified using the following regular
	// expression pattern: `[0-9]+(ms|s|m|h|d|w|y)` (ms = milliseconds,
	// s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years).
	// The default value is `15d`.
	Retention string `json:"retention,omitempty"`
	// Defines the maximum amount of disk space used by data blocks plus the
	// write-ahead log (WAL).
	// Supported values are `B`, `KB`, `KiB`, `MB`, `MiB`, `GB`, `GiB`, `TB`,
	// `TiB`, `PB`, `PiB`, `EB`, and `EiB`.
	// By default, no limit is defined.
	RetentionSize string `json:"retentionSize,omitempty"`
	// OmitFromDoc
	TelemetryMatches []string `json:"-"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines the pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Defines the metrics collection profile that Prometheus uses to collect
	// metrics from the platform components. Supported values are `full` or
	// `minimal`. In the `full` profile (default), Prometheus collects all
	// metrics that are exposed by the platform components. In the `minimal`
	// profile, Prometheus only collects metrics necessary for the default
	// platform alerts, recording rules, telemetry and console dashboards.
	CollectionProfile CollectionProfile `json:"collectionProfile,omitempty"`
	// Defines persistent storage for Prometheus. Use this setting to
	// configure the persistent volume claim, including storage class,
	// volume size and name.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// The `PrometheusOperatorConfig` resource defines settings for the Prometheus
// Operator component.
type PrometheusOperatorConfig struct {
	// Defines the log level settings for Prometheus Operator.
	// The possible values are `error`, `warn`, `info`, and `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for the PrometheusOperator container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// The `OpenShiftStateMetricsConfig` resource defines settings for the
// `openshift-state-metrics` agent.
type OpenShiftStateMetricsConfig struct {
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for the OpenShiftStateMetrics container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// `TelemeterClientConfig` defines settings for the Telemeter Client
// component.
type TelemeterClientConfig struct {
	// OmitFromDoc
	ClusterID string `json:"clusterID,omitempty"`
	// OmitFromDoc
	Enabled *bool `json:"enabled,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector"`
	// Defines resource requests and limits for the TelemeterClient container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// OmitFromDoc
	TelemeterServerURL string `json:"telemeterServerURL,omitempty"`
	// OmitFromDoc
	Token string `json:"token,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// The `ThanosQuerierConfig` resource defines settings for the Thanos Querier
// component.
type ThanosQuerierConfig struct {
	// A Boolean flag that enables or disables request logging.
	// The default value is `false`.
	EnableRequestLogging bool `json:"enableRequestLogging,omitempty"`
	// Defines the log level setting for Thanos Querier.
	// The possible values are `error`, `warn`, `info`, and `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// A Boolean flag that enables setting CORS headers.
	// The headers would allow access from any origin.
	// The default value is `false`.
	EnableCORS bool `json:"enableCORS,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for the Thanos Querier container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// The `NodeExporterConfig` resource defines settings for the `node-exporter` agent.
type NodeExporterConfig struct {
	// Defines which collectors are enabled and their additional configuration parameters.
	Collectors NodeExporterCollectorConfig `json:"collectors,omitempty"`
	// The target number of CPUs on which the Node Exporter's process will run.
	// Use this setting to override the default value, which is set either to `4` or to the number of CPUs on the host, whichever is smaller.
	// The default value is computed at runtime and set via the `GOMAXPROCS` environment variable before Node Exporter is launched.
	// If a kernel deadlock occurs or if performance degrades when reading from `sysfs` concurrently,
	// you can change this value to `1`, which limits Node Exporter to running on one CPU.
	// For nodes with a high CPU count, setting the limit to a low number saves resources by preventing Go routines from being scheduled to run on all CPUs.
	// However, I/O performance degrades if the `maxProcs` value is set too low, and there are many metrics to collect.
	MaxProcs uint32 `json:"maxProcs,omitempty"`
	// A list of network devices, as regular expressions, to be excluded from the relevant collector configuration such as `netdev` and `netclass`.
	// When not set, the Cluster Monitoring Operator uses a predefined list of devices to be excluded to minimize the impact on memory usage.
	// When set as an empty list, no devices are excluded.
	// If you modify this setting, monitor the `prometheus-k8s` deployment closely for excessive memory usage.
	IgnoredNetworkDevices *[]string `json:"ignoredNetworkDevices,omitempty"`
	// Defines resource requests and limits for the NodeExporter container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
}

// The `NodeExporterCollectorConfig` resource defines settings for individual collectors
// of the `node-exporter` agent.
type NodeExporterCollectorConfig struct {
	// Defines the configuration of the `cpufreq` collector, which collects CPU frequency statistics.
	// Disabled by default.
	CpuFreq NodeExporterCollectorCpufreqConfig `json:"cpufreq,omitempty"`
	// Defines the configuration of the `tcpstat` collector, which collects TCP connection statistics.
	// Disabled by default.
	TcpStat NodeExporterCollectorTcpStatConfig `json:"tcpstat,omitempty"`
	// Defines the configuration of the `netdev` collector, which collects network devices statistics.
	// Enabled by default.
	NetDev NodeExporterCollectorNetDevConfig `json:"netdev,omitempty"`
	// Defines the configuration of the `netclass` collector, which collects information about network devices.
	// Enabled by default.
	NetClass NodeExporterCollectorNetClassConfig `json:"netclass,omitempty"`
	// Defines the configuration of the `buddyinfo` collector, which collects statistics about memory fragmentation from the `node_buddyinfo_blocks` metric. This metric collects data from `/proc/buddyinfo`.
	// Disabled by default.
	BuddyInfo NodeExporterCollectorBuddyInfoConfig `json:"buddyinfo,omitempty"`
	// Defines the configuration of the `mountstats` collector, which collects statistics about NFS volume I/O activities.
	// Disabled by default.
	MountStats NodeExporterCollectorMountStatsConfig `json:"mountstats,omitempty"`
	// Defines the configuration of the `ksmd` collector, which collects statistics from the kernel same-page merger daemon.
	// Disabled by default.
	Ksmd NodeExporterCollectorKSMDConfig `json:"ksmd,omitempty"`
	// Defines the configuration of the `processes` collector, which collects statistics from processes and threads running in the system.
	// Disabled by default.
	Processes NodeExporterCollectorProcessesConfig `json:"processes,omitempty"`
	// Defines the configuration of the `sysctl` collector, which collects sysctl metrics.
	// Disabled by default.
	Sysctl NodeExporterCollectorSysctlConfig `json:"sysctl,omitempty"`
	// Defines the configuration of the `systemd` collector, which collects statistics on the systemd daemon and its managed services.
	// Disabled by default.
	Systemd NodeExporterCollectorSystemdConfig `json:"systemd,omitempty"`
}

// The `NodeExporterCollectorCpufreqConfig` resource works as an on/off switch for
// the `cpufreq` collector of the `node-exporter` agent.
// By default, the `cpufreq` collector is disabled.
// Under certain circumstances, enabling the cpufreq collector increases CPU usage on machines with many cores.
// If you enable this collector and have machines with many cores, monitor your systems closely for excessive CPU usage.
// Please refer to https://github.com/prometheus/node_exporter/issues/1880 for more details.
// A related bug: https://bugzilla.redhat.com/show_bug.cgi?id=1972076
type NodeExporterCollectorCpufreqConfig struct {
	// A Boolean flag that enables or disables the `cpufreq` collector.
	Enabled bool `json:"enabled,omitempty"`
}

// The `NodeExporterCollectorTcpStatConfig` resource works as an on/off switch for
// the `tcpstat` collector of the `node-exporter` agent.
// By default, the `tcpstat` collector is disabled.
type NodeExporterCollectorTcpStatConfig struct {
	// A Boolean flag that enables or disables the `tcpstat` collector.
	Enabled bool `json:"enabled,omitempty"`
}

// The `NodeExporterCollectorSysctlConfig` resource works as an on/off switch for
// the `sysctl` collector of the `node-exporter` agent.
// Caution! Exposing metrics like kernel.random.uuid can disrupt Prometheus, as it generates new data series with every scrape. Use this option judiciously!
// By default, the `sysctl` collector is disabled.
type NodeExporterCollectorSysctlConfig struct {
	// A Boolean flag that enables or disables the `sysctl` collector.
	Enabled bool `json:"enabled,omitempty"`
	// A list of numeric sysctl values.
	// Note that a sysctl can contain multiple values, for example:
	// `net.ipv4.tcp_rmem = 4096	131072	6291456`.
	// Using `includeSysctlMetrics: ['net.ipv4.tcp_rmem']` the collector will expose:
	// `node_sysctl_net_ipv4_tcp_rmem{index="0"} 4096`,
	// `node_sysctl_net_ipv4_tcp_rmem{index="1"} 131072`,
	// `node_sysctl_net_ipv4_tcp_rmem{index="2"} 6291456`.
	// If the indexes have defined meaning like in this case, the values can be mapped to multiple metrics:
	// `includeSysctlMetrics: ['net.ipv4.tcp_rmem:min,default,max']`.
	// The collector will expose these metrics as such:
	// `node_sysctl_net_ipv4_tcp_rmem_min 4096`,
	// `node_sysctl_net_ipv4_tcp_rmem_default 131072`,
	// `node_sysctl_net_ipv4_tcp_rmem_max 6291456`.
	IncludeSysctlMetrics []string `json:"includeSysctlMetrics,omitempty"`
	// A list of string sysctl values.
	// For example:
	// `includeSysctlMetrics: ['kernel.core_pattern', 'kernel.seccomp.actions_avail = kill_process kill_thread']`.
	// The collector will expose these metrics as such:
	// `node_sysctl_info{name="kernel.core_pattern", value="core"} 1`,
	// `node_sysctl_info{name="kernel.seccomp.actions_avail", index="0", value="kill_process"} 1`,
	// `node_sysctl_info{name="kernel.seccomp.actions_avail", index="1", value="kill_thread"} 1`,
	// ...
	IncludeInfoSysctlMetrics []string `json:"includeInfoSysctlMetrics,omitempty"`
}

// The `NodeExporterCollectorNetDevConfig` resource works as an on/off switch for
// the `netdev` collector of the `node-exporter` agent.
// By default, the `netdev` collector is enabled.
// If disabled, these metrics become unavailable:
// `node_network_receive_bytes_total`,
// `node_network_receive_compressed_total`,
// `node_network_receive_drop_total`,
// `node_network_receive_errs_total`,
// `node_network_receive_fifo_total`,
// `node_network_receive_frame_total`,
// `node_network_receive_multicast_total`,
// `node_network_receive_nohandler_total`,
// `node_network_receive_packets_total`,
// `node_network_transmit_bytes_total`,
// `node_network_transmit_carrier_total`,
// `node_network_transmit_colls_total`,
// `node_network_transmit_compressed_total`,
// `node_network_transmit_drop_total`,
// `node_network_transmit_errs_total`,
// `node_network_transmit_fifo_total`,
// `node_network_transmit_packets_total`.
type NodeExporterCollectorNetDevConfig struct {
	// A Boolean flag that enables or disables the `netdev` collector.
	Enabled bool `json:"enabled,omitempty"`
}

// The `NodeExporterCollectorNetClassConfig` resource works as an on/off switch for
// the `netclass` collector of the `node-exporter` agent.
// By default, the `netclass` collector is enabled.
// If disabled, these metrics become unavailable:
// `node_network_info`,
// `node_network_address_assign_type`,
// `node_network_carrier`,
// `node_network_carrier_changes_total`,
// `node_network_carrier_up_changes_total`,
// `node_network_carrier_down_changes_total`,
// `node_network_device_id`,
// `node_network_dormant`,
// `node_network_flags`,
// `node_network_iface_id`,
// `node_network_iface_link`,
// `node_network_iface_link_mode`,
// `node_network_mtu_bytes`,
// `node_network_name_assign_type`,
// `node_network_net_dev_group`,
// `node_network_speed_bytes`,
// `node_network_transmit_queue_length`,
// `node_network_protocol_type`.
type NodeExporterCollectorNetClassConfig struct {
	// A Boolean flag that enables or disables the `netclass` collector.
	Enabled bool `json:"enabled,omitempty"`
	// A Boolean flag that activates the `netlink` implementation of the `netclass` collector.
	// Its default value is `true`: activating the netlink mode.
	// This implementation improves the performance of the `netclass` collector.
	UseNetlink bool `json:"useNetlink,omitempty"`
}

// The `NodeExporterCollectorBuddyInfoConfig` resource works as an on/off switch for
// the `buddyinfo` collector of the `node-exporter` agent.
// By default, the `buddyinfo` collector is disabled.
type NodeExporterCollectorBuddyInfoConfig struct {
	// A Boolean flag that enables or disables the `buddyinfo` collector.
	Enabled bool `json:"enabled,omitempty"`
}

// The `NodeExporterCollectorMountStatsConfig` resource works as an on/off switch for
// the `mountstats` collector of the `node-exporter` agent.
// By default, the `mountstats` collector is disabled.
// If enabled, these metrics become available:
//
//	`node_mountstats_nfs_read_bytes_total`,
//	`node_mountstats_nfs_write_bytes_total`,
//	`node_mountstats_nfs_operations_requests_total`.
//
// Please be aware that these metrics can have a high cardinality.
// If you enable this collector, closely monitor any increases in memory usage for the `prometheus-k8s` pods.
type NodeExporterCollectorMountStatsConfig struct {
	// A Boolean flag that enables or disables the `mountstats` collector.
	Enabled bool `json:"enabled,omitempty"`
}

// The `NodeExporterCollectorKSMDConfig` resource works as an on/off switch for
// the `ksmd` collector of the `node-exporter` agent.
// By default, the `ksmd` collector is disabled.
type NodeExporterCollectorKSMDConfig struct {
	// A Boolean flag that enables or disables the `ksmd` collector.
	Enabled bool `json:"enabled,omitempty"`
}

// The `NodeExporterCollectorProcessesConfig` resource works as an on/off switch for
// the `processes` collector of the `node-exporter` agent.
// If enabled, these metrics become available:
// `node_processes_max_processes`,
// `node_processes_pids`,
// `node_processes_state`,
// `node_processes_threads`,
// `node_processes_threads_state`.
// The metric `node_processes_state` and `node_processes_threads_state` can have up to 5 series each,
// depending on the state of the processes and threads.
// The possible states of a process or a thread are:
// 'D' (UNINTERRUPTABLE_SLEEP),
// 'R' (RUNNING & RUNNABLE),
// 'S' (INTERRRUPTABLE_SLEEP),
// 'T' (STOPPED),
// 'Z' (ZOMBIE).
// By default, the `processes` collector is disabled.
type NodeExporterCollectorProcessesConfig struct {
	// A Boolean flag that enables or disables the `processes` collector.
	Enabled bool `json:"enabled,omitempty"`
}

// The `NodeExporterCollectorSystemdConfig` resource works as an on/off switch for
// the `systemd` collector of the `node-exporter` agent.
// By default, the `systemd` collector is disabled.
// If enabled, the following metrics become available:
// `node_systemd_system_running`,
// `node_systemd_units`,
// `node_systemd_version`.
// If the unit uses a socket, it also generates these 3 metrics:
// `node_systemd_socket_accepted_connections_total`,
// `node_systemd_socket_current_connections`,
// `node_systemd_socket_refused_connections_total`.
// You can use the `units` parameter to select the systemd units to be included by the `systemd` collector.
// The selected units are used to generate the `node_systemd_unit_state` metric, which shows the state of each systemd unit.
// The timer units such as `logrotate.timer` generate one more metric `node_systemd_timer_last_trigger_seconds`.
// However, this metric's cardinality might be high (at least 5 series per unit per node).
// If you enable this collector with a long list of selected units, closely monitor the `prometheus-k8s` deployment for excessive memory usage.
type NodeExporterCollectorSystemdConfig struct {
	// A Boolean flag that enables or disables the `systemd` collector.
	Enabled bool `json:"enabled,omitempty"`
	// A list of regular expression (regex) patterns that match systemd units to be included by the `systemd` collector.
	// By default, the list is empty, so the collector exposes no metrics for systemd units.
	Units []string `json:"units,omitempty"`
}

// The `UserWorkloadConfiguration` resource defines the settings
// responsible for user-defined projects in the
// `user-workload-monitoring-config` config map  in the
// `openshift-user-workload-monitoring` namespace. You can only enable
// `UserWorkloadConfiguration` after you have set `enableUserWorkload` to
// `true` in the `cluster-monitoring-config` config map under the
// `openshift-monitoring` namespace.
type UserWorkloadConfiguration struct {
	// Defines the settings for the Alertmanager component in user workload
	// monitoring.
	Alertmanager *AlertmanagerUserWorkloadConfig `json:"alertmanager,omitempty"`
	// Defines the settings for the Prometheus component in user workload
	// monitoring.
	Prometheus *PrometheusRestrictedConfig `json:"prometheus,omitempty"`
	// Defines the settings for the Prometheus Operator component in user
	// workload monitoring.
	PrometheusOperator *PrometheusOperatorConfig `json:"prometheusOperator,omitempty"`
	// Defines the settings for the Thanos Ruler component in user workload
	// monitoring.
	ThanosRuler *ThanosRulerConfig `json:"thanosRuler,omitempty"`

	// Defines the list of namespaces for which Prometheus and Thanos Ruler in
	// user-defined monitoring don't enforce the `namespace` label value in
	// `PrometheusRule` objects.
	//
	// It allows to define recording and alerting rules that can query across
	// multiple projects (not limited to user-defined projects) instead of
	// deploying identical `PrometheusRule` objects in each user project.
	//
	// To make the resulting alerts and metrics visible to project users, the
	// query expressions should return a `namespace` label with a non-empty
	// value.
	NamespacesWithoutLabelEnforcement []string `json:"namespacesWithoutLabelEnforcement,omitempty"`
}

// The `AlertmanagerUserWorkloadConfig` resource defines the settings for the Alertmanager instance used for user-defined projects.
type AlertmanagerUserWorkloadConfig struct {
	// A Boolean flag that enables or disables a dedicated instance of
	// Alertmanager for user-defined alerts in the
	// `openshift-user-workload-monitoring` namespace.
	// The default value is `false`.
	Enabled bool `json:"enabled,omitempty"`
	// A Boolean flag to enable or disable user-defined namespaces
	// to be selected for `AlertmanagerConfig` lookup.
	// The default value is `false`.
	EnableAlertmanagerConfig bool `json:"enableAlertmanagerConfig,omitempty"`
	// Defines the log level setting for Alertmanager for user workload
	// monitoring.
	// The possible values are `error`, `warn`, `info`, and `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines resource requests and limits for the Alertmanager container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines a list of secrets that need to be mounted into the Alertmanager.
	// The secrets must reside within the same namespace as the Alertmanager object.
	// They will be added as volumes named secret-<secret-name> and mounted at
	// /etc/alertmanager/secrets/<secret-name> within the 'alertmanager' container of
	// the Alertmanager Pods.
	Secrets []string `json:"secrets,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Defines persistent storage for Alertmanager. Use this setting to
	// configure the persistent volume claim, including storage class,
	// volume size and name.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// The `PrometheusRestrictedConfig` resource defines the settings for the
// Prometheus component that monitors user-defined projects.
type PrometheusRestrictedConfig struct {
	// Configures the default interval between consecutive scrapes in case the `ServiceMonitor` or `PodMonitor` resource does not specify any value.
	// The interval must be set between 5 seconds and 5 minutes.
	// The value can be expressed in:
	// seconds (for example `30s`.), minutes (for example `1m`.) or a mix of minutes and seconds (for example `1m30s`.).
	// The default value is `30s`.
	ScrapeInterval string `json:"scrapeInterval,omitempty"`
	// Configures the default interval between rule evaluations in case the `PrometheusRule` resource does not specify any value.
	// The interval must be set between 5 seconds and 5 minutes.
	// The value can be expressed in:
	// seconds (for example `30s`.), minutes (for example `1m`.) or a mix of minutes and seconds (for example `1m30s`.).
	// It only applies to `PrometheusRule` resources with the `openshift.io/prometheus-rule-evaluation-scope="leaf-prometheus"` label.
	// The default value is `30s`.
	EvaluationInterval string `json:"evaluationInterval,omitempty"`
	// Configures additional Alertmanager instances that receive alerts from
	// the Prometheus component. By default, no additional Alertmanager
	// instances are configured.
	AlertmanagerConfigs []AdditionalAlertmanagerConfig `json:"additionalAlertmanagerConfigs,omitempty"`
	// Specifies a per-scrape limit on the number of labels accepted for a
	// sample.
	// If the number of labels exceeds this limit after metric relabeling,
	// the entire scrape is treated as failed.
	// The default value is `0`, which means that no limit is set.
	EnforcedLabelLimit *uint64 `json:"enforcedLabelLimit,omitempty"`
	// Specifies a per-scrape limit on the length of a label name for a sample.
	// If the length of a label name exceeds this limit after metric
	// relabeling, the entire scrape is treated as failed.
	// The default value is `0`, which means that no limit is set.
	EnforcedLabelNameLengthLimit *uint64 `json:"enforcedLabelNameLengthLimit,omitempty"`
	// Specifies a per-scrape limit on the length of a label value for
	// a sample. If the length of a label value exceeds this limit after
	// metric relabeling, the entire scrape is treated as failed.
	// The default value is `0`, which means that no limit is set.
	EnforcedLabelValueLengthLimit *uint64 `json:"enforcedLabelValueLengthLimit,omitempty"`
	// Specifies a global limit on the number of scraped samples that will be
	// accepted.
	// This setting overrides the `SampleLimit` value set in any user-defined
	// `ServiceMonitor` or `PodMonitor` object if the value is greater than
	// `enforcedTargetLimit`.
	// Administrators can use this setting to keep the overall number of
	// samples under control.
	// The default value is `0`, which means that no limit is set.
	EnforcedSampleLimit *uint64 `json:"enforcedSampleLimit,omitempty"`
	// Specifies a global limit on the number of scraped targets.
	// This setting overrides the `TargetLimit` value set in any user-defined
	// `ServiceMonitor` or `PodMonitor` object if the value is greater than
	// `enforcedSampleLimit`.
	// Administrators can use this setting to keep the overall number of
	// targets under control.
	// The default value is `0`.
	EnforcedTargetLimit *uint64 `json:"enforcedTargetLimit,omitempty"`
	// Defines labels to be added to any time series or alerts when
	// communicating with external systems such as federation, remote storage,
	// and Alertmanager.
	// By default, no labels are added.
	ExternalLabels map[string]string `json:"externalLabels,omitempty"`
	// Defines the log level setting for Prometheus.
	// The possible values are `error`, `warn`, `info`, and `debug`.
	// The default setting is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Specifies the file to which PromQL queries are logged.
	// This setting can be either a filename, in which
	// case the queries are saved to an `emptyDir` volume
	// at `/var/log/prometheus`, or a full path to a location where
	// an `emptyDir` volume will be mounted and the queries saved.
	// Writing to `/dev/stderr`, `/dev/stdout` or `/dev/null` is supported, but
	// writing to any other `/dev/` path is not supported. Relative paths are
	// also not supported.
	// By default, PromQL queries are not logged.
	QueryLogFile string `json:"queryLogFile,omitempty"`
	// Defines the remote write configuration, including URL, authentication,
	// and relabeling settings.
	RemoteWrite []RemoteWriteSpec `json:"remoteWrite,omitempty"`
	// Defines resource requests and limits for the Prometheus container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines the duration for which Prometheus retains data.
	// This definition must be specified using the following regular
	// expression pattern: `[0-9]+(ms|s|m|h|d|w|y)` (ms = milliseconds,
	// s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years).
	// The default value is `24h`.
	Retention string `json:"retention,omitempty"`
	// Defines the maximum amount of disk space used by data blocks plus the
	// write-ahead log (WAL).
	// Supported values are `B`, `KB`, `KiB`, `MB`, `MiB`, `GB`, `GiB`, `TB`,
	// `TiB`, `PB`, `PiB`, `EB`, and `EiB`.
	// The default value is `nil`.
	RetentionSize string `json:"retentionSize,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Defines persistent storage for Prometheus. Use this setting to
	// configure the storage class and size of a volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// The `ThanosRulerConfig` resource defines configuration for the Thanos Ruler instance for user-defined projects.
type ThanosRulerConfig struct {
	// Configures how the Thanos Ruler component communicates
	// with additional Alertmanager instances.
	// The default value is `nil`.
	AlertmanagersConfigs []AdditionalAlertmanagerConfig `json:"additionalAlertmanagerConfigs,omitempty"`
	// Configures the default interval between Prometheus rule evaluations in case the `PrometheusRule` resource does not specify any value.
	// The interval must be set between 5 seconds and 5 minutes.
	// The value can be expressed in:
	// seconds (for example `30s`.), minutes (for example `1m`.) or a mix of minutes and seconds (for example `1m30s`.).
	// It applies to `PrometheusRule` resources without the `openshift.io/prometheus-rule-evaluation-scope="leaf-prometheus"` label.
	// The default value is `15s`.
	EvaluationInterval string `json:"evaluationInterval,omitempty"`
	// Defines the log level setting for Thanos Ruler.
	// The possible values are `error`, `warn`, `info`, and `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines the nodes on which the Pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for the Thanos Ruler container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines the duration for which Prometheus retains data.
	// This definition must be specified using the following regular
	// expression pattern: `[0-9]+(ms|s|m|h|d|w|y)` (ms = milliseconds,
	// s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years).
	// The default value is `24h`.
	Retention string `json:"retention,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines topology spread constraints for the pods.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Defines persistent storage for Thanos Ruler. Use this setting to
	// configure the storage class and size of a volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// The `PrometheusOperatorAdmissionWebhookConfig` resource defines settings for the Prometheus
// Operator's admission webhook workload.
type PrometheusOperatorAdmissionWebhookConfig struct {
	// Defines resource requests and limits for the prometheus-operator-admission-webhook container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// The `MonitoringPluginConfig` resource defines settings for the
// Console Plugin component in the `openshift-monitoring` namespace.
type MonitoringPluginConfig struct {
	// Defines the nodes on which the Pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for the console-plugin container.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
}

// ----- Common Types -----

// The `AdditionalAlertmanagerConfig` resource defines settings for how a
// component communicates with additional Alertmanager instances.
type AdditionalAlertmanagerConfig struct {
	// Defines the API version of Alertmanager. Possible values are `v1` or
	// `v2`.
	// The default is `v2`.
	APIVersion string `json:"apiVersion"`
	// Defines the secret key reference containing the bearer token
	// to use when authenticating to Alertmanager.
	BearerToken *v1.SecretKeySelector `json:"bearerToken,omitempty"`
	// Defines the path prefix to add in front of the push endpoint path.
	PathPrefix string `json:"pathPrefix,omitempty"`
	// Defines the URL scheme to use when communicating with Alertmanager
	// instances.
	// Possible values are `http` or `https`. The default value is `http`.
	Scheme string `json:"scheme,omitempty"`
	// A list of statically configured Alertmanager endpoints in the form
	// of `<hosts>:<port>`.
	StaticConfigs []string `json:"staticConfigs,omitempty"`
	// Defines the timeout value used when sending alerts.
	Timeout *string `json:"timeout,omitempty"`
	// Defines the TLS settings to use for Alertmanager connections.
	TLSConfig TLSConfig `json:"tlsConfig,omitempty"`
}

// The `RemoteWriteSpec` resource defines the settings for remote write storage.
type RemoteWriteSpec struct {
	// Defines the authorization settings for remote write storage.
	Authorization *monv1.SafeAuthorization `json:"authorization,omitempty"`
	// Defines basic authentication settings for the remote write endpoint URL.
	BasicAuth *monv1.BasicAuth `json:"basicAuth,omitempty"`
	// Defines the file that contains the bearer token for the remote write
	// endpoint.
	// However, because you cannot mount secrets in a pod, in practice
	// you can only reference the token of the service account.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Specifies the custom HTTP headers to be sent along with each remote write request.
	// Headers set by Prometheus cannot be overwritten.
	Headers map[string]string `json:"headers,omitempty"`
	// Defines settings for sending series metadata to remote write storage.
	MetadataConfig *monv1.MetadataConfig `json:"metadataConfig,omitempty"`
	// Defines the name of the remote write queue. This name is used in
	// metrics and logging to differentiate queues.
	// If specified, this name must be unique.
	Name string `json:"name,omitempty"`
	// Defines OAuth2 authentication settings for the remote write endpoint.
	OAuth2 *monv1.OAuth2 `json:"oauth2,omitempty"`
	// Defines an optional proxy URL.
	// If the cluster-wide proxy is enabled, it replaces the proxyUrl setting.
	// The cluster-wide proxy supports both HTTP and HTTPS proxies, with HTTPS taking precedence.
	ProxyURL string `json:"proxyUrl,omitempty"`
	// Allows tuning configuration for remote write queue parameters.
	QueueConfig *monv1.QueueConfig `json:"queueConfig,omitempty"`
	// Defines the timeout value for requests to the remote write endpoint.
	RemoteTimeout string `json:"remoteTimeout,omitempty"`
	// Enables sending exemplars via remote write. When enabled, Prometheus is
	// configured to store a maximum of 100,000 exemplars in memory.
	// Note that this setting only applies to user-defined monitoring. It is not applicable
	// to default in-cluster monitoring.
	SendExemplars *bool `json:"sendExemplars,omitempty"`
	// Defines AWS Signature Version 4 authentication settings.
	Sigv4 *monv1.Sigv4 `json:"sigv4,omitempty"`
	// Defines TLS authentication settings for the remote write endpoint.
	TLSConfig *monv1.SafeTLSConfig `json:"tlsConfig,omitempty"`
	// Defines the URL of the remote write endpoint to which samples will be sent.
	URL string `json:"url"`
	// Defines the list of remote write relabel configurations.
	WriteRelabelConfigs []monv1.RelabelConfig `json:"writeRelabelConfigs,omitempty"`
}

// The `TLSConfig` resource configures the settings for TLS connections.
type TLSConfig struct {
	// Defines the secret key reference containing the Certificate Authority
	// (CA) to use for the remote host.
	CA *v1.SecretKeySelector `json:"ca,omitempty"`
	// Defines the secret key reference containing the public certificate to
	// use for the remote host.
	Cert *v1.SecretKeySelector `json:"cert,omitempty"`
	// Defines the secret key reference containing the private key to use for
	// the remote host.
	Key *v1.SecretKeySelector `json:"key,omitempty"`
	// Used to verify the hostname on the returned certificate.
	ServerName string `json:"serverName,omitempty"`
	// When set to `true`, disables the verification of the remote host's
	// certificate and name.
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
}
