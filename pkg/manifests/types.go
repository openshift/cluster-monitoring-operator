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

// `ClusterMonitoringConfiguration` defines settings that customize the
// default platform monitoring stack through the `cluster-monitoring-config` ConfigMap in the
// `openshift-monitoring` namespace.
type ClusterMonitoringConfiguration struct {
	// `AlertmanagerMainConfig` defines settings for the main Alertmanager instance.
	AlertmanagerMainConfig *AlertmanagerMainConfig `json:"alertmanagerMain,omitempty"`
	// OmitFromDoc
	EtcdConfig *EtcdConfig `json:"-"`
	// `UserWorkloadEnabled` is a Boolean flag that enables monitoring for user-defined projects.
	UserWorkloadEnabled *bool `json:"enableUserWorkload,omitempty"`
	// OmitFromDoc
	HTTPConfig *HTTPConfig `json:"http,omitempty"`
	// `K8sPrometheusAdapter` defines settings for the Prometheus Adapter component.
	K8sPrometheusAdapter *K8sPrometheusAdapter `json:"k8sPrometheusAdapter,omitempty"`
	// `KubeStateMetricsConfig` defines settings for the `kube-state-metrics` agent.
	KubeStateMetricsConfig *KubeStateMetricsConfig `json:"kubeStateMetrics,omitempty"`
	// `PrometheusK8sConfig` defines settings for the Prometheus component.
	PrometheusK8sConfig *PrometheusK8sConfig `json:"prometheusK8s,omitempty"`
	// `PrometheusOperatorConfig` defines settings for the Prometheus Operator component.
	PrometheusOperatorConfig *PrometheusOperatorConfig `json:"prometheusOperator,omitempty"`
	// `OpenShiftMetricsConfig` defines settings for the `openshift-state-metrics` agent.
	OpenShiftMetricsConfig *OpenShiftStateMetricsConfig `json:"openshiftStateMetrics,omitempty"`
	// OmitFromDoc
	TelemeterClientConfig *TelemeterClientConfig `json:"telemeterClient,omitempty"`
	// `ThanosQuerierConfig` defines settings for the Thanos Querier component.
	ThanosQuerierConfig *ThanosQuerierConfig `json:"thanosQuerier,omitempty"`
}

// `AlertmanagerMainConfig` defines settings for the main Alertmanager instance.
type AlertmanagerMainConfig struct {
	// A Boolean flag that enables or disables the main Alertmanager instance
	// in the `openshift-monitoring` namespace.
	// The default value is `true`.
	Enabled *bool `json:"enabled,omitempty"`
	// A Boolean flag that enables or disables user-defined namespaces
	// to be selected for `AlertmanagerConfig` lookups. By default Alertmanager only
	// looks for configuration settings in the namespace to which it was deployed. This setting only applies
	// if the user workload monitoring instance of Alertmanager is not enabled.
	// The default value is `false`.
	EnableUserAlertManagerConfig bool `json:"enableUserAlertmanagerConfig,omitempty"`
	// Defines the log level setting for Alertmanager.
	// The possible values are: `error`, `warn`, `info`, `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines the nodes on which the Pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for single pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines a pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Defines persistent storage for Alertmanager. Use this setting to
	// configure the storage class and size of a volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// `K8sPrometheusAdapter` defines settings for the Prometheus Adapter component.
type K8sPrometheusAdapter struct {
	// Defines the audit configuration used by the Prometheus Adapter instance.
	// Possible profile values are: `metadata`, `request`, `requestresponse`, and `none`.
	// The default value is `metadata`.
	Audit *Audit `json:"audit,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`

	DedicatedServiceMonitors *DedicatedServiceMonitors `json:"dedicatedServiceMonitors,omitempty"`
}

// Configuration for prometheus-adapter dedicated Service Monitors.
// When Enabled is set to true, CMO will deploy and scrape a dedicated
// Service Monitor, that exposes the kubelet /metrics/resource endpoint. This
// Service Monitor sets honorTimestamps: true and only keeps metrics that are
// relevant for the pod resource queries of prometheus-adapter.
// Additionally prometheus-adapter is configured to use these dedicated metrics.
// Overall this will improve the consistency of prometheus-adapter based CPU
// usage measurements used by for example the oc adm top pod command or the
// Horizontal Pod Autoscaler.
type DedicatedServiceMonitors struct {
	Enabled bool `json:"enabled,omitempty"`
}

// `KubeStateMetricsConfig` defines settings for the `kube-state-metrics` agent.
type KubeStateMetricsConfig struct {
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// `PrometheusK8sConfig` defines settings for the Prometheus component.
type PrometheusK8sConfig struct {
	// Configures how the Prometheus component communicates
	// with additional Alertmanager instances.
	// The default value is `nil`.
	AlertmanagerConfigs []AdditionalAlertmanagerConfig `json:"additionalAlertmanagerConfigs,omitempty"`
	// Enforces a body size limit for Prometheus scraped metrics. If a scraped 
	// metric is larger than the limit, the scrape will fail.
	// The following values are valid:
	// an empty value to specify no limit,
	// a numeric value in Prometheus size format (such as `64MB`), or
	// the string `automatic`, which indicates that the limit will be 
	// automatically calculated based on cluster capacity.
	// The default value is `64MB`.
	EnforcedBodySizeLimit string `json:"enforcedBodySizeLimit,omitempty"`
	// Defines labels to be added to any time series or alerts when communicating
	// with external systems such as federation, remote storage, and Alertmanager.
	// The default value is `nil`.
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
	// Relative paths are not supported, nor is writing to 
	// Linux `std` text streams.
	// The default value is blank.
	QueryLogFile string `json:"queryLogFile,omitempty"`
	// Defines the remote write configuration, including URL, authentication, 
	// and relabeling settings.
	RemoteWrite []RemoteWriteSpec `json:"remoteWrite,omitempty"`
	// Defines resource requests and limits for single pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines the duration for which Prometheus retains data.
	// This definition must be specified using the following regular
	// expression pattern: `[0-9]+(ms|s|m|h|d|w|y)` (ms = milliseconds, 
	// s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years).
	// The default value is `15d`.
	Retention string `json:"retention,omitempty"`
	// Defines the maximum amount of disk space used by data blocks plus the 
	// write-ahead log (WAL).
	// The default value is `nil`.
	RetentionSize string `json:"retentionSize,omitempty"`
	// OmitFromDoc
	TelemetryMatches []string `json:"-"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines the pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Defines persistent storage for Prometheus. Use this setting to
	// configure the storage class and size of a volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// `PrometheusOperatorConfig` defines settings for the Prometheus Operator component.
type PrometheusOperatorConfig struct {
	// Defines the log level settings for Prometheus Operator.
	// The possible values are `error`, `warn`, `info`, and `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// `OpenShiftStateMetricsConfig` defines settings for the `openshift-state-metrics` agent.
type OpenShiftStateMetricsConfig struct {
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// `ThanosQuerierConfig` defines settings for the Thanos Querier component.
type ThanosQuerierConfig struct {
	// A Boolean flag that enables or disables request logging.
	// The default value is `false`.
	EnableRequestLogging bool `json:"enableRequestLogging,omitempty"`
	// Defines the log level setting for Thanos Querier.
	// The possible values are `error`, `warn`, `info`, and `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for single pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// `UserWorkloadConfiguration` defines the settings for the
// monitoring stack responsible for user-defined projects in the
// `user-workload-monitoring-config` ConfigMap in the 
// `openshift-user-workload-monitoring` namespace.
type UserWorkloadConfiguration struct {
	// Defines the settings for the Alertmanager component in user workload monitoring.
	Alertmanager *AlertmanagerUserWorkloadConfig `json:"alertmanager,omitempty"`
	// Defines the settings for the Prometheus component in user workload monitoring.
	Prometheus *PrometheusRestrictedConfig `json:"prometheus,omitempty"`
	// Defines the settings for the Prometheus Operator component in user workload monitoring.
	PrometheusOperator *PrometheusOperatorConfig `json:"prometheusOperator,omitempty"`
	// Defines the settings for the Thanos Ruler component in user workload monitoring.
	ThanosRuler *ThanosRulerConfig `json:"thanosRuler,omitempty"`
}

// `AlertmanagerUserWorkloadConfig` defines the settings for the Alertmanager 
// instance used for user-defined projects.
type AlertmanagerUserWorkloadConfig struct {
	// A Boolean flag that enables or disables a dedicated instance of 
	// Alertmanager for user-defined projects in the `openshift-user-workload-monitoring` namespace.
	// The default value is `false`.
	Enabled bool `json:"enabled,omitempty"`
	// A Boolean flag to enable or disable user-defined namespaces to be selected
	// for `AlertmanagerConfig` lookup. By default, Alertmanager only looks for configuration
	// in the namespace to which it was deployed.
	// The default value is `false`.
	EnableAlertmanagerConfig bool `json:"enableAlertmanagerConfig,omitempty"`
	// Defines the log level setting for Alertmanager for user workload monitoring.
	// The possible values are `error`, `warn`, `info`, and `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines resource requests and limits for single pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines the nodes on which the pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines persistent storage for Alertmanager. Use this setting to
	// configure the storage class and size of a volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// `PrometheusRestrictedConfig` defines the settings for the Prometheus 
// component that monitors user-defined projects.
type PrometheusRestrictedConfig struct {
	// Configures how the Prometheus component communicates
	// with additional Alertmanager instances.
	// The default value is `nil`.
	AlertmanagerConfigs []AdditionalAlertmanagerConfig `json:"additionalAlertmanagerConfigs,omitempty"`
	// Specifies a per-scrape limit on the number of labels accepted for a sample. 
	// If the number of labels exceeds this limit after metric relabeling, 
	// the entire scrape is treated as failed. 
	// The default value is `0`, which means that no limit is set.
	EnforcedLabelLimit *uint64 `json:"enforcedLabelLimit,omitempty"`
	// Specifies a per-scrape limit on the length of a label name for a sample. 
	// If a label name exceeds this limit after metric relabeling, 
	// the entire scrape is treated as failed. 
	// The default value is `0`, which means that no limit is set.
	EnforcedLabelNameLengthLimit *uint64 `json:"enforcedLabelNameLengthLimit,omitempty"`
	// Specifies a per-scrape limit on the length of a label value for
	// a sample. If a label value exceeds this limit after 
	// metric relabeling, the entire scrape is treated as failed.
	// The default value is `0`, which means that no limit is set.
	EnforcedLabelValueLengthLimit *uint64 `json:"enforcedLabelValueLengthLimit,omitempty"`
	// Specifies a global limit on the number of scraped samples that will be accepted.
	// This setting overrides any `SampleLimit` value set per `ServiceMonitor` or `PodMonitor`. 
	// Administrators can use this setting to enforce a `SampleLimit` value and 
	// keep the overall number of samples or series under the set limit. 
	// However, if the `SampleLimit` value is lower than this limit,
	// the `SampleLimit` value is used instead.
	// The default value is `0`.
	EnforcedSampleLimit *uint64 `json:"enforcedSampleLimit,omitempty"`
	// Specifies a global limit on the number of scraped targets. This value overrides
	// any `TargetLimit` value set per `ServiceMonitor` or `PodMonitor`. 
	// Administrators can use this setting to enforce a `TargetLimit` value and
	// keep the overall number of targets under the set limit. Note
	// However, if the `TargetLimit` value is lower than this limit, 
	// the `TargetLimit` value is used instead. If one of the values is
	// `0`, the non-zero value is used. If both values are 
	// `0`, no limit is set.
	// The default value is `0`.
	EnforcedTargetLimit *uint64 `json:"enforcedTargetLimit,omitempty"`
	// Defines labels to be added to any time series or alert when 
	// communicating with external systems such as federation, remote storage, and Alertmanager.
	// The default value is `nil`.
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
	// Relative paths are not supported, nor is writing to 
	// Linux `std` text streams.
	// The default value is `nil`.
	QueryLogFile string `json:"queryLogFile,omitempty"`
	// Defines the remote write configuration, including URL, authentication, 
	// and relabeling settings.
	RemoteWrite []RemoteWriteSpec `json:"remoteWrite,omitempty"`
	// Defines resource requests and limits for single pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines the duration for which Prometheus retains data.
	// This definition must be specified using the following regular
	// expression pattern: `[0-9]+(ms|s|m|h|d|w|y)` (ms = milliseconds, 
	// s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years).
	// The default value is `15d`.
	Retention string `json:"retention,omitempty"`
	// Defines the maximum amount of disk space used by data blocks plus the 
	// write-ahead log (WAL).
	// The default value is `nil`.
	RetentionSize string `json:"retentionSize,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines persistent storage for Prometheus. Use this setting to
	// configure the storage class and size of a volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// `ThanosRulerConfig` defines configuration for the Thanos Ruler instance for user-defined projects.
type ThanosRulerConfig struct {
	// Configures how the Thanos Ruler component communicates
	// with additional Alertmanager instances.
	// The default value is `nil`.
	AlertmanagersConfigs []AdditionalAlertmanagerConfig `json:"additionalAlertmanagerConfigs,omitempty"`
	// Defines the log level setting for Thanos Ruler.
	// The possible values are `error`, `warn`, `info`, and `debug`.
	// The default value is `info`.
	LogLevel string `json:"logLevel,omitempty"`
	// Defines the nodes on which the Pods are scheduled.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Defines resource requests and limits for single pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Defines the duration for which Prometheus retains data.
	// This definition must be specified using the following regular
	// expression pattern: `[0-9]+(ms|s|m|h|d|w|y)` (ms = milliseconds, 
	// s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years).
	// The default value is `15d`.
	Retention string `json:"retention,omitempty"`
	// Defines tolerations for the pods.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// Defines topology spread constraints for the pods.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// Defines persistent storage for Thanos Ruler. Use this setting to
	// configure the storage class and size of a volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// ----- Common Types -----

// `AdditionalAlertmanagerConfig` defines settings for how a component 
// communicates with additional Alertmanager instances.
type AdditionalAlertmanagerConfig struct {
	// Defines the API version of Alertmanager.
	APIVersion string `json:"apiVersion"`
	// Defines the bearer token to use when authenticating to Alertmanager.
	BearerToken *v1.SecretKeySelector `json:"bearerToken,omitempty"`
	// Defines the path prefix to add in front of the push endpoint path.
	PathPrefix string `json:"pathPrefix,omitempty"`
	// Defines the URL scheme to use when communicating with Alertmanager instances.
	Scheme string `json:"scheme,omitempty"`
	// A list of statically configured Alertmanager instances.
	StaticConfigs []string `json:"staticConfigs,omitempty"`
	// Defines the timeout value used when sending alerts.
	Timeout *string `json:"timeout,omitempty"`
	// Defines the TLS settings to use for Alertmanager connections.
	TLSConfig TLSConfig `json:"tlsConfig,omitempty"`
}

// `RemoteWriteSpec` defines the settings for remote write storage.
type RemoteWriteSpec struct {
	// Defines the authorization settings for remote write storage.
	Authorization *monv1.SafeAuthorization `json:"authorization,omitempty"`
	// Defines basic authentication settings for the remote write endpoint URL.
	BasicAuth *monv1.BasicAuth `json:"basicAuth,omitempty"`
	// Defines the file that contains the bearer token for the remote write endpoint.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Specifies the custom HTTP headers to be sent along with each remote write request.
	// Headers set by Prometheus cannot be overwritten.
	Headers map[string]string `json:"headers,omitempty"`
	// Defines settings for sending series metadata to remote write storage.
	MetadataConfig *monv1.MetadataConfig `json:"metadataConfig,omitempty"`
	// Defines the name of the remote write queue. This name is used in
	// meetrics and logging to differentiate queues.
	// If specified, this name must be unique.
	Name string `json:"name,omitempty"`
	// Defines OAuth2 authentication settings for the remote write endpoint.
	OAuth2 *monv1.OAuth2 `json:"oauth2,omitempty"`
	// Defines an optional proxy URL.
	ProxyURL string `json:"proxyUrl,omitempty"`
	// Allows tuning configuration for remote write queue parameters.
	QueueConfig *monv1.QueueConfig `json:"queueConfig,omitempty"`
	// Defines the timeout value for requests to the remote write endpoint.
	RemoteTimeout string `json:"remoteTimeout,omitempty"`
	// Defines AWS Signature Verification 4 authentication settings.
	Sigv4 *monv1.Sigv4 `json:"sigv4,omitempty"`
	// Defines TLS authentication settings for the remote write endpoint.
	TLSConfig *monv1.SafeTLSConfig `json:"tlsConfig,omitempty"`
	// Defines the URL of the remote write endpoint to which samples will be sent.
	URL string `json:"url"`
	// Defines the list of remote write relabel configurations.
	WriteRelabelConfigs []monv1.RelabelConfig `json:"writeRelabelConfigs,omitempty"`
}

// `TLSConfig` configures the settings for TLS connections.
type TLSConfig struct {
	// Defines the CA cert in the Prometheus container to use for the targets.
	CA *v1.SecretKeySelector `json:"ca,omitempty"`
	// Defines the client cert in the Prometheus container to use for the targets.
	Cert *v1.SecretKeySelector `json:"cert,omitempty"`
	// Defines the client key in the Prometheus container to use for the targets.
	Key *v1.SecretKeySelector `json:"key,omitempty"`
	// Used to verify the hostname for the targets.
	ServerName string `json:"serverName,omitempty"`
	// Disables target certificate validation.
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
}