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

// ClusterMonitoringConfiguration defines configuration that allows users to customise the
// platform monitoring stack through the cluster-monitoring-config ConfigMap in the
// openshift-monitoring namespace
type ClusterMonitoringConfiguration struct {
	// AlertmanagerMainConfig defines configuration related with the main Alertmanager instance.
	AlertmanagerMainConfig *AlertmanagerMainConfig `json:"alertmanagerMain,omitempty"`
	// OmitFromDoc
	EtcdConfig *EtcdConfig `json:"-"`
	// UserWorkloadEnabled boolean flag to enable monitoring for user-defined projects.
	UserWorkloadEnabled *bool `json:"enableUserWorkload,omitempty"`
	// OmitFromDoc
	HTTPConfig *HTTPConfig `json:"http,omitempty"`
	// K8sPrometheusAdapter defines configuration related with prometheus-adapter
	K8sPrometheusAdapter *K8sPrometheusAdapter `json:"k8sPrometheusAdapter,omitempty"`
	// KubeStateMetricsConfig defines configuration related with kube-state-metrics agent
	KubeStateMetricsConfig *KubeStateMetricsConfig `json:"kubeStateMetrics,omitempty"`
	// PrometheusK8sConfig defines configuration related with prometheus
	PrometheusK8sConfig *PrometheusK8sConfig `json:"prometheusK8s,omitempty"`
	// PrometheusOperatorConfig defines configuration related with prometheus-operator
	PrometheusOperatorConfig *PrometheusOperatorConfig `json:"prometheusOperator,omitempty"`
	// OpenShiftMetricsConfig defines configuration related with openshift-state-metrics agent
	OpenShiftMetricsConfig *OpenShiftStateMetricsConfig `json:"openshiftStateMetrics,omitempty"`
	// OmitFromDoc
	TelemeterClientConfig *TelemeterClientConfig `json:"telemeterClient,omitempty"`
	// ThanosQuerierConfig defines configuration related with the Thanos Querier component
	ThanosQuerierConfig *ThanosQuerierConfig `json:"thanosQuerier,omitempty"`
}

// AlertmanagerMainConfig defines configuration related with the main Alertmanager instance.
type AlertmanagerMainConfig struct {
	// Enabled a boolean flag to enable or disable the main Alertmanager instance
	// under openshift-monitoring
	// default: true
	Enabled *bool `json:"enabled,omitempty"`
	// EnableUserAlertManagerConfig boolean flag to enable or disable user-defined namespaces
	// to be selected for AlertmanagerConfig lookup, by default Alertmanager only
	// looks for configuration in the namespace where it was deployed to. This will only work
	// if the UWM Alertmanager instance is not enabled.
	// default: false
	EnableUserAlertManagerConfig bool `json:"enableUserAlertmanagerConfig,omitempty"`
	// LogLevel defines the log level for Alertmanager.
	// Possible values are: error, warn, info, debug.
	// default: info
	LogLevel string `json:"logLevel,omitempty"`
	// NodeSelector defines which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Resources define resources requests and limits for single Pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Tolerations defines the Pods tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// TopologySpreadConstraints defines the pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// VolumeClaimTemplate defines persistent storage for Alertmanager. It's possible to
	// configure storageClass and size of volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// K8sPrometheusAdapter defines configuration related with Prometheus Adapater
type K8sPrometheusAdapter struct {
	// Audit defines the audit configuration to be used by the prometheus adapter instance.
	// Possible profile values are: "metadata, request, requestresponse, none".
	// default: metadata
	Audit *Audit `json:"audit,omitempty"`
	// NodeSelector defines which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Tolerations defines the Pods tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`

	DedicatedServiceMonitors *DedicatedServiceMonitors `json:"dedicatedServiceMonitors"`
}

type DedicatedServiceMonitors struct {
	Enabled bool `json:"enabled"`
}

// KubeStateMetricsConfig defines configuration related with the kube-state-metrics agent.
type KubeStateMetricsConfig struct {
	// NodeSelector defines which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Tolerations defines the Pods tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// PrometheusK8sConfig holds configuration related to the Prometheus component.
type PrometheusK8sConfig struct {
	// AlertmanagerConfigs holds configuration about how the Prometheus component should communicate
	// with aditional Alertmanager instances.
	// default: nil
	AlertmanagerConfigs []AdditionalAlertmanagerConfig `json:"additionalAlertmanagerConfigs,omitempty"`
	// EnforcedBodySizeLimit enforces body size limit of Prometheus scrapes, if a scrape is bigger than
	// the limit it will fail.
	// 3 kinds of values are accepted:
	//  1. empty value: no limit
	//  2. a value in Prometheus size format, e.g. "64MB"
	//  3. string "automatic", which means the limit will be automatically calculated based on
	//     cluster capacity.
	// default: 64MB
	EnforcedBodySizeLimit string `json:"enforcedBodySizeLimit,omitempty"`
	// ExternalLabels defines labels to be added to any time series or alerts when communicating
	// with external systems (federation, remote storage, Alertmanager).
	// default: nil
	ExternalLabels map[string]string `json:"externalLabels,omitempty"`
	// LogLevel defines the log level for Prometheus.
	// Possible values are: error, warn, info, debug.
	// default: info
	LogLevel string `json:"logLevel,omitempty"`
	// NodeSelector defines which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// QueryLogFile specifies the file to which PromQL queries are logged. Suports both just a filename
	// in which case they will be saved to an emptyDir volume at /var/log/prometheus, if a full path is
	// given an emptyDir volume will be mounted at that location. Relative paths not supported,
	// also not supported writing to linux std streams.
	// default: ""
	QueryLogFile string `json:"queryLogFile,omitempty"`
	// RemoteWrite Holds the remote write configuration, everything from url, authorization to relabeling
	RemoteWrite []RemoteWriteSpec `json:"remoteWrite,omitempty"`
	// Resources define resources requests and limits for single Pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Retention defines the Time duration Prometheus shall retain data for. Must match the regular expression
	// [0-9]+(ms|s|m|h|d|w|y) (milliseconds seconds minutes hours days weeks years).
	// default: 15d
	Retention string `json:"retention,omitempty"`
	// RetentionSize defines the maximum amount of disk space used by blocks + WAL.
	// default: nil
	RetentionSize string `json:"retentionSize,omitempty"`
	// OmitFromDoc
	TelemetryMatches []string `json:"-"`
	// Tolerations defines the Pods tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// TopologySpreadConstraints defines the pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// VolumeClaimTemplate defines persistent storage for Prometheus. It's possible to
	// configure storageClass and size of volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// PrometheusOperatorConfig holds configuration related to Prometheus Operator.
type PrometheusOperatorConfig struct {
	// LogLevel defines the log level for Prometheus Operator.
	// Possible values are: error, warn, info, debug.
	// default: info
	LogLevel string `json:"logLevel,omitempty"`
	// NodeSelector defines which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Tolerations defines the Pods tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// OpenShiftStateMetricsConfig holds configuration related to openshift-state-metrics agent.
type OpenShiftStateMetricsConfig struct {
	// NodeSelector defines which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Tolerations defines the Pods tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// ThanosQuerierConfig holds configuration related to Thanos Querier component.
type ThanosQuerierConfig struct {
	// EnableRequestLogging boolean flag to enable or disable request logging
	// default: false
	EnableRequestLogging bool `json:"enableRequestLogging,omitempty"`
	// LogLevel defines the log level for Thanos Querier.
	// Possible values are: error, warn, info, debug.
	// default: info
	LogLevel string `json:"logLevel,omitempty"`
	// NodeSelector defines which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Resources define resources requests and limits for single Pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Tolerations defines the Pods tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
}

// UserWorkloadConfiguration defines configuration that allows users to customise the
// monitoring stack responsible for user-defined projects through the
// user-workload-monitoring-config ConfigMap in the openshift-user-workload-monitoring namespace
type UserWorkloadConfiguration struct {
	// Alertmanager defines configuration for Alertmanager component.
	Alertmanager *AlertmanagerUserWorkloadConfig `json:"alertmanager,omitempty"`
	// Prometheus defines configuration for Prometheus component.
	Prometheus *PrometheusRestrictedConfig `json:"prometheus,omitempty"`
	// PrometheusOperator defines configuration for prometheus-operator component.
	PrometheusOperator *PrometheusOperatorConfig `json:"prometheusOperator,omitempty"`
	// ThanosRuler defines configuration for the Thanos Ruler component
	ThanosRuler *ThanosRulerConfig `json:"thanosRuler,omitempty"`
}

// AlertmanagerUserWorkloadConfig defines configuration for the Alertmanager instance for
// user-defined projects.
type AlertmanagerUserWorkloadConfig struct {
	// Enabled a boolean flag to enable or disable a dedicated instance of Alertmanager
	// for user-defined projects under openshift-user-workload-monitoring
	// default: false
	Enabled bool `json:"enabled,omitempty"`
	// EnableAlertmanagerConfig a boolean flag to enable or disable user-defined namespaces to be selected
	// for AlertmanagerConfig lookup, by default Alertmanager only looks for configuration
	// in the namespace where it was deployed to
	// default: false
	EnableAlertmanagerConfig bool `json:"enableAlertmanagerConfig,omitempty"`
	// LogLevel defines the log level for Alertmanager.
	// Possible values are: error, warn, info, debug.
	// default: info
	LogLevel string `json:"logLevel,omitempty"`
	// Resources define resources requests and limits for single Pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// NodeSelector defines which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Tolerations defines the Pods tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// VolumeClaimTemplate defines persistent storage for Alertmanager. It's possible to
	// configure storageClass and size of volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// PrometheusRestrictedConfig defines configuration related to the Prometheus component that
// will monitor user-defined projects.
type PrometheusRestrictedConfig struct {
	// AlertmanagerConfigs holds configuration about how the Prometheus component should communicate
	// with aditional Alertmanager instances.
	// default: nil
	AlertmanagerConfigs []AdditionalAlertmanagerConfig `json:"additionalAlertmanagerConfigs,omitempty"`
	// EnforcedLabelLimit per-scrape limit on the number of labels accepted for a sample. If more than this
	// number of labels are present post metric-relabeling, the entire scrape will be treated as
	// failed. 0 means no limit.
	// default: 0
	EnforcedLabelLimit *uint64 `json:"enforcedLabelLimit,omitempty"`
	// EnforcedLabelNameLengthLimit per-scrape limit on the length of labels name that will be accepted for
	// a sample. If a label name is longer than this number post metric-relabeling, the entire scrape
	// will be treated as failed. 0 means no limit.
	// default: 0
	EnforcedLabelNameLengthLimit *uint64 `json:"enforcedLabelNameLengthLimit,omitempty"`
	// EnforcedLabelValueLengthLimit per-scrape limit on the length of labels value that will be accepted for
	// a sample. If a label value is longer than this number post metric-relabeling, the entire scrape will
	// be treated as failed. 0 means no limit.
	// default: 0
	EnforcedLabelValueLengthLimit *uint64 `json:"enforcedLabelValueLengthLimit,omitempty"`
	// EnforcedSampleLimit defines a global limit on the number of scraped samples that will be accepted.
	// This overrides any SampleLimit set per ServiceMonitor or/and PodMonitor. It is meant to be
	// used by admins to enforce the SampleLimit to keep the overall number of samples/series under the
	// desired limit. Note that if SampleLimit is lower that value will be taken instead.
	// default: 0
	EnforcedSampleLimit *uint64 `json:"enforcedSampleLimit,omitempty"`
	// EnforcedTargetLimit defines a global limit on the number of scraped targets. This overrides
	// any TargetLimit set per ServiceMonitor or/and PodMonitor. It is meant to be used by admins to
	// enforce the TargetLimit to keep the overall number of targets under the desired limit. Note
	// that if TargetLimit is lower, that value will be taken instead, except if either value is
	// zero, in which case the non-zero value will be used. If both values are zero, no limit is
	// enforced.
	// default: 0
	EnforcedTargetLimit *uint64 `json:"enforcedTargetLimit,omitempty"`
	// ExternalLabels defines labels to be added to any time series or alerts when communicating
	// with external systems (federation, remote storage, Alertmanager).
	// default: nil
	ExternalLabels map[string]string `json:"externalLabels,omitempty"`
	// LogLevel defines the log level for Prometheus.
	// Possible values are: error, warn, info, debug.
	// default: info
	LogLevel string `json:"logLevel,omitempty"`
	// NodeSelector defines which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// QueryLogFile specifies the file to which PromQL queries are logged. Suports both just a filename
	// in which case they will be saved to an emptyDir volume at /var/log/prometheus, if a full path is
	// given an emptyDir volume will be mounted at that location. Relative paths not supported,
	// also not supported writing to linux std streams.
	// default: ""
	QueryLogFile string `json:"queryLogFile,omitempty"`
	// RemoteWrite Holds the remote write configuration, everything from url, authorization to relabeling
	RemoteWrite []RemoteWriteSpec `json:"remoteWrite,omitempty"`
	// Resources define resources requests and limits for single Pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Retention defines the Time duration Prometheus shall retain data for. Must match the regular expression
	// [0-9]+(ms|s|m|h|d|w|y) (milliseconds seconds minutes hours days weeks years).
	// default: 15d
	Retention string `json:"retention,omitempty"`
	// RetentionSize defines the maximum amount of disk space used by blocks + WAL.
	// default: nil
	RetentionSize string `json:"retentionSize,omitempty"`
	// Tolerations defines the Pods tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// VolumeClaimTemplate defines persistent storage for Prometheus. It's possible to
	// configure storageClass and size of volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// ThanosRulerConfig defines configuration for the Thanos Ruler instance for user-defined projects.
type ThanosRulerConfig struct {
	// AlertmanagerConfigs holds configuration about how the Thanos Ruler component should communicate
	// with aditional Alertmanager instances.
	// default: nil
	AlertmanagersConfigs []AdditionalAlertmanagerConfig `json:"additionalAlertmanagerConfigs,omitempty"`
	// LogLevel defines the log level for Thanos Ruler.
	// Possible values are: error, warn, info, debug.
	// default: info
	LogLevel string `json:"logLevel,omitempty"`
	// NodeSelector defines which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Resources define resources requests and limits for single Pods.
	Resources *v1.ResourceRequirements `json:"resources,omitempty"`
	// Retention defines the time duration Thanos Ruler shall retain data for. Must match the regular expression
	// [0-9]+(ms|s|m|h|d|w|y) (milliseconds seconds minutes hours days weeks years).
	// default: 15d
	Retention string `json:"retention,omitempty"`
	// Tolerations defines the Pods tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// TopologySpreadConstraints defines the pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// VolumeClaimTemplate defines persistent storage for Thanos Ruler. It's possible to
	// configure storageClass and size of volume.
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate,omitempty"`
}

// ----- Common Types -----

// AdditionalAlertmanagerConfig defines configuration on how a component should communicate with
// aditional Alertmanager instances.
type AdditionalAlertmanagerConfig struct {
	// APIVersion defines the api version of Alertmanager.
	APIVersion string `json:"apiVersion"`
	// BearerToken defines the bearer token to use when authenticating to Alertmanager.
	BearerToken *v1.SecretKeySelector `json:"bearerToken,omitempty"`
	// PathPrefix defines the path prefix to add in front of the push endpoint path.
	PathPrefix string `json:"pathPrefix,omitempty"`
	// Scheme the URL scheme to use when talking to Alertmanagers.
	Scheme string `json:"scheme,omitempty"`
	// StaticConfigs a list of statically configured Alertmanagers.
	StaticConfigs []string `json:"staticConfigs,omitempty"`
	// Timeout defines the timeout used when sending alerts.
	Timeout *string `json:"timeout,omitempty"`
	// TLSConfig defines the TLS Config to use for alertmanager connection.
	TLSConfig TLSConfig `json:"tlsConfig,omitempty"`
}

// RemoteWriteSpec is almost a 1to1 copy of monv1.RemoteWriteSpec but with the
// BearerToken field removed. In the future other fields might be added here.
type RemoteWriteSpec struct {
	// Authorization defines the authorization section for remote write
	Authorization *monv1.SafeAuthorization `json:"authorization,omitempty"`
	// BasicAuth defines configuration for basic authentication for the URL.
	BasicAuth *monv1.BasicAuth `json:"basicAuth,omitempty"`
	// BearerTokenFile defines the file where the bearer token for remote write resides.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// Headers custom HTTP headers to be sent along with each remote write request.
	// Be aware that headers that are set by Prometheus itself can't be overwritten.
	Headers map[string]string `json:"headers,omitempty"`
	// MetadataConfig configures the sending of series metadata to remote storage.
	MetadataConfig *monv1.MetadataConfig `json:"metadataConfig,omitempty"`
	// Name defines the name of the remote write queue, must be unique if specified. The
	// name is used in metrics and logging in order to differentiate queues.
	Name string `json:"name,omitempty"`
	// OAuth2 configures OAuth2 authentication for remote write.
	OAuth2 *monv1.OAuth2 `json:"oauth2,omitempty"`
	// ProxyURL defines an optional proxy URL
	ProxyURL string `json:"proxyUrl,omitempty"`
	// QueueConfig allows tuning of the remote write queue parameters.
	QueueConfig *monv1.QueueConfig `json:"queueConfig,omitempty"`
	// RemoteTimeout defines the timeout for requests to the remote write endpoint.
	RemoteTimeout string `json:"remoteTimeout,omitempty"`
	// Sigv4 allows to configures AWS's Signature Verification 4
	Sigv4 *monv1.Sigv4 `json:"sigv4,omitempty"`
	// TLSConfig defines the TLS configuration to use for remote write.
	TLSConfig *monv1.SafeTLSConfig `json:"tlsConfig,omitempty"`
	// URL defines the URL of the endpoint to send samples to.
	URL string `json:"url"`
	// WriteRelabelConfigs defines the list of remote write relabel configurations.
	WriteRelabelConfigs []monv1.RelabelConfig `json:"writeRelabelConfigs,omitempty"`
}

// TLSConfig configures the options for TLS connections.
type TLSConfig struct {
	// CA defines the CA cert in the Prometheus container to use for the targets.
	CA *v1.SecretKeySelector `json:"ca,omitempty"`
	// Cert defines the client cert in the Prometheus container to use for the targets.
	Cert *v1.SecretKeySelector `json:"cert,omitempty"`
	// Key defines the client key in the Prometheus container to use for the targets.
	Key *v1.SecretKeySelector `json:"key,omitempty"`
	// ServerName used to verify the hostname for the targets.
	ServerName string `json:"serverName,omitempty"`
	// InsecureSkipVerify disable target certificate validation.
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
}
