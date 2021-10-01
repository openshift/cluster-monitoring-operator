package manifests

import (
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	v12 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/api/core/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

// ClusterMonitoringConfig is the configuration that allows users to customise the
// monitoring stack
// +k8s:openapi-gen=true
type ClusterMonitoringConfiguration struct {
	// Configuration for prometheus operator
	PrometheusOperatorConfig *PrometheusOperatorConfig `json:"prometheusOperator"`
	// Configuration for prometheus
	PrometheusK8sConfig    *PrometheusK8sConfig         `json:"prometheusK8s"`
	AlertmanagerMainConfig *AlertmanagerMainConfig      `json:"alertmanagerMain"`
	KubeStateMetricsConfig *KubeStateMetricsConfig      `json:"kubeStateMetrics"`
	OpenShiftMetricsConfig *OpenShiftStateMetricsConfig `json:"openshiftStateMetrics"`
	GrafanaConfig          *GrafanaConfig               `json:"grafana"`
	EtcdConfig             *EtcdConfig                  `json:"-"`
	HTTPConfig             *HTTPConfig                  `json:"http"`
	TelemeterClientConfig  *TelemeterClientConfig       `json:"telemeterClient"`
	K8sPrometheusAdapter   *K8sPrometheusAdapter        `json:"k8sPrometheusAdapter"`
	ThanosQuerierConfig    *ThanosQuerierConfig         `json:"thanosQuerier"`
	UserWorkloadEnabled    *bool                        `json:"enableUserWorkload"`
}

type PrometheusK8sConfig struct {
	LogLevel            string                             `json:"logLevel,omitempty" status:"TechPreview"`
	Retention           string                             `json:"retention"`
	NodeSelector        map[string]string                  `json:"nodeSelector"`
	Tolerations         []v1.Toleration                    `json:"tolerations"`
	Resources           *v1.ResourceRequirements           `json:"resources"`
	ExternalLabels      map[string]string                  `json:"externalLabels"`
	VolumeClaimTemplate *v12.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate"`
	RemoteWrite         []RemoteWriteSpec                  `json:"remoteWrite"`
	TelemetryMatches    []string                           `json:"-"`
	AlertmanagerConfigs []AdditionalAlertmanagerConfig     `json:"additionalAlertmanagerConfigs"`
}

type KubeStateMetricsConfig struct {
	NodeSelector map[string]string `json:"nodeSelector"`
	Tolerations  []v1.Toleration   `json:"tolerations"`
}

type OpenShiftStateMetricsConfig struct {
	NodeSelector map[string]string `json:"nodeSelector"`
	Tolerations  []v1.Toleration   `json:"tolerations"`
}

type K8sPrometheusAdapter struct {
	NodeSelector map[string]string `json:"nodeSelector"`
	Tolerations  []v1.Toleration   `json:"tolerations"`
	Audit        *Audit            `json:"audit"`
}

type Audit struct {
	Profile auditv1.Level `json:"profile"`
}

type UserWorkloadConfiguration struct {
	PrometheusOperator *PrometheusOperatorConfig   `json:"prometheusOperator"`
	Prometheus         *PrometheusRestrictedConfig `json:"prometheus"`
	ThanosRuler        *ThanosRulerConfig          `json:"thanosRuler"`
}

type PrometheusRestrictedConfig struct {
	LogLevel            string                             `json:"logLevel"`
	Retention           string                             `json:"retention"`
	NodeSelector        map[string]string                  `json:"nodeSelector"`
	Tolerations         []v1.Toleration                    `json:"tolerations"`
	Resources           *v1.ResourceRequirements           `json:"resources"`
	ExternalLabels      map[string]string                  `json:"externalLabels"`
	VolumeClaimTemplate *v12.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate"`
	RemoteWrite         []RemoteWriteSpec                  `json:"remoteWrite"`
	EnforcedSampleLimit *uint64                            `json:"enforcedSampleLimit"`
	EnforcedTargetLimit *uint64                            `json:"enforcedTargetLimit"`
	AlertmanagerConfigs []AdditionalAlertmanagerConfig     `json:"additionalAlertmanagerConfigs"`
}

type ThanosRulerConfig struct {
	LogLevel             string                             `json:"logLevel"`
	NodeSelector         map[string]string                  `json:"nodeSelector"`
	Tolerations          []v1.Toleration                    `json:"tolerations"`
	Resources            *v1.ResourceRequirements           `json:"resources"`
	VolumeClaimTemplate  *v12.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate"`
	AlertmanagersConfigs []AdditionalAlertmanagerConfig     `json:"additionalAlertmanagerConfigs"`
}

type ThanosQuerierConfig struct {
	LogLevel     string                   `json:"logLevel"`
	NodeSelector map[string]string        `json:"nodeSelector"`
	Tolerations  []v1.Toleration          `json:"tolerations"`
	Resources    *v1.ResourceRequirements `json:"resources"`
}

type GrafanaConfig struct {
	Enabled      *bool             `json:"enabled"`
	NodeSelector map[string]string `json:"nodeSelector"`
	Tolerations  []v1.Toleration   `json:"tolerations"`
}

type PrometheusOperatorConfig struct {
	LogLevel     string            `json:"logLevel"`
	NodeSelector map[string]string `json:"nodeSelector"`
	Tolerations  []v1.Toleration   `json:"tolerations"`
}

// RemoteWriteSpec is almost a 1to1 copy of monv1.RemoteWriteSpec but with the
// BearerToken field removed. In the future other fields might be added here.
type RemoteWriteSpec struct {
	// The URL of the endpoint to send samples to.
	URL string `json:"url"`
	// The name of the remote write queue, must be unique if specified. The
	// name is used in metrics and logging in order to differentiate queues.
	// Only valid in Prometheus versions 2.15.0 and newer.
	Name string `json:"name,omitempty"`
	// Timeout for requests to the remote write endpoint.
	RemoteTimeout string `json:"remoteTimeout,omitempty"`
	// Custom HTTP headers to be sent along with each remote write request.
	// Be aware that headers that are set by Prometheus itself can't be overwritten.
	// Only valid in Prometheus versions 2.25.0 and newer.
	Headers map[string]string `json:"headers,omitempty"`
	// The list of remote write relabel configurations.
	WriteRelabelConfigs []monv1.RelabelConfig `json:"writeRelabelConfigs,omitempty"`
	// BasicAuth for the URL.
	BasicAuth *monv1.BasicAuth `json:"basicAuth,omitempty"`
	// Bearer token for remote write.
	BearerTokenFile string `json:"bearerTokenFile,omitempty"`
	// TLS Config to use for remote write.
	TLSConfig *monv1.SafeTLSConfig `json:"tlsConfig,omitempty"`
	// Optional ProxyURL
	ProxyURL string `json:"proxyUrl,omitempty"`
	// QueueConfig allows tuning of the remote write queue parameters.
	QueueConfig *monv1.QueueConfig `json:"queueConfig,omitempty"`
	// MetadataConfig configures the sending of series metadata to remote storage.
	MetadataConfig *monv1.MetadataConfig `json:"metadataConfig,omitempty"`
}

type AdditionalAlertmanagerConfig struct {
	// The URL scheme to use when talking to Alertmanagers.
	Scheme string `json:"scheme,omitempty"`
	// Path prefix to add in front of the push endpoint path.
	PathPrefix string `json:"pathPrefix,omitempty"`
	// The timeout used when sending alerts.
	Timeout *string `json:"timeout,omitempty"`
	// The api version of Alertmanager.
	APIVersion string `json:"apiVersion"`
	// TLS Config to use for alertmanager connection.
	TLSConfig TLSConfig `json:"tlsConfig,omitempty"`
	// Bearer token to use when authenticating to Alertmanager.
	BearerToken *v1.SecretKeySelector `json:"bearerToken,omitempty"`
	// List of statically configured Alertmanagers.
	StaticConfigs []string `json:"staticConfigs,omitempty"`
}

// TLSConfig configures the options for TLS connections.
type TLSConfig struct {
	// The CA cert in the Prometheus container to use for the targets.
	CA *v1.SecretKeySelector `json:"ca,omitempty"`
	// The client cert in the Prometheus container to use for the targets.
	Cert *v1.SecretKeySelector `json:"cert,omitempty"`
	// The client key in the Prometheus container to use for the targets.
	Key *v1.SecretKeySelector `json:"key,omitempty"`
	// Used to verify the hostname for the targets.
	ServerName string `json:"serverName,omitempty"`
	// Disable target certificate validation.
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
}

type AlertmanagerMainConfig struct {
	Enabled             *bool                                `json:"enabled"`
	LogLevel            string                               `json:"logLevel"`
	NodeSelector        map[string]string                    `json:"nodeSelector"`
	Tolerations         []v1.Toleration                      `json:"tolerations"`
	Resources           *v1.ResourceRequirements             `json:"resources"`
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate"`
}

type HTTPConfig struct {
	HTTPProxy  string `json:"httpProxy"`
	HTTPSProxy string `json:"httpsProxy"`
	NoProxy    string `json:"noProxy"`
}

type TelemeterClientConfig struct {
	ClusterID          string            `json:"clusterID"`
	Enabled            *bool             `json:"enabled"`
	TelemeterServerURL string            `json:"telemeterServerURL"`
	Token              string            `json:"token"`
	NodeSelector       map[string]string `json:"nodeSelector"`
	Tolerations        []v1.Toleration   `json:"tolerations"`
}
