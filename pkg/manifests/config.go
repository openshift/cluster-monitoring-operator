// Copyright 2018 The Cluster Monitoring Operator Authors
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/pkg/errors"
	poperator "github.com/prometheus-operator/prometheus-operator/pkg/operator"
	"golang.org/x/exp/slices"
	v1 "k8s.io/api/core/v1"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/metrics"
)

const (
	DefaultRetentionValue = "15d"

	// Limit the body size from scrape queries
	// Assumptions: one node has in average 110 pods, each pod exposes 400 metrics, each metric is expressed by on average 250 bytes.
	// 1.5x the size for a safe margin,
	// minimal HA requires 3 nodes. it rounds to 47.2 MB (49,500,000 Bytes).
	minimalSizeLimit = 3 * 1.5 * 110 * 400 * 250

	// A value of Prometheusk8s.enforceBodySizeLimit,
	// meaning the limit will be automatically calculated based on cluster capacity.
	automaticBodySizeLimit = "automatic"
)

type Config struct {
	Images      *Images `json:"-"`
	RemoteWrite bool    `json:"-"`
	TechPreview bool    `json:"-"`

	ClusterMonitoringConfiguration *ClusterMonitoringConfiguration `json:"-"`
	UserWorkloadConfiguration      *UserWorkloadConfiguration      `json:"-"`
}

func (c Config) IsStorageConfigured() bool {
	if c.ClusterMonitoringConfiguration == nil {
		return false
	}

	prometheusK8sConfig := c.ClusterMonitoringConfiguration.PrometheusK8sConfig
	if prometheusK8sConfig == nil {
		return false
	}

	return prometheusK8sConfig.VolumeClaimTemplate != nil
}

func (c Config) HasInconsistentAlertmanagerConfigurations() bool {
	if c.ClusterMonitoringConfiguration == nil || c.UserWorkloadConfiguration == nil {
		return false
	}

	amConfig := c.ClusterMonitoringConfiguration.AlertmanagerMainConfig
	uwmConfig := c.UserWorkloadConfiguration.Alertmanager

	if amConfig == nil || uwmConfig == nil {
		return false
	}

	return amConfig.EnableUserAlertManagerConfig && uwmConfig.Enabled
}

// AdditionalAlertmanagerConfigsForPrometheusUserWorkload returns the alertmanager configurations for
// the User Workload Monitoring Prometheus instance.
// If no additional configurations are specified, GetPrometheusUWAdditionalAlertmanagerConfigs returns nil.
func (c Config) AdditionalAlertmanagerConfigsForPrometheusUserWorkload() []AdditionalAlertmanagerConfig {
	if c.UserWorkloadConfiguration == nil {
		return nil
	}

	if c.UserWorkloadConfiguration.Prometheus == nil {
		return nil
	}

	alertmanagerConfigs := c.UserWorkloadConfiguration.Prometheus.AlertmanagerConfigs
	if len(alertmanagerConfigs) == 0 {
		return nil
	}

	return alertmanagerConfigs
}

// GetThanosRulerAlertmanagerConfigs returns the alertmanager configurations for
// the User Workload Monitoring Thanos Ruler instance.
// If no additional configurations are specified, GetThanosRulerAlertmanagerConfigs returns nil.
func (c Config) GetThanosRulerAlertmanagerConfigs() []AdditionalAlertmanagerConfig {
	if c.UserWorkloadConfiguration == nil {
		return nil
	}

	if c.UserWorkloadConfiguration.ThanosRuler == nil {
		return nil
	}

	alertmanagerConfigs := c.UserWorkloadConfiguration.ThanosRuler.AlertmanagersConfigs
	if len(alertmanagerConfigs) == 0 {
		return nil
	}

	return alertmanagerConfigs
}

type Images struct {
	K8sPrometheusAdapter               string
	PromLabelProxy                     string
	PrometheusOperatorAdmissionWebhook string
	PrometheusOperator                 string
	PrometheusConfigReloader           string
	Prometheus                         string
	Alertmanager                       string
	OauthProxy                         string
	NodeExporter                       string
	KubeStateMetrics                   string
	OpenShiftStateMetrics              string
	KubeRbacProxy                      string
	TelemeterClient                    string
	Thanos                             string
	MonitoringPlugin                   string
}

type HTTPConfig struct {
	HTTPProxy  string `json:"httpProxy"`
	HTTPSProxy string `json:"httpsProxy"`
	NoProxy    string `json:"noProxy"`
}

func (a AlertmanagerMainConfig) IsEnabled() bool {
	return a.Enabled == nil || *a.Enabled
}

// Audit profile configurations
type Audit struct {

	// The Profile to set for audit logs. This currently matches the various
	// audit log levels such as: "metadata, request, requestresponse, none".
	// The default audit log level is "metadata"
	//
	// see: https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-policy
	// for more information about auditing and log levels.
	Profile auditv1.Level `json:"profile"`
}

type EtcdConfig struct {
	Enabled *bool `json:"-"`
}

// IsEnabled returns the underlying value of the `Enabled` boolean pointer.
// It defaults to false if the pointer is nil.
func (e *EtcdConfig) IsEnabled() bool {
	if e.Enabled == nil {
		return false
	}
	return *e.Enabled
}

func (cfg *TelemeterClientConfig) IsEnabled() bool {
	if cfg == nil {
		return false
	}

	if (cfg.Enabled != nil && !*cfg.Enabled) ||
		cfg.ClusterID == "" ||
		cfg.Token == "" {
		return false
	}

	return true
}

func (cps CollectionProfiles) String() string {
	var sb strings.Builder
	for i := 0; i < len(cps)-1; i++ {
		sb.WriteString(string(cps[i]))
		sb.WriteString(", ")
	}
	sb.WriteString(string(cps[len(cps)-1]))
	return sb.String()
}

func NewConfig(content io.Reader, tp bool) (*Config, error) {
	c := Config{}
	cmc := defaultClusterMonitoringConfiguration()
	err := k8syaml.NewYAMLOrJSONDecoder(content, 4096).Decode(&cmc)
	if err != nil {
		return nil, err
	}
	c.ClusterMonitoringConfiguration = &cmc
	res := &c
	res.applyDefaults()
	c.UserWorkloadConfiguration = NewDefaultUserWorkloadMonitoringConfig()
	// The operator should only create some manifests if techPreview is enabled
	c.TechPreview = tp

	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile != FullCollectionProfile && !tp {
		return nil, errors.Wrap(ErrConfigValidation, "collectionProfiles is a TechPreview feature, to be able to use a profile different from the default (\"full\") please enable TechPreview")
	}

	// Validate the configured collection profile iff tech preview is enabled, even if the default profile is set.
	if tp {
		for _, profile := range SupportedCollectionProfiles {
			var v float64
			if profile == c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile {
				v = 1
			}
			metrics.CollectionProfile.WithLabelValues(string(profile)).Set(v)
		}
		if !slices.Contains(SupportedCollectionProfiles, c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile) {
			return nil, errors.Wrap(ErrConfigValidation, fmt.Sprintf(`%q is not supported, supported collection profiles are: %q`, c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile, SupportedCollectionProfiles.String()))
		}
	}

	return res, nil
}

func defaultClusterMonitoringConfiguration() ClusterMonitoringConfiguration {
	return ClusterMonitoringConfiguration{
		NodeExporterConfig: NodeExporterConfig{
			Collectors: NodeExporterCollectorConfig{
				NetDev: NodeExporterCollectorNetDevConfig{
					Enabled: true,
				},
				NetClass: NodeExporterCollectorNetClassConfig{
					Enabled:    true,
					UseNetlink: true,
				},
			},
		},
	}
}

func (c *Config) applyDefaults() {
	if c.Images == nil {
		c.Images = &Images{}
	}
	if c.ClusterMonitoringConfiguration == nil {
		c.ClusterMonitoringConfiguration = &ClusterMonitoringConfiguration{}
	}
	if c.ClusterMonitoringConfiguration.PrometheusOperatorConfig == nil {
		c.ClusterMonitoringConfiguration.PrometheusOperatorConfig = &PrometheusOperatorConfig{}
	}
	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig == nil {
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig = &PrometheusK8sConfig{}
	}
	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention == "" && c.ClusterMonitoringConfiguration.PrometheusK8sConfig.RetentionSize == "" {
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention = DefaultRetentionValue
	}
	if c.ClusterMonitoringConfiguration.AlertmanagerMainConfig == nil {
		c.ClusterMonitoringConfiguration.AlertmanagerMainConfig = &AlertmanagerMainConfig{}
	}
	if c.ClusterMonitoringConfiguration.UserWorkloadEnabled == nil {
		disable := false
		c.ClusterMonitoringConfiguration.UserWorkloadEnabled = &disable
	}
	if c.ClusterMonitoringConfiguration.ThanosQuerierConfig == nil {
		c.ClusterMonitoringConfiguration.ThanosQuerierConfig = &ThanosQuerierConfig{}
	}
	if c.ClusterMonitoringConfiguration.KubeStateMetricsConfig == nil {
		c.ClusterMonitoringConfiguration.KubeStateMetricsConfig = &KubeStateMetricsConfig{}
	}
	if c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig == nil {
		c.ClusterMonitoringConfiguration.OpenShiftMetricsConfig = &OpenShiftStateMetricsConfig{}
	}
	if c.ClusterMonitoringConfiguration.HTTPConfig == nil {
		c.ClusterMonitoringConfiguration.HTTPConfig = &HTTPConfig{}
	}
	if c.ClusterMonitoringConfiguration.TelemeterClientConfig == nil {
		c.ClusterMonitoringConfiguration.TelemeterClientConfig = &TelemeterClientConfig{
			TelemeterServerURL: "https://infogw.api.openshift.com/",
		}
	}

	if c.ClusterMonitoringConfiguration.K8sPrometheusAdapter == nil {
		c.ClusterMonitoringConfiguration.K8sPrometheusAdapter = &K8sPrometheusAdapter{}
	}
	if c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.DedicatedServiceMonitors == nil {
		c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.DedicatedServiceMonitors = &DedicatedServiceMonitors{}
	}
	if c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.Audit == nil {
		c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.Audit = &Audit{}
	}
	if c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.Audit.Profile == "" {
		c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.Audit.Profile = auditv1.LevelMetadata
	}

	if c.ClusterMonitoringConfiguration.EtcdConfig == nil {
		c.ClusterMonitoringConfiguration.EtcdConfig = &EtcdConfig{}
	}

	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile == "" {
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile = FullCollectionProfile
	}

	// `defaultExcludedDevices` is the default for two arguments: `collector.netclass.ignored-devices` and `--collector.netdev.device-exclude`.
	// The following virtual NICs are ignored by default:
	// * `veth` network interface associated with containers.
	// * OVN renames `veth.*` to `<rand-hex>@if<X>` where `X` is `/sys/class/net/<if>/ifindex`
	// thus `[a-f0-9]{15}`
	// * `enP.*` virtual NICs on Azure cluster
	// * OVN virtual interfaces `ovn-k8s-mp[0-9]*`
	// * virtual tunnels and bridges: `tun[0-9]*|br[0-9]*|br-ex|br-int|br-ext`
	// * Calico Virtual NICs `cali[a-f0-9]*`
	// Refer to:
	// https://issues.redhat.com/browse/OCPBUGS-1321
	// https://issues.redhat.com/browse/OCPBUGS-2729
	// https://issues.redhat.com/browse/OCPBUGS-7282
	defaultExcludedDevices := []string{
		"veth.*",
		"[a-f0-9]{15}",
		"enP.*",
		"ovn-k8s-mp[0-9]*",
		"br-ex",
		"br-int",
		"br-ext",
		"br[0-9]*",
		"tun[0-9]*",
		"cali[a-f0-9]*",
	}
	if c.ClusterMonitoringConfiguration.NodeExporterConfig.IgnoredNetworkDevices == nil {
		c.ClusterMonitoringConfiguration.NodeExporterConfig.IgnoredNetworkDevices = &defaultExcludedDevices
	}
}

func (c *Config) SetImages(images map[string]string) {
	c.Images.PrometheusOperatorAdmissionWebhook = images["prometheus-operator-admission-webhook"]
	c.Images.PrometheusOperator = images["prometheus-operator"]
	c.Images.PrometheusConfigReloader = images["prometheus-config-reloader"]
	c.Images.Prometheus = images["prometheus"]
	c.Images.Alertmanager = images["alertmanager"]
	c.Images.OauthProxy = images["oauth-proxy"]
	c.Images.NodeExporter = images["node-exporter"]
	c.Images.KubeStateMetrics = images["kube-state-metrics"]
	c.Images.KubeRbacProxy = images["kube-rbac-proxy"]
	c.Images.TelemeterClient = images["telemeter-client"]
	c.Images.PromLabelProxy = images["prom-label-proxy"]
	c.Images.K8sPrometheusAdapter = images["k8s-prometheus-adapter"]
	c.Images.OpenShiftStateMetrics = images["openshift-state-metrics"]
	c.Images.Thanos = images["thanos"]
	c.Images.MonitoringPlugin = images["monitoring-plugin"]
}

func (c *Config) SetTelemetryMatches(matches []string) {
	c.ClusterMonitoringConfiguration.PrometheusK8sConfig.TelemetryMatches = matches
}

func (c *Config) SetRemoteWrite(rw bool) {
	c.RemoteWrite = rw
	if c.RemoteWrite && c.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL == "https://infogw.api.openshift.com/" {
		c.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL = "https://infogw.api.openshift.com/metrics/v1/receive"
	}
}

func (c *Config) LoadClusterID(load func() (*configv1.ClusterVersion, error)) error {
	if c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID != "" {
		return nil
	}

	cv, err := load()
	if err != nil {
		return fmt.Errorf("error loading cluster version: %v", err)
	}

	c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID = string(cv.Spec.ClusterID)
	return nil
}

func (c *Config) LoadToken(load func() (*v1.Secret, error)) error {
	if c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token != "" {
		return nil
	}

	secret, err := load()
	if err != nil {
		return fmt.Errorf("error loading secret: %v", err)
	}

	if secret.Type != v1.SecretTypeDockerConfigJson {
		return fmt.Errorf("error expecting secret type %s got %s", v1.SecretTypeDockerConfigJson, secret.Type)
	}

	ps := struct {
		Auths struct {
			COC struct {
				Auth string `json:"auth"`
			} `json:"cloud.openshift.com"`
		} `json:"auths"`
	}{}

	if err := json.Unmarshal(secret.Data[v1.DockerConfigJsonKey], &ps); err != nil {
		return fmt.Errorf("unmarshaling pull secret failed: %v", err)
	}

	c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token = ps.Auths.COC.Auth
	return nil
}

// HTTPProxy implements the ProxyReader interface.
func (c *Config) HTTPProxy() string {
	return c.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy
}

// HTTPSProxy implements the ProxyReader interface.
func (c *Config) HTTPSProxy() string {
	return c.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy
}

// NoProxy implements the ProxyReader interface.
func (c *Config) NoProxy() string {
	return c.ClusterMonitoringConfiguration.HTTPConfig.NoProxy
}

// PodCapacityReader returns the maximum number of pods that can be scheduled in a cluster.
type PodCapacityReader interface {
	PodCapacity(context.Context) (int, error)
}

func (c *Config) LoadEnforcedBodySizeLimit(pcr PodCapacityReader, ctx context.Context) error {
	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit == "" {
		return nil
	}

	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit == automaticBodySizeLimit {
		podCapacity, err := pcr.PodCapacity(ctx)
		if err != nil {
			return fmt.Errorf("error fetching pod capacity: %v", err)
		}
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit = calculateBodySizeLimit(podCapacity)
		return nil
	}

	return poperator.ValidateSizeField(c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit)
}

func calculateBodySizeLimit(podCapacity int) string {
	const samplesPerPod = 400 // 400 samples per pod
	const sizePerSample = 200 // 200 Bytes

	bodySize := podCapacity * samplesPerPod * sizePerSample
	if bodySize < minimalSizeLimit {
		klog.Infof("Calculated scrape body size limit %v is too small, using default value %v instead", bodySize, minimalSizeLimit)
		bodySize = minimalSizeLimit
	}

	return fmt.Sprintf("%dMB", int(math.Ceil(float64(bodySize)/(1024*1024))))
}

// NewConfigFromString transforms a string containing configuration in the
// openshift-monitoring/cluster-monitoring-configuration format into a data
// structure that facilitates programmatical checks of that configuration. The
// content of the data structure might change if TechPreview is enabled (tp), as
// some features are only meant for TechPreview.
func NewConfigFromString(content string, tp bool) (*Config, error) {
	if content == "" {
		return NewDefaultConfig(), nil
	}

	return NewConfig(bytes.NewBuffer([]byte(content)), tp)
}

func NewDefaultConfig() *Config {
	c := &Config{}
	cmc := defaultClusterMonitoringConfiguration()
	c.ClusterMonitoringConfiguration = &cmc
	c.UserWorkloadConfiguration = NewDefaultUserWorkloadMonitoringConfig()
	c.applyDefaults()
	return c
}

func (u *UserWorkloadConfiguration) applyDefaults() {
	if u.PrometheusOperator == nil {
		u.PrometheusOperator = &PrometheusOperatorConfig{}
	}
	if u.Prometheus == nil {
		u.Prometheus = &PrometheusRestrictedConfig{}
	}
	if u.ThanosRuler == nil {
		u.ThanosRuler = &ThanosRulerConfig{}
	}
	if u.Alertmanager == nil {
		u.Alertmanager = &AlertmanagerUserWorkloadConfig{}
	}
}

func NewUserConfigFromString(content string) (*UserWorkloadConfiguration, error) {
	if content == "" {
		return NewDefaultUserWorkloadMonitoringConfig(), nil
	}
	u := &UserWorkloadConfiguration{}
	err := k8syaml.NewYAMLOrJSONDecoder(bytes.NewBuffer([]byte(content)), 100).Decode(&u)
	if err != nil {
		return nil, err
	}

	u.applyDefaults()

	return u, nil
}

func NewDefaultUserWorkloadMonitoringConfig() *UserWorkloadConfiguration {
	u := &UserWorkloadConfiguration{}
	u.applyDefaults()
	return u
}
