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
	"encoding/json"
	"fmt"
	"io"

	configv1 "github.com/openshift/api/config/v1"
	v1 "k8s.io/api/core/v1"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

const (
	DefaultRetentionValue = "15d"
)

type Config struct {
	Images      *Images `json:"-"`
	RemoteWrite bool    `json:"-"`

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

// GetPrometheusUWAdditionalAlertmanagerConfigs returns the alertmanager configurations for
// the User Workload Monitoring Prometheus instance.
// If no additional configurations are specified, GetPrometheusUWAdditionalAlertmanagerConfigs returns nil.
func (c Config) GetPrometheusUWAdditionalAlertmanagerConfigs() []AdditionalAlertmanagerConfig {
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
	K8sPrometheusAdapter     string
	PromLabelProxy           string
	PrometheusOperator       string
	PrometheusConfigReloader string
	Prometheus               string
	Alertmanager             string
	Grafana                  string
	OauthProxy               string
	NodeExporter             string
	KubeStateMetrics         string
	OpenShiftStateMetrics    string
	KubeRbacProxy            string
	TelemeterClient          string
	Thanos                   string
}

func (a AlertmanagerMainConfig) IsEnabled() bool {
	return a.Enabled == nil || *a.Enabled
}

// IsEnabled returns the underlying value of the `Enabled` boolean pointer.  It
// defaults to TRUE if the pointer is nil because Grafana should be enabled by
// default.
func (g *GrafanaConfig) IsEnabled() bool {
	if g.Enabled == nil {
		return true
	}
	return *g.Enabled
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

	if (cfg.Enabled != nil && *cfg.Enabled == false) ||
		cfg.ClusterID == "" ||
		cfg.Token == "" {
		return false
	}

	return true
}

func NewConfig(content io.Reader) (*Config, error) {
	c := Config{}
	cmc := ClusterMonitoringConfiguration{}
	err := k8syaml.NewYAMLOrJSONDecoder(content, 4096).Decode(&cmc)
	if err != nil {
		return nil, err
	}
	c.ClusterMonitoringConfiguration = &cmc
	res := &c
	res.applyDefaults()
	c.UserWorkloadConfiguration = NewDefaultUserWorkloadMonitoringConfig()

	return res, nil
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
	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention == "" {
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
	if c.ClusterMonitoringConfiguration.GrafanaConfig == nil {
		c.ClusterMonitoringConfiguration.GrafanaConfig = &GrafanaConfig{}
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
	if c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.Audit == nil {
		c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.Audit = &Audit{}
	}
	if c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.Audit.Profile == "" {
		c.ClusterMonitoringConfiguration.K8sPrometheusAdapter.Audit.Profile = auditv1.LevelMetadata
	}

	if c.ClusterMonitoringConfiguration.EtcdConfig == nil {
		c.ClusterMonitoringConfiguration.EtcdConfig = &EtcdConfig{}
	}
}

func (c *Config) SetImages(images map[string]string) {
	c.Images.PrometheusOperator = images["prometheus-operator"]
	c.Images.PrometheusConfigReloader = images["prometheus-config-reloader"]
	c.Images.Prometheus = images["prometheus"]
	c.Images.Alertmanager = images["alertmanager"]
	c.Images.Grafana = images["grafana"]
	c.Images.OauthProxy = images["oauth-proxy"]
	c.Images.NodeExporter = images["node-exporter"]
	c.Images.KubeStateMetrics = images["kube-state-metrics"]
	c.Images.KubeRbacProxy = images["kube-rbac-proxy"]
	c.Images.TelemeterClient = images["telemeter-client"]
	c.Images.PromLabelProxy = images["prom-label-proxy"]
	c.Images.K8sPrometheusAdapter = images["k8s-prometheus-adapter"]
	c.Images.OpenShiftStateMetrics = images["openshift-state-metrics"]
	c.Images.Thanos = images["thanos"]
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

func NewConfigFromString(content string) (*Config, error) {
	if content == "" {
		return NewDefaultConfig(), nil
	}

	return NewConfig(bytes.NewBuffer([]byte(content)))
}

func NewDefaultConfig() *Config {
	c := &Config{}
	cmc := ClusterMonitoringConfiguration{}
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
