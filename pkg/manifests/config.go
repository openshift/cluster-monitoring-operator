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

	monv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	configv1 "github.com/openshift/api/config/v1"
	v1 "k8s.io/api/core/v1"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

type Config struct {
	Images      *Images               `json:"-"`
	RemoteWrite bool                  `json:"-"`
	Platform    configv1.PlatformType `json:"-"`

	ClusterMonitoringConfiguration *ClusterMonitoringConfiguration `json:"-"`
	UserWorkloadConfiguration      *UserWorkloadConfiguration      `json:"-"`
}

type ClusterMonitoringConfiguration struct {
	PrometheusOperatorConfig *PrometheusOperatorConfig    `json:"prometheusOperator"`
	PrometheusK8sConfig      *PrometheusK8sConfig         `json:"prometheusK8s"`
	AlertmanagerMainConfig   *AlertmanagerMainConfig      `json:"alertmanagerMain"`
	KubeStateMetricsConfig   *KubeStateMetricsConfig      `json:"kubeStateMetrics"`
	OpenShiftMetricsConfig   *OpenShiftStateMetricsConfig `json:"openshiftStateMetrics"`
	GrafanaConfig            *GrafanaConfig               `json:"grafana"`
	EtcdConfig               *EtcdConfig                  `json:"-"`
	HTTPConfig               *HTTPConfig                  `json:"http"`
	TelemeterClientConfig    *TelemeterClientConfig       `json:"telemeterClient"`
	K8sPrometheusAdapter     *K8sPrometheusAdapter        `json:"k8sPrometheusAdapter"`
	ThanosQuerierConfig      *ThanosQuerierConfig         `json:"thanosQuerier"`
	UserWorkloadEnabled      *bool                        `json:"enableUserWorkload"`
	// TODO: Remove in 4.7 release.
	PrometheusUserWorkloadConfig         *PrometheusK8sConfig      `json:"prometheusUserWorkload"`
	PrometheusOperatorUserWorkloadConfig *PrometheusOperatorConfig `json:"prometheusOperatorUserWorkload"`
	ThanosRulerConfig                    *ThanosRulerConfig        `json:"thanosRuler"`
	UserWorkloadConfig                   *UserWorkloadConfig       `json:"techPreviewUserWorkload"`
}

type Images struct {
	K8sPrometheusAdapter     string
	PromLabelProxy           string
	PrometheusOperator       string
	PrometheusConfigReloader string
	ConfigmapReloader        string
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

type HTTPConfig struct {
	HTTPProxy  string `json:"httpProxy"`
	HTTPSProxy string `json:"httpsProxy"`
	NoProxy    string `json:"noProxy"`
}

type PrometheusOperatorConfig struct {
	LogLevel     string            `json:"logLevel"`
	NodeSelector map[string]string `json:"nodeSelector"`
	Tolerations  []v1.Toleration   `json:"tolerations"`
}

type PrometheusK8sConfig struct {
	LogLevel            string                               `json:"logLevel"`
	Retention           string                               `json:"retention"`
	NodeSelector        map[string]string                    `json:"nodeSelector"`
	Tolerations         []v1.Toleration                      `json:"tolerations"`
	Resources           *v1.ResourceRequirements             `json:"resources"`
	ExternalLabels      map[string]string                    `json:"externalLabels"`
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate"`
	RemoteWrite         []monv1.RemoteWriteSpec              `json:"remoteWrite"`
	TelemetryMatches    []string                             `json:"-"`
}

type AlertmanagerMainConfig struct {
	NodeSelector        map[string]string                    `json:"nodeSelector"`
	Tolerations         []v1.Toleration                      `json:"tolerations"`
	Resources           *v1.ResourceRequirements             `json:"resources"`
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate"`
}

type ThanosRulerConfig struct {
	LogLevel            string                               `json:"logLevel"`
	NodeSelector        map[string]string                    `json:"nodeSelector"`
	Tolerations         []v1.Toleration                      `json:"tolerations"`
	Resources           *v1.ResourceRequirements             `json:"resources"`
	VolumeClaimTemplate *monv1.EmbeddedPersistentVolumeClaim `json:"volumeClaimTemplate"`
}

type ThanosQuerierConfig struct {
	NodeSelector map[string]string        `json:"nodeSelector"`
	Tolerations  []v1.Toleration          `json:"tolerations"`
	Resources    *v1.ResourceRequirements `json:"resources"`
}

type GrafanaConfig struct {
	NodeSelector map[string]string `json:"nodeSelector"`
	Tolerations  []v1.Toleration   `json:"tolerations"`
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

type UserWorkloadConfig struct {
	Enabled *bool `json:"enabled"`
}

type TelemeterClientConfig struct {
	ClusterID          string            `json:"clusterID"`
	Enabled            *bool             `json:"enabled"`
	TelemeterServerURL string            `json:"telemeterServerURL"`
	Token              string            `json:"token"`
	NodeSelector       map[string]string `json:"nodeSelector"`
	Tolerations        []v1.Toleration   `json:"tolerations"`
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
	if c.ClusterMonitoringConfiguration.PrometheusOperatorUserWorkloadConfig == nil {
		c.ClusterMonitoringConfiguration.PrometheusOperatorUserWorkloadConfig = &PrometheusOperatorConfig{}
	}
	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig == nil {
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig = &PrometheusK8sConfig{}
	}
	if c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention == "" {
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention = "15d"
	}
	if c.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig == nil {
		c.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig = &PrometheusK8sConfig{}
	}
	if c.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.Retention == "" {
		c.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.Retention = "15d"
	}
	if c.ClusterMonitoringConfiguration.AlertmanagerMainConfig == nil {
		c.ClusterMonitoringConfiguration.AlertmanagerMainConfig = &AlertmanagerMainConfig{}
	}
	if c.ClusterMonitoringConfiguration.UserWorkloadEnabled == nil {
		disable := false
		c.ClusterMonitoringConfiguration.UserWorkloadEnabled = &disable
	}
	if c.ClusterMonitoringConfiguration.ThanosRulerConfig == nil {
		c.ClusterMonitoringConfiguration.ThanosRulerConfig = &ThanosRulerConfig{}
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
	if c.ClusterMonitoringConfiguration.EtcdConfig == nil {
		c.ClusterMonitoringConfiguration.EtcdConfig = &EtcdConfig{}
	}
	if c.ClusterMonitoringConfiguration.UserWorkloadConfig == nil {
		c.ClusterMonitoringConfiguration.UserWorkloadConfig = &UserWorkloadConfig{}
	}
}

func (c *Config) SetImages(images map[string]string) {
	c.Images.PrometheusOperator = images["prometheus-operator"]
	c.Images.PrometheusConfigReloader = images["prometheus-config-reloader"]
	c.Images.ConfigmapReloader = images["configmap-reloader"]
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

func (c *Config) LoadProxy(load func() (*configv1.Proxy, error)) error {
	if c.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy != "" || c.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy != "" || c.ClusterMonitoringConfiguration.HTTPConfig.NoProxy != "" {
		return nil
	}

	p, err := load()
	if err != nil {
		return fmt.Errorf("error loading proxy: %v", err)
	}

	c.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy = p.Status.HTTPProxy
	c.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy = p.Status.HTTPSProxy
	c.ClusterMonitoringConfiguration.HTTPConfig.NoProxy = p.Status.NoProxy

	return nil
}

func (c *Config) LoadPlatform(load func() (*configv1.Infrastructure, error)) error {
	i, err := load()
	if err != nil {
		return fmt.Errorf("error loading platform: %v", err)
	}
	c.Platform = i.Status.Platform
	return nil
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

type UserWorkloadConfiguration struct {
	PrometheusOperator *PrometheusOperatorConfig `json:"prometheusOperator"`
	Prometheus         *PrometheusK8sConfig      `json:"prometheus"`
	ThanosRuler        *ThanosRulerConfig        `json:"thanosRuler"`
}

func (u *UserWorkloadConfiguration) applyDefaults() {
	if u.PrometheusOperator == nil {
		u.PrometheusOperator = &PrometheusOperatorConfig{}
	}
	if u.Prometheus == nil {
		u.Prometheus = &PrometheusK8sConfig{}
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

// IsUserWorkloadEnabled checks if user workload monitoring is
// enabled on old or new configuration.
func (c *Config) IsUserWorkloadEnabled() bool {
	if *c.ClusterMonitoringConfiguration.UserWorkloadEnabled == true {
		return true
	}

	return c.ClusterMonitoringConfiguration.UserWorkloadConfig.isEnabled()
}

// isEnabled returns the underlying value of the `Enabled` boolean pointer.
// It defaults to false if the pointer is nil.
func (c *UserWorkloadConfig) isEnabled() bool {
	if c.Enabled == nil {
		return false
	}
	return *c.Enabled
}
