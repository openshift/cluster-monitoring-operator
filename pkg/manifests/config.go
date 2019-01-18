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
	"io"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type Config struct {
	Images                   *Images                   `json:"-"`
	PrometheusOperatorConfig *PrometheusOperatorConfig `json:"prometheusOperator"`
	PrometheusK8sConfig      *PrometheusK8sConfig      `json:"prometheusK8s"`
	AlertmanagerMainConfig   *AlertmanagerMainConfig   `json:"alertmanagerMain"`
	KubeStateMetricsConfig   *KubeStateMetricsConfig   `json:"kubeStateMetrics"`
	GrafanaConfig            *GrafanaConfig            `json:"grafana"`
	EtcdConfig               *EtcdConfig               `json:"etcd"`
	HTTPConfig               *HTTPConfig               `json:"http"`
	TelemeterClientConfig    *TelemeterClientConfig    `json:"telemeterClient"`
	K8sPrometheusAdapter     *K8sPrometheusAdapter     `json:"k8sPrometheusAdapter"`
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
	KubeRbacProxy            string
	TelemeterClient          string
}

type HTTPConfig struct {
	HTTPProxy  string `json:"httpProxy"`
	HTTPSProxy string `json:"httpsProxy"`
	NoProxy    string `json:"noProxy"`
}

type PrometheusOperatorConfig struct {
	NodeSelector map[string]string `json:"nodeSelector"`
}

type PrometheusK8sConfig struct {
	Retention           string                    `json:"retention"`
	NodeSelector        map[string]string         `json:"nodeSelector"`
	Resources           *v1.ResourceRequirements  `json:"resources"`
	ExternalLabels      map[string]string         `json:"externalLabels"`
	VolumeClaimTemplate *v1.PersistentVolumeClaim `json:"volumeClaimTemplate"`
	Hostport            string                    `json:"hostport"`
}

type AlertmanagerMainConfig struct {
	NodeSelector        map[string]string         `json:"nodeSelector"`
	Resources           *v1.ResourceRequirements  `json:"resources"`
	VolumeClaimTemplate *v1.PersistentVolumeClaim `json:"volumeClaimTemplate"`
	Hostport            string                    `json:"hostport"`
}

type GrafanaConfig struct {
	NodeSelector map[string]string `json:"nodeSelector"`
	Hostport     string            `json:"hostport"`
}

type KubeStateMetricsConfig struct {
	NodeSelector map[string]string `json:"nodeSelector"`
}

type K8sPrometheusAdapter struct {
	NodeSelector map[string]string `json:"nodeSelector"`
}

type EtcdConfig struct {
	Enabled    *bool  `json:"enabled"`
	ServerName string `json:"serverName"`
}

// IsEnabled returns the underlying value of the `Enabled` boolean pointer.
// It defaults to false if the pointer is nil.
func (e *EtcdConfig) IsEnabled() bool {
	if e.Enabled == nil {
		return false
	}
	return *e.Enabled
}

type TelemeterClientConfig struct {
	ClusterID          string            `json:"clusterID"`
	Enabled            *bool             `json:"enabled"`
	TelemeterServerURL string            `json:"telemeterServerURL"`
	Token              string            `json:"token"`
	NodeSelector       map[string]string `json:"nodeSelector"`
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

	err := yaml.NewYAMLOrJSONDecoder(content, 100).Decode(&c)
	if err != nil {
		return nil, err
	}

	res := &c
	res.applyDefaults()

	return res, nil
}

func (c *Config) applyDefaults() {
	if c.Images == nil {
		c.Images = &Images{}
	}
	if c.PrometheusOperatorConfig == nil {
		c.PrometheusOperatorConfig = &PrometheusOperatorConfig{}
	}
	if c.PrometheusK8sConfig == nil {
		c.PrometheusK8sConfig = &PrometheusK8sConfig{}
	}
	if c.PrometheusK8sConfig.Retention == "" {
		c.PrometheusK8sConfig.Retention = "15d"
	}
	if c.PrometheusK8sConfig.Resources == nil {
		c.PrometheusK8sConfig.Resources = &v1.ResourceRequirements{}
	}
	if c.AlertmanagerMainConfig == nil {
		c.AlertmanagerMainConfig = &AlertmanagerMainConfig{}
	}
	if c.AlertmanagerMainConfig.Resources == nil {
		c.AlertmanagerMainConfig.Resources = &v1.ResourceRequirements{}
	}
	if c.GrafanaConfig == nil {
		c.GrafanaConfig = &GrafanaConfig{}
	}
	if c.KubeStateMetricsConfig == nil {
		c.KubeStateMetricsConfig = &KubeStateMetricsConfig{}
	}
	if c.HTTPConfig == nil {
		c.HTTPConfig = &HTTPConfig{}
	}
	if c.TelemeterClientConfig == nil {
		c.TelemeterClientConfig = &TelemeterClientConfig{}
	}
	if c.K8sPrometheusAdapter == nil {
		c.K8sPrometheusAdapter = &K8sPrometheusAdapter{}
	}
	if c.EtcdConfig == nil {
		c.EtcdConfig = &EtcdConfig{}
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
}

func (c *Config) LoadClusterID(load func() (*configv1.ClusterVersion, error)) error {
	if c.TelemeterClientConfig.ClusterID != "" {
		return nil
	}

	cv, err := load()
	if err != nil {
		return fmt.Errorf("error loading cluster version: %v", err)
	}

	c.TelemeterClientConfig.ClusterID = string(cv.Spec.ClusterID)
	return nil
}

func (c *Config) LoadToken(load func() (*v1.ConfigMap, error)) error {
	if c.TelemeterClientConfig.Token != "" {
		return nil
	}

	cmap, err := load()
	if err != nil {
		return fmt.Errorf("error loading configmap: %v", err)
	}

	ic := make(map[string]interface{})
	if err := yaml.Unmarshal([]byte(cmap.Data["install-config"]), &ic); err != nil {
		return fmt.Errorf("unmarshaling install config failed: %v", err)
	}

	if _, ok := ic["pullSecret"].(string); !ok {
		return errors.New("could not find pull secret")
	}

	ps := struct {
		Auths struct {
			COC struct {
				Auth string `json:"auth"`
			} `json:"cloud.openshift.com"`
		} `json:"auths"`
	}{}

	if err := json.Unmarshal([]byte(ic["pullSecret"].(string)), &ps); err != nil {
		return fmt.Errorf("unmarshaling pull secret failed: %v", err)
	}

	c.TelemeterClientConfig.Token = ps.Auths.COC.Auth
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
	c.applyDefaults()
	return c
}
