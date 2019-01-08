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
	PrometheusOperatorConfig *PrometheusOperatorConfig `json:"prometheusOperator"`
	PrometheusK8sConfig      *PrometheusK8sConfig      `json:"prometheusK8s"`
	AlertmanagerMainConfig   *AlertmanagerMainConfig   `json:"alertmanagerMain"`
	AuthConfig               *AuthConfig               `json:"auth"`
	NodeExporterConfig       *NodeExporterConfig       `json:"nodeExporter"`
	KubeStateMetricsConfig   *KubeStateMetricsConfig   `json:"kubeStateMetrics"`
	KubeRbacProxyConfig      *KubeRbacProxyConfig      `json:"kubeRbacProxy"`
	GrafanaConfig            *GrafanaConfig            `json:"grafana"`
	EtcdConfig               *EtcdConfig               `json:"etcd"`
	HTTPConfig               *HTTPConfig               `json:"http"`
	TelemeterClientConfig    *TelemeterClientConfig    `json:"telemeterClient"`
}

type HTTPConfig struct {
	HTTPProxy  string `json:"httpProxy"`
	HTTPSProxy string `json:"httpsProxy"`
	NoProxy    string `json:"noProxy"`
}

type PrometheusOperatorConfig struct {
	Image                         string            `json:"-"`
	PrometheusConfigReloaderImage string            `json:"-"`
	ConfigReloaderImage           string            `json:"-"`
	NodeSelector                  map[string]string `json:"nodeSelector"`
}

type PrometheusK8sConfig struct {
	Retention           string                    `json:"retention"`
	Image               string                    `json:"-"`
	NodeSelector        map[string]string         `json:"nodeSelector"`
	Resources           *v1.ResourceRequirements  `json:"resources"`
	ExternalLabels      map[string]string         `json:"externalLabels"`
	VolumeClaimTemplate *v1.PersistentVolumeClaim `json:"volumeClaimTemplate"`
	Hostport            string                    `json:"hostport"`
}

type AlertmanagerMainConfig struct {
	Image               string                    `json:"-"`
	NodeSelector        map[string]string         `json:"nodeSelector"`
	Resources           *v1.ResourceRequirements  `json:"resources"`
	VolumeClaimTemplate *v1.PersistentVolumeClaim `json:"volumeClaimTemplate"`
	Hostport            string                    `json:"hostport"`
}

type GrafanaConfig struct {
	Image        string            `json:"-"`
	NodeSelector map[string]string `json:"nodeSelector"`
	Hostport     string            `json:"hostport"`
}

type AuthConfig struct {
	Image string `json:"-"`
}

type NodeExporterConfig struct {
	Image string `json:"-"`
}

type KubeStateMetricsConfig struct {
	Image        string            `json:"-"`
	NodeSelector map[string]string `json:"nodeSelector"`
}

type KubeRbacProxyConfig struct {
	Image string `json:"-"`
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
	Image              string `json:"-"`
	ClusterID          string `json:"clusterID"`
	Enabled            *bool  `json:"enabled"`
	TelemeterServerURL string `json:"telemeterServerURL"`
	Token              string `json:"token"`
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
	if c.AuthConfig == nil {
		c.AuthConfig = &AuthConfig{}
	}
	if c.NodeExporterConfig == nil {
		c.NodeExporterConfig = &NodeExporterConfig{}
	}
	if c.KubeStateMetricsConfig == nil {
		c.KubeStateMetricsConfig = &KubeStateMetricsConfig{}
	}
	if c.KubeRbacProxyConfig == nil {
		c.KubeRbacProxyConfig = &KubeRbacProxyConfig{}
	}
	if c.HTTPConfig == nil {
		c.HTTPConfig = &HTTPConfig{}
	}
	if c.TelemeterClientConfig == nil {
		c.TelemeterClientConfig = &TelemeterClientConfig{}
	}
	if c.EtcdConfig == nil {
		c.EtcdConfig = &EtcdConfig{}
	}
}

func (c *Config) SetImages(images map[string]string) {
	c.PrometheusOperatorConfig.Image = images["prometheus-operator"]
	c.PrometheusOperatorConfig.PrometheusConfigReloaderImage = images["prometheus-config-reloader"]
	c.PrometheusOperatorConfig.ConfigReloaderImage = images["configmap-reload"]
	c.PrometheusK8sConfig.Image = images["prometheus"]
	c.AlertmanagerMainConfig.Image = images["alertmanager"]
	c.GrafanaConfig.Image = images["grafana"]
	c.AuthConfig.Image = images["oauth-proxy"]
	c.NodeExporterConfig.Image = images["node-exporter"]
	c.KubeStateMetricsConfig.Image = images["kube-state-metrics"]
	c.KubeRbacProxyConfig.Image = images["kube-rbac-proxy"]
	c.TelemeterClientConfig.Image = images["telemeter-client"]
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
