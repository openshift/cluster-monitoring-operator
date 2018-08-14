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
}

type HTTPConfig struct {
	HTTPProxy  string `json:"httpProxy"`
	HTTPSProxy string `json:"httpsProxy"`
	NoProxy    string `json:"noProxy"`
}

type PrometheusOperatorConfig struct {
	BaseImage                   string `json:"baseImage"`
	Tag                         string `json:"-"`
	PrometheusConfigReloader    string `json:"prometheusConfigReloaderBaseImage"`
	PrometheusConfigReloaderTag string `json:"-"`
	ConfigReloaderImage         string `json:"configReloaderBaseImage"`
	ConfigReloaderTag           string `json:"-"`
}

type PrometheusK8sConfig struct {
	Retention           string                    `json:"retention"`
	BaseImage           string                    `json:"baseImage"`
	Tag                 string                    `json:"-"`
	NodeSelector        map[string]string         `json:"nodeSelector"`
	Resources           *v1.ResourceRequirements  `json:"resources"`
	ExternalLabels      map[string]string         `json:"externalLabels"`
	VolumeClaimTemplate *v1.PersistentVolumeClaim `json:"volumeClaimTemplate"`
	Hostport            string                    `json:"hostport"`
}

type AlertmanagerMainConfig struct {
	BaseImage           string                    `json:"baseImage"`
	Tag                 string                    `json:"-"`
	NodeSelector        map[string]string         `json:"nodeSelector"`
	Resources           *v1.ResourceRequirements  `json:"resources"`
	VolumeClaimTemplate *v1.PersistentVolumeClaim `json:"volumeClaimTemplate"`
	Hostport            string                    `json:"hostport"`
}

type GrafanaConfig struct {
	BaseImage    string            `json:"baseImage"`
	Tag          string            `json:"-"`
	NodeSelector map[string]string `json:"nodeSelector"`
	Hostport     string            `json:"hostport"`
}

type AuthConfig struct {
	BaseImage string `json:"baseImage"`
	Tag       string `json:"-"`
}

type NodeExporterConfig struct {
	BaseImage string `json:"baseImage"`
	Tag       string `json:"-"`
}

type KubeStateMetricsConfig struct {
	BaseImage    string            `json:"baseImage"`
	Tag          string            `json:"-"`
	NodeSelector map[string]string `json:"nodeSelector"`
}

type KubeRbacProxyConfig struct {
	BaseImage string `json:"baseImage"`
	Tag       string `json:"-"`
}

type EtcdConfig struct {
	Enabled   *bool          `json:"enabled"`
	Targets   EtcdTargets    `json:"targets,omitempty"`
	TLSConfig *EtcdTLSConfig `json:"tlsConfig"`
}

type EtcdTargets struct {
	IPs      []string          `json:"ips"`
	Selector map[string]string `json:"selector"`
}

type EtcdTLSConfig struct {
	ServerName string `json:"serverName"`
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
	if c.PrometheusOperatorConfig.BaseImage == "" {
		c.PrometheusOperatorConfig.BaseImage = "quay.io/coreos/prometheus-operator"
	}
	if c.PrometheusOperatorConfig.PrometheusConfigReloader == "" {
		c.PrometheusOperatorConfig.PrometheusConfigReloader = "quay.io/coreos/prometheus-config-reloader"
	}
	if c.PrometheusOperatorConfig.ConfigReloaderImage == "" {
		c.PrometheusOperatorConfig.ConfigReloaderImage = "quay.io/coreos/configmap-reload"
	}
	if c.PrometheusK8sConfig == nil {
		c.PrometheusK8sConfig = &PrometheusK8sConfig{}
	}
	if c.PrometheusK8sConfig.BaseImage == "" {
		c.PrometheusK8sConfig.BaseImage = "quay.io/prometheus/prometheus"
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
	if c.AlertmanagerMainConfig.BaseImage == "" {
		c.AlertmanagerMainConfig.BaseImage = "quay.io/prometheus/alertmanager"
	}
	if c.AlertmanagerMainConfig.Resources == nil {
		c.AlertmanagerMainConfig.Resources = &v1.ResourceRequirements{}
	}
	if c.GrafanaConfig == nil {
		c.GrafanaConfig = &GrafanaConfig{}
	}
	if c.GrafanaConfig.BaseImage == "" {
		c.GrafanaConfig.BaseImage = "grafana/grafana"
	}
	if c.AuthConfig == nil {
		c.AuthConfig = &AuthConfig{}
	}
	if c.AuthConfig.BaseImage == "" {
		c.AuthConfig.BaseImage = "openshift/oauth-proxy"
	}
	if c.NodeExporterConfig == nil {
		c.NodeExporterConfig = &NodeExporterConfig{}
	}
	if c.NodeExporterConfig.BaseImage == "" {
		c.NodeExporterConfig.BaseImage = "quay.io/prometheus/node-exporter"
	}
	if c.KubeStateMetricsConfig == nil {
		c.KubeStateMetricsConfig = &KubeStateMetricsConfig{}
	}
	if c.KubeStateMetricsConfig.BaseImage == "" {
		c.KubeStateMetricsConfig.BaseImage = "quay.io/coreos/kube-state-metrics"
	}
	if c.KubeRbacProxyConfig == nil {
		c.KubeRbacProxyConfig = &KubeRbacProxyConfig{}
	}
	if c.KubeRbacProxyConfig.BaseImage == "" {
		c.KubeRbacProxyConfig.BaseImage = "quay.io/brancz/kube-rbac-proxy"
	}
	if c.HTTPConfig == nil {
		c.HTTPConfig = &HTTPConfig{}
	}
}

func (c *Config) SetTagOverrides(tagOverrides map[string]string) {
	c.PrometheusOperatorConfig.Tag, _ = tagOverrides["prometheus-operator"]
	c.PrometheusOperatorConfig.PrometheusConfigReloaderTag, _ = tagOverrides["prometheus-config-reloader"]
	c.PrometheusOperatorConfig.ConfigReloaderTag, _ = tagOverrides["config-reloader"]
	c.PrometheusK8sConfig.Tag, _ = tagOverrides["prometheus"]
	c.AlertmanagerMainConfig.Tag, _ = tagOverrides["alertmanager"]
	c.GrafanaConfig.Tag, _ = tagOverrides["grafana"]
	c.AuthConfig.Tag, _ = tagOverrides["oauth-proxy"]
	c.NodeExporterConfig.Tag, _ = tagOverrides["node-exporter"]
	c.KubeStateMetricsConfig.Tag, _ = tagOverrides["kube-state-metrics"]
	c.KubeRbacProxyConfig.Tag, _ = tagOverrides["kube-rbac-proxy"]
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
