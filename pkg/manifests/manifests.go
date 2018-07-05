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
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	monv1 "github.com/coreos/prometheus-operator/pkg/client/monitoring/v1"
	routev1 "github.com/openshift/api/route/v1"
	securityv1 "github.com/openshift/api/security/v1"
	appsv1 "k8s.io/api/apps/v1beta2"
	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	rbacv1beta1 "k8s.io/api/rbac/v1beta1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

var (
	AlertmanagerConfig             = "assets/alertmanager/secret.yaml"
	AlertmanagerService            = "assets/alertmanager/service.yaml"
	AlertmanagerProxySecret        = "assets/alertmanager/proxy-secret.yaml"
	AlertmanagerMain               = "assets/alertmanager/alertmanager.yaml"
	AlertmanagerServiceAccount     = "assets/alertmanager/service-account.yaml"
	AlertmanagerClusterRoleBinding = "assets/alertmanager/cluster-role-binding.yaml"
	AlertmanagerClusterRole        = "assets/alertmanager/cluster-role.yaml"
	AlertmanagerRoute              = "assets/alertmanager/route.yaml"
	AlertmanagerServiceMonitor     = "assets/alertmanager/service-monitor.yaml"

	KubeStateMetricsClusterRoleBinding = "assets/kube-state-metrics/cluster-role-binding.yaml"
	KubeStateMetricsClusterRole        = "assets/kube-state-metrics/cluster-role.yaml"
	KubeStateMetricsDeployment         = "assets/kube-state-metrics/deployment.yaml"
	KubeStateMetricsServiceAccount     = "assets/kube-state-metrics/service-account.yaml"
	KubeStateMetricsService            = "assets/kube-state-metrics/service.yaml"
	KubeStateMetricsServiceMonitor     = "assets/kube-state-metrics/service-monitor.yaml"

	NodeExporterDaemonSet                  = "assets/node-exporter/daemonset.yaml"
	NodeExporterService                    = "assets/node-exporter/service.yaml"
	NodeExporterServiceAccount             = "assets/node-exporter/service-account.yaml"
	NodeExporterClusterRole                = "assets/node-exporter/cluster-role.yaml"
	NodeExporterClusterRoleBinding         = "assets/node-exporter/cluster-role-binding.yaml"
	NodeExporterSecurityContextConstraints = "assets/node-exporter/security-context-constraints.yaml"
	NodeExporterServiceMonitor             = "assets/node-exporter/service-monitor.yaml"

	PrometheusK8sClusterRoleBinding            = "assets/prometheus-k8s/cluster-role-binding.yaml"
	PrometheusK8sRoleBindingDefault            = "assets/prometheus-k8s/role-binding-default.yaml"
	PrometheusK8sRoleBindingKubeSystem         = "assets/prometheus-k8s/role-binding-kube-system.yaml"
	PrometheusK8sRoleBinding                   = "assets/prometheus-k8s/role-binding-namespace.yaml"
	PrometheusK8sRoleBindingConfig             = "assets/prometheus-k8s/role-binding-config.yaml"
	PrometheusK8sClusterRole                   = "assets/prometheus-k8s/cluster-role.yaml"
	PrometheusK8sRoleDefault                   = "assets/prometheus-k8s/role-default.yaml"
	PrometheusK8sRoleKubeSystem                = "assets/prometheus-k8s/role-kube-system.yaml"
	PrometheusK8sRoleConfig                    = "assets/prometheus-k8s/role-config.yaml"
	PrometheusK8sRole                          = "assets/prometheus-k8s/role-namespace.yaml"
	PrometheusK8sRules                         = "assets/prometheus-k8s/rules.yaml"
	PrometheusK8sServiceAccount                = "assets/prometheus-k8s/service-account.yaml"
	PrometheusK8s                              = "assets/prometheus-k8s/prometheus.yaml"
	PrometheusK8sKubeletServiceMonitor         = "assets/prometheus-k8s/service-monitor-kubelet.yaml"
	PrometheusK8sApiserverServiceMonitor       = "assets/prometheus-k8s/service-monitor-apiserver.yaml"
	PrometheusK8sPrometheusServiceMonitor      = "assets/prometheus-k8s/service-monitor.yaml"
	PrometheusK8sKubeControllersServiceMonitor = "assets/prometheus-k8s/service-monitor-kube-controllers.yaml"
	PrometheusK8sService                       = "assets/prometheus-k8s/service.yaml"
	PrometheusK8sProxySecret                   = "assets/prometheus-k8s/proxy-secret.yaml"
	PrometheusK8sRoute                         = "assets/prometheus-k8s/route.yaml"
	PrometheusK8sHtpasswd                      = "assets/prometheus-k8s/htpasswd-secret.yaml"
	PrometheusK8sEtcdService                   = "assets/prometheus-k8s/service-etcd.yaml"
	PrometheusK8sEtcdEndpoints                 = "assets/prometheus-k8s/endpoints-etcd.yaml"
	PrometheusK8sEtcdCerts                     = "assets/prometheus-k8s/secret-etcd-certs.yaml"
	PrometheusK8sEtcdServiceMonitor            = "assets/prometheus-k8s/service-monitor-etcd.yaml"

	PrometheusOperatorClusterRoleBinding = "assets/prometheus-operator/cluster-role-binding.yaml"
	PrometheusOperatorClusterRole        = "assets/prometheus-operator/cluster-role.yaml"
	PrometheusOperatorServiceAccount     = "assets/prometheus-operator/service-account.yaml"
	PrometheusOperatorDeployment         = "assets/prometheus-operator/deployment.yaml"
	PrometheusOperatorService            = "assets/prometheus-operator/service.yaml"
	PrometheusOperatorServiceMonitor     = "assets/prometheus-operator/service-monitor.yaml"

	KubeControllersService = "assets/prometheus-k8s/kube-controllers-service.yaml"

	GrafanaClusterRoleBinding   = "assets/grafana/cluster-role-binding.yaml"
	GrafanaClusterRole          = "assets/grafana/cluster-role.yaml"
	GrafanaConfigSecret         = "assets/grafana/config.yaml"
	GrafanaDatasourcesSecret    = "assets/grafana/dashboard-datasources.yaml"
	GrafanaDashboardDefinitions = "assets/grafana/dashboard-definitions.yaml"
	GrafanaDashboardSources     = "assets/grafana/dashboard-sources.yaml"
	GrafanaDeployment           = "assets/grafana/deployment.yaml"
	GrafanaProxySecret          = "assets/grafana/proxy-secret.yaml"
	GrafanaRoute                = "assets/grafana/route.yaml"
	GrafanaServiceAccount       = "assets/grafana/service-account.yaml"
	GrafanaService              = "assets/grafana/service.yaml"
)

var (
	PrometheusConfigReloaderFlag = "--prometheus-config-reloader="
	ConfigReloaderImageFlag      = "--config-reloader-image="

	AuthProxyExternalURLFlag  = "-external-url="
	AuthProxyCookieDomainFlag = "-cookie-domain="
	AuthProxyRedirectURLFlag  = "-redirect-url="
)

func MustAssetReader(asset string) io.Reader {
	return bytes.NewReader(MustAsset(asset))
}

type Factory struct {
	namespace string
	config    *Config
}

func NewFactory(namespace string, c *Config) *Factory {
	return &Factory{
		namespace: namespace,
		config:    c,
	}
}

func (f *Factory) PrometheusExternalURL(host string) *url.URL {
	if f.config.PrometheusK8sConfig.Hostport != "" {
		host = f.config.PrometheusK8sConfig.Hostport
	}

	return &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/",
	}
}

func (f *Factory) AlertmanagerExternalURL(host string) *url.URL {
	if f.config.AlertmanagerMainConfig.Hostport != "" {
		host = f.config.AlertmanagerMainConfig.Hostport
	}

	return &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/",
	}
}

func (f *Factory) AlertmanagerConfig() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(AlertmanagerConfig))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) AlertmanagerProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(AlertmanagerProxySecret))
	if err != nil {
		return nil, err
	}

	p, err := GeneratePassword(43)
	if err != nil {
		return nil, err
	}
	s.Data["session_secret"] = []byte(p)
	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) AlertmanagerService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(AlertmanagerService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) AlertmanagerServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(AlertmanagerServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) AlertmanagerClusterRoleBinding() (*rbacv1beta1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(AlertmanagerClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) AlertmanagerClusterRole() (*rbacv1beta1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(AlertmanagerClusterRole))
}

func (f *Factory) AlertmanagerServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(AlertmanagerServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("alertmanager-main.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) AlertmanagerMain(host string) (*monv1.Alertmanager, error) {
	a, err := f.NewAlertmanager(MustAssetReader(AlertmanagerMain))
	if err != nil {
		return nil, err
	}

	if f.config.AlertmanagerMainConfig.BaseImage != "" {
		a.Spec.BaseImage = f.config.AlertmanagerMainConfig.BaseImage
	}

	a.Spec.ExternalURL = f.AlertmanagerExternalURL(host).String()

	if f.config.AlertmanagerMainConfig.Resources != nil {
		a.Spec.Resources = *f.config.AlertmanagerMainConfig.Resources
	}

	if f.config.AlertmanagerMainConfig.VolumeClaimTemplate != nil {
		a.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *f.config.AlertmanagerMainConfig.VolumeClaimTemplate,
		}
	}

	if f.config.AlertmanagerMainConfig.NodeSelector != nil {
		a.Spec.NodeSelector = f.config.AlertmanagerMainConfig.NodeSelector
	}

	if f.config.AuthConfig.BaseImage != "" {
		image, err := imageFromString(a.Spec.Containers[0].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.AuthConfig.BaseImage
		a.Spec.Containers[0].Image = image.String()
	}

	a.Namespace = f.namespace

	return a, nil
}

func (f *Factory) AlertmanagerRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(MustAssetReader(AlertmanagerRoute))
	if err != nil {
		return nil, err
	}

	if f.config.AlertmanagerMainConfig.Hostport != "" {
		r.Spec.Host = f.config.AlertmanagerMainConfig.Hostport
	}
	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) KubeStateMetricsClusterRoleBinding() (*rbacv1beta1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(KubeStateMetricsClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) KubeStateMetricsClusterRole() (*rbacv1beta1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(KubeStateMetricsClusterRole))
}

func (f *Factory) KubeStateMetricsServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(KubeStateMetricsServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("kube-state-metrics.%s.svc", f.namespace)
	sm.Spec.Endpoints[1].TLSConfig.ServerName = fmt.Sprintf("kube-state-metrics.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) KubeStateMetricsDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(MustAssetReader(KubeStateMetricsDeployment))
	if err != nil {
		return nil, err
	}

	if f.config.KubeRbacProxyConfig.BaseImage != "" {
		image, err := imageFromString(d.Spec.Template.Spec.Containers[0].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.KubeRbacProxyConfig.BaseImage
		d.Spec.Template.Spec.Containers[0].Image = image.String()
	}

	if f.config.KubeRbacProxyConfig.BaseImage != "" {
		image, err := imageFromString(d.Spec.Template.Spec.Containers[1].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.KubeRbacProxyConfig.BaseImage
		d.Spec.Template.Spec.Containers[1].Image = image.String()
	}

	if f.config.KubeStateMetricsConfig.BaseImage != "" {
		image, err := imageFromString(d.Spec.Template.Spec.Containers[2].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.KubeStateMetricsConfig.BaseImage
		d.Spec.Template.Spec.Containers[2].Image = image.String()
	}

	d.Namespace = f.namespace

	return d, nil
}

func (f *Factory) KubeStateMetricsServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(KubeStateMetricsServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) KubeStateMetricsService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(KubeStateMetricsService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) NodeExporterServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(NodeExporterServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("node-exporter.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) NodeExporterDaemonSet() (*appsv1.DaemonSet, error) {
	ds, err := f.NewDaemonSet(MustAssetReader(NodeExporterDaemonSet))
	if err != nil {
		return nil, err
	}

	if f.config.NodeExporterConfig.BaseImage != "" {
		image, err := imageFromString(ds.Spec.Template.Spec.Containers[0].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.NodeExporterConfig.BaseImage
		ds.Spec.Template.Spec.Containers[0].Image = image.String()
	}

	if f.config.KubeRbacProxyConfig.BaseImage != "" {
		image, err := imageFromString(ds.Spec.Template.Spec.Containers[1].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.KubeRbacProxyConfig.BaseImage
		ds.Spec.Template.Spec.Containers[1].Image = image.String()
	}
	ds.Namespace = f.namespace

	return ds, nil
}

func (f *Factory) NodeExporterService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(NodeExporterService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) NodeExporterSecurityContextConstraints() (*securityv1.SecurityContextConstraints, error) {
	scc, err := f.NewSecurityContextConstraints(MustAssetReader(NodeExporterSecurityContextConstraints))
	if err != nil {
		return nil, err
	}

	scc.Users = append(scc.Users, fmt.Sprintf("system:serviceaccount:%s:node-exporter", f.namespace))

	return scc, nil
}

func (f *Factory) NodeExporterServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(NodeExporterServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) NodeExporterClusterRoleBinding() (*rbacv1beta1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(NodeExporterClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) NodeExporterClusterRole() (*rbacv1beta1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(NodeExporterClusterRole))
}

func (f *Factory) PrometheusK8sClusterRoleBinding() (*rbacv1beta1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(PrometheusK8sClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusK8sClusterRole() (*rbacv1beta1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(PrometheusK8sClusterRole))
}

func (f *Factory) PrometheusK8sRoleBindingDefault() (*rbacv1beta1.RoleBinding, error) {
	rb, err := f.NewRoleBinding(MustAssetReader(PrometheusK8sRoleBindingDefault))
	if err != nil {
		return nil, err
	}

	rb.Subjects[0].Namespace = f.namespace

	return rb, nil
}

func (f *Factory) PrometheusK8sRoleConfig() (*rbacv1beta1.Role, error) {
	r, err := f.NewRole(MustAssetReader(PrometheusK8sRoleConfig))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) PrometheusK8sRoleDefault() (*rbacv1beta1.Role, error) {
	return f.NewRole(MustAssetReader(PrometheusK8sRoleDefault))
}

func (f *Factory) PrometheusK8sRoleBindingKubeSystem() (*rbacv1beta1.RoleBinding, error) {
	rb, err := f.NewRoleBinding(MustAssetReader(PrometheusK8sRoleBindingKubeSystem))
	if err != nil {
		return nil, err
	}

	rb.Subjects[0].Namespace = f.namespace

	return rb, nil
}

func (f *Factory) PrometheusK8sRoleKubeSystem() (*rbacv1beta1.Role, error) {
	return f.NewRole(MustAssetReader(PrometheusK8sRoleKubeSystem))
}

func (f *Factory) PrometheusK8sRoleBinding() (*rbacv1beta1.RoleBinding, error) {
	rb, err := f.NewRoleBinding(MustAssetReader(PrometheusK8sRoleBinding))
	if err != nil {
		return nil, err
	}

	rb.Subjects[0].Namespace = f.namespace

	return rb, nil
}

func (f *Factory) PrometheusK8sRoleBindingConfig() (*rbacv1beta1.RoleBinding, error) {
	rb, err := f.NewRoleBinding(MustAssetReader(PrometheusK8sRoleBindingConfig))
	if err != nil {
		return nil, err
	}

	rb.Namespace = f.namespace

	return rb, nil
}

func (f *Factory) PrometheusK8sRole() (*rbacv1beta1.Role, error) {
	r, err := f.NewRole(MustAssetReader(PrometheusK8sRole))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) PrometheusK8sRules() (*monv1.PrometheusRule, error) {
	r, err := f.NewPrometheusRule(MustAssetReader(PrometheusK8sRules))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) PrometheusK8sServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(PrometheusK8sServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(PrometheusK8sProxySecret))
	if err != nil {
		return nil, err
	}

	p, err := GeneratePassword(43)
	if err != nil {
		return nil, err
	}
	s.Data["session_secret"] = []byte(p)
	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sHtpasswdSecret(password string) (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(PrometheusK8sHtpasswd))
	if err != nil {
		return nil, err
	}

	h := sha1.New()
	h.Write([]byte(password))
	s.Data["auth"] = []byte("internal:{SHA}" + base64.StdEncoding.EncodeToString(h.Sum(nil)))
	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sEtcdService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(PrometheusK8sEtcdService))
	if err != nil {
		return nil, err
	}

	if f.config.EtcdConfig.Targets.Selector != nil {
		s.Spec.Selector = f.config.EtcdConfig.Targets.Selector
	}

	return s, nil
}

func (f *Factory) PrometheusK8sEtcdEndpoints() (*v1.Endpoints, error) {
	e, err := f.NewEndpoints(MustAssetReader(PrometheusK8sEtcdEndpoints))
	if err != nil {
		return nil, err
	}

	if f.config.EtcdConfig.Targets.IPs != nil {
		addresses := []v1.EndpointAddress{}
		for _, ip := range f.config.EtcdConfig.Targets.IPs {
			addresses = append(addresses, v1.EndpointAddress{IP: ip})
		}
		e.Subsets[0].Addresses = addresses
	}

	return e, nil
}

func (f *Factory) PrometheusK8sEtcdCerts() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(PrometheusK8sEtcdCerts))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sEtcdServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sEtcdServiceMonitor))
	if err != nil {
		return nil, err
	}

	if f.config.EtcdConfig.TLSConfig != nil && f.config.EtcdConfig.TLSConfig.ServerName != "" {
		s.Spec.Endpoints[0].TLSConfig.ServerName = f.config.EtcdConfig.TLSConfig.ServerName
	}
	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(MustAssetReader(PrometheusK8sRoute))
	if err != nil {
		return nil, err
	}

	if f.config.PrometheusK8sConfig.Hostport != "" {
		r.Spec.Host = f.config.PrometheusK8sConfig.Hostport
	}
	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) PrometheusK8s(host string) (*monv1.Prometheus, error) {
	p, err := f.NewPrometheus(MustAssetReader(PrometheusK8s))
	if err != nil {
		return nil, err
	}

	if f.config.PrometheusK8sConfig.Retention != "" {
		p.Spec.Retention = f.config.PrometheusK8sConfig.Retention
	}

	if f.config.PrometheusK8sConfig.BaseImage != "" {
		p.Spec.BaseImage = f.config.PrometheusK8sConfig.BaseImage
	}

	p.Spec.ExternalURL = f.PrometheusExternalURL(host).String()

	if f.config.PrometheusK8sConfig.Resources != nil {
		p.Spec.Resources = *f.config.PrometheusK8sConfig.Resources
	}

	if f.config.PrometheusK8sConfig.NodeSelector != nil {
		p.Spec.NodeSelector = f.config.PrometheusK8sConfig.NodeSelector
	}

	if f.config.PrometheusK8sConfig.ExternalLabels != nil {
		p.Spec.ExternalLabels = f.config.PrometheusK8sConfig.ExternalLabels
	}

	if f.config.PrometheusK8sConfig.VolumeClaimTemplate != nil {
		p.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *f.config.PrometheusK8sConfig.VolumeClaimTemplate,
		}
	}

	if f.config.AuthConfig.BaseImage != "" {
		image, err := imageFromString(p.Spec.Containers[0].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.AuthConfig.BaseImage
		p.Spec.Containers[0].Image = image.String()
	}

	p.Spec.Alerting.Alertmanagers[0].Namespace = f.namespace
	p.Spec.Alerting.Alertmanagers[0].TLSConfig.ServerName = fmt.Sprintf("alertmanager-main.%s.svc", f.namespace)
	p.Namespace = f.namespace

	return p, nil
}

func (f *Factory) PrometheusK8sKubeletServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sKubeletServiceMonitor))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sApiserverServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sApiserverServiceMonitor))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sPrometheusServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sPrometheusServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-k8s.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) PrometheusK8sKubeControllersServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sKubeControllersServiceMonitor))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusOperatorServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(PrometheusOperatorServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) PrometheusOperatorClusterRoleBinding() (*rbacv1beta1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(PrometheusOperatorClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusOperatorClusterRole() (*rbacv1beta1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(PrometheusOperatorClusterRole))
}

func (f *Factory) PrometheusOperatorServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(PrometheusOperatorServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusOperatorDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(MustAssetReader(PrometheusOperatorDeployment))
	if err != nil {
		return nil, err
	}

	if f.config.PrometheusOperatorConfig.BaseImage != "" {
		image, err := imageFromString(d.Spec.Template.Spec.Containers[0].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.PrometheusOperatorConfig.BaseImage
		d.Spec.Template.Spec.Containers[0].Image = image.String()
	}

	args := d.Spec.Template.Spec.Containers[0].Args
	for i := range args {
		if strings.HasPrefix(args[i], PrometheusConfigReloaderFlag) && f.config.PrometheusOperatorConfig.PrometheusConfigReloader != "" {
			image, err := imageFromString(strings.TrimSuffix(args[i], PrometheusConfigReloaderFlag))
			if err != nil {
				return nil, err
			}
			image.repo = f.config.PrometheusOperatorConfig.PrometheusConfigReloader
			args[i] = PrometheusConfigReloaderFlag + image.String()
		}

		if strings.HasPrefix(args[i], ConfigReloaderImageFlag) && f.config.PrometheusOperatorConfig.ConfigReloaderImage != "" {
			image, err := imageFromString(strings.TrimSuffix(args[i], ConfigReloaderImageFlag))
			if err != nil {
				return nil, err
			}
			image.repo = f.config.PrometheusOperatorConfig.ConfigReloaderImage
			args[i] = ConfigReloaderImageFlag + image.String()
		}
	}
	d.Spec.Template.Spec.Containers[0].Args = args
	d.Namespace = f.namespace

	return d, nil
}

func (f *Factory) PrometheusOperatorService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(PrometheusOperatorService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(PrometheusK8sService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) KubeControllersService() (*v1.Service, error) {
	return f.NewService(MustAssetReader(KubeControllersService))
}

func (f *Factory) GrafanaClusterRoleBinding() (*rbacv1beta1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(GrafanaClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) GrafanaClusterRole() (*rbacv1beta1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(GrafanaClusterRole))
}

func (f *Factory) GrafanaConfig() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(GrafanaConfigSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

type GrafanaDatasources struct {
	ApiVersion  int                  `json:"apiVersion"`
	Datasources []*GrafanaDatasource `json:"datasources"`
}

type GrafanaDatasource struct {
	Access            string           `json:"access"`
	BasicAuth         bool             `json:"basicAuth"`
	BasicAuthPassword string           `json:"basicAuthPassword"`
	BasicAuthUser     string           `json:"basicAuthUser"`
	Editable          bool             `json:"editable"`
	JsonData          *GrafanaJsonData `json:"jsonData"`
	Name              string           `json:"name"`
	OrgId             int              `json:"orgId"`
	Type              string           `json:"type"`
	Url               string           `json:"url"`
	Version           int              `json:"version"`
}

type GrafanaJsonData struct {
	TlsSkipVerify bool `json:"tlsSkipVerify"`
}

func (f *Factory) GrafanaDatasources() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(GrafanaDatasourcesSecret))
	if err != nil {
		return nil, err
	}

	d := &GrafanaDatasources{}
	err = json.Unmarshal(s.Data["prometheus.yaml"], d)
	if err != nil {
		return nil, err
	}
	d.Datasources[0].BasicAuthPassword, err = GeneratePassword(255)
	if err != nil {
		return nil, err
	}

	b, err := json.MarshalIndent(d, "", "    ")
	if err != nil {
		return nil, err
	}
	s.Data["prometheus.yaml"] = b

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) GrafanaDashboardDefinitions() (*v1.ConfigMapList, error) {
	cl, err := f.NewConfigMapList(MustAssetReader(GrafanaDashboardDefinitions))
	if err != nil {
		return nil, err
	}

	for _, c := range cl.Items {
		c.Namespace = f.namespace
	}

	return cl, nil
}

func (f *Factory) GrafanaDashboardSources() (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(MustAssetReader(GrafanaDashboardSources))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace

	return c, nil
}

func (f *Factory) GrafanaDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(MustAssetReader(GrafanaDeployment))
	if err != nil {
		return nil, err
	}

	if f.config.GrafanaConfig.BaseImage != "" {
		image, err := imageFromString(d.Spec.Template.Spec.Containers[0].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.GrafanaConfig.BaseImage
		d.Spec.Template.Spec.Containers[0].Image = image.String()
	}

	if f.config.AuthConfig.BaseImage != "" {
		image, err := imageFromString(d.Spec.Template.Spec.Containers[1].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.AuthConfig.BaseImage
		d.Spec.Template.Spec.Containers[1].Image = image.String()
	}

	d.Namespace = f.namespace

	return d, nil
}

func (f *Factory) GrafanaProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(GrafanaProxySecret))
	if err != nil {
		return nil, err
	}

	p, err := GeneratePassword(43)
	if err != nil {
		return nil, err
	}
	s.Data["session_secret"] = []byte(p)
	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) GrafanaRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(MustAssetReader(GrafanaRoute))
	if err != nil {
		return nil, err
	}

	if f.config.GrafanaConfig.Hostport != "" {
		r.Spec.Host = f.config.GrafanaConfig.Hostport
	}
	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) GrafanaServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(GrafanaServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) GrafanaService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(GrafanaService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func hostFromBaseAddress(baseAddress string) (string, error) {
	host, _, err := net.SplitHostPort(baseAddress)
	if err != nil && !IsMissingPortInAddressError(err) {
		return "", nil
	}

	if host == "" {
		return baseAddress, nil
	}

	return host, nil
}

func IsMissingPortInAddressError(err error) bool {
	switch e := err.(type) {
	case *net.AddrError:
		if e.Err == "missing port in address" {
			return true
		}
	}
	return false
}

func (f *Factory) NewDaemonSet(manifest io.Reader) (*appsv1.DaemonSet, error) {
	ds, err := NewDaemonSet(manifest)
	if err != nil {
		return nil, err
	}

	if ds.GetNamespace() == "" {
		ds.SetNamespace(f.namespace)
	}

	return ds, nil
}

func (f *Factory) NewService(manifest io.Reader) (*v1.Service, error) {
	s, err := NewService(manifest)
	if err != nil {
		return nil, err
	}

	if s.GetNamespace() == "" {
		s.SetNamespace(f.namespace)
	}

	return s, nil
}

func (f *Factory) NewEndpoints(manifest io.Reader) (*v1.Endpoints, error) {
	e, err := NewEndpoints(manifest)
	if err != nil {
		return nil, err
	}

	if e.GetNamespace() == "" {
		e.SetNamespace(f.namespace)
	}

	return e, nil
}

func (f *Factory) NewRoute(manifest io.Reader) (*routev1.Route, error) {
	r, err := NewRoute(manifest)
	if err != nil {
		return nil, err
	}

	if r.GetNamespace() == "" {
		r.SetNamespace(f.namespace)
	}

	return r, nil
}

func (f *Factory) NewSecret(manifest io.Reader) (*v1.Secret, error) {
	s, err := NewSecret(manifest)
	if err != nil {
		return nil, err
	}

	if s.GetNamespace() == "" {
		s.SetNamespace(f.namespace)
	}

	return s, nil
}

func (f *Factory) NewRoleBinding(manifest io.Reader) (*rbacv1beta1.RoleBinding, error) {
	rb, err := NewRoleBinding(manifest)
	if err != nil {
		return nil, err
	}

	if rb.GetNamespace() == "" {
		rb.SetNamespace(f.namespace)
	}

	return rb, nil
}

func (f *Factory) NewRole(manifest io.Reader) (*rbacv1beta1.Role, error) {
	r, err := NewRole(manifest)
	if err != nil {
		return nil, err
	}

	if r.GetNamespace() == "" {
		r.SetNamespace(f.namespace)
	}

	return r, nil
}

func (f *Factory) NewConfigMap(manifest io.Reader) (*v1.ConfigMap, error) {
	cm, err := NewConfigMap(manifest)
	if err != nil {
		return nil, err
	}

	if cm.GetNamespace() == "" {
		cm.SetNamespace(f.namespace)
	}

	return cm, nil
}

func (f *Factory) NewConfigMapList(manifest io.Reader) (*v1.ConfigMapList, error) {
	cml, err := NewConfigMapList(manifest)
	if err != nil {
		return nil, err
	}

	for _, cm := range cml.Items {
		if cm.GetNamespace() == "" {
			cm.SetNamespace(f.namespace)
		}
	}

	return cml, nil
}

func (f *Factory) NewServiceAccount(manifest io.Reader) (*v1.ServiceAccount, error) {
	sa, err := NewServiceAccount(manifest)
	if err != nil {
		return nil, err
	}

	if sa.GetNamespace() == "" {
		sa.SetNamespace(f.namespace)
	}

	return sa, nil
}

func (f *Factory) NewPrometheus(manifest io.Reader) (*monv1.Prometheus, error) {
	p, err := NewPrometheus(manifest)
	if err != nil {
		return nil, err
	}

	if p.GetNamespace() == "" {
		p.SetNamespace(f.namespace)
	}

	return p, nil
}

func (f *Factory) NewPrometheusRule(manifest io.Reader) (*monv1.PrometheusRule, error) {
	p, err := NewPrometheusRule(manifest)
	if err != nil {
		return nil, err
	}

	if p.GetNamespace() == "" {
		p.SetNamespace(f.namespace)
	}

	return p, nil
}

func (f *Factory) NewAlertmanager(manifest io.Reader) (*monv1.Alertmanager, error) {
	a, err := NewAlertmanager(manifest)
	if err != nil {
		return nil, err
	}

	if a.GetNamespace() == "" {
		a.SetNamespace(f.namespace)
	}

	return a, nil
}

func (f *Factory) NewServiceMonitor(manifest io.Reader) (*monv1.ServiceMonitor, error) {
	sm, err := NewServiceMonitor(manifest)
	if err != nil {
		return nil, err
	}

	if sm.GetNamespace() == "" {
		sm.SetNamespace(f.namespace)
	}

	return sm, nil
}

func (f *Factory) NewDeployment(manifest io.Reader) (*appsv1.Deployment, error) {
	d, err := NewDeployment(manifest)
	if err != nil {
		return nil, err
	}

	if d.GetNamespace() == "" {
		d.SetNamespace(f.namespace)
	}

	return d, nil
}

func (f *Factory) NewIngress(manifest io.Reader) (*v1beta1.Ingress, error) {
	i, err := NewIngress(manifest)
	if err != nil {
		return nil, err
	}

	if i.GetNamespace() == "" {
		i.SetNamespace(f.namespace)
	}

	return i, nil
}

func (f *Factory) NewSecurityContextConstraints(manifest io.Reader) (*securityv1.SecurityContextConstraints, error) {
	return NewSecurityContextConstraints(manifest)
}

func (f *Factory) NewClusterRoleBinding(manifest io.Reader) (*rbacv1beta1.ClusterRoleBinding, error) {
	return NewClusterRoleBinding(manifest)
}

func (f *Factory) NewClusterRole(manifest io.Reader) (*rbacv1beta1.ClusterRole, error) {
	return NewClusterRole(manifest)
}

func NewDaemonSet(manifest io.Reader) (*appsv1.DaemonSet, error) {
	ds := appsv1.DaemonSet{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&ds)
	if err != nil {
		return nil, err
	}

	return &ds, nil
}

func NewService(manifest io.Reader) (*v1.Service, error) {
	s := v1.Service{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&s)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func NewEndpoints(manifest io.Reader) (*v1.Endpoints, error) {
	e := v1.Endpoints{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&e)
	if err != nil {
		return nil, err
	}

	return &e, nil
}

func NewRoute(manifest io.Reader) (*routev1.Route, error) {
	r := routev1.Route{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func NewSecret(manifest io.Reader) (*v1.Secret, error) {
	s := v1.Secret{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func NewClusterRoleBinding(manifest io.Reader) (*rbacv1beta1.ClusterRoleBinding, error) {
	crb := rbacv1beta1.ClusterRoleBinding{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&crb)
	if err != nil {
		return nil, err
	}

	return &crb, nil
}

func NewClusterRole(manifest io.Reader) (*rbacv1beta1.ClusterRole, error) {
	cr := rbacv1beta1.ClusterRole{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&cr)
	if err != nil {
		return nil, err
	}

	return &cr, nil
}

func NewRoleBinding(manifest io.Reader) (*rbacv1beta1.RoleBinding, error) {
	rb := rbacv1beta1.RoleBinding{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&rb)
	if err != nil {
		return nil, err
	}

	return &rb, nil
}

func NewRole(manifest io.Reader) (*rbacv1beta1.Role, error) {
	r := rbacv1beta1.Role{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func NewConfigMap(manifest io.Reader) (*v1.ConfigMap, error) {
	cm := v1.ConfigMap{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&cm)
	if err != nil {
		return nil, err
	}

	return &cm, nil
}

func NewConfigMapList(manifest io.Reader) (*v1.ConfigMapList, error) {
	cml := v1.ConfigMapList{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&cml)
	if err != nil {
		return nil, err
	}

	return &cml, nil
}

func NewServiceAccount(manifest io.Reader) (*v1.ServiceAccount, error) {
	sa := v1.ServiceAccount{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&sa)
	if err != nil {
		return nil, err
	}

	return &sa, nil
}

func NewPrometheus(manifest io.Reader) (*monv1.Prometheus, error) {
	p := monv1.Prometheus{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&p)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func NewPrometheusRule(manifest io.Reader) (*monv1.PrometheusRule, error) {
	p := monv1.PrometheusRule{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&p)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func NewAlertmanager(manifest io.Reader) (*monv1.Alertmanager, error) {
	a := monv1.Alertmanager{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&a)
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func NewServiceMonitor(manifest io.Reader) (*monv1.ServiceMonitor, error) {
	sm := monv1.ServiceMonitor{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&sm)
	if err != nil {
		return nil, err
	}

	return &sm, nil
}

func NewDeployment(manifest io.Reader) (*appsv1.Deployment, error) {
	d := appsv1.Deployment{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&d)
	if err != nil {
		return nil, err
	}

	return &d, nil
}

func NewIngress(manifest io.Reader) (*v1beta1.Ingress, error) {
	i := v1beta1.Ingress{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&i)
	if err != nil {
		return nil, err
	}

	return &i, nil
}

func NewSecurityContextConstraints(manifest io.Reader) (*securityv1.SecurityContextConstraints, error) {
	s := securityv1.SecurityContextConstraints{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&s)
	if err != nil {
		return nil, err
	}

	return &s, nil
}
