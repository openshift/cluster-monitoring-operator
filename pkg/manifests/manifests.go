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
	AlertmanagerConfig             = "assets/alertmanager/alertmanager-config.yaml"
	AlertmanagerService            = "assets/alertmanager/alertmanager-service.yaml"
	AlertmanagerProxySecret        = "assets/alertmanager/alertmanager-proxy-secret.yaml"
	AlertmanagerMain               = "assets/alertmanager/alertmanager.yaml"
	AlertmanagerServiceAccount     = "assets/alertmanager/alertmanager-service-account.yaml"
	AlertmanagerClusterRoleBinding = "assets/alertmanager/alertmanager-cluster-role-binding.yaml"
	AlertmanagerClusterRole        = "assets/alertmanager/alertmanager-cluster-role.yaml"
	AlertmanagerRoute              = "assets/alertmanager/alertmanager-route.yaml"

	KubeStateMetricsClusterRoleBinding      = "assets/kube-state-metrics/kube-state-metrics-cluster-role-binding.yaml"
	KubeStateMetricsClusterRole             = "assets/kube-state-metrics/kube-state-metrics-cluster-role.yaml"
	KubeStateMetricsAddonResizerRoleBinding = "assets/kube-state-metrics/kube-state-metrics-role-binding.yaml"
	KubeStateMetricsAddonResizerRole        = "assets/kube-state-metrics/kube-state-metrics-role.yaml"
	KubeStateMetricsDeployment              = "assets/kube-state-metrics/kube-state-metrics-deployment.yaml"
	KubeStateMetricsServiceAccount          = "assets/kube-state-metrics/kube-state-metrics-service-account.yaml"
	KubeStateMetricsService                 = "assets/kube-state-metrics/kube-state-metrics-service.yaml"

	NodeExporterDaemonSet                  = "assets/node-exporter/node-exporter-ds.yaml"
	NodeExporterService                    = "assets/node-exporter/node-exporter-svc.yaml"
	NodeExporterServiceAccount             = "assets/node-exporter/node-exporter-service-account.yaml"
	NodeExporterClusterRole                = "assets/node-exporter/node-exporter-cluster-role.yaml"
	NodeExporterClusterRoleBinding         = "assets/node-exporter/node-exporter-cluster-role-binding.yaml"
	NodeExporterSecurityContextConstraints = "assets/node-exporter/node-exporter-security-context-constraints.yaml"

	PrometheusK8sClusterRoleBinding                  = "assets/prometheus-k8s/prometheus-k8s-cluster-role-binding.yaml"
	PrometheusK8sRoleBindingDefault                  = "assets/prometheus-k8s/prometheus-k8s-role-binding-default.yaml"
	PrometheusK8sRoleBindingKubeSystem               = "assets/prometheus-k8s/prometheus-k8s-role-binding-kube-system.yaml"
	PrometheusK8sRoleBinding                         = "assets/prometheus-k8s/prometheus-k8s-role-binding.yaml"
	PrometheusK8sClusterRole                         = "assets/prometheus-k8s/prometheus-k8s-cluster-role.yaml"
	PrometheusK8sRoleDefault                         = "assets/prometheus-k8s/prometheus-k8s-role-default.yaml"
	PrometheusK8sRoleKubeSystem                      = "assets/prometheus-k8s/prometheus-k8s-role-kube-system.yaml"
	PrometheusK8sRole                                = "assets/prometheus-k8s/prometheus-k8s-role.yaml"
	PrometheusK8sRules                               = "assets/prometheus-k8s/prometheus-k8s-rules.yaml"
	PrometheusK8sServiceAccount                      = "assets/prometheus-k8s/prometheus-k8s-service-account.yaml"
	PrometheusK8s                                    = "assets/prometheus-k8s/prometheus-k8s.yaml"
	PrometheusK8sKubeletServiceMonitor               = "assets/prometheus-k8s/prometheus-k8s-service-monitor-kubelet.yaml"
	PrometheusK8sNodeExporterServiceMonitor          = "assets/prometheus-k8s/prometheus-k8s-service-monitor-node-exporter.yaml"
	PrometheusK8sApiserverServiceMonitor             = "assets/prometheus-k8s/prometheus-k8s-service-monitor-apiserver.yaml"
	PrometheusK8sKubeStateMetricsServiceMonitor      = "assets/prometheus-k8s/prometheus-k8s-service-monitor-kube-state-metrics.yaml"
	PrometheusK8sPrometheusServiceMonitor            = "assets/prometheus-k8s/prometheus-k8s-service-monitor-prometheus.yaml"
	PrometheusK8sAlertmanagerServiceMonitor          = "assets/prometheus-k8s/prometheus-k8s-service-monitor-alertmanager.yaml"
	PrometheusK8sKubeControllersServiceMonitor       = "assets/prometheus-k8s/prometheus-k8s-service-monitor-kube-controllers.yaml"
	PrometheusK8sKubeDNSServiceMonitor               = "assets/prometheus-k8s/prometheus-k8s-service-monitor-kube-dns.yaml"
	PrometheusK8sPrometheusOperatorServiceMonitor    = "assets/prometheus-k8s/prometheus-k8s-service-monitor-prometheus-operator.yaml"
	PrometheusK8sAvailabilityAppCreateServiceMonitor = "assets/prometheus-k8s/prometheus-k8s-service-monitor-availability-app-create.yaml"
	PrometheusK8sService                             = "assets/prometheus-k8s/prometheus-k8s-svc.yaml"
	PrometheusK8sProxySecret                         = "assets/prometheus-k8s/prometheus-k8s-proxy-secret.yaml"
	PrometheusK8sRoute                               = "assets/prometheus-k8s/prometheus-k8s-route.yaml"

	PrometheusOperatorClusterRoleBinding = "assets/prometheus-operator/prometheus-operator-cluster-role-binding.yaml"
	PrometheusOperatorClusterRole        = "assets/prometheus-operator/prometheus-operator-cluster-role.yaml"
	PrometheusOperatorServiceAccount     = "assets/prometheus-operator/prometheus-operator-service-account.yaml"
	PrometheusOperatorDeployment         = "assets/prometheus-operator/prometheus-operator.yaml"
	PrometheusOperatorService            = "assets/prometheus-operator/prometheus-operator-svc.yaml"

	KubeControllersService = "assets/prometheus-k8s/kube-controllers-svc.yaml"
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
	return f.NewSecret(MustAssetReader(AlertmanagerConfig))
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

	return s, nil
}

func (f *Factory) AlertmanagerService() (*v1.Service, error) {
	return f.NewService(MustAssetReader(AlertmanagerService))
}

func (f *Factory) AlertmanagerServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(MustAssetReader(AlertmanagerServiceAccount))
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

func (f *Factory) KubeStateMetricsAddonResizerRoleBinding() (*rbacv1beta1.RoleBinding, error) {
	return f.NewRoleBinding(MustAssetReader(KubeStateMetricsAddonResizerRoleBinding))
}

func (f *Factory) KubeStateMetricsAddonResizerRole() (*rbacv1beta1.Role, error) {
	return f.NewRole(MustAssetReader(KubeStateMetricsAddonResizerRole))
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

	if f.config.KubeStateMetricsConfig.AddonResizerBaseImage != "" {
		image, err := imageFromString(d.Spec.Template.Spec.Containers[3].Image)
		if err != nil {
			return nil, err
		}
		image.repo = f.config.KubeStateMetricsConfig.AddonResizerBaseImage
		d.Spec.Template.Spec.Containers[3].Image = image.String()
	}

	return d, nil
}

func (f *Factory) KubeStateMetricsServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(MustAssetReader(KubeStateMetricsServiceAccount))
}

func (f *Factory) KubeStateMetricsService() (*v1.Service, error) {
	return f.NewService(MustAssetReader(KubeStateMetricsService))
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

	return ds, nil
}

func (f *Factory) NodeExporterService() (*v1.Service, error) {
	return f.NewService(MustAssetReader(NodeExporterService))
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
	return f.NewServiceAccount(MustAssetReader(NodeExporterServiceAccount))
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

func (f *Factory) PrometheusK8sRole() (*rbacv1beta1.Role, error) {
	return f.NewRole(MustAssetReader(PrometheusK8sRole))
}

func (f *Factory) PrometheusK8sRules() (*v1.ConfigMap, error) {
	return f.NewConfigMap(MustAssetReader(PrometheusK8sRules))
}

func (f *Factory) PrometheusK8sServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(MustAssetReader(PrometheusK8sServiceAccount))
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

	return p, nil
}

func (f *Factory) PrometheusK8sKubeletServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(MustAssetReader(PrometheusK8sKubeletServiceMonitor))
}

func (f *Factory) PrometheusK8sNodeExporterServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sNodeExporterServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.NamespaceSelector.MatchNames[0] = f.namespace
	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("node-exporter.%s.svc", f.namespace)

	return sm, nil
}

func (f *Factory) PrometheusK8sApiserverServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(MustAssetReader(PrometheusK8sApiserverServiceMonitor))
}

func (f *Factory) PrometheusK8sKubeStateMetricsServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sKubeStateMetricsServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.NamespaceSelector.MatchNames[0] = f.namespace
	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("kube-state-metrics.%s.svc", f.namespace)
	sm.Spec.Endpoints[1].TLSConfig.ServerName = fmt.Sprintf("kube-state-metrics.%s.svc", f.namespace)

	return sm, nil
}

func (f *Factory) PrometheusK8sPrometheusServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sPrometheusServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.NamespaceSelector.MatchNames[0] = f.namespace
	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-k8s.%s.svc", f.namespace)

	return sm, nil
}

func (f *Factory) PrometheusK8sAlertmanagerServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sAlertmanagerServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.NamespaceSelector.MatchNames[0] = f.namespace
	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("alertmanager-main.%s.svc", f.namespace)

	return sm, nil
}

func (f *Factory) PrometheusK8sKubeControllersServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(MustAssetReader(PrometheusK8sKubeControllersServiceMonitor))
}

func (f *Factory) PrometheusK8sKubeDNSServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(MustAssetReader(PrometheusK8sKubeDNSServiceMonitor))
}

func (f *Factory) PrometheusK8sPrometheusOperatorServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sPrometheusOperatorServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.NamespaceSelector.MatchNames[0] = f.namespace

	return sm, nil
}

func (f *Factory) PrometheusK8sAvailabilityAppCreateServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(MustAssetReader(PrometheusK8sAvailabilityAppCreateServiceMonitor))
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
	return f.NewServiceAccount(MustAssetReader(PrometheusOperatorServiceAccount))
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

	return d, nil
}

func (f *Factory) PrometheusOperatorService() (*v1.Service, error) {
	return f.NewService(MustAssetReader(PrometheusOperatorService))
}

func (f *Factory) PrometheusK8sService() (*v1.Service, error) {
	return f.NewService(MustAssetReader(PrometheusK8sService))
}

func (f *Factory) KubeControllersService() (*v1.Service, error) {
	return f.NewService(MustAssetReader(KubeControllersService))
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
