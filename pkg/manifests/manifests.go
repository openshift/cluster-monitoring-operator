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

	// #nosec
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	routev1 "github.com/openshift/api/route/v1"
	securityv1 "github.com/openshift/api/security/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/promqlgen"
	"github.com/pkg/errors"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/yaml"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
)

const (
	configManagedNamespace = "openshift-config-managed"
	sharedConfigMap        = "monitoring-shared-config"
)

var (
	AlertmanagerConfig              = "alertmanager/secret.yaml"
	AlertmanagerService             = "alertmanager/service.yaml"
	AlertmanagerProxySecret         = "alertmanager/proxy-secret.yaml"
	AlertmanagerMain                = "alertmanager/alertmanager.yaml"
	AlertmanagerServiceAccount      = "alertmanager/service-account.yaml"
	AlertmanagerClusterRoleBinding  = "alertmanager/cluster-role-binding.yaml"
	AlertmanagerClusterRole         = "alertmanager/cluster-role.yaml"
	AlertmanagerRBACProxySecret     = "alertmanager/kube-rbac-proxy-secret.yaml"
	AlertmanagerRoute               = "alertmanager/route.yaml"
	AlertmanagerServiceMonitor      = "alertmanager/service-monitor.yaml"
	AlertmanagerTrustedCABundle     = "alertmanager/trusted-ca-bundle.yaml"
	AlertmanagerPrometheusRule      = "alertmanager/prometheus-rule.yaml"
	AlertmanagerPodDisruptionBudget = "alertmanager/pod-disruption-budget.yaml"

	KubeStateMetricsClusterRoleBinding = "kube-state-metrics/cluster-role-binding.yaml"
	KubeStateMetricsClusterRole        = "kube-state-metrics/cluster-role.yaml"
	KubeStateMetricsDeployment         = "kube-state-metrics/deployment.yaml"
	KubeStateMetricsServiceAccount     = "kube-state-metrics/service-account.yaml"
	KubeStateMetricsService            = "kube-state-metrics/service.yaml"
	KubeStateMetricsServiceMonitor     = "kube-state-metrics/service-monitor.yaml"
	KubeStateMetricsPrometheusRule     = "kube-state-metrics/prometheus-rule.yaml"

	OpenShiftStateMetricsClusterRoleBinding = "openshift-state-metrics/cluster-role-binding.yaml"
	OpenShiftStateMetricsClusterRole        = "openshift-state-metrics/cluster-role.yaml"
	OpenShiftStateMetricsDeployment         = "openshift-state-metrics/deployment.yaml"
	OpenShiftStateMetricsServiceAccount     = "openshift-state-metrics/service-account.yaml"
	OpenShiftStateMetricsService            = "openshift-state-metrics/service.yaml"
	OpenShiftStateMetricsServiceMonitor     = "openshift-state-metrics/service-monitor.yaml"

	NodeExporterDaemonSet                  = "node-exporter/daemonset.yaml"
	NodeExporterService                    = "node-exporter/service.yaml"
	NodeExporterServiceAccount             = "node-exporter/service-account.yaml"
	NodeExporterClusterRole                = "node-exporter/cluster-role.yaml"
	NodeExporterClusterRoleBinding         = "node-exporter/cluster-role-binding.yaml"
	NodeExporterSecurityContextConstraints = "node-exporter/security-context-constraints.yaml"
	NodeExporterServiceMonitor             = "node-exporter/service-monitor.yaml"
	NodeExporterPrometheusRule             = "node-exporter/prometheus-rule.yaml"

	PrometheusK8sClusterRoleBinding          = "prometheus-k8s/cluster-role-binding.yaml"
	PrometheusK8sRoleBindingConfig           = "prometheus-k8s/role-binding-config.yaml"
	PrometheusK8sRoleBindingList             = "prometheus-k8s/role-binding-specific-namespaces.yaml"
	PrometheusK8sClusterRole                 = "prometheus-k8s/cluster-role.yaml"
	PrometheusK8sRoleConfig                  = "prometheus-k8s/role-config.yaml"
	PrometheusK8sRoleList                    = "prometheus-k8s/role-specific-namespaces.yaml"
	PrometheusK8sPrometheusRule              = "prometheus-k8s/prometheus-rule.yaml"
	PrometheusK8sServiceAccount              = "prometheus-k8s/service-account.yaml"
	PrometheusK8s                            = "prometheus-k8s/prometheus.yaml"
	PrometheusK8sPrometheusServiceMonitor    = "prometheus-k8s/service-monitor.yaml"
	PrometheusK8sService                     = "prometheus-k8s/service.yaml"
	PrometheusK8sServiceThanosSidecar        = "prometheus-k8s/service-thanos-sidecar.yaml"
	PrometheusK8sProxySecret                 = "prometheus-k8s/proxy-secret.yaml"
	PrometheusRBACProxySecret                = "prometheus-k8s/kube-rbac-proxy-secret.yaml"
	PrometheusK8sRoute                       = "prometheus-k8s/route.yaml"
	PrometheusK8sHtpasswd                    = "prometheus-k8s/htpasswd-secret.yaml"
	PrometheusK8sServingCertsCABundle        = "prometheus-k8s/serving-certs-ca-bundle.yaml"
	PrometheusK8sKubeletServingCABundle      = "prometheus-k8s/kubelet-serving-ca-bundle.yaml"
	PrometheusK8sGrpcTLSSecret               = "prometheus-k8s/grpc-tls-secret.yaml"
	PrometheusK8sTrustedCABundle             = "prometheus-k8s/trusted-ca-bundle.yaml"
	PrometheusK8sThanosSidecarServiceMonitor = "prometheus-k8s/service-monitor-thanos-sidecar.yaml"
	PrometheusK8sPodDisruptionBudget         = "prometheus-k8s/pod-disruption-budget.yaml"

	PrometheusUserWorkloadServingCertsCABundle        = "prometheus-user-workload/serving-certs-ca-bundle.yaml"
	PrometheusUserWorkloadServiceAccount              = "prometheus-user-workload/service-account.yaml"
	PrometheusUserWorkloadClusterRole                 = "prometheus-user-workload/cluster-role.yaml"
	PrometheusUserWorkloadClusterRoleBinding          = "prometheus-user-workload/cluster-role-binding.yaml"
	PrometheusUserWorkloadRoleConfig                  = "prometheus-user-workload/role-config.yaml"
	PrometheusUserWorkloadRoleList                    = "prometheus-user-workload/role-specific-namespaces.yaml"
	PrometheusUserWorkloadRoleBindingList             = "prometheus-user-workload/role-binding-specific-namespaces.yaml"
	PrometheusUserWorkloadRoleBindingConfig           = "prometheus-user-workload/role-binding-config.yaml"
	PrometheusUserWorkloadService                     = "prometheus-user-workload/service.yaml"
	PrometheusUserWorkloadServiceThanosSidecar        = "prometheus-user-workload/service-thanos-sidecar.yaml"
	PrometheusUserWorkload                            = "prometheus-user-workload/prometheus.yaml"
	PrometheusUserWorkloadPrometheusServiceMonitor    = "prometheus-user-workload/service-monitor.yaml"
	PrometheusUserWorkloadGrpcTLSSecret               = "prometheus-user-workload/grpc-tls-secret.yaml"
	PrometheusUserWorkloadThanosSidecarServiceMonitor = "prometheus-user-workload/service-monitor-thanos-sidecar.yaml"
	PrometheusUserWorkloadPodDisruptionBudget         = "prometheus-user-workload/pod-disruption-budget.yaml"

	PrometheusAdapterAPIService                         = "prometheus-adapter/api-service.yaml"
	PrometheusAdapterClusterRole                        = "prometheus-adapter/cluster-role.yaml"
	PrometheusAdapterClusterRoleBinding                 = "prometheus-adapter/cluster-role-binding.yaml"
	PrometheusAdapterClusterRoleBindingDelegator        = "prometheus-adapter/cluster-role-binding-delegator.yaml"
	PrometheusAdapterClusterRoleBindingView             = "prometheus-adapter/cluster-role-binding-view.yaml"
	PrometheusAdapterClusterRoleServerResources         = "prometheus-adapter/cluster-role-server-resources.yaml"
	PrometheusAdapterClusterRoleAggregatedMetricsReader = "prometheus-adapter/cluster-role-aggregated-metrics-reader.yaml"
	PrometheusAdapterConfigMap                          = "prometheus-adapter/config-map.yaml"
	PrometheusAdapterConfigMapPrometheus                = "prometheus-adapter/configmap-prometheus.yaml"
	PrometheusAdapterDeployment                         = "prometheus-adapter/deployment.yaml"
	PrometheusAdapterPodDisruptionBudget                = "prometheus-adapter/pod-disruption-budget.yaml"
	PrometheusAdapterRoleBindingAuthReader              = "prometheus-adapter/role-binding-auth-reader.yaml"
	PrometheusAdapterService                            = "prometheus-adapter/service.yaml"
	PrometheusAdapterServiceMonitor                     = "prometheus-adapter/service-monitor.yaml"
	PrometheusAdapterServiceAccount                     = "prometheus-adapter/service-account.yaml"

	PrometheusOperatorClusterRoleBinding    = "prometheus-operator/cluster-role-binding.yaml"
	PrometheusOperatorClusterRole           = "prometheus-operator/cluster-role.yaml"
	PrometheusOperatorServiceAccount        = "prometheus-operator/service-account.yaml"
	PrometheusOperatorDeployment            = "prometheus-operator/deployment.yaml"
	PrometheusOperatorService               = "prometheus-operator/service.yaml"
	PrometheusOperatorServiceMonitor        = "prometheus-operator/service-monitor.yaml"
	PrometheusOperatorCertsCABundle         = "prometheus-operator/operator-certs-ca-bundle.yaml"
	PrometheusOperatorRuleValidatingWebhook = "prometheus-operator/prometheus-rule-validating-webhook.yaml"
	PrometheusOperatorPrometheusRule        = "prometheus-operator/prometheus-rule.yaml"

	PrometheusOperatorUserWorkloadServiceAccount     = "prometheus-operator-user-workload/service-account.yaml"
	PrometheusOperatorUserWorkloadClusterRole        = "prometheus-operator-user-workload/cluster-role.yaml"
	PrometheusOperatorUserWorkloadClusterRoleBinding = "prometheus-operator-user-workload/cluster-role-binding.yaml"
	PrometheusOperatorUserWorkloadService            = "prometheus-operator-user-workload/service.yaml"
	PrometheusOperatorUserWorkloadDeployment         = "prometheus-operator-user-workload/deployment.yaml"
	PrometheusOperatorUserWorkloadServiceMonitor     = "prometheus-operator-user-workload/service-monitor.yaml"

	GrafanaClusterRoleBinding   = "grafana/cluster-role-binding.yaml"
	GrafanaClusterRole          = "grafana/cluster-role.yaml"
	GrafanaConfigSecret         = "grafana/config.yaml"
	GrafanaDatasourcesSecret    = "grafana/dashboard-datasources.yaml"
	GrafanaDashboardDefinitions = "grafana/dashboard-definitions.yaml"
	GrafanaDashboardSources     = "grafana/dashboard-sources.yaml"
	GrafanaDeployment           = "grafana/deployment.yaml"
	GrafanaProxySecret          = "grafana/proxy-secret.yaml"
	GrafanaRoute                = "grafana/route.yaml"
	GrafanaServiceAccount       = "grafana/service-account.yaml"
	GrafanaService              = "grafana/service.yaml"
	GrafanaServiceMonitor       = "grafana/service-monitor.yaml"
	GrafanaTrustedCABundle      = "grafana/trusted-ca-bundle.yaml"

	ClusterMonitoringOperatorService            = "cluster-monitoring-operator/service.yaml"
	ClusterMonitoringOperatorServiceMonitor     = "cluster-monitoring-operator/service-monitor.yaml"
	ClusterMonitoringClusterRole                = "cluster-monitoring-operator/cluster-role.yaml"
	ClusterMonitoringRulesEditClusterRole       = "cluster-monitoring-operator/monitoring-rules-edit-cluster-role.yaml"
	ClusterMonitoringRulesViewClusterRole       = "cluster-monitoring-operator/monitoring-rules-view-cluster-role.yaml"
	ClusterMonitoringEditClusterRole            = "cluster-monitoring-operator/monitoring-edit-cluster-role.yaml"
	ClusterMonitoringEditUserWorkloadConfigRole = "cluster-monitoring-operator/user-workload-config-edit-role.yaml"
	ClusterMonitoringGrpcTLSSecret              = "cluster-monitoring-operator/grpc-tls-secret.yaml"
	ClusterMonitoringOperatorPrometheusRule     = "cluster-monitoring-operator/prometheus-rule.yaml"

	TelemeterClientClusterRole            = "telemeter-client/cluster-role.yaml"
	TelemeterClientClusterRoleBinding     = "telemeter-client/cluster-role-binding.yaml"
	TelemeterClientClusterRoleBindingView = "telemeter-client/cluster-role-binding-view.yaml"
	TelemeterClientDeployment             = "telemeter-client/deployment.yaml"
	TelemeterClientSecret                 = "telemeter-client/secret.yaml"
	TelemeterClientService                = "telemeter-client/service.yaml"
	TelemeterClientServiceAccount         = "telemeter-client/service-account.yaml"
	TelemeterClientServiceMonitor         = "telemeter-client/service-monitor.yaml"
	TelemeterClientServingCertsCABundle   = "telemeter-client/serving-certs-ca-bundle.yaml"

	ThanosQuerierDeployment           = "thanos-querier/deployment.yaml"
	ThanosQuerierService              = "thanos-querier/service.yaml"
	ThanosQuerierServiceMonitor       = "thanos-querier/service-monitor.yaml"
	ThanosQuerierPrometheusRule       = "thanos-querier/prometheus-rule.yaml"
	ThanosQuerierRoute                = "thanos-querier/route.yaml"
	ThanosQuerierOauthCookieSecret    = "thanos-querier/oauth-cookie-secret.yaml"
	ThanosQuerierHtpasswdSecret       = "thanos-querier/oauth-htpasswd-secret.yaml"
	ThanosQuerierRBACProxySecret      = "thanos-querier/kube-rbac-proxy-secret.yaml"
	ThanosQuerierRBACProxyRulesSecret = "thanos-querier/kube-rbac-proxy-rules-secret.yaml"
	ThanosQuerierServiceAccount       = "thanos-querier/service-account.yaml"
	ThanosQuerierClusterRole          = "thanos-querier/cluster-role.yaml"
	ThanosQuerierClusterRoleBinding   = "thanos-querier/cluster-role-binding.yaml"
	ThanosQuerierGrpcTLSSecret        = "thanos-querier/grpc-tls-secret.yaml"
	ThanosQuerierTrustedCABundle      = "thanos-querier/trusted-ca-bundle.yaml"

	ThanosRulerCustomResource               = "thanos-ruler/thanos-ruler.yaml"
	ThanosRulerService                      = "thanos-ruler/service.yaml"
	ThanosRulerRoute                        = "thanos-ruler/route.yaml"
	ThanosRulerOauthCookieSecret            = "thanos-ruler/oauth-cookie-secret.yaml"
	ThanosRulerHtpasswdSecret               = "thanos-ruler/oauth-htpasswd-secret.yaml"
	ThanosRulerQueryConfigSecret            = "thanos-ruler/query-config-secret.yaml"
	ThanosRulerAlertmanagerConfigSecret     = "thanos-ruler/alertmanagers-config-secret.yaml"
	ThanosRulerServiceAccount               = "thanos-ruler/service-account.yaml"
	ThanosRulerClusterRole                  = "thanos-ruler/cluster-role.yaml"
	ThanosRulerClusterRoleBinding           = "thanos-ruler/cluster-role-binding.yaml"
	ThanosRulerMonitoringClusterRoleBinding = "thanos-ruler/cluster-role-binding-monitoring.yaml"
	ThanosRulerGrpcTLSSecret                = "thanos-ruler/grpc-tls-secret.yaml"
	ThanosRulerTrustedCABundle              = "thanos-ruler/trusted-ca-bundle.yaml"
	ThanosRulerServiceMonitor               = "thanos-ruler/service-monitor.yaml"
	ThanosRulerPrometheusRule               = "thanos-ruler/thanos-ruler-prometheus-rule.yaml"

	TelemeterTrustedCABundle = "telemeter-client/trusted-ca-bundle.yaml"

	ControlPlanePrometheusRule        = "control-plane/prometheus-rule.yaml"
	ControlPlaneEtcdPrometheusRule    = "control-plane/etcd-prometheus-rule.yaml"
	ControlPlaneKubeletServiceMonitor = "control-plane/service-monitor-kubelet.yaml"
	ControlPlaneEtcdServiceMonitor    = "control-plane/service-monitor-etcd.yaml"
)

var (
	PrometheusConfigReloaderFlag                         = "--prometheus-config-reloader="
	PrometheusOperatorPrometheusInstanceNamespacesFlag   = "--prometheus-instance-namespaces="
	PrometheusOperatorAlertmanagerInstanceNamespacesFlag = "--alertmanager-instance-namespaces="

	AuthProxyExternalURLFlag  = "-external-url="
	AuthProxyCookieDomainFlag = "-cookie-domain="
	AuthProxyRedirectURLFlag  = "-redirect-url="

	TrustedCABundleKey = "ca-bundle.crt"
)

type Factory struct {
	namespace             string
	namespaceUserWorkload string
	config                *Config
	infrastructure        InfrastructureReader
	proxy                 ProxyReader
	assets                *Assets
}

// InfrastructureReader has methods to describe the cluster infrastructure.
type InfrastructureReader interface {
	HighlyAvailableInfrastructure() bool
	HostedControlPlane() bool
}

// ProxyReader has methods to describe the proxy configuration.
type ProxyReader interface {
	HTTPProxy() string
	HTTPSProxy() string
	NoProxy() string
}

func NewFactory(namespace, namespaceUserWorkload string, c *Config, infrastructure InfrastructureReader, proxy ProxyReader, a *Assets) *Factory {
	return &Factory{
		namespace:             namespace,
		namespaceUserWorkload: namespaceUserWorkload,
		config:                c,
		infrastructure:        infrastructure,
		proxy:                 proxy,
		assets:                a,
	}
}

func (f *Factory) PrometheusExternalURL(host string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/",
	}
}

func (f *Factory) AlertmanagerExternalURL(host string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/",
	}
}

func (f *Factory) AlertmanagerConfig() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(AlertmanagerConfig))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) AlertmanagerProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(AlertmanagerProxySecret))
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
	s, err := f.NewService(f.assets.MustNewAssetReader(AlertmanagerService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) AlertmanagerServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(AlertmanagerServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) AlertmanagerClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(AlertmanagerClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) AlertmanagerClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(AlertmanagerClusterRole))
}

func (f *Factory) AlertmanagerServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(AlertmanagerServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("alertmanager-main.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) AlertmanagerTrustedCABundle() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(f.assets.MustNewAssetReader(AlertmanagerTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func setContainerEnvironmentVariable(container *v1.Container, name, value string) {
	for i := range container.Env {
		if container.Env[i].Name == name {
			container.Env[i].Value = value
			break
		}
	}
}

func (f *Factory) injectProxyVariables(container *v1.Container) {
	if f.proxy.HTTPProxy() != "" {
		setContainerEnvironmentVariable(container, "HTTP_PROXY", f.proxy.HTTPProxy())
	}
	if f.proxy.HTTPSProxy() != "" {
		setContainerEnvironmentVariable(container, "HTTPS_PROXY", f.proxy.HTTPSProxy())
	}
	if f.proxy.NoProxy() != "" {
		setContainerEnvironmentVariable(container, "NO_PROXY", f.proxy.NoProxy())
	}
}

func (f *Factory) AlertmanagerMain(host string, trustedCABundleCM *v1.ConfigMap) (*monv1.Alertmanager, error) {
	a, err := f.NewAlertmanager(f.assets.MustNewAssetReader(AlertmanagerMain))
	if err != nil {
		return nil, err
	}

	a.Spec.Image = &f.config.Images.Alertmanager

	a.Spec.ExternalURL = f.AlertmanagerExternalURL(host).String()

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Resources != nil {
		a.Spec.Resources = *f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Resources
	}

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.VolumeClaimTemplate != nil {
		a.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.VolumeClaimTemplate,
		}
	}

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.NodeSelector != nil {
		a.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Tolerations) > 0 {
		a.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Tolerations
	}

	for i, c := range a.Spec.Containers {
		switch c.Name {
		case "alertmanager-proxy":
			a.Spec.Containers[i].Image = f.config.Images.OauthProxy

			f.injectProxyVariables(&a.Spec.Containers[i])

			if trustedCABundleCM != nil {
				volumeName := "alertmanager-trusted-ca-bundle"
				a.Spec.VolumeMounts = append(a.Spec.VolumeMounts, trustedCABundleVolumeMount(volumeName))
				volume := trustedCABundleVolume(trustedCABundleCM.Name, volumeName)
				volume.VolumeSource.ConfigMap.Items = append(volume.VolumeSource.ConfigMap.Items, v1.KeyToPath{
					Key:  TrustedCABundleKey,
					Path: "tls-ca-bundle.pem",
				})
				a.Spec.Volumes = append(a.Spec.Volumes, volume)
				a.Spec.Containers[i].VolumeMounts = append(
					a.Spec.Containers[i].VolumeMounts,
					trustedCABundleVolumeMount(volumeName),
				)
			}
		case "kube-rbac-proxy":
			a.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		case "prom-label-proxy":
			a.Spec.Containers[i].Image = f.config.Images.PromLabelProxy
		}
	}

	a.Namespace = f.namespace

	return a, nil
}

func (f *Factory) AlertmanagerRBACProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(AlertmanagerRBACProxySecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) AlertmanagerRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(f.assets.MustNewAssetReader(AlertmanagerRoute))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) AlertmanagerPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(AlertmanagerPrometheusRule))
}

func (f *Factory) AlertmanagerPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(AlertmanagerPodDisruptionBudget))
}

func (f *Factory) KubeStateMetricsClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(KubeStateMetricsClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) KubeStateMetricsClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(KubeStateMetricsClusterRole))
}

func (f *Factory) KubeStateMetricsServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(KubeStateMetricsServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("kube-state-metrics.%s.svc", f.namespace)
	sm.Spec.Endpoints[1].TLSConfig.ServerName = fmt.Sprintf("kube-state-metrics.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) KubeStateMetricsDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(KubeStateMetricsDeployment))
	if err != nil {
		return nil, err
	}
	for i, container := range d.Spec.Template.Spec.Containers {
		if container.Name == "kube-state-metrics" {
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeStateMetrics
		}
		if container.Name == "kube-rbac-proxy-self" || container.Name == "kube-rbac-proxy-main" {
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		}
	}

	if f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.NodeSelector != nil {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Tolerations
	}
	d.Namespace = f.namespace

	return d, nil
}

func (f *Factory) KubeStateMetricsServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(KubeStateMetricsServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) KubeStateMetricsService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(KubeStateMetricsService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) KubeStateMetricsPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(KubeStateMetricsPrometheusRule))
}

func (f *Factory) OpenShiftStateMetricsClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(OpenShiftStateMetricsClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) OpenShiftStateMetricsClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(OpenShiftStateMetricsClusterRole))
}

func (f *Factory) OpenShiftStateMetricsServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(OpenShiftStateMetricsServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("openshift-state-metrics.%s.svc", f.namespace)
	sm.Spec.Endpoints[1].TLSConfig.ServerName = fmt.Sprintf("openshift-state-metrics.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) OpenShiftStateMetricsDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(OpenShiftStateMetricsDeployment))
	if err != nil {
		return nil, err
	}

	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "kube-rbac-proxy-main":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		case "kube-rbac-proxy-self":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		case "openshift-state-metrics":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.OpenShiftStateMetrics
		}
	}

	if f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.NodeSelector != nil {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.Tolerations
	}
	d.Namespace = f.namespace

	return d, nil
}

func (f *Factory) OpenShiftStateMetricsServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(OpenShiftStateMetricsServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) OpenShiftStateMetricsService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(OpenShiftStateMetricsService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) NodeExporterServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(NodeExporterServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("node-exporter.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) NodeExporterDaemonSet() (*appsv1.DaemonSet, error) {
	ds, err := f.NewDaemonSet(f.assets.MustNewAssetReader(NodeExporterDaemonSet))
	if err != nil {
		return nil, err
	}

	for i, container := range ds.Spec.Template.Spec.Containers {
		switch container.Name {
		case "node-exporter":
			ds.Spec.Template.Spec.Containers[i].Image = f.config.Images.NodeExporter
		case "kube-rbac-proxy":
			ds.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		}
	}

	for i, container := range ds.Spec.Template.Spec.InitContainers {
		switch container.Name {
		case "init-textfile":
			ds.Spec.Template.Spec.InitContainers[i].Image = f.config.Images.NodeExporter
		}
	}

	ds.Namespace = f.namespace

	return ds, nil
}

func (f *Factory) NodeExporterService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(NodeExporterService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) NodeExporterSecurityContextConstraints() (*securityv1.SecurityContextConstraints, error) {
	scc, err := f.NewSecurityContextConstraints(f.assets.MustNewAssetReader(NodeExporterSecurityContextConstraints))
	if err != nil {
		return nil, err
	}

	return scc, nil
}

func (f *Factory) NodeExporterServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(NodeExporterServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) NodeExporterClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(NodeExporterClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) NodeExporterClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(NodeExporterClusterRole))
}

func (f *Factory) NodeExporterPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(NodeExporterPrometheusRule))
}

func (f *Factory) PrometheusK8sClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusK8sClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) ThanosQuerierClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(ThanosQuerierClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusUserWorkloadClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusUserWorkloadClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespaceUserWorkload

	return crb, nil
}

func (f *Factory) PrometheusK8sClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(PrometheusK8sClusterRole))
}

func (f *Factory) ThanosQuerierClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(ThanosQuerierClusterRole))
}

func (f *Factory) PrometheusUserWorkloadClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(PrometheusUserWorkloadClusterRole))
}

func (f *Factory) PrometheusK8sRoleConfig() (*rbacv1.Role, error) {
	r, err := f.NewRole(f.assets.MustNewAssetReader(PrometheusK8sRoleConfig))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) PrometheusUserWorkloadRoleConfig() (*rbacv1.Role, error) {
	r, err := f.NewRole(f.assets.MustNewAssetReader(PrometheusUserWorkloadRoleConfig))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespaceUserWorkload

	return r, nil
}

func (f *Factory) PrometheusK8sRoleBindingList() (*rbacv1.RoleBindingList, error) {
	rbl, err := f.NewRoleBindingList(f.assets.MustNewAssetReader(PrometheusK8sRoleBindingList))
	if err != nil {
		return nil, err
	}

	for _, rb := range rbl.Items {
		rb.Subjects[0].Namespace = f.namespace
	}

	return rbl, nil
}

func (f *Factory) PrometheusUserWorkloadRoleBindingList() (*rbacv1.RoleBindingList, error) {
	rbl, err := f.NewRoleBindingList(f.assets.MustNewAssetReader(PrometheusUserWorkloadRoleBindingList))
	if err != nil {
		return nil, err
	}

	for _, rb := range rbl.Items {
		rb.Subjects[0].Namespace = f.namespaceUserWorkload
	}

	return rbl, nil
}

func (f *Factory) PrometheusK8sRoleBindingConfig() (*rbacv1.RoleBinding, error) {
	rb, err := f.NewRoleBinding(f.assets.MustNewAssetReader(PrometheusK8sRoleBindingConfig))
	if err != nil {
		return nil, err
	}

	rb.Namespace = f.namespace

	return rb, nil
}

func (f *Factory) PrometheusUserWorkloadRoleBindingConfig() (*rbacv1.RoleBinding, error) {
	rb, err := f.NewRoleBinding(f.assets.MustNewAssetReader(PrometheusUserWorkloadRoleBindingConfig))
	if err != nil {
		return nil, err
	}

	rb.Namespace = f.namespaceUserWorkload

	return rb, nil
}

func (f *Factory) PrometheusK8sRoleList() (*rbacv1.RoleList, error) {
	rl, err := f.NewRoleList(f.assets.MustNewAssetReader(PrometheusK8sRoleList))
	if err != nil {
		return nil, err
	}

	for _, r := range rl.Items {
		r.Namespace = f.namespace
	}

	return rl, nil
}

func (f *Factory) PrometheusUserWorkloadRoleList() (*rbacv1.RoleList, error) {
	rl, err := f.NewRoleList(f.assets.MustNewAssetReader(PrometheusUserWorkloadRoleList))
	if err != nil {
		return nil, err
	}

	for _, r := range rl.Items {
		r.Namespace = f.namespaceUserWorkload
	}

	return rl, nil
}

func (f *Factory) PrometheusK8sPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(PrometheusK8sPrometheusRule))
}

func (f *Factory) PrometheusK8sServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(PrometheusK8sServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ThanosQuerierServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(ThanosQuerierServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusUserWorkloadServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(PrometheusUserWorkloadServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) PrometheusK8sProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(PrometheusK8sProxySecret))
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

func (f *Factory) PrometheusK8sGrpcTLSSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(PrometheusK8sGrpcTLSSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusUserWorkloadGrpcTLSSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(PrometheusUserWorkloadGrpcTLSSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) ThanosQuerierGrpcTLSSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(ThanosQuerierGrpcTLSSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ThanosQuerierOauthCookieSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(ThanosQuerierOauthCookieSecret))
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
	s, err := f.NewSecret(f.assets.MustNewAssetReader(PrometheusK8sHtpasswd))
	if err != nil {
		return nil, err
	}

	f.generateHtpasswdSecret(s, password)
	return s, nil
}

func (f *Factory) ThanosQuerierHtpasswdSecret(password string) (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(ThanosQuerierHtpasswdSecret))
	if err != nil {
		return nil, err
	}

	f.generateHtpasswdSecret(s, password)
	return s, nil
}

func (f *Factory) ThanosRulerHtpasswdSecret(password string) (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(ThanosRulerHtpasswdSecret))
	if err != nil {
		return nil, err
	}

	f.generateHtpasswdSecret(s, password)
	s.Namespace = f.namespaceUserWorkload
	return s, nil
}

func (f *Factory) generateHtpasswdSecret(s *v1.Secret, password string) {
	// #nosec
	// TODO: Replace this with a safer algorithm
	h := sha1.New()
	h.Write([]byte(password))
	s.Data["auth"] = []byte("internal:{SHA}" + base64.StdEncoding.EncodeToString(h.Sum(nil)))
	s.Namespace = f.namespace
}

func (f *Factory) ThanosRulerQueryConfigSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(ThanosRulerQueryConfigSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload
	return s, nil
}

func (f *Factory) ThanosRulerAlertmanagerConfigSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(ThanosRulerAlertmanagerConfigSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload
	return s, nil
}

func (f *Factory) PrometheusRBACProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(PrometheusRBACProxySecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ThanosQuerierRBACProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(ThanosQuerierRBACProxySecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}
func (f *Factory) ThanosQuerierRBACProxyRulesSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(ThanosQuerierRBACProxyRulesSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sServingCertsCABundle() (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusK8sServingCertsCABundle))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace

	return c, nil
}

func (f *Factory) PrometheusUserWorkloadServingCertsCABundle() (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusUserWorkloadServingCertsCABundle))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespaceUserWorkload

	return c, nil
}

func (f *Factory) PrometheusK8sKubeletServingCABundle(data map[string]string) (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusK8sKubeletServingCABundle))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace
	c.Data = data

	return c, nil
}

func (f *Factory) PrometheusOperatorCertsCABundle() (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusOperatorCertsCABundle))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace

	return c, nil
}

func (f *Factory) PrometheusK8sThanosSidecarServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusK8sThanosSidecarServiceMonitor))
	if err != nil {
		return nil, err
	}

	s.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-k8s-thanos-sidecar.%s.svc", f.namespace)
	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(f.assets.MustNewAssetReader(PrometheusK8sRoute))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) ThanosQuerierRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(f.assets.MustNewAssetReader(ThanosQuerierRoute))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) SharingConfig(promHost, amHost, grafanaHost, thanosHost *url.URL) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sharedConfigMap,
			Namespace: configManagedNamespace,
		},
		Data: map[string]string{
			// Configmap keys need to include "public" to indicate that they are public values.
			// See https://bugzilla.redhat.com/show_bug.cgi?id=1807100.
			"grafanaPublicURL":      grafanaHost.String(),
			"prometheusPublicURL":   promHost.String(),
			"alertmanagerPublicURL": amHost.String(),
			"thanosPublicURL":       thanosHost.String(),
		},
	}
}

func (f *Factory) PrometheusK8sTrustedCABundle() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusK8sTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func (f *Factory) PrometheusK8s(host string, grpcTLS *v1.Secret, trustedCABundleCM *v1.ConfigMap) (*monv1.Prometheus, error) {
	p, err := f.NewPrometheus(f.assets.MustNewAssetReader(PrometheusK8s))
	if err != nil {
		return nil, err
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.LogLevel != "" {
		p.Spec.LogLevel = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.LogLevel
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention != "" {
		p.Spec.Retention = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention
	}

	p.Spec.Image = &f.config.Images.Prometheus
	p.Spec.ExternalURL = f.PrometheusExternalURL(host).String()

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Resources != nil {
		p.Spec.Resources = *f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Resources
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.NodeSelector != nil {
		p.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Tolerations) > 0 {
		p.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Tolerations
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.ExternalLabels != nil {
		p.Spec.ExternalLabels = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.ExternalLabels
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.VolumeClaimTemplate != nil {
		p.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.VolumeClaimTemplate,
		}
	}

	telemetryEnabled := f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled()
	if telemetryEnabled && f.config.RemoteWrite {

		selectorRelabelConfig, err := promqlgen.LabelSelectorsToRelabelConfig(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.TelemetryMatches)
		if err != nil {
			return nil, errors.Wrap(err, "generate label selector relabel config")
		}

		compositeToken, err := json.Marshal(map[string]string{
			"cluster_id":          f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID,
			"authorization_token": f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Token,
		})

		spec := monv1.RemoteWriteSpec{
			URL:         f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL,
			BearerToken: base64.StdEncoding.EncodeToString(compositeToken),
			QueueConfig: &monv1.QueueConfig{
				// Amount of samples to load from the WAL into the in-memory
				// buffer before waiting for samples to be sent successfully
				// and then continuing to read from the WAL.
				Capacity: 30000,
				// Should we accumulate 10000 samples before the batch send
				// deadline is reached, we will send this amount of samples
				// anyways.
				MaxSamplesPerSend: 10000,
				// Batch samples for 1m until we send them if we not reach the
				// 10000 MaxSamplesPerSend first.
				BatchSendDeadline: "1m",
				// Backoff is doubled on every backoff. We start with 1s
				// backoff and double until the MaxBackOff.
				MinBackoff: "1s",
				// 128s is the 8th backoff in a row, once we end up here, we
				// don't increase backoff time anymore. As we would at most
				// produce (concurrency/256) number of requests per second.
				MaxBackoff: "256s",
			},
			WriteRelabelConfigs: []monv1.RelabelConfig{
				*selectorRelabelConfig,
				monv1.RelabelConfig{
					TargetLabel: "_id",
					Replacement: f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID,
				},
				// relabeling the `ALERTS` series to `alerts` allows us to make
				// a distinction between the series produced in-cluster and out
				// of cluster.
				monv1.RelabelConfig{
					SourceLabels: []string{"__name__"},
					TargetLabel:  "__name__",
					Regex:        "ALERTS",
					Replacement:  "alerts",
				},
			},
		}

		p.Spec.RemoteWrite = []monv1.RemoteWriteSpec{spec}

	}
	if !telemetryEnabled {
		p.Spec.RemoteWrite = nil
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite) > 0 {
		p.Spec.RemoteWrite = append(p.Spec.RemoteWrite, f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite...)
	}

	for _, rw := range p.Spec.RemoteWrite {
		if f.proxy.HTTPProxy() != "" {
			rw.ProxyURL = f.proxy.HTTPProxy()
		}
		if f.proxy.HTTPSProxy() != "" {
			rw.ProxyURL = f.proxy.HTTPSProxy()
		}
	}

	if !f.config.ClusterMonitoringConfiguration.EtcdConfig.IsEnabled() {
		secrets := []string{}
		for _, s := range p.Spec.Secrets {
			if s != "kube-etcd-client-certs" {
				secrets = append(secrets, s)
			}
		}

		p.Spec.Secrets = secrets
	}

	if f.config.Images.Thanos != "" {
		p.Spec.Thanos.Image = &f.config.Images.Thanos
	}

	p.Spec.Alerting.Alertmanagers[0].Namespace = f.namespace
	p.Spec.Alerting.Alertmanagers[0].TLSConfig.ServerName = fmt.Sprintf("alertmanager-main.%s.svc", f.namespace)
	p.Namespace = f.namespace

	for i, container := range p.Spec.Containers {
		switch container.Name {
		case "prometheus-proxy":
			p.Spec.Containers[i].Image = f.config.Images.OauthProxy

			f.injectProxyVariables(&p.Spec.Containers[i])

		case "kube-rbac-proxy":
			p.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		case "kube-rbac-proxy-thanos":
			p.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		case "prom-label-proxy":
			p.Spec.Containers[i].Image = f.config.Images.PromLabelProxy
		}
	}
	p.Spec.Volumes = append(p.Spec.Volumes, v1.Volume{
		Name: "secret-grpc-tls",
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: grpcTLS.GetName(),
			},
		},
	})

	if trustedCABundleCM != nil {
		volumeName := "prometheus-trusted-ca-bundle"
		volume := trustedCABundleVolume(trustedCABundleCM.Name, volumeName)
		volume.VolumeSource.ConfigMap.Items = append(volume.VolumeSource.ConfigMap.Items, v1.KeyToPath{
			Key:  TrustedCABundleKey,
			Path: "tls-ca-bundle.pem",
		})
		p.Spec.Volumes = append(p.Spec.Volumes, volume)

		// we only need the trusted CA bundle in:
		// 1. Prometheus, because users might want to configure external remote write.
		// 2. In OAuth proxy, as that communicates externally when executing the OAuth handshake.
		for i, container := range p.Spec.Containers {
			if container.Name == "prometheus-proxy" || container.Name == "prometheus" {
				p.Spec.Containers[i].VolumeMounts = append(
					p.Spec.Containers[i].VolumeMounts,
					trustedCABundleVolumeMount(volumeName),
				)
			}
		}
	}

	return p, nil
}

func (f *Factory) PrometheusUserWorkload(grpcTLS *v1.Secret) (*monv1.Prometheus, error) {
	p, err := f.NewPrometheus(f.assets.MustNewAssetReader(PrometheusUserWorkload))
	if err != nil {
		return nil, err
	}
	if f.config.UserWorkloadConfiguration.Prometheus.LogLevel != "" {
		p.Spec.LogLevel = f.config.UserWorkloadConfiguration.Prometheus.LogLevel
	}

	if f.config.UserWorkloadConfiguration.Prometheus.Retention != "" {
		p.Spec.Retention = f.config.UserWorkloadConfiguration.Prometheus.Retention
	}

	p.Spec.Image = &f.config.Images.Prometheus

	if f.config.UserWorkloadConfiguration.Prometheus.Resources != nil {
		p.Spec.Resources = *f.config.UserWorkloadConfiguration.Prometheus.Resources
	}

	if f.config.UserWorkloadConfiguration.Prometheus.NodeSelector != nil {
		p.Spec.NodeSelector = f.config.UserWorkloadConfiguration.Prometheus.NodeSelector
	}

	if len(f.config.UserWorkloadConfiguration.Prometheus.Tolerations) > 0 {
		p.Spec.Tolerations = f.config.UserWorkloadConfiguration.Prometheus.Tolerations
	}

	if f.config.UserWorkloadConfiguration.Prometheus.ExternalLabels != nil {
		p.Spec.ExternalLabels = f.config.UserWorkloadConfiguration.Prometheus.ExternalLabels
	}

	if f.config.UserWorkloadConfiguration.Prometheus.VolumeClaimTemplate != nil {
		p.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *f.config.UserWorkloadConfiguration.Prometheus.VolumeClaimTemplate,
		}
	}

	if len(f.config.UserWorkloadConfiguration.Prometheus.RemoteWrite) > 0 {
		p.Spec.RemoteWrite = f.config.UserWorkloadConfiguration.Prometheus.RemoteWrite
	}

	if f.config.UserWorkloadConfiguration.Prometheus.EnforcedSampleLimit != nil {
		p.Spec.EnforcedSampleLimit = f.config.UserWorkloadConfiguration.Prometheus.EnforcedSampleLimit
	}

	// end removal
	if f.config.Images.Thanos != "" {
		p.Spec.Thanos.Image = &f.config.Images.Thanos
	}

	for i, container := range p.Spec.Containers {
		if container.Name == "kube-rbac-proxy" || container.Name == "kube-rbac-proxy-thanos" {
			p.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		}
	}
	p.Spec.Alerting.Alertmanagers[0].Namespace = f.namespace
	p.Spec.Alerting.Alertmanagers[0].TLSConfig.ServerName = fmt.Sprintf("alertmanager-main.%s.svc", f.namespace)
	p.Namespace = f.namespaceUserWorkload

	p.Spec.Volumes = append(p.Spec.Volumes, v1.Volume{
		Name: "secret-grpc-tls",
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: grpcTLS.GetName(),
			},
		},
	})

	return p, nil
}

func (f *Factory) PrometheusK8sPrometheusServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusK8sPrometheusServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-k8s.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) PrometheusUserWorkloadPrometheusServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusUserWorkloadPrometheusServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-user-workload.%s.svc", f.namespaceUserWorkload)
	sm.Namespace = f.namespaceUserWorkload

	return sm, nil
}

func (f *Factory) PrometheusK8sPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(PrometheusK8sPodDisruptionBudget))
}

func (f *Factory) PrometheusUserWorkloadPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(PrometheusUserWorkloadPodDisruptionBudget))
}

func (f *Factory) PrometheusAdapterClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(PrometheusAdapterClusterRole))
}

func (f *Factory) PrometheusAdapterClusterRoleServerResources() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(PrometheusAdapterClusterRoleServerResources))
}

func (f *Factory) PrometheusAdapterClusterRoleAggregatedMetricsReader() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(PrometheusAdapterClusterRoleAggregatedMetricsReader))
}

func (f *Factory) PrometheusAdapterClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusAdapterClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusAdapterClusterRoleBindingDelegator() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusAdapterClusterRoleBindingDelegator))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusAdapterClusterRoleBindingView() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusAdapterClusterRoleBindingView))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusAdapterRoleBindingAuthReader() (*rbacv1.RoleBinding, error) {
	rb, err := f.NewRoleBinding(f.assets.MustNewAssetReader(PrometheusAdapterRoleBindingAuthReader))
	if err != nil {
		return nil, err
	}

	rb.Subjects[0].Namespace = f.namespace

	return rb, nil
}

func (f *Factory) PrometheusAdapterServiceAccount() (*v1.ServiceAccount, error) {
	sa, err := f.NewServiceAccount(f.assets.MustNewAssetReader(PrometheusAdapterServiceAccount))
	if err != nil {
		return nil, err
	}

	sa.Namespace = f.namespace

	return sa, nil
}

func (f *Factory) PrometheusAdapterConfigMap() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusAdapterConfigMap))
	if err != nil {
		return nil, err
	}

	cm.Namespace = f.namespace

	return cm, nil
}

func (f *Factory) PrometheusAdapterConfigMapPrometheus() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusAdapterConfigMapPrometheus))
	if err != nil {
		return nil, err
	}

	cm.Namespace = f.namespace

	return cm, nil
}

func (f *Factory) PrometheusAdapterDeployment(apiAuthSecretName string, requestheader map[string]string) (*appsv1.Deployment, error) {
	dep, err := f.NewDeployment(f.assets.MustNewAssetReader(PrometheusAdapterDeployment))
	if err != nil {
		return nil, err
	}

	spec := dep.Spec.Template.Spec

	spec.Containers[0].Image = f.config.Images.K8sPrometheusAdapter
	if f.config.ClusterMonitoringConfiguration.K8sPrometheusAdapter != nil && len(f.config.ClusterMonitoringConfiguration.K8sPrometheusAdapter.NodeSelector) > 0 {
		spec.NodeSelector = f.config.ClusterMonitoringConfiguration.K8sPrometheusAdapter.NodeSelector
	}

	if f.config.ClusterMonitoringConfiguration.K8sPrometheusAdapter != nil && len(f.config.ClusterMonitoringConfiguration.K8sPrometheusAdapter.Tolerations) > 0 {
		spec.Tolerations = f.config.ClusterMonitoringConfiguration.K8sPrometheusAdapter.Tolerations
	}
	dep.Namespace = f.namespace

	r := newErrMapReader(requestheader)

	var (
		requestheaderAllowedNames       = strings.Join(r.slice("requestheader-allowed-names"), ",")
		requestheaderExtraHeadersPrefix = strings.Join(r.slice("requestheader-extra-headers-prefix"), ",")
		requestheaderGroupHeaders       = strings.Join(r.slice("requestheader-group-headers"), ",")
		requestheaderUsernameHeaders    = strings.Join(r.slice("requestheader-username-headers"), ",")
	)

	if r.Error() != nil {
		return nil, errors.Wrap(r.err, "value not found in extension api server authentication configmap")
	}

	spec.Containers[0].Args = append(spec.Containers[0].Args,
		"--client-ca-file=/etc/tls/private/client-ca-file",
		"--requestheader-client-ca-file=/etc/tls/private/requestheader-client-ca-file",
		"--requestheader-allowed-names="+requestheaderAllowedNames,
		"--requestheader-extra-headers-prefix="+requestheaderExtraHeadersPrefix,
		"--requestheader-group-headers="+requestheaderGroupHeaders,
		"--requestheader-username-headers="+requestheaderUsernameHeaders,
		"--tls-cert-file=/etc/tls/private/tls.crt",
		"--tls-private-key-file=/etc/tls/private/tls.key",
	)

	spec.Containers[0].VolumeMounts = append(spec.Containers[0].VolumeMounts,
		v1.VolumeMount{
			Name:      "tls",
			ReadOnly:  true,
			MountPath: "/etc/tls/private",
		},
	)

	spec.Volumes = append(spec.Volumes,
		v1.Volume{
			Name: "tls",
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: apiAuthSecretName,
				},
			},
		},
	)

	dep.Spec.Template.Spec = spec

	return dep, nil
}

func (f *Factory) PrometheusAdapterPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	pdb, err := f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(PrometheusAdapterPodDisruptionBudget))
	if err != nil {
		return nil, err
	}

	if pdb != nil {
		pdb.Namespace = f.namespace
	}

	return pdb, nil
}

func (f *Factory) PrometheusAdapterService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(PrometheusAdapterService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusAdapterServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusAdapterServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Namespace = f.namespace
	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-adapter.%s.svc", f.namespace)

	return sm, nil
}

func (f *Factory) PrometheusAdapterSecret(tlsSecret *v1.Secret, apiAuthConfigmap *v1.ConfigMap) (*v1.Secret, error) {
	data := make(map[string]string)

	for k, v := range tlsSecret.Data {
		data[k] = string(v)
	}

	for k, v := range apiAuthConfigmap.Data {
		data[k] = v
	}

	r := newErrMapReader(data)

	var (
		clientCA              = r.value("client-ca-file")
		requestheaderClientCA = r.value("requestheader-client-ca-file")
		tlsCA                 = r.value("tls.crt")
		tlsKey                = r.value("tls.key")
	)

	if r.Error() != nil {
		return nil, errors.Wrap(r.err, "value not found in extension api server authentication configmap")
	}

	h := fnv.New64()
	h.Write([]byte(clientCA + requestheaderClientCA + tlsCA + tlsKey))
	hash := strconv.FormatUint(h.Sum64(), 32)

	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: f.namespace,
			Name:      fmt.Sprintf("prometheus-adapter-%s", hash),
			Labels: map[string]string{
				"monitoring.openshift.io/name": "prometheus-adapter",
				"monitoring.openshift.io/hash": hash,
			},
		},
		Data: map[string][]byte{
			"client-ca-file":               []byte(clientCA),
			"requestheader-client-ca-file": []byte(requestheaderClientCA),
			"tls.crt":                      []byte(tlsCA),
			"tls.key":                      []byte(tlsKey),
		},
	}, nil
}

func (f *Factory) PrometheusAdapterAPIService() (*apiregistrationv1.APIService, error) {
	return f.NewAPIService(f.assets.MustNewAssetReader(PrometheusAdapterAPIService))
}

func (f *Factory) PrometheusOperatorServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusOperatorServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Namespace = f.namespace
	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-operator.%s.svc", f.namespace)

	return sm, nil
}

func (f *Factory) PrometheusOperatorPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(PrometheusOperatorPrometheusRule))
}

func (f *Factory) PrometheusOperatorUserWorkloadServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Namespace = f.namespaceUserWorkload
	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-operator.%s.svc", f.namespaceUserWorkload)

	return sm, nil
}

func (f *Factory) PrometheusUserWorkloadThanosSidecarServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusUserWorkloadThanosSidecarServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Namespace = f.namespaceUserWorkload
	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-user-workload-thanos-sidecar.%s.svc", f.namespaceUserWorkload)

	return sm, nil
}

func (f *Factory) PrometheusOperatorClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusOperatorClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusOperatorUserWorkloadClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespaceUserWorkload

	return crb, nil
}

func (f *Factory) PrometheusOperatorClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(PrometheusOperatorClusterRole))
}

func (f *Factory) PrometheusOperatorUserWorkloadClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadClusterRole))
}

func (f *Factory) PrometheusOperatorServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(PrometheusOperatorServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusOperatorUserWorkloadServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) PrometheusOperatorDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(PrometheusOperatorDeployment))
	if err != nil {
		return nil, err
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.NodeSelector) > 0 {

		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Tolerations
	}

	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "kube-rbac-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		case "prometheus-operator":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.PrometheusOperator

			args := d.Spec.Template.Spec.Containers[i].Args
			for i := range args {
				if strings.HasPrefix(args[i], PrometheusConfigReloaderFlag) && f.config.Images.PrometheusConfigReloader != "" {
					args[i] = PrometheusConfigReloaderFlag + f.config.Images.PrometheusConfigReloader
				}

				if strings.HasPrefix(args[i], PrometheusOperatorAlertmanagerInstanceNamespacesFlag) && f.namespace != "" {
					args[i] = PrometheusOperatorAlertmanagerInstanceNamespacesFlag + f.namespace
				}

				if strings.HasPrefix(args[i], PrometheusOperatorPrometheusInstanceNamespacesFlag) && f.namespace != "" {
					args[i] = PrometheusOperatorPrometheusInstanceNamespacesFlag + f.namespace
				}
			}
			if f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.LogLevel != "" {
				args = append(args, fmt.Sprintf("--log-level=%s", f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.LogLevel))
			}
			d.Spec.Template.Spec.Containers[i].Args = args
		}
	}
	d.Namespace = f.namespace

	return d, nil
}

func (f *Factory) PrometheusOperatorUserWorkloadDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadDeployment))
	if err != nil {
		return nil, err
	}

	if len(f.config.UserWorkloadConfiguration.PrometheusOperator.NodeSelector) > 0 {
		d.Spec.Template.Spec.NodeSelector = f.config.UserWorkloadConfiguration.PrometheusOperator.NodeSelector
	}

	if len(f.config.UserWorkloadConfiguration.PrometheusOperator.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.UserWorkloadConfiguration.PrometheusOperator.Tolerations
	}

	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "kube-rbac-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		case "prometheus-operator":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.PrometheusOperator

			args := d.Spec.Template.Spec.Containers[i].Args
			for i := range args {
				if strings.HasPrefix(args[i], PrometheusConfigReloaderFlag) {
					args[i] = PrometheusConfigReloaderFlag + f.config.Images.PrometheusConfigReloader
				}

				if strings.HasPrefix(args[i], PrometheusOperatorAlertmanagerInstanceNamespacesFlag) {
					args[i] = PrometheusOperatorAlertmanagerInstanceNamespacesFlag + f.namespaceUserWorkload
				}

				if strings.HasPrefix(args[i], PrometheusOperatorPrometheusInstanceNamespacesFlag) {
					args[i] = PrometheusOperatorPrometheusInstanceNamespacesFlag + f.namespaceUserWorkload
				}
			}
			if f.config.UserWorkloadConfiguration.PrometheusOperator.LogLevel != "" {
				args = append(args, fmt.Sprintf("--log-level=%s", f.config.UserWorkloadConfiguration.PrometheusOperator.LogLevel))
			}
			d.Spec.Template.Spec.Containers[i].Args = args
		}
	}
	d.Namespace = f.namespaceUserWorkload

	return d, nil
}

func (f *Factory) PrometheusRuleValidatingWebhook() (*admissionv1.ValidatingWebhookConfiguration, error) {
	wc, err := f.NewValidatingWebhook(f.assets.MustNewAssetReader(PrometheusOperatorRuleValidatingWebhook))
	if err != nil {
		return nil, err
	}
	return wc, nil
}

func (f *Factory) PrometheusOperatorService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(PrometheusOperatorService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusOperatorUserWorkloadService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) PrometheusK8sService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(PrometheusK8sService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sServiceThanosSidecar() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(PrometheusK8sServiceThanosSidecar))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusUserWorkloadService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(PrometheusUserWorkloadService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) PrometheusUserWorkloadServiceThanosSidecar() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(PrometheusUserWorkloadServiceThanosSidecar))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) GrafanaClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(GrafanaClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) GrafanaClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(GrafanaClusterRole))
}

func (f *Factory) GrafanaConfig() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(GrafanaConfigSecret))
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
	s, err := f.NewSecret(f.assets.MustNewAssetReader(GrafanaDatasourcesSecret))
	if err != nil {
		return nil, err
	}

	d := &GrafanaDatasources{}
	err = json.Unmarshal(s.Data["datasources.yaml"], d)
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
	cl, err := f.NewConfigMapList(f.assets.MustNewAssetReader(GrafanaDashboardDefinitions))
	if err != nil {
		return nil, err
	}

	configmaps := []v1.ConfigMap{}
	for _, c := range cl.Items {
		c.Namespace = f.namespace
		if !f.config.ClusterMonitoringConfiguration.EtcdConfig.IsEnabled() {
			if c.GetName() != "grafana-dashboard-etcd" {
				configmaps = append(configmaps, c)
			}
		} else {
			configmaps = append(configmaps, c)
		}
	}
	cl.Items = configmaps

	return cl, nil
}

func (f *Factory) GrafanaDashboardSources() (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(f.assets.MustNewAssetReader(GrafanaDashboardSources))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace

	return c, nil
}

func (f *Factory) GrafanaTrustedCABundle() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(f.assets.MustNewAssetReader(GrafanaTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

// GrafanaDeployment generates a new Deployment for Grafana.
// If the passed ConfigMap is not empty it mounts the Trusted CA Bundle as a VolumeMount to
// /etc/pki/ca-trust/extracted/pem/ location.
func (f *Factory) GrafanaDeployment(proxyCABundleCM *v1.ConfigMap) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(GrafanaDeployment))
	if err != nil {
		return nil, err
	}

	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "grafana":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.Grafana

			if !f.config.ClusterMonitoringConfiguration.EtcdConfig.IsEnabled() {
				vols := []v1.Volume{}
				volMounts := []v1.VolumeMount{}
				for _, v := range d.Spec.Template.Spec.Volumes {
					if v.Name != "grafana-dashboard-etcd" {
						vols = append(vols, v)
					}
				}
				for _, vm := range d.Spec.Template.Spec.Containers[i].VolumeMounts {
					if vm.Name != "grafana-dashboard-etcd" {
						volMounts = append(volMounts, vm)
					}
				}

				d.Spec.Template.Spec.Volumes = vols
				d.Spec.Template.Spec.Containers[i].VolumeMounts = volMounts
			}

		case "grafana-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.OauthProxy

			f.injectProxyVariables(&d.Spec.Template.Spec.Containers[i])

			if proxyCABundleCM != nil {
				volumeName := "grafana-trusted-ca-bundle"
				d.Spec.Template.Spec.Containers[i].VolumeMounts = append(d.Spec.Template.Spec.Containers[i].VolumeMounts, trustedCABundleVolumeMount(volumeName))
				volume := trustedCABundleVolume(proxyCABundleCM.Name, volumeName)
				volume.VolumeSource.ConfigMap.Items = append(volume.VolumeSource.ConfigMap.Items, v1.KeyToPath{
					Key:  TrustedCABundleKey,
					Path: "tls-ca-bundle.pem",
				})
				d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, volume)
			}
		}
	}

	if f.config.ClusterMonitoringConfiguration.GrafanaConfig.NodeSelector != nil {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.GrafanaConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.GrafanaConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.GrafanaConfig.Tolerations
	}

	d.Namespace = f.namespace

	return d, nil
}

func (f *Factory) GrafanaProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(GrafanaProxySecret))
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
	r, err := f.NewRoute(f.assets.MustNewAssetReader(GrafanaRoute))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) GrafanaServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(GrafanaServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) GrafanaService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(GrafanaService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) GrafanaServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(GrafanaServiceMonitor))
	if err != nil {
		return nil, err
	}

	s.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("grafana.%s.svc", f.namespace)
	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ClusterMonitoringClusterRole() (*rbacv1.ClusterRole, error) {
	cr, err := f.NewClusterRole(f.assets.MustNewAssetReader(ClusterMonitoringClusterRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func (f *Factory) ClusterMonitoringRulesEditClusterRole() (*rbacv1.ClusterRole, error) {
	cr, err := f.NewClusterRole(f.assets.MustNewAssetReader(ClusterMonitoringRulesEditClusterRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func (f *Factory) ClusterMonitoringRulesViewClusterRole() (*rbacv1.ClusterRole, error) {
	cr, err := f.NewClusterRole(f.assets.MustNewAssetReader(ClusterMonitoringRulesViewClusterRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func (f *Factory) ClusterMonitoringEditClusterRole() (*rbacv1.ClusterRole, error) {
	cr, err := f.NewClusterRole(f.assets.MustNewAssetReader(ClusterMonitoringEditClusterRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func (f *Factory) ClusterMonitoringEditUserWorkloadConfigRole() (*rbacv1.Role, error) {
	cr, err := f.NewRole(f.assets.MustNewAssetReader(ClusterMonitoringEditUserWorkloadConfigRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func (f *Factory) ClusterMonitoringOperatorService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(ClusterMonitoringOperatorService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ClusterMonitoringOperatorServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(ClusterMonitoringOperatorServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("cluster-monitoring-operator.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) ClusterMonitoringOperatorPrometheusRule() (*monv1.PrometheusRule, error) {
	r, err := f.NewPrometheusRule(f.assets.MustNewAssetReader(ClusterMonitoringOperatorPrometheusRule))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) ControlPlanePrometheusRule() (*monv1.PrometheusRule, error) {
	r, err := f.NewPrometheusRule(f.assets.MustNewAssetReader(ControlPlanePrometheusRule))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	if f.infrastructure.HostedControlPlane() {
		groups := []monv1.RuleGroup{}
		for _, g := range r.Spec.Groups {
			switch g.Name {
			case "kubernetes-system-apiserver",
				"kubernetes-system-controller-manager",
				"kubernetes-system-scheduler":
				// skip
			default:
				groups = append(groups, g)
			}
		}
		r.Spec.Groups = groups
	}

	return r, nil
}

func (f *Factory) ControlPlaneEtcdPrometheusRule() (*monv1.PrometheusRule, error) {
	r, err := f.NewPrometheusRule(f.assets.MustNewAssetReader(ControlPlaneEtcdPrometheusRule))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) ControlPlaneEtcdSecret(tlsClient *v1.Secret, ca *v1.ConfigMap) (*v1.Secret, error) {
	data := make(map[string]string)

	for k, v := range tlsClient.Data {
		data[k] = string(v)
	}

	for k, v := range ca.Data {
		data[k] = v
	}

	r := newErrMapReader(data)

	var (
		clientCA   = r.value(TrustedCABundleKey)
		clientCert = r.value("tls.crt")
		clientKey  = r.value("tls.key")
	)

	if r.Error() != nil {
		return nil, errors.Wrap(r.err, "couldn't find etcd certificate data")
	}

	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: f.namespace,
			Name:      "kube-etcd-client-certs",
		},
		StringData: map[string]string{
			"etcd-client-ca.crt": clientCA,
			"etcd-client.key":    clientKey,
			"etcd-client.crt":    clientCert,
		},
	}, nil
}

func (f *Factory) ControlPlaneEtcdServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(ControlPlaneEtcdServiceMonitor))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ControlPlaneKubeletServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(ControlPlaneKubeletServiceMonitor))
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

func (f *Factory) NewPodDisruptionBudget(manifest io.Reader) (*policyv1.PodDisruptionBudget, error) {
	if !f.infrastructure.HighlyAvailableInfrastructure() {
		return nil, nil
	}

	pdb, err := NewPodDisruptionBudget(manifest)
	if err != nil {
		return nil, err
	}

	if pdb.GetNamespace() == "" {
		pdb.SetNamespace(f.namespace)
	}

	return pdb, nil
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

func (f *Factory) NewRoleBinding(manifest io.Reader) (*rbacv1.RoleBinding, error) {
	rb, err := NewRoleBinding(manifest)
	if err != nil {
		return nil, err
	}

	if rb.GetNamespace() == "" {
		rb.SetNamespace(f.namespace)
	}

	return rb, nil
}

func (f *Factory) NewRoleList(manifest io.Reader) (*rbacv1.RoleList, error) {
	rl, err := NewRoleList(manifest)
	if err != nil {
		return nil, err
	}

	for _, r := range rl.Items {
		if r.GetNamespace() == "" {
			r.SetNamespace(f.namespace)
		}
	}

	return rl, nil
}

func (f *Factory) NewRoleBindingList(manifest io.Reader) (*rbacv1.RoleBindingList, error) {
	rbl, err := NewRoleBindingList(manifest)
	if err != nil {
		return nil, err
	}

	for _, rb := range rbl.Items {
		if rb.GetNamespace() == "" {
			rb.SetNamespace(f.namespace)
		}
	}

	return rbl, nil
}

func (f *Factory) NewRole(manifest io.Reader) (*rbacv1.Role, error) {
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

	if !f.infrastructure.HighlyAvailableInfrastructure() {
		p.Spec.Replicas = func(i int32) *int32 { return &i }(1)
		p.Spec.Affinity = nil
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

func (f *Factory) NewTelemeterPrometheusRecRuleFromString(expr string) (*monv1.PrometheusRule, error) {
	p := &monv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "telemetry",
		},
		Spec: monv1.PrometheusRuleSpec{
			Groups: []monv1.RuleGroup{
				{
					Name: "telemeter.rules",
					Rules: []monv1.Rule{
						{
							Record: "cluster:telemetry_selected_series:count",
							Expr:   intstr.FromString(expr),
						},
					},
				},
			},
		},
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

	if !f.infrastructure.HighlyAvailableInfrastructure() {
		a.Spec.Replicas = func(i int32) *int32 { return &i }(1)
		a.Spec.Affinity = nil
	}

	return a, nil
}

func (f *Factory) NewThanosRuler(manifest io.Reader) (*monv1.ThanosRuler, error) {
	t, err := NewThanosRuler(manifest)
	if err != nil {
		return nil, err
	}

	if t.GetNamespace() == "" {
		t.SetNamespace(f.namespaceUserWorkload)
	}

	if !f.infrastructure.HighlyAvailableInfrastructure() {
		t.Spec.Replicas = func(i int32) *int32 { return &i }(1)
		t.Spec.Affinity = nil
	}

	return t, nil
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

	if !f.infrastructure.HighlyAvailableInfrastructure() {
		d.Spec.Replicas = func(i int32) *int32 { return &i }(1)
		d.Spec.Template.Spec.Affinity = nil
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

func (f *Factory) NewAPIService(manifest io.Reader) (*apiregistrationv1.APIService, error) {
	return NewAPIService(manifest)
}

func (f *Factory) NewSecurityContextConstraints(manifest io.Reader) (*securityv1.SecurityContextConstraints, error) {
	return NewSecurityContextConstraints(manifest)
}

func (f *Factory) NewClusterRoleBinding(manifest io.Reader) (*rbacv1.ClusterRoleBinding, error) {
	return NewClusterRoleBinding(manifest)
}

func (f *Factory) NewClusterRole(manifest io.Reader) (*rbacv1.ClusterRole, error) {
	return NewClusterRole(manifest)
}

func (f *Factory) NewValidatingWebhook(manifest io.Reader) (*admissionv1.ValidatingWebhookConfiguration, error) {
	return NewValidatingWebhook(manifest)
}

func (f *Factory) ThanosQuerierDeployment(grpcTLS *v1.Secret, enableUserWorkloadMonitoring bool, trustedCA *v1.ConfigMap) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(ThanosQuerierDeployment))
	if err != nil {
		return nil, err
	}

	d.Namespace = f.namespace

	for i, c := range d.Spec.Template.Spec.Containers {
		switch c.Name {
		case "oauth-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.OauthProxy

			f.injectProxyVariables(&d.Spec.Template.Spec.Containers[i])

			if trustedCA != nil {
				volumeName := "thanos-querier-trusted-ca-bundle"
				d.Spec.Template.Spec.Containers[i].VolumeMounts = append(
					d.Spec.Template.Spec.Containers[i].VolumeMounts,
					trustedCABundleVolumeMount(volumeName),
				)

				volume := trustedCABundleVolume(trustedCA.Name, volumeName)
				volume.VolumeSource.ConfigMap.Items = append(volume.VolumeSource.ConfigMap.Items, v1.KeyToPath{
					Key:  TrustedCABundleKey,
					Path: "tls-ca-bundle.pem",
				})
				d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, volume)
			}

		case "thanos-query":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.Thanos

			if enableUserWorkloadMonitoring {
				d.Spec.Template.Spec.Containers[i].Args = append(
					d.Spec.Template.Spec.Containers[i].Args,
					"--store=dnssrv+_grpc._tcp.prometheus-operated.openshift-user-workload-monitoring.svc.cluster.local",
					"--store=dnssrv+_grpc._tcp.thanos-ruler-operated.openshift-user-workload-monitoring.svc.cluster.local",
					"--rule=dnssrv+_grpc._tcp.prometheus-operated.openshift-user-workload-monitoring.svc.cluster.local",
					"--rule=dnssrv+_grpc._tcp.thanos-ruler-operated.openshift-user-workload-monitoring.svc.cluster.local",
				)
			}

			if f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.Resources != nil {
				d.Spec.Template.Spec.Containers[i].Resources = *f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.Resources
			}
			if f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.LogLevel != "" {
				d.Spec.Template.Spec.Containers[i].Args = append(d.Spec.Template.Spec.Containers[i].Args, fmt.Sprintf("--log.level=%s", f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.LogLevel))
			}

		case "prom-label-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.PromLabelProxy

		case "kube-rbac-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy

		case "kube-rbac-proxy-rules":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		}
	}

	d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, v1.Volume{
		Name: "secret-grpc-tls",
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: grpcTLS.GetName(),
			},
		},
	})

	if f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.NodeSelector != nil {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.Tolerations
	}

	return d, nil
}

func (f *Factory) ThanosQuerierTrustedCABundle() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(f.assets.MustNewAssetReader(ThanosQuerierTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func (f *Factory) ThanosQuerierService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(ThanosQuerierService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ThanosQuerierPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(ThanosQuerierPrometheusRule))
}

func (f *Factory) ThanosQuerierServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(ThanosQuerierServiceMonitor))
	if err != nil {
		return nil, err
	}

	var found bool
	const endpointPort = "web"
	for i := range sm.Spec.Endpoints {
		if sm.Spec.Endpoints[i].Port == endpointPort {
			found = true
			sm.Spec.Endpoints[i].TLSConfig.ServerName = fmt.Sprintf("thanos-querier.%s.svc", f.namespace)
		}
	}
	if !found {
		return nil, errors.Errorf("failed to find endpoint port %q", endpointPort)
	}

	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) TelemeterTrustedCABundle() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(f.assets.MustNewAssetReader(TelemeterTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

// TelemeterClientServingCertsCABundle generates a new servinc certs CA bundle ConfigMap for TelemeterClient.
func (f *Factory) TelemeterClientServingCertsCABundle() (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(f.assets.MustNewAssetReader(TelemeterClientServingCertsCABundle))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace

	return c, nil
}

// TelemeterClientClusterRole generates a new ClusterRole for Telemeter client.
func (f *Factory) TelemeterClientClusterRole() (*rbacv1.ClusterRole, error) {
	cr, err := f.NewClusterRole(f.assets.MustNewAssetReader(TelemeterClientClusterRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

// TelemeterClientClusterRoleBinding generates a new ClusterRoleBinding for Telemeter client.
func (f *Factory) TelemeterClientClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(TelemeterClientClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	return crb, nil
}

// TelemeterClientClusterRoleBindingView generates a new ClusterRoleBinding for Telemeter client
// for the cluster monitoring view ClusterRole.
func (f *Factory) TelemeterClientClusterRoleBindingView() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(TelemeterClientClusterRoleBindingView))
	if err != nil {
		return nil, err
	}

	return crb, nil
}

// TelemeterClientServiceMonitor generates a new ServiceMonitor for Telemeter client.
func (f *Factory) TelemeterClientServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(TelemeterClientServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("telemeter-client.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

// TelemeterClientDeployment generates a new Deployment for Telemeter client.
// If the passed ConfigMap is not empty it mounts the Trusted CA Bundle as a VolumeMount to
// /etc/pki/ca-trust/extracted/pem/ location.
func (f *Factory) TelemeterClientDeployment(proxyCABundleCM *v1.ConfigMap) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(TelemeterClientDeployment))
	if err != nil {
		return nil, err
	}

	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "telemeter-client":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.TelemeterClient

			if f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID != "" {
				setContainerEnvironmentVariable(&d.Spec.Template.Spec.Containers[i], "ID", f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID)
			}
			if f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL != "" {
				setContainerEnvironmentVariable(&d.Spec.Template.Spec.Containers[i], "TO", f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL)
			}

			f.injectProxyVariables(&d.Spec.Template.Spec.Containers[i])

			cmd := []string{}
			// Note: matchers are read only during CMO bootstrap. This mechanism was chosen as CMO image will be reloaded during upgrades
			// and matchers shouldn't change during runtime. It offers similar amount of protection against unwanted configuration changes
			// while not having any performace penalty. However it should be changed to usual reconciliation mechanism after CMO performance
			// issues are solved.
			for _, a := range d.Spec.Template.Spec.Containers[i].Command {
				if !strings.HasPrefix(a, "--match=") {
					cmd = append(cmd, a)
				}
			}
			for _, m := range f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.TelemetryMatches {
				cmd = append(cmd, fmt.Sprintf("--match=%s", m))
			}
			cmd = append(cmd, "--limit-bytes=5242880")
			d.Spec.Template.Spec.Containers[i].Command = cmd

			if proxyCABundleCM != nil {
				volumeName := "telemeter-trusted-ca-bundle"
				d.Spec.Template.Spec.Containers[i].VolumeMounts = append(d.Spec.Template.Spec.Containers[i].VolumeMounts, trustedCABundleVolumeMount(volumeName))
				volume := trustedCABundleVolume(proxyCABundleCM.Name, volumeName)
				volume.VolumeSource.ConfigMap.Items = append(volume.VolumeSource.ConfigMap.Items, v1.KeyToPath{
					Key:  TrustedCABundleKey,
					Path: "tls-ca-bundle.pem",
				})
				d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, volume)
			}

		case "reload":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.PrometheusConfigReloader
		case "kube-rbac-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
		}
	}

	if len(f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.NodeSelector) > 0 {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.NodeSelector
	}
	if len(f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Tolerations
	}
	d.Namespace = f.namespace
	return d, nil
}

// TelemeterClientService generates a new Service for Telemeter client.
func (f *Factory) TelemeterClientService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(TelemeterClientService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

// TelemeterClientServiceAccount generates a new ServiceAccount for Telemeter client.
func (f *Factory) TelemeterClientServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(TelemeterClientServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

// TelemeterClientSecret generates a new Secret for Telemeter client.
func (f *Factory) TelemeterClientSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(TelemeterClientSecret))
	if err != nil {
		return nil, err
	}

	salt, err := GeneratePassword(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Telemeter client salt: %v", err)
	}
	s.Data["salt"] = []byte(salt)

	if f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Token != "" {
		s.Data["token"] = []byte(f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Token)
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ThanosRulerService() (*v1.Service, error) {
	s, err := f.NewService(f.assets.MustNewAssetReader(ThanosRulerService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) ThanosRulerServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(f.assets.MustNewAssetReader(ThanosRulerServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) ThanosRulerClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(ThanosRulerClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespaceUserWorkload

	return crb, nil
}

func (f *Factory) ThanosRulerMonitoringClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(f.assets.MustNewAssetReader(ThanosRulerMonitoringClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespaceUserWorkload

	return crb, nil
}

func (f *Factory) ThanosRulerClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(ThanosRulerClusterRole))
}

func (f *Factory) ThanosRulerPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(ThanosRulerPrometheusRule))
}

func (f *Factory) ThanosRulerServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetReader(ThanosRulerServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("thanos-ruler.%s.svc", f.namespaceUserWorkload)
	sm.Namespace = f.namespaceUserWorkload

	return sm, nil
}

func (f *Factory) ThanosRulerRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(f.assets.MustNewAssetReader(ThanosRulerRoute))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespaceUserWorkload

	return r, nil
}

func (f *Factory) ThanosRulerTrustedCABundle() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(f.assets.MustNewAssetReader(ThanosRulerTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func (f *Factory) ThanosRulerGrpcTLSSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(ThanosRulerGrpcTLSSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) ThanosRulerOauthCookieSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(ThanosRulerOauthCookieSecret))
	if err != nil {
		return nil, err
	}

	p, err := GeneratePassword(43)
	if err != nil {
		return nil, err
	}
	s.Data["session_secret"] = []byte(p)
	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) ThanosRulerCustomResource(queryURL string, trustedCA *v1.ConfigMap, grpcTLS *v1.Secret) (*monv1.ThanosRuler, error) {
	t, err := f.NewThanosRuler(f.assets.MustNewAssetReader(ThanosRulerCustomResource))
	if err != nil {
		return nil, err
	}

	t.Spec.Image = f.config.Images.Thanos

	if f.config.UserWorkloadConfiguration.ThanosRuler.LogLevel != "" {
		t.Spec.LogLevel = f.config.UserWorkloadConfiguration.ThanosRuler.LogLevel
	}

	if f.config.UserWorkloadConfiguration.ThanosRuler.Resources != nil {
		t.Spec.Resources = *f.config.UserWorkloadConfiguration.ThanosRuler.Resources
	}

	if f.config.UserWorkloadConfiguration.ThanosRuler.VolumeClaimTemplate != nil {
		t.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *f.config.UserWorkloadConfiguration.ThanosRuler.VolumeClaimTemplate,
		}
	}

	if f.config.UserWorkloadConfiguration.ThanosRuler.NodeSelector != nil {
		t.Spec.NodeSelector = f.config.UserWorkloadConfiguration.ThanosRuler.NodeSelector
	}

	if len(f.config.UserWorkloadConfiguration.ThanosRuler.Tolerations) > 0 {
		t.Spec.Tolerations = f.config.UserWorkloadConfiguration.ThanosRuler.Tolerations
	}

	for i, container := range t.Spec.Containers {
		switch container.Name {
		case "thanos-ruler-proxy":
			t.Spec.Containers[i].Image = f.config.Images.OauthProxy

			f.injectProxyVariables(&t.Spec.Containers[i])

			if trustedCA != nil {
				volumeName := "thanos-ruler-trusted-ca-bundle"
				t.Spec.Containers[i].VolumeMounts = append(
					t.Spec.Containers[i].VolumeMounts,
					trustedCABundleVolumeMount(volumeName),
				)

				volume := trustedCABundleVolume(trustedCA.Name, volumeName)
				volume.VolumeSource.ConfigMap.Items = append(volume.VolumeSource.ConfigMap.Items, v1.KeyToPath{
					Key:  TrustedCABundleKey,
					Path: "tls-ca-bundle.pem",
				})
				t.Spec.Volumes = append(t.Spec.Volumes, volume)
			}
		}
	}

	// Mounting TLS secret to thanos-ruler
	if grpcTLS == nil {
		return nil, errors.New("could not generate thanos ruler CRD: GRPC TLS secret was not found")
	}
	secretName := "secret-grpc-tls"
	secretVolume := v1.Volume{
		Name: secretName,
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: grpcTLS.GetName(),
			},
		},
	}
	t.Spec.Volumes = append(t.Spec.Volumes, secretVolume)

	if queryURL != "" {
		t.Spec.AlertQueryURL = queryURL
	}

	t.Namespace = f.namespaceUserWorkload

	return t, nil
}

func NewDaemonSet(manifest io.Reader) (*appsv1.DaemonSet, error) {
	ds := appsv1.DaemonSet{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&ds)
	if err != nil {
		return nil, err
	}

	return &ds, nil
}

func NewPodDisruptionBudget(manifest io.Reader) (*policyv1.PodDisruptionBudget, error) {
	pdb := policyv1.PodDisruptionBudget{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&pdb)
	if err != nil {
		return nil, err
	}

	return &pdb, nil
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

func NewClusterRoleBinding(manifest io.Reader) (*rbacv1.ClusterRoleBinding, error) {
	crb := rbacv1.ClusterRoleBinding{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&crb)
	if err != nil {
		return nil, err
	}

	return &crb, nil
}

func NewClusterRole(manifest io.Reader) (*rbacv1.ClusterRole, error) {
	cr := rbacv1.ClusterRole{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&cr)
	if err != nil {
		return nil, err
	}

	return &cr, nil
}

func NewRoleBinding(manifest io.Reader) (*rbacv1.RoleBinding, error) {
	rb := rbacv1.RoleBinding{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&rb)
	if err != nil {
		return nil, err
	}

	return &rb, nil
}

func NewRole(manifest io.Reader) (*rbacv1.Role, error) {
	r := rbacv1.Role{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func NewRoleBindingList(manifest io.Reader) (*rbacv1.RoleBindingList, error) {
	rbl := rbacv1.RoleBindingList{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&rbl)
	if err != nil {
		return nil, err
	}

	return &rbl, nil
}

func NewRoleList(manifest io.Reader) (*rbacv1.RoleList, error) {
	rl := rbacv1.RoleList{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&rl)
	if err != nil {
		return nil, err
	}

	return &rl, nil
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

func NewThanosRuler(manifest io.Reader) (*monv1.ThanosRuler, error) {
	t := monv1.ThanosRuler{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&t)
	if err != nil {
		return nil, err
	}

	return &t, nil
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

func NewAPIService(manifest io.Reader) (*apiregistrationv1.APIService, error) {
	s := apiregistrationv1.APIService{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&s)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func NewSecurityContextConstraints(manifest io.Reader) (*securityv1.SecurityContextConstraints, error) {
	s := securityv1.SecurityContextConstraints{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&s)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func NewValidatingWebhook(manifest io.Reader) (*admissionv1.ValidatingWebhookConfiguration, error) {
	v := admissionv1.ValidatingWebhookConfiguration{}
	err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

// HashTrustedCA synthesizes a configmap just by copying "ca-bundle.crt" from the given configmap
// and naming it by hashing the contents of "ca-bundle.crt".
// It adds "monitoring.openshift.io/name" and "monitoring.openshift.io/hash" labels.
// Any other labels from the given configmap are discarded.
//
// It returns an error if the given configmap does not contain the "ca-bundle.crt" data key
// or data is empty string.
func (f *Factory) HashTrustedCA(caBundleCM *v1.ConfigMap, prefix string) (*v1.ConfigMap, error) {
	caBundle, ok := caBundleCM.Data[TrustedCABundleKey]
	if !ok {
		return nil, errors.Errorf("CA bundle key %q missing", TrustedCABundleKey)
	}
	if caBundle == "" {
		return nil, errors.Errorf("CA bundle key %q empty", TrustedCABundleKey)
	}

	h := fnv.New64()
	h.Write([]byte(caBundle))
	hash := strconv.FormatUint(h.Sum64(), 32)

	ns := f.namespace
	if caBundleCM.ObjectMeta.Namespace != "" {
		ns = caBundleCM.ObjectMeta.Namespace
	}

	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      fmt.Sprintf("%s-trusted-ca-bundle-%s", prefix, hash),
			Labels: map[string]string{
				"monitoring.openshift.io/name": prefix,
				"monitoring.openshift.io/hash": hash,
			},
		},
		Data: map[string]string{
			TrustedCABundleKey: caBundle,
		},
	}, nil
}

// HashSecret synthesizes a secret by setting the given data
// and naming it by hashing the values of the given data.
//
// For simplicity, data is expected to be given in a key-value format,
// i.e. HashSecret(someSecret, value1, key1, value2, key2, ...).
//
// It adds "monitoring.openshift.io/name" and "monitoring.openshift.io/hash" labels.
// Any other labels from the given secret are discarded.
//
// It still returns a secret if the given secret does not contain any data.
func (f *Factory) HashSecret(secret *v1.Secret, data ...string) (*v1.Secret, error) {
	h := fnv.New64()
	m := make(map[string][]byte)

	var err error
	for i := 0; i < len(data)/2; i++ {
		k := data[i*2]
		v := []byte(data[i*2+1])
		_, err = h.Write(v)
		m[k] = v
	}
	if err != nil {
		return nil, errors.Wrap(err, "error hashing tls data")
	}
	hash := strconv.FormatUint(h.Sum64(), 32)

	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: secret.GetNamespace(),
			Name:      fmt.Sprintf("%s-%s", secret.GetName(), hash),
			Labels: map[string]string{
				"monitoring.openshift.io/name": secret.GetName(),
				"monitoring.openshift.io/hash": hash,
			},
		},
		Data: m,
	}, nil
}

func trustedCABundleVolumeMount(name string) v1.VolumeMount {
	return v1.VolumeMount{
		Name:      name,
		ReadOnly:  true,
		MountPath: "/etc/pki/ca-trust/extracted/pem/",
	}
}

func trustedCABundleVolume(configMapName, volumeName string) v1.Volume {
	yes := true

	return v1.Volume{
		Name: volumeName,
		VolumeSource: v1.VolumeSource{
			ConfigMap: &v1.ConfigMapVolumeSource{
				LocalObjectReference: v1.LocalObjectReference{
					Name: configMapName,
				},
				Optional: &yes,
			},
		},
	}
}
