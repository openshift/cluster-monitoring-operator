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

	monv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	securityv1 "github.com/openshift/api/security/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/promqlgen"
	"github.com/pkg/errors"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/yaml"
	apiregistrationv1beta1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

const (
	configManagedNamespace = "openshift-config-managed"
	sharedConfigMap        = "monitoring-shared-config"
)

var (
	AlertmanagerConfig             = "assets/alertmanager/secret.yaml"
	AlertmanagerService            = "assets/alertmanager/service.yaml"
	AlertmanagerProxySecret        = "assets/alertmanager/proxy-secret.yaml"
	AlertmanagerMain               = "assets/alertmanager/alertmanager.yaml"
	AlertmanagerServiceAccount     = "assets/alertmanager/service-account.yaml"
	AlertmanagerClusterRoleBinding = "assets/alertmanager/cluster-role-binding.yaml"
	AlertmanagerClusterRole        = "assets/alertmanager/cluster-role.yaml"
	AlertmanagerRBACProxySecret    = "assets/alertmanager/kube-rbac-proxy-secret.yaml"
	AlertmanagerRoute              = "assets/alertmanager/route.yaml"
	AlertmanagerServiceMonitor     = "assets/alertmanager/service-monitor.yaml"
	AlertmanagerTrustedCABundle    = "assets/alertmanager/trusted-ca-bundle.yaml"

	KubeStateMetricsClusterRoleBinding = "assets/kube-state-metrics/cluster-role-binding.yaml"
	KubeStateMetricsClusterRole        = "assets/kube-state-metrics/cluster-role.yaml"
	KubeStateMetricsDeployment         = "assets/kube-state-metrics/deployment.yaml"
	KubeStateMetricsServiceAccount     = "assets/kube-state-metrics/service-account.yaml"
	KubeStateMetricsService            = "assets/kube-state-metrics/service.yaml"
	KubeStateMetricsServiceMonitor     = "assets/kube-state-metrics/service-monitor.yaml"

	OpenShiftStateMetricsClusterRoleBinding = "assets/openshift-state-metrics/cluster-role-binding.yaml"
	OpenShiftStateMetricsClusterRole        = "assets/openshift-state-metrics/cluster-role.yaml"
	OpenShiftStateMetricsDeployment         = "assets/openshift-state-metrics/deployment.yaml"
	OpenShiftStateMetricsServiceAccount     = "assets/openshift-state-metrics/service-account.yaml"
	OpenShiftStateMetricsService            = "assets/openshift-state-metrics/service.yaml"
	OpenShiftStateMetricsServiceMonitor     = "assets/openshift-state-metrics/service-monitor.yaml"

	NodeExporterDaemonSet                  = "assets/node-exporter/daemonset.yaml"
	NodeExporterService                    = "assets/node-exporter/service.yaml"
	NodeExporterServiceAccount             = "assets/node-exporter/service-account.yaml"
	NodeExporterClusterRole                = "assets/node-exporter/cluster-role.yaml"
	NodeExporterClusterRoleBinding         = "assets/node-exporter/cluster-role-binding.yaml"
	NodeExporterSecurityContextConstraints = "assets/node-exporter/security-context-constraints.yaml"
	NodeExporterServiceMonitor             = "assets/node-exporter/service-monitor.yaml"

	PrometheusK8sClusterRoleBinding       = "assets/prometheus-k8s/cluster-role-binding.yaml"
	PrometheusK8sRoleBindingConfig        = "assets/prometheus-k8s/role-binding-config.yaml"
	PrometheusK8sRoleBindingList          = "assets/prometheus-k8s/role-binding-specific-namespaces.yaml"
	PrometheusK8sClusterRole              = "assets/prometheus-k8s/cluster-role.yaml"
	PrometheusK8sRoleConfig               = "assets/prometheus-k8s/role-config.yaml"
	PrometheusK8sRoleList                 = "assets/prometheus-k8s/role-specific-namespaces.yaml"
	PrometheusK8sRules                    = "assets/prometheus-k8s/rules.yaml"
	PrometheusK8sServiceAccount           = "assets/prometheus-k8s/service-account.yaml"
	PrometheusK8s                         = "assets/prometheus-k8s/prometheus.yaml"
	PrometheusK8sKubeletServiceMonitor    = "assets/prometheus-k8s/service-monitor-kubelet.yaml"
	PrometheusK8sPrometheusServiceMonitor = "assets/prometheus-k8s/service-monitor.yaml"
	PrometheusK8sService                  = "assets/prometheus-k8s/service.yaml"
	PrometheusK8sProxySecret              = "assets/prometheus-k8s/proxy-secret.yaml"
	PrometheusRBACProxySecret             = "assets/prometheus-k8s/kube-rbac-proxy-secret.yaml"
	PrometheusK8sRoute                    = "assets/prometheus-k8s/route.yaml"
	PrometheusK8sHtpasswd                 = "assets/prometheus-k8s/htpasswd-secret.yaml"
	PrometheusK8sEtcdServiceMonitor       = "assets/prometheus-k8s/service-monitor-etcd.yaml"
	PrometheusK8sServingCertsCABundle     = "assets/prometheus-k8s/serving-certs-ca-bundle.yaml"
	PrometheusK8sKubeletServingCABundle   = "assets/prometheus-k8s/kubelet-serving-ca-bundle.yaml"
	PrometheusK8sGrpcTLSSecret            = "assets/prometheus-k8s/grpc-tls-secret.yaml"
	PrometheusK8sTrustedCABundle          = "assets/prometheus-k8s/trusted-ca-bundle.yaml"

	PrometheusUserWorkloadServingCertsCABundle     = "assets/prometheus-user-workload/serving-certs-ca-bundle.yaml"
	PrometheusUserWorkloadServiceAccount           = "assets/prometheus-user-workload/service-account.yaml"
	PrometheusUserWorkloadClusterRole              = "assets/prometheus-user-workload/cluster-role.yaml"
	PrometheusUserWorkloadClusterRoleBinding       = "assets/prometheus-user-workload/cluster-role-binding.yaml"
	PrometheusUserWorkloadRoleConfig               = "assets/prometheus-user-workload/role-config.yaml"
	PrometheusUserWorkloadRoleList                 = "assets/prometheus-user-workload/role-specific-namespaces.yaml"
	PrometheusUserWorkloadRoleBindingList          = "assets/prometheus-user-workload/role-binding-specific-namespaces.yaml"
	PrometheusUserWorkloadRoleBindingConfig        = "assets/prometheus-user-workload/role-binding-config.yaml"
	PrometheusUserWorkloadService                  = "assets/prometheus-user-workload/service.yaml"
	PrometheusUserWorkload                         = "assets/prometheus-user-workload/prometheus.yaml"
	PrometheusUserWorkloadPrometheusServiceMonitor = "assets/prometheus-user-workload/service-monitor.yaml"
	PrometheusUserWorkloadGrpcTLSSecret            = "assets/prometheus-user-workload/grpc-tls-secret.yaml"

	PrometheusAdapterAPIService                         = "assets/prometheus-adapter/api-service.yaml"
	PrometheusAdapterClusterRole                        = "assets/prometheus-adapter/cluster-role.yaml"
	PrometheusAdapterClusterRoleBinding                 = "assets/prometheus-adapter/cluster-role-binding.yaml"
	PrometheusAdapterClusterRoleBindingDelegator        = "assets/prometheus-adapter/cluster-role-binding-delegator.yaml"
	PrometheusAdapterClusterRoleBindingView             = "assets/prometheus-adapter/cluster-role-binding-view.yaml"
	PrometheusAdapterClusterRoleServerResources         = "assets/prometheus-adapter/cluster-role-server-resources.yaml"
	PrometheusAdapterClusterRoleAggregatedMetricsReader = "assets/prometheus-adapter/cluster-role-aggregated-metrics-reader.yaml"
	PrometheusAdapterConfigMap                          = "assets/prometheus-adapter/config-map.yaml"
	PrometheusAdapterConfigMapPrometheus                = "assets/prometheus-adapter/configmap-prometheus.yaml"
	PrometheusAdapterDeployment                         = "assets/prometheus-adapter/deployment.yaml"
	PrometheusAdapterRoleBindingAuthReader              = "assets/prometheus-adapter/role-binding-auth-reader.yaml"
	PrometheusAdapterService                            = "assets/prometheus-adapter/service.yaml"
	PrometheusAdapterServiceAccount                     = "assets/prometheus-adapter/service-account.yaml"

	PrometheusOperatorClusterRoleBinding    = "assets/prometheus-operator/cluster-role-binding.yaml"
	PrometheusOperatorClusterRole           = "assets/prometheus-operator/cluster-role.yaml"
	PrometheusOperatorServiceAccount        = "assets/prometheus-operator/service-account.yaml"
	PrometheusOperatorDeployment            = "assets/prometheus-operator/deployment.yaml"
	PrometheusOperatorService               = "assets/prometheus-operator/service.yaml"
	PrometheusOperatorServiceMonitor        = "assets/prometheus-operator/service-monitor.yaml"
	PrometheusOperatorCertsCABundle         = "assets/prometheus-operator/operator-certs-ca-bundle.yaml"
	PrometheusOperatorRuleValidatingWebhook = "assets/prometheus-operator/prometheus-rule-validating-webhook.yaml"

	PrometheusOperatorUserWorkloadServiceAccount     = "assets/prometheus-operator-user-workload/service-account.yaml"
	PrometheusOperatorUserWorkloadClusterRole        = "assets/prometheus-operator-user-workload/cluster-role.yaml"
	PrometheusOperatorUserWorkloadClusterRoleBinding = "assets/prometheus-operator-user-workload/cluster-role-binding.yaml"
	PrometheusOperatorUserWorkloadService            = "assets/prometheus-operator-user-workload/service.yaml"
	PrometheusOperatorUserWorkloadDeployment         = "assets/prometheus-operator-user-workload/deployment.yaml"
	PrometheusOperatorUserWorkloadServiceMonitor     = "assets/prometheus-operator-user-workload/service-monitor.yaml"

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
	GrafanaServiceMonitor       = "assets/grafana/service-monitor.yaml"
	GrafanaTrustedCABundle      = "assets/grafana/trusted-ca-bundle.yaml"

	ClusterMonitoringOperatorService            = "assets/cluster-monitoring-operator/service.yaml"
	ClusterMonitoringOperatorServiceMonitor     = "assets/cluster-monitoring-operator/service-monitor.yaml"
	ClusterMonitoringClusterRole                = "assets/cluster-monitoring-operator/cluster-role.yaml"
	ClusterMonitoringRulesEditClusterRole       = "assets/cluster-monitoring-operator/monitoring-rules-edit-cluster-role.yaml"
	ClusterMonitoringRulesViewClusterRole       = "assets/cluster-monitoring-operator/monitoring-rules-view-cluster-role.yaml"
	ClusterMonitoringEditClusterRole            = "assets/cluster-monitoring-operator/monitoring-edit-cluster-role.yaml"
	ClusterMonitoringEditUserWorkloadConfigRole = "assets/cluster-monitoring-operator/user-workload-config-edit-role.yaml"
	ClusterMonitoringGrpcTLSSecret              = "assets/cluster-monitoring-operator/grpc-tls-secret.yaml"

	TelemeterClientClusterRole            = "assets/telemeter-client/cluster-role.yaml"
	TelemeterClientClusterRoleBinding     = "assets/telemeter-client/cluster-role-binding.yaml"
	TelemeterClientClusterRoleBindingView = "assets/telemeter-client/cluster-role-binding-view.yaml"
	TelemeterClientDeployment             = "assets/telemeter-client/deployment.yaml"
	TelemeterClientSecret                 = "assets/telemeter-client/secret.yaml"
	TelemeterClientService                = "assets/telemeter-client/service.yaml"
	TelemeterClientServiceAccount         = "assets/telemeter-client/service-account.yaml"
	TelemeterClientServiceMonitor         = "assets/telemeter-client/service-monitor.yaml"
	TelemeterClientServingCertsCABundle   = "assets/telemeter-client/serving-certs-c-a-bundle.yaml"

	ThanosQuerierDeployment           = "assets/thanos-querier/deployment.yaml"
	ThanosQuerierService              = "assets/thanos-querier/service.yaml"
	ThanosQuerierServiceMonitor       = "assets/thanos-querier/service-monitor.yaml"
	ThanosQuerierPrometheusRule       = "assets/thanos-querier/prometheus-rule.yaml"
	ThanosQuerierRoute                = "assets/thanos-querier/route.yaml"
	ThanosQuerierOauthCookieSecret    = "assets/thanos-querier/oauth-cookie-secret.yaml"
	ThanosQuerierHtpasswdSecret       = "assets/thanos-querier/oauth-htpasswd-secret.yaml"
	ThanosQuerierRBACProxySecret      = "assets/thanos-querier/kube-rbac-proxy-secret.yaml"
	ThanosQuerierRBACProxyRulesSecret = "assets/thanos-querier/kube-rbac-proxy-rules-secret.yaml"
	ThanosQuerierServiceAccount       = "assets/thanos-querier/service-account.yaml"
	ThanosQuerierClusterRole          = "assets/thanos-querier/cluster-role.yaml"
	ThanosQuerierClusterRoleBinding   = "assets/thanos-querier/cluster-role-binding.yaml"
	ThanosQuerierGrpcTLSSecret        = "assets/thanos-querier/grpc-tls-secret.yaml"
	ThanosQuerierTrustedCABundle      = "assets/thanos-querier/trusted-ca-bundle.yaml"

	ThanosRulerCustomResource               = "assets/thanos-ruler/thanos-ruler.yaml"
	ThanosRulerService                      = "assets/thanos-ruler/service.yaml"
	ThanosRulerRoute                        = "assets/thanos-ruler/route.yaml"
	ThanosRulerOauthCookieSecret            = "assets/thanos-ruler/oauth-cookie-secret.yaml"
	ThanosRulerHtpasswdSecret               = "assets/thanos-ruler/oauth-htpasswd-secret.yaml"
	ThanosRulerQueryConfigSecret            = "assets/thanos-ruler/query-config-secret.yaml"
	ThanosRulerAlertmanagerConfigSecret     = "assets/thanos-ruler/alertmanagers-config-secret.yaml"
	ThanosRulerServiceAccount               = "assets/thanos-ruler/service-account.yaml"
	ThanosRulerClusterRole                  = "assets/thanos-ruler/cluster-role.yaml"
	ThanosRulerClusterRoleBinding           = "assets/thanos-ruler/cluster-role-binding.yaml"
	ThanosRulerMonitoringClusterRoleBinding = "assets/thanos-ruler/cluster-role-binding-monitoring.yaml"
	ThanosRulerGrpcTLSSecret                = "assets/thanos-ruler/grpc-tls-secret.yaml"
	ThanosRulerTrustedCABundle              = "assets/thanos-ruler/trusted-ca-bundle.yaml"
	ThanosRulerServiceMonitor               = "assets/thanos-ruler/service-monitor.yaml"
	ThanosRulerPrometheusRule               = "assets/thanos-ruler/thanos-ruler-prometheus-rule.yaml"

	TelemeterTrustedCABundle = "assets/telemeter-client/trusted-ca-bundle.yaml"
)

var (
	PrometheusConfigReloaderFlag                         = "--prometheus-config-reloader="
	ConfigReloaderImageFlag                              = "--config-reloader-image="
	PrometheusOperatorNamespaceFlag                      = "--namespaces="
	PrometheusOperatorDenyNamespaceFlag                  = "--deny-namespaces="
	PrometheusOperatorPrometheusInstanceNamespacesFlag   = "--prometheus-instance-namespaces="
	PrometheusOperatorAlertmanagerInstanceNamespacesFlag = "--alertmanager-instance-namespaces="

	AuthProxyExternalURLFlag  = "-external-url="
	AuthProxyCookieDomainFlag = "-cookie-domain="
	AuthProxyRedirectURLFlag  = "-redirect-url="

	TrustedCABundleKey = "ca-bundle.crt"
)

const (
	IBMCloudPlatformType configv1.PlatformType = "IBMCloud"
)

func MustAssetReader(asset string) io.Reader {
	return bytes.NewReader(MustAsset(asset))
}

type Factory struct {
	namespace, namespaceUserWorkload string
	config                           *Config
}

func NewFactory(namespace, namespaceUserWorkload string, c *Config) *Factory {
	return &Factory{
		namespace:             namespace,
		namespaceUserWorkload: namespaceUserWorkload,
		config:                c,
	}
}

func (f *Factory) PrometheusExternalURL(host string) *url.URL {
	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Hostport != "" {
		host = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Hostport
	}

	return &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/",
	}
}

func (f *Factory) AlertmanagerExternalURL(host string) *url.URL {
	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Hostport != "" {
		host = f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Hostport
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

func (f *Factory) AlertmanagerClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(AlertmanagerClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) AlertmanagerClusterRole() (*rbacv1.ClusterRole, error) {
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

func (f *Factory) AlertmanagerTrustedCABundle() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(MustAssetReader(AlertmanagerTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func (f *Factory) AlertmanagerMain(host string, trustedCABundleCM *v1.ConfigMap) (*monv1.Alertmanager, error) {
	a, err := f.NewAlertmanager(MustAssetReader(AlertmanagerMain))
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

	setEnv := func(container *v1.Container, name, value string) {
		for i := range container.Env {
			if container.Env[i].Name == name {
				container.Env[i].Value = value
				break
			}
		}
	}
	for i, c := range a.Spec.Containers {
		switch c.Name {
		case "alertmanager-proxy":
			a.Spec.Containers[i].Image = f.config.Images.OauthProxy

			if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy != "" {
				setEnv(&a.Spec.Containers[i], "HTTP_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy)
			}
			if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy != "" {
				setEnv(&a.Spec.Containers[i], "HTTPS_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy)
			}
			if f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy != "" {
				setEnv(&a.Spec.Containers[i], "NO_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy)
			}

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
	s, err := f.NewSecret(MustAssetReader(AlertmanagerRBACProxySecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) AlertmanagerRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(MustAssetReader(AlertmanagerRoute))
	if err != nil {
		return nil, err
	}

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Hostport != "" {
		r.Spec.Host = f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Hostport
	}
	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) KubeStateMetricsClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(KubeStateMetricsClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) KubeStateMetricsClusterRole() (*rbacv1.ClusterRole, error) {
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

func (f *Factory) OpenShiftStateMetricsClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(OpenShiftStateMetricsClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) OpenShiftStateMetricsClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(OpenShiftStateMetricsClusterRole))
}

func (f *Factory) OpenShiftStateMetricsServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(OpenShiftStateMetricsServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("openshift-state-metrics.%s.svc", f.namespace)
	sm.Spec.Endpoints[1].TLSConfig.ServerName = fmt.Sprintf("openshift-state-metrics.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
}

func (f *Factory) OpenShiftStateMetricsDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(MustAssetReader(OpenShiftStateMetricsDeployment))
	if err != nil {
		return nil, err
	}

	d.Spec.Template.Spec.Containers[0].Image = f.config.Images.KubeRbacProxy
	d.Spec.Template.Spec.Containers[1].Image = f.config.Images.KubeRbacProxy
	d.Spec.Template.Spec.Containers[2].Image = f.config.Images.OpenShiftStateMetrics

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
	s, err := f.NewServiceAccount(MustAssetReader(OpenShiftStateMetricsServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) OpenShiftStateMetricsService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(OpenShiftStateMetricsService))
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

	ds.Spec.Template.Spec.InitContainers[0].Image = f.config.Images.NodeExporter
	ds.Spec.Template.Spec.Containers[0].Image = f.config.Images.NodeExporter
	ds.Spec.Template.Spec.Containers[1].Image = f.config.Images.KubeRbacProxy

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

func (f *Factory) NodeExporterClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(NodeExporterClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) NodeExporterClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(NodeExporterClusterRole))
}

func (f *Factory) PrometheusK8sClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(PrometheusK8sClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) ThanosQuerierClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(ThanosQuerierClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusUserWorkloadClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(PrometheusUserWorkloadClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespaceUserWorkload

	return crb, nil
}

func (f *Factory) PrometheusK8sClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(PrometheusK8sClusterRole))
}

func (f *Factory) ThanosQuerierClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(ThanosQuerierClusterRole))
}

func (f *Factory) PrometheusUserWorkloadClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(PrometheusUserWorkloadClusterRole))
}

func (f *Factory) PrometheusK8sRoleConfig() (*rbacv1.Role, error) {
	r, err := f.NewRole(MustAssetReader(PrometheusK8sRoleConfig))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) PrometheusUserWorkloadRoleConfig() (*rbacv1.Role, error) {
	r, err := f.NewRole(MustAssetReader(PrometheusUserWorkloadRoleConfig))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespaceUserWorkload

	return r, nil
}

func (f *Factory) PrometheusK8sRoleBindingList() (*rbacv1.RoleBindingList, error) {
	rbl, err := f.NewRoleBindingList(MustAssetReader(PrometheusK8sRoleBindingList))
	if err != nil {
		return nil, err
	}

	for _, rb := range rbl.Items {
		rb.Subjects[0].Namespace = f.namespace
	}

	return rbl, nil
}

func (f *Factory) PrometheusUserWorkloadRoleBindingList() (*rbacv1.RoleBindingList, error) {
	rbl, err := f.NewRoleBindingList(MustAssetReader(PrometheusUserWorkloadRoleBindingList))
	if err != nil {
		return nil, err
	}

	for _, rb := range rbl.Items {
		rb.Subjects[0].Namespace = f.namespaceUserWorkload
	}

	return rbl, nil
}

func (f *Factory) PrometheusK8sRoleBindingConfig() (*rbacv1.RoleBinding, error) {
	rb, err := f.NewRoleBinding(MustAssetReader(PrometheusK8sRoleBindingConfig))
	if err != nil {
		return nil, err
	}

	rb.Namespace = f.namespace

	return rb, nil
}

func (f *Factory) PrometheusUserWorkloadRoleBindingConfig() (*rbacv1.RoleBinding, error) {
	rb, err := f.NewRoleBinding(MustAssetReader(PrometheusUserWorkloadRoleBindingConfig))
	if err != nil {
		return nil, err
	}

	rb.Namespace = f.namespaceUserWorkload

	return rb, nil
}

func (f *Factory) PrometheusK8sRoleList() (*rbacv1.RoleList, error) {
	rl, err := f.NewRoleList(MustAssetReader(PrometheusK8sRoleList))
	if err != nil {
		return nil, err
	}

	for _, r := range rl.Items {
		r.Namespace = f.namespace
	}

	return rl, nil
}

func (f *Factory) PrometheusUserWorkloadRoleList() (*rbacv1.RoleList, error) {
	rl, err := f.NewRoleList(MustAssetReader(PrometheusUserWorkloadRoleList))
	if err != nil {
		return nil, err
	}

	for _, r := range rl.Items {
		r.Namespace = f.namespaceUserWorkload
	}

	return rl, nil
}

func (f *Factory) PrometheusK8sRules() (*monv1.PrometheusRule, error) {
	r, err := f.NewPrometheusRule(MustAssetReader(PrometheusK8sRules))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespace

	if !f.config.ClusterMonitoringConfiguration.EtcdConfig.IsEnabled() {
		groups := []monv1.RuleGroup{}
		for _, g := range r.Spec.Groups {
			if g.Name != "etcd" {
				groups = append(groups, g)
			}
		}
		r.Spec.Groups = groups
	}

	if f.config.Platform == IBMCloudPlatformType {
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

func (f *Factory) PrometheusK8sServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(PrometheusK8sServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ThanosQuerierServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(ThanosQuerierServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusUserWorkloadServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(PrometheusUserWorkloadServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

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

func (f *Factory) PrometheusK8sGrpcTLSSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(PrometheusK8sGrpcTLSSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusUserWorkloadGrpcTLSSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(PrometheusUserWorkloadGrpcTLSSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) ThanosQuerierGrpcTLSSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(ThanosQuerierGrpcTLSSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ThanosQuerierOauthCookieSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(ThanosQuerierOauthCookieSecret))
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

	f.generateHtpasswdSecret(s, password)
	return s, nil
}

func (f *Factory) ThanosQuerierHtpasswdSecret(password string) (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(ThanosQuerierHtpasswdSecret))
	if err != nil {
		return nil, err
	}

	f.generateHtpasswdSecret(s, password)
	return s, nil
}

func (f *Factory) ThanosRulerHtpasswdSecret(password string) (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(ThanosRulerHtpasswdSecret))
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
	s, err := f.NewSecret(MustAssetReader(ThanosRulerQueryConfigSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload
	return s, nil
}

func (f *Factory) ThanosRulerAlertmanagerConfigSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(ThanosRulerAlertmanagerConfigSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload
	return s, nil
}

func (f *Factory) PrometheusRBACProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(PrometheusRBACProxySecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ThanosQuerierRBACProxySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(ThanosQuerierRBACProxySecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}
func (f *Factory) ThanosQuerierRBACProxyRulesSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(ThanosQuerierRBACProxyRulesSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sServingCertsCABundle() (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(MustAssetReader(PrometheusK8sServingCertsCABundle))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace

	return c, nil
}

func (f *Factory) PrometheusUserWorkloadServingCertsCABundle() (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(MustAssetReader(PrometheusUserWorkloadServingCertsCABundle))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespaceUserWorkload

	return c, nil
}

func (f *Factory) PrometheusK8sKubeletServingCABundle(data map[string]string) (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(MustAssetReader(PrometheusK8sKubeletServingCABundle))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace
	c.Data = data

	return c, nil
}

func (f *Factory) PrometheusOperatorCertsCABundle() (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(MustAssetReader(PrometheusOperatorCertsCABundle))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace

	return c, nil
}

func (f *Factory) PrometheusK8sEtcdServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sEtcdServiceMonitor))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusK8sEtcdSecret(tlsClient *v1.Secret, ca *v1.ConfigMap) (*v1.Secret, error) {
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

func (f *Factory) PrometheusK8sRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(MustAssetReader(PrometheusK8sRoute))
	if err != nil {
		return nil, err
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Hostport != "" {
		r.Spec.Host = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Hostport
	}
	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) ThanosQuerierRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(MustAssetReader(ThanosQuerierRoute))
	if err != nil {
		return nil, err
	}

	// apply hostport configuration to thanos
	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Hostport != "" {
		r.Spec.Host = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Hostport
	}
	r.Namespace = f.namespace

	return r, nil
}

func (f *Factory) SharingConfigDeprecated(promHost, amHost, grafanaHost, thanosHost *url.URL) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sharing-config",
			Namespace: f.namespace,
		},
		Data: map[string]string{
			"grafanaURL":      grafanaHost.String(),
			"prometheusURL":   promHost.String(),
			"alertmanagerURL": amHost.String(),
			"thanosURL":       thanosHost.String(),
		},
	}
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
	cm, err := f.NewConfigMap(MustAssetReader(PrometheusK8sTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

const (
	// These constants refer to indices of prometheus-k8s containers.
	// They need to be in sync with jsonnet/prometheus.jsonnet
	K8S_CONTAINER_OAUTH_PROXY      = 0
	K8S_CONTAINER_KUBE_RBAC_PROXY  = 1
	K8S_CONTAINER_PROM_LABEL_PROXY = 2
	K8S_CONTAINER_THANOS_SIDECAR   = 3
	K8S_CONTAINER_PROMETHEUS       = 4
)

func (f *Factory) PrometheusK8s(host string, grpcTLS *v1.Secret, trustedCABundleCM *v1.ConfigMap) (*monv1.Prometheus, error) {
	p, err := f.NewPrometheus(MustAssetReader(PrometheusK8s))
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
		if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy != "" {
			rw.ProxyURL = f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy
		}
		if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy != "" {
			rw.ProxyURL = f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy
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

	p.Spec.Containers[K8S_CONTAINER_OAUTH_PROXY].Image = f.config.Images.OauthProxy
	p.Spec.Containers[K8S_CONTAINER_KUBE_RBAC_PROXY].Image = f.config.Images.KubeRbacProxy
	p.Spec.Containers[K8S_CONTAINER_PROM_LABEL_PROXY].Image = f.config.Images.PromLabelProxy

	p.Spec.Alerting.Alertmanagers[0].Namespace = f.namespace
	p.Spec.Alerting.Alertmanagers[0].TLSConfig.ServerName = fmt.Sprintf("alertmanager-main.%s.svc", f.namespace)
	p.Namespace = f.namespace

	setEnv := func(name, value string) {
		for i := range p.Spec.Containers[K8S_CONTAINER_OAUTH_PROXY].Env {
			if p.Spec.Containers[K8S_CONTAINER_OAUTH_PROXY].Env[i].Name == name {
				p.Spec.Containers[K8S_CONTAINER_OAUTH_PROXY].Env[i].Value = value
				break
			}
		}
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy != "" {
		setEnv("HTTP_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy)
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy != "" {
		setEnv("HTTPS_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy)
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy != "" {
		setEnv("NO_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy)
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

		p.Spec.Containers[K8S_CONTAINER_OAUTH_PROXY].VolumeMounts = append(
			p.Spec.Containers[K8S_CONTAINER_OAUTH_PROXY].VolumeMounts,
			trustedCABundleVolumeMount(volumeName),
		)

		p.Spec.Containers[K8S_CONTAINER_PROMETHEUS].VolumeMounts = append(
			p.Spec.Containers[K8S_CONTAINER_PROMETHEUS].VolumeMounts,
			trustedCABundleVolumeMount(volumeName),
		)
	}

	return p, nil
}

func (f *Factory) PrometheusUserWorkload(grpcTLS *v1.Secret) (*monv1.Prometheus, error) {
	p, err := f.NewPrometheus(MustAssetReader(PrometheusUserWorkload))
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

	// TODO: remove after 4.7

	if f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.LogLevel != "" {
		p.Spec.LogLevel = f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.LogLevel
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.Retention != "" {
		p.Spec.Retention = f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.Retention
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.Resources != nil {
		p.Spec.Resources = *f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.Resources
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.NodeSelector != nil {
		p.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.Tolerations) > 0 {
		p.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.Tolerations
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.ExternalLabels != nil {
		p.Spec.ExternalLabels = f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.ExternalLabels
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.VolumeClaimTemplate != nil {
		p.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.VolumeClaimTemplate,
		}
	}
	if len(f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.RemoteWrite) > 0 {
		p.Spec.RemoteWrite = f.config.ClusterMonitoringConfiguration.PrometheusUserWorkloadConfig.RemoteWrite
	}
	// end removal
	if f.config.Images.Thanos != "" {
		p.Spec.Thanos.Image = &f.config.Images.Thanos
	}

	p.Spec.Containers[0].Image = f.config.Images.KubeRbacProxy
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

func (f *Factory) PrometheusK8sKubeletServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(MustAssetReader(PrometheusK8sKubeletServiceMonitor))
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

func (f *Factory) PrometheusUserWorkloadPrometheusServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(PrometheusUserWorkloadPrometheusServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-user-workload.%s.svc", f.namespaceUserWorkload)
	sm.Namespace = f.namespaceUserWorkload

	return sm, nil
}

func (f *Factory) PrometheusAdapterClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(PrometheusAdapterClusterRole))
}

func (f *Factory) PrometheusAdapterClusterRoleServerResources() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(PrometheusAdapterClusterRoleServerResources))
}

func (f *Factory) PrometheusAdapterClusterRoleAggregatedMetricsReader() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(PrometheusAdapterClusterRoleAggregatedMetricsReader))
}

func (f *Factory) PrometheusAdapterClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(PrometheusAdapterClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusAdapterClusterRoleBindingDelegator() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(PrometheusAdapterClusterRoleBindingDelegator))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusAdapterClusterRoleBindingView() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(PrometheusAdapterClusterRoleBindingView))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusAdapterRoleBindingAuthReader() (*rbacv1.RoleBinding, error) {
	rb, err := f.NewRoleBinding(MustAssetReader(PrometheusAdapterRoleBindingAuthReader))
	if err != nil {
		return nil, err
	}

	rb.Subjects[0].Namespace = f.namespace

	return rb, nil
}

func (f *Factory) PrometheusAdapterServiceAccount() (*v1.ServiceAccount, error) {
	sa, err := f.NewServiceAccount(MustAssetReader(PrometheusAdapterServiceAccount))
	if err != nil {
		return nil, err
	}

	sa.Namespace = f.namespace

	return sa, nil
}

func (f *Factory) PrometheusAdapterConfigMap() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(MustAssetReader(PrometheusAdapterConfigMap))
	if err != nil {
		return nil, err
	}

	cm.Namespace = f.namespace

	return cm, nil
}

func (f *Factory) PrometheusAdapterConfigMapPrometheus() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(MustAssetReader(PrometheusAdapterConfigMapPrometheus))
	if err != nil {
		return nil, err
	}

	cm.Namespace = f.namespace

	return cm, nil
}

func (f *Factory) PrometheusAdapterDeployment(apiAuthSecretName string, requestheader map[string]string) (*appsv1.Deployment, error) {
	dep, err := f.NewDeployment(MustAssetReader(PrometheusAdapterDeployment))
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

func (f *Factory) PrometheusAdapterService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(PrometheusAdapterService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
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

func (f *Factory) PrometheusAdapterAPIService() (*apiregistrationv1beta1.APIService, error) {
	return f.NewAPIService(MustAssetReader(PrometheusAdapterAPIService))
}

func (f *Factory) PrometheusOperatorServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(PrometheusOperatorServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Namespace = f.namespace
	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-operator.%s.svc", f.namespace)

	return sm, nil
}

func (f *Factory) PrometheusOperatorUserWorkloadServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(PrometheusOperatorUserWorkloadServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Namespace = f.namespaceUserWorkload
	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("prometheus-operator.%s.svc", f.namespaceUserWorkload)

	return sm, nil
}

func (f *Factory) PrometheusOperatorClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(PrometheusOperatorClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) PrometheusOperatorUserWorkloadClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(PrometheusOperatorUserWorkloadClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespaceUserWorkload

	return crb, nil
}

func (f *Factory) PrometheusOperatorClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(PrometheusOperatorClusterRole))
}

func (f *Factory) PrometheusOperatorUserWorkloadClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(PrometheusOperatorUserWorkloadClusterRole))
}

func (f *Factory) PrometheusOperatorServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(PrometheusOperatorServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusOperatorUserWorkloadServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(PrometheusOperatorUserWorkloadServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) PrometheusOperatorDeployment(namespaces []string) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(MustAssetReader(PrometheusOperatorDeployment))
	if err != nil {
		return nil, err
	}
	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.NodeSelector) > 0 {

		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Tolerations
	}

	d.Spec.Template.Spec.Containers[0].Image = f.config.Images.PrometheusOperator
	d.Spec.Template.Spec.Containers[1].Image = f.config.Images.KubeRbacProxy

	args := d.Spec.Template.Spec.Containers[0].Args
	for i := range args {
		if strings.HasPrefix(args[i], PrometheusOperatorNamespaceFlag) && len(namespaces) > 0 {
			args[i] = PrometheusOperatorNamespaceFlag + strings.Join(namespaces, ",")
		}

		if strings.HasPrefix(args[i], PrometheusConfigReloaderFlag) && f.config.Images.PrometheusConfigReloader != "" {
			args[i] = PrometheusConfigReloaderFlag + f.config.Images.PrometheusConfigReloader
		}

		if strings.HasPrefix(args[i], ConfigReloaderImageFlag) && f.config.Images.ConfigmapReloader != "" {
			args[i] = ConfigReloaderImageFlag + f.config.Images.ConfigmapReloader
		}

		if strings.HasPrefix(args[i], PrometheusOperatorAlertmanagerInstanceNamespacesFlag) && f.namespace != "" {
			args[i] = PrometheusOperatorAlertmanagerInstanceNamespacesFlag + f.namespace
		}

		if strings.HasPrefix(args[i], PrometheusOperatorPrometheusInstanceNamespacesFlag) && f.namespace != "" {
			args[i] = PrometheusOperatorPrometheusInstanceNamespacesFlag + f.namespace
		}
	}
	d.Spec.Template.Spec.Containers[0].Args = args
	d.Namespace = f.namespace

	return d, nil
}

func (f *Factory) PrometheusOperatorUserWorkloadDeployment(denyNamespaces []string) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(MustAssetReader(PrometheusOperatorUserWorkloadDeployment))
	if err != nil {
		return nil, err
	}
	if len(f.config.UserWorkloadConfiguration.PrometheusOperator.NodeSelector) > 0 {
		d.Spec.Template.Spec.NodeSelector = f.config.UserWorkloadConfiguration.PrometheusOperator.NodeSelector
	}

	if len(f.config.UserWorkloadConfiguration.PrometheusOperator.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.UserWorkloadConfiguration.PrometheusOperator.Tolerations
	}

	// TODO: remove in 4.7
	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorUserWorkloadConfig.NodeSelector) > 0 {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.PrometheusOperatorUserWorkloadConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorUserWorkloadConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.PrometheusOperatorUserWorkloadConfig.Tolerations
	}

	// end of remove

	d.Spec.Template.Spec.Containers[0].Image = f.config.Images.PrometheusOperator
	d.Spec.Template.Spec.Containers[1].Image = f.config.Images.KubeRbacProxy

	args := d.Spec.Template.Spec.Containers[0].Args
	for i := range args {
		if strings.HasPrefix(args[i], PrometheusOperatorDenyNamespaceFlag) {
			args[i] = PrometheusOperatorDenyNamespaceFlag + strings.Join(denyNamespaces, ",")
		}

		if strings.HasPrefix(args[i], PrometheusConfigReloaderFlag) {
			args[i] = PrometheusConfigReloaderFlag + f.config.Images.PrometheusConfigReloader
		}

		if strings.HasPrefix(args[i], ConfigReloaderImageFlag) {
			args[i] = ConfigReloaderImageFlag + f.config.Images.ConfigmapReloader
		}

		if strings.HasPrefix(args[i], PrometheusOperatorAlertmanagerInstanceNamespacesFlag) {
			args[i] = PrometheusOperatorAlertmanagerInstanceNamespacesFlag + f.namespaceUserWorkload
		}

		if strings.HasPrefix(args[i], PrometheusOperatorPrometheusInstanceNamespacesFlag) {
			args[i] = PrometheusOperatorPrometheusInstanceNamespacesFlag + f.namespaceUserWorkload
		}
	}
	d.Spec.Template.Spec.Containers[0].Args = args
	d.Namespace = f.namespaceUserWorkload

	return d, nil
}

func (f *Factory) PrometheusRuleValidatingWebhook() (*admissionv1.ValidatingWebhookConfiguration, error) {
	wc, err := f.NewValidatingWebhook(MustAssetReader(PrometheusOperatorRuleValidatingWebhook))
	if err != nil {
		return nil, err
	}
	return wc, nil
}

func (f *Factory) PrometheusOperatorService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(PrometheusOperatorService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) PrometheusOperatorUserWorkloadService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(PrometheusOperatorUserWorkloadService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

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

func (f *Factory) PrometheusUserWorkloadService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(PrometheusUserWorkloadService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) GrafanaClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(GrafanaClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespace

	return crb, nil
}

func (f *Factory) GrafanaClusterRole() (*rbacv1.ClusterRole, error) {
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
	cl, err := f.NewConfigMapList(MustAssetReader(GrafanaDashboardDefinitions))
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
	c, err := f.NewConfigMap(MustAssetReader(GrafanaDashboardSources))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace

	return c, nil
}

func (f *Factory) GrafanaTrustedCABundle() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(MustAssetReader(GrafanaTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

// GrafanaDeployment generates a new Deployment for Grafana.
// If the passed ConfigMap is not empty it mounts the Trusted CA Bundle as a VolumeMount to
// /etc/pki/ca-trust/extracted/pem/ location.
func (f *Factory) GrafanaDeployment(proxyCABundleCM *v1.ConfigMap) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(MustAssetReader(GrafanaDeployment))
	if err != nil {
		return nil, err
	}

	d.Spec.Template.Spec.Containers[0].Image = f.config.Images.Grafana

	if !f.config.ClusterMonitoringConfiguration.EtcdConfig.IsEnabled() {
		vols := []v1.Volume{}
		volMounts := []v1.VolumeMount{}
		for _, v := range d.Spec.Template.Spec.Volumes {
			if v.Name != "grafana-dashboard-etcd" {
				vols = append(vols, v)
			}
		}
		for _, vm := range d.Spec.Template.Spec.Containers[0].VolumeMounts {
			if vm.Name != "grafana-dashboard-etcd" {
				volMounts = append(volMounts, vm)
			}
		}

		d.Spec.Template.Spec.Volumes = vols
		d.Spec.Template.Spec.Containers[0].VolumeMounts = volMounts
	}

	d.Spec.Template.Spec.Containers[1].Image = f.config.Images.OauthProxy

	setEnv := func(name, value string) {
		for i := range d.Spec.Template.Spec.Containers[1].Env {
			if d.Spec.Template.Spec.Containers[1].Env[i].Name == name {
				d.Spec.Template.Spec.Containers[1].Env[i].Value = value
				break
			}
		}
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy != "" {
		setEnv("HTTP_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy)
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy != "" {
		setEnv("HTTPS_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy)
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy != "" {
		setEnv("NO_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy)
	}

	if f.config.ClusterMonitoringConfiguration.GrafanaConfig.NodeSelector != nil {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.GrafanaConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.GrafanaConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.GrafanaConfig.Tolerations
	}

	if proxyCABundleCM != nil {
		volumeName := "grafana-trusted-ca-bundle"
		d.Spec.Template.Spec.Containers[1].VolumeMounts = append(d.Spec.Template.Spec.Containers[1].VolumeMounts, trustedCABundleVolumeMount(volumeName))
		volume := trustedCABundleVolume(proxyCABundleCM.Name, volumeName)
		volume.VolumeSource.ConfigMap.Items = append(volume.VolumeSource.ConfigMap.Items, v1.KeyToPath{
			Key:  TrustedCABundleKey,
			Path: "tls-ca-bundle.pem",
		})
		d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, volume)
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

	if f.config.ClusterMonitoringConfiguration.GrafanaConfig.Hostport != "" {
		r.Spec.Host = f.config.ClusterMonitoringConfiguration.GrafanaConfig.Hostport
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

func (f *Factory) GrafanaServiceMonitor() (*monv1.ServiceMonitor, error) {
	s, err := f.NewServiceMonitor(MustAssetReader(GrafanaServiceMonitor))
	if err != nil {
		return nil, err
	}

	s.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("grafana.%s.svc", f.namespace)
	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ClusterMonitoringClusterRole() (*rbacv1.ClusterRole, error) {
	cr, err := f.NewClusterRole(MustAssetReader(ClusterMonitoringClusterRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func (f *Factory) ClusterMonitoringRulesEditClusterRole() (*rbacv1.ClusterRole, error) {
	cr, err := f.NewClusterRole(MustAssetReader(ClusterMonitoringRulesEditClusterRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func (f *Factory) ClusterMonitoringRulesViewClusterRole() (*rbacv1.ClusterRole, error) {
	cr, err := f.NewClusterRole(MustAssetReader(ClusterMonitoringRulesViewClusterRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func (f *Factory) ClusterMonitoringEditClusterRole() (*rbacv1.ClusterRole, error) {
	cr, err := f.NewClusterRole(MustAssetReader(ClusterMonitoringEditClusterRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func (f *Factory) ClusterMonitoringEditUserWorkloadConfigRole() (*rbacv1.Role, error) {
	cr, err := f.NewRole(MustAssetReader(ClusterMonitoringEditUserWorkloadConfigRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func (f *Factory) ClusterMonitoringOperatorService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(ClusterMonitoringOperatorService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ClusterMonitoringOperatorServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(ClusterMonitoringOperatorServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("cluster-monitoring-operator.%s.svc", f.namespace)
	sm.Namespace = f.namespace

	return sm, nil
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

func (f *Factory) NewAPIService(manifest io.Reader) (*apiregistrationv1beta1.APIService, error) {
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
	d, err := f.NewDeployment(MustAssetReader(ThanosQuerierDeployment))
	if err != nil {
		return nil, err
	}

	d.Namespace = f.namespace

	setEnv := func(container *v1.Container, name, value string) {
		for i := range container.Env {
			if container.Env[i].Name == name {
				container.Env[i].Value = value
				break
			}
		}
	}
	for i, c := range d.Spec.Template.Spec.Containers {
		switch c.Name {
		case "oauth-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.OauthProxy

			if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy != "" {
				setEnv(&d.Spec.Template.Spec.Containers[i], "HTTP_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy)
			}
			if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy != "" {
				setEnv(&d.Spec.Template.Spec.Containers[i], "HTTPS_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy)
			}
			if f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy != "" {
				setEnv(&d.Spec.Template.Spec.Containers[i], "NO_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy)
			}

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
	cm, err := f.NewConfigMap(MustAssetReader(ThanosQuerierTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func (f *Factory) ThanosQuerierService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(ThanosQuerierService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ThanosQuerierPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(MustAssetReader(ThanosQuerierPrometheusRule))
}

func (f *Factory) ThanosQuerierServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(ThanosQuerierServiceMonitor))
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
	cm, err := f.NewConfigMap(MustAssetReader(TelemeterTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

// TelemeterClientServingCertsCABundle generates a new servinc certs CA bundle ConfigMap for TelemeterClient.
func (f *Factory) TelemeterClientServingCertsCABundle() (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(MustAssetReader(TelemeterClientServingCertsCABundle))
	if err != nil {
		return nil, err
	}

	c.Namespace = f.namespace

	return c, nil
}

// TelemeterClientClusterRole generates a new ClusterRole for Telemeter client.
func (f *Factory) TelemeterClientClusterRole() (*rbacv1.ClusterRole, error) {
	cr, err := f.NewClusterRole(MustAssetReader(TelemeterClientClusterRole))
	if err != nil {
		return nil, err
	}

	return cr, nil
}

// TelemeterClientClusterRoleBinding generates a new ClusterRoleBinding for Telemeter client.
func (f *Factory) TelemeterClientClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(TelemeterClientClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	return crb, nil
}

// TelemeterClientClusterRoleBindingView generates a new ClusterRoleBinding for Telemeter client
// for the cluster monitoring view ClusterRole.
func (f *Factory) TelemeterClientClusterRoleBindingView() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(TelemeterClientClusterRoleBindingView))
	if err != nil {
		return nil, err
	}

	return crb, nil
}

// TelemeterClientServiceMonitor generates a new ServiceMonitor for Telemeter client.
func (f *Factory) TelemeterClientServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(TelemeterClientServiceMonitor))
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
	d, err := f.NewDeployment(MustAssetReader(TelemeterClientDeployment))
	if err != nil {
		return nil, err
	}

	setEnv := func(name, value string) {
		for i := range d.Spec.Template.Spec.Containers[0].Env {
			if d.Spec.Template.Spec.Containers[0].Env[i].Name == name {
				d.Spec.Template.Spec.Containers[0].Env[i].Value = value
				break
			}
		}
	}
	if f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID != "" {
		setEnv("ID", f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID)
	}
	if f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL != "" {
		setEnv("TO", f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL)
	}

	if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy != "" {
		setEnv("HTTP_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy)
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy != "" {
		setEnv("HTTPS_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy)
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy != "" {
		setEnv("NO_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy)
	}

	d.Spec.Template.Spec.Containers[0].Image = f.config.Images.TelemeterClient
	d.Spec.Template.Spec.Containers[1].Image = f.config.Images.ConfigmapReloader
	d.Spec.Template.Spec.Containers[2].Image = f.config.Images.KubeRbacProxy

	cmd := []string{}
	for _, a := range d.Spec.Template.Spec.Containers[0].Command {
		if !strings.HasPrefix(a, "--match=") {
			cmd = append(cmd, a)
		}
	}
	for _, m := range f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.TelemetryMatches {
		cmd = append(cmd, fmt.Sprintf("--match=%s", m))
	}
	cmd = append(cmd, "--limit-bytes=5242880")
	d.Spec.Template.Spec.Containers[0].Command = cmd

	if len(f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.NodeSelector) > 0 {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.NodeSelector
	}
	if len(f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Tolerations
	}
	d.Namespace = f.namespace
	if proxyCABundleCM != nil {
		volumeName := "telemeter-trusted-ca-bundle"
		d.Spec.Template.Spec.Containers[0].VolumeMounts = append(d.Spec.Template.Spec.Containers[0].VolumeMounts, trustedCABundleVolumeMount(volumeName))
		volume := trustedCABundleVolume(proxyCABundleCM.Name, volumeName)
		volume.VolumeSource.ConfigMap.Items = append(volume.VolumeSource.ConfigMap.Items, v1.KeyToPath{
			Key:  TrustedCABundleKey,
			Path: "tls-ca-bundle.pem",
		})
		d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, volume)
	}
	return d, nil
}

// TelemeterClientService generates a new Service for Telemeter client.
func (f *Factory) TelemeterClientService() (*v1.Service, error) {
	s, err := f.NewService(MustAssetReader(TelemeterClientService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

// TelemeterClientServiceAccount generates a new ServiceAccount for Telemeter client.
func (f *Factory) TelemeterClientServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(TelemeterClientServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace

	return s, nil
}

// TelemeterClientSecret generates a new Secret for Telemeter client.
func (f *Factory) TelemeterClientSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(TelemeterClientSecret))
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
	s, err := f.NewService(MustAssetReader(ThanosRulerService))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) ThanosRulerServiceAccount() (*v1.ServiceAccount, error) {
	s, err := f.NewServiceAccount(MustAssetReader(ThanosRulerServiceAccount))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) ThanosRulerClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(ThanosRulerClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespaceUserWorkload

	return crb, nil
}

func (f *Factory) ThanosRulerMonitoringClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	crb, err := f.NewClusterRoleBinding(MustAssetReader(ThanosRulerMonitoringClusterRoleBinding))
	if err != nil {
		return nil, err
	}

	crb.Subjects[0].Namespace = f.namespaceUserWorkload

	return crb, nil
}

func (f *Factory) ThanosRulerClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(MustAssetReader(ThanosRulerClusterRole))
}

func (f *Factory) ThanosRulerPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(MustAssetReader(ThanosRulerPrometheusRule))
}

func (f *Factory) ThanosRulerServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(MustAssetReader(ThanosRulerServiceMonitor))
	if err != nil {
		return nil, err
	}

	sm.Spec.Endpoints[0].TLSConfig.ServerName = fmt.Sprintf("thanos-ruler.%s.svc", f.namespaceUserWorkload)
	sm.Namespace = f.namespaceUserWorkload

	return sm, nil
}

func (f *Factory) ThanosRulerRoute() (*routev1.Route, error) {
	r, err := f.NewRoute(MustAssetReader(ThanosRulerRoute))
	if err != nil {
		return nil, err
	}

	r.Namespace = f.namespaceUserWorkload

	return r, nil
}

func (f *Factory) ThanosRulerTrustedCABundle() (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(MustAssetReader(ThanosRulerTrustedCABundle))
	if err != nil {
		return nil, err
	}

	return cm, nil
}

func (f *Factory) ThanosRulerGrpcTLSSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(ThanosRulerGrpcTLSSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload

	return s, nil
}

func (f *Factory) ThanosRulerOauthCookieSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(MustAssetReader(ThanosRulerOauthCookieSecret))
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
	t, err := f.NewThanosRuler(MustAssetReader(ThanosRulerCustomResource))
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

	// TODO: remove in 4.7
	if f.config.ClusterMonitoringConfiguration.ThanosRulerConfig.LogLevel != "" {
		t.Spec.LogLevel = f.config.ClusterMonitoringConfiguration.ThanosRulerConfig.LogLevel
	}

	if f.config.ClusterMonitoringConfiguration.ThanosRulerConfig.Resources != nil {
		t.Spec.Resources = *f.config.ClusterMonitoringConfiguration.ThanosRulerConfig.Resources
	}

	if f.config.ClusterMonitoringConfiguration.ThanosRulerConfig.VolumeClaimTemplate != nil {
		t.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *f.config.ClusterMonitoringConfiguration.ThanosRulerConfig.VolumeClaimTemplate,
		}
	}

	if f.config.ClusterMonitoringConfiguration.ThanosRulerConfig.NodeSelector != nil {
		t.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.ThanosRulerConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.ThanosRulerConfig.Tolerations) > 0 {
		t.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.ThanosRulerConfig.Tolerations
	}
	// end of remove

	t.Spec.Containers[1].Image = f.config.Images.OauthProxy
	setEnv := func(name, value string) {
		for i := range t.Spec.Containers[1].Env {
			if t.Spec.Containers[1].Env[i].Name == name {
				t.Spec.Containers[1].Env[i].Value = value
				break
			}
		}
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy != "" {
		setEnv("HTTP_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPProxy)
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy != "" {
		setEnv("HTTPS_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.HTTPSProxy)
	}
	if f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy != "" {
		setEnv("NO_PROXY", f.config.ClusterMonitoringConfiguration.HTTPConfig.NoProxy)
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

	if trustedCA != nil {
		volumeName := "thanos-ruler-trusted-ca-bundle"
		t.Spec.Containers[1].VolumeMounts = append(
			t.Spec.Containers[1].VolumeMounts,
			trustedCABundleVolumeMount(volumeName),
		)

		volume := trustedCABundleVolume(trustedCA.Name, volumeName)
		volume.VolumeSource.ConfigMap.Items = append(volume.VolumeSource.ConfigMap.Items, v1.KeyToPath{
			Key:  TrustedCABundleKey,
			Path: "tls-ca-bundle.pem",
		})
		t.Spec.Volumes = append(t.Spec.Volumes, volume)
	}

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

func NewAPIService(manifest io.Reader) (*apiregistrationv1beta1.APIService, error) {
	s := apiregistrationv1beta1.APIService{}
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
