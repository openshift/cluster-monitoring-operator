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
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	securityv1 "github.com/openshift/api/security/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/promqlgen"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/pkg/errors"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	yaml2 "gopkg.in/yaml.v2"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
)

const (
	configManagedNamespace = "openshift-config-managed"
	sharedConfigMap        = "monitoring-shared-config"

	htpasswdArg = "-htpasswd-file=/etc/proxy/htpasswd/auth"
	clientCAArg = "--client-ca-file=/etc/tls/client/client-ca.crt"

	tmpClusterIDLabelName = "__tmp_openshift_cluster_id__"

	nodeSelectorMaster = "node-role.kubernetes.io/master"

	platformAlertmanagerService     = "alertmanager-main"
	userWorkloadAlertmanagerService = "alertmanager-user-workload"

	telemetryTokenSecretKey = "token"
)

var (
	AlertmanagerConfig                = "alertmanager/secret.yaml"
	AlertmanagerService               = "alertmanager/service.yaml"
	AlertmanagerProxySecret           = "alertmanager/proxy-secret.yaml"
	AlertmanagerMain                  = "alertmanager/alertmanager.yaml"
	AlertmanagerServiceAccount        = "alertmanager/service-account.yaml"
	AlertmanagerClusterRoleBinding    = "alertmanager/cluster-role-binding.yaml"
	AlertmanagerClusterRole           = "alertmanager/cluster-role.yaml"
	AlertmanagerRBACProxySecret       = "alertmanager/kube-rbac-proxy-secret.yaml"
	AlertmanagerRBACProxyMetricSecret = "alertmanager/kube-rbac-proxy-metric-secret.yaml"
	AlertmanagerRoute                 = "alertmanager/route.yaml"
	AlertmanagerServiceMonitor        = "alertmanager/service-monitor.yaml"
	AlertmanagerTrustedCABundle       = "alertmanager/trusted-ca-bundle.yaml"
	AlertmanagerPrometheusRule        = "alertmanager/prometheus-rule.yaml"
	AlertmanagerPodDisruptionBudget   = "alertmanager/pod-disruption-budget.yaml"

	AlertmanagerUserWorkloadSecret                 = "alertmanager-user-workload/secret.yaml"
	AlertmanagerUserWorkloadService                = "alertmanager-user-workload/service.yaml"
	AlertmanagerUserWorkload                       = "alertmanager-user-workload/alertmanager.yaml"
	AlertmanagerUserWorkloadServiceAccount         = "alertmanager-user-workload/service-account.yaml"
	AlertmanagerUserWorkloadClusterRoleBinding     = "alertmanager-user-workload/cluster-role-binding.yaml"
	AlertmanagerUserWorkloadClusterRole            = "alertmanager-user-workload/cluster-role.yaml"
	AlertmanagerUserWorkloadRBACProxyTenancySecret = "alertmanager-user-workload/kube-rbac-proxy-tenancy-secret.yaml"
	AlertmanagerUserWorkloadRBACProxyMetricSecret  = "alertmanager-user-workload/kube-rbac-proxy-metric-secret.yaml"
	AlertmanagerUserWorkloadTrustedCABundle        = "alertmanager-user-workload/trusted-ca-bundle.yaml"
	AlertmanagerUserWorkloadPodDisruptionBudget    = "alertmanager-user-workload/pod-disruption-budget.yaml"
	AlertmanagerUserWorkloadServiceMonitor         = "alertmanager-user-workload/service-monitor.yaml"

	KubeStateMetricsClusterRoleBinding  = "kube-state-metrics/cluster-role-binding.yaml"
	KubeStateMetricsClusterRole         = "kube-state-metrics/cluster-role.yaml"
	KubeStateMetricsDeployment          = "kube-state-metrics/deployment.yaml"
	KubeStateMetricsServiceAccount      = "kube-state-metrics/service-account.yaml"
	KubeStateMetricsService             = "kube-state-metrics/service.yaml"
	KubeStateMetricsServiceMonitor      = "kube-state-metrics/service-monitor.yaml"
	KubeStateMetricsPrometheusRule      = "kube-state-metrics/prometheus-rule.yaml"
	KubeStateMetricsKubeRbacProxySecret = "kube-state-metrics/kube-rbac-proxy-secret.yaml"

	OpenShiftStateMetricsClusterRoleBinding  = "openshift-state-metrics/cluster-role-binding.yaml"
	OpenShiftStateMetricsClusterRole         = "openshift-state-metrics/cluster-role.yaml"
	OpenShiftStateMetricsDeployment          = "openshift-state-metrics/deployment.yaml"
	OpenShiftStateMetricsServiceAccount      = "openshift-state-metrics/service-account.yaml"
	OpenShiftStateMetricsService             = "openshift-state-metrics/service.yaml"
	OpenShiftStateMetricsServiceMonitor      = "openshift-state-metrics/service-monitor.yaml"
	OpenShiftStateMetricsKubeRbacProxySecret = "openshift-state-metrics/kube-rbac-proxy-secret.yaml"

	NodeExporterDaemonSet                  = "node-exporter/daemonset.yaml"
	NodeExporterService                    = "node-exporter/service.yaml"
	NodeExporterServiceAccount             = "node-exporter/service-account.yaml"
	NodeExporterClusterRole                = "node-exporter/cluster-role.yaml"
	NodeExporterClusterRoleBinding         = "node-exporter/cluster-role-binding.yaml"
	NodeExporterSecurityContextConstraints = "node-exporter/security-context-constraints.yaml"
	NodeExporterServiceMonitor             = "node-exporter/service-monitor.yaml"
	NodeExporterPrometheusRule             = "node-exporter/prometheus-rule.yaml"
	NodeExporterKubeRbacProxySecret        = "node-exporter/kube-rbac-proxy-secret.yaml"

	PrometheusK8sClusterRoleBinding               = "prometheus-k8s/cluster-role-binding.yaml"
	PrometheusK8sRoleBindingConfig                = "prometheus-k8s/role-binding-config.yaml"
	PrometheusK8sRoleBindingList                  = "prometheus-k8s/role-binding-specific-namespaces.yaml"
	PrometheusK8sClusterRole                      = "prometheus-k8s/cluster-role.yaml"
	PrometheusK8sRoleConfig                       = "prometheus-k8s/role-config.yaml"
	PrometheusK8sRoleList                         = "prometheus-k8s/role-specific-namespaces.yaml"
	PrometheusK8sPrometheusRule                   = "prometheus-k8s/prometheus-rule.yaml"
	PrometheusK8sThanosSidecarPrometheusRule      = "prometheus-k8s/prometheus-rule-thanos-sidecar.yaml"
	PrometheusK8sServiceAccount                   = "prometheus-k8s/service-account.yaml"
	PrometheusK8s                                 = "prometheus-k8s/prometheus.yaml"
	PrometheusK8sPrometheusServiceMonitor         = "prometheus-k8s/service-monitor.yaml"
	PrometheusK8sService                          = "prometheus-k8s/service.yaml"
	PrometheusK8sServiceThanosSidecar             = "prometheus-k8s/service-thanos-sidecar.yaml"
	PrometheusK8sProxySecret                      = "prometheus-k8s/proxy-secret.yaml"
	PrometheusRBACProxySecret                     = "prometheus-k8s/kube-rbac-proxy-secret.yaml"
	PrometheusUserWorkloadRBACProxyMetricsSecret  = "prometheus-user-workload/kube-rbac-proxy-metrics-secret.yaml"
	PrometheusUserWorkloadRBACProxyFederateSecret = "prometheus-user-workload/kube-rbac-proxy-federate-secret.yaml"
	PrometheusK8sAPIRoute                         = "prometheus-k8s/api-route.yaml"
	PrometheusK8sFederateRoute                    = "prometheus-k8s/federate-route.yaml"
	PrometheusK8sServingCertsCABundle             = "prometheus-k8s/serving-certs-ca-bundle.yaml"
	PrometheusK8sKubeletServingCABundle           = "prometheus-k8s/kubelet-serving-ca-bundle.yaml"
	PrometheusK8sGrpcTLSSecret                    = "prometheus-k8s/grpc-tls-secret.yaml"
	PrometheusK8sTrustedCABundle                  = "prometheus-k8s/trusted-ca-bundle.yaml"
	PrometheusK8sThanosSidecarServiceMonitor      = "prometheus-k8s/service-monitor-thanos-sidecar.yaml"
	PrometheusK8sTAlertmanagerRoleBinding         = "prometheus-k8s/alertmanager-role-binding.yaml"
	PrometheusK8sPodDisruptionBudget              = "prometheus-k8s/pod-disruption-budget.yaml"
	PrometheusK8sTelemetry                        = "prometheus-k8s/telemetry-secret.yaml"

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
	PrometheusUserWorkloadAlertmanagerRoleBinding     = "prometheus-user-workload/alertmanager-role-binding.yaml"
	PrometheusUserWorkloadPodDisruptionBudget         = "prometheus-user-workload/pod-disruption-budget.yaml"
	PrometheusUserWorkloadConfigMap                   = "prometheus-user-workload/config-map.yaml"
	PrometheusUserWorkloadFederateRoute               = "prometheus-user-workload/federate-route.yaml"

	PrometheusAdapterAPIService                         = "prometheus-adapter/api-service.yaml"
	PrometheusAdapterClusterRole                        = "prometheus-adapter/cluster-role.yaml"
	PrometheusAdapterClusterRoleBinding                 = "prometheus-adapter/cluster-role-binding.yaml"
	PrometheusAdapterClusterRoleBindingDelegator        = "prometheus-adapter/cluster-role-binding-delegator.yaml"
	PrometheusAdapterClusterRoleBindingView             = "prometheus-adapter/cluster-role-binding-view.yaml"
	PrometheusAdapterClusterRoleServerResources         = "prometheus-adapter/cluster-role-server-resources.yaml"
	PrometheusAdapterClusterRoleAggregatedMetricsReader = "prometheus-adapter/cluster-role-aggregated-metrics-reader.yaml"
	PrometheusAdapterConfigMap                          = "prometheus-adapter/config-map.yaml"
	PrometheusAdapterConfigMapDedicatedSM               = "prometheus-adapter/config-map-dedicated-service-monitors.yaml"
	PrometheusAdapterConfigMapPrometheus                = "prometheus-adapter/configmap-prometheus.yaml"
	PrometheusAdapterConfigMapAuditPolicy               = "prometheus-adapter/configmap-audit-profiles.yaml"
	PrometheusAdapterDeployment                         = "prometheus-adapter/deployment.yaml"
	PrometheusAdapterPodDisruptionBudget                = "prometheus-adapter/pod-disruption-budget.yaml"
	PrometheusAdapterRoleBindingAuthReader              = "prometheus-adapter/role-binding-auth-reader.yaml"
	PrometheusAdapterService                            = "prometheus-adapter/service.yaml"
	PrometheusAdapterServiceMonitor                     = "prometheus-adapter/service-monitor.yaml"
	PrometheusAdapterServiceAccount                     = "prometheus-adapter/service-account.yaml"

	AdmissionWebhookRuleValidatingWebhook               = "admission-webhook/prometheus-rule-validating-webhook.yaml"
	AdmissionWebhookAlertmanagerConfigValidatingWebhook = "admission-webhook/alertmanager-config-validating-webhook.yaml"
	AdmissionWebhookDeployment                          = "admission-webhook/deployment.yaml"
	AdmissionWebhookPodDisruptionBudget                 = "admission-webhook/pod-disruption-budget.yaml"
	AdmissionWebhookService                             = "admission-webhook/service.yaml"
	AdmissionWebhookServiceAccount                      = "admission-webhook/service-account.yaml"

	PrometheusOperatorClusterRoleBinding  = "prometheus-operator/cluster-role-binding.yaml"
	PrometheusOperatorClusterRole         = "prometheus-operator/cluster-role.yaml"
	PrometheusOperatorServiceAccount      = "prometheus-operator/service-account.yaml"
	PrometheusOperatorDeployment          = "prometheus-operator/deployment.yaml"
	PrometheusOperatorService             = "prometheus-operator/service.yaml"
	PrometheusOperatorServiceMonitor      = "prometheus-operator/service-monitor.yaml"
	PrometheusOperatorCertsCABundle       = "prometheus-operator/operator-certs-ca-bundle.yaml"
	PrometheusOperatorPrometheusRule      = "prometheus-operator/prometheus-rule.yaml"
	PrometheusOperatorKubeRbacProxySecret = "prometheus-operator/kube-rbac-proxy-secret.yaml"

	PrometheusOperatorUserWorkloadServiceAccount      = "prometheus-operator-user-workload/service-account.yaml"
	PrometheusOperatorUserWorkloadClusterRole         = "prometheus-operator-user-workload/cluster-role.yaml"
	PrometheusOperatorUserWorkloadClusterRoleBinding  = "prometheus-operator-user-workload/cluster-role-binding.yaml"
	PrometheusOperatorUserWorkloadService             = "prometheus-operator-user-workload/service.yaml"
	PrometheusOperatorUserWorkloadDeployment          = "prometheus-operator-user-workload/deployment.yaml"
	PrometheusOperatorUserWorkloadServiceMonitor      = "prometheus-operator-user-workload/service-monitor.yaml"
	PrometheusOperatorUserWorkloadKubeRbacProxySecret = "prometheus-operator-user-workload/kube-rbac-proxy-secret.yaml"

	ClusterMonitoringOperatorServiceMonitor     = "cluster-monitoring-operator/service-monitor.yaml"
	ClusterMonitoringClusterRoleView            = "cluster-monitoring-operator/cluster-role-view.yaml"
	ClusterMonitoringAlertmanagerEditRole       = "cluster-monitoring-operator/monitoring-alertmanager-edit-role.yaml"
	ClusterMonitoringRulesEditClusterRole       = "cluster-monitoring-operator/monitoring-rules-edit-cluster-role.yaml"
	ClusterMonitoringRulesViewClusterRole       = "cluster-monitoring-operator/monitoring-rules-view-cluster-role.yaml"
	ClusterMonitoringEditClusterRole            = "cluster-monitoring-operator/monitoring-edit-cluster-role.yaml"
	ClusterMonitoringEditAlertingClusterRole    = "cluster-monitoring-operator/alerting-edit-cluster-role.yaml"
	ClusterMonitoringEditUserWorkloadConfigRole = "cluster-monitoring-operator/user-workload-config-edit-role.yaml"
	ClusterMonitoringGrpcTLSSecret              = "cluster-monitoring-operator/grpc-tls-secret.yaml"
	ClusterMonitoringOperatorPrometheusRule     = "cluster-monitoring-operator/prometheus-rule.yaml"
	ClusterMonitoringMetricsClientCertsSecret   = "cluster-monitoring-operator/metrics-client-certs.yaml"
	ClusterMonitoringMetricsClientCACM          = "cluster-monitoring-operator/metrics-client-ca.yaml"

	TelemeterClientClusterRole            = "telemeter-client/cluster-role.yaml"
	TelemeterClientClusterRoleBinding     = "telemeter-client/cluster-role-binding.yaml"
	TelemeterClientClusterRoleBindingView = "telemeter-client/cluster-role-binding-view.yaml"
	TelemeterClientDeployment             = "telemeter-client/deployment.yaml"
	TelemeterClientSecret                 = "telemeter-client/secret.yaml"
	TelemeterClientService                = "telemeter-client/service.yaml"
	TelemeterClientServiceAccount         = "telemeter-client/service-account.yaml"
	TelemeterClientServiceMonitor         = "telemeter-client/service-monitor.yaml"
	TelemeterClientServingCertsCABundle   = "telemeter-client/serving-certs-ca-bundle.yaml"
	TelemeterClientKubeRbacProxySecret    = "telemeter-client/kube-rbac-proxy-secret.yaml"
	TelemeterClientPrometheusRule         = "telemeter-client/prometheus-rule.yaml"

	ThanosQuerierDeployment             = "thanos-querier/deployment.yaml"
	ThanosQuerierPodDisruptionBudget    = "thanos-querier/pod-disruption-budget.yaml"
	ThanosQuerierService                = "thanos-querier/service.yaml"
	ThanosQuerierServiceMonitor         = "thanos-querier/service-monitor.yaml"
	ThanosQuerierPrometheusRule         = "thanos-querier/prometheus-rule.yaml"
	ThanosQuerierRoute                  = "thanos-querier/route.yaml"
	ThanosQuerierOauthCookieSecret      = "thanos-querier/oauth-cookie-secret.yaml"
	ThanosQuerierRBACProxySecret        = "thanos-querier/kube-rbac-proxy-secret.yaml"
	ThanosQuerierRBACProxyRulesSecret   = "thanos-querier/kube-rbac-proxy-rules-secret.yaml"
	ThanosQuerierRBACProxyMetricsSecret = "thanos-querier/kube-rbac-proxy-metric-secret.yaml"
	ThanosQuerierServiceAccount         = "thanos-querier/service-account.yaml"
	ThanosQuerierClusterRole            = "thanos-querier/cluster-role.yaml"
	ThanosQuerierClusterRoleBinding     = "thanos-querier/cluster-role-binding.yaml"
	ThanosQuerierGrpcTLSSecret          = "thanos-querier/grpc-tls-secret.yaml"
	ThanosQuerierTrustedCABundle        = "thanos-querier/trusted-ca-bundle.yaml"

	ThanosRulerCustomResource               = "thanos-ruler/thanos-ruler.yaml"
	ThanosRulerService                      = "thanos-ruler/service.yaml"
	ThanosRulerRoute                        = "thanos-ruler/route.yaml"
	ThanosRulerOauthCookieSecret            = "thanos-ruler/oauth-cookie-secret.yaml"
	ThanosRulerQueryConfigSecret            = "thanos-ruler/query-config-secret.yaml"
	ThanosRulerAlertmanagerConfigSecret     = "thanos-ruler/alertmanagers-config-secret.yaml"
	ThanosRulerRBACProxyMetricsSecret       = "thanos-ruler/kube-rbac-proxy-metrics-secret.yaml"
	ThanosRulerServiceAccount               = "thanos-ruler/service-account.yaml"
	ThanosRulerClusterRole                  = "thanos-ruler/cluster-role.yaml"
	ThanosRulerClusterRoleBinding           = "thanos-ruler/cluster-role-binding.yaml"
	ThanosRulerMonitoringClusterRoleBinding = "thanos-ruler/cluster-role-binding-monitoring.yaml"
	ThanosRulerGrpcTLSSecret                = "thanos-ruler/grpc-tls-secret.yaml"
	ThanosRulerTrustedCABundle              = "thanos-ruler/trusted-ca-bundle.yaml"
	ThanosRulerServiceMonitor               = "thanos-ruler/service-monitor.yaml"
	ThanosRulerPrometheusRule               = "thanos-ruler/thanos-ruler-prometheus-rule.yaml"
	ThanosRulerAlertmanagerRoleBinding      = "thanos-ruler/alertmanager-role-binding.yaml"
	ThanosRulerPodDisruptionBudget          = "thanos-ruler/pod-disruption-budget.yaml"

	TelemeterTrustedCABundle = "telemeter-client/trusted-ca-bundle.yaml"

	ControlPlanePrometheusRule          = "control-plane/prometheus-rule.yaml"
	ControlPlaneKubeletServiceMonitor   = "control-plane/service-monitor-kubelet.yaml"
	ControlPlaneKubeletServiceMonitorPA = "control-plane/service-monitor-kubelet-resource-metrics.yaml"
	ControlPlaneEtcdServiceMonitor      = "control-plane/service-monitor-etcd.yaml"
)

var (
	PrometheusConfigReloaderFlag                         = "--prometheus-config-reloader="
	PrometheusOperatorPrometheusInstanceNamespacesFlag   = "--prometheus-instance-namespaces="
	PrometheusOperatorAlertmanagerInstanceNamespacesFlag = "--alertmanager-instance-namespaces="
	PrometheusOperatorWebTLSCipherSuitesFlag             = "--web.tls-cipher-suites="
	PrometheusOperatorWebTLSMinTLSVersionFlag            = "--web.tls-min-version="
	PrometheusAdapterTLSCipherSuitesFlag                 = "--tls-cipher-suites="
	PrometheusAdapterTLSMinTLSVersionFlag                = "--tls-min-version="
	KubeRbacProxyTLSCipherSuitesFlag                     = "--tls-cipher-suites="
	KubeRbacProxyMinTLSVersionFlag                       = "--tls-min-version="

	AuthProxyExternalURLFlag  = "-external-url="
	AuthProxyCookieDomainFlag = "-cookie-domain="
	AuthProxyRedirectURLFlag  = "-redirect-url="

	TrustedCABundleKey = "ca-bundle.crt"

	AdditionalAlertmanagerConfigSecretKey               = "alertmanager-configs.yaml"
	PrometheusK8sAdditionalAlertmanagerConfigSecretName = "prometheus-k8s-additional-alertmanager-configs"
	PrometheusUWAdditionalAlertmanagerConfigSecretName  = "prometheus-user-workload-additional-alertmanager-configs"
)

var (
	ErrConfigValidation = fmt.Errorf("invalid value for config")
)

type Factory struct {
	namespace             string
	namespaceUserWorkload string
	config                *Config
	infrastructure        InfrastructureReader
	proxy                 ProxyReader
	assets                *Assets
	APIServerConfig       *APIServerConfig
	consoleConfig         *configv1.Console
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

func NewFactory(namespace, namespaceUserWorkload string, c *Config, infrastructure InfrastructureReader, proxy ProxyReader, a *Assets, apiServerConfig *APIServerConfig, consoleConfig *configv1.Console) *Factory {
	return &Factory{
		namespace:             namespace,
		namespaceUserWorkload: namespaceUserWorkload,
		config:                c,
		infrastructure:        infrastructure,
		proxy:                 proxy,
		assets:                a,
		APIServerConfig:       apiServerConfig,
		consoleConfig:         consoleConfig,
	}
}

func (f *Factory) AlertmanagerConfig() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(AlertmanagerConfig))
}

func (f *Factory) AlertmanagerUserWorkloadSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(AlertmanagerUserWorkloadSecret))
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

	return s, nil
}

func (f *Factory) AlertmanagerService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(AlertmanagerService))
}

func (f *Factory) AlertmanagerUserWorkloadService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(AlertmanagerUserWorkloadService))
}

func (f *Factory) AlertmanagerServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(AlertmanagerServiceAccount))
}

func (f *Factory) AlertmanagerUserWorkloadServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(AlertmanagerUserWorkloadServiceAccount))
}

func (f *Factory) AlertmanagerClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(AlertmanagerClusterRoleBinding))
}

func (f *Factory) AlertmanagerUserWorkloadClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(AlertmanagerUserWorkloadClusterRoleBinding))
}

func (f *Factory) AlertmanagerClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(AlertmanagerClusterRole))
}

func (f *Factory) AlertmanagerUserWorkloadClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(AlertmanagerUserWorkloadClusterRole))
}

func (f *Factory) AlertmanagerServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(AlertmanagerServiceMonitor))
}

func (f *Factory) AlertmanagerUserWorkloadServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(AlertmanagerUserWorkloadServiceMonitor))
}

func (f *Factory) AlertmanagerTrustedCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(AlertmanagerTrustedCABundle))
}

func (f *Factory) AlertmanagerUserWorkloadTrustedCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(AlertmanagerUserWorkloadTrustedCABundle))
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

func (f *Factory) AlertmanagerUserWorkload(trustedCABundleCM *v1.ConfigMap) (*monv1.Alertmanager, error) {
	a, err := f.NewAlertmanager(f.assets.MustNewAssetReader(AlertmanagerUserWorkload))
	if err != nil {
		return nil, err
	}

	a.Spec.Image = &f.config.Images.Alertmanager

	// TODO(simonpasquier): link to the alerting page of the dev console. It
	// depends on https://issues.redhat.com/browse/MON-2289.
	if f.consoleConfig != nil && f.consoleConfig.Status.ConsoleURL != "" {
		a.Spec.ExternalURL, err = url.JoinPath(f.consoleConfig.Status.ConsoleURL, "monitoring")
		if err != nil {
			return nil, err
		}
	}

	alertmanagerConfig := f.config.UserWorkloadConfiguration.Alertmanager

	if alertmanagerConfig.LogLevel != "" {
		a.Spec.LogLevel = alertmanagerConfig.LogLevel
	}

	if alertmanagerConfig.Resources != nil {
		a.Spec.Resources = *alertmanagerConfig.Resources
	}

	if alertmanagerConfig.EnableAlertmanagerConfig {
		a.Spec.AlertmanagerConfigSelector = &metav1.LabelSelector{}

		a.Spec.AlertmanagerConfigNamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "openshift.io/cluster-monitoring",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"true"},
				},
				{
					Key:      "openshift.io/user-monitoring",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"false"},
				},
			},
		}
	}

	if alertmanagerConfig.VolumeClaimTemplate != nil {
		a.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *alertmanagerConfig.VolumeClaimTemplate,
		}
	}

	setupStartupProbe(a)

	if alertmanagerConfig.NodeSelector != nil {
		a.Spec.NodeSelector = alertmanagerConfig.NodeSelector
	}

	if len(alertmanagerConfig.Tolerations) > 0 {
		a.Spec.Tolerations = alertmanagerConfig.Tolerations
	}

	for i, c := range a.Spec.Containers {
		switch c.Name {
		case "alertmanager-proxy", "tenancy-proxy", "kube-rbac-proxy-metric":
			a.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			a.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(c.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
		case "prom-label-proxy":
			a.Spec.Containers[i].Image = f.config.Images.PromLabelProxy
		}
	}

	return a, nil
}

// setupStartupProbe configures a startup probe if necessary.
// When no persistent storage is configured, add a startup probe to
// ensure that the Alertmanager container has time to replicate data
// from other peers before declaring itself as ready. This allows
// silences and notifications to be preserved on roll-outs.
//
// On startup, Alertmanager resolves the names of the peers before
// initiating the web service.  To account for this, the execution of
// the probe is delayed by 20 seconds so that Alertmanager gets enough
// time for the resolution + data synchronisation before the probe
// returns (20s is twice the time that Alertmanager waits before
// declaring that it can start sending notfications).
//
// We also account for slow DNS resolvers by retrying for 400 seconds
// (PeriodSeconds x FailureThreshold) thus giving AlertManager a total
// of 7 minutes (420 seconds) in case the endpoint isn't ready after 20s.
//
// See bugs below for details:
//   - https://bugzilla.redhat.com/show_bug.cgi?id=2037073
//   - https://bugzilla.redhat.com/show_bug.cgi?id=2083226
func setupStartupProbe(a *monv1.Alertmanager) {
	if a.Spec.Storage != nil {
		return
	}

	if *a.Spec.Replicas < 2 {
		return
	}

	a.Spec.Containers = append(a.Spec.Containers,
		v1.Container{
			Name: "alertmanager",
			StartupProbe: &v1.Probe{
				ProbeHandler: v1.ProbeHandler{
					Exec: &v1.ExecAction{
						Command: []string{
							"sh",
							"-c",
							"exec curl --fail http://localhost:9093/-/ready",
						},
					},
				},
				InitialDelaySeconds: 20,
				PeriodSeconds:       10,
				FailureThreshold:    40,
				TimeoutSeconds:      3,
			},
		},
	)
}

func (f *Factory) AlertmanagerMain(trustedCABundleCM *v1.ConfigMap) (*monv1.Alertmanager, error) {
	a, err := f.NewAlertmanager(f.assets.MustNewAssetReader(AlertmanagerMain))
	if err != nil {
		return nil, err
	}

	a.Spec.Image = &f.config.Images.Alertmanager

	if f.consoleConfig != nil && f.consoleConfig.Status.ConsoleURL != "" {
		a.Spec.ExternalURL, err = url.JoinPath(f.consoleConfig.Status.ConsoleURL, "monitoring")
		if err != nil {
			return nil, err
		}
	}

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.LogLevel != "" {
		a.Spec.LogLevel = f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.LogLevel
	}

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Resources != nil {
		a.Spec.Resources = *f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Resources
	}

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Secrets != nil {
		a.Spec.Secrets = append(a.Spec.Secrets, f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Secrets...)
	}

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.EnableUserAlertManagerConfig &&
		!f.config.UserWorkloadConfiguration.Alertmanager.Enabled {
		a.Spec.AlertmanagerConfigSelector = &metav1.LabelSelector{}

		a.Spec.AlertmanagerConfigNamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "openshift.io/cluster-monitoring",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"true"},
				},
				{
					Key:      "openshift.io/user-monitoring",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"false"},
				},
			},
		}
	}

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.VolumeClaimTemplate != nil {
		a.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.VolumeClaimTemplate,
		}
	}

	setupStartupProbe(a)

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.NodeSelector != nil {
		a.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Tolerations) > 0 {
		a.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Tolerations
	}

	if len(f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.TopologySpreadConstraints) > 0 {
		a.Spec.TopologySpreadConstraints =
			f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.TopologySpreadConstraints
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
		case "kube-rbac-proxy", "kube-rbac-proxy-metric":
			a.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			a.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(c.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
		case "prom-label-proxy":
			a.Spec.Containers[i].Image = f.config.Images.PromLabelProxy
		}
	}

	a.Namespace = f.namespace

	return a, nil
}

func (f *Factory) AlertmanagerRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(AlertmanagerRBACProxySecret))
}

func (f *Factory) AlertmanagerUserWorkloadRBACProxyTenancySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(AlertmanagerUserWorkloadRBACProxyTenancySecret))
}

func (f *Factory) AlertmanagerRBACProxyMetricSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(AlertmanagerRBACProxyMetricSecret))
}

func (f *Factory) AlertmanagerUserWorkloadRBACProxyMetricSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(AlertmanagerUserWorkloadRBACProxyMetricSecret))
}

func (f *Factory) AlertmanagerRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetReader(AlertmanagerRoute))
}

func (f *Factory) AlertmanagerPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(AlertmanagerPrometheusRule))
}

func (f *Factory) KubeStateMetricsClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(KubeStateMetricsClusterRoleBinding))
}

func (f *Factory) AlertmanagerPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(AlertmanagerPodDisruptionBudget))
}

func (f *Factory) AlertmanagerUserWorkloadPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(AlertmanagerUserWorkloadPodDisruptionBudget))
}

func (f *Factory) KubeStateMetricsClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(KubeStateMetricsClusterRole))
}

func (f *Factory) KubeStateMetricsServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(KubeStateMetricsServiceMonitor))
}

func (f *Factory) KubeStateMetricsDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(KubeStateMetricsDeployment))
	if err != nil {
		return nil, err
	}
	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "kube-rbac-proxy-self", "kube-rbac-proxy-main":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			d.Spec.Template.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
		case "kube-state-metrics":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeStateMetrics
		}
	}

	if f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.NodeSelector != nil {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Tolerations
	}

	return d, nil
}

func (f *Factory) KubeStateMetricsServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(KubeStateMetricsServiceAccount))
}

func (f *Factory) KubeStateMetricsService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(KubeStateMetricsService))
}

func (f *Factory) KubeStateMetricsRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(KubeStateMetricsKubeRbacProxySecret))
}

func (f *Factory) KubeStateMetricsPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(KubeStateMetricsPrometheusRule))
}

func (f *Factory) OpenShiftStateMetricsClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(OpenShiftStateMetricsClusterRoleBinding))
}

func (f *Factory) OpenShiftStateMetricsClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(OpenShiftStateMetricsClusterRole))
}

func (f *Factory) OpenShiftStateMetricsServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(OpenShiftStateMetricsServiceMonitor))
}

func (f *Factory) OpenShiftStateMetricsDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(OpenShiftStateMetricsDeployment))
	if err != nil {
		return nil, err
	}

	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "kube-rbac-proxy-main", "kube-rbac-proxy-self":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			d.Spec.Template.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
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
	return f.NewServiceAccount(f.assets.MustNewAssetReader(OpenShiftStateMetricsServiceAccount))
}

func (f *Factory) OpenShiftStateMetricsService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(OpenShiftStateMetricsService))
}

func (f *Factory) OpenShiftStateMetricsRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(OpenShiftStateMetricsKubeRbacProxySecret))
}

func (f *Factory) NodeExporterServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(NodeExporterServiceMonitor))
}

func (f *Factory) updateNodeExporterArgs(args []string) []string {
	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.CpuFreq.Enabled {
		args = setArg(args, "--collector.cpufreq", "")
	} else {
		args = setArg(args, "--no-collector.cpufreq", "")
	}

	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.TcpStat.Enabled {
		args = setArg(args, "--collector.tcpstat", "")
	} else {
		args = setArg(args, "--no-collector.tcpstat", "")
	}

	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.NetDev.Enabled {
		args = setArg(args, "--collector.netdev", "")
	} else {
		args = setArg(args, "--no-collector.netdev", "")
	}

	return args
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
			ds.Spec.Template.Spec.Containers[i].Args = f.updateNodeExporterArgs(ds.Spec.Template.Spec.Containers[i].Args)
		case "kube-rbac-proxy":
			ds.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			ds.Spec.Template.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
		}
	}

	for i, container := range ds.Spec.Template.Spec.InitContainers {
		switch container.Name {
		case "init-textfile":
			ds.Spec.Template.Spec.InitContainers[i].Image = f.config.Images.NodeExporter
		}
	}

	return ds, nil
}

func (f *Factory) NodeExporterService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(NodeExporterService))
}

func (f *Factory) NodeExporterSecurityContextConstraints() (*securityv1.SecurityContextConstraints, error) {
	return f.NewSecurityContextConstraints(f.assets.MustNewAssetReader(NodeExporterSecurityContextConstraints))
}

func (f *Factory) NodeExporterServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(NodeExporterServiceAccount))
}

func (f *Factory) NodeExporterClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(NodeExporterClusterRoleBinding))
}

func (f *Factory) NodeExporterClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(NodeExporterClusterRole))
}

func (f *Factory) NodeExporterPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(NodeExporterPrometheusRule))
}

func (f *Factory) NodeExporterRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(NodeExporterKubeRbacProxySecret))
}

func (f *Factory) PrometheusK8sClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusK8sClusterRoleBinding))
}

func (f *Factory) PrometheusK8sAlertmanagerRoleBinding() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetReader(PrometheusK8sTAlertmanagerRoleBinding))
}

func (f *Factory) ThanosQuerierClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(ThanosQuerierClusterRoleBinding))
}

func (f *Factory) PrometheusUserWorkloadClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusUserWorkloadClusterRoleBinding))
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
	return f.NewRole(f.assets.MustNewAssetReader(PrometheusK8sRoleConfig))
}

func (f *Factory) PrometheusUserWorkloadRoleConfig() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetReader(PrometheusUserWorkloadRoleConfig))
}

func (f *Factory) PrometheusK8sRoleBindingList() (*rbacv1.RoleBindingList, error) {
	return f.NewRoleBindingList(f.assets.MustNewAssetReader(PrometheusK8sRoleBindingList))
}

func (f *Factory) PrometheusUserWorkloadRoleBindingList() (*rbacv1.RoleBindingList, error) {
	return f.NewRoleBindingList(f.assets.MustNewAssetReader(PrometheusUserWorkloadRoleBindingList))
}

func (f *Factory) PrometheusK8sRoleBindingConfig() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetReader(PrometheusK8sRoleBindingConfig))
}

func (f *Factory) PrometheusUserWorkloadRoleBindingConfig() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetReader(PrometheusUserWorkloadRoleBindingConfig))
}

func (f *Factory) PrometheusK8sRoleList() (*rbacv1.RoleList, error) {
	return f.NewRoleList(f.assets.MustNewAssetReader(PrometheusK8sRoleList))
}

func (f *Factory) PrometheusUserWorkloadRoleList() (*rbacv1.RoleList, error) {
	return f.NewRoleList(f.assets.MustNewAssetReader(PrometheusUserWorkloadRoleList))
}

func (f *Factory) PrometheusUserWorkloadFederateRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetReader(PrometheusUserWorkloadFederateRoute))
}

func (f *Factory) PrometheusK8sPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(PrometheusK8sPrometheusRule))
}

func (f *Factory) PrometheusK8sServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(PrometheusK8sServiceAccount))
}

func (f *Factory) ThanosQuerierServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(ThanosQuerierServiceAccount))
}

func (f *Factory) PrometheusUserWorkloadServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(PrometheusUserWorkloadServiceAccount))
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

	return s, nil
}

func (f *Factory) PrometheusK8sGrpcTLSSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(PrometheusK8sGrpcTLSSecret))
}

func (f *Factory) PrometheusK8sThanosSidecarPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(PrometheusK8sThanosSidecarPrometheusRule))
}

func (f *Factory) PrometheusUserWorkloadGrpcTLSSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(PrometheusUserWorkloadGrpcTLSSecret))
}

func (f *Factory) ThanosQuerierGrpcTLSSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(ThanosQuerierGrpcTLSSecret))
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

	var alertingConfiguration thanosAlertingConfiguration
	err = yaml2.Unmarshal([]byte(s.StringData["alertmanagers.yaml"]), &alertingConfiguration)
	if err != nil {
		return nil, err
	}

	if f.config.UserWorkloadConfiguration.Alertmanager.Enabled {
		alertingConfiguration.Alertmanagers[0].HTTPConfig.TLSConfig.ServerName = fmt.Sprintf(
			"%s.%s.svc",
			userWorkloadAlertmanagerService,
			f.namespaceUserWorkload,
		)
		alertingConfiguration.Alertmanagers[0].StaticConfigs = []string{
			fmt.Sprintf(
				"dnssrv+_web._tcp.alertmanager-operated.%s.svc",
				f.namespaceUserWorkload,
			),
		}
	} else if !f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.IsEnabled() {
		alertingConfiguration.Alertmanagers = []thanosAlertmanagerConfiguration{}
	}

	additionalConfigs, err := ConvertToThanosAlertmanagerConfiguration(f.config.GetThanosRulerAlertmanagerConfigs())
	if err != nil {
		return nil, err
	}

	alertingConfiguration.Alertmanagers = append(alertingConfiguration.Alertmanagers, additionalConfigs...)

	b, err := yaml2.Marshal(alertingConfiguration)
	if err != nil {
		return nil, err
	}

	s.StringData["alertmanagers.yaml"] = string(b)

	return s, nil
}

func (f *Factory) PrometheusRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(PrometheusRBACProxySecret))
}

func (f *Factory) PrometheusUserWorkloadRBACProxyMetricsSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(PrometheusUserWorkloadRBACProxyMetricsSecret))
}

func (f *Factory) PrometheusUserWorkloadRBACProxyFederateSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(PrometheusUserWorkloadRBACProxyFederateSecret))
}

func (f *Factory) ThanosQuerierRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(ThanosQuerierRBACProxySecret))
}
func (f *Factory) ThanosQuerierRBACProxyRulesSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(ThanosQuerierRBACProxyRulesSecret))
}

func (f *Factory) ThanosQuerierRBACProxyMetricsSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(ThanosQuerierRBACProxyMetricsSecret))
}

func (f *Factory) PrometheusK8sServingCertsCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusK8sServingCertsCABundle))
}

func (f *Factory) PrometheusUserWorkloadConfigMap() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusUserWorkloadConfigMap))
}

func (f *Factory) PrometheusUserWorkloadServingCertsCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusUserWorkloadServingCertsCABundle))
}

func (f *Factory) PrometheusK8sKubeletServingCABundle(data map[string]string) (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusK8sKubeletServingCABundle))
	if err != nil {
		return nil, err
	}

	c.Data = data
	return c, nil
}

func (f *Factory) PrometheusOperatorCertsCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusOperatorCertsCABundle))
}

func (f *Factory) PrometheusK8sThanosSidecarServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusK8sThanosSidecarServiceMonitor))
}

func (f *Factory) PrometheusK8sAPIRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetReader(PrometheusK8sAPIRoute))
}

func (f *Factory) PrometheusK8sFederateRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetReader(PrometheusK8sFederateRoute))
}

func (f *Factory) ThanosQuerierRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetReader(ThanosQuerierRoute))
}

func (f *Factory) SharingConfig(
	promHost, amHost, thanosHost *url.URL,
	alertmanagerUserWorkloadHost, alertmanagerTenancyHost string,
) *v1.ConfigMap {
	data := map[string]string{}

	// Configmap keys need to include "public" to indicate that they are public values.
	// See https://bugzilla.redhat.com/show_bug.cgi?id=1807100.
	if promHost != nil {
		data["prometheusPublicURL"] = fmt.Sprintf("%s://%s", promHost.Scheme, promHost.Host)
	}

	if amHost != nil {
		data["alertmanagerPublicURL"] = fmt.Sprintf("%s://%s", amHost.Scheme, amHost.Host)
	}

	if thanosHost != nil {
		data["thanosPublicURL"] = fmt.Sprintf("%s://%s", thanosHost.Scheme, thanosHost.Host)
	}
	data["alertmanagerUserWorkloadHost"] = alertmanagerUserWorkloadHost
	data["alertmanagerTenancyHost"] = alertmanagerTenancyHost

	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sharedConfigMap,
			Namespace: configManagedNamespace,
		},
		Data: data,
	}
}

func (f *Factory) PrometheusK8sTrustedCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusK8sTrustedCABundle))
}

func (f *Factory) NewPrometheusK8s() (*monv1.Prometheus, error) {
	return f.NewPrometheus(f.assets.MustNewAssetReader(PrometheusK8s))
}

func (f *Factory) PrometheusK8sTelemetrySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetReader(PrometheusK8sTelemetry))
	if err != nil {
		return nil, err
	}
	compositeToken, err := json.Marshal(map[string]string{
		"cluster_id":          f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID,
		"authorization_token": f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Token,
	})
	if err != nil {
		return nil, err
	}

	b := make([]byte, base64.StdEncoding.EncodedLen(len(compositeToken)))
	base64.StdEncoding.Encode(b, compositeToken)
	s.Data = map[string][]byte{
		telemetryTokenSecretKey: b,
	}

	return s, nil
}

func (f *Factory) PrometheusK8s(grpcTLS *v1.Secret, trustedCABundleCM *v1.ConfigMap, telemetrySecret *v1.Secret) (*monv1.Prometheus, error) {
	p, err := f.NewPrometheusK8s()
	if err != nil {
		return nil, err
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.LogLevel != "" {
		p.Spec.LogLevel = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.LogLevel
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention != "" {
		p.Spec.Retention = monv1.Duration(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention)
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.RetentionSize != "" {
		p.Spec.RetentionSize = monv1.ByteSize(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.RetentionSize)
	}

	p.Spec.Image = &f.config.Images.Prometheus

	if f.consoleConfig != nil && f.consoleConfig.Status.ConsoleURL != "" {
		p.Spec.ExternalURL, err = url.JoinPath(f.consoleConfig.Status.ConsoleURL, "monitoring")
		if err != nil {
			return nil, err
		}
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Resources != nil {
		p.Spec.Resources = *f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Resources
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.NodeSelector != nil {
		p.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Tolerations) > 0 {
		p.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Tolerations
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.TopologySpreadConstraints) > 0 {
		p.Spec.TopologySpreadConstraints =
			f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.TopologySpreadConstraints
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.ExternalLabels != nil {
		p.Spec.ExternalLabels = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.ExternalLabels
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.VolumeClaimTemplate != nil {
		p.Spec.Storage = &monv1.StorageSpec{
			VolumeClaimTemplate: *f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.VolumeClaimTemplate,
		}
	}

	if err := f.setupQueryLogFile(p, f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.QueryLogFile); err != nil {
		return nil, err
	}

	clusterID := f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID
	if f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() && f.config.RemoteWrite {
		selectorRelabelConfig, err := promqlgen.LabelSelectorsToRelabelConfig(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.TelemetryMatches)
		if err != nil {
			return nil, errors.Wrap(err, "generate label selector relabel config")
		}

		p.Spec.Secrets = append(p.Spec.Secrets, telemetrySecret.GetName())

		spec := monv1.RemoteWriteSpec{
			URL:             f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL,
			BearerTokenFile: fmt.Sprintf("/etc/prometheus/secrets/%s/%s", telemetrySecret.GetName(), telemetryTokenSecretKey),
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
				{
					TargetLabel: "_id",
					Replacement: clusterID,
				},
				// relabeling the `ALERTS` series to `alerts` allows us to make
				// a distinction between the series produced in-cluster and out
				// of cluster.
				{
					SourceLabels: []monv1.LabelName{"__name__"},
					TargetLabel:  "__name__",
					Regex:        "ALERTS",
					Replacement:  "alerts",
				},
			},
			MetadataConfig: &monv1.MetadataConfig{
				Send: false,
			},
		}

		p.Spec.RemoteWrite = []monv1.RemoteWriteSpec{spec}
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite) > 0 {
		p.Spec.RemoteWrite = addRemoteWriteConfigs(clusterID, p.Spec.RemoteWrite, f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite...)
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

	setupAlerting(p, platformAlertmanagerService, f.namespace)

	for i, container := range p.Spec.Containers {
		switch container.Name {
		case "prometheus":
			// Increase the startup probe timeout to 1h from 15m to avoid restart failures when the WAL replay
			// takes a long time. See https://issues.redhat.com/browse/OCPBUGS-4168 for details.
			// TODO (JoaoBraveCoding): Once prometheus-operator adds CRD support to configure startupProbe directly
			// we should use that instead of using strategic merge patch
			// See https://github.com/prometheus-operator/prometheus-operator/issues/4730
			p.Spec.Containers[i].StartupProbe = &v1.Probe{
				PeriodSeconds:    15,
				FailureThreshold: 240,
			}
		case "prometheus-proxy":
			p.Spec.Containers[i].Image = f.config.Images.OauthProxy

			f.injectProxyVariables(&p.Spec.Containers[i])

		case "kube-rbac-proxy":
			p.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			p.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
		case "kube-rbac-proxy-thanos":
			p.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy

			p.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
			p.Spec.Containers[i].Args = append(
				p.Spec.Containers[i].Args,
				clientCAArg,
			)

			p.Spec.Containers[i].VolumeMounts = append(
				p.Spec.Containers[i].VolumeMounts,
				v1.VolumeMount{
					Name:      "metrics-client-ca",
					MountPath: "/etc/tls/client",
					ReadOnly:  true,
				},
			)

			p.Spec.Volumes = append(
				p.Spec.Volumes,
				v1.Volume{
					Name: "metrics-client-ca",
					VolumeSource: v1.VolumeSource{
						ConfigMap: &v1.ConfigMapVolumeSource{
							LocalObjectReference: v1.LocalObjectReference{
								Name: "metrics-client-ca",
							},
						},
					},
				})
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

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.AlertmanagerConfigs != nil {
		p.Spec.AdditionalAlertManagerConfigs = &v1.SecretKeySelector{
			Key: AdditionalAlertmanagerConfigSecretKey,
			LocalObjectReference: v1.LocalObjectReference{
				Name: PrometheusK8sAdditionalAlertmanagerConfigSecretName,
			},
		}
		p.Spec.Secrets = append(p.Spec.Secrets, getAdditionalAlertmanagerSecrets(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.AlertmanagerConfigs)...)
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit != "" {
		p.Spec.EnforcedBodySizeLimit = monv1.ByteSize(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit)
	}

	return p, nil
}

func setupAlerting(p *monv1.Prometheus, svcName, svcNamespace string) {
	eps := p.Spec.Alerting.Alertmanagers[0]

	eps.Name = svcName
	eps.Namespace = svcNamespace
	eps.TLSConfig.ServerName = fmt.Sprintf("%s.%s.svc", svcName, svcNamespace)

	p.Spec.Alerting.Alertmanagers = []monv1.AlertmanagerEndpoints{eps}
}

func (f *Factory) setupQueryLogFile(p *monv1.Prometheus, queryLogFile string) error {
	if queryLogFile == "" {
		return nil
	}
	dirPath := filepath.Dir(queryLogFile)
	// queryLogFile is not an absolute path nor a simple filename
	if !filepath.IsAbs(queryLogFile) && dirPath != "." {
		return errors.Wrap(ErrConfigValidation, `relative paths to query log file are not supported`)
	}
	if dirPath == "/" {
		return errors.Wrap(ErrConfigValidation, `query log file can't be stored on the root directory`)
	}

	// /prometheus is where Prometheus will store the TSDB so it is
	// already mounted inside the pod (either from a persistent volume claim or from an empty dir).
	// When queryLogFile is a simple filename the prometheus-operator will take
	// care of mounting an emptyDir under /var/log/prometheus
	p.Spec.QueryLogFile = queryLogFile
	if dirPath == "/prometheus" || dirPath == "." {
		return nil
	}

	// It is not necesssary to mount a volume if the user configured
	// the query log file to be one of the preexisting linux output streams.
	if dirPath == "/dev" {
		base := filepath.Base(p.Spec.QueryLogFile)
		if base != "stdout" && base != "stderr" && base != "null" {
			return errors.Wrap(ErrConfigValidation, `query log file can't be stored on a new file on the dev directory`)
		}
		return nil
	}

	p.Spec.Volumes = append(
		p.Spec.Volumes,
		v1.Volume{
			Name: "query-log",
			VolumeSource: v1.VolumeSource{
				EmptyDir: &v1.EmptyDirVolumeSource{},
			},
		})

	p.Spec.VolumeMounts = append(
		p.Spec.VolumeMounts,
		v1.VolumeMount{
			Name:      "query-log",
			MountPath: dirPath,
		})
	return nil
}

func (f *Factory) PrometheusK8sAdditionalAlertManagerConfigsSecret() (*v1.Secret, error) {
	amConfigs := f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.AlertmanagerConfigs
	prometheusAmConfigs := PrometheusAdditionalAlertmanagerConfigs(amConfigs)

	config, err := yaml2.Marshal(prometheusAmConfigs)
	if err != nil {
		return nil, err
	}

	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusK8sAdditionalAlertmanagerConfigSecretName,
			Namespace: f.namespace,
		},
		Data: map[string][]byte{
			AdditionalAlertmanagerConfigSecretKey: config,
		},
	}, nil
}

func (f *Factory) PrometheusUserWorkloadAdditionalAlertManagerConfigsSecret() (*v1.Secret, error) {
	amConfigs := f.config.AdditionalAlertmanagerConfigsForPrometheusUserWorkload()
	prometheusAmConfigs := PrometheusAdditionalAlertmanagerConfigs(amConfigs)
	config, err := yaml2.Marshal(prometheusAmConfigs)
	if err != nil {
		return nil, err
	}

	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      PrometheusUWAdditionalAlertmanagerConfigSecretName,
			Namespace: f.namespaceUserWorkload,
		},
		Data: map[string][]byte{
			AdditionalAlertmanagerConfigSecretKey: config,
		},
	}, nil
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
		p.Spec.Retention = monv1.Duration(f.config.UserWorkloadConfiguration.Prometheus.Retention)
	}

	if f.config.UserWorkloadConfiguration.Prometheus.RetentionSize != "" {
		p.Spec.RetentionSize = monv1.ByteSize(f.config.UserWorkloadConfiguration.Prometheus.RetentionSize)
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
		p.Spec.RemoteWrite = addRemoteWriteConfigs(
			f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID,
			p.Spec.RemoteWrite,
			f.config.UserWorkloadConfiguration.Prometheus.RemoteWrite...)
	}

	if f.config.UserWorkloadConfiguration.Prometheus.EnforcedSampleLimit != nil {
		p.Spec.EnforcedSampleLimit = f.config.UserWorkloadConfiguration.Prometheus.EnforcedSampleLimit
	}

	if f.config.UserWorkloadConfiguration.Prometheus.EnforcedTargetLimit != nil {
		p.Spec.EnforcedTargetLimit = f.config.UserWorkloadConfiguration.Prometheus.EnforcedTargetLimit
	}

	if f.config.UserWorkloadConfiguration.Prometheus.EnforcedLabelLimit != nil {
		p.Spec.EnforcedLabelLimit = f.config.UserWorkloadConfiguration.Prometheus.EnforcedLabelLimit
	}

	if f.config.UserWorkloadConfiguration.Prometheus.EnforcedLabelNameLengthLimit != nil {
		p.Spec.EnforcedLabelNameLengthLimit = f.config.UserWorkloadConfiguration.Prometheus.EnforcedLabelNameLengthLimit
	}

	if f.config.UserWorkloadConfiguration.Prometheus.EnforcedLabelValueLengthLimit != nil {
		p.Spec.EnforcedLabelValueLengthLimit = f.config.UserWorkloadConfiguration.Prometheus.EnforcedLabelValueLengthLimit
	}

	if f.config.Images.Thanos != "" {
		p.Spec.Thanos.Image = &f.config.Images.Thanos
	}

	if err := f.setupQueryLogFile(p, f.config.UserWorkloadConfiguration.Prometheus.QueryLogFile); err != nil {
		return nil, err
	}

	for i, container := range p.Spec.Containers {
		switch container.Name {
		case "prometheus":
			// Increase the startup probe timeout to 1h from 15m to avoid restart failures when the WAL replay
			// takes a long time. See https://issues.redhat.com/browse/OCPBUGS-4168 for details.
			// TODO (JoaoBraveCoding): Once prometheus-operator adds CRD support to configure startupProbe directly
			// we should use that instead of using strategic merge patch
			// See https://github.com/prometheus-operator/prometheus-operator/issues/4730
			p.Spec.Containers[i].StartupProbe = &v1.Probe{
				PeriodSeconds:    15,
				FailureThreshold: 240,
			}
		case "kube-rbac-proxy-metrics", "kube-rbac-proxy-federate", "kube-rbac-proxy-thanos":
			p.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			p.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
		}
	}

	if f.config.UserWorkloadConfiguration.Alertmanager.Enabled {
		setupAlerting(p, userWorkloadAlertmanagerService, f.namespaceUserWorkload)
	} else {
		setupAlerting(p, platformAlertmanagerService, f.namespace)
	}

	p.Spec.Volumes = append(p.Spec.Volumes, v1.Volume{
		Name: "secret-grpc-tls",
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: grpcTLS.GetName(),
			},
		},
	})

	alertManagerConfigs := f.config.AdditionalAlertmanagerConfigsForPrometheusUserWorkload()
	if len(alertManagerConfigs) > 0 {
		p.Spec.AdditionalAlertManagerConfigs = &v1.SecretKeySelector{
			Key: AdditionalAlertmanagerConfigSecretKey,
			LocalObjectReference: v1.LocalObjectReference{
				Name: PrometheusUWAdditionalAlertmanagerConfigSecretName,
			},
		}
		p.Spec.Secrets = append(p.Spec.Secrets, getAdditionalAlertmanagerSecrets(alertManagerConfigs)...)
	}

	return p, nil
}

func (f *Factory) PrometheusK8sPrometheusServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusK8sPrometheusServiceMonitor))
}

func (f *Factory) PrometheusUserWorkloadPrometheusServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusUserWorkloadPrometheusServiceMonitor))
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
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusAdapterClusterRoleBinding))
}

func (f *Factory) PrometheusAdapterClusterRoleBindingDelegator() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusAdapterClusterRoleBindingDelegator))
}

func (f *Factory) PrometheusAdapterClusterRoleBindingView() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusAdapterClusterRoleBindingView))
}

func (f *Factory) PrometheusAdapterRoleBindingAuthReader() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetReader(PrometheusAdapterRoleBindingAuthReader))
}

func (f *Factory) PrometheusAdapterServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(PrometheusAdapterServiceAccount))
}

func (f *Factory) PrometheusAdapterConfigMap() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusAdapterConfigMap))
}

func (f *Factory) PrometheusAdapterConfigMapDedicated() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusAdapterConfigMapDedicatedSM))
}

func (f *Factory) PrometheusAdapterConfigMapAuditPolicy() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusAdapterConfigMapAuditPolicy))
}

func (f *Factory) PrometheusAdapterConfigMapPrometheus() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(PrometheusAdapterConfigMapPrometheus))
}

func validateAuditProfile(profile auditv1.Level) error {
	// Refer: audit rules: https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-policy
	// for valid log levels

	switch profile {
	case auditv1.LevelNone,
		auditv1.LevelMetadata,
		auditv1.LevelRequest,
		auditv1.LevelRequestResponse:
		return nil
	default:
		// a wrong profile name is a Config validation Error
		return fmt.Errorf("%w - adapter audit profile: %s", ErrConfigValidation, profile)
	}
}

func (f *Factory) PrometheusAdapterDeployment(apiAuthSecretName string, requestheader map[string]string, configName string) (*appsv1.Deployment, error) {
	dep, err := f.NewDeployment(f.assets.MustNewAssetReader(PrometheusAdapterDeployment))
	if err != nil {
		return nil, err
	}

	spec := dep.Spec.Template.Spec

	spec.Containers[0].Image = f.config.Images.K8sPrometheusAdapter

	config := f.config.ClusterMonitoringConfiguration.K8sPrometheusAdapter
	if config != nil && len(config.NodeSelector) > 0 {
		spec.NodeSelector = config.NodeSelector
	}

	if config != nil && len(config.Tolerations) > 0 {
		spec.Tolerations = config.Tolerations
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

	if err := validateAuditProfile(config.Audit.Profile); err != nil {
		return nil, err
	}

	profile := strings.ToLower(string(config.Audit.Profile))
	spec.Containers[0].Args = append(spec.Containers[0].Args,
		fmt.Sprintf("--audit-policy-file=/etc/audit/%s-profile.yaml", profile),
		"--audit-log-path=/var/log/adapter/audit.log",
		"--audit-log-maxsize=100", // 100 MB
		"--audit-log-maxbackup=5", // limit space consumed by restricting backups
		"--audit-log-compress=true",
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
		v1.Volume{
			Name: "config",
			VolumeSource: v1.VolumeSource{
				ConfigMap: &v1.ConfigMapVolumeSource{
					LocalObjectReference: v1.LocalObjectReference{
						Name: configName,
					},
				},
			},
		},
	)

	spec.Containers[0].Args = f.setTLSSecurityConfiguration(spec.Containers[0].Args,
		PrometheusAdapterTLSCipherSuitesFlag, PrometheusAdapterTLSMinTLSVersionFlag)

	dep.Spec.Template.Spec = spec

	return dep, nil
}

func (f *Factory) PrometheusAdapterPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(PrometheusAdapterPodDisruptionBudget))
}

func (f *Factory) PrometheusAdapterService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(PrometheusAdapterService))
}

func (f *Factory) PrometheusAdapterServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusAdapterServiceMonitor))
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
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusOperatorServiceMonitor))
}

func (f *Factory) PrometheusOperatorPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(PrometheusOperatorPrometheusRule))
}

func (f *Factory) PrometheusOperatorUserWorkloadServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadServiceMonitor))
}

func (f *Factory) PrometheusUserWorkloadThanosSidecarServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(PrometheusUserWorkloadThanosSidecarServiceMonitor))
}

func (f *Factory) PrometheusUserWorkloadAlertManagerRoleBinding() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetReader(PrometheusUserWorkloadAlertmanagerRoleBinding))
}

func (f *Factory) PrometheusOperatorClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusOperatorClusterRoleBinding))
}

func (f *Factory) PrometheusOperatorUserWorkloadClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadClusterRoleBinding))
}

func (f *Factory) PrometheusOperatorUserWorkloadCRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadKubeRbacProxySecret))
}

func (f *Factory) PrometheusOperatorClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(PrometheusOperatorClusterRole))
}

func (f *Factory) PrometheusOperatorUserWorkloadClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadClusterRole))
}

func (f *Factory) PrometheusOperatorServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(PrometheusOperatorServiceAccount))
}

func (f *Factory) PrometheusOperatorUserWorkloadServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadServiceAccount))
}

func (f *Factory) PrometheusOperatorRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(PrometheusOperatorKubeRbacProxySecret))
}

func (f *Factory) PrometheusOperatorAdmissionWebhookServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(AdmissionWebhookServiceAccount))
}

func (f *Factory) PrometheusOperatorAdmissionWebhookService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(AdmissionWebhookService))
}

func (f *Factory) PrometheusOperatorAdmissionWebhookPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(AdmissionWebhookPodDisruptionBudget))
}

func (f *Factory) PrometheusOperatorAdmissionWebhookDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(AdmissionWebhookDeployment))
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
		case "prometheus-operator-admission-webhook":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.PrometheusOperatorAdmissionWebhook

			args := d.Spec.Template.Spec.Containers[i].Args
			if f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.LogLevel != "" {
				args = append(args, fmt.Sprintf("--log-level=%s", f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.LogLevel))
			}

			// The admission webhook supports only TLS versions >= 1.2.
			tlsVersionEnforcer := &minTLSVersionEnforcer{
				atLeast: tls.VersionTLS12,
				inner:   f.APIServerConfig,
			}
			args = f.setTLSSecurityConfigurationWithMinTLSVersion(
				args,
				PrometheusOperatorWebTLSCipherSuitesFlag,
				PrometheusOperatorWebTLSMinTLSVersionFlag,
				tlsVersionEnforcer,
			)
			d.Spec.Template.Spec.Containers[i].Args = args
		}
	}
	d.Namespace = f.namespace

	return d, nil
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
			d.Spec.Template.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
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
			d.Spec.Template.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
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

type minTLSVersioner interface {
	MinTLSVersion() string
}

// minTLSVersionEnforcer ensures that a minimal version of TLS is used.
type minTLSVersionEnforcer struct {
	atLeast uint16
	inner   minTLSVersioner
}

// MinTLSVersion implements the minTLSVersioner interface.
func (m *minTLSVersionEnforcer) MinTLSVersion() string {
	v := m.inner.MinTLSVersion()
	if crypto.TLSVersionOrDie(v) < m.atLeast {
		return crypto.TLSVersionToNameOrDie(m.atLeast)
	}

	return v
}

func (f *Factory) setTLSSecurityConfigurationWithMinTLSVersion(args []string, tlsCipherSuitesArg string, minTLSversionArg string, versioner minTLSVersioner) []string {
	cipherSuites := strings.Join(crypto.OpenSSLToIANACipherSuites(f.APIServerConfig.TLSCiphers()), ",")
	args = setArg(args, tlsCipherSuitesArg, cipherSuites)

	args = setArg(args, minTLSversionArg, versioner.MinTLSVersion())

	return args
}

func (f *Factory) setTLSSecurityConfiguration(args []string, tlsCipherSuitesArg string, minTLSversionArg string) []string {
	return f.setTLSSecurityConfigurationWithMinTLSVersion(args, tlsCipherSuitesArg, minTLSversionArg, f.APIServerConfig)
}

func setArg(args []string, argName string, argValue string) []string {
	found := false
	for i, arg := range args {
		if strings.HasPrefix(arg, argName) {
			args[i] = argName + argValue
			found = true
		}
	}

	if !found {
		args = append(args, argName+argValue)
	}

	return args
}

func (f *Factory) PrometheusRuleValidatingWebhook() (*admissionv1.ValidatingWebhookConfiguration, error) {
	return f.NewValidatingWebhook(f.assets.MustNewAssetReader(AdmissionWebhookRuleValidatingWebhook))
}

func (f *Factory) AlertManagerConfigValidatingWebhook() (*admissionv1.ValidatingWebhookConfiguration, error) {
	return f.NewValidatingWebhook(f.assets.MustNewAssetReader(AdmissionWebhookAlertmanagerConfigValidatingWebhook))
}

func (f *Factory) PrometheusOperatorService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(PrometheusOperatorService))
}

func (f *Factory) PrometheusOperatorUserWorkloadService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(PrometheusOperatorUserWorkloadService))
}

func (f *Factory) PrometheusK8sService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(PrometheusK8sService))
}

func (f *Factory) PrometheusK8sServiceThanosSidecar() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(PrometheusK8sServiceThanosSidecar))
}

func (f *Factory) PrometheusK8sPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(PrometheusK8sPodDisruptionBudget))
}

func (f *Factory) PrometheusUserWorkloadPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(PrometheusUserWorkloadPodDisruptionBudget))
}

func (f *Factory) ThanosRulerPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(ThanosRulerPodDisruptionBudget))
}

func (f *Factory) PrometheusUserWorkloadService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(PrometheusUserWorkloadService))
}

func (f *Factory) PrometheusUserWorkloadServiceThanosSidecar() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(PrometheusUserWorkloadServiceThanosSidecar))
}

func (f *Factory) ClusterMonitoringClusterRoleView() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(ClusterMonitoringClusterRoleView))
}

func (f *Factory) ClusterMonitoringRulesEditClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(ClusterMonitoringRulesEditClusterRole))
}

func (f *Factory) ClusterMonitoringRulesViewClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(ClusterMonitoringRulesViewClusterRole))
}

func (f *Factory) ClusterMonitoringEditClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(ClusterMonitoringEditClusterRole))
}

func (f *Factory) ClusterMonitoringAlertingEditClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(ClusterMonitoringEditAlertingClusterRole))
}

func (f *Factory) ClusterMonitoringEditUserWorkloadConfigRole() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetReader(ClusterMonitoringEditUserWorkloadConfigRole))
}

func (f *Factory) ClusterMonitoringAlertManagerEditRole() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetReader(ClusterMonitoringAlertmanagerEditRole))
}

func (f *Factory) ClusterMonitoringOperatorServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(ClusterMonitoringOperatorServiceMonitor))
}

func (f *Factory) ClusterMonitoringOperatorPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(ClusterMonitoringOperatorPrometheusRule))
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
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(ControlPlaneEtcdServiceMonitor))
}

func (f *Factory) ControlPlaneKubeletServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(ControlPlaneKubeletServiceMonitor))
}

func (f *Factory) ControlPlaneKubeletServiceMonitorPA() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(ControlPlaneKubeletServiceMonitorPA))
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
	return NewDaemonSet(manifest)
}

func (f *Factory) NewPodDisruptionBudget(manifest io.Reader) (*policyv1.PodDisruptionBudget, error) {
	if !f.infrastructure.HighlyAvailableInfrastructure() {
		return nil, nil
	}

	return NewPodDisruptionBudget(manifest)
}

func (f *Factory) NewService(manifest io.Reader) (*v1.Service, error) {
	return NewService(manifest)
}

func (f *Factory) NewEndpoints(manifest io.Reader) (*v1.Endpoints, error) {
	return NewEndpoints(manifest)
}

func (f *Factory) NewRoute(manifest io.Reader) (*routev1.Route, error) {
	return NewRoute(manifest)
}

func (f *Factory) NewSecret(manifest io.Reader) (*v1.Secret, error) {
	return NewSecret(manifest)
}

func (f *Factory) NewRoleBinding(manifest io.Reader) (*rbacv1.RoleBinding, error) {
	return NewRoleBinding(manifest)
}

func (f *Factory) NewRoleList(manifest io.Reader) (*rbacv1.RoleList, error) {
	return NewRoleList(manifest)
}

func (f *Factory) NewRoleBindingList(manifest io.Reader) (*rbacv1.RoleBindingList, error) {
	return NewRoleBindingList(manifest)
}

func (f *Factory) NewRole(manifest io.Reader) (*rbacv1.Role, error) {
	return NewRole(manifest)
}

func (f *Factory) NewConfigMap(manifest io.Reader) (*v1.ConfigMap, error) {
	return NewConfigMap(manifest)
}

func (f *Factory) NewConfigMapList(manifest io.Reader) (*v1.ConfigMapList, error) {
	return NewConfigMapList(manifest)
}

func (f *Factory) NewServiceAccount(manifest io.Reader) (*v1.ServiceAccount, error) {
	return NewServiceAccount(manifest)
}

func (f *Factory) NewPrometheus(manifest io.Reader) (*monv1.Prometheus, error) {
	p, err := NewPrometheus(manifest)
	if err != nil {
		return nil, err
	}

	if !f.infrastructure.HighlyAvailableInfrastructure() {
		p.Spec.Replicas = func(i int32) *int32 { return &i }(1)
		p.Spec.Affinity = nil
	}

	return p, nil
}

func (f *Factory) NewPrometheusRule(manifest io.Reader) (*monv1.PrometheusRule, error) {
	return NewPrometheusRule(manifest)
}

func (f *Factory) NewAlertmanager(manifest io.Reader) (*monv1.Alertmanager, error) {
	a, err := NewAlertmanager(manifest)
	if err != nil {
		return nil, err
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
	if !f.infrastructure.HighlyAvailableInfrastructure() {
		err := doubleServiceMonitorInterval(sm)
		if err != nil {
			return nil, err
		}
	}

	return sm, nil
}

func (f *Factory) NewDeployment(manifest io.Reader) (*appsv1.Deployment, error) {
	d, err := NewDeployment(manifest)
	if err != nil {
		return nil, err
	}

	if f.infrastructure.HostedControlPlane() {
		delete(d.Spec.Template.Spec.NodeSelector, nodeSelectorMaster)
	}

	if !f.infrastructure.HighlyAvailableInfrastructure() {
		d.Spec.Replicas = func(i int32) *int32 { return &i }(1)
		d.Spec.Template.Spec.Affinity = nil
	}

	return d, nil
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

func (f *Factory) ThanosQuerierPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetReader(ThanosQuerierPodDisruptionBudget))
}

func (f *Factory) ThanosQuerierDeployment(grpcTLS *v1.Secret, enableUserWorkloadMonitoring bool, trustedCA *v1.ConfigMap) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(ThanosQuerierDeployment))
	if err != nil {
		return nil, err
	}

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
					"--target=dnssrv+_grpc._tcp.prometheus-operated.openshift-user-workload-monitoring.svc.cluster.local",
				)
			}

			if f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.Resources != nil {
				d.Spec.Template.Spec.Containers[i].Resources = *f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.Resources
			}

			if f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.LogLevel != "" {
				d.Spec.Template.Spec.Containers[i].Args = append(d.Spec.Template.Spec.Containers[i].Args, fmt.Sprintf("--log.level=%s", f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.LogLevel))
			}

			if f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.EnableRequestLogging {
				d.Spec.Template.Spec.Containers[i].Args = append(
					d.Spec.Template.Spec.Containers[i].Args,
					fmt.Sprintf("--request.logging-config=%s",
						getThanosQuerierRequestLoggingConf(f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.LogLevel),
					),
				)
			}

		case "prom-label-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.PromLabelProxy

		case "kube-rbac-proxy", "kube-rbac-proxy-rules", "kube-rbac-proxy-metrics":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			d.Spec.Template.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(c.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
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
	return f.NewConfigMap(f.assets.MustNewAssetReader(ThanosQuerierTrustedCABundle))
}

func (f *Factory) ThanosQuerierService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetReader(ThanosQuerierService))
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
	const endpointPort = "metrics"
	for i := range sm.Spec.Endpoints {
		if sm.Spec.Endpoints[i].Port == endpointPort {
			found = true
			sm.Spec.Endpoints[i].TLSConfig.ServerName = fmt.Sprintf("thanos-querier.%s.svc", f.namespace)
		}
	}
	if !found {
		return nil, errors.Errorf("failed to find endpoint port %q", endpointPort)
	}

	return sm, nil
}

func (f *Factory) TelemeterTrustedCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(TelemeterTrustedCABundle))
}

// TelemeterClientServingCertsCABundle generates a new servinc certs CA bundle ConfigMap for TelemeterClient.
func (f *Factory) TelemeterClientServingCertsCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(TelemeterClientServingCertsCABundle))
}

// TelemeterClientClusterRole generates a new ClusterRole for Telemeter client.
func (f *Factory) TelemeterClientClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(TelemeterClientClusterRole))
}

// TelemeterClientClusterRoleBinding generates a new ClusterRoleBinding for Telemeter client.
func (f *Factory) TelemeterClientClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(TelemeterClientClusterRoleBinding))
}

// TelemeterClientClusterRoleBindingView generates a new ClusterRoleBinding for Telemeter client
// for the cluster monitoring view ClusterRole.
func (f *Factory) TelemeterClientClusterRoleBindingView() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(TelemeterClientClusterRoleBindingView))
}

// TelemeterClientServiceMonitor generates a new ServiceMonitor for Telemeter client.
func (f *Factory) TelemeterClientServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(TelemeterClientServiceMonitor))
}

func (f *Factory) TelemeterClientKubeRbacProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(TelemeterClientKubeRbacProxySecret))
}

func (f *Factory) TelemeterClientPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(TelemeterClientPrometheusRule))
}

// TelemeterClientDeployment generates a new Deployment for Telemeter client.
// If the passed ConfigMap is not empty it mounts the Trusted CA Bundle as a VolumeMount to
// /etc/pki/ca-trust/extracted/pem/ location.
func (f *Factory) TelemeterClientDeployment(proxyCABundleCM *v1.ConfigMap, s *v1.Secret) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetReader(TelemeterClientDeployment))
	if err != nil {
		return nil, err
	}

	// Set annotation on deployment to trigger redeployments
	if s != nil {
		hash := sha256.New()
		d.Spec.Template.Annotations["telemeter-token-hash"] = string(hash.Sum(s.Data["token"]))
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
			d.Spec.Template.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
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
	return f.NewService(f.assets.MustNewAssetReader(TelemeterClientService))
}

// TelemeterClientServiceAccount generates a new ServiceAccount for Telemeter client.
func (f *Factory) TelemeterClientServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(TelemeterClientServiceAccount))
}

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
	return f.NewService(f.assets.MustNewAssetReader(ThanosRulerService))
}

func (f *Factory) ThanosRulerServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetReader(ThanosRulerServiceAccount))
}

func (f *Factory) ThanosRulerClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(ThanosRulerClusterRoleBinding))
}

func (f *Factory) ThanosRulerMonitoringClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetReader(ThanosRulerMonitoringClusterRoleBinding))
}

func (f *Factory) ThanosRulerClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetReader(ThanosRulerClusterRole))
}

func (f *Factory) ThanosRulerPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetReader(ThanosRulerPrometheusRule))
}

func (f *Factory) ThanosRulerAlertManagerRoleBinding() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetReader(ThanosRulerAlertmanagerRoleBinding))
}

func (f *Factory) ThanosRulerServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetReader(ThanosRulerServiceMonitor))
}

func (f *Factory) ThanosRulerRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetReader(ThanosRulerRoute))
}

func (f *Factory) ThanosRulerTrustedCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetReader(ThanosRulerTrustedCABundle))
}

func (f *Factory) ThanosRulerGrpcTLSSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(ThanosRulerGrpcTLSSecret))
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

func (f *Factory) ThanosRulerRBACProxyMetricsSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetReader(ThanosRulerRBACProxyMetricsSecret))
}

func (f *Factory) ThanosRulerCustomResource(
	queryURL string,
	trustedCA *v1.ConfigMap,
	grpcTLS *v1.Secret,
	alertmanagerConfig *v1.Secret,
) (*monv1.ThanosRuler, error) {
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

	if f.config.UserWorkloadConfiguration.ThanosRuler.Retention != "" {
		t.Spec.Retention = monv1.Duration(f.config.UserWorkloadConfiguration.ThanosRuler.Retention)
	}

	if len(f.config.UserWorkloadConfiguration.ThanosRuler.TopologySpreadConstraints) > 0 {
		t.Spec.TopologySpreadConstraints = f.config.UserWorkloadConfiguration.ThanosRuler.TopologySpreadConstraints
	}

	if len(f.config.UserWorkloadConfiguration.ThanosRuler.Tolerations) > 0 {
		t.Spec.Tolerations = f.config.UserWorkloadConfiguration.ThanosRuler.Tolerations
	}

	if f.config.UserWorkloadConfiguration.Prometheus.ExternalLabels != nil {
		t.Spec.Labels = f.config.UserWorkloadConfiguration.Prometheus.ExternalLabels
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
		case "kube-rbac-proxy-metrics":
			t.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			t.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
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

	f.mountThanosRulerAlertmanagerSecrets(t)
	f.injectThanosRulerAlertmanagerDigest(t, alertmanagerConfig)

	if queryURL != "" {
		t.Spec.AlertQueryURL = queryURL
	}

	t.Namespace = f.namespaceUserWorkload

	return t, nil
}

func (f *Factory) mountThanosRulerAlertmanagerSecrets(t *monv1.ThanosRuler) {
	amAuthSecrets := getAdditionalAlertmanagerSecrets(f.config.GetThanosRulerAlertmanagerConfigs())
	if len(amAuthSecrets) == 0 {
		return
	}

	var volumeMounts []v1.VolumeMount
	var volumes []v1.Volume
	for i, secret := range amAuthSecrets {
		volumeName := fmt.Sprintf("alertmanager-additional-config-secret-%d", i)
		volumes = append(volumes, v1.Volume{
			Name: volumeName,
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: secret,
				},
			},
		})

		volumeMounts = append(volumeMounts, v1.VolumeMount{
			Name:      volumeName,
			MountPath: "/etc/prometheus/secrets/" + secret,
		})
	}

	t.Spec.Volumes = append(t.Spec.Volumes, volumes...)
	for i, _ := range t.Spec.Containers {
		containerName := t.Spec.Containers[i].Name
		if containerName == "thanos-ruler" {
			t.Spec.Containers[i].VolumeMounts = append(t.Spec.Containers[i].VolumeMounts, volumeMounts...)
		}
	}
}

func (f *Factory) injectThanosRulerAlertmanagerDigest(t *monv1.ThanosRuler, alertmanagerConfig *v1.Secret) {
	digest := ""
	if alertmanagerConfig == nil {
		return
	}
	digestBytes := md5.Sum([]byte(alertmanagerConfig.StringData["alertmanagers.yaml"]))
	digest = fmt.Sprintf("%x", digestBytes)
	for i, _ := range t.Spec.Containers {
		containerName := t.Spec.Containers[i].Name
		if containerName == "thanos-ruler" {
			// Thanos ruler does not refresh its config when the alertmanagers secret changes.
			// Because of this, we need to redeploy the statefulset
			// whenever there is a change in the data of the secret.
			t.Spec.Containers[i].Env = append(t.Spec.Containers[i].Env, v1.EnvVar{
				Name:  "ALERTMANAGER_CONFIG_SECRET_VERSION",
				Value: digest,
			})
		}
	}
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

func addRemoteWriteConfigs(clusterID string, rw []monv1.RemoteWriteSpec, rwTargets ...RemoteWriteSpec) []monv1.RemoteWriteSpec {
	clusterIDRelabelConfig := []monv1.RelabelConfig{
		{
			TargetLabel: tmpClusterIDLabelName,
			Replacement: clusterID,
		},
	}
	tmpRelabelDrop := monv1.RelabelConfig{
		Regex:  tmpClusterIDLabelName,
		Action: "labeldrop",
	}

	for _, target := range rwTargets {
		// prepend our temporary cluster id label
		writeRelabelConfigs := append(clusterIDRelabelConfig, target.WriteRelabelConfigs...)
		// and append the drop rule for our temporary cluster id
		writeRelabelConfigs = append(writeRelabelConfigs, tmpRelabelDrop)
		rwConf := monv1.RemoteWriteSpec{
			URL:                 target.URL,
			Name:                target.Name,
			RemoteTimeout:       monv1.Duration(target.RemoteTimeout),
			Headers:             target.Headers,
			QueueConfig:         target.QueueConfig,
			WriteRelabelConfigs: writeRelabelConfigs,
			BasicAuth:           target.BasicAuth,
			BearerTokenFile:     target.BearerTokenFile,
			Sigv4:               target.Sigv4,
			ProxyURL:            target.ProxyURL,
			MetadataConfig:      target.MetadataConfig,
			OAuth2:              target.OAuth2,
		}
		if target.TLSConfig != nil {
			rwConf.TLSConfig = &monv1.TLSConfig{
				SafeTLSConfig: *target.TLSConfig,
			}
		}
		if target.Authorization != nil {
			rwConf.Authorization = &monv1.Authorization{
				SafeAuthorization: *target.Authorization,
			}
		}
		rw = append(rw, rwConf)
	}
	return rw
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

func getAdditionalAlertmanagerSecrets(alertmanagerConfigs []AdditionalAlertmanagerConfig) []string {
	secretsName := []string{}

	for _, alertmanagerConfig := range alertmanagerConfigs {
		if alertmanagerConfig.TLSConfig.CA != nil {
			secretsName = append(secretsName, alertmanagerConfig.TLSConfig.CA.Name)
		}
		if alertmanagerConfig.TLSConfig.Cert != nil {
			secretsName = append(secretsName, alertmanagerConfig.TLSConfig.Cert.Name)
		}
		if alertmanagerConfig.TLSConfig.Key != nil {
			secretsName = append(secretsName, alertmanagerConfig.TLSConfig.Key.Name)
		}
		if alertmanagerConfig.BearerToken != nil {
			secretsName = append(secretsName, alertmanagerConfig.BearerToken.Name)
		}
	}

	return removeEmptyDuplicates(secretsName)
}

func removeEmptyDuplicates(elements []string) []string {
	encountered := map[string]struct{}{}
	result := []string{}

	for _, v := range elements {
		if _, found := encountered[v]; found {
			continue
		}

		encountered[v] = struct{}{}
		if v != "" {
			// Append to result slice if it is not empty
			result = append(result, v)
		}
	}

	// Return the new slice.
	return result
}

func getThanosQuerierRequestLoggingConf(logLevel string) string {
	switch logLevel {
	case "debug":
		logLevel = "DEBUG"
	case "info":
		logLevel = "INFO"
	case "warn":
		logLevel = "WARNING"
	case "error":
		logLevel = "ERROR"
	default:
		logLevel = "ERROR"
	}

	return fmt.Sprintf(`http:
  options:
    level: %s
    decision:
      log_start: false
      log_end: true
grpc:
  options:
    level: %s
    decision:
      log_start: false
      log_end: true`, logLevel, logLevel)
}

// doubleServiceMonitorInterval doubles every ServiceMonitor endpoint interval value,
// but the maximum value is 2 minutes.
func doubleServiceMonitorInterval(sm *monv1.ServiceMonitor) error {
	for i := range sm.Spec.Endpoints {
		e := &sm.Spec.Endpoints[i]
		if e.Interval != "" {
			intervalTime, err := time.ParseDuration(string(e.Interval))
			if err != nil {
				return err
			}
			updatedInterval := intervalTime * 2
			if updatedInterval > 2*time.Minute {
				updatedInterval = 2 * time.Minute
			}
			e.Interval = monv1.Duration(updatedInterval.String())
		}
	}
	return nil
}
