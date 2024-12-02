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
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	consolev1 "github.com/openshift/api/console/v1"
	routev1 "github.com/openshift/api/route/v1"
	securityv1 "github.com/openshift/api/security/v1"
	"github.com/openshift/library-go/pkg/crypto"
	mon "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	yaml2 "gopkg.in/yaml.v2"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/utils/ptr"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/openshift/cluster-monitoring-operator/pkg/promqlgen"
)

const (
	configManagedNamespace = "openshift-config-managed"
	sharedConfigMap        = "monitoring-shared-config"

	tmpClusterIDLabelName = "__tmp_openshift_cluster_id__"

	nodeSelectorMaster = "node-role.kubernetes.io/master"

	userMonitoringLabel    = "openshift.io/user-monitoring"
	clusterMonitoringLabel = "openshift.io/cluster-monitoring"

	platformAlertmanagerService     = "alertmanager-main"
	userWorkloadAlertmanagerService = "alertmanager-user-workload"

	telemetryTokenSecretKey = "token"

	collectionProfileLabel = "monitoring.openshift.io/collection-profile"

	// --enable-feature=exemplar-storage: https://prometheus.io/docs/prometheus/latest/feature_flags/#exemplars-storage
	EnableFeatureExemplarStorageString = "exemplar-storage"

	DescriptionAnnotation    = "openshift.io/description"
	TestFilePlacehoderPrefix = "xx_omitted_before_deploy__test_file_name:"
)

var (
	AlertmanagerConfig                = "alertmanager/secret.yaml"
	AlertmanagerService               = "alertmanager/service.yaml"
	AlertmanagerMain                  = "alertmanager/alertmanager.yaml"
	AlertmanagerServiceAccount        = "alertmanager/service-account.yaml"
	AlertmanagerClusterRoleBinding    = "alertmanager/cluster-role-binding.yaml"
	AlertmanagerClusterRole           = "alertmanager/cluster-role.yaml"
	AlertmanagerRBACProxySecret       = "alertmanager/kube-rbac-proxy-secret.yaml"
	AlertmanagerRBACProxyMetricSecret = "alertmanager/kube-rbac-proxy-metric-secret.yaml"
	AlertmanagerRBACProxyWebSecret    = "alertmanager/kube-rbac-proxy-web-secret.yaml"
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
	AlertmanagerUserWorkloadRBACProxySecret        = "alertmanager-user-workload/kube-rbac-proxy-secret.yaml"
	AlertmanagerUserWorkloadRBACProxyTenancySecret = "alertmanager-user-workload/kube-rbac-proxy-tenancy-secret.yaml"
	AlertmanagerUserWorkloadRBACProxyMetricSecret  = "alertmanager-user-workload/kube-rbac-proxy-metric-secret.yaml"
	AlertmanagerUserWorkloadTrustedCABundle        = "alertmanager-user-workload/trusted-ca-bundle.yaml"
	AlertmanagerUserWorkloadPodDisruptionBudget    = "alertmanager-user-workload/pod-disruption-budget.yaml"
	AlertmanagerUserWorkloadServiceMonitor         = "alertmanager-user-workload/service-monitor.yaml"

	KubeStateMetricsClusterRoleBinding    = "kube-state-metrics/cluster-role-binding.yaml"
	KubeStateMetricsClusterRole           = "kube-state-metrics/cluster-role.yaml"
	KubeStateMetricsDeployment            = "kube-state-metrics/deployment.yaml"
	KubeStateMetricsServiceAccount        = "kube-state-metrics/service-account.yaml"
	KubeStateMetricsService               = "kube-state-metrics/service.yaml"
	KubeStateMetricsServiceMonitor        = "kube-state-metrics/service-monitor.yaml"
	KubeStateMetricsMinimalServiceMonitor = "kube-state-metrics/minimal-service-monitor.yaml"
	KubeStateMetricsPrometheusRule        = "kube-state-metrics/prometheus-rule.yaml"
	KubeStateMetricsKubeRbacProxySecret   = "kube-state-metrics/kube-rbac-proxy-secret.yaml"
	KubeStateMetricsCRSConfig             = "kube-state-metrics/custom-resource-state-configmap.yaml"

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
	NodeExporterMinimalServiceMonitor      = "node-exporter/minimal-service-monitor.yaml"
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
	PrometheusK8sRBACProxyWebSecret               = "prometheus-k8s/kube-rbac-proxy-web-secret.yaml"
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

	PrometheusUserWorkloadServingCertsCABundle                = "prometheus-user-workload/serving-certs-ca-bundle.yaml"
	PrometheusUserWorkloadTrustedCABundle                     = "prometheus-user-workload/trusted-ca-bundle.yaml"
	PrometheusUserWorkloadServiceAccount                      = "prometheus-user-workload/service-account.yaml"
	PrometheusUserWorkloadClusterRole                         = "prometheus-user-workload/cluster-role.yaml"
	PrometheusUserWorkloadClusterRoleBinding                  = "prometheus-user-workload/cluster-role-binding.yaml"
	PrometheusUserWorkloadAlertmanagerUserWorkloadRoleBinding = "prometheus-user-workload/alertmanager-user-workload-role-binding.yaml"
	PrometheusUserWorkloadRoleConfig                          = "prometheus-user-workload/role-config.yaml"
	PrometheusUserWorkloadRoleList                            = "prometheus-user-workload/role-specific-namespaces.yaml"
	PrometheusUserWorkloadRoleBindingList                     = "prometheus-user-workload/role-binding-specific-namespaces.yaml"
	PrometheusUserWorkloadRoleBindingConfig                   = "prometheus-user-workload/role-binding-config.yaml"
	PrometheusUserWorkloadService                             = "prometheus-user-workload/service.yaml"
	PrometheusUserWorkloadServiceThanosSidecar                = "prometheus-user-workload/service-thanos-sidecar.yaml"
	PrometheusUserWorkload                                    = "prometheus-user-workload/prometheus.yaml"
	PrometheusUserWorkloadPrometheusServiceMonitor            = "prometheus-user-workload/service-monitor.yaml"
	PrometheusUserWorkloadGrpcTLSSecret                       = "prometheus-user-workload/grpc-tls-secret.yaml"
	PrometheusUserWorkloadThanosSidecarServiceMonitor         = "prometheus-user-workload/service-monitor-thanos-sidecar.yaml"
	PrometheusUserWorkloadAlertmanagerRoleBinding             = "prometheus-user-workload/alertmanager-role-binding.yaml"
	PrometheusUserWorkloadPodDisruptionBudget                 = "prometheus-user-workload/pod-disruption-budget.yaml"
	PrometheusUserWorkloadConfigMap                           = "prometheus-user-workload/config-map.yaml"
	PrometheusUserWorkloadFederateRoute                       = "prometheus-user-workload/federate-route.yaml"

	MetricsServerAPIService                      = "metrics-server/api-service.yaml"
	MetricsServerServiceAccount                  = "metrics-server/service-account.yaml"
	MetricsServerClusterRole                     = "metrics-server/cluster-role.yaml"
	MetricsServerClusterRoleBinding              = "metrics-server/cluster-role-binding.yaml"
	MetricsServerClusterRoleBindingAuthDelegator = "metrics-server/cluster-role-binding-auth-delegator.yaml"
	MetricsServerRoleBindingAuthReader           = "metrics-server/role-binding-auth-reader.yaml"
	MetricsServerConfigMapAuditPolicy            = "metrics-server/configmap-audit-profiles.yaml"
	MetricsServerDeployment                      = "metrics-server/deployment.yaml"
	MetricsServerService                         = "metrics-server/service.yaml"
	MetricsServerServiceMonitor                  = "metrics-server/service-monitor.yaml"
	MetricsServerPodDisruptionBudget             = "metrics-server/pod-disruption-budget.yaml"

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
	PrometheusOperatorPrometheusRule      = "prometheus-operator/prometheus-rule.yaml"
	PrometheusOperatorKubeRbacProxySecret = "prometheus-operator/kube-rbac-proxy-secret.yaml"

	PrometheusOperatorUserWorkloadServiceAccount      = "prometheus-operator-user-workload/service-account.yaml"
	PrometheusOperatorUserWorkloadClusterRole         = "prometheus-operator-user-workload/cluster-role.yaml"
	PrometheusOperatorUserWorkloadClusterRoleBinding  = "prometheus-operator-user-workload/cluster-role-binding.yaml"
	PrometheusOperatorUserWorkloadService             = "prometheus-operator-user-workload/service.yaml"
	PrometheusOperatorUserWorkloadDeployment          = "prometheus-operator-user-workload/deployment.yaml"
	PrometheusOperatorUserWorkloadServiceMonitor      = "prometheus-operator-user-workload/service-monitor.yaml"
	PrometheusOperatorUserWorkloadKubeRbacProxySecret = "prometheus-operator-user-workload/kube-rbac-proxy-secret.yaml"

	ClusterMonitoringOperatorServiceMonitor                = "cluster-monitoring-operator/service-monitor.yaml"
	ClusterMonitoringClusterRoleView                       = "cluster-monitoring-operator/cluster-role-view.yaml"
	ClusterMonitoringClusterRoleAggregatedMetricsReader    = "cluster-monitoring-operator/cluster-role-aggregated-metrics-reader.yaml"
	ClusterMonitoringClusterRolePodMetricsReader           = "cluster-monitoring-operator/cluster-role-pod-metrics-reader.yaml"
	ClusterMonitoringAlertmanagerViewRole                  = "cluster-monitoring-operator/monitoring-alertmanager-view-role.yaml"
	ClusterMonitoringAlertmanagerEditRole                  = "cluster-monitoring-operator/monitoring-alertmanager-edit-role.yaml"
	ClusterMonitoringApiReaderRole                         = "cluster-monitoring-operator/cluster-monitoring-api-role.yaml"
	ClusterMonitoringRulesEditClusterRole                  = "cluster-monitoring-operator/monitoring-rules-edit-cluster-role.yaml"
	ClusterMonitoringRulesViewClusterRole                  = "cluster-monitoring-operator/monitoring-rules-view-cluster-role.yaml"
	ClusterMonitoringEditClusterRole                       = "cluster-monitoring-operator/monitoring-edit-cluster-role.yaml"
	ClusterMonitoringEditAlertingClusterRole               = "cluster-monitoring-operator/alerting-edit-cluster-role.yaml"
	ClusterMonitoringEditUserWorkloadConfigRole            = "cluster-monitoring-operator/user-workload-config-edit-role.yaml"
	ClusterMonitoringEditUserWorkloadAlertmanagerApiReader = "cluster-monitoring-operator/user-workload-alertmanager-api-reader.yaml"
	ClusterMonitoringEditUserWorkloadAlertmanagerApiWriter = "cluster-monitoring-operator/user-workload-alertmanager-api-writer.yaml"
	ClusterMonitoringGrpcTLSSecret                         = "cluster-monitoring-operator/grpc-tls-secret.yaml"
	ClusterMonitoringOperatorPrometheusRule                = "cluster-monitoring-operator/prometheus-rule.yaml"
	ClusterMonitoringMetricsClientCertsSecret              = "cluster-monitoring-operator/metrics-client-certs.yaml"
	ClusterMonitoringFederateClientCertsSecret             = "cluster-monitoring-operator/federate-client-certs.yaml"
	ClusterMonitoringMetricsClientCACM                     = "cluster-monitoring-operator/metrics-client-ca.yaml"

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
	ThanosQuerierRBACProxySecret        = "thanos-querier/kube-rbac-proxy-secret.yaml"
	ThanosQuerierRBACProxyRulesSecret   = "thanos-querier/kube-rbac-proxy-rules-secret.yaml"
	ThanosQuerierRBACProxyMetricsSecret = "thanos-querier/kube-rbac-proxy-metric-secret.yaml"
	ThanosQuerierRBACProxyWebSecret     = "thanos-querier/kube-rbac-proxy-web-secret.yaml"
	ThanosQuerierServiceAccount         = "thanos-querier/service-account.yaml"
	ThanosQuerierClusterRole            = "thanos-querier/cluster-role.yaml"
	ThanosQuerierClusterRoleBinding     = "thanos-querier/cluster-role-binding.yaml"
	ThanosQuerierGrpcTLSSecret          = "thanos-querier/grpc-tls-secret.yaml"

	ThanosRulerCustomResource                                = "thanos-ruler/thanos-ruler.yaml"
	ThanosRulerService                                       = "thanos-ruler/service.yaml"
	ThanosRulerRoute                                         = "thanos-ruler/route.yaml"
	ThanosRulerQueryConfigSecret                             = "thanos-ruler/query-config-secret.yaml"
	ThanosRulerAlertmanagerConfigSecret                      = "thanos-ruler/alertmanagers-config-secret.yaml"
	ThanosRulerRBACProxyMetricsSecret                        = "thanos-ruler/kube-rbac-proxy-metrics-secret.yaml"
	ThanosRulerRBACProxyWebSecret                            = "thanos-ruler/kube-rbac-proxy-web-secret.yaml"
	ThanosRulerServiceAccount                                = "thanos-ruler/service-account.yaml"
	ThanosRulerClusterRole                                   = "thanos-ruler/cluster-role.yaml"
	ThanosRulerClusterRoleBinding                            = "thanos-ruler/cluster-role-binding.yaml"
	ThanosRulerMonitoringClusterRoleBinding                  = "thanos-ruler/cluster-role-binding-monitoring.yaml"
	ThanosRulerMonitoringAlertmanagerUserWorkloadRoleBinding = "thanos-ruler/alertmanager-user-workload-role-binding.yaml"
	ThanosRulerGrpcTLSSecret                                 = "thanos-ruler/grpc-tls-secret.yaml"
	ThanosRulerServiceMonitor                                = "thanos-ruler/service-monitor.yaml"
	ThanosRulerPrometheusRule                                = "thanos-ruler/thanos-ruler-prometheus-rule.yaml"
	ThanosRulerAlertmanagerRoleBinding                       = "thanos-ruler/alertmanager-role-binding.yaml"
	ThanosRulerPodDisruptionBudget                           = "thanos-ruler/pod-disruption-budget.yaml"

	TelemeterTrustedCABundle = "telemeter-client/trusted-ca-bundle.yaml"

	ControlPlanePrometheusRule               = "control-plane/prometheus-rule.yaml"
	ControlPlaneKubeletServiceMonitor        = "control-plane/service-monitor-kubelet.yaml"
	ControlPlaneKubeletMinimalServiceMonitor = "control-plane/minimal-service-monitor-kubelet.yaml"

	MonitoringPlugin                    = "monitoring-plugin/console-plugin.yaml"
	MonitoringPluginDeployment          = "monitoring-plugin/deployment.yaml"
	MonitoringPluginDeploymentContainer = "monitoring-plugin"
	MonitoringPluginServiceAccount      = "monitoring-plugin/service-account.yaml"
	MonitoringPluginService             = "monitoring-plugin/service.yaml"
	MonitoringPluginPodDisruptionBudget = "monitoring-plugin/pod-disruption-budget.yaml"
)

var (
	PrometheusConfigReloaderFlag                         = "--prometheus-config-reloader="
	PrometheusOperatorPrometheusInstanceNamespacesFlag   = "--prometheus-instance-namespaces="
	PrometheusOperatorAlertmanagerInstanceNamespacesFlag = "--alertmanager-instance-namespaces="
	PrometheusOperatorWebTLSCipherSuitesFlag             = "--web.tls-cipher-suites="
	PrometheusOperatorWebTLSMinTLSVersionFlag            = "--web.tls-min-version="
	MetricsServerTLSCipherSuitesFlag                     = "--tls-cipher-suites="
	MetricsServerTLSMinTLSVersionFlag                    = "--tls-min-version="
	KubeRbacProxyTLSCipherSuitesFlag                     = "--tls-cipher-suites="
	KubeRbacProxyMinTLSVersionFlag                       = "--tls-min-version="

	kubeStateMetricsCustomResourceStateConfigFileFlag = "--custom-resource-state-config-file="
	kubeStateMetricsCustomResourceStateConfigFile     = "/etc/kube-state-metrics/custom-resource-state-configmap.yaml"

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

func NewFactory(
	namespace, namespaceUserWorkload string,
	c *Config,
	infrastructure InfrastructureReader,
	proxy ProxyReader,
	a *Assets,
	apiServerConfig *APIServerConfig,
	consoleConfig *configv1.Console,
) *Factory {
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
	return f.NewSecret(f.assets.MustNewAssetSlice(AlertmanagerConfig))
}

func (f *Factory) AlertmanagerUserWorkloadSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadSecret))
}

func (f *Factory) AlertmanagerService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(AlertmanagerService))
}

func (f *Factory) AlertmanagerUserWorkloadService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadService))
}

func (f *Factory) AlertmanagerServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(AlertmanagerServiceAccount))
}

func (f *Factory) AlertmanagerUserWorkloadServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadServiceAccount))
}

func (f *Factory) AlertmanagerClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(AlertmanagerClusterRoleBinding))
}

func (f *Factory) AlertmanagerUserWorkloadClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadClusterRoleBinding))
}

func (f *Factory) AlertmanagerClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(AlertmanagerClusterRole))
}

func (f *Factory) AlertmanagerUserWorkloadClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadClusterRole))
}

func (f *Factory) AlertmanagerServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(AlertmanagerServiceMonitor))
}

func (f *Factory) AlertmanagerUserWorkloadServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadServiceMonitor))
}

func (f *Factory) AlertmanagerTrustedCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetSlice(AlertmanagerTrustedCABundle))
}

func (f *Factory) AlertmanagerUserWorkloadTrustedCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadTrustedCABundle))
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

func (f *Factory) AlertmanagerUserWorkload() (*monv1.Alertmanager, error) {
	a, err := f.NewAlertmanager(f.assets.MustNewAssetSlice(AlertmanagerUserWorkload))
	if err != nil {
		return nil, err
	}

	a.Spec.Image = &f.config.Images.Alertmanager

	// TODO(simonpasquier): link to the alerting page of the dev console. It
	// depends on https://issues.redhat.com/browse/MON-2289.
	alertGeneratorURL, err := makeConsoleURL(f.consoleConfig, "monitoring")
	if err != nil {
		return nil, err
	}
	a.Spec.ExternalURL = alertGeneratorURL

	alertmanagerConfig := f.config.UserWorkloadConfiguration.Alertmanager

	if alertmanagerConfig.LogLevel != "" {
		a.Spec.LogLevel = alertmanagerConfig.LogLevel
	}

	if alertmanagerConfig.Resources != nil {
		a.Spec.Resources = *alertmanagerConfig.Resources
	}

	a.Spec.Secrets = append(a.Spec.Secrets, alertmanagerConfig.Secrets...)

	if alertmanagerConfig.EnableAlertmanagerConfig {
		a.Spec.AlertmanagerConfigSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      userMonitoringLabel,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"false"},
				},
			},
		}
		a.Spec.AlertmanagerConfigNamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      clusterMonitoringLabel,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"true"},
				},
				{
					Key:      userMonitoringLabel,
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

	if len(alertmanagerConfig.TopologySpreadConstraints) > 0 {
		a.Spec.TopologySpreadConstraints =
			alertmanagerConfig.TopologySpreadConstraints
	}

	for i, c := range a.Spec.Containers {
		switch c.Name {
		case "alertmanager":
			f.injectProxyVariables(&a.Spec.Containers[i])
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

	for i := range a.Spec.Containers {
		if a.Spec.Containers[i].Name != "alertmanager" {
			continue
		}

		a.Spec.Containers[i].StartupProbe = &v1.Probe{
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
		}
	}
}

func (f *Factory) AlertmanagerMain() (*monv1.Alertmanager, error) {
	a, err := f.NewAlertmanager(f.assets.MustNewAssetSlice(AlertmanagerMain))
	if err != nil {
		return nil, err
	}

	a.Spec.Image = &f.config.Images.Alertmanager

	alertGeneratorURL, err := makeConsoleURL(f.consoleConfig, "monitoring")
	if err != nil {
		return nil, err
	}
	a.Spec.ExternalURL = alertGeneratorURL

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.LogLevel != "" {
		a.Spec.LogLevel = f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.LogLevel
	}

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Resources != nil {
		a.Spec.Resources = *f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Resources
	}

	a.Spec.Secrets = append(a.Spec.Secrets, f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.Secrets...)

	if f.config.ClusterMonitoringConfiguration.AlertmanagerMainConfig.EnableUserAlertManagerConfig &&
		!f.config.UserWorkloadConfiguration.Alertmanager.Enabled {
		a.Spec.AlertmanagerConfigSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      userMonitoringLabel,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"false"},
				},
			},
		}

		a.Spec.AlertmanagerConfigNamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      clusterMonitoringLabel,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"true"},
				},
				{
					Key:      userMonitoringLabel,
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
		case "alertmanager":
			f.injectProxyVariables(&a.Spec.Containers[i])
		case "kube-rbac-proxy", "kube-rbac-proxy-metric", "kube-rbac-proxy-web":
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
	return f.NewSecret(f.assets.MustNewAssetSlice(AlertmanagerRBACProxySecret))
}

func (f *Factory) AlertmanagerUserWorkloadRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadRBACProxySecret))
}

func (f *Factory) AlertmanagerUserWorkloadRBACProxyTenancySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadRBACProxyTenancySecret))
}

func (f *Factory) AlertmanagerRBACProxyMetricSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(AlertmanagerRBACProxyMetricSecret))
}

func (f *Factory) AlertmanagerRBACProxyWebSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(AlertmanagerRBACProxyWebSecret))
}

func (f *Factory) AlertmanagerUserWorkloadRBACProxyMetricSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadRBACProxyMetricSecret))
}

func (f *Factory) AlertmanagerRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetSlice(AlertmanagerRoute))
}

func (f *Factory) AlertmanagerPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetSlice(AlertmanagerPrometheusRule))
}

func (f *Factory) KubeStateMetricsClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(KubeStateMetricsClusterRoleBinding))
}

func (f *Factory) AlertmanagerPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetSlice(AlertmanagerPodDisruptionBudget))
}

func (f *Factory) AlertmanagerUserWorkloadPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetSlice(AlertmanagerUserWorkloadPodDisruptionBudget))
}

func (f *Factory) KubeStateMetricsClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(KubeStateMetricsClusterRole))
}

func (f *Factory) KubeStateMetricsServiceMonitors() ([]*monv1.ServiceMonitor, error) {
	return serviceMonitors(f.config.CollectionProfilesFeatureGateEnabled, f.KubeStateMetricsServiceMonitor, f.KubeStateMetricsMinimalServiceMonitor)
}

func (f *Factory) KubeStateMetricsServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(KubeStateMetricsServiceMonitor))
}

func (f *Factory) KubeStateMetricsMinimalServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(KubeStateMetricsMinimalServiceMonitor))
}

func (f *Factory) KubeStateMetricsDeployment(enableCRSMetrics bool) (*appsv1.Deployment, error) {
	flagCRSConfigFile := kubeStateMetricsCustomResourceStateConfigFileFlag + kubeStateMetricsCustomResourceStateConfigFile
	d, err := f.NewDeployment(f.assets.MustNewAssetSlice(KubeStateMetricsDeployment))
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
			if f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Resources != nil {
				d.Spec.Template.Spec.Containers[i].Resources = *f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Resources
			}
			if enableCRSMetrics {
				d.Spec.Template.Spec.Containers[i].Args = append(container.Args, flagCRSConfigFile)
			}
		}
	}

	if f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.NodeSelector != nil {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.Tolerations
	}

	if len(f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.TopologySpreadConstraints) > 0 {
		d.Spec.Template.Spec.TopologySpreadConstraints = f.config.ClusterMonitoringConfiguration.KubeStateMetricsConfig.TopologySpreadConstraints
	}

	return d, nil
}

func (f *Factory) KubeStateMetricsServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(KubeStateMetricsServiceAccount))
}

func (f *Factory) KubeStateMetricsService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(KubeStateMetricsService))
}

func (f *Factory) KubeStateMetricsRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(KubeStateMetricsKubeRbacProxySecret))
}

func (f *Factory) KubeStateMetricsPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetSlice(KubeStateMetricsPrometheusRule))
}

func (f *Factory) KubeStateMetricsCRSConfigMap() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetSlice(KubeStateMetricsCRSConfig))
}

func (f *Factory) OpenShiftStateMetricsClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(OpenShiftStateMetricsClusterRoleBinding))
}

func (f *Factory) OpenShiftStateMetricsClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(OpenShiftStateMetricsClusterRole))
}

func (f *Factory) OpenShiftStateMetricsServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(OpenShiftStateMetricsServiceMonitor))
}

func (f *Factory) OpenShiftStateMetricsDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetSlice(OpenShiftStateMetricsDeployment))
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
			if f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.Resources != nil {
				d.Spec.Template.Spec.Containers[i].Resources = *f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.Resources
			}
		}
	}

	if f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.NodeSelector != nil {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.Tolerations
	}
	if len(f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.TopologySpreadConstraints) > 0 {
		d.Spec.Template.Spec.TopologySpreadConstraints =
			f.config.ClusterMonitoringConfiguration.OpenShiftMetricsConfig.TopologySpreadConstraints
	}
	d.Namespace = f.namespace

	return d, nil
}

func (f *Factory) OpenShiftStateMetricsServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(OpenShiftStateMetricsServiceAccount))
}

func (f *Factory) OpenShiftStateMetricsService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(OpenShiftStateMetricsService))
}

func (f *Factory) OpenShiftStateMetricsRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(OpenShiftStateMetricsKubeRbacProxySecret))
}

func (f *Factory) NodeExporterServiceMonitors() ([]*monv1.ServiceMonitor, error) {
	return serviceMonitors(f.config.CollectionProfilesFeatureGateEnabled, f.NodeExporterServiceMonitor, f.NodeExporterMinimalServiceMonitor)
}

func (f *Factory) NodeExporterServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(NodeExporterServiceMonitor))
}

func (f *Factory) updateNodeExporterArgs(args []string) ([]string, error) {
	args = setArg(args, fmt.Sprintf("--runtime.gomaxprocs=%d", f.config.ClusterMonitoringConfiguration.NodeExporterConfig.MaxProcs), "")
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

	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Sysctl.Enabled {
		includeSysctlMetrics := f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Sysctl.IncludeSysctlMetrics
		includeInfoSysctlMetrics := f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Sysctl.IncludeInfoSysctlMetrics

		args = setArg(args, "--collector.sysctl", "")

		sysctlSet := uniqueSet(includeSysctlMetrics)
		for _, sysctl := range sysctlSet {
			args = append(args, fmt.Sprintf("--collector.sysctl.include=%s", sysctl))
		}

		sysctlSet = uniqueSet(includeInfoSysctlMetrics)
		for _, sysctl := range sysctlSet {
			args = append(args, fmt.Sprintf("--collector.sysctl.include-info=%s", sysctl))
		}
	} else {
		args = setArg(args, "--no-collector.sysctl", "")
	}

	var excludedDevices string
	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.NetDev.Enabled ||
		f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.NetClass.Enabled {
		devs := *f.config.ClusterMonitoringConfiguration.NodeExporterConfig.IgnoredNetworkDevices
		// An empty list generates a regular expression matching empty strings: `^()$`
		// It is therefore preferable not to set the exclusion regex at all.
		if len(devs) > 0 {
			var err error
			excludedDevices, err = regexListToArg(devs)
			if err != nil {
				return nil, fmt.Errorf("invalid regexp in config nodeExporter.ignoredNetworkDevices: %w", err)
			}
		}
	}

	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.NetDev.Enabled {
		args = setArg(args, "--collector.netdev", "")
		args = setArg(args, "--collector.netdev.device-exclude=", excludedDevices)
	} else {
		args = setArg(args, "--no-collector.netdev", "")
	}

	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.NetClass.Enabled {
		args = setArg(args, "--collector.netclass", "")
		if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.NetClass.UseNetlink {
			args = setArg(args, "--collector.netclass.netlink", "")
		}
		args = setArg(args, "--collector.netclass.ignored-devices=", excludedDevices)
	} else {
		args = setArg(args, "--no-collector.netclass", "")
	}

	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.BuddyInfo.Enabled {
		args = setArg(args, "--collector.buddyinfo", "")
	} else {
		args = setArg(args, "--no-collector.buddyinfo", "")
	}

	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.MountStats.Enabled {
		args = setArg(args, "--collector.mountstats", "")
	} else {
		args = setArg(args, "--no-collector.mountstats", "")
	}

	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Ksmd.Enabled {
		args = setArg(args, "--collector.ksmd", "")
	} else {
		args = setArg(args, "--no-collector.ksmd", "")
	}

	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Processes.Enabled {
		args = setArg(args, "--collector.processes", "")
	} else {
		args = setArg(args, "--no-collector.processes", "")
	}

	if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Systemd.Enabled {
		args = setArg(args, "--collector.systemd", "")

		pattern, err := regexListToArg(f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Collectors.Systemd.Units)
		if err != nil {
			return nil, fmt.Errorf("systemd unit pattern validation error: %w", err)
		}
		args = setArg(args, "--collector.systemd.unit-include=", pattern)
	} else {
		args = setArg(args, "--no-collector.systemd", "")
	}

	return args, nil
}

// concatenate all patterns into a single regexp using OR
func regexListToArg(list []string) (string, error) {
	for _, pattern := range list {
		_, err := regexp.Compile(pattern)
		if err != nil {
			return "", fmt.Errorf("invalid regexp pattern: %s", pattern)
		}
	}
	r := "^(" + strings.Join(list, "|") + ")$"
	_, err := regexp.Compile(r)
	return r, err
}

func (f *Factory) NodeExporterMinimalServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(NodeExporterMinimalServiceMonitor))
}

func (f *Factory) NodeExporterDaemonSet() (*appsv1.DaemonSet, error) {
	ds, err := f.NewDaemonSet(f.assets.MustNewAssetSlice(NodeExporterDaemonSet))
	if err != nil {
		return nil, err
	}

	for i, container := range ds.Spec.Template.Spec.Containers {
		switch container.Name {
		case "node-exporter":
			ds.Spec.Template.Spec.Containers[i].Image = f.config.Images.NodeExporter
			ds.Spec.Template.Spec.Containers[i].Args, err = f.updateNodeExporterArgs(ds.Spec.Template.Spec.Containers[i].Args)
			if err != nil {
				return nil, err
			}
			if f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Resources != nil {
				ds.Spec.Template.Spec.Containers[i].Resources = *f.config.ClusterMonitoringConfiguration.NodeExporterConfig.Resources
			}
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
	return f.NewService(f.assets.MustNewAssetSlice(NodeExporterService))
}

func (f *Factory) NodeExporterSecurityContextConstraints() (*securityv1.SecurityContextConstraints, error) {
	return f.NewSecurityContextConstraints(f.assets.MustNewAssetSlice(NodeExporterSecurityContextConstraints))
}

func (f *Factory) NodeExporterServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(NodeExporterServiceAccount))
}

func (f *Factory) NodeExporterClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(NodeExporterClusterRoleBinding))
}

func (f *Factory) NodeExporterClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(NodeExporterClusterRole))
}

func (f *Factory) NodeExporterPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetSlice(NodeExporterPrometheusRule))
}

func (f *Factory) NodeExporterRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(NodeExporterKubeRbacProxySecret))
}

func (f *Factory) PrometheusK8sClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(PrometheusK8sClusterRoleBinding))
}

func (f *Factory) PrometheusK8sAlertmanagerRoleBinding() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetSlice(PrometheusK8sTAlertmanagerRoleBinding))
}

func (f *Factory) ThanosQuerierClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(ThanosQuerierClusterRoleBinding))
}

func (f *Factory) PrometheusUserWorkloadClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(PrometheusUserWorkloadClusterRoleBinding))
}

func (f *Factory) PrometheusUserWorkloadAlertmanagerUserWorkloadRoleBinding() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetSlice(PrometheusUserWorkloadAlertmanagerUserWorkloadRoleBinding))
}

func (f *Factory) PrometheusK8sClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(PrometheusK8sClusterRole))
}

func (f *Factory) ThanosQuerierClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(ThanosQuerierClusterRole))
}

func (f *Factory) PrometheusUserWorkloadClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(PrometheusUserWorkloadClusterRole))
}

func (f *Factory) PrometheusK8sRoleConfig() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetSlice(PrometheusK8sRoleConfig))
}

func (f *Factory) PrometheusUserWorkloadRoleConfig() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetSlice(PrometheusUserWorkloadRoleConfig))
}

func (f *Factory) PrometheusK8sRoleBindingList() (*rbacv1.RoleBindingList, error) {
	return f.NewRoleBindingList(f.assets.MustNewAssetSlice(PrometheusK8sRoleBindingList))
}

func (f *Factory) PrometheusUserWorkloadRoleBindingList() (*rbacv1.RoleBindingList, error) {
	return f.NewRoleBindingList(f.assets.MustNewAssetSlice(PrometheusUserWorkloadRoleBindingList))
}

func (f *Factory) PrometheusK8sRoleBindingConfig() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetSlice(PrometheusK8sRoleBindingConfig))
}

func (f *Factory) PrometheusUserWorkloadRoleBindingConfig() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetSlice(PrometheusUserWorkloadRoleBindingConfig))
}

func (f *Factory) PrometheusK8sRoleList() (*rbacv1.RoleList, error) {
	return f.NewRoleList(f.assets.MustNewAssetSlice(PrometheusK8sRoleList))
}

func (f *Factory) PrometheusUserWorkloadRoleList() (*rbacv1.RoleList, error) {
	return f.NewRoleList(f.assets.MustNewAssetSlice(PrometheusUserWorkloadRoleList))
}

func (f *Factory) PrometheusUserWorkloadFederateRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetSlice(PrometheusUserWorkloadFederateRoute))
}

func (f *Factory) PrometheusK8sPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetSlice(PrometheusK8sPrometheusRule))
}

func (f *Factory) PrometheusK8sServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(PrometheusK8sServiceAccount))
}

func (f *Factory) ThanosQuerierServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(ThanosQuerierServiceAccount))
}

func (f *Factory) PrometheusUserWorkloadServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(PrometheusUserWorkloadServiceAccount))
}

func (f *Factory) PrometheusK8sGrpcTLSSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(PrometheusK8sGrpcTLSSecret))
}

func (f *Factory) PrometheusK8sThanosSidecarPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetSlice(PrometheusK8sThanosSidecarPrometheusRule))
}

func (f *Factory) PrometheusUserWorkloadGrpcTLSSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(PrometheusUserWorkloadGrpcTLSSecret))
}

func (f *Factory) ThanosQuerierGrpcTLSSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(ThanosQuerierGrpcTLSSecret))
}

func (f *Factory) ThanosRulerQueryConfigSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetSlice(ThanosRulerQueryConfigSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespaceUserWorkload
	return s, nil
}

func (f *Factory) ThanosRulerAlertmanagerConfigSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetSlice(ThanosRulerAlertmanagerConfigSecret))
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
	return f.NewSecret(f.assets.MustNewAssetSlice(PrometheusRBACProxySecret))
}

func (f *Factory) PrometheusUserWorkloadRBACProxyMetricsSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(PrometheusUserWorkloadRBACProxyMetricsSecret))
}

func (f *Factory) PrometheusUserWorkloadRBACProxyFederateSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(PrometheusUserWorkloadRBACProxyFederateSecret))
}

func (f *Factory) ThanosQuerierRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(ThanosQuerierRBACProxySecret))
}
func (f *Factory) ThanosQuerierRBACProxyRulesSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(ThanosQuerierRBACProxyRulesSecret))
}

func (f *Factory) ThanosQuerierRBACProxyMetricsSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(ThanosQuerierRBACProxyMetricsSecret))
}

func (f *Factory) ThanosQuerierRBACProxyWebSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(ThanosQuerierRBACProxyWebSecret))
}

func (f *Factory) PrometheusK8sServingCertsCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetSlice(PrometheusK8sServingCertsCABundle))
}

func (f *Factory) PrometheusUserWorkloadConfigMap() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetSlice(PrometheusUserWorkloadConfigMap))
}

func (f *Factory) PrometheusUserWorkloadServingCertsCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetSlice(PrometheusUserWorkloadServingCertsCABundle))
}

func (f *Factory) PrometheusK8sKubeletServingCABundle(data map[string]string) (*v1.ConfigMap, error) {
	c, err := f.NewConfigMap(f.assets.MustNewAssetSlice(PrometheusK8sKubeletServingCABundle))
	if err != nil {
		return nil, err
	}

	c.Data = data
	return c, nil
}

func (f *Factory) PrometheusK8sThanosSidecarServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(PrometheusK8sThanosSidecarServiceMonitor))
}

func (f *Factory) PrometheusK8sAPIRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetSlice(PrometheusK8sAPIRoute))
}

func (f *Factory) PrometheusK8sFederateRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetSlice(PrometheusK8sFederateRoute))
}

func (f *Factory) ThanosQuerierRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetSlice(ThanosQuerierRoute))
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
	return f.NewConfigMap(f.assets.MustNewAssetSlice(PrometheusK8sTrustedCABundle))
}

func (f *Factory) PrometheusUserWorkloadTrustedCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetSlice(PrometheusUserWorkloadTrustedCABundle))
}

func (f *Factory) NewPrometheusK8s() (*monv1.Prometheus, error) {
	return f.NewPrometheus(f.assets.MustNewAssetSlice(PrometheusK8s))
}

func (f *Factory) PrometheusK8sTelemetrySecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetSlice(PrometheusK8sTelemetry))
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

func (f *Factory) PrometheusK8s(grpcTLS *v1.Secret, telemetrySecret *v1.Secret) (*monv1.Prometheus, error) {
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

	alertGeneratorURL, err := makeConsoleURL(f.consoleConfig, "monitoring")
	if err != nil {
		return nil, err
	}
	p.Spec.ExternalURL = alertGeneratorURL

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Resources != nil {
		p.Spec.Resources = *f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Resources
	}

	if f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.NodeSelector != nil {
		p.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Tolerations) > 0 {
		p.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.Tolerations
	}

	for _, tsc := range f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.TopologySpreadConstraints {
		p.Spec.TopologySpreadConstraints = append(
			p.Spec.TopologySpreadConstraints,
			monv1.TopologySpreadConstraint{
				CoreV1TopologySpreadConstraint: monv1.CoreV1TopologySpreadConstraint(tsc),
			},
		)
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

	if err := setupProfilesToIgnore(p, f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.CollectionProfile); err != nil {
		return nil, err
	}

	clusterID := f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID
	if f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.IsEnabled() && f.config.RemoteWrite {
		selectorRelabelConfig, err := promqlgen.LabelSelectorsToRelabelConfig(f.config.ClusterMonitoringConfiguration.PrometheusK8sConfig.TelemetryMatches)
		if err != nil {
			return nil, fmt.Errorf("generate label selector relabel config: %w", err)
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
				// anyway.
				MaxSamplesPerSend: 10000,
				// Batch samples for 1m until we send them if we not reach the
				// 10000 MaxSamplesPerSend first.
				BatchSendDeadline: ptr.To(monv1.Duration("1m")),
				// Backoff is doubled on every backoff. We start with 1s
				// backoff and double until the MaxBackOff.
				MinBackoff: ptr.To(monv1.Duration("1s")),
				// 128s is the 8th backoff in a row, once we end up here, we
				// don't increase backoff time anymore. As we would at most
				// produce (concurrency/256) number of requests per second.
				MaxBackoff: ptr.To(monv1.Duration("256s")),
			},
			WriteRelabelConfigs: []monv1.RelabelConfig{
				*selectorRelabelConfig,
				{
					TargetLabel: "_id",
					Replacement: ptr.To(clusterID),
				},
				// relabeling the `ALERTS` series to `alerts` allows us to make
				// a distinction between the series produced in-cluster and out
				// of cluster.
				{
					SourceLabels: []monv1.LabelName{"__name__"},
					TargetLabel:  "__name__",
					Regex:        "ALERTS",
					Replacement:  ptr.To("alerts"),
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

	f.setupPrometheusRemoteWriteProxy(p)

	if f.config.Images.Thanos != "" {
		p.Spec.Thanos.Image = &f.config.Images.Thanos
	}

	setupAlerting(p, platformAlertmanagerService, f.namespace)
	f.setupGoGC(p)

	for i, container := range p.Spec.Containers {
		switch container.Name {
		case "kube-rbac-proxy", "kube-rbac-proxy-web", "kube-rbac-proxy-thanos":
			p.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			p.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
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

func (f *Factory) setupGoGC(p *monv1.Prometheus) {
	if f.infrastructure.HighlyAvailableInfrastructure() {
		return
	}

	for i, container := range p.Spec.Containers {
		if container.Name != "prometheus" {
			continue
		}

		// Prometheus automatically sets GOGC=75 unless the environment
		// variable is set explicitly. The (upstream) rationale is that GOGC=75
		// reduces memory usage significantly for a slight increase of CPU
		// usage.
		// OCP components running on Single Node OpenShift environments should
		// be savvy on CPU hence set GOGC=100 (Go runtime default) in this
		// case.
		p.Spec.Containers[i].Env = append(p.Spec.Containers[i].Env, v1.EnvVar{Name: "GOGC", Value: "100"})
	}
}

func setupAlerting(p *monv1.Prometheus, svcName, svcNamespace string) {
	eps := p.Spec.Alerting.Alertmanagers[0]

	eps.Name = svcName
	eps.Namespace = ptr.To(svcNamespace)
	eps.TLSConfig.ServerName = ptr.To(fmt.Sprintf("%s.%s.svc", svcName, svcNamespace))

	p.Spec.Alerting.Alertmanagers = []monv1.AlertmanagerEndpoints{eps}
}

func (f *Factory) setupQueryLogFile(p *monv1.Prometheus, queryLogFile string) error {
	if queryLogFile == "" {
		return nil
	}
	dirPath := filepath.Dir(queryLogFile)
	// queryLogFile is not an absolute path nor a simple filename
	if !filepath.IsAbs(queryLogFile) && dirPath != "." {
		return fmt.Errorf(`relative paths to query log file are not supported: %w`, ErrConfigValidation)
	}
	if dirPath == "/" {
		return fmt.Errorf(`query log file can't be stored on the root directory: %w`, ErrConfigValidation)
	}

	// /prometheus is where Prometheus will store the TSDB, so it is
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
			return fmt.Errorf(`query log file can't be stored on a new file on the dev directory: %w`, ErrConfigValidation)
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

// setupProfilesToIgnore configures the label selectors of the Prometheus ("p")
// to select any ServiceMonitor's or PodMonitor's that doesn't have the scrape
// profile label or that matches the CollectionProfile ("cp").
func setupProfilesToIgnore(p *monv1.Prometheus, cp CollectionProfile) error {
	// Our goal is to configure Prometheus to select both the resources that
	// either don't have the collection profile label or have the desired value.
	// However, with label selectors we are not able to express OR conditions.
	// Hence, the only alternative is to configure Prometheus to not select any
	// resource that matches either of the collection profiles that we are not
	// interested in.
	profiles := make([]string, 0, len(SupportedCollectionProfiles)-1)
	for _, profile := range SupportedCollectionProfiles {
		if profile == cp {
			continue
		}
		profiles = append(profiles, string(profile))
	}

	labelSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      collectionProfileLabel,
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   profiles,
			},
		},
	}

	p.Spec.ServiceMonitorSelector = labelSelector
	p.Spec.PodMonitorSelector = labelSelector
	p.Spec.ProbeSelector = labelSelector

	return nil
}

func (f *Factory) setupPrometheusRemoteWriteProxy(p *monv1.Prometheus) {
	for k := range p.Spec.RemoteWrite {
		rw := &p.Spec.RemoteWrite[k]

		if f.proxy.HTTPProxy() != "" {
			rw.ProxyURL = ptr.To(f.proxy.HTTPProxy())
		}
		if f.proxy.HTTPSProxy() != "" {
			rw.ProxyURL = ptr.To(f.proxy.HTTPSProxy())
		}
		if f.proxy.NoProxy() != "" {
			rw.NoProxy = ptr.To(f.proxy.NoProxy())
		}
	}
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
	p, err := f.NewPrometheus(f.assets.MustNewAssetSlice(PrometheusUserWorkload))
	if err != nil {
		return nil, err
	}
	if f.config.UserWorkloadConfiguration.Prometheus.ScrapeInterval != "" {
		p.Spec.ScrapeInterval = monv1.Duration(f.config.UserWorkloadConfiguration.Prometheus.ScrapeInterval)
	}

	if f.config.UserWorkloadConfiguration.Prometheus.EvaluationInterval != "" {
		p.Spec.EvaluationInterval = monv1.Duration(f.config.UserWorkloadConfiguration.Prometheus.EvaluationInterval)
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

	alertGeneratorURL, err := makeConsoleURL(f.consoleConfig, "monitoring")
	if err != nil {
		return nil, err
	}
	p.Spec.ExternalURL = alertGeneratorURL

	if f.config.UserWorkloadConfiguration.Prometheus.Resources != nil {
		p.Spec.Resources = *f.config.UserWorkloadConfiguration.Prometheus.Resources
	}

	if f.config.UserWorkloadConfiguration.Prometheus.NodeSelector != nil {
		p.Spec.NodeSelector = f.config.UserWorkloadConfiguration.Prometheus.NodeSelector
	}

	if len(f.config.UserWorkloadConfiguration.Prometheus.Tolerations) > 0 {
		p.Spec.Tolerations = f.config.UserWorkloadConfiguration.Prometheus.Tolerations
	}

	for _, tsc := range f.config.UserWorkloadConfiguration.Prometheus.TopologySpreadConstraints {
		p.Spec.TopologySpreadConstraints = append(
			p.Spec.TopologySpreadConstraints,
			monv1.TopologySpreadConstraint{
				CoreV1TopologySpreadConstraint: monv1.CoreV1TopologySpreadConstraint(tsc),
			},
		)
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

		// Since `SendExemplars` is experimental currently, we need to enable "exemplar-storage" explicitly to make sure
		// CMO turns this on automatically in Prometheus if any *UWM* RemoteWrite[] enables this.
		for _, rws := range f.config.UserWorkloadConfiguration.Prometheus.RemoteWrite {
			if ptr.Deref(rws.SendExemplars, false) {
				p.Spec.EnableFeatures = append(p.Spec.EnableFeatures, EnableFeatureExemplarStorageString)
				break
			}
		}
	}

	f.setupPrometheusRemoteWriteProxy(p)

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

	p.Spec.Volumes = append(p.Spec.Volumes, v1.Volume{
		Name: "secret-grpc-tls",
		VolumeSource: v1.VolumeSource{
			Secret: &v1.SecretVolumeSource{
				SecretName: grpcTLS.GetName(),
			},
		},
	})

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

	f.setupGoGC(p)

	if f.config.UserWorkloadConfiguration.Alertmanager.Enabled {
		setupAlerting(p, userWorkloadAlertmanagerService, f.namespaceUserWorkload)
	} else {
		setupAlerting(p, platformAlertmanagerService, f.namespace)
	}

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

	p.Spec.ExcludedFromEnforcement = f.excludedFromEnforcement()

	return p, nil
}

func (f *Factory) excludedFromEnforcement() []monv1.ObjectReference {
	if !*f.config.ClusterMonitoringConfiguration.UserWorkload.RulesWithoutLabelEnforcementAllowed {
		return nil
	}

	refs := make([]monv1.ObjectReference, 0, len(f.config.UserWorkloadConfiguration.NamespacesWithoutLabelEnforcement))
	for _, ns := range f.config.UserWorkloadConfiguration.NamespacesWithoutLabelEnforcement {
		refs = append(refs, monv1.ObjectReference{
			Group:     mon.GroupName,
			Resource:  mon.PrometheusRuleName,
			Namespace: ns,
		})
	}

	return refs
}

func (f *Factory) PrometheusK8sPrometheusServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(PrometheusK8sPrometheusServiceMonitor))
}

func (f *Factory) PrometheusUserWorkloadPrometheusServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(PrometheusUserWorkloadPrometheusServiceMonitor))
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

func (f *Factory) MetricsServerConfigMapAuditPolicy() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetSlice(MetricsServerConfigMapAuditPolicy))
}

func (f *Factory) MetricsServerServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(MetricsServerServiceAccount))
}

func (f *Factory) MetricsServerClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(MetricsServerClusterRole))
}

func (f *Factory) MetricsServerClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(MetricsServerClusterRoleBinding))
}

func (f *Factory) MetricsServerClusterRoleBindingAuthDelegator() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(MetricsServerClusterRoleBindingAuthDelegator))
}

func (f *Factory) MetricsServerRoleBindingAuthReader() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetSlice(MetricsServerRoleBindingAuthReader))
}

func (f *Factory) MetricsServerDeployment(apiAuthSecretName string, kubeletCABundle *v1.ConfigMap, servingCASecret, metricsClientCert *v1.Secret, requestheader map[string]string) (*appsv1.Deployment, error) {
	dep, err := f.NewDeployment(f.assets.MustNewAssetSlice(MetricsServerDeployment))
	if err != nil {
		return nil, err
	}

	podSpec := &dep.Spec.Template.Spec
	containers := podSpec.Containers
	idx := slices.IndexFunc(containers, containerNameEquals("metrics-server"))
	if idx < 0 {
		return nil, fmt.Errorf("failed to find metrics-server container %q in deployment %q",
			"metrics-server", MetricsServerDeployment)
	}

	containers[idx].Image = f.config.Images.MetricsServer
	containers[idx].Args = f.setTLSSecurityConfiguration(podSpec.Containers[0].Args,
		MetricsServerTLSCipherSuitesFlag, MetricsServerTLSMinTLSVersionFlag)

	// By default, the /readyz endpoint is used to assert the component
	// readiness. This endpoint returns success when the metrics-server has
	// metric samples over 2 intervals (e.g. it has scraped at least one
	// kubelet twice).
	// In single-node deployments, it happens sometimes (especially in
	// end-to-end tests) that the kubelet fails to respond in a timely fashion
	// due to contention in cAdvisor, leading to a delayed readiness (and test
	// failures). To workaround the issue, we use the /livez endpoint in this
	// mode.
	// The long-term plan is to switch resource metrics from cAdvisor to the
	// CRI stats API (currently an alpha feature). Once it happens, we can
	// remove this change.
	// See https://issues.redhat.com//browse/OCPBUGS-32510 for details.
	if !f.infrastructure.HighlyAvailableInfrastructure() {
		containers[idx].StartupProbe = containers[idx].ReadinessProbe.DeepCopy()
		containers[idx].ReadinessProbe.HTTPGet.Path = "/livez"
	}

	// Hash the Kubelet Serving CA Bundle configmap value and propagate it as a annotation to the
	// deployment's pods to trigger a new rollout when the CA is rotated.
	dep.Spec.Template.Annotations["monitoring.openshift.io/kubelet-serving-ca-bundle-hash"] = hashStringMap(kubeletCABundle.Data)

	// Hash the TLS secret and propagate it as a annotation to the
	// deployment's pods to trigger a new rollout when the TLS certificate/key
	// are rotated.
	dep.Spec.Template.Annotations["monitoring.openshift.io/serving-ca-secret-hash"] = hashByteMap(servingCASecret.Data)

	// Hash the metrics client cert and propagate it as an annotation to the
	// deployment's pods to trigger a new rollout when the metrics client cert
	// is rotated.
	dep.Spec.Template.Annotations["monitoring.openshift.io/metrics-client-cert-hash"] = hashByteMap(metricsClientCert.Data)

	config := f.config.ClusterMonitoringConfiguration.MetricsServerConfig
	if config == nil {
		return dep, nil
	}

	r := newErrMapReader(requestheader)

	var (
		requestheaderAllowedNames       = strings.Join(r.slice("requestheader-allowed-names"), ",")
		requestheaderExtraHeadersPrefix = strings.Join(r.slice("requestheader-extra-headers-prefix"), ",")
		requestheaderGroupHeaders       = strings.Join(r.slice("requestheader-group-headers"), ",")
		requestheaderUsernameHeaders    = strings.Join(r.slice("requestheader-username-headers"), ",")
	)

	if r.Error() != nil {
		return nil, fmt.Errorf("value not found in extension api server authentication configmap: %w", r.err)
	}

	containers[idx].Args = append(containers[idx].Args,
		"--client-ca-file=/etc/client-ca-bundle/client-ca-file",
		"--requestheader-client-ca-file=/etc/client-ca-bundle/requestheader-client-ca-file",
		"--requestheader-allowed-names="+requestheaderAllowedNames,
		"--requestheader-extra-headers-prefix="+requestheaderExtraHeadersPrefix,
		"--requestheader-group-headers="+requestheaderGroupHeaders,
		"--requestheader-username-headers="+requestheaderUsernameHeaders,
	)

	podSpec.Containers[0].VolumeMounts = append(podSpec.Containers[0].VolumeMounts,
		v1.VolumeMount{
			Name:      "client-ca-bundle",
			ReadOnly:  true,
			MountPath: "/etc/client-ca-bundle",
		},
	)

	if err := validateAuditProfile(config.Audit.Profile); err != nil {
		return nil, err
	}

	profile := strings.ToLower(string(config.Audit.Profile))
	containers[idx].Args = append(containers[idx].Args,
		fmt.Sprintf("--audit-policy-file=/etc/audit/%s-profile.yaml", profile),
		"--audit-log-path=/var/log/metrics-server/audit.log",
		"--audit-log-maxsize=100", // 100 MB
		"--audit-log-maxbackup=5", // limit space consumed by restricting backups
		"--audit-log-compress=true",
	)

	podSpec.Volumes = append(podSpec.Volumes,
		v1.Volume{
			Name: "client-ca-bundle",
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: apiAuthSecretName,
				},
			},
		},
	)

	if len(config.NodeSelector) > 0 {
		podSpec.NodeSelector = config.NodeSelector
	}

	if len(config.Tolerations) > 0 {
		podSpec.Tolerations = config.Tolerations
	}

	if config.Resources != nil {
		containers[idx].Resources = *config.Resources
	}

	if len(config.TopologySpreadConstraints) > 0 {
		podSpec.TopologySpreadConstraints = config.TopologySpreadConstraints
	}

	return dep, nil
}

func (f *Factory) MetricsServerSecret(tlsSecret *v1.Secret, apiAuthConfigmap *v1.ConfigMap) (*v1.Secret, error) {
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
		return nil, fmt.Errorf("value not found in extension api server authentication configmap: %w", r.err)
	}

	h := fnv.New64()
	h.Write([]byte(clientCA + requestheaderClientCA + tlsCA + tlsKey))
	hash := strconv.FormatUint(h.Sum64(), 32)

	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: f.namespace,
			Name:      fmt.Sprintf("metrics-server-%s", hash),
			Labels: map[string]string{
				"monitoring.openshift.io/name": "metrics-server",
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

func (f *Factory) MetricsServerPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetSlice(MetricsServerPodDisruptionBudget))
}

func (f *Factory) MetricsServerService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(MetricsServerService))
}

func (f *Factory) MetricsServerServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(MetricsServerServiceMonitor))
}

func (f *Factory) MetricsServerAPIService() (*apiregistrationv1.APIService, error) {
	return f.NewAPIService(f.assets.MustNewAssetSlice(MetricsServerAPIService))
}

func (f *Factory) PrometheusOperatorServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(PrometheusOperatorServiceMonitor))
}

func (f *Factory) PrometheusOperatorPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetSlice(PrometheusOperatorPrometheusRule))
}

func (f *Factory) PrometheusOperatorUserWorkloadServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(PrometheusOperatorUserWorkloadServiceMonitor))
}

func (f *Factory) PrometheusUserWorkloadThanosSidecarServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(PrometheusUserWorkloadThanosSidecarServiceMonitor))
}

func (f *Factory) PrometheusUserWorkloadAlertManagerRoleBinding() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetSlice(PrometheusUserWorkloadAlertmanagerRoleBinding))
}

func (f *Factory) PrometheusOperatorClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(PrometheusOperatorClusterRoleBinding))
}

func (f *Factory) PrometheusOperatorUserWorkloadClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(PrometheusOperatorUserWorkloadClusterRoleBinding))
}

func (f *Factory) PrometheusOperatorUserWorkloadCRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(PrometheusOperatorUserWorkloadKubeRbacProxySecret))
}

func (f *Factory) PrometheusOperatorClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(PrometheusOperatorClusterRole))
}

func (f *Factory) PrometheusOperatorUserWorkloadClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(PrometheusOperatorUserWorkloadClusterRole))
}

func (f *Factory) PrometheusOperatorServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(PrometheusOperatorServiceAccount))
}

func (f *Factory) PrometheusOperatorUserWorkloadServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(PrometheusOperatorUserWorkloadServiceAccount))
}

func (f *Factory) PrometheusOperatorRBACProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(PrometheusOperatorKubeRbacProxySecret))
}

func (f *Factory) PrometheusOperatorAdmissionWebhookServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(AdmissionWebhookServiceAccount))
}

func (f *Factory) PrometheusOperatorAdmissionWebhookService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(AdmissionWebhookService))
}

func (f *Factory) PrometheusOperatorAdmissionWebhookPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetSlice(AdmissionWebhookPodDisruptionBudget))
}

func (f *Factory) PrometheusOperatorAdmissionWebhookDeployment() (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetSlice(AdmissionWebhookDeployment))
	if err != nil {
		return nil, err
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.NodeSelector) > 0 {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Tolerations
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig.TopologySpreadConstraints) > 0 {
		d.Spec.Template.Spec.TopologySpreadConstraints =
			f.config.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig.TopologySpreadConstraints
	}

	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "prometheus-operator-admission-webhook":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.PrometheusOperatorAdmissionWebhook

			if f.config.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig.Resources != nil {
				d.Spec.Template.Spec.Containers[i].Resources = *f.config.ClusterMonitoringConfiguration.PrometheusOperatorAdmissionWebhookConfig.Resources
			}

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
	d, err := f.NewDeployment(f.assets.MustNewAssetSlice(PrometheusOperatorDeployment))
	if err != nil {
		return nil, err
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.NodeSelector) > 0 {
		d.Spec.Template.Spec.NodeSelector = f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.NodeSelector
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Tolerations
	}

	if len(f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.TopologySpreadConstraints) > 0 {
		d.Spec.Template.Spec.TopologySpreadConstraints =
			f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.TopologySpreadConstraints
	}

	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "kube-rbac-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			d.Spec.Template.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
		case "prometheus-operator":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.PrometheusOperator

			if f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Resources != nil {
				d.Spec.Template.Spec.Containers[i].Resources = *f.config.ClusterMonitoringConfiguration.PrometheusOperatorConfig.Resources
			}

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
	d, err := f.NewDeployment(f.assets.MustNewAssetSlice(PrometheusOperatorUserWorkloadDeployment))
	if err != nil {
		return nil, err
	}

	if len(f.config.UserWorkloadConfiguration.PrometheusOperator.NodeSelector) > 0 {
		d.Spec.Template.Spec.NodeSelector = f.config.UserWorkloadConfiguration.PrometheusOperator.NodeSelector
	}

	if len(f.config.UserWorkloadConfiguration.PrometheusOperator.Tolerations) > 0 {
		d.Spec.Template.Spec.Tolerations = f.config.UserWorkloadConfiguration.PrometheusOperator.Tolerations
	}

	if len(f.config.UserWorkloadConfiguration.PrometheusOperator.TopologySpreadConstraints) > 0 {
		d.Spec.Template.Spec.TopologySpreadConstraints = f.config.UserWorkloadConfiguration.PrometheusOperator.TopologySpreadConstraints
	}

	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "kube-rbac-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.KubeRbacProxy
			d.Spec.Template.Spec.Containers[i].Args = f.setTLSSecurityConfiguration(container.Args, KubeRbacProxyTLSCipherSuitesFlag, KubeRbacProxyMinTLSVersionFlag)
		case "prometheus-operator":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.PrometheusOperator

			if f.config.UserWorkloadConfiguration.PrometheusOperator.Resources != nil {
				d.Spec.Template.Spec.Containers[i].Resources = *f.config.UserWorkloadConfiguration.PrometheusOperator.Resources
			}

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
		if arg == argName ||
			(argName[len(argName)-1] == '=' && strings.HasPrefix(arg, argName)) {
			args[i] = argName + argValue
			found = true
		}
	}

	if !found {
		args = append(args, argName+argValue)
	}

	return args
}

func uniqueSet(input []string) []string {
	uniqueMap := make(map[string]struct{})
	var unique []string
	for _, str := range input {
		if _, ok := uniqueMap[str]; !ok {
			uniqueMap[str] = struct{}{}
			unique = append(unique, str)
		}
	}
	return unique
}

func (f *Factory) PrometheusRuleValidatingWebhook() (*admissionv1.ValidatingWebhookConfiguration, error) {
	return f.NewValidatingWebhook(f.assets.MustNewAssetSlice(AdmissionWebhookRuleValidatingWebhook))
}

func (f *Factory) AlertManagerConfigValidatingWebhook() (*admissionv1.ValidatingWebhookConfiguration, error) {
	return f.NewValidatingWebhook(f.assets.MustNewAssetSlice(AdmissionWebhookAlertmanagerConfigValidatingWebhook))
}

func (f *Factory) PrometheusOperatorService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(PrometheusOperatorService))
}

func (f *Factory) PrometheusOperatorUserWorkloadService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(PrometheusOperatorUserWorkloadService))
}

func (f *Factory) PrometheusK8sService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(PrometheusK8sService))
}

func (f *Factory) PrometheusK8sRBACProxyWebSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(PrometheusK8sRBACProxyWebSecret))
}

func (f *Factory) PrometheusK8sServiceThanosSidecar() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(PrometheusK8sServiceThanosSidecar))
}

func (f *Factory) PrometheusK8sPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetSlice(PrometheusK8sPodDisruptionBudget))
}

func (f *Factory) PrometheusUserWorkloadPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetSlice(PrometheusUserWorkloadPodDisruptionBudget))
}

func (f *Factory) ThanosRulerPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetSlice(ThanosRulerPodDisruptionBudget))
}

func (f *Factory) PrometheusUserWorkloadService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(PrometheusUserWorkloadService))
}

func (f *Factory) PrometheusUserWorkloadServiceThanosSidecar() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(PrometheusUserWorkloadServiceThanosSidecar))
}

func (f *Factory) ClusterMonitoringClusterRoleView() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(ClusterMonitoringClusterRoleView))
}

func (f *Factory) ClusterMonitoringClusterRoleAggregatedMetricsReader() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(ClusterMonitoringClusterRoleAggregatedMetricsReader))
}

func (f *Factory) ClusterMonitoringClusterRolePodMetricsReader() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(ClusterMonitoringClusterRolePodMetricsReader))
}

func (f *Factory) ClusterMonitoringRulesEditClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(ClusterMonitoringRulesEditClusterRole))
}

func (f *Factory) ClusterMonitoringRulesViewClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(ClusterMonitoringRulesViewClusterRole))
}

func (f *Factory) ClusterMonitoringEditClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(ClusterMonitoringEditClusterRole))
}

func (f *Factory) ClusterMonitoringAlertingEditClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(ClusterMonitoringEditAlertingClusterRole))
}

func (f *Factory) ClusterMonitoringEditUserWorkloadConfigRole() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetSlice(ClusterMonitoringEditUserWorkloadConfigRole))
}

func (f *Factory) ClusterMonitoringEditUserWorkloadAlertmanagerApiReader() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetSlice(ClusterMonitoringEditUserWorkloadAlertmanagerApiReader))
}

func (f *Factory) ClusterMonitoringEditUserWorkloadAlertmanagerApiWriter() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetSlice(ClusterMonitoringEditUserWorkloadAlertmanagerApiWriter))
}

func (f *Factory) ClusterMonitoringAlertManagerViewRole() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetSlice(ClusterMonitoringAlertmanagerViewRole))
}

func (f *Factory) ClusterMonitoringAlertManagerEditRole() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetSlice(ClusterMonitoringAlertmanagerEditRole))
}

func (f *Factory) ClusterMonitoringApiReaderRole() (*rbacv1.Role, error) {
	return f.NewRole(f.assets.MustNewAssetSlice(ClusterMonitoringApiReaderRole))
}

func (f *Factory) ClusterMonitoringOperatorServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(ClusterMonitoringOperatorServiceMonitor))
}

func (f *Factory) ClusterMonitoringOperatorPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetSlice(ClusterMonitoringOperatorPrometheusRule))
}

func (f *Factory) ControlPlanePrometheusRule() (*monv1.PrometheusRule, error) {
	r, err := f.NewPrometheusRule(f.assets.MustNewAssetSlice(ControlPlanePrometheusRule))
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

func (f *Factory) ControlPlaneKubeletServiceMonitors() ([]*monv1.ServiceMonitor, error) {
	return serviceMonitors(f.config.CollectionProfilesFeatureGateEnabled, f.ControlPlaneKubeletServiceMonitor, f.ControlPlaneKubeletMinimalServiceMonitor)
}

func (f *Factory) ControlPlaneKubeletServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(ControlPlaneKubeletServiceMonitor))
}

func (f *Factory) ControlPlaneKubeletMinimalServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(ControlPlaneKubeletMinimalServiceMonitor))
}

func IsMissingPortInAddressError(err error) bool {
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return addrErr.Err == "missing port in address"
	}
	return false
}

func (f *Factory) NewDaemonSet(manifest []byte) (*appsv1.DaemonSet, error) {
	ds := appsv1.DaemonSet{}
	err := decodeYAML(manifest, &ds)
	if err != nil {
		return nil, err
	}

	return &ds, nil
}

func (f *Factory) NewPodDisruptionBudget(manifest []byte) (*policyv1.PodDisruptionBudget, error) {
	if !f.infrastructure.HighlyAvailableInfrastructure() {
		return nil, nil
	}
	pdb := policyv1.PodDisruptionBudget{}
	err := decodeYAML(manifest, &pdb)
	if err != nil {
		return nil, err
	}

	return &pdb, nil
}

// descriptionWithoutPlaceholder omit tested examples placehoders from the description annotation,
// those should only be visible in the docs.
func descriptionWithoutPlaceholder(desc string) string {
	re := regexp.MustCompile(fmt.Sprintf("(?m)\n^%s.*$", TestFilePlacehoderPrefix))
	return re.ReplaceAllString(desc, "")
}

func (f *Factory) NewService(manifest []byte) (*v1.Service, error) {
	s := v1.Service{}
	err := decodeYAML(manifest, &s)
	if err != nil {
		return nil, err
	}

	desc, ok := s.Annotations[DescriptionAnnotation]
	if ok {
		s.Annotations[DescriptionAnnotation] = descriptionWithoutPlaceholder(desc)
	}

	return &s, nil
}

func (f *Factory) NewEndpoints(manifest []byte) (*v1.Endpoints, error) {
	e := v1.Endpoints{}
	err := decodeYAML(manifest, &e)
	if err != nil {
		return nil, err
	}

	return &e, nil
}

func (f *Factory) NewRoute(manifest []byte) (*routev1.Route, error) {
	r := routev1.Route{}
	err := decodeYAML(manifest, &r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func (f *Factory) NewSecret(manifest []byte) (*v1.Secret, error) {
	s := v1.Secret{}
	err := decodeYAML(manifest, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (f *Factory) NewRoleBinding(manifest []byte) (*rbacv1.RoleBinding, error) {
	rb := rbacv1.RoleBinding{}
	err := decodeYAML(manifest, &rb)
	if err != nil {
		return nil, err
	}

	return &rb, nil
}

func (f *Factory) NewRoleList(manifest []byte) (*rbacv1.RoleList, error) {
	rl := rbacv1.RoleList{}
	err := decodeYAML(manifest, &rl)
	if err != nil {
		return nil, err
	}

	return &rl, nil
}

func (f *Factory) NewRoleBindingList(manifest []byte) (*rbacv1.RoleBindingList, error) {
	rbl := rbacv1.RoleBindingList{}
	err := decodeYAML(manifest, &rbl)
	if err != nil {
		return nil, err
	}

	return &rbl, nil
}

func (f *Factory) NewRole(manifest []byte) (*rbacv1.Role, error) {
	r := rbacv1.Role{}
	err := decodeYAML(manifest, &r)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func (f *Factory) NewConfigMap(manifest []byte) (*v1.ConfigMap, error) {
	cm := v1.ConfigMap{}
	err := decodeYAML(manifest, &cm)
	if err != nil {
		return nil, err
	}

	return &cm, nil
}

func (f *Factory) NewConfigMapList(manifest []byte) (*v1.ConfigMapList, error) {
	cml := v1.ConfigMapList{}
	err := decodeYAML(manifest, &cml)
	if err != nil {
		return nil, err
	}

	return &cml, nil
}

func (f *Factory) NewServiceAccount(manifest []byte) (*v1.ServiceAccount, error) {
	sa := v1.ServiceAccount{}
	err := decodeYAML(manifest, &sa)
	if err != nil {
		return nil, err
	}

	return &sa, nil
}

func (f *Factory) NewPrometheus(manifest []byte) (*monv1.Prometheus, error) {
	p := monv1.Prometheus{}
	err := decodeYAML(manifest, &p)
	if err != nil {
		return nil, err
	}

	if !f.infrastructure.HighlyAvailableInfrastructure() {
		p.Spec.Replicas = func(i int32) *int32 { return &i }(1)
		p.Spec.Affinity = nil
	}

	return &p, nil
}

func (f *Factory) NewPrometheusRule(manifest []byte) (*monv1.PrometheusRule, error) {
	p := monv1.PrometheusRule{}
	err := decodeYAML(manifest, &p)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func (f *Factory) NewAlertmanager(manifest []byte) (*monv1.Alertmanager, error) {
	a := monv1.Alertmanager{}
	err := decodeYAML(manifest, &a)
	if err != nil {
		return nil, err
	}

	if !f.infrastructure.HighlyAvailableInfrastructure() {
		a.Spec.Replicas = func(i int32) *int32 { return &i }(1)
		a.Spec.Affinity = nil
	}

	return &a, nil
}

func (f *Factory) NewThanosRuler(manifest []byte) (*monv1.ThanosRuler, error) {
	t := monv1.ThanosRuler{}
	err := decodeYAML(manifest, &t)
	if err != nil {
		return nil, err
	}

	if !f.infrastructure.HighlyAvailableInfrastructure() {
		t.Spec.Replicas = func(i int32) *int32 { return &i }(1)
		t.Spec.Affinity = nil
	}

	return &t, nil
}

func (f *Factory) NewServiceMonitor(manifest []byte) (*monv1.ServiceMonitor, error) {
	sm := monv1.ServiceMonitor{}
	err := decodeYAML(manifest, &sm)
	if err != nil {
		return nil, err
	}
	if !f.infrastructure.HighlyAvailableInfrastructure() {
		err := doubleServiceMonitorInterval(&sm)
		if err != nil {
			return nil, err
		}
	}

	return &sm, nil
}

func (f *Factory) NewDeployment(manifest []byte) (*appsv1.Deployment, error) {
	d := appsv1.Deployment{}
	err := decodeYAML(manifest, &d)
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

	return &d, nil
}

func (f *Factory) NewAPIService(manifest []byte) (*apiregistrationv1.APIService, error) {
	s := apiregistrationv1.APIService{}
	err := decodeYAML(manifest, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (f *Factory) NewSecurityContextConstraints(manifest []byte) (*securityv1.SecurityContextConstraints, error) {
	s := securityv1.SecurityContextConstraints{}
	err := decodeYAML(manifest, &s)
	if err != nil {
		return nil, err
	}

	return &s, nil
}

func (f *Factory) NewClusterRoleBinding(manifest []byte) (*rbacv1.ClusterRoleBinding, error) {
	crb := rbacv1.ClusterRoleBinding{}
	err := decodeYAML(manifest, &crb)
	if err != nil {
		return nil, err
	}

	return &crb, nil
}

func (f *Factory) NewClusterRole(manifest []byte) (*rbacv1.ClusterRole, error) {
	cr := rbacv1.ClusterRole{}
	err := decodeYAML(manifest, &cr)
	if err != nil {
		return nil, err
	}

	return &cr, nil
}

func (f *Factory) NewValidatingWebhook(manifest []byte) (*admissionv1.ValidatingWebhookConfiguration, error) {
	v := admissionv1.ValidatingWebhookConfiguration{}
	err := decodeYAML(manifest, &v)
	if err != nil {
		return nil, err
	}

	return &v, nil
}

func (f *Factory) NewConsolePlugin(manifest []byte) (*consolev1.ConsolePlugin, error) {
	cp := consolev1.ConsolePlugin{}
	err := decodeYAML(manifest, &cp)
	if err != nil {
		return nil, err
	}

	return &cp, nil
}

func (f *Factory) MonitoringPlugin() (*consolev1.ConsolePlugin, error) {
	return f.NewConsolePlugin(f.assets.MustNewAssetSlice(MonitoringPlugin))
}

func (f *Factory) MonitoringPluginDeployment(tlsSecret *v1.Secret) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetSlice(MonitoringPluginDeployment))
	if err != nil {
		return nil, err
	}

	// ensure console-plugin container is present even if config isn't defined so that,
	// we validate that deployment has the expected container name. Thereby avoiding
	// any surprises should user add config later.
	podSpec := &d.Spec.Template.Spec
	containers := podSpec.Containers
	idx := slices.IndexFunc(containers, containerNameEquals(MonitoringPluginDeploymentContainer))
	if idx < 0 {
		return nil, fmt.Errorf("failed to find console-plugin container %q in deployment %q",
			MonitoringPluginDeploymentContainer, MonitoringPluginDeployment)
	}

	containers[idx].Image = f.config.Images.MonitoringPlugin

	// Hash the TLS secret and propagate it as an annotation to the
	// deployment's pods to trigger a new rollout when the TLS certificate/key
	// are rotated.
	d.Spec.Template.Annotations["monitoring.openshift.io/cert-hash"] = hashByteMap(tlsSecret.Data)

	cfg := f.config.ClusterMonitoringConfiguration.MonitoringPluginConfig
	if cfg == nil {
		return d, nil
	}

	if cfg.Resources != nil {
		containers[idx].Resources = *cfg.Resources
	}

	if cfg.NodeSelector != nil {
		podSpec.NodeSelector = cfg.NodeSelector
	}

	if len(cfg.Tolerations) > 0 {
		podSpec.Tolerations = cfg.Tolerations
	}

	if len(cfg.TopologySpreadConstraints) > 0 {
		podSpec.TopologySpreadConstraints = cfg.TopologySpreadConstraints
	}

	return d, nil
}

func (f *Factory) MonitoringPluginPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetSlice(MonitoringPluginPodDisruptionBudget))
}

func (f *Factory) MonitoringPluginServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(MonitoringPluginServiceAccount))
}

func (f *Factory) MonitoringPluginService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(MonitoringPluginService))
}

func (f *Factory) ThanosQuerierPodDisruptionBudget() (*policyv1.PodDisruptionBudget, error) {
	return f.NewPodDisruptionBudget(f.assets.MustNewAssetSlice(ThanosQuerierPodDisruptionBudget))
}

func (f *Factory) ThanosQuerierDeployment(grpcTLS *v1.Secret, enableUserWorkloadMonitoring bool) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetSlice(ThanosQuerierDeployment))
	if err != nil {
		return nil, err
	}

	for i, c := range d.Spec.Template.Spec.Containers {
		switch c.Name {
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

			if !f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.EnableCORS {
				d.Spec.Template.Spec.Containers[i].Args = append(
					d.Spec.Template.Spec.Containers[i].Args, "--web.disable-cors")
			}

		case "prom-label-proxy":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.PromLabelProxy

		case "kube-rbac-proxy", "kube-rbac-proxy-rules", "kube-rbac-proxy-metrics", "kube-rbac-proxy-web":
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
	if len(f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.TopologySpreadConstraints) > 0 {
		d.Spec.Template.Spec.TopologySpreadConstraints =
			f.config.ClusterMonitoringConfiguration.ThanosQuerierConfig.TopologySpreadConstraints
	}

	return d, nil
}

func (f *Factory) ThanosQuerierService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(ThanosQuerierService))
}

func (f *Factory) ThanosQuerierPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetSlice(ThanosQuerierPrometheusRule))
}

func (f *Factory) ThanosQuerierServiceMonitor() (*monv1.ServiceMonitor, error) {
	sm, err := f.NewServiceMonitor(f.assets.MustNewAssetSlice(ThanosQuerierServiceMonitor))
	if err != nil {
		return nil, err
	}

	var found bool
	const endpointPort = "metrics"
	for i := range sm.Spec.Endpoints {
		if sm.Spec.Endpoints[i].Port == endpointPort {
			found = true
			sm.Spec.Endpoints[i].TLSConfig.ServerName = ptr.To(fmt.Sprintf("thanos-querier.%s.svc", f.namespace))
		}
	}
	if !found {
		return nil, fmt.Errorf("failed to find endpoint port %q", endpointPort)
	}

	return sm, nil
}

func (f *Factory) TelemeterTrustedCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetSlice(TelemeterTrustedCABundle))
}

// TelemeterClientServingCertsCABundle generates a new servinc certs CA bundle ConfigMap for TelemeterClient.
func (f *Factory) TelemeterClientServingCertsCABundle() (*v1.ConfigMap, error) {
	return f.NewConfigMap(f.assets.MustNewAssetSlice(TelemeterClientServingCertsCABundle))
}

// TelemeterClientClusterRole generates a new ClusterRole for Telemeter client.
func (f *Factory) TelemeterClientClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(TelemeterClientClusterRole))
}

// TelemeterClientClusterRoleBinding generates a new ClusterRoleBinding for Telemeter client.
func (f *Factory) TelemeterClientClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(TelemeterClientClusterRoleBinding))
}

// TelemeterClientClusterRoleBindingView generates a new ClusterRoleBinding for Telemeter client
// for the cluster monitoring view ClusterRole.
func (f *Factory) TelemeterClientClusterRoleBindingView() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(TelemeterClientClusterRoleBindingView))
}

// TelemeterClientServiceMonitor generates a new ServiceMonitor for Telemeter client.
func (f *Factory) TelemeterClientServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(TelemeterClientServiceMonitor))
}

func (f *Factory) TelemeterClientKubeRbacProxySecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(TelemeterClientKubeRbacProxySecret))
}

func (f *Factory) TelemeterClientPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetSlice(TelemeterClientPrometheusRule))
}

// TelemeterClientDeployment generates a new Deployment for Telemeter client.
// If the passed ConfigMap is not empty it mounts the Trusted CA Bundle as a VolumeMount to
// /etc/pki/ca-trust/extracted/pem/ location.
func (f *Factory) TelemeterClientDeployment(proxyCABundleCM *v1.ConfigMap, s *v1.Secret) (*appsv1.Deployment, error) {
	d, err := f.NewDeployment(f.assets.MustNewAssetSlice(TelemeterClientDeployment))
	if err != nil {
		return nil, err
	}

	// Set annotation on deployment to trigger redeployments
	if s != nil {
		h := fnv.New64()
		h.Write(s.Data["token"])
		d.Spec.Template.Annotations["telemeter-token-hash"] = strconv.FormatUint(h.Sum64(), 32)
	}

	for i, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "telemeter-client":
			d.Spec.Template.Spec.Containers[i].Image = f.config.Images.TelemeterClient

			if f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Resources != nil {
				d.Spec.Template.Spec.Containers[i].Resources = *f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Resources
			}

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
			// while not having any performance penalty. However, it should be changed to usual reconciliation mechanism after CMO performance
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
	if len(f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.TopologySpreadConstraints) > 0 {
		d.Spec.Template.Spec.TopologySpreadConstraints =
			f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.TopologySpreadConstraints
	}
	d.Namespace = f.namespace
	return d, nil
}

// TelemeterClientService generates a new Service for Telemeter client.
func (f *Factory) TelemeterClientService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(TelemeterClientService))
}

// TelemeterClientServiceAccount generates a new ServiceAccount for Telemeter client.
func (f *Factory) TelemeterClientServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(TelemeterClientServiceAccount))
}

func (f *Factory) TelemeterClientSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetSlice(TelemeterClientSecret))
	if err != nil {
		return nil, err
	}

	salt, err := GeneratePassword(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Telemeter client salt: %w", err)
	}
	s.Data["salt"] = []byte(salt)

	if f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Token != "" {
		s.Data["token"] = []byte(f.config.ClusterMonitoringConfiguration.TelemeterClientConfig.Token)
	}

	s.Namespace = f.namespace

	return s, nil
}

func (f *Factory) ThanosRulerService() (*v1.Service, error) {
	return f.NewService(f.assets.MustNewAssetSlice(ThanosRulerService))
}

func (f *Factory) ThanosRulerServiceAccount() (*v1.ServiceAccount, error) {
	return f.NewServiceAccount(f.assets.MustNewAssetSlice(ThanosRulerServiceAccount))
}

func (f *Factory) ThanosRulerClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(ThanosRulerClusterRoleBinding))
}

func (f *Factory) ThanosRulerMonitoringClusterRoleBinding() (*rbacv1.ClusterRoleBinding, error) {
	return f.NewClusterRoleBinding(f.assets.MustNewAssetSlice(ThanosRulerMonitoringClusterRoleBinding))
}

func (f *Factory) ThanosRulerMonitoringAlertmanagerUserWorkloadRoleBinding() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetSlice(ThanosRulerMonitoringAlertmanagerUserWorkloadRoleBinding))
}

func (f *Factory) ThanosRulerClusterRole() (*rbacv1.ClusterRole, error) {
	return f.NewClusterRole(f.assets.MustNewAssetSlice(ThanosRulerClusterRole))
}

func (f *Factory) ThanosRulerPrometheusRule() (*monv1.PrometheusRule, error) {
	return f.NewPrometheusRule(f.assets.MustNewAssetSlice(ThanosRulerPrometheusRule))
}

func (f *Factory) ThanosRulerAlertManagerRoleBinding() (*rbacv1.RoleBinding, error) {
	return f.NewRoleBinding(f.assets.MustNewAssetSlice(ThanosRulerAlertmanagerRoleBinding))
}

func (f *Factory) ThanosRulerServiceMonitor() (*monv1.ServiceMonitor, error) {
	return f.NewServiceMonitor(f.assets.MustNewAssetSlice(ThanosRulerServiceMonitor))
}

func (f *Factory) ThanosRulerRoute() (*routev1.Route, error) {
	return f.NewRoute(f.assets.MustNewAssetSlice(ThanosRulerRoute))
}

func (f *Factory) ThanosRulerGrpcTLSSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(ThanosRulerGrpcTLSSecret))
}

func (f *Factory) ThanosRulerRBACProxyMetricsSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(ThanosRulerRBACProxyMetricsSecret))
}

func (f *Factory) ThanosRulerRBACProxyWebSecret() (*v1.Secret, error) {
	return f.NewSecret(f.assets.MustNewAssetSlice(ThanosRulerRBACProxyWebSecret))
}

func (f *Factory) ThanosRulerCustomResource(
	grpcTLS *v1.Secret,
	alertmanagerConfig *v1.Secret,
) (*monv1.ThanosRuler, error) {
	t, err := f.NewThanosRuler(f.assets.MustNewAssetSlice(ThanosRulerCustomResource))
	if err != nil {
		return nil, err
	}

	t.Spec.Image = f.config.Images.Thanos

	if f.config.UserWorkloadConfiguration.ThanosRuler.EvaluationInterval != "" {
		t.Spec.EvaluationInterval = monv1.Duration(f.config.UserWorkloadConfiguration.ThanosRuler.EvaluationInterval)
	}

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
		case "kube-rbac-proxy-metrics", "kube-rbac-proxy-web":
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

	alertGeneratorURL, err := makeConsoleURL(f.consoleConfig, "monitoring")
	if err != nil {
		return nil, err
	}
	t.Spec.AlertQueryURL = alertGeneratorURL

	t.Spec.ExcludedFromEnforcement = f.excludedFromEnforcement()

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
	for i := range t.Spec.Containers {
		containerName := t.Spec.Containers[i].Name
		if containerName == "thanos-ruler" {
			t.Spec.Containers[i].VolumeMounts = append(t.Spec.Containers[i].VolumeMounts, volumeMounts...)
		}
	}
}

func (f *Factory) injectThanosRulerAlertmanagerDigest(t *monv1.ThanosRuler, alertmanagerConfig *v1.Secret) {
	if alertmanagerConfig == nil {
		return
	}
	digestBytes := sha256.Sum224([]byte(alertmanagerConfig.StringData["alertmanagers.yaml"]))
	digest := fmt.Sprintf("%x", digestBytes)
	for i := range t.Spec.Containers {
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

// decodeYAML is just a wrapper around an Unmarshaling function to make it
// easier to change the implementation
func decodeYAML(manifest []byte, out interface{}) error {
	return k8syaml.UnmarshalStrict(manifest, out)
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
		return nil, fmt.Errorf("CA bundle key %q missing", TrustedCABundleKey)
	}
	if caBundle == "" {
		return nil, fmt.Errorf("CA bundle key %q empty", TrustedCABundleKey)
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
		return nil, fmt.Errorf("error hashing tls data: %w", err)
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

func makeConsoleURL(c *configv1.Console, path string) (string, error) {
	if c != nil && c.Status.ConsoleURL != "" {
		return url.JoinPath(c.Status.ConsoleURL, path)
	}
	return "", nil
}

func serviceMonitors(appendMinimal bool, fullServiceMonitor, minimalServiceMonitor func() (*monv1.ServiceMonitor, error)) ([]*monv1.ServiceMonitor, error) {
	sMonitor, err := fullServiceMonitor()
	if err != nil {
		return nil, err
	}
	sMonitorMinimal, err := minimalServiceMonitor()
	if err != nil {
		return nil, err
	}
	sms := []*monv1.ServiceMonitor{sMonitor}
	if appendMinimal {
		sms = append(sms, sMonitorMinimal)
	}
	return sms, nil
}

func addRemoteWriteConfigs(clusterID string, rw []monv1.RemoteWriteSpec, rwTargets ...RemoteWriteSpec) []monv1.RemoteWriteSpec {
	clusterIDRelabelConfig := []monv1.RelabelConfig{
		{
			TargetLabel: tmpClusterIDLabelName,
			Replacement: ptr.To(clusterID),
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
			MetadataConfig:      target.MetadataConfig,
			OAuth2:              target.OAuth2,
			SendExemplars:       target.SendExemplars,
		}
		if target.ProxyURL != "" {
			rwConf.ProxyConfig.ProxyURL = ptr.To(target.ProxyURL)
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
	return v1.Volume{
		Name: volumeName,
		VolumeSource: v1.VolumeSource{
			ConfigMap: &v1.ConfigMapVolumeSource{
				LocalObjectReference: v1.LocalObjectReference{
					Name: configMapName,
				},
				// TODO(simonpasquier): evaluate if the volume should really be optional.
				Optional: ptr.To(true),
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

func containerNameEquals(name string) func(corev1.Container) bool {
	return func(c corev1.Container) bool {
		return c.Name == name
	}
}

func hashByteMap(s map[string][]byte) string {
	h := fnv.New64()
	// The data's keys need to be sorted in a predictable order to always
	// produce the same hash.
	for _, k := range sets.StringKeySet[[]byte](s).List() {
		h.Write(s[k])
	}

	return strconv.FormatUint(h.Sum64(), 32)
}

func hashStringMap(m map[string]string) string {
	byteMap := make(map[string][]byte, len(m))
	for k, v := range m {
		byteMap[k] = []byte(v)
	}
	return hashByteMap(byteMap)
}
