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
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/openshift/library-go/pkg/crypto"

	v1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeInfrastructureReader struct {
	highlyAvailableInfrastructure bool
	hostedControlPlane            bool
}

func (f *fakeInfrastructureReader) HighlyAvailableInfrastructure() bool {
	return f.highlyAvailableInfrastructure
}

func (f *fakeInfrastructureReader) HostedControlPlane() bool {
	return f.hostedControlPlane
}

func defaultInfrastructureReader() InfrastructureReader {
	return &fakeInfrastructureReader{highlyAvailableInfrastructure: true, hostedControlPlane: false}
}

type fakeProxyReader struct{}

func (f *fakeProxyReader) HTTPProxy() string { return "" }

func (f *fakeProxyReader) HTTPSProxy() string { return "" }

func (f *fakeProxyReader) NoProxy() string { return "" }

const assetsPath = "../../assets"

func TestHashSecret(t *testing.T) {
	for _, tt := range []struct {
		name            string
		data            []string
		given, expected *v1.Secret
		errExpected     bool
	}{
		{
			name:  "no data",
			given: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			expected: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-cnskssi2248p5",
					Labels: map[string]string{
						"monitoring.openshift.io/hash": "cnskssi2248p5",
						"monitoring.openshift.io/name": "foo",
					},
				},
				Data: make(map[string][]byte),
			},
		},
		{
			name:  "one entry",
			given: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			data:  []string{"key1", "value1"},
			expected: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-3dquk0q6eln15",
					Labels: map[string]string{
						"monitoring.openshift.io/hash": "3dquk0q6eln15",
						"monitoring.openshift.io/name": "foo",
					},
				},
				Data: map[string][]byte{
					"key1": []byte("value1"),
				},
			},
		},
		{
			name:  "one valid one invalid entry",
			given: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			data:  []string{"key1", "value1", "key2"},
			expected: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-3dquk0q6eln15",
					Labels: map[string]string{
						"monitoring.openshift.io/hash": "3dquk0q6eln15",
						"monitoring.openshift.io/name": "foo",
					},
				},
				Data: map[string][]byte{
					"key1": []byte("value1"),
				},
			},
		},
		{
			name:  "two entries",
			given: &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			data:  []string{"key1", "value1", "key2", "value2"},
			expected: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo-bfcd7k3kr4396",
					Labels: map[string]string{
						"monitoring.openshift.io/hash": "bfcd7k3kr4396",
						"monitoring.openshift.io/name": "foo",
					},
				},
				Data: map[string][]byte{
					"key1": []byte("value1"),
					"key2": []byte("value2"),
				},
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
			s, err := f.HashSecret(tt.given, tt.data...)
			if got := err != nil; got != tt.errExpected {
				t.Errorf("expected error %t, got %t, err %v", tt.errExpected, got, err)
				return
			}

			if !reflect.DeepEqual(s, tt.expected) {
				t.Errorf("expected secret to be equal, but it isn't. got %v, expected %v", s, tt.expected)
			}
		})
	}
}

func TestUnconfiguredManifests(t *testing.T) {
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	_, err := f.AlertmanagerConfig()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sGrpcTLSSecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadGrpcTLSSecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosRulerAlertmanagerConfigSecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosRulerQueryConfigSecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosRulerMonitoringClusterRoleBinding()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosRulerPrometheusRule()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosQuerierGrpcTLSSecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosQuerierClusterRoleBinding()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosQuerierClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosQuerierDeployment(&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}}, true, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosQuerierServiceAccount()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosQuerierOauthCookieSecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosQuerierHtpasswdSecret("foo")
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosQuerierRBACProxySecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosQuerierRoute()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ThanosQuerierService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.AlertmanagerService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.AlertmanagerServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.AlertmanagerMain("alertmanager-main.openshift-monitoring.svc", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.KubeStateMetricsClusterRoleBinding()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.KubeStateMetricsClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.KubeStateMetricsServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.KubeStateMetricsDeployment()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.KubeStateMetricsServiceAccount()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.KubeStateMetricsService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.OpenShiftStateMetricsClusterRoleBinding()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.OpenShiftStateMetricsClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.OpenShiftStateMetricsServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.OpenShiftStateMetricsDeployment()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.OpenShiftStateMetricsServiceAccount()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.OpenShiftStateMetricsService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.NodeExporterServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.NodeExporterDaemonSet()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.NodeExporterService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sClusterRoleBinding()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sRoleConfig()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sRoleBindingConfig()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sRoleBindingList()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sRoleList()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sPrometheusRule()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sThanosSidecarPrometheusRule()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sServiceAccount()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sTrustedCABundle()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8s("prometheus-k8s.openshift-monitoring.svc", &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sPrometheusServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sServingCertsCABundle()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterClusterRoleServerResources()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterClusterRoleAggregatedMetricsReader()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterClusterRoleBinding()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterClusterRoleBindingDelegator()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterRoleBindingAuthReader()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterServiceAccount()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterConfigMap()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterConfigMapPrometheus()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorUserWorkloadServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorUserWorkloadClusterRoleBinding()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorUserWorkloadClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorUserWorkloadServiceAccount()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorUserWorkloadService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadServingCertsCABundle()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadServiceAccount()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadClusterRoleBinding()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadRoleConfig()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadRoleList()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadRoleBindingList()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadRoleBindingConfig()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkload(&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusUserWorkloadPrometheusServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	tlsSecret := &v1.Secret{
		Data: map[string][]byte{
			"tls.crt": []byte("foo"),
			"tls.key": []byte("bar"),
		},
	}

	apiAuthConfigmap := &v1.ConfigMap{
		Data: map[string]string{
			"client-ca-file":               "foo",
			"requestheader-client-ca-file": "bar",
		},
	}

	_, err = f.PrometheusAdapterSecret(tlsSecret, apiAuthConfigmap)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterDeployment("foo", map[string]string{
		"requestheader-allowed-names":        "",
		"requestheader-extra-headers-prefix": "",
		"requestheader-group-headers":        "",
		"requestheader-username-headers":     "",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusAdapterAPIService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorClusterRoleBinding()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorServiceAccount()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorDeployment()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaClusterRoleBinding()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaConfig()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaDatasources()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaDashboardDefinitions()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaDashboardSources()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaTrustedCABundle()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaDeployment(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaProxySecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaRoute()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaServiceAccount()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GrafanaServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ClusterMonitoringClusterRoleView()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ClusterMonitoringRulesEditClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ClusterMonitoringRulesViewClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ClusterMonitoringEditClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ClusterMonitoringEditUserWorkloadConfigRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ClusterMonitoringOperatorService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ClusterMonitoringOperatorServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ControlPlaneEtcdServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ControlPlaneKubeletServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.TelemeterClientDeployment(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.TelemeterTrustedCABundle()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.AlertmanagerTrustedCABundle()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorUserWorkloadCRBACProxySecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.NodeExporterRBACProxySecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.TelemeterClientKubeRbacProxySecret()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusOperatorRBACProxySecret()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSharingConfig(t *testing.T) {
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	u, err := url.Parse("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}

	cm := f.SharingConfig(u, u, u, u)
	if cm.Namespace == "openshift-monitoring" {
		t.Fatalf("expecting namespace other than %q", "openshift-monitoring")
	}
	for k := range cm.Data {
		if !strings.Contains(k, "Public") {
			t.Fatalf("expecting key %q to contain 'Public'", k)
		}
	}
}

func TestPrometheusOperatorConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`prometheusOperator:
  nodeSelector:
    type: master
  image: quay.io/test/prometheus-operator
  prometheusConfigReloaderImage: quay.io/test/prometheus-config-reloader
  configReloaderImage: quay.io/test/configmap-reload
`)

	c.SetImages(map[string]string{
		"prometheus-operator":        "docker.io/openshift/origin-prometheus-operator:latest",
		"prometheus-config-reloader": "docker.io/openshift/origin-prometheus-config-reloader:latest",
		"configmap-reloader":         "docker.io/openshift/origin-configmap-reloader:latest",
		"kube-rbac-proxy":            "docker.io/openshift/origin-kube-rbac-proxy:latest",
	})

	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	d, err := f.PrometheusOperatorDeployment()
	if err != nil {
		t.Fatal(err)
	}

	if len(d.Spec.Template.Spec.NodeSelector) == 0 {
		t.Fatal("expected node selector to be present, got none")
	}

	if got := d.Spec.Template.Spec.NodeSelector["type"]; got != "master" {
		t.Fatalf("expected node selector to be master, got %q", got)
	}

	prometheusReloaderFound := false
	prometheusWebTLSCipherSuitesArg := ""
	prometheusWebTLSVersionArg := ""
	kubeRbacProxyTLSCipherSuitesArg := ""
	kubeRbacProxyMinTLSVersionArg := ""
	for _, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "prometheus-operator":
			if container.Image != "docker.io/openshift/origin-prometheus-operator:latest" {
				t.Fatalf("%s image incorrectly configured", container.Name)
			}

			if getContainerArgValue(d.Spec.Template.Spec.Containers, PrometheusConfigReloaderFlag+"docker.io/openshift/origin-prometheus-config-reloader:latest", container.Name) != "" {
				prometheusReloaderFound = true
			}
			prometheusWebTLSCipherSuitesArg = getContainerArgValue(d.Spec.Template.Spec.Containers, PrometheusOperatorWebTLSCipherSuitesFlag, container.Name)
			prometheusWebTLSVersionArg = getContainerArgValue(d.Spec.Template.Spec.Containers, PrometheusOperatorWebTLSMinTLSVersionFlag, container.Name)
		case "kube-rbac-proxy":
			if container.Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
				t.Fatalf("%s image incorrectly configured", container.Name)
			}
			kubeRbacProxyTLSCipherSuitesArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyTLSCipherSuitesFlag, container.Name)
			kubeRbacProxyMinTLSVersionArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyMinTLSVersionFlag, container.Name)
		}
	}

	if !prometheusReloaderFound {
		t.Fatal("Configuring the Prometheus Config reloader image failed")
	}

	expectedPrometheusWebTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		PrometheusOperatorWebTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))
	if expectedPrometheusWebTLSCipherSuitesArg != prometheusWebTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", prometheusWebTLSCipherSuitesArg, expectedPrometheusWebTLSCipherSuitesArg)
	}

	expectedPrometheusWebTLSVersionArg := fmt.Sprintf("%s%s",
		PrometheusOperatorWebTLSMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedPrometheusWebTLSVersionArg != prometheusWebTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", prometheusWebTLSVersionArg, expectedPrometheusWebTLSVersionArg)
	}

	expectedKubeRbacProxyTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		KubeRbacProxyTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))

	if expectedKubeRbacProxyTLSCipherSuitesArg != kubeRbacProxyTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", kubeRbacProxyTLSCipherSuitesArg, expectedKubeRbacProxyTLSCipherSuitesArg)
	}

	expectedKubeRbacProxyMinTLSVersionArg := fmt.Sprintf("%s%s",
		KubeRbacProxyMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedKubeRbacProxyMinTLSVersionArg != kubeRbacProxyMinTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", kubeRbacProxyMinTLSVersionArg, expectedKubeRbacProxyMinTLSVersionArg)
	}

	d2, err := f.PrometheusOperatorDeployment()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(d, d2) {
		t.Fatal("expected PrometheusOperatorDeployment to be an idempotent function")
	}
}

func getContainerArgValue(containers []v1.Container, argFlag string, containerName string) string {
	for _, container := range containers {
		if container.Name == containerName {
			for _, arg := range container.Args {
				if strings.HasPrefix(arg, argFlag) {
					return arg
				}
			}
		}
	}
	return ""
}

func TestPrometheusK8sRemoteWrite(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		config                  func() *Config
		expectedRemoteWriteURLs []string
	}{
		{
			name: "default config",

			config: func() *Config {
				c, err := NewConfigFromString("")
				if err != nil {
					t.Fatal(err)
				}

				return c
			},

			expectedRemoteWriteURLs: nil,
		},
		{
			name: "legacy telemetry",

			config: func() *Config {
				c, err := NewConfigFromString("")
				if err != nil {
					t.Fatal(err)
				}

				c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID = "123"
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token = "secret"

				return c
			},

			expectedRemoteWriteURLs: nil,
		},
		{
			name: "legacy telemetry and custom remote write",

			config: func() *Config {
				c, err := NewConfigFromString("")
				if err != nil {
					t.Fatal(err)
				}

				c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID = "123"
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token = "secret"
				c.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite = []RemoteWriteSpec{{URL: "http://custom"}}

				return c
			},

			expectedRemoteWriteURLs: []string{
				"http://custom",
			},
		},
		{
			name: "remote write telemetry",

			config: func() *Config {
				c, err := NewConfigFromString("")
				if err != nil {
					t.Fatal(err)
				}

				c.SetRemoteWrite(true)
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID = "123"
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token = "secret"

				return c
			},

			expectedRemoteWriteURLs: []string{
				"https://infogw.api.openshift.com/metrics/v1/receive",
			},
		},
		{
			name: "remote write telemetry and custom remote write",

			config: func() *Config {
				c, err := NewConfigFromString("")
				if err != nil {
					t.Fatal(err)
				}

				c.SetRemoteWrite(true)
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID = "123"
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token = "secret"
				c.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite = []RemoteWriteSpec{{URL: "http://custom"}}

				return c
			},

			expectedRemoteWriteURLs: []string{
				"http://custom",
				"https://infogw.api.openshift.com/metrics/v1/receive",
			},
		},
		{
			name: "remote write telemetry with custom url and custom remote write",

			config: func() *Config {
				c, err := NewConfigFromString("")
				if err != nil {
					t.Fatal(err)
				}

				c.SetRemoteWrite(true)
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.TelemeterServerURL = "http://custom-telemeter"
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID = "123"
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token = "secret"
				c.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite = []RemoteWriteSpec{{URL: "http://custom-remote-write"}}

				return c
			},

			expectedRemoteWriteURLs: []string{
				"http://custom-remote-write",
				"http://custom-telemeter",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.config()

			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
			p, err := f.PrometheusK8s(
				"prometheus-k8s.openshift-monitoring.svc",
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			)
			if err != nil {
				t.Fatal(err)
			}

			var got []string
			for _, rw := range p.Spec.RemoteWrite {
				got = append(got, rw.URL)
			}
			sort.Strings(got)
			sort.Strings(tc.expectedRemoteWriteURLs)

			if !reflect.DeepEqual(got, tc.expectedRemoteWriteURLs) {
				t.Errorf("want remote write URLs %v, got %v", tc.expectedRemoteWriteURLs, got)
			}
		})
	}
}

func TestPrometheusK8sConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`prometheusK8s:
  retention: 25h
  nodeSelector:
    type: master
  tolerations:
  - effect: PreferNoSchedule
    operator: Exists
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 15Gi
  resources:
    limits:
      cpu: 200m
      memory: 1000Mi
    requests:
      cpu: 100m
      memory: 750Mi
  externalLabels:
    datacenter: eu-west
  remoteWrite:
  - url: "https://test.remotewrite.com/api/write"
  queryLogFile: /tmp/test
ingress:
  baseAddress: monitoring-demo.staging.core-os.net
`)

	if err != nil {
		t.Fatal(err)
	}
	c.SetImages(map[string]string{
		"prometheus":       "docker.io/openshift/origin-prometheus:latest",
		"oauth-proxy":      "docker.io/openshift/origin-oauth-proxy:latest",
		"kube-rbac-proxy":  "docker.io/openshift/origin-kube-rbac-proxy:latest",
		"prom-label-proxy": "docker.io/openshift/origin-prom-label-proxy:latest",
	})

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	p, err := f.PrometheusK8s(
		"prometheus-k8s.openshift-monitoring.svc",
		&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
		&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	if p.Spec.Retention != "25h" {
		t.Fatal("Retention is not configured correctly")
	}

	if *p.Spec.Image != "docker.io/openshift/origin-prometheus:latest" {
		t.Fatal("Prometheus image is not configured correctly")
	}

	kubeRbacProxyTLSCipherSuitesArg := ""
	kubeRbacProxyMinTLSVersionArg := ""
	for _, container := range p.Spec.Containers {
		switch container.Name {
		case "prometheus-proxy":
			if container.Image != "docker.io/openshift/origin-oauth-proxy:latest" {
				t.Fatalf("image for %s is not configured correctly: %s", container.Name, container.Image)
			}
			volumeName := "prometheus-trusted-ca-bundle"
			if !trustedCABundleVolumeConfigured(p.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !trustedCABundleVolumeMountsConfigured(container.VolumeMounts, volumeName) {
				t.Fatalf("trusted CA bundle volume mount for %s is not configured correctly", container.Name)
			}

		case "kube-rbac-proxy":
			if container.Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
				t.Fatalf("image for %s is not configured correctly: %s", container.Name, container.Image)
			}
			kubeRbacProxyTLSCipherSuitesArg = getContainerArgValue(p.Spec.Containers, KubeRbacProxyTLSCipherSuitesFlag, container.Name)
			kubeRbacProxyMinTLSVersionArg = getContainerArgValue(p.Spec.Containers, KubeRbacProxyMinTLSVersionFlag, container.Name)

		case "prom-label-proxy":
			if container.Image != "docker.io/openshift/origin-prom-label-proxy:latest" {
				t.Fatalf("image for %s is not configured correctly: %s", container.Name, container.Image)
			}
		case "prometheus":
			volumeName := "prometheus-trusted-ca-bundle"
			if !trustedCABundleVolumeConfigured(p.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !trustedCABundleVolumeMountsConfigured(container.VolumeMounts, volumeName) {
				t.Fatalf("trusted CA bundle volume mount for %s is not configured correctly", container.Name)
			}
		}
	}

	expectedKubeRbacProxyTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		KubeRbacProxyTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))

	if expectedKubeRbacProxyTLSCipherSuitesArg != kubeRbacProxyTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", kubeRbacProxyTLSCipherSuitesArg, expectedKubeRbacProxyTLSCipherSuitesArg)
	}

	expectedKubeRbacProxyMinTLSVersionArg := fmt.Sprintf("%s%s",
		KubeRbacProxyMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedKubeRbacProxyMinTLSVersionArg != kubeRbacProxyMinTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", kubeRbacProxyMinTLSVersionArg, expectedKubeRbacProxyMinTLSVersionArg)
	}

	cpuLimit := p.Spec.Resources.Limits[v1.ResourceCPU]
	memoryLimit := p.Spec.Resources.Limits[v1.ResourceMemory]
	cpuRequest := p.Spec.Resources.Requests[v1.ResourceCPU]
	memoryRequest := p.Spec.Resources.Requests[v1.ResourceMemory]
	cpuLimitPtr := &cpuLimit
	memoryLimitPtr := &memoryLimit
	cpuRequestPtr := &cpuRequest
	memoryRequestPtr := &memoryRequest
	if cpuLimitPtr.String() != "200m" {
		t.Fatal("Prometheus CPU limit is not configured correctly:", cpuLimitPtr.String())
	}
	if memoryLimitPtr.String() != "1000Mi" {
		t.Fatal("Prometheus memory limit is not configured correctly:", memoryLimitPtr.String())
	}
	if cpuRequestPtr.String() != "100m" {
		t.Fatal("Prometheus CPU request is not configured correctly:", cpuRequestPtr.String())
	}
	if memoryRequestPtr.String() != "750Mi" {
		t.Fatal("Prometheus memory request is not configured correctly:", memoryRequestPtr.String())
	}

	if p.Spec.NodeSelector["type"] != "master" {
		t.Fatal("Prometheus node selector not configured correctly")
	}

	if p.Spec.Tolerations[0].Effect != "PreferNoSchedule" {
		t.Fatal("Prometheus toleration effect not configured correctly")
	}
	if p.Spec.Tolerations[0].Operator != "Exists" {
		t.Fatal("Prometheus toleration effect not configured correctly")
	}

	if p.Spec.ExternalLabels["datacenter"] != "eu-west" {
		t.Fatal("Prometheus external labels are not configured correctly")
	}

	if p.Spec.AdditionalAlertManagerConfigs != nil {
		t.Fatal("additionalAlertmanagerConfigs should not be set")
	}

	storageRequest := p.Spec.Storage.VolumeClaimTemplate.Spec.Resources.Requests[v1.ResourceStorage]
	storageRequestPtr := &storageRequest
	if storageRequestPtr.String() != "15Gi" {
		t.Fatal("Prometheus volumeClaimTemplate not configured correctly, expected 15Gi storage request, but found", storageRequestPtr.String())
	}

	if p.Spec.RemoteWrite[0].URL != "https://test.remotewrite.com/api/write" {
		t.Fatal("Prometheus remote-write is not configured correctly")
	}

	if p.Spec.QueryLogFile != "/tmp/test" {
		t.Fatal("Prometheus query log is not configured correctly")
	}
}

func TestPrometheusK8sAdditionalAlertManagerConfigsSecret(t *testing.T) {
	testCases := []struct {
		name           string
		config         string
		expected       string
		mountedSecrets []string
	}{
		{
			name:           "empty config",
			config:         "",
			expected:       "[]\n",
			mountedSecrets: []string{},
		},
		{
			name: "basic config",
			config: `prometheusK8s:
  additionalAlertmanagerConfigs:
  - staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			expected: `- static_configs:
  - targets:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			mountedSecrets: []string{},
		},
		{
			name: "version, path and scheme override",
			config: `prometheusK8s:
  additionalAlertmanagerConfigs:
  - apiVersion: v1
    pathPrefix: /path
    scheme: ftp
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			expected: `- scheme: ftp
  path_prefix: /path
  api_version: v1
  static_configs:
  - targets:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			mountedSecrets: []string{},
		},
		{
			name: "bearer token",
			config: `prometheusK8s:
  additionalAlertmanagerConfigs:
  - apiVersion: v2
    scheme: https    
    bearerToken:
      name: alertmanager1-bearer-token
      key: token
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com`,
			expected: `- scheme: https
  api_version: v2
  authorization:
    credentials_file: /etc/prometheus/secrets/alertmanager1-bearer-token/token
  static_configs:
  - targets:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			mountedSecrets: []string{"alertmanager1-bearer-token"},
		},
		{
			name: "tls configuration token",
			config: `prometheusK8s:
  additionalAlertmanagerConfigs:
  - apiVersion: v2
    scheme: https    
    tlsConfig:
      ca:
        name: alertmanager-tls
        key: tls.ca
      cert:
        name: alertmanager-tls
        key: tls.ca
      key:
        name: alertmanager-tls
        key: tls.ca
      serverName: alertmanager-remote.com
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com`,
			expected: `- scheme: https
  api_version: v2
  tls_config:
    ca_file: /etc/prometheus/secrets/alertmanager-tls/tls.ca
    cert_file: /etc/prometheus/secrets/alertmanager-tls/tls.ca
    key_file: /etc/prometheus/secrets/alertmanager-tls/tls.ca
    server_name: alertmanager-remote.com
  static_configs:
  - targets:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			mountedSecrets: []string{"alertmanager-tls"},
		},
		{
			name: "tls configuration token",
			config: `prometheusK8s:
  additionalAlertmanagerConfigs:
  - apiVersion: v2
    scheme: https    
    tlsConfig:
      ca:
        name: alertmanager-ca-tls
        key: tls.ca
      cert:
        name: alertmanager-cert-tls
        key: tls.ca
      key:
        name: alertmanager-key-tls
        key: tls.ca
      serverName: alertmanager-remote.com
      insecureSkipVerify: true
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com`,
			expected: `- scheme: https
  api_version: v2
  tls_config:
    ca_file: /etc/prometheus/secrets/alertmanager-ca-tls/tls.ca
    cert_file: /etc/prometheus/secrets/alertmanager-cert-tls/tls.ca
    key_file: /etc/prometheus/secrets/alertmanager-key-tls/tls.ca
    server_name: alertmanager-remote.com
    insecure_skip_verify: true
  static_configs:
  - targets:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			mountedSecrets: []string{"alertmanager-ca-tls", "alertmanager-cert-tls", "alertmanager-key-tls"},
		},
		{
			name: "full configuration",
			config: `prometheusK8s:
  additionalAlertmanagerConfigs:
  - apiVersion: v2
    scheme: https
    bearerToken:
      name: alertmanager-bearer-token
      key: token
    tlsConfig:
      ca:
        name: alertmanager-ca-tls
        key: tls.ca
      cert:
        name: alertmanager-cert-tls
        key: tls.ca
      key:
        name: alertmanager-key-tls
        key: tls.ca
      serverName: alertmanager-remote.com
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com`,
			expected: `- scheme: https
  api_version: v2
  authorization:
    credentials_file: /etc/prometheus/secrets/alertmanager-bearer-token/token
  tls_config:
    ca_file: /etc/prometheus/secrets/alertmanager-ca-tls/tls.ca
    cert_file: /etc/prometheus/secrets/alertmanager-cert-tls/tls.ca
    key_file: /etc/prometheus/secrets/alertmanager-key-tls/tls.ca
    server_name: alertmanager-remote.com
  static_configs:
  - targets:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			mountedSecrets: []string{"alertmanager-bearer-token", "alertmanager-ca-tls", "alertmanager-cert-tls", "alertmanager-key-tls"},
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewConfigFromString(tt.config)
			if err != nil {
				t.Fatal(err)
			}
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})

			p, err := f.PrometheusK8s(
				"prometheus-k8s.openshift-monitoring.svc",
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			)

			secrets := make(map[string]struct{})
			for _, s := range p.Spec.Secrets {
				secrets[s] = struct{}{}
			}
			for _, exp := range tt.mountedSecrets {
				if _, found := secrets[exp]; found {
					continue
				}
				t.Fatalf("Prometheus secrets are not generated correctly, expected to have %s but got none", exp)
			}

			s, err := f.PrometheusK8sAdditionalAlertManagerConfigsSecret()
			if err != nil {
				t.Fatal(err)
			}

			if s.Name != PrometheusK8sAdditionalAlertmanagerConfigSecretName {
				t.Fatalf("invalid secret name, got %s, want %s", s.Name, PrometheusK8sAdditionalAlertmanagerConfigSecretName)
			}

			if s.Namespace != "openshift-monitoring" {
				t.Fatalf("invalid secret namespace, got %s, want %s", s.Namespace, "openshift-monitoring")
			}

			if !reflect.DeepEqual(string(s.Data[AdditionalAlertmanagerConfigSecretKey]), tt.expected) {
				t.Fatalf("additionalAlertmanagerConfigs is not configured correctly\n\ngot:\n\n%#+v\n\nexpected:\n\n%#+v\n", string(s.Data[AdditionalAlertmanagerConfigSecretKey]), tt.expected)
			}
		})
	}
}

func TestThanosRulerAdditionalAlertManagerConfigsSecret(t *testing.T) {
	testCases := []struct {
		name     string
		config   string
		expected string
	}{
		{
			name: "no config with alertmanager disabled",
			config: `alertmanagerMain:
  enabled: false`,
			expected: `alertmanagers: []`,
		},
		{
			name:   "no config",
			config: ``,
			expected: `"alertmanagers":
- "api_version": "v2"
  "http_config":
    "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    "tls_config":
      "ca_file": "/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt"
      "server_name": "alertmanager-main.openshift-monitoring.svc"
  "scheme": "https"
  "static_configs":
  - "dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc"`,
		},
		{
			name: "basic config",
			config: `thanosRuler:
  additionalAlertmanagerConfigs:
  - staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			expected: `"alertmanagers":
- "api_version": "v2"
  "http_config":
    "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    "tls_config":
      "ca_file": "/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt"
      "server_name": "alertmanager-main.openshift-monitoring.svc"
  "scheme": "https"
  "static_configs":
  - "dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc"
- static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
		{
			name: "basic config with alertmanager disabled",
			config: `thanosRuler:
  additionalAlertmanagerConfigs:
  - staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
alertmanagerMain:
  enabled: false
`,
			expected: `alertmanagers:
- static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
		{
			name: "version, path and scheme override",
			config: `thanosRuler:
  additionalAlertmanagerConfigs:
  - version: v1
    pathPrefix: /path-prefix
    scheme: ftp
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			expected: `"alertmanagers":
- "api_version": "v2"
  "http_config":
    "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    "tls_config":
      "ca_file": "/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt"
      "server_name": "alertmanager-main.openshift-monitoring.svc"
  "scheme": "https"
  "static_configs":
  - "dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc"
- scheme: ftp
  path_prefix: /path-prefix
  static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
		{
			name: "bearer token",
			config: `thanosRuler:
  additionalAlertmanagerConfigs:
  - bearerToken:
      key: key
      name: bearer-token
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			expected: `"alertmanagers":
- "api_version": "v2"
  "http_config":
    "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    "tls_config":
      "ca_file": "/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt"
      "server_name": "alertmanager-main.openshift-monitoring.svc"
  "scheme": "https"
  "static_configs":
  - "dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc"
- http_config:
    bearer_token_file: /etc/prometheus/secrets/bearer-token/key
  static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
		{
			name: "tls configuration token",
			config: `thanosRuler:
  additionalAlertmanagerConfigs:
  - tlsConfig:
      ca:
        name: alertmanager-tls
        key: tls.ca
      cert:
        name: alertmanager-tls
        key: tls.ca
      key:
        name: alertmanager-tls
        key: tls.ca
      serverName: alertmanager-remote.com
      insecureSkipVerify: true
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com`,
			expected: `"alertmanagers":
- "api_version": "v2"
  "http_config":
    "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    "tls_config":
      "ca_file": "/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt"
      "server_name": "alertmanager-main.openshift-monitoring.svc"
  "scheme": "https"
  "static_configs":
  - "dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc"
- http_config:
    tls_config:
      ca_file: /etc/prometheus/secrets/alertmanager-tls/tls.ca
      cert_file: /etc/prometheus/secrets/alertmanager-tls/tls.ca
      key_file: /etc/prometheus/secrets/alertmanager-tls/tls.ca
      server_name: alertmanager-remote.com
      insecure_skip_verify: true
  static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
		{
			name: "tls configuration token",
			config: `thanosRuler:
  additionalAlertmanagerConfigs:
  - tlsConfig:
      ca:
        name: alertmanager-ca-tls
        key: tls.ca
      cert:
        name: alertmanager-cert-tls
        key: tls.ca
      key:
        name: alertmanager-key-tls
        key: tls.ca
      serverName: alertmanager-remote.com
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com`,
			expected: `"alertmanagers":
- "api_version": "v2"
  "http_config":
    "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    "tls_config":
      "ca_file": "/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt"
      "server_name": "alertmanager-main.openshift-monitoring.svc"
  "scheme": "https"
  "static_configs":
  - "dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc"
- http_config:
    tls_config:
      ca_file: /etc/prometheus/secrets/alertmanager-ca-tls/tls.ca
      cert_file: /etc/prometheus/secrets/alertmanager-cert-tls/tls.ca
      key_file: /etc/prometheus/secrets/alertmanager-key-tls/tls.ca
      server_name: alertmanager-remote.com
  static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
		{
			name: "full configuration",
			config: `thanosRuler:
  additionalAlertmanagerConfigs:
  - apiVersion: v2
    scheme: https
    bearerToken:
      name: alertmanager-bearer-token
      key: token
    tlsConfig:
      ca:
        name: alertmanager-ca-tls
        key: tls.ca
      cert:
        name: alertmanager-cert-tls
        key: tls.ca
      key:
        name: alertmanager-key-tls
        key: tls.ca
      serverName: alertmanager-remote.com
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com`,
			expected: `"alertmanagers":
- "api_version": "v2"
  "http_config":
    "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    "tls_config":
      "ca_file": "/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt"
      "server_name": "alertmanager-main.openshift-monitoring.svc"
  "scheme": "https"
  "static_configs":
  - "dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc"
- scheme: https
  api_version: v2
  http_config:
    bearer_token_file: /etc/prometheus/secrets/alertmanager-bearer-token/token
    tls_config:
      ca_file: /etc/prometheus/secrets/alertmanager-ca-tls/tls.ca
      cert_file: /etc/prometheus/secrets/alertmanager-cert-tls/tls.ca
      key_file: /etc/prometheus/secrets/alertmanager-key-tls/tls.ca
      server_name: alertmanager-remote.com
  static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewConfigFromString(tt.config)
			if err != nil {
				t.Fatal(err)
			}
			uwc, err := NewUserConfigFromString(tt.config)
			if err != nil {
				t.Fatal(err)
			}
			c.UserWorkloadConfiguration = uwc
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})

			s, err := f.ThanosRulerAlertmanagerConfigSecret()
			if err != nil {
				t.Fatal(err)
			}

			if s.Name != "thanos-ruler-alertmanagers-config" {
				t.Fatalf("invalid secret name, got %s, want %s", s.Name, "thanos-ruler-alertmanagers-config")
			}

			if s.Namespace != "openshift-user-workload-monitoring" {
				t.Fatalf("invalid secret namepace, got %s, want %s", s.Namespace, "openshift-user-workload-monitoring")
			}

			if !reflect.DeepEqual(s.StringData["alertmanagers.yaml"], tt.expected) {
				t.Fatalf("additionalAlertmanagerConfigs is not configured correctly\n\ngot:\n\n%#+v\n\nexpected:\n\n%#+v\n", s.StringData["alertmanagers.yaml"], tt.expected)
			}
		})
	}
}

func TestK8sPrometheusAdapterAuditLog(t *testing.T) {
	argsForProfile := func(profile string) []string {
		return []string{
			fmt.Sprintf("--audit-policy-file=/etc/audit/%s-profile.yaml", profile),
			"--audit-log-path=/var/log/adapter/audit.log",
			"--audit-log-maxsize=100",
			"--audit-log-maxbackup=5",
			"--audit-log-compress=true",
		}
	}

	tt := []struct {
		scenario string
		config   string
		args     []string
		err      error
	}{{
		scenario: "no config",
		config:   ``,
		args:     argsForProfile("metadata"),
	}, {
		scenario: "no adapter config",
		config:   `k8sPrometheusAdapter: `,
		args:     argsForProfile("metadata"),
	}, {
		scenario: "no audit config",
		config: `
k8sPrometheusAdapter:
  audit: {} `,
		args: argsForProfile("metadata"),
	}, {
		scenario: "Request",
		config: `
k8sPrometheusAdapter:
  audit:
    profile: Request
`,
		args: argsForProfile("request"),
	}, {
		scenario: "RequestResponse",
		config: `
k8sPrometheusAdapter:
  audit:
    profile: RequestResponse
`,
		args: argsForProfile("requestresponse"),
	}, {
		scenario: "None",
		config: `
  k8sPrometheusAdapter:
    audit:
     profile: None
`,
		args: argsForProfile("none"),
	}, {
		scenario: "no audit config",
		config: `
  k8sPrometheusAdapter:
    audit:
      profile: Foobar  # should generate an error
`,
		err: ErrConfigValidation,
	}}

	for _, test := range tt {
		t.Run(test.scenario, func(t *testing.T) {
			c, err := NewConfigFromString(test.config)
			if err != nil {
				t.Logf("%s\n\n", test.config)
				t.Fatal(err)
			}

			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring",
				c, defaultInfrastructureReader(), &fakeProxyReader{},
				NewAssets(assetsPath), &APIServerConfig{})

			d, err := f.PrometheusAdapterDeployment("foo", map[string]string{
				"requestheader-allowed-names":        "",
				"requestheader-extra-headers-prefix": "",
				"requestheader-group-headers":        "",
				"requestheader-username-headers":     "",
			})

			if test.err != nil || err != nil {
				// fail only if the error isn't what is expected
				if !errors.Is(err, test.err) {
					t.Fatalf("Expected error %q but got %q", test.err, err)
				}
				return
			}

			adapterArgs := d.Spec.Template.Spec.Containers[0].Args
			auditArgs := []string{}
			for _, arg := range adapterArgs {
				if strings.HasPrefix(arg, "--audit-") {
					auditArgs = append(auditArgs, arg)
				}
			}
			assertDeepEqual(t, test.args, auditArgs,
				"k8s-prometheus-adapter audit is not configured correctly")
		})
	}
}

func assertDeepEqual(t *testing.T, expected, got interface{}, msg string) {
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf(`%s
got:
	%#+v

expected:
	%#+v
	`, msg, got, expected)
	}
}

func TestK8sPrometheusAdapterConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`
k8sPrometheusAdapter:
  nodeSelector:
    test: value
`)
	if err != nil {
		t.Fatal(err)
	}
	c.SetImages(map[string]string{
		"k8s-prometheus-adapter": "docker.io/openshift/origin-k8s-prometheus-adapter:latest",
	})

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	d, err := f.PrometheusAdapterDeployment("foo", map[string]string{
		"requestheader-allowed-names":        "",
		"requestheader-extra-headers-prefix": "",
		"requestheader-group-headers":        "",
		"requestheader-username-headers":     "",
	})
	if err != nil {
		t.Fatal(err)
	}

	if d.Spec.Template.Spec.Containers[0].Image != "docker.io/openshift/origin-k8s-prometheus-adapter:latest" {
		t.Fatal("k8s-prometheus-adapter image is not configured correctly")
	}
	expected := map[string]string{"test": "value"}
	if !reflect.DeepEqual(d.Spec.Template.Spec.NodeSelector, expected) {
		t.Fatalf("k8s-prometheus-adapter nodeSelector is not configured correctly\n\ngot:\n\n%#+v\n\nexpected:\n\n%#+v\n", d.Spec.Template.Spec.NodeSelector, expected)
	}
}

func TestAlertmanagerMainStartupProbe(t *testing.T) {
	for _, tc := range []struct {
		name                string
		config              string
		infrastructure      InfrastructureReader
		startupProbeDefined bool
	}{
		{
			name:                "without persistent storage",
			config:              `alertmanagerMain: {}`,
			infrastructure:      defaultInfrastructureReader(),
			startupProbeDefined: true,
		},
		{
			name:                "without persistent storage and single node",
			config:              `alertmanagerMain: {}`,
			infrastructure:      &fakeInfrastructureReader{highlyAvailableInfrastructure: false, hostedControlPlane: false},
			startupProbeDefined: false,
		},
		{
			name: "with persistent storage",
			config: `alertmanagerMain:
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 10Gi
`,
			infrastructure:      defaultInfrastructureReader(),
			startupProbeDefined: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewConfigFromString(tc.config)
			if err != nil {
				t.Fatal(err)
			}
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, tc.infrastructure, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
			a, err := f.AlertmanagerMain(
				"alertmanager-main.openshift-monitoring.svc",
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			)
			if err != nil {
				t.Fatal(err)
			}

			for _, container := range a.Spec.Containers {
				switch container.Name {
				case "alertmanager":
					if container.StartupProbe != nil {
						if !tc.startupProbeDefined {
							t.Fatal("Alertmanager container not configured correctly, expected no startupProbe, but found", container.StartupProbe.String())
						}
						return
					}

					if tc.startupProbeDefined {
						t.Fatal("Alertmanager container not configured correctly, expected startupProbe, but found none")
					}
					return
				}
			}

			if tc.startupProbeDefined {
				t.Fatal("Alertmanager container not found")
			}
		})
	}
}

func TestAlertmanagerMainConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`alertmanagerMain:
  logLevel: debug
  baseImage: quay.io/test/alertmanager
  nodeSelector:
    type: worker
  tolerations:
  - effect: PreferNoSchedule
    operator: Exists
  resources:
    limits:
      cpu: 20m
      memory: 100Mi
    requests:
      cpu: 10m
      memory: 75Mi
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 10Gi
ingress:
  baseAddress: monitoring-demo.staging.core-os.net
`)
	if err != nil {
		t.Fatal(err)
	}
	c.SetImages(map[string]string{
		"alertmanager": "docker.io/openshift/origin-prometheus-alertmanager:latest",
	})

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	a, err := f.AlertmanagerMain(
		"alertmanager-main.openshift-monitoring.svc",
		&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	if a.Spec.LogLevel != "debug" {
		t.Fatalf("Alertmanager logLevel is not configured correctly, want: 'debug', got: '%s'", a.Spec.LogLevel)
	}

	if *a.Spec.Image != "docker.io/openshift/origin-prometheus-alertmanager:latest" {
		t.Fatal("Alertmanager image is not configured correctly")
	}

	cpuLimit := a.Spec.Resources.Limits[v1.ResourceCPU]
	memoryLimit := a.Spec.Resources.Limits[v1.ResourceMemory]
	cpuRequest := a.Spec.Resources.Requests[v1.ResourceCPU]
	memoryRequest := a.Spec.Resources.Requests[v1.ResourceMemory]
	cpuLimitPtr := &cpuLimit
	memoryLimitPtr := &memoryLimit
	cpuRequestPtr := &cpuRequest
	memoryRequestPtr := &memoryRequest
	if cpuLimitPtr.String() != "20m" {
		t.Fatal("Alertmanager CPU limit is not configured correctly:", cpuLimitPtr.String())
	}
	if memoryLimitPtr.String() != "100Mi" {
		t.Fatal("Alertmanager memory limit is not configured correctly:", memoryLimitPtr.String())
	}
	if cpuRequestPtr.String() != "10m" {
		t.Fatal("Alertmanager CPU request is not configured correctly:", cpuRequestPtr.String())
	}
	if memoryRequestPtr.String() != "75Mi" {
		t.Fatal("Alertmanager memory request is not configured correctly:", memoryRequestPtr.String())
	}

	if a.Spec.NodeSelector["type"] != "worker" {
		t.Fatal("Alertmanager node selector not configured correctly")
	}

	if a.Spec.Tolerations[0].Effect != "PreferNoSchedule" {
		t.Fatal("Prometheus toleration effect not configured correctly")
	}
	if a.Spec.Tolerations[0].Operator != "Exists" {
		t.Fatal("Prometheus toleration effect not configured correctly")
	}

	storageRequest := a.Spec.Storage.VolumeClaimTemplate.Spec.Resources.Requests[v1.ResourceStorage]
	storageRequestPtr := &storageRequest
	if storageRequestPtr.String() != "10Gi" {
		t.Fatal("Alertmanager volumeClaimTemplate not configured correctly, expected 10Gi storage request, but found", storageRequestPtr.String())
	}

	kubeRbacProxyTLSCipherSuitesArg := ""
	kubeRbacProxyMinTLSVersionArg := ""
	for _, container := range a.Spec.Containers {
		volumeName := "alertmanager-trusted-ca-bundle"
		switch container.Name {
		case "prometheus-proxy", "prometheus":
			if !trustedCABundleVolumeConfigured(a.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !trustedCABundleVolumeMountsConfigured(container.VolumeMounts, volumeName) {
				t.Fatalf("trusted CA bundle volume mount for %s is not configured correctly", container.Name)
			}
		case "kube-rbac-proxy", "kube-rbac-proxy-metric":
			kubeRbacProxyTLSCipherSuitesArg = getContainerArgValue(a.Spec.Containers, KubeRbacProxyTLSCipherSuitesFlag, container.Name)
			kubeRbacProxyMinTLSVersionArg = getContainerArgValue(a.Spec.Containers, KubeRbacProxyMinTLSVersionFlag, container.Name)
		}
	}

	expectedKubeRbacProxyTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		KubeRbacProxyTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))

	if expectedKubeRbacProxyTLSCipherSuitesArg != kubeRbacProxyTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", kubeRbacProxyTLSCipherSuitesArg, expectedKubeRbacProxyTLSCipherSuitesArg)
	}

	expectedKubeRbacProxyMinTLSVersionArg := fmt.Sprintf("%s%s",
		KubeRbacProxyMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedKubeRbacProxyMinTLSVersionArg != kubeRbacProxyMinTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", kubeRbacProxyMinTLSVersionArg, expectedKubeRbacProxyMinTLSVersionArg)
	}
}

func TestNodeExporter(t *testing.T) {
	c, err := NewConfigFromString(``)
	if err != nil {
		t.Fatal(err)
	}
	c.SetImages(map[string]string{
		"node-exporter":   "docker.io/openshift/origin-prometheus-node-exporter:latest",
		"kube-rbac-proxy": "docker.io/openshift/origin-kube-rbac-proxy:latest",
	})

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})

	ds, err := f.NodeExporterDaemonSet()
	if err != nil {
		t.Fatal(err)
	}

	kubeRbacProxyTLSCipherSuitesArg := ""
	kubeRbacProxyMinTLSVersionArg := ""

	for _, container := range ds.Spec.Template.Spec.Containers {
		switch container.Name {
		case "node-exporter":
			if container.Image != "docker.io/openshift/origin-prometheus-node-exporter:latest" {
				t.Fatalf("image for node-exporter daemonset is wrong: %s", container.Name)
			}
		case "kube-rbac-proxy":
			if container.Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
				t.Fatalf("image for kube-rbac-proxy in node-exporter daemonset is wrong: %s", container.Name)
			}
			kubeRbacProxyTLSCipherSuitesArg = getContainerArgValue(ds.Spec.Template.Spec.Containers, KubeRbacProxyTLSCipherSuitesFlag, container.Name)
			kubeRbacProxyMinTLSVersionArg = getContainerArgValue(ds.Spec.Template.Spec.Containers, KubeRbacProxyMinTLSVersionFlag, container.Name)
		}
	}

	expectedKubeRbacProxyTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		KubeRbacProxyTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))

	if expectedKubeRbacProxyTLSCipherSuitesArg != kubeRbacProxyTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", kubeRbacProxyTLSCipherSuitesArg, expectedKubeRbacProxyTLSCipherSuitesArg)
	}

	expectedKubeRbacProxyMinTLSVersionArg := fmt.Sprintf("%s%s",
		KubeRbacProxyMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedKubeRbacProxyMinTLSVersionArg != kubeRbacProxyMinTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", kubeRbacProxyMinTLSVersionArg, expectedKubeRbacProxyMinTLSVersionArg)
	}

	ds2, err := f.NodeExporterDaemonSet()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(ds, ds2) {
		t.Fatal("expected NodeExporterDaemonSet to be an idempotent function")
	}
}

func TestKubeStateMetrics(t *testing.T) {
	c, err := NewConfigFromString(``)
	if err != nil {
		t.Fatal(err)
	}
	c.SetImages(map[string]string{
		"kube-state-metrics": "docker.io/openshift/origin-kube-state-metrics:latest",
		"kube-rbac-proxy":    "docker.io/openshift/origin-kube-rbac-proxy:latest",
	})

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})

	d, err := f.KubeStateMetricsDeployment()
	if err != nil {
		t.Fatal(err)
	}

	kubeRbacProxyTLSCipherSuitesArg := ""
	kubeRbacProxyMinTLSVersionArg := ""
	for _, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "kube-state-metrics":
			if container.Image != "docker.io/openshift/origin-kube-state-metrics:latest" {
				t.Fatal("kube-state-metrics image incorrectly configured")
			}
		case "kube-rbac-proxy-self", "kube-rbac-proxy-main":
			if container.Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
				t.Fatalf("%s image incorrectly configured", container.Name)
			}

			kubeRbacProxyTLSCipherSuitesArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyTLSCipherSuitesFlag, container.Name)
			kubeRbacProxyMinTLSVersionArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyMinTLSVersionFlag, container.Name)
		}
	}

	expectedKubeRbacProxyTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		KubeRbacProxyTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))

	if expectedKubeRbacProxyTLSCipherSuitesArg != kubeRbacProxyTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", kubeRbacProxyTLSCipherSuitesArg, expectedKubeRbacProxyTLSCipherSuitesArg)
	}

	expectedKubeRbacProxyMinTLSVersionArg := fmt.Sprintf("%s%s",
		KubeRbacProxyMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedKubeRbacProxyMinTLSVersionArg != kubeRbacProxyMinTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", kubeRbacProxyMinTLSVersionArg, expectedKubeRbacProxyMinTLSVersionArg)
	}

	d2, err := f.KubeStateMetricsDeployment()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(d, d2) {
		t.Fatal("expected KubeStateMetricsDeployment to be an idempotent function")
	}
}

func TestOpenShiftStateMetrics(t *testing.T) {
	c, err := NewConfigFromString(``)
	if err != nil {
		t.Fatal(err)
	}
	c.SetImages(map[string]string{
		"openshift-state-metrics": "docker.io/openshift/origin-openshift-state-metrics:latest",
		"kube-rbac-proxy":         "docker.io/openshift/origin-kube-rbac-proxy:latest",
	})

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})

	d, err := f.OpenShiftStateMetricsDeployment()
	if err != nil {
		t.Fatal(err)
	}

	kubeRbacProxyTLSCipherSuitesArg := ""
	kubeRbacProxyMinTLSVersionArg := ""
	for _, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "openshift-state-metrics":
			if container.Image != "docker.io/openshift/origin-openshift-state-metrics:latest" {
				t.Fatal("openshift-state-metrics image incorrectly configured")
			}

		case "kube-rbac-proxy-self", "kube-rbac-proxy-main":
			if container.Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
				t.Fatal("kube-rbac-proxy image incorrectly configured")
			}
			kubeRbacProxyTLSCipherSuitesArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyTLSCipherSuitesFlag, container.Name)
			kubeRbacProxyMinTLSVersionArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyMinTLSVersionFlag, container.Name)
		}
	}

	expectedKubeRbacProxyTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		KubeRbacProxyTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))

	if expectedKubeRbacProxyTLSCipherSuitesArg != kubeRbacProxyTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", kubeRbacProxyTLSCipherSuitesArg, expectedKubeRbacProxyTLSCipherSuitesArg)
	}

	expectedKubeRbacProxyMinTLSVersionArg := fmt.Sprintf("%s%s",
		KubeRbacProxyMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedKubeRbacProxyMinTLSVersionArg != kubeRbacProxyMinTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", kubeRbacProxyMinTLSVersionArg, expectedKubeRbacProxyMinTLSVersionArg)
	}

	d2, err := f.OpenShiftStateMetricsDeployment()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(d, d2) {
		t.Fatal("expected OpenShiftStateMetricsDeployment to be an idempotent function")
	}

}

func TestPrometheusK8sControlPlaneRulesFiltered(t *testing.T) {
	tests := []struct {
		name           string
		infrastructure InfrastructureReader
		verify         func(bool)
	}{
		{
			name:           "default config",
			infrastructure: defaultInfrastructureReader(),
			verify: func(api bool) {
				if !api {
					t.Fatal("did not get all expected kubernetes control plane rules")
				}
			},
		},
		{
			name:           "hosted control plane",
			infrastructure: &fakeInfrastructureReader{highlyAvailableInfrastructure: true, hostedControlPlane: true},
			verify: func(api bool) {
				if api {
					t.Fatalf("kubernetes control plane rules found, none expected")
				}
			},
		},
	}

	for _, tc := range tests {
		f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), tc.infrastructure, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
		r, err := f.ControlPlanePrometheusRule()
		if err != nil {
			t.Fatal(err)
		}
		apiServerRulesFound := false
		for _, g := range r.Spec.Groups {
			switch g.Name {
			case "kubernetes-system-apiserver":
				apiServerRulesFound = true
			}
		}
		tc.verify(apiServerRulesFound)
	}
}

func TestEtcdGrafanaDashboardFiltered(t *testing.T) {
	enabled := false
	c := NewDefaultConfig()
	c.ClusterMonitoringConfiguration.EtcdConfig.Enabled = &enabled
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})

	cms, err := f.GrafanaDashboardDefinitions()
	if err != nil {
		t.Fatal(err)
	}

	for _, cm := range cms.Items {
		if cm.Name == "grafana-dashboard-etcd" {
			t.Fatal("etcd dashboard found, even if etcd is disabled")
		}
	}
}

func TestEtcdGrafanaDashboard(t *testing.T) {
	enabled := true
	c := NewDefaultConfig()
	c.ClusterMonitoringConfiguration.EtcdConfig.Enabled = &enabled
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})

	cms, err := f.GrafanaDashboardDefinitions()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, cm := range cms.Items {
		if cm.Name == "grafana-dashboard-etcd" {
			found = true
		}
	}
	if !found {
		t.Fatal("etcd dashboard not found, even if etcd is enabled")
	}
}

func TestThanosQuerierConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`thanosQuerier:
  nodeSelector:
    type: foo
  tolerations:
  - effect: PreferNoSchedule
    operator: Exists
  resources:
    limits:
      cpu: 1m
      memory: 2Mi
    requests:
      cpu: 3m
      memory: 4Mi
`)

	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	d, err := f.ThanosQuerierDeployment(
		&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
		false,
		&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name      string
		want, got interface{}
	}{
		{
			name: "node selector",
			want: map[string]string{"type": "foo"},
			got:  d.Spec.Template.Spec.NodeSelector,
		},
		{
			name: "tolerations",
			want: []v1.Toleration{
				{
					Effect:   "PreferNoSchedule",
					Operator: "Exists",
				},
			},
			got: d.Spec.Template.Spec.Tolerations,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !reflect.DeepEqual(tc.got, tc.want) {
				t.Errorf("want %+v, got %+v", tc.want, tc.got)
			}
		})
	}

	kubeRbacProxyTLSCipherSuitesArg := ""
	kubeRbacProxyMinTLSVersionArg := ""
	for _, c := range d.Spec.Template.Spec.Containers {
		switch c.Name {
		case "thanos-query":
			for _, tc := range []struct {
				name, want string
				resource   func() *resource.Quantity
			}{
				{
					name:     "limits/cpu",
					want:     "1m",
					resource: c.Resources.Limits.Cpu,
				},
				{
					name:     "limits/memory",
					want:     "2Mi",
					resource: c.Resources.Limits.Memory,
				},
				{
					name:     "requests/cpu",
					want:     "3m",
					resource: c.Resources.Requests.Cpu,
				},
				{
					name:     "requests/memory",
					want:     "4Mi",
					resource: c.Resources.Requests.Memory,
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if got := tc.resource(); got.Cmp(resource.MustParse(tc.want)) != 0 {
						t.Errorf("want %v, got %v", tc.want, got)
					}
				})
			}

		case "oauth-proxy":
			volumeName := "thanos-querier-trusted-ca-bundle"
			if !trustedCABundleVolumeConfigured(d.Spec.Template.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", c.Name)
			}
			if !trustedCABundleVolumeMountsConfigured(c.VolumeMounts, volumeName) {
				t.Fatalf("trusted CA bundle volume mount for %s is not configured correctly", c.Name)
			}

		case "kube-rbac-proxy", "kube-rbac-proxy-rules", "kube-rbac-proxy-metrics":
			kubeRbacProxyTLSCipherSuitesArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyTLSCipherSuitesFlag, c.Name)
			kubeRbacProxyMinTLSVersionArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyMinTLSVersionFlag, c.Name)
		}
	}
	expectedKubeRbacProxyTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		KubeRbacProxyTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))

	if expectedKubeRbacProxyTLSCipherSuitesArg != kubeRbacProxyTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", kubeRbacProxyTLSCipherSuitesArg, expectedKubeRbacProxyTLSCipherSuitesArg)
	}

	expectedKubeRbacProxyMinTLSVersionArg := fmt.Sprintf("%s%s",
		KubeRbacProxyMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedKubeRbacProxyMinTLSVersionArg != kubeRbacProxyMinTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", kubeRbacProxyMinTLSVersionArg, expectedKubeRbacProxyMinTLSVersionArg)
	}
}

func TestGrafanaConfiguration(t *testing.T) {
	c, err := NewConfigFromString(``)
	if err != nil {
		t.Fatal(err)
	}
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	d, err := f.GrafanaDeployment(&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}})
	if err != nil {
		t.Fatal(err)
	}

	kubeRbacProxyTLSCipherSuitesArg := ""
	kubeRbacProxyMinTLSVersionArg := ""
	for _, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "grafana-proxy":
			volumeName := "grafana-trusted-ca-bundle"
			if !trustedCABundleVolumeConfigured(d.Spec.Template.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !trustedCABundleVolumeMountsConfigured(container.VolumeMounts, volumeName) {
				t.Fatalf("trusted CA bundle volume mount for %s is not configured correctly", container.Name)
			}
		case "kube-rbac-proxy-metrics":
			kubeRbacProxyTLSCipherSuitesArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyTLSCipherSuitesFlag, container.Name)
			kubeRbacProxyMinTLSVersionArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyMinTLSVersionFlag, container.Name)
		}
	}
	expectedKubeRbacProxyTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		KubeRbacProxyTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))

	if expectedKubeRbacProxyTLSCipherSuitesArg != kubeRbacProxyTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", kubeRbacProxyTLSCipherSuitesArg, expectedKubeRbacProxyTLSCipherSuitesArg)
	}

	expectedKubeRbacProxyMinTLSVersionArg := fmt.Sprintf("%s%s",
		KubeRbacProxyMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedKubeRbacProxyMinTLSVersionArg != kubeRbacProxyMinTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", kubeRbacProxyMinTLSVersionArg, expectedKubeRbacProxyMinTLSVersionArg)
	}
}

func TestTelemeterConfiguration(t *testing.T) {
	c, err := NewConfigFromString(``)
	if err != nil {
		t.Fatal(err)
	}
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	d, err := f.TelemeterClientDeployment(&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}})
	if err != nil {
		t.Fatal(err)
	}

	kubeRbacProxyTLSCipherSuitesArg := ""
	kubeRbacProxyMinTLSVersionArg := ""
	for _, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "telemeter-client":
			volumeName := "telemeter-trusted-ca-bundle"
			if !trustedCABundleVolumeConfigured(d.Spec.Template.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !trustedCABundleVolumeMountsConfigured(container.VolumeMounts, volumeName) {
				t.Fatalf("trusted CA bundle volume mount for %s is not configured correctly", container.Name)
			}
		case "kube-rbac-proxy":
			kubeRbacProxyTLSCipherSuitesArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyTLSCipherSuitesFlag, container.Name)
			kubeRbacProxyMinTLSVersionArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyMinTLSVersionFlag, container.Name)
		}
	}

	expectedKubeRbacProxyTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		KubeRbacProxyTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))

	if expectedKubeRbacProxyTLSCipherSuitesArg != kubeRbacProxyTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", kubeRbacProxyTLSCipherSuitesArg, expectedKubeRbacProxyTLSCipherSuitesArg)
	}

	expectedKubeRbacProxyMinTLSVersionArg := fmt.Sprintf("%s%s",
		KubeRbacProxyMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedKubeRbacProxyMinTLSVersionArg != kubeRbacProxyMinTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", kubeRbacProxyMinTLSVersionArg, expectedKubeRbacProxyMinTLSVersionArg)
	}
}

func TestThanosRulerConfiguration(t *testing.T) {
	c, err := NewConfigFromString(``)
	if err != nil {
		t.Fatal(err)
	}
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	tr, err := f.ThanosRulerCustomResource(
		"",
		&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
		&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, container := range tr.Spec.Containers {
		if container.Name == "thanos-ruler-proxy" {
			volumeName := "thanos-ruler-trusted-ca-bundle"
			if !trustedCABundleVolumeConfigured(tr.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !trustedCABundleVolumeMountsConfigured(container.VolumeMounts, volumeName) {
				t.Fatalf("trusted CA bundle volume mount for %s is not configured correctly", container.Name)
			}
		}
	}
}

func TestNonHighlyAvailableInfrastructure(t *testing.T) {
	type spec struct {
		replicas int32
		affinity *v1.Affinity
	}

	tests := []struct {
		name    string
		getSpec func(f *Factory) (spec, error)
	}{
		{
			name: "Prometheus",
			getSpec: func(f *Factory) (spec, error) {
				p, err := f.PrometheusK8s(
					"prometheus-k8s.openshift-monitoring.svc",
					&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
					&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				)
				if err != nil {
					return spec{}, err
				}
				return spec{*p.Spec.Replicas, p.Spec.Affinity}, nil
			},
		},
		{
			name: "Alertmanager",
			getSpec: func(f *Factory) (spec, error) {
				a, err := f.AlertmanagerMain(
					"alertmanager-main.openshift-monitoring.svc",
					&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				)
				if err != nil {
					return spec{}, err
				}
				return spec{*a.Spec.Replicas, a.Spec.Affinity}, nil
			},
		},
		{
			name: "Thanos querier",
			getSpec: func(f *Factory) (spec, error) {
				q, err := f.ThanosQuerierDeployment(
					&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
					true,
					&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				)
				if err != nil {
					return spec{}, err
				}
				return spec{*q.Spec.Replicas, q.Spec.Template.Spec.Affinity}, nil
			},
		},
		{
			name: "Prometheus (user-workload)",
			getSpec: func(f *Factory) (spec, error) {
				p, err := f.PrometheusUserWorkload(
					&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				)
				if err != nil {
					return spec{}, err
				}
				return spec{*p.Spec.Replicas, p.Spec.Affinity}, nil
			},
		},
		{
			name: "Thanos ruler",
			getSpec: func(f *Factory) (spec, error) {
				t, err := f.ThanosRulerCustomResource(
					"",
					&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
					&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
					nil,
				)
				if err != nil {
					return spec{}, err
				}
				return spec{*t.Spec.Replicas, t.Spec.Affinity}, nil
			},
		},
		{
			name: "Prometheus adapter",
			getSpec: func(f *Factory) (spec, error) {
				p, err := f.PrometheusAdapterDeployment("foo",
					map[string]string{
						"requestheader-allowed-names":        "",
						"requestheader-extra-headers-prefix": "",
						"requestheader-group-headers":        "",
						"requestheader-username-headers":     "",
					})
				if err != nil {
					return spec{}, err
				}
				return spec{*p.Spec.Replicas, p.Spec.Template.Spec.Affinity}, nil
			},
		},
	}

	for _, tc := range tests {
		f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), &fakeInfrastructureReader{highlyAvailableInfrastructure: false}, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
		spec, err := tc.getSpec(f)
		if err != nil {
			t.Error(err)
		}

		if spec.replicas != 1 {
			t.Errorf("expecting 1 replica, got %d", spec.replicas)
		}

		if spec.affinity != nil {
			t.Errorf("expected no affinity constraints with 1 replica, got %v", spec.affinity)
		}
	}
}

func TestPodDisruptionBudget(t *testing.T) {
	tests := []struct {
		name   string
		getPDB func(f *Factory) (*policyv1.PodDisruptionBudget, error)
		ha     bool
	}{
		{
			name: "PrometheusK8s HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.PrometheusK8sPodDisruptionBudget()
			},
			ha: true,
		},
		{
			name: "PrometheusK8s non-HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.PrometheusK8sPodDisruptionBudget()
			},
			ha: false,
		},
		{
			name: "Alertmanager HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.AlertmanagerPodDisruptionBudget()
			},
			ha: true,
		},
		{
			name: "Alertmanager non-HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.AlertmanagerPodDisruptionBudget()
			},
			ha: false,
		},
		{
			name: "PrometheusAdapter HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.PrometheusAdapterPodDisruptionBudget()
			},
			ha: true,
		},
		{
			name: "PrometheusAdapter non-HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.PrometheusAdapterPodDisruptionBudget()
			},
			ha: false,
		},
		{
			name: "ThanosQuerier HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.ThanosQuerierPodDisruptionBudget()
			},
			ha: true,
		},
		{
			name: "ThanosQuerier non-HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.ThanosQuerierPodDisruptionBudget()
			},
			ha: false,
		},
		{
			name: "PrometheusUWM HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.PrometheusUserWorkloadPodDisruptionBudget()
			},
			ha: true,
		},
		{
			name: "PrometheusUWM non-HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.PrometheusUserWorkloadPodDisruptionBudget()
			},
			ha: false,
		},
		{
			name: "ThanosRuler HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.ThanosRulerPodDisruptionBudget()
			},
			ha: true,
		},
		{
			name: "ThanosRuler non-HA",
			getPDB: func(f *Factory) (*policyv1.PodDisruptionBudget, error) {
				return f.ThanosRulerPodDisruptionBudget()
			},
			ha: false,
		},
	}

	for _, tc := range tests {
		f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), &fakeInfrastructureReader{highlyAvailableInfrastructure: tc.ha}, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
		pdb, err := tc.getPDB(f)
		if err != nil {
			t.Error(err)
		}

		if tc.ha && pdb == nil {
			t.Error("expected PodDisruptionBudget in HA infrastructure")
		} else if !tc.ha && pdb != nil {
			t.Error("unexpected PodDisruptionBudget in non-HA infrastructure")
		}
	}

}

func TestPrometheusOperatorUserWorkloadConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`
enableUserWorkload: true
`)

	c.SetImages(map[string]string{
		"prometheus-operator":        "docker.io/openshift/origin-prometheus-operator:latest",
		"prometheus-config-reloader": "docker.io/openshift/origin-prometheus-config-reloader:latest",
		"configmap-reloader":         "docker.io/openshift/origin-configmap-reloader:latest",
		"kube-rbac-proxy":            "docker.io/openshift/origin-kube-rbac-proxy:latest",
	})

	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{})
	d, err := f.PrometheusOperatorUserWorkloadDeployment()
	if err != nil {
		t.Fatal(err)
	}

	prometheusReloaderFound := false
	prometheusWebTLSCipherSuitesArg := ""
	prometheusWebTLSVersionArg := ""
	kubeRbacProxyTLSCipherSuitesArg := ""
	kubeRbacProxyMinTLSVersionArg := ""
	for _, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "prometheus-operator":
			if container.Image != "docker.io/openshift/origin-prometheus-operator:latest" {
				t.Fatalf("%s image incorrectly configured", container.Name)
			}
			if getContainerArgValue(d.Spec.Template.Spec.Containers, PrometheusConfigReloaderFlag+"docker.io/openshift/origin-prometheus-config-reloader:latest", container.Name) != "" {
				prometheusReloaderFound = true
			}

			prometheusWebTLSCipherSuitesArg = getContainerArgValue(d.Spec.Template.Spec.Containers, PrometheusOperatorWebTLSCipherSuitesFlag, container.Name)
			prometheusWebTLSVersionArg = getContainerArgValue(d.Spec.Template.Spec.Containers, PrometheusOperatorWebTLSMinTLSVersionFlag, container.Name)

		case "kube-rbac-proxy":
			if container.Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
				t.Fatal("kube-rbac-proxy image incorrectly configured")
			}
			kubeRbacProxyTLSCipherSuitesArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyTLSCipherSuitesFlag, container.Name)
			kubeRbacProxyMinTLSVersionArg = getContainerArgValue(d.Spec.Template.Spec.Containers, KubeRbacProxyMinTLSVersionFlag, container.Name)
		}
	}

	if !prometheusReloaderFound {
		t.Fatal("Configuring the Prometheus Config reloader image failed")
	}

	expectedPrometheusWebTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		PrometheusOperatorWebTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","),
	)
	if expectedPrometheusWebTLSCipherSuitesArg != prometheusWebTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", prometheusWebTLSCipherSuitesArg, expectedPrometheusWebTLSCipherSuitesArg)
	}

	expectedPrometheusWebTLSVersionArg := fmt.Sprintf("%s%s",
		PrometheusOperatorWebTLSMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedPrometheusWebTLSVersionArg != prometheusWebTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", prometheusWebTLSVersionArg, expectedPrometheusWebTLSVersionArg)
	}

	expectedKubeRbacProxyTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		KubeRbacProxyTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))

	if expectedKubeRbacProxyTLSCipherSuitesArg != kubeRbacProxyTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", kubeRbacProxyTLSCipherSuitesArg, expectedKubeRbacProxyTLSCipherSuitesArg)
	}

	expectedKubeRbacProxyMinTLSVersionArg := fmt.Sprintf("%s%s",
		KubeRbacProxyMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedKubeRbacProxyMinTLSVersionArg != kubeRbacProxyMinTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", kubeRbacProxyMinTLSVersionArg, expectedKubeRbacProxyMinTLSVersionArg)
	}

	d2, err := f.PrometheusOperatorUserWorkloadDeployment()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(d, d2) {
		t.Fatal("expected PrometheusOperatorUserWorkloadDeployment to be an idempotent function")
	}
}

func trustedCABundleVolumeConfigured(volumes []v1.Volume, volumeName string) bool {
	for _, volume := range volumes {
		if volume.Name == volumeName {
			return true
		}
	}
	return false
}

func trustedCABundleVolumeMountsConfigured(volumeMounts []v1.VolumeMount, volumeName string) bool {
	for _, volumeMount := range volumeMounts {
		if volumeMount.Name == volumeName {
			return true
		}
	}
	return false
}
