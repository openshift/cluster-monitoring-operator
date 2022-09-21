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
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/crypto"

	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	configv1 "github.com/openshift/api/config/v1"
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
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
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
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
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

	_, err = f.AlertmanagerMain(nil)
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

	_, err = f.PrometheusK8s(&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}}, nil)
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
	}, "adapter-config")
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

	_, err = f.ClusterMonitoringAlertingEditClusterRole()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.ClusterMonitoringEditUserWorkloadConfigRole()
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
	for _, tc := range []struct {
		name string
		url  string
	}{
		{
			name: "simple url",
			url:  "http://example.com/",
		},
		{
			name: "assert path component is dropped",
			url:  "http://example.com/some/path",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
			u, err := url.Parse("http://example.com/")
			if err != nil {
				t.Fatal(err)
			}

			cm := f.SharingConfig(u, u, u, "alertmanager-main.openshift-monitoring.svc:9094", "alertmanager-main.openshift-monitoring.svc:9092")
			if cm.Namespace == "openshift-monitoring" {
				t.Fatalf("expecting namespace other than %q", "openshift-monitoring")
			}
			for k, v := range cm.Data {
				if !strings.Contains(k, "Public") {
					continue
				}
				publicURL, err := url.Parse(v)
				if err != nil {
					t.Fatal(err)
				}
				if v != fmt.Sprintf("%s://%s", publicURL.Scheme, publicURL.Host) {
					t.Fatalf("expecting public URLs on only contain <scheme>://<host>, got %s", v)
				}
			}
		})
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

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
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

func TestPrometheusOperatorAdmissionWebhookConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`prometheusOperator:
  nodeSelector:
    type: master
`)

	c.SetImages(map[string]string{
		"prometheus-operator-admission-webhook": "docker.io/openshift/origin-prometheus-operator-admission-webhook:latest",
	})

	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
	d, err := f.PrometheusOperatorAdmissionWebhookDeployment()
	if err != nil {
		t.Fatal(err)
	}

	if len(d.Spec.Template.Spec.NodeSelector) == 0 {
		t.Fatal("expected node selector to be present, got none")
	}

	if got := d.Spec.Template.Spec.NodeSelector["type"]; got != "master" {
		t.Fatalf("expected node selector to be master, got %q", got)
	}

	webTLSCipherSuitesArg := ""
	webTLSVersionArg := ""
	for _, container := range d.Spec.Template.Spec.Containers {
		switch container.Name {
		case "prometheus-operator-admission-webhook":
			if container.Image != "docker.io/openshift/origin-prometheus-operator-admission-webhook:latest" {
				t.Fatalf("%s image incorrectly configured", container.Name)
			}

			webTLSCipherSuitesArg = getContainerArgValue(d.Spec.Template.Spec.Containers, PrometheusOperatorWebTLSCipherSuitesFlag, container.Name)
			webTLSVersionArg = getContainerArgValue(d.Spec.Template.Spec.Containers, PrometheusOperatorWebTLSMinTLSVersionFlag, container.Name)
		}
	}

	expectedPrometheusWebTLSCipherSuitesArg := fmt.Sprintf("%s%s",
		PrometheusOperatorWebTLSCipherSuitesFlag,
		strings.Join(crypto.OpenSSLToIANACipherSuites(APIServerDefaultTLSCiphers), ","))
	if expectedPrometheusWebTLSCipherSuitesArg != webTLSCipherSuitesArg {
		t.Fatalf("incorrect TLS ciphers, \n got %s, \nwant %s", webTLSCipherSuitesArg, expectedPrometheusWebTLSCipherSuitesArg)
	}

	expectedPrometheusWebTLSVersionArg := fmt.Sprintf("%s%s",
		PrometheusOperatorWebTLSMinTLSVersionFlag, APIServerDefaultMinTLSVersion)
	if expectedPrometheusWebTLSVersionArg != webTLSVersionArg {
		t.Fatalf("incorrect TLS version \n got %s, \nwant %s", webTLSVersionArg, expectedPrometheusWebTLSVersionArg)
	}

	d2, err := f.PrometheusOperatorAdmissionWebhookDeployment()
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
			arg, ok := getArgValue(container, argFlag)
			if ok {
				return arg.original
			}
		}
	}
	return ""
}

type argValue struct {
	key      string
	value    string
	original string
}

// returns the value of the container arg if found or false
func getArgValue(container v1.Container, flag string) (argValue, bool) {
	for _, arg := range container.Args {
		if strings.HasPrefix(arg, flag) {
			parts := strings.Split(arg, "=")
			return argValue{
				key:      parts[0],
				value:    parts[1],
				original: arg,
			}, true
		}
	}
	return argValue{}, false
}

func TestPrometheusK8sRemoteWriteClusterIDRelabel(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		config                            func() *Config
		expectedRemoteWriteRelabelConfigs [][]monv1.RelabelConfig
	}{
		{
			name: "simple remote write",

			config: func() *Config {
				c, err := NewConfigFromString("")
				if err != nil {
					t.Fatal(err)
				}

				c.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite = []RemoteWriteSpec{{URL: "http://custom"}}

				return c
			},

			expectedRemoteWriteRelabelConfigs: [][]monv1.RelabelConfig{
				{
					{
						TargetLabel: "__tmp_openshift_cluster_id__",
						Replacement: "",
					},
					{
						Regex:  "__tmp_openshift_cluster_id__",
						Action: "labeldrop",
					},
				},
			},
		},
		{
			name: "simple remote write with relabel config",

			config: func() *Config {
				c, err := NewConfigFromString("")
				if err != nil {
					t.Fatal(err)
				}

				c.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite = []RemoteWriteSpec{
					{
						URL: "http://custom",
						WriteRelabelConfigs: []monv1.RelabelConfig{
							{
								SourceLabels: []monv1.LabelName{"__tmp_openshift_cluster_id__"},
								TargetLabel:  "cluster",
							},
						},
					},
				}

				return c
			},

			expectedRemoteWriteRelabelConfigs: [][]monv1.RelabelConfig{
				{
					{
						TargetLabel: "__tmp_openshift_cluster_id__",
						Replacement: "",
					},
					{
						SourceLabels: []monv1.LabelName{"__tmp_openshift_cluster_id__"},
						TargetLabel:  "cluster",
					},
					{
						Regex:  "__tmp_openshift_cluster_id__",
						Action: "labeldrop",
					},
				},
			},
		},
		{
			name: "multiple remote write with relabel config",

			config: func() *Config {
				c, err := NewConfigFromString("")
				if err != nil {
					t.Fatal(err)
				}

				c.ClusterMonitoringConfiguration.PrometheusK8sConfig.RemoteWrite = []RemoteWriteSpec{
					{
						URL: "http://custom",
						WriteRelabelConfigs: []monv1.RelabelConfig{
							{
								SourceLabels: []monv1.LabelName{"__tmp_openshift_cluster_id__"},
								TargetLabel:  "cluster",
							},
						},
					},
					{
						URL: "http://other_custom",
						WriteRelabelConfigs: []monv1.RelabelConfig{
							{
								SourceLabels: []monv1.LabelName{"__tmp_openshift_cluster_id__"},
								TargetLabel:  "some_other_label",
							},
							{
								TargetLabel: "unrelated_to_cluster_id",
								Replacement: "some_value",
							},
						},
					},
				}

				return c
			},

			expectedRemoteWriteRelabelConfigs: [][]monv1.RelabelConfig{
				{
					{
						TargetLabel: "__tmp_openshift_cluster_id__",
						Replacement: "",
					},
					{
						SourceLabels: []monv1.LabelName{"__tmp_openshift_cluster_id__"},
						TargetLabel:  "cluster",
					},
					{
						Regex:  "__tmp_openshift_cluster_id__",
						Action: "labeldrop",
					},
				},
				{
					{
						TargetLabel: "__tmp_openshift_cluster_id__",
						Replacement: "",
					},
					{
						SourceLabels: []monv1.LabelName{"__tmp_openshift_cluster_id__"},
						TargetLabel:  "some_other_label",
					},
					{
						TargetLabel: "unrelated_to_cluster_id",
						Replacement: "some_value",
					},
					{
						Regex:  "__tmp_openshift_cluster_id__",
						Action: "labeldrop",
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.config()

			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
			p, err := f.PrometheusK8s(
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			)
			if err != nil {
				t.Fatal(err)
			}

			var got [][]monv1.RelabelConfig
			for _, rw := range p.Spec.RemoteWrite {
				got = append(got, rw.WriteRelabelConfigs)
			}

			if !reflect.DeepEqual(got, tc.expectedRemoteWriteRelabelConfigs) {
				t.Errorf("want remote write relabel config %v, got %v", tc.expectedRemoteWriteRelabelConfigs, got)
			}
		})
	}
}

func TestPrometheusK8sRemoteWriteURLs(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		config                  func() *Config
		expectedRemoteWriteURLs []string
	}{
		{
			name: "default config",

			config: func() *Config {
				c := NewDefaultConfig()
				return c
			},

			expectedRemoteWriteURLs: nil,
		},
		{
			name: "legacy telemetry",

			config: func() *Config {
				c := NewDefaultConfig()
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID = "123"
				c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token = "secret"

				return c
			},

			expectedRemoteWriteURLs: nil,
		},
		{
			name: "legacy telemetry and custom remote write",

			config: func() *Config {
				c := NewDefaultConfig()
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
				c := NewDefaultConfig()
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
				c := NewDefaultConfig()
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
				c := NewDefaultConfig()
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

			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
			p, err := f.PrometheusK8s(
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

func TestPrometheusK8sRemoteWriteOauth2(t *testing.T) {
	expectedOauth2Config := monv1.OAuth2{
		ClientID: monv1.SecretOrConfigMap{
			Secret: &v1.SecretKeySelector{
				LocalObjectReference: v1.LocalObjectReference{
					Name: "oauth2-credentials",
				},
				Key: "id",
			},
		},
		ClientSecret: v1.SecretKeySelector{
			LocalObjectReference: v1.LocalObjectReference{
				Name: "oauth2-credentials",
			},
			Key: "secret",
		},
		TokenURL: "https://example.com/oauth2/token",
		Scopes:   []string{"scope1", "scope2"},
		EndpointParams: map[string]string{
			"param1": "value1",
			"param2": "value2",
		},
	}
	c, err := NewConfigFromString(`prometheusK8s:
  remoteWrite:
    - url: https://test.remotewrite.com/api/write
      remoteTimeout: 30s
      oauth2:
        clientId:
          secret:
            name: oauth2-credentials
            key: id
        clientSecret:
          name: oauth2-credentials
          key: secret
        tokenUrl: https://example.com/oauth2/token
        scopes:
          - scope1
          - scope2
        endpointParams:
          param1: value1
          param2: value2
`)
	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
	p, err := f.PrometheusK8s(
		&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
		&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	if p.Spec.RemoteWrite[0].URL != "https://test.remotewrite.com/api/write" {
		t.Errorf("want remote write URL https://test.remotewrite.com/api/write, got %v", p.Spec.RemoteWrite[0].URL)
	}

	if !reflect.DeepEqual(p.Spec.RemoteWrite[0].OAuth2, &expectedOauth2Config) {
		t.Errorf("want OAuth2 config %v, got %v", expectedOauth2Config, p.Spec.RemoteWrite[0].OAuth2)
	}

}
func TestRemoteWriteAuthorizationConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		config  string
		checkFn []func(*testing.T, monv1.RemoteWriteSpec)
	}{
		{
			name: "basic authentication configuration",
			config: `prometheusK8s:
  remoteWrite:
  - url: "https://basicAuth.remotewrite.com/api/write"
    basicAuth:
      username:
        name: remoteWriteAuth
        key: user
      password:
        name: remoteWriteAuth
        key: password
`,
			checkFn: []func(*testing.T, monv1.RemoteWriteSpec){
				func(t *testing.T, target monv1.RemoteWriteSpec) {
					if target.BasicAuth.Username.Name != "remoteWriteAuth" {
						t.Fatalf("Name field not correct in section RemoteWriteSpec.BasicAuth.Username expected 'remoteWriteAuth', got %s", target.BasicAuth.Username.Name)
					}
					if target.BasicAuth.Username.Key != "user" {
						t.Fatalf("Key field not correct in section RemoteWriteSpec.BasicAuth.Username expected 'user', got %s", target.BasicAuth.Username.Key)
					}
					if target.BasicAuth.Password.Name != "remoteWriteAuth" {
						t.Fatalf("Name field not correct in section RemoteWriteSpec.BasicAuth.Password expected 'remoteWriteAuth', got %s", target.BasicAuth.Password.Name)
					}
					if target.BasicAuth.Password.Key != "password" {
						t.Fatalf("Key field not correct in section RemoteWriteSpec.BasicAuth.Password expected 'password', got %s", target.BasicAuth.Password.Key)
					}
				},
			},
		},
		{
			name: "bearerTokenFile authentication configuration",
			config: `prometheusK8s:
  remoteWrite:
  - url: "https://bearerTokenFile.remotewrite.com/api/write"
    bearerTokenFile: "/secret/remoteWriteAuth"
`,
			checkFn: []func(*testing.T, monv1.RemoteWriteSpec){
				func(t *testing.T, target monv1.RemoteWriteSpec) {
					if target.BearerTokenFile != "/secret/remoteWriteAuth" {
						t.Fatalf("BearerTokenFile field not correct in section RemoteWriteSpec expected '/secret/remoteWriteAuth', got %s", target.BearerTokenFile)
					}
				},
			},
		},
		{
			name: "authorization authentication configuration",
			config: `prometheusK8s:
  remoteWrite:
  - url: "https://authorization.remotewrite.com/api/write"
    authorization:
      type: Bearer
      credentials:
        name: remoteWriteAuth
        key: token
`,
			checkFn: []func(*testing.T, monv1.RemoteWriteSpec){
				func(t *testing.T, target monv1.RemoteWriteSpec) {
					if target.Authorization.Type != "Bearer" {
						t.Fatalf("Bearer field not correct in section RemoteWriteSpec expected 'Bearer', got %s", target.Authorization.Type)
					}
					if target.Authorization.Credentials.Name != "remoteWriteAuth" {
						t.Fatalf("Name field not correct in section RemoteWriteSpec.Authorization.Credentials expected 'remoteWriteAuth', got %s", target.Authorization.Credentials.Name)
					}
					if target.Authorization.Credentials.Key != "token" {
						t.Fatalf("Key field not correct in section RemoteWriteSpec.Authorization.Credentials expected 'token', got %s", target.Authorization.Credentials.Key)
					}
				},
			},
		},
		{
			name: "sigv4 authentication configuration",
			config: `prometheusK8s:
  remoteWrite:
  - url: "https://authorization.remotewrite.com/api/write"
    sigv4:
      region: eu
      accessKey:
        name: aws-credentials
        key: access
      secretKey:
        name: aws-credentials
        key: secret
      profile: "SomeProfile"
      roleArn: "SomeRoleArn"
`,
			checkFn: []func(*testing.T, monv1.RemoteWriteSpec){
				func(t *testing.T, target monv1.RemoteWriteSpec) {
					if target.Sigv4.Region != "eu" {
						t.Fatalf("Region field not correct in section RemoteWriteSpec.Sigv4 expected 'eu', got %s", target.Sigv4)
					}
					if target.Sigv4.AccessKey.Name != "aws-credentials" {
						t.Fatalf("Name field not correct in section RemoteWriteSpec.Sigv4.AccessKey expected 'aws-credentials', got %s", target.Sigv4.AccessKey.Name)
					}
					if target.Sigv4.AccessKey.Key != "access" {
						t.Fatalf("Key field not correct in section RemoteWriteSpec.Sigv4.AccessKey expected 'access', got %s", target.Sigv4.AccessKey.Key)
					}
					if target.Sigv4.SecretKey.Name != "aws-credentials" {
						t.Fatalf("Name field not correct in section RemoteWriteSpec.Sigv4.SecretKey expected 'aws-credentials', got %s", target.Sigv4.SecretKey.Name)
					}
					if target.Sigv4.SecretKey.Key != "secret" {
						t.Fatalf("Key field not correct in section RemoteWriteSpec.Sigv4.SecretKey expected 'secret', got %s", target.Sigv4.SecretKey.Key)
					}
					if target.Sigv4.Profile != "SomeProfile" {
						t.Fatalf("Profile field not correct in section RemoteWriteSpec.Sigv4 expected 'SomeProfile', got %s", target.Sigv4.Profile)
					}
					if target.Sigv4.RoleArn != "SomeRoleArn" {
						t.Fatalf("RoleArn field not correct in section RemoteWriteSpec.Sigv4 expected 'SomeRoleArn', got %s", target.Sigv4.RoleArn)
					}
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewConfigFromString(tc.config)
			if err != nil {
				t.Fatal(err)
			}
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
			p, err := f.PrometheusK8s(
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Spec.RemoteWrite) != len(tc.checkFn) {
				t.Fatalf("got %d check functions but only %d RemoteWrite targets", len(tc.checkFn), len(p.Spec.RemoteWrite))
			}

			for i, target := range p.Spec.RemoteWrite {
				tc.checkFn[i](t, target)
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
  topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: type
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        foo: bar
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

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
	p, err := f.PrometheusK8s(
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

	if p.Spec.EnforcedBodySizeLimit != "" {
		t.Fatal("EnforcedBodySizeLimit is not set to empty by default")
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
			if !volumeConfigured(p.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !volumeMountsConfigured(container.VolumeMounts, volumeName) {
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
			if !volumeConfigured(p.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !volumeMountsConfigured(container.VolumeMounts, volumeName) {
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

	if p.Spec.TopologySpreadConstraints[0].MaxSkew != 1 {
		t.Fatal("Prometheus topology spread contraints MaxSkew not configured correctly")
	}

	if p.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != "DoNotSchedule" {
		t.Fatal("Prometheus topology spread contraints WhenUnsatisfiable not configured correctly")
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

func TestPrometheusQueryLogFileConfig(t *testing.T) {
	for _, tc := range []struct {
		name             string
		queryLogFilePath string
		expected         string
		errExpected      bool
		volumeExpected   bool
	}{
		{
			name:             "basic config",
			queryLogFilePath: "/tmp/query.log",
			expected:         "/tmp/query.log",
			errExpected:      false,
			volumeExpected:   true,
		},
		{
			name:             "query log file on the TSDB storage volume",
			queryLogFilePath: "/prometheus/query.log",
			expected:         "/prometheus/query.log",
			errExpected:      false,
			volumeExpected:   false,
		},
		{
			name:             "log to stdout",
			queryLogFilePath: "/dev/stdout",
			expected:         "/dev/stdout",
			errExpected:      false,
			volumeExpected:   false,
		},
		{
			name:             "invalid path, query log on root",
			queryLogFilePath: "/query.log",
			expected:         "",
			errExpected:      true,
			volumeExpected:   false,
		},
		{
			name:             "invalid file under dev",
			queryLogFilePath: "/dev/query.log",
			expected:         "",
			errExpected:      true,
			volumeExpected:   false,
		},
		{
			name:             "invalid path, relative path",
			queryLogFilePath: "./dev/query.log",
			expected:         "",
			errExpected:      true,
			volumeExpected:   false,
		},
		{
			name:             "filename only",
			queryLogFilePath: "query.log",
			expected:         "query.log",
			errExpected:      false,
			volumeExpected:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewDefaultConfig()
			c.ClusterMonitoringConfiguration.PrometheusK8sConfig.QueryLogFile = tc.queryLogFilePath
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
			p, err := f.PrometheusK8s(
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			)
			if err != nil {
				if !tc.errExpected {
					t.Fatalf("Expecting no error but got %v", err)
				}
				return
			}
			if tc.errExpected {
				t.Fatalf("Expected query log file %s to give an error, but err is nil", tc.queryLogFilePath)
			}

			if p.Spec.QueryLogFile != tc.expected {
				t.Fatal("Prometheus query log is not configured correctly")
			}

			if tc.volumeExpected {
				volumeName := "query-log"
				if !volumeConfigured(p.Spec.Volumes, volumeName) {
					t.Fatal("Query log file volume is not configured correctly")
				}
				if !volumeMountsConfigured(p.Spec.VolumeMounts, volumeName) {
					t.Fatal("Query log file volume mount is not configured correctly")
				}
			} else {
				volumeName := "query-log"
				if volumeConfigured(p.Spec.Volumes, volumeName) {
					t.Fatal("Query log file volume is configured, but it should not as prometheus-operator will take care of it")
				}
				if volumeMountsConfigured(p.Spec.VolumeMounts, volumeName) {
					t.Fatal("Query log file volume is configured, but it should not as prometheus-operator will take care of it")
				}
			}
		})
	}
}

func TestPrometheusRetentionConfigs(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		retention             string
		retentionSize         string
		expectedRetention     string
		expectedRetentionSize string
	}{
		{
			name:                  "both retention and retentionSize defined",
			retention:             "30d",
			retentionSize:         "15GiB",
			expectedRetention:     "30d",
			expectedRetentionSize: "15GiB",
		},
		{
			name:                  "only retention defined",
			retention:             "45d",
			expectedRetention:     "45d",
			expectedRetentionSize: "",
		},
		{
			name:                  "only retentionSize defined",
			retentionSize:         "25GB",
			expectedRetention:     "",
			expectedRetentionSize: "25GB",
		},
		{
			name:                  "both retention and retentionSize empty",
			expectedRetention:     "15d",
			expectedRetentionSize: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewDefaultConfig()
			c.ClusterMonitoringConfiguration.PrometheusK8sConfig.Retention = tc.retention
			c.ClusterMonitoringConfiguration.PrometheusK8sConfig.RetentionSize = tc.retentionSize

			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})

			p, err := f.PrometheusK8s(
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			)

			if err != nil {
				t.Fatalf("Unexpected error occured %v", err)
				return
			}

			if tc.retention == "" && tc.retentionSize == "" {
				if p.Spec.Retention != "15d" && p.Spec.RetentionSize != "" {
					t.Fatal("Default Retention is not configured correctly")
				}
				return
			}

			if string(p.Spec.Retention) != tc.expectedRetention {
				t.Fatal("Retention is not configured correctly")
			}

			if string(p.Spec.RetentionSize) != tc.expectedRetentionSize {
				t.Fatal("RetentionSize is not configured correctly")
			}
		})
	}
}

func TestPrometheusK8sConfigurationBodySizeLimit(t *testing.T) {
	pcr := &fakePodCapacity{
		capacity: 1000,
		err:      nil,
	}
	ctx := context.Background()

	c, err := NewConfigFromString(`
prometheusK8s:
    enforcedBodySizeLimit: "10MB"
  `)

	if err != nil {
		t.Fatal(err)
	}

	err = c.LoadEnforcedBodySizeLimit(pcr, ctx)

	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, nil)
	p, err := f.PrometheusK8s(
		&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
		&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	// the body size limit value is not set at configuration parsing time.
	if p.Spec.EnforcedBodySizeLimit != "10MB" {
		t.Fatalf("EnforcedBodySizeLimit is not configured correctly, expected 10MB but got %v", p.Spec.EnforcedBodySizeLimit)
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
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})

			p, err := f.PrometheusK8s(
				&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
			)
			if err != nil {
				t.Fatal(err)
			}

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
		name               string
		config             string
		userWorkloadConfig string

		expected string
	}{
		{
			name: "no config with platform alertmanager disabled",
			config: `alertmanagerMain:
  enabled: false`,
			expected: `alertmanagers: []
`,
		},
		{
			name: "no config with UWM alertmanager disabled",
			expected: `alertmanagers:
- scheme: https
  api_version: v2
  http_config:
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    tls_config:
      ca_file: /etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt
      server_name: alertmanager-main.openshift-monitoring.svc
  static_configs:
  - dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc
`,
		},
		{
			name: "no config with UWM alertmanager enabled",
			userWorkloadConfig: `alertmanager:
    enabled: true
`,
			expected: `alertmanagers:
- scheme: https
  api_version: v2
  http_config:
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    tls_config:
      ca_file: /etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt
      server_name: alertmanager-user-workload.openshift-user-workload-monitoring.svc
  static_configs:
  - dnssrv+_web._tcp.alertmanager-operated.openshift-user-workload-monitoring.svc
`,
		},
		{
			name: "basic config",
			userWorkloadConfig: `thanosRuler:
  additionalAlertmanagerConfigs:
  - staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			expected: `alertmanagers:
- scheme: https
  api_version: v2
  http_config:
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    tls_config:
      ca_file: /etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt
      server_name: alertmanager-main.openshift-monitoring.svc
  static_configs:
  - dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc
- static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
		{
			name: "basic config with platform alertmanager disabled",
			config: `alertmanagerMain:
  enabled: false
`,
			userWorkloadConfig: `thanosRuler:
  additionalAlertmanagerConfigs:
  - staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			expected: `alertmanagers:
- static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
		{
			name: "version, path and scheme override",
			userWorkloadConfig: `thanosRuler:
  additionalAlertmanagerConfigs:
  - apiVersion: v1
    pathPrefix: /path-prefix
    scheme: ftp
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			expected: `alertmanagers:
- scheme: https
  api_version: v2
  http_config:
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    tls_config:
      ca_file: /etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt
      server_name: alertmanager-main.openshift-monitoring.svc
  static_configs:
  - dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc
- scheme: ftp
  path_prefix: /path-prefix
  api_version: v1
  static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
		{
			name: "bearer token",
			userWorkloadConfig: `thanosRuler:
  additionalAlertmanagerConfigs:
  - bearerToken:
      key: key
      name: bearer-token
    staticConfigs:
    - alertmanager1-remote.com
    - alertmanager1-remotex.com
`,
			expected: `alertmanagers:
- scheme: https
  api_version: v2
  http_config:
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    tls_config:
      ca_file: /etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt
      server_name: alertmanager-main.openshift-monitoring.svc
  static_configs:
  - dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc
- http_config:
    bearer_token_file: /etc/prometheus/secrets/bearer-token/key
  static_configs:
  - alertmanager1-remote.com
  - alertmanager1-remotex.com
`,
		},
		{
			name: "tls configuration token",
			userWorkloadConfig: `thanosRuler:
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
			expected: `alertmanagers:
- scheme: https
  api_version: v2
  http_config:
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    tls_config:
      ca_file: /etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt
      server_name: alertmanager-main.openshift-monitoring.svc
  static_configs:
  - dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc
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
			userWorkloadConfig: `thanosRuler:
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
			expected: `alertmanagers:
- scheme: https
  api_version: v2
  http_config:
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    tls_config:
      ca_file: /etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt
      server_name: alertmanager-main.openshift-monitoring.svc
  static_configs:
  - dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc
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
			userWorkloadConfig: `thanosRuler:
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
			expected: `alertmanagers:
- scheme: https
  api_version: v2
  http_config:
    bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token
    tls_config:
      ca_file: /etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt
      server_name: alertmanager-main.openshift-monitoring.svc
  static_configs:
  - dnssrv+_web._tcp.alertmanager-operated.openshift-monitoring.svc
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

			uwc, err := NewUserConfigFromString(tt.userWorkloadConfig)
			if err != nil {
				t.Fatal(err)
			}
			c.UserWorkloadConfiguration = uwc

			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})

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
				NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})

			d, err := f.PrometheusAdapterDeployment("foo", map[string]string{
				"requestheader-allowed-names":        "",
				"requestheader-extra-headers-prefix": "",
				"requestheader-group-headers":        "",
				"requestheader-username-headers":     "",
			},
				"adapter-config")

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

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
	d, err := f.PrometheusAdapterDeployment("foo", map[string]string{
		"requestheader-allowed-names":        "",
		"requestheader-extra-headers-prefix": "",
		"requestheader-group-headers":        "",
		"requestheader-username-headers":     "",
	}, "adapter-config")
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
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, tc.infrastructure, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
			a, err := f.AlertmanagerMain(
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
  enableUserAlertmanagerConfig: true
  nodeSelector:
    type: worker
  tolerations:
  - effect: PreferNoSchedule
    operator: Exists
  topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: type
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        foo: bar
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

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
	a, err := f.AlertmanagerMain(
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

	if a.Spec.TopologySpreadConstraints[0].MaxSkew != 1 {
		t.Fatal("Alertmanager main topology spread contraints MaxSkew not configured correctly")
	}

	if a.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != "DoNotSchedule" {
		t.Fatal("Alertmanager main topology spread contraints WhenUnsatisfiable not configured correctly")
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
			if !volumeConfigured(a.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !volumeMountsConfigured(container.VolumeMounts, volumeName) {
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

	{

		if a.Spec.AlertmanagerConfigSelector == nil {
			t.Fatal("expected 'alertmanagerConfigSelector' to configure selector")
		}

		if !reflect.DeepEqual(a.Spec.AlertmanagerConfigSelector, &metav1.LabelSelector{}) {
			t.Fatal("expected match all alertmanagerConfigSelector")
		}

		if a.Spec.AlertmanagerConfigNamespaceSelector == nil {
			t.Fatal("expected 'enableUserAlertmanagerConfig' to configure selector")
		}

		if len(a.Spec.AlertmanagerConfigNamespaceSelector.MatchExpressions) != 2 {
			t.Fatal("expected 'enableUserAlertmanagerConfig' to configure selector match expressions")
		}

		expectPlatformOptIn := metav1.LabelSelectorRequirement{
			Key:      "openshift.io/cluster-monitoring",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{"true"},
		}

		expectUWMOptIn := metav1.LabelSelectorRequirement{
			Key:      "openshift.io/user-monitoring",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{"false"},
		}

		gotPlatformOptIn := a.Spec.AlertmanagerConfigNamespaceSelector.MatchExpressions[0]
		if !reflect.DeepEqual(expectPlatformOptIn, gotPlatformOptIn) {
			t.Fatalf("unexpected result for platform labels. wanted %v but got %v", expectPlatformOptIn, gotPlatformOptIn)
		}
		gotUWMOptIn := a.Spec.AlertmanagerConfigNamespaceSelector.MatchExpressions[1]
		if !reflect.DeepEqual(expectUWMOptIn, gotUWMOptIn) {
			t.Fatalf("unexpected result for UWM labels. wanted %v but got %v", expectUWMOptIn, gotUWMOptIn)
		}
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

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})

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

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})

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

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})

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
		f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), tc.infrastructure, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
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
  logLevel: debug
  enableRequestLogging: true`)

	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
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

			{
				// test request logging config
				const (
					expectLoggingFlag = "--request.logging-config"
					expectResult      = `http:
  options:
    level: DEBUG
    decision:
      log_start: false
      log_end: true
grpc:
  options:
    level: DEBUG
    decision:
      log_start: false
      log_end: true`
				)

				got, ok := getArgValue(c, expectLoggingFlag)
				if !ok {
					t.Fatalf("expected logging flag to be set for Thanos query")
				}
				if got.value != expectResult {
					t.Fatalf("unexpected flag value for Thanos query, wanted %s but got %s", expectResult, got.value)
				}
			}

			{
				// test log level
				const (
					expectLogLevelFlag = "--log.level"
					expectResult       = "debug"
				)

				got, ok := getArgValue(c, expectLogLevelFlag)
				if !ok {
					t.Fatalf("expected log level flag to be set for Thanos query")
				}
				if got.value != expectResult {
					t.Fatalf("unexpected flag value for Thanos query, wanted %s but got %s", expectResult, got.value)
				}
			}

		case "oauth-proxy":
			volumeName := "thanos-querier-trusted-ca-bundle"
			if !volumeConfigured(d.Spec.Template.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", c.Name)
			}
			if !volumeMountsConfigured(c.VolumeMounts, volumeName) {
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

func TestTelemeterConfiguration(t *testing.T) {
	c, err := NewConfigFromString(``)
	if err != nil {
		t.Fatal(err)
	}
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
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
			if !volumeConfigured(d.Spec.Template.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !volumeMountsConfigured(container.VolumeMounts, volumeName) {
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
	uwc, err := NewUserConfigFromString(`thanosRuler:
  topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: type
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        foo: bar`)

	c.UserWorkloadConfiguration = uwc
	if err != nil {
		t.Fatal(err)
	}
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
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
			if !volumeConfigured(tr.Spec.Volumes, volumeName) {
				t.Fatalf("trusted CA bundle volume for %s is not configured correctly", container.Name)
			}
			if !volumeMountsConfigured(container.VolumeMounts, volumeName) {
				t.Fatalf("trusted CA bundle volume mount for %s is not configured correctly", container.Name)
			}
		}
	}
	if tr.Spec.TopologySpreadConstraints[0].MaxSkew != 1 {
		t.Fatal("Thanos ruler topology spread contraints MaxSkew not configured correctly")
	}

	if tr.Spec.TopologySpreadConstraints[0].WhenUnsatisfiable != "DoNotSchedule" {
		t.Fatal("Thanos ruler topology spread contraints WhenUnsatisfiable not configured correctly")
	}

}

func TestThanosRulerRetentionConfig(t *testing.T) {
	c := NewDefaultConfig()
	c.UserWorkloadConfiguration.ThanosRuler.Retention = "30d"

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})

	tr, err := f.ThanosRulerCustomResource(
		"",
		&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
		&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
		nil,
	)

	if err != nil {
		t.Fatalf("Unexpected error occured %v", err)
		return
	}

	if tr.Spec.Retention != "30d" {
		t.Fatal("Retention is not configured correctly")
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
			name: "Alertmanager (user-workload)",
			getSpec: func(f *Factory) (spec, error) {
				p, err := f.AlertmanagerUserWorkload(
					&v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}},
				)
				if err != nil {
					return spec{}, err
				}
				return spec{*p.Spec.Replicas, p.Spec.Affinity}, nil
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
					},
					"adapter-config")
				if err != nil {
					return spec{}, err
				}
				return spec{*p.Spec.Replicas, p.Spec.Template.Spec.Affinity}, nil
			},
		},
	}

	for _, tc := range tests {
		f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), &fakeInfrastructureReader{highlyAvailableInfrastructure: false}, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
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

func TestNonHighlyAvailableInfrastructureServiceMonitors(t *testing.T) {
	type spec struct {
		replicas int32
		affinity *v1.Affinity
	}

	tests := []struct {
		name         string
		getEndpoints func(f *Factory) ([]monv1.Endpoint, error)
	}{
		{
			name: "Prometheus Adapter Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.PrometheusAdapterServiceMonitor()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
		{
			name: "Alermanager Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.AlertmanagerServiceMonitor()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
		{
			name: "CMO Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.ClusterMonitoringOperatorServiceMonitor()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
		{
			name: "etcd Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.ControlPlaneEtcdServiceMonitor()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
		{
			name: "kubelet Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.ControlPlaneKubeletServiceMonitor()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
		{
			name: "kubelet PA dedicated Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.ControlPlaneKubeletServiceMonitorPA()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
		{
			name: "Kube State Metrics Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.KubeStateMetricsServiceMonitor()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
		{
			name: "Node Exporter Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.NodeExporterServiceMonitor()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
		{
			name: "OpenShift State Metrics Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.OpenShiftStateMetricsServiceMonitor()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
		{
			name: "Prometheus K8s Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.PrometheusK8sPrometheusServiceMonitor()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
		{
			name: "Thanos Sidecar Service Monitor",
			getEndpoints: func(f *Factory) ([]monv1.Endpoint, error) {
				pt, err := f.PrometheusK8sThanosSidecarServiceMonitor()
				if err != nil {
					return nil, err
				}
				return pt.Spec.Endpoints, nil
			},
		},
	}
	for _, tc := range tests {
		nonHAFac := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), &fakeInfrastructureReader{highlyAvailableInfrastructure: false}, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
		noHAEndpoints, err := tc.getEndpoints(nonHAFac)
		if err != nil {
			t.Error(err)
		}
		HAFac := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), &fakeInfrastructureReader{highlyAvailableInfrastructure: true}, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
		HAEndpoints, err := tc.getEndpoints(HAFac)
		if err != nil {
			t.Error(err)
		}

		for i := range noHAEndpoints {
			if noHAEndpoints[i].Interval == "" {
				continue
			}
			noHAInt, err := time.ParseDuration(string(noHAEndpoints[i].Interval))
			if err != nil {
				t.Errorf("Unexpected error when parsing %s: %v", noHAEndpoints[i].Interval, err)
			}
			HAInt, err := time.ParseDuration(string(HAEndpoints[i].Interval))
			if err != nil {
				t.Errorf("Unexpected error when parsing %s: %v", HAEndpoints[i].Interval, err)
			}

			if HAInt*2 >= 2*time.Minute {
				if noHAInt != 2*time.Minute {
					t.Errorf("Unexpected value. %d should be max 2 minutes", noHAInt)
				}
			} else if noHAInt != HAInt*2 {
				t.Errorf("Unexpected value. %d should be twice as big as %d", noHAInt, HAInt)
			}
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
		f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), &fakeInfrastructureReader{highlyAvailableInfrastructure: tc.ha}, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
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

	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
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

func TestPrometheusOperatorNodeSelector(t *testing.T) {
	for _, tc := range []struct {
		name           string
		infrastructure InfrastructureReader
		expectedLabels map[string]string
	}{
		{
			name:           "Test default topology, highly available and control plane in-cluster",
			infrastructure: defaultInfrastructureReader(),
			expectedLabels: map[string]string{
				"kubernetes.io/os": "linux",
				nodeSelectorMaster: "",
			},
		},
		{
			name:           "Test hypershift topology, highly available and control plane external",
			infrastructure: &fakeInfrastructureReader{highlyAvailableInfrastructure: true, hostedControlPlane: true},
			expectedLabels: map[string]string{
				"kubernetes.io/os": "linux",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewConfigFromString(`
enableUserWorkload: true
`)
			if err != nil {
				t.Fatal(err)
			}
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", c, tc.infrastructure, &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
			d, err := f.PrometheusOperatorDeployment()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(d.Spec.Template.Spec.NodeSelector, tc.expectedLabels) {
				t.Fatalf("prometheus-operator nodeSelector is not configured correctly\n\ngot:\n\n%#+v\n\nexpected:\n\n%#+v\n", d.Spec.Template.Spec.NodeSelector, tc.expectedLabels)
			}
			uwlDeployment, err := f.PrometheusOperatorUserWorkloadDeployment()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(uwlDeployment.Spec.Template.Spec.NodeSelector, tc.expectedLabels) {
				t.Fatalf("user workload monitoring prometheus-operator nodeSelector is not configured correctly\n\ngot:\n\n%#+v\n\nexpected:\n\n%#+v\n", d.Spec.Template.Spec.NodeSelector, tc.expectedLabels)
			}
		})
	}
}

func volumeConfigured(volumes []v1.Volume, volumeName string) bool {
	for _, volume := range volumes {
		if volume.Name == volumeName {
			return true
		}
	}
	return false
}

func volumeMountsConfigured(volumeMounts []v1.VolumeMount, volumeName string) bool {
	for _, volumeMount := range volumeMounts {
		if volumeMount.Name == volumeName {
			return true
		}
	}
	return false
}
