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
	"reflect"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUnconfiguredManifests(t *testing.T) {
	f := NewFactory("openshift-monitoring", NewDefaultConfig())
	_, err := f.AlertmanagerConfig()
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

	_, err = f.PrometheusK8sRules()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sEtcdServiceMonitor()
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

	_, err = f.PrometheusK8s("prometheus-k8s.openshift-monitoring.svc", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sKubeletServiceMonitor()
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

	_, err = f.PrometheusOperatorDeployment([]string{"default", "openshift-monitoring"})
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

	_, err = f.ClusterMonitoringClusterRole()
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
	})

	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", c)
	d, err := f.PrometheusOperatorDeployment([]string{"default", "openshift-monitoring"})
	if err != nil {
		t.Fatal(err)
	}

	if len(d.Spec.Template.Spec.NodeSelector) == 0 {
		t.Fatal("expected node selector to be present, got none")
	}

	if got := d.Spec.Template.Spec.NodeSelector["type"]; got != "master" {
		t.Fatalf("expected node selector to be master, got %q", got)
	}

	expectedPromOpImage := "docker.io/openshift/origin-prometheus-operator:latest"
	resPromOpImage := d.Spec.Template.Spec.Containers[0].Image
	if resPromOpImage != expectedPromOpImage {
		t.Fatalf("Configuring the Prometheus Operator image failed, expected: %v, got %v", expectedPromOpImage, resPromOpImage)
	}

	configReloaderFound := false
	prometheusReloaderFound := false
	namespacesFound := false
	for i := range d.Spec.Template.Spec.Containers[0].Args {
		if strings.HasPrefix(d.Spec.Template.Spec.Containers[0].Args[i], PrometheusConfigReloaderFlag+"docker.io/openshift/origin-prometheus-config-reloader:latest") {
			prometheusReloaderFound = true
		}
		if strings.HasPrefix(d.Spec.Template.Spec.Containers[0].Args[i], ConfigReloaderImageFlag+"docker.io/openshift/origin-configmap-reloader:latest") {
			configReloaderFound = true
		}
		if strings.HasPrefix(d.Spec.Template.Spec.Containers[0].Args[i], PrometheusOperatorNamespaceFlag+"default,openshift-monitoring") {
			namespacesFound = true
		}
	}

	if !configReloaderFound {
		t.Fatal("Configuring the Config reloader image failed")
	}

	if !prometheusReloaderFound {
		t.Fatal("Configuring the Prometheus Reloader image failed")
	}

	if !namespacesFound {
		t.Fatal("Configuring the namespaces to watch failed")
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

	f := NewFactory("openshift-monitoring", c)
	p, err := f.PrometheusK8s("prometheus-k8s.openshift-monitoring.svc", &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}})
	if err != nil {
		t.Fatal(err)
	}

	if p.Spec.Retention != "25h" {
		t.Fatal("Retention is not configured correctly")
	}

	if *p.Spec.Image != "docker.io/openshift/origin-prometheus:latest" {
		t.Fatal("Prometheus image is not configured correctly")
	}

	if p.Spec.Containers[0].Image != "docker.io/openshift/origin-oauth-proxy:latest" {
		t.Fatal("oauth-proxy image is not configured correctly")
	}

	if p.Spec.Containers[1].Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
		t.Fatal("kube-rbac-proxy image is not configured correctly")
	}

	if p.Spec.Containers[2].Image != "docker.io/openshift/origin-prom-label-proxy:latest" {
		t.Fatal("prom-label-proxy image is not configured correctly")
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
	storageRequest := p.Spec.Storage.VolumeClaimTemplate.Spec.Resources.Requests[v1.ResourceStorage]
	storageRequestPtr := &storageRequest
	if storageRequestPtr.String() != "15Gi" {
		t.Fatal("Prometheus volumeClaimTemplate not configured correctly, expected 15Gi storage request, but found", storageRequestPtr.String())
	}

	if p.Spec.RemoteWrite[0].URL != "https://test.remotewrite.com/api/write" {
		t.Fatal("Prometheus remote-write is not configured correctly")
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

	f := NewFactory("openshift-monitoring", c)
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

func TestAlertmanagerMainConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`alertmanagerMain:
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

	f := NewFactory("openshift-monitoring", c)
	a, err := f.AlertmanagerMain("alertmanager-main.openshift-monitoring.svc", nil)
	if err != nil {
		t.Fatal(err)
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

	f := NewFactory("openshift-monitoring", c)

	ds, err := f.NodeExporterDaemonSet()
	if err != nil {
		t.Fatal(err)
	}
	if ds.Spec.Template.Spec.Containers[0].Image != "docker.io/openshift/origin-prometheus-node-exporter:latest" {
		t.Fatalf("image for node-exporter daemonset is wrong: %s", ds.Spec.Template.Spec.Containers[0].Image)
	}
	if ds.Spec.Template.Spec.Containers[1].Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
		t.Fatalf("image for kube-rbac-proxy in node-exporter daemonset is wrong: %s", ds.Spec.Template.Spec.Containers[1].Image)
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

	f := NewFactory("openshift-monitoring", c)

	d, err := f.KubeStateMetricsDeployment()
	if err != nil {
		t.Fatal(err)
	}

	if d.Spec.Template.Spec.Containers[0].Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
		t.Fatal("kube-rbac-proxy image incorrectly configured")
	}
	if d.Spec.Template.Spec.Containers[1].Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
		t.Fatal("kube-rbac-proxy image incorrectly configured")
	}
	if d.Spec.Template.Spec.Containers[2].Image != "docker.io/openshift/origin-kube-state-metrics:latest" {
		t.Fatal("kube-state-metrics image incorrectly configured")
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

	f := NewFactory("openshift-monitoring", c)

	d, err := f.OpenShiftStateMetricsDeployment()
	if err != nil {
		t.Fatal(err)
	}

	if d.Spec.Template.Spec.Containers[0].Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
		t.Fatal("kube-rbac-proxy image incorrectly configured")
	}
	if d.Spec.Template.Spec.Containers[1].Image != "docker.io/openshift/origin-kube-rbac-proxy:latest" {
		t.Fatal("kube-rbac-proxy image incorrectly configured")
	}
	if d.Spec.Template.Spec.Containers[2].Image != "docker.io/openshift/origin-openshift-state-metrics:latest" {
		t.Fatal("openshift-state-metrics image incorrectly configured")
	}
}

func TestPrometheusEtcdRulesFiltered(t *testing.T) {
	enabled := false
	c := NewDefaultConfig()
	c.EtcdConfig.Enabled = &enabled
	f := NewFactory("openshift-monitoring", c)

	r, err := f.PrometheusK8sRules()
	if err != nil {
		t.Fatal(err)
	}

	for _, g := range r.Spec.Groups {
		if g.Name == "etcd" {
			t.Fatal("etcd rules found, even if etcd is disabled")
		}
	}
}

func TestPrometheusEtcdRules(t *testing.T) {
	enabled := true
	c := NewDefaultConfig()
	c.EtcdConfig.Enabled = &enabled
	f := NewFactory("openshift-monitoring", c)

	r, err := f.PrometheusK8sRules()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, g := range r.Spec.Groups {
		if g.Name == "etcd" {
			found = true
		}
	}
	if !found {
		t.Fatal("etcd rules not found, even if etcd is enabled")
	}
}

func TestEtcdGrafanaDashboardFiltered(t *testing.T) {
	enabled := false
	c := NewDefaultConfig()
	c.EtcdConfig.Enabled = &enabled
	f := NewFactory("openshift-monitoring", c)

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
	c.EtcdConfig.Enabled = &enabled
	f := NewFactory("openshift-monitoring", c)

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
