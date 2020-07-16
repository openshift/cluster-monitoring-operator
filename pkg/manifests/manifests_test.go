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
	"reflect"
	"sort"
	"strings"
	"testing"

	monv1 "github.com/coreos/prometheus-operator/pkg/client/monitoring/v1"
	"k8s.io/api/core/v1"
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

	_, err = f.AlertmanagerMain("alertmanager-main.openshift-monitoring.svc")
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

	_, err = f.KubeStateMetricsSecurityContextConstraints()
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

	_, err = f.PrometheusK8sEtcdService()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sEtcdEndpoints()
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

	_, err = f.PrometheusK8s("prometheus-k8s.openshift-monitoring.svc")
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sKubeletServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sApiserverServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sPrometheusServiceMonitor()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.PrometheusK8sKubeControllersServiceMonitor()
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

	_, err = f.KubeControllersService()
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

	_, err = f.GrafanaDeployment()
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
}

func TestHTTPConfig(t *testing.T) {
	type checkFunc func(*monv1.Alertmanager) error

	checks := func(cs ...checkFunc) checkFunc {
		return func(a *monv1.Alertmanager) error {
			for _, f := range cs {
				if err := f(a); err != nil {
					return err
				}
			}
			return nil
		}
	}

	hasContainers := func(a *monv1.Alertmanager) error {
		if len(a.Spec.Containers) == 0 {
			return errors.New("expected spec to have containers, but it doesn't have any")
		}
		return nil
	}

	containerHasEnv := func(c v1.Container, name, value string) bool {
		for e := range c.Env {
			if c.Env[e].Name != name {
				continue
			}
			if c.Env[e].Value == value {
				return true
			}
		}
		return false
	}

	containersHaveEnv := func(name, value string) checkFunc {
		return func(a *monv1.Alertmanager) error {
			for c := range a.Spec.Containers {
				if !containerHasEnv(a.Spec.Containers[c], name, value) {
					return fmt.Errorf(
						"containers expected to have env var %v=%v, but %v doesn't",
						name, value, a.Spec.Containers[c].Name,
					)
				}
			}
			return nil
		}
	}

	for _, tc := range []struct {
		name   string
		config string
		check  checkFunc
	}{
		{
			name: "no http config",

			check: checks(
				hasContainers,
				containersHaveEnv("HTTP_PROXY", ""),
				containersHaveEnv("HTTPS_PROXY", ""),
				containersHaveEnv("NO_PROXY", ""),
			),
		},
		{
			name: "empty http config",

			config: `http:`,

			check: checks(
				hasContainers,
				containersHaveEnv("HTTP_PROXY", ""),
				containersHaveEnv("HTTPS_PROXY", ""),
				containersHaveEnv("NO_PROXY", ""),
			),
		},
		{
			name: "http proxy only",

			config: `http:
  httpProxy: http://insecure.proxy`,

			check: checks(
				hasContainers,
				containersHaveEnv("HTTP_PROXY", "http://insecure.proxy"),
				containersHaveEnv("HTTPS_PROXY", ""),
				containersHaveEnv("NO_PROXY", ""),
			),
		},
		{
			name: "https proxy only",

			config: `http:
  httpsProxy: https://secure.proxy`,

			check: checks(
				hasContainers,
				containersHaveEnv("HTTP_PROXY", ""),
				containersHaveEnv("HTTPS_PROXY", "https://secure.proxy"),
				containersHaveEnv("NO_PROXY", ""),
			),
		},
		{
			name: "https and http proxy",

			config: `http:
  httpProxy: http://insecure.proxy
  httpsProxy: https://secure.proxy`,

			check: checks(
				hasContainers,
				containersHaveEnv("HTTP_PROXY", "http://insecure.proxy"),
				containersHaveEnv("HTTPS_PROXY", "https://secure.proxy"),
				containersHaveEnv("NO_PROXY", ""),
			),
		},
		{
			name: "https and no proxy",

			config: `http:
  httpsProxy: https://secure.proxy
  noProxy: .test.local,.cluster.local`,

			check: checks(
				hasContainers,
				containersHaveEnv("HTTP_PROXY", ""),
				containersHaveEnv("HTTPS_PROXY", "https://secure.proxy"),
				containersHaveEnv("NO_PROXY", ".test.local,.cluster.local"),
			),
		},
		{
			name: "http and https and no proxy",

			config: `http:
  httpProxy: http://insecure.proxy
  httpsProxy: https://secure.proxy
  noProxy: .test.local,.cluster.local`,

			check: checks(
				hasContainers,
				containersHaveEnv("HTTP_PROXY", "http://insecure.proxy"),
				containersHaveEnv("HTTPS_PROXY", "https://secure.proxy"),
				containersHaveEnv("NO_PROXY", ".test.local,.cluster.local"),
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewConfigFromString(tc.config)
			if err != nil {
				t.Error(err)
				return
			}

			f := NewFactory("openshift-monitoring", c)
			d, err := f.AlertmanagerMain("alertmanager-main.openshift-monitoring.svc")
			if err != nil {
				t.Error(err)
				return
			}

			if err := tc.check(d); err != nil {
				t.Error(err)
				return
			}
		})
	}
}

func TestPrometheusOperatorConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`prometheusOperator:
  nodeSelector:
    type: master
  baseImage: quay.io/test/prometheus-operator
  prometheusConfigReloaderBaseImage: quay.io/test/prometheus-config-reloader
  configReloaderBaseImage: quay.io/test/configmap-reload
`)
	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", c)
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

	if !strings.HasPrefix(d.Spec.Template.Spec.Containers[0].Image, "quay.io/test/prometheus-operator") {
		t.Fatal("Configuring the Prometheus Operator base image failed")
	}

	configReloaderFound := false
	prometheusReloaderFound := false
	for i := range d.Spec.Template.Spec.Containers[0].Args {
		if strings.HasPrefix(d.Spec.Template.Spec.Containers[0].Args[i], PrometheusConfigReloaderFlag+"quay.io/test/prometheus-config-reloader") {
			prometheusReloaderFound = true
		}
		if strings.HasPrefix(d.Spec.Template.Spec.Containers[0].Args[i], ConfigReloaderImageFlag+"quay.io/test/configmap-reload") {
			configReloaderFound = true
		}
	}

	if !configReloaderFound {
		t.Fatal("Configuring the Config reloader base image failed")
	}

	if !prometheusReloaderFound {
		t.Fatal("Configuring the Prometheus Reloader base image failed")
	}
}

func TestPrometheusK8sConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`prometheusK8s:
  retention: 25h
  baseImage: quay.io/test/prometheus
  nodeSelector:
    type: master
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

	f := NewFactory("openshift-monitoring", c)
	p, err := f.PrometheusK8s("prometheus-k8s.openshift-monitoring.svc")
	if err != nil {
		t.Fatal(err)
	}

	if p.Spec.Retention != "25h" {
		t.Fatal("Retention is not configured correctly")
	}

	if p.Spec.BaseImage != "quay.io/test/prometheus" {
		t.Fatal("Prometheus base image is not configured correctly")
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

func TestAlertmanagerMainConfiguration(t *testing.T) {
	c, err := NewConfigFromString(`alertmanagerMain:
  baseImage: quay.io/test/alertmanager
  nodeSelector:
    type: worker
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

	f := NewFactory("openshift-monitoring", c)
	a, err := f.AlertmanagerMain("alertmanager-main.openshift-monitoring.svc")
	if err != nil {
		t.Fatal(err)
	}

	if a.Spec.BaseImage != "quay.io/test/alertmanager" {
		t.Fatal("Alertmanager base image is not configured correctly")
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

	storageRequest := a.Spec.Storage.VolumeClaimTemplate.Spec.Resources.Requests[v1.ResourceStorage]
	storageRequestPtr := &storageRequest
	if storageRequestPtr.String() != "10Gi" {
		t.Fatal("Alertmanager volumeClaimTemplate not configured correctly, expected 10Gi storage request, but found", storageRequestPtr.String())
	}
}

func TestNodeExporter(t *testing.T) {
	c, err := NewConfigFromString(`nodeExporter:
  baseImage: quay.io/test/node-exporter
kubeRbacProxy:
  baseImage: quay.io/test/kube-rbac-proxy
`)
	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", c)

	ds, err := f.NodeExporterDaemonSet()
	if err != nil {
		t.Fatal(err)
	}
	image, err := imageFromString(ds.Spec.Template.Spec.Containers[0].Image)
	if err != nil {
		t.Fatal(err)
	}
	if image.repo != "quay.io/test/node-exporter" {
		t.Fatalf("image for node-exporter daemonset is wrong: %s", ds.Spec.Template.Spec.Containers[0].Image)
	}
	image, err = imageFromString(ds.Spec.Template.Spec.Containers[1].Image)
	if err != nil {
		t.Fatal(err)
	}
	if image.repo != "quay.io/test/kube-rbac-proxy" {
		t.Fatalf("image for kube-rbac-proxy in node-exporter daemonset is wrong: %s", ds.Spec.Template.Spec.Containers[1].Image)
	}
}

func TestKubeStateMetrics(t *testing.T) {
	c, err := NewConfigFromString(`kubeStateMetrics:
  baseImage: quay.io/test/kube-state-metrics
kubeRbacProxy:
  baseImage: quay.io/test/kube-rbac-proxy
`)
	if err != nil {
		t.Fatal(err)
	}

	f := NewFactory("openshift-monitoring", c)

	d, err := f.KubeStateMetricsDeployment()
	if err != nil {
		t.Fatal(err)
	}

	expected := []string{
		"quay.io/test/kube-rbac-proxy",
		"quay.io/test/kube-rbac-proxy",
		"quay.io/test/kube-state-metrics",
	}
	actual := []string{}
	for _, c := range d.Spec.Template.Spec.Containers {
		image, err := imageFromString(c.Image)
		if err != nil {
			t.Fatal(err)
		}
		actual = append(actual, image.repo)
	}
	sort.Strings(expected)
	sort.Strings(actual)
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("expected: %v\ngot:\n%s", expected, actual)
	}
}

func TestPrometheusEtcdRulesFiltered(t *testing.T) {
	f := NewFactory("openshift-monitoring", NewDefaultConfig())

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
	c, err := NewConfigFromString(`etcd: {}`)
	if err != nil {
		t.Fatal(err)
	}

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
	f := NewFactory("openshift-monitoring", NewDefaultConfig())

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
	c, err := NewConfigFromString(`etcd: {}`)
	if err != nil {
		t.Fatal(err)
	}

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
