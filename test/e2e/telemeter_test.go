// Copyright 2019 The Cluster Monitoring Operator Authors
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

package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8syaml "sigs.k8s.io/yaml"
)

// Some metrics may only be conditionally present depending on the environment, or the configuration.
// For such metrics, we skip the presence check.
var ignoredMetrics = map[string]struct{}{
	"kube_pod_restart_policy":                                       {}, // Disabled through --metric-denylist.
	"kubelet_volume_stats_used_bytes":                               {},
	"node_accelerator_card_info":                                    {}, // Even though card_info metric is enabled by default, the PCI device that gets detected (an Intel (0x8086) 82440FX NorthBridge (0x1237) on a 4.22 aws cluster) is ignored: https://github.com/openshift/node_exporter/blob/b7efb8c0f7d45f4ccb9120d4bcfb60ebe721ed69/collector/accelerators.go#L114-L119.
	"selinux_warning_controller_selinux_volume_conflict":            {},
	"volume_manager_selinux_pod_context_mismatch_errors_total":      {},
	"volume_manager_selinux_pod_context_mismatch_warnings_total":    {},
	"volume_manager_selinux_volume_context_mismatch_errors_total":   {},
	"volume_manager_selinux_volume_context_mismatch_warnings_total": {},
}

// TestTelemeterRemoteWrite verifies that the monitoring stack can send data to
// the telemeter server using the native Prometheus remote write endpoint.
func TestTelemeterRemoteWrite(t *testing.T) {
	cm := f.BuildCMOConfigMap(t, "{}")
	f.MustCreateOrUpdateConfigMap(t, cm)

	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, cm)
	})

	// Put CMO deployment into unmanaged state and enable telemetry via remote-write manually.
	ctx := context.Background()
	patch := []byte(`{
	"spec": {
		"overrides": [{
			"group": "apps",
			"kind": "Deployment",
			"name": "cluster-monitoring-operator",
			"namespace": "openshift-monitoring",
			"unmanaged": true
		}]
	}
}`)
	_, err := f.OpenShiftConfigClient.ConfigV1().ClusterVersions().Patch(ctx, "version", types.MergePatchType, patch, metav1.PatchOptions{})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		patch := []byte(`{"spec": {"overrides": []}}`)
		_, _ = f.OpenShiftConfigClient.ConfigV1().ClusterVersions().Patch(ctx, "version", types.MergePatchType, patch, metav1.PatchOptions{})
	})

	dep, err := f.KubeClient.AppsV1().Deployments(f.Ns).Get(ctx, "cluster-monitoring-operator", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for i, c := range dep.Spec.Template.Spec.Containers {
		if c.Name != "cluster-monitoring-operator" {
			continue
		}
		dep.Spec.Template.Spec.Containers[i].Args = append(dep.Spec.Template.Spec.Containers[i].Args, "-enabled-remote-write=true")
	}
	dep, err = f.KubeClient.AppsV1().Deployments(f.Ns).Update(ctx, dep, metav1.UpdateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// Check that Prometheus sends samples to Telemeter.
	f.PrometheusK8sClient.WaitForQueryReturn(
		t,
		5*time.Minute,
		`min without(pod,instance) (rate(prometheus_remote_storage_samples_total{job="prometheus-k8s",url=~"https://infogw.api.openshift.com.+"}[5m]))`,
		func(v float64) error {
			if v == 0 {
				return errors.New("expecting samples to be sent via Prometheus remote write but got none")
			}
			return nil
		},
	)
}

// TestTelemeterClient verifies that the telemeter client can collect metrics from the monitoring stack and forward them to the telemeter server.
func TestTelemeterClient(t *testing.T) {
	{
		f.PrometheusK8sClient.WaitForQueryReturn(
			t,
			5*time.Minute,
			`metricsclient_request_send{client="federate_to",job="telemeter-client",status_code="200"}`,
			func(v float64) error {
				if v == 0 {
					return fmt.Errorf("expecting metricsclient request send more than 0 but got none")
				}
				return nil
			},
		)

		f.PrometheusK8sClient.WaitForQueryReturn(
			t,
			5*time.Minute,
			`federate_samples{job="telemeter-client"}`,
			func(v float64) error {
				if v < 10 {
					return fmt.Errorf("expecting federate samples from telemeter client greater than or equal to 10 but got %f", v)
				}
				return nil
			},
		)
	}
}

func TestTelemetryCollectionProfile(t *testing.T) {
	cm := f.BuildCMOConfigMap(t, `prometheusK8s:
  collectionProfile: telemetry
`)
	f.MustCreateOrUpdateConfigMap(t, cm)
	t.Cleanup(func() {
		f.MustDeleteConfigMap(t, cm)
	})

	cmoMonitors := map[string]string{
		"openshift-monitoring/alertmanager-main-telemetry":           manifests.AlertmanagerTelemetryServiceMonitor,
		"openshift-monitoring/cluster-monitoring-operator-telemetry": manifests.ClusterMonitoringOperatorTelemetryServiceMonitor,
		"openshift-monitoring/kube-state-metrics-telemetry":          manifests.KubeStateMetricsTelemetryServiceMonitor,
		"openshift-monitoring/kubelet-telemetry":                     manifests.ControlPlaneKubeletTelemetryServiceMonitor,
		"openshift-monitoring/node-exporter-telemetry":               manifests.NodeExporterTelemetryServiceMonitor,
		"openshift-monitoring/openshift-state-metrics-telemetry":     manifests.OpenShiftStateMetricsTelemetryServiceMonitor,
		"openshift-monitoring/prometheus-k8s-telemetry":              manifests.PrometheusK8sPrometheusTelemetryServiceMonitor,
		"openshift-monitoring/telemeter-client-telemetry":            manifests.TelemeterClientTelemetryServiceMonitor,
	}

	// Extract all metrics for each monitor from telemetry rules that rely on CMO monitors.
	expectedMetrics := extractMetricsFromWhitelist(t, cmoMonitors)

	// Verify that all expected metrics are present in their corresponding ServiceMonitor assets.
	verifyMetricsInServiceMonitors(t, expectedMetrics, cmoMonitors)

	// Query Prometheus to verify expected metrics are being scraped.
	for monitorKey, metrics := range expectedMetrics {
		for metric := range metrics {
			if _, ok := ignoredMetrics[metric]; ok {
				continue
			}
			body, err := f.PrometheusK8sClient.PrometheusQuery(metric)
			if err != nil {
				t.Errorf("failed to query metric %s from monitor %s: %v", metric, monitorKey, err)
			}
			count, err := framework.GetResultSizeFromPromQuery(body)
			if err != nil {
				t.Errorf("failed to parse query result for metric %s from monitor %s: %v", metric, monitorKey, err)
			}
			if count == 0 {
				t.Errorf("no timeseries found for metric %s from monitor %s", metric, monitorKey)
			}
		}
	}
}

func extractMetricsFromWhitelist(t *testing.T, cmoMonitors map[string]string) map[string]map[string]struct{} {
	configMapPath := filepath.Join("..", "..", "manifests", "0000_50_cluster-monitoring-operator_04-config.yaml")
	data, err := os.ReadFile(configMapPath)
	if err != nil {
		t.Fatalf("failed to read whitelist ConfigMap: %v", err)
	}

	var cm struct {
		Data struct {
			MetricsYAML string `yaml:"metrics.yaml"`
		} `yaml:"data"`
	}

	if err := k8syaml.Unmarshal(data, &cm); err != nil {
		t.Fatalf("failed to parse whitelist ConfigMap: %v", err)
	}

	expectedMetrics := make(map[string]map[string]struct{})
	lines := strings.Split(cm.Data.MetricsYAML, "\n")
	markerRegex := regexp.MustCompile(`#marker:(reliesExclusivelyOnCMOmonitors|reliesPartiallyOnCMOmonitors)`)
	monitorLineRegex := regexp.MustCompile(`^\s*#\s*-\s*([^:]+):\s*(.+)$`) //    # - openshift-monitoring/monitor-name: metric1, metric2

	for i, line := range lines {
		if !markerRegex.MatchString(line) {
			continue
		}
		monitorMetricsCommentHeader := "This rule sources metrics from the following monitors:"
		for j := i - 1; j >= 0; j-- {
			if strings.Contains(lines[j], monitorMetricsCommentHeader) {
				break
			}
			matches := monitorLineRegex.FindStringSubmatch(lines[j])
			if len(matches) != 3 {
				continue
			}
			monitorKey := strings.TrimSpace(matches[1])
			if _, ok := cmoMonitors[monitorKey]; !ok {
				continue
			}
			if expectedMetrics[monitorKey] == nil {
				expectedMetrics[monitorKey] = make(map[string]struct{})
			}
			for _, m := range strings.Split(matches[2], ",") {
				if metric := strings.TrimSpace(m); metric != "" {
					expectedMetrics[monitorKey][metric] = struct{}{}
				}
			}
		}
	}

	return expectedMetrics
}

func verifyMetricsInServiceMonitors(t *testing.T, expectedMetrics map[string]map[string]struct{}, cmoMonitors map[string]string) {
	for monitorKey, metrics := range expectedMetrics {
		assetPath := cmoMonitors[monitorKey]
		data, err := os.ReadFile(filepath.Join("..", "..", "assets", assetPath))
		if err != nil {
			t.Errorf("failed to read ServiceMonitor %s: %v", monitorKey, err)
			continue
		}

		var sm monv1.ServiceMonitor
		if err := k8syaml.Unmarshal(data, &sm); err != nil {
			t.Errorf("failed to parse ServiceMonitor %s: %v", monitorKey, err)
			continue
		}

		if len(sm.Spec.Endpoints) == 0 {
			t.Errorf("ServiceMonitor %s has no endpoints", monitorKey)
			continue
		}

		var regexPattern string
		for _, endpoint := range sm.Spec.Endpoints {
			for _, relabeling := range endpoint.MetricRelabelConfigs {
				if len(relabeling.SourceLabels) > 0 &&
					relabeling.SourceLabels[0] == "__name__" &&
					relabeling.Regex != "" {
					regexPattern = relabeling.Regex
					break
				}
			}
			if regexPattern != "" {
				break
			}
		}

		if regexPattern == "" {
			t.Errorf("ServiceMonitor %s (at %s) has no __name__ regex pattern in any endpoint", monitorKey, assetPath)
			continue
		}

		regex, err := regexp.Compile(regexPattern)
		if err != nil {
			t.Errorf("failed to compile regex for %s: %v", monitorKey, err)
			continue
		}

		for metric := range metrics {
			if !regex.MatchString(metric) {
				t.Errorf("metric %s not in ServiceMonitor %s regex: %s", metric, monitorKey, regexPattern)
			}
		}
	}
}
