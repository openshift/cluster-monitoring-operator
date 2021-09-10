// Copyright 2020 The Cluster Monitoring Operator Authors
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
	"fmt"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	clusterMonitorConfigMapName      = "cluster-monitoring-config"
	userWorkloadMonitorConfigMapName = "user-workload-monitoring-config"
)

func TestClusterMonitoringOperatorConfiguration(t *testing.T) {
	// Enable user workload monitoring to assess that an invalid configuration
	// doesn't rollback the last known and valid configuration.
	setupUserWorkloadAssets(t, f)
	defer tearDownUserWorkloadAssets(t, f)

	t.Log("asserting that CMO is healthy")
	f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionFalse)(t)
	f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionTrue)(t)

	// Push an invalid configuration.
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterMonitorConfigMapName,
			Namespace: f.Ns,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": `cannot be deserialized`,
		},
	}
	f.MustCreateOrUpdateConfigMap(t, cm)

	t.Log("asserting that CMO goes degraded after an invalid configuration is pushed")
	f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionTrue)(t)
	f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionFalse)(t)
	// Check that the previous setup hasn't been reverted
	f.AssertStatefulsetExists("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)

	// Restore the first configuration.
	f.MustCreateOrUpdateConfigMap(t, getUserWorkloadEnabledConfigMap(t, f))
	t.Log("asserting that CMO goes back healthy after the configuration is fixed")
	f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionFalse)(t)
	f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionTrue)(t)
}

func TestGrafanaConfiguration(t *testing.T) {
	config := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-monitoring-config",
			Namespace: f.Ns,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": "grafana: { enabled: false }",
		},
	}
	f.MustCreateOrUpdateConfigMap(t, config)

	// Wait for Grafana deployment to disappear.
	f.AssertDeploymentDoesNotExist("grafana", f.Ns)(t)

	t.Log("asserting that CMO is healthy after disabling Grafana")
	f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionFalse)(t)
	f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionTrue)(t)

	// Push a default configuration that re-enables Grafana.
	config.Data["config.yaml"] = "grafana: { enabled: true }"
	f.MustCreateOrUpdateConfigMap(t, config)
	// Wait for Grafana deployment to appear.
	f.AssertDeploymentExists("grafana", f.Ns)(t)

	t.Log("asserting that CMO is healthy after re-enabling Grafana")
	f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionFalse)(t)
	f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionTrue)(t)
}

func TestClusterMonitorPrometheusOperatorConfig(t *testing.T) {
	const (
		containerName = "prometheus-operator"
	)

	data := `prometheusOperator:
  logLevel: info
  tolerations:
    - operator: "Exists"
`
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	for _, tc := range []scenario{
		{

			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=prometheus-operator",
				[]framework.PodAssertion{
					expectCatchAllToleration(),
					expectContainerArg("--log-level=info", containerName),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestClusterMonitorPrometheusK8Config(t *testing.T) {
	const (
		pvcClaimName    = "prometheus-k8s-db-prometheus-k8s-0"
		statefulsetName = "prometheus-k8s"
		cpu             = "1m"
		mem             = "3Mi"
		storage         = "2Gi"
		podName         = "prometheus-k8s-0"
		containerName   = "prometheus"
		labelSelector   = "app.kubernetes.io/component=prometheus"
		crName          = "k8s"
		thanosRule      = "prometheus-k8s-thanos-sidecar-rules"
	)

	data := fmt.Sprintf(`prometheusK8s:
  logLevel: debug
  retention: 10h
  queryLogFile: /tmp/test.log
  tolerations:
    - operator: "Exists"
  externalLabels:
    datacenter: eu-west
  remoteWrite:
  - url: "https://test.remotewrite.com/api/write"
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: %s
  resources:
    requests:
      cpu: %s
      memory: %s
`, storage, cpu, mem)
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	for _, tc := range []scenario{
		{
			name:      "assert pvc was created",
			assertion: f.AssertPersistentVolumeClaimsExist(pvcClaimName, f.Ns),
		},
		{
			name:      "assert ss exists and rolled out",
			assertion: f.AssertStatefulSetExistsAndRollout(statefulsetName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				labelSelector,
				[]framework.PodAssertion{
					expectCatchAllToleration(),
					expectMatchingRequests(podName, containerName, mem, cpu),
					expectContainerArg("--log.level=debug", containerName),
					expectContainerArg("--storage.tsdb.retention.time=10h", containerName),
				},
			),
		},
		{
			name:      "assert external labels are present on the CR",
			assertion: assertExternalLabelExists(f.Ns, crName, "datacenter", "eu-west"),
		},
		{
			name:      "assert remote write url value in set in CR",
			assertion: assertRemoteWriteWasSet(f.Ns, crName, "https://test.remotewrite.com/api/write"),
		},
		{
			name:      "assert query log file value is set and correct",
			assertion: assertQueryLogValueEquals(f.Ns, crName, "/tmp/test.log"),
		},
		{
			name:      "assert rule for Thanos sidecar exists",
			assertion: f.AssertPrometheusRuleExists(thanosRule, f.Ns),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestClusterMonitorAlertManagerConfig(t *testing.T) {
	const (
		pvcClaimName    = "alertmanager-main-db-alertmanager-main-0"
		statefulsetName = "alertmanager-main"
		cpu             = "10m"
		mem             = "13Mi"
		storage         = "2Gi"
		podName         = "alertmanager-main-0"
		containerName   = "alertmanager"
		labelSelector   = "alertmanager=main"
	)

	data := fmt.Sprintf(`alertmanagerMain:
  resources:
    requests:
      cpu: %s
      memory: %s
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: %s
  tolerations:
    - operator: "Exists"
`, cpu, mem, storage)
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	for _, tc := range []scenario{
		{
			name:      "assert that PVC is created",
			assertion: f.AssertPersistentVolumeClaimsExist(pvcClaimName, f.Ns),
		},
		{
			name:      "assert that ss is created and rolled out",
			assertion: f.AssertStatefulSetExistsAndRollout(statefulsetName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				labelSelector,
				[]framework.PodAssertion{
					expectCatchAllToleration(),
					expectMatchingRequests(podName, containerName, mem, cpu),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestClusterMonitorKSMConfig(t *testing.T) {
	const (
		deploymentName = "kube-state-metrics"
	)

	data := `kubeStateMetrics:
  tolerations:
    - operator: "Exists"
`
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	for _, tc := range []scenario{
		{
			name:      "test the kube-state-metrics deployment is rolled out",
			assertion: f.AssertDeploymentExistsAndRollout(deploymentName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=kube-state-metrics",
				[]framework.PodAssertion{
					expectCatchAllToleration(),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestClusterMonitorOSMConfig(t *testing.T) {
	const (
		deploymentName = "openshift-state-metrics"
	)

	data := `openshiftStateMetrics:
  tolerations:
    - operator: "Exists"
`
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	for _, tc := range []scenario{
		{
			name:      "test the openshift-state-metrics deployment is rolled out",
			assertion: f.AssertDeploymentExistsAndRollout(deploymentName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"k8s-app=openshift-state-metrics",
				[]framework.PodAssertion{
					expectCatchAllToleration(),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestClusterMonitorGrafanaConfig(t *testing.T) {
	const deploymentName = "grafana"
	data := `grafana:
  tolerations:
    - operator: "Exists"
`
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	for _, tc := range []scenario{
		{
			name:      "test the grafana deployment is rolled out",
			assertion: f.AssertDeploymentExistsAndRollout(deploymentName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/component=grafana",
				[]framework.PodAssertion{
					expectCatchAllToleration(),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestClusterMonitorTelemeterClientConfig(t *testing.T) {
	const (
		deploymentName = "telemeter-client"
	)

	data := `telemeterClient:
  tolerations:
    - operator: "Exists"
`
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	for _, tc := range []scenario{
		{
			name:      "test the telemeter-client deployment is rolled out",
			assertion: f.AssertDeploymentExistsAndRollout(deploymentName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/component=grafana",
				[]framework.PodAssertion{
					expectCatchAllToleration(),
				},
			),
		},
	} {
		if ok := t.Run(tc.name, tc.assertion); !ok {
			t.Fatalf("scenario %q failed", tc.name)
		}
	}
}

func TestClusterMonitorK8sPromAdapterConfig(t *testing.T) {
	const (
		deploymentName = "prometheus-adapter"
	)

	data := `k8sPrometheusAdapter:
  tolerations:
    - operator: "Exists"
`
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	for _, tc := range []scenario{
		{
			name:      "test the prometheus-adapter deployment is rolled out",
			assertion: f.AssertDeploymentExistsAndRollout(deploymentName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/component=metrics-adapter",
				[]framework.PodAssertion{
					expectCatchAllToleration(),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestClusterMonitorThanosQuerierConfig(t *testing.T) {
	const (
		deploymentName = "thanos-querier"
		containerName  = "thanos-query"
		cpu            = "1m"
		mem            = "3Mi"
	)

	data := fmt.Sprintf(`thanosQuerier:
  logLevel: debug
  tolerations:
    - operator: "Exists"
  resources:
    requests:
      cpu: %s
      memory: %s
`, cpu, mem)
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	for _, test := range []scenario{
		{
			name:      "test the thanos-querier deployment is rolled out",
			assertion: f.AssertDeploymentExistsAndRollout(deploymentName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=thanos-query",
				[]framework.PodAssertion{
					expectCatchAllToleration(),
					expectMatchingRequests("*", containerName, mem, cpu),
				},
			),
		},
	} {
		t.Run(test.name, test.assertion)
	}
}

func TestUserWorkloadMonitorPromOperatorConfig(t *testing.T) {
	const (
		containerName = "prometheus-operator"
	)

	setupUserWorkloadAssetsWithTeardownHook(t, f)

	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": `prometheusOperator:
  logLevel: debug
  tolerations:
    - operator: "Exists"
`,
		},
	}
	f.MustCreateOrUpdateConfigMap(t, uwmCM)

	for _, test := range []scenario{
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.UserWorkloadMonitoringNs,
				"app.kubernetes.io/name=prometheus-operator",
				[]framework.PodAssertion{
					expectCatchAllToleration(),
					expectContainerArg("--log-level=debug", containerName),
				},
			),
		},
	} {
		t.Run(test.name, test.assertion)
	}
}

func TestUserWorkloadMonitorPrometheusK8Config(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)
	const (
		pvcClaimName    = "prometheus-user-workload-db-prometheus-user-workload-0"
		statefulsetName = "prometheus-user-workload"
		cpu             = "1m"
		mem             = "3Mi"
		storage         = "2Gi"
		podName         = "prometheus-user-workload-0"
		containerName   = "prometheus"
		labelSelector   = "app.kubernetes.io/component=prometheus"
		crName          = "user-workload"
	)

	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": fmt.Sprintf(`prometheus:
  enforcedTargetLimit: 10
  logLevel: debug
  retention: 10h
  queryLogFile: /tmp/test.log
  tolerations:
    - operator: "Exists"
  externalLabels:
    datacenter: eu-west
  remoteWrite:
  - url: "https://test.remotewrite.com/api/write"
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: %s
  resources:
    requests:
      cpu: %s
      memory: %s
`, storage, cpu, mem),
		},
	}
	f.MustCreateOrUpdateConfigMap(t, uwmCM)

	for _, tc := range []scenario{
		{
			name:      "assert pvc was created",
			assertion: f.AssertPersistentVolumeClaimsExist(pvcClaimName, f.UserWorkloadMonitoringNs),
		},
		{
			name:      "assert ss exists and rolled out",
			assertion: f.AssertStatefulSetExistsAndRollout(statefulsetName, f.UserWorkloadMonitoringNs),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.UserWorkloadMonitoringNs,
				labelSelector,
				[]framework.PodAssertion{
					expectCatchAllToleration(),
					expectMatchingRequests(podName, containerName, mem, cpu),
					expectContainerArg("--log.level=debug", containerName),
					expectContainerArg("--storage.tsdb.retention.time=10h", containerName),
				},
			),
		},
		{
			name:      "assert external labels are present on the CR",
			assertion: assertExternalLabelExists(f.UserWorkloadMonitoringNs, crName, "datacenter", "eu-west"),
		},
		{
			name:      "assert remote write url value in set in CR",
			assertion: assertRemoteWriteWasSet(f.UserWorkloadMonitoringNs, crName, "https://test.remotewrite.com/api/write"),
		},
		{
			name:      "assert enforced target limit is configured",
			assertion: assertEnforcedTargetLimit(10),
		},
		{
			name:      "assert query log file value is set and correct",
			assertion: assertQueryLogValueEquals(f.UserWorkloadMonitoringNs, crName, "/tmp/test.log"),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestUserWorkloadMonitorThanosRulerConfig(t *testing.T) {
	const (
		containerName   = "thanos-ruler"
		pvcClaimName    = "thanos-ruler-user-workload-data-thanos-ruler-user-workload-0"
		statefulsetName = "thanos-ruler-user-workload"
		cpu             = "1m"
		mem             = "3Mi"
		storage         = "2Gi"
	)

	setupUserWorkloadAssetsWithTeardownHook(t, f)

	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": fmt.Sprintf(`thanosRuler:
  logLevel: debug
  tolerations:
    - operator: "Exists"
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: %s
  resources:
    requests:
      cpu: %s
      memory: %s
`, storage, cpu, mem),
		},
	}
	f.MustCreateOrUpdateConfigMap(t, uwmCM)

	for _, tc := range []scenario{
		{
			name:      "assert pvc was created",
			assertion: f.AssertPersistentVolumeClaimsExist(pvcClaimName, f.UserWorkloadMonitoringNs),
		},
		{
			name:      "assert ss exists and rolled out",
			assertion: f.AssertStatefulSetExistsAndRollout(statefulsetName, f.UserWorkloadMonitoringNs),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=thanos-ruler",
				[]framework.PodAssertion{
					expectCatchAllToleration(),
					expectMatchingRequests("*", containerName, mem, cpu),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func configMapWithData(t *testing.T, addData string) *v1.ConfigMap {
	t.Helper()
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterMonitorConfigMapName,
			Namespace: f.Ns,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": addData,
		},
	}
}

// checks that the toleration is set accordingly
// this toleration will match all so will not affect rolling out workloads
func expectCatchAllToleration() framework.PodAssertion {
	return func(pod v1.Pod) error {
		var hasToleration bool
		for _, toleration := range pod.Spec.Tolerations {
			if toleration.Operator == "Exists" {
				hasToleration = true
				break
			}
		}

		if !hasToleration {
			return fmt.Errorf("expected 'Exists' operator toleration but found none")
		}
		return nil
	}
}

// checks that the container name has the same request cpu,mem as expected
// pass "*" as podName t match all
func expectMatchingRequests(podName, containerName, expectMem, expectCPU string) framework.PodAssertion {
	return func(pod v1.Pod) error {
		if podName == "*" || pod.Name == podName {
			for _, container := range pod.Spec.Containers {
				if container.Name == containerName {
					containerMemory := container.Resources.Requests[v1.ResourceMemory]
					actualMemory := containerMemory.String()
					if actualMemory != expectMem {
						return fmt.Errorf("memory requests %s does not match actual %s", expectMem, actualMemory)
					}
					containerCPU := container.Resources.Requests[v1.ResourceCPU]
					actualCPU := containerCPU.String()
					if actualCPU != expectCPU {
						return fmt.Errorf("CPU requests %s does not match actual %s", expectCPU, actualCPU)
					}
				}
			}
		}
		return nil
	}
}

func expectContainerArg(arg string, containerName string) framework.PodAssertion {
	return func(pod v1.Pod) error {
		for _, container := range pod.Spec.Containers {
			if container.Name == containerName {
				for _, a := range container.Args {
					if a == arg {
						return nil
					}
				}
				return fmt.Errorf("arg %s not propagated from manifest", arg)
			}
		}
		return nil
	}
}

func expectVolumeMountsInContainer(containerName, mountName string) framework.PodAssertion {
	return func(pod v1.Pod) error {
		for _, container := range pod.Spec.Containers {
			if container.Name == containerName {
				for _, mount := range container.VolumeMounts {
					if mount.Name == mountName {
						return nil
					}
				}
				return fmt.Errorf("expected volume mount %s not found in container %s", mountName, containerName)
			}
		}
		return nil
	}
}

func assertExternalLabelExists(namespace, crName, expectKey, expectValue string) func(t *testing.T) {
	return func(t *testing.T) {
		err := framework.Poll(time.Second, time.Minute*5, func() error {
			prom, err := f.MonitoringClient.Prometheuses(namespace).Get(context.Background(), crName, metav1.GetOptions{})
			if err != nil {
				t.Fatal("failed to get required prometheus cr", err)
			}

			if prom.Spec.ExternalLabels == nil {
				return fmt.Errorf("external labels map is nil")
			}

			gotValue, ok := prom.Spec.ExternalLabels[expectKey]
			if !ok {
				return fmt.Errorf("expected key %s is missing", expectKey)
			}

			if gotValue != expectValue {
				return fmt.Errorf("expected value %s but got %s", expectValue, gotValue)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertRemoteWriteWasSet(namespace, crName, urlValue string) func(t *testing.T) {
	return func(t *testing.T) {
		err := framework.Poll(time.Second, time.Minute*5, func() error {
			prom, err := f.MonitoringClient.Prometheuses(namespace).Get(context.Background(), crName, metav1.GetOptions{})
			if err != nil {
				t.Fatal("failed to get required prometheus cr", err)
			}

			if len(prom.Spec.RemoteWrite) == 0 {
				return fmt.Errorf("remote write spec not set")
			}

			for _, gotValue := range prom.Spec.RemoteWrite {
				if gotValue.URL == urlValue {
					return nil
				}
			}
			return fmt.Errorf("expected remote write url value not found")
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertEnforcedTargetLimit(limit uint64) func(*testing.T) {
	ctx := context.Background()
	return func(t *testing.T) {
		err := framework.Poll(time.Second, 5*time.Minute, func() error {
			prom, err := f.MonitoringClient.Prometheuses(f.UserWorkloadMonitoringNs).Get(ctx, "user-workload", metav1.GetOptions{})
			if err != nil {
				return err
			}

			if prom.Spec.EnforcedTargetLimit == nil {
				return errors.New("EnforcedTargetLimit not set")
			} else if *prom.Spec.EnforcedTargetLimit != limit {
				return fmt.Errorf("expected EnforcedTargetLimit to be %d, but got %d", limit, *prom.Spec.EnforcedTargetLimit)
			}

			return nil
		})

		if err != nil {
			t.Fatalf("Timed out waiting for EnforcedTargetLimit configuration: %v", err)
		}
	}
}

func assertQueryLogValueEquals(namespace, crName, value string) func(t *testing.T) {
	return func(t *testing.T) {
		err := framework.Poll(time.Second, time.Minute*5, func() error {
			prom, err := f.MonitoringClient.Prometheuses(namespace).Get(context.Background(), crName, metav1.GetOptions{})
			if err != nil {
				t.Fatal("failed to get required prometheus cr", err)
			}

			if prom.Spec.QueryLogFile != value {
				return fmt.Errorf(
					"expected query log file value not found wanted '%s', got '%s'",
					value, prom.Spec.QueryLogFile,
				)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
