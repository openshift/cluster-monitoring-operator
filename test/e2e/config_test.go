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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Jeffail/gabs"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/stretchr/testify/require"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
			Name:      framework.ClusterMonitorConfigMapName,
			Namespace: f.Ns,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": `cannot be deserialized`,
		},
	}
	err := f.OperatorClient.CreateOrUpdateConfigMap(ctx, cm)
	// The CMO validate webhook shouldn't allow that.
	require.True(t, apierrors.IsForbidden(err))

	// If the change isn't caught by the validate webhook (here we explicitly skip it),
	// CMO status will still reflect the failure.
	cm.Labels["monitoringconfigmaps.openshift.io/skip-validate-webhook"] = "true"
	f.MustCreateOrUpdateConfigMap(t, cm)

	t.Log("asserting that CMO goes degraded after an invalid configuration is pushed")
	f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionTrue)(t)
	f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionFalse)(t)
	f.AssertOperatorConditionReason(configv1.OperatorDegraded, "InvalidConfiguration")
	f.AssertOperatorConditionReason(configv1.OperatorAvailable, "InvalidConfiguration")
	// Check that the previous setup hasn't been reverted
	f.AssertStatefulsetExists("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)

	// Restore the first configuration.
	f.MustCreateOrUpdateConfigMap(t, getUserWorkloadEnabledConfigMap(t, f))
	t.Log("asserting that CMO goes back healthy after the configuration is fixed")
	f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionFalse)(t)
	f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionTrue)(t)
}

func TestClusterMonitoringStatus(t *testing.T) {
	const (
		storage = "2Gi"
	)
	for _, tc := range []struct {
		name               string
		config             string
		userWorkloadConfig string
		assertion          func(t *testing.T)
	}{
		{
			name:               "default config, no persistent storage",
			config:             "",
			userWorkloadConfig: "",
			assertion: func(t *testing.T) {
				f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionTrue)(t)
				f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionFalse)(t)
				f.AssertOperatorConditionReason(configv1.OperatorDegraded, client.StorageNotConfiguredReason)
				f.AssertOperatorConditionMessageContains(configv1.OperatorDegraded, client.StorageNotConfiguredMessage)
			},
		},
		{
			name: "default config with presistent storage",
			config: fmt.Sprintf(`enableUserWorkload: true
alertmanagerMain:
  enableUserAlertmanagerConfig: true
prometheusK8s:
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: %s
`, storage),
			userWorkloadConfig: "",
			assertion: func(t *testing.T) {
				f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionTrue)(t)
				f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionFalse)(t)
				f.AssertOperatorConditionReason(configv1.OperatorDegraded, "")
				f.AssertOperatorConditionMessage(configv1.OperatorDegraded, "")
			},
		},
		{
			name: "default config with presistent storage",
			config: fmt.Sprintf(`prometheusK8s:
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: %s
`, storage),
			userWorkloadConfig: "",
			assertion: func(t *testing.T) {
				f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionTrue)(t)
				f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionFalse)(t)
				f.AssertOperatorConditionReason(configv1.OperatorDegraded, "")
				f.AssertOperatorConditionMessage(configv1.OperatorDegraded, "")
			},
		},
		{
			name: "default config with presistent storage but with UserAlermanagerConfig missconfiguration",
			config: fmt.Sprintf(`enableUserWorkload: true
alertmanagerMain:
  enableUserAlertmanagerConfig: true
prometheusK8s:
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: %s
`, storage),
			userWorkloadConfig: `alertmanager:
  enabled: true
`,
			assertion: func(t *testing.T) {
				f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionTrue)(t)
				f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionFalse)(t)
				f.AssertOperatorConditionReason(configv1.OperatorDegraded, client.UserAlermanagerConfigMisconfiguredReason)
				f.AssertOperatorConditionMessage(configv1.OperatorDegraded, client.UserAlermanagerConfigMisconfiguredMessage)
			},
		},
		{
			name: "default config with presistent storage but with UserAlermanagerConfig missconfiguration",
			config: fmt.Sprintf(`enableUserWorkload: true
alertmanagerMain:
  enableUserAlertmanagerConfig: true
prometheusK8s:
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: %s
`, storage),
			userWorkloadConfig: `alertmanager:
  enabled: true
  enableAlertmanagerConfig: true
`,
			assertion: func(t *testing.T) {
				f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionTrue)(t)
				f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionFalse)(t)
				f.AssertOperatorConditionReason(configv1.OperatorDegraded, "")
				f.AssertOperatorConditionMessage(configv1.OperatorDegraded, "")
			},
		},
	} {
		f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, tc.config))

		if tc.userWorkloadConfig != "" {
			uwmCM := f.BuildUserWorkloadConfigMap(t, tc.userWorkloadConfig)
			f.MustCreateOrUpdateConfigMap(t, uwmCM)
		}

		t.Run(tc.name, tc.assertion)
	}
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
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))

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
  retentionSize: 15GB
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
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))

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
					// Set by default.
					expectContainerArg("--scrape.timestamp-tolerance=15ms", containerName),
					expectContainerArg("--enable-feature=delayed-compaction", containerName),
					// Set via the config above.
					expectContainerArg("--log.level=debug", containerName),
					expectContainerArg("--storage.tsdb.retention.time=10h", containerName),
					expectContainerArg("--storage.tsdb.retention.size=15GB", containerName),
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
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))

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
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))

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
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))

	for _, tc := range []scenario{
		{
			name:      "test the openshift-state-metrics deployment is rolled out",
			assertion: f.AssertDeploymentExistsAndRollout(deploymentName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=openshift-state-metrics",
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
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))

	for _, tc := range []scenario{
		{
			name:      "test the telemeter-client deployment is rolled out",
			assertion: f.AssertDeploymentExistsAndRollout(deploymentName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=telemeter-client",
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

func TestTelemeterClientSecret(t *testing.T) {
	for _, tc := range []struct {
		name         string
		oldC         string
		newC         string
		tokenChanged bool
	}{
		{
			name: "Existing Secret",
			oldC: `telemeterClient:
  token: mySecretToken
`,
			newC: `telemeterClient:
  token: mySecretToken
`,
			tokenChanged: false,
		},
		{
			name: "Existing Secret, new token",
			oldC: `telemeterClient:
  token: mySecretToken
`,
			newC: `telemeterClient:
  token: myNewSecretToken
`,
			tokenChanged: true,
		},
	} {

		t.Run(tc.name, func(t *testing.T) {
			f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, tc.oldC))
			oldS := f.MustGetSecret(t, "telemeter-client", f.Ns)
			f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, tc.newC))
			if tc.tokenChanged {
				f.AssertValueInSecretNotEquals(oldS.GetName(), oldS.GetNamespace(), "token", string(oldS.Data["token"]))
				f.AssertValueInSecretNotEquals(oldS.GetName(), oldS.GetNamespace(), "salt", string(oldS.Data["salt"]))
				return
			}
			f.AssertValueInSecretEquals(oldS.GetName(), oldS.GetNamespace(), "token", string(oldS.Data["token"]))
			f.AssertValueInSecretEquals(oldS.GetName(), oldS.GetNamespace(), "salt", string(oldS.Data["salt"]))
		})
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
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))

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
					expectContainerArg("--web.disable-cors", containerName),
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

	uwmCM := f.BuildUserWorkloadConfigMap(t,
		`prometheusOperator:
  logLevel: debug
  tolerations:
    - operator: "Exists"
`,
	)
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

	uwmCM := f.BuildUserWorkloadConfigMap(t,
		fmt.Sprintf(`prometheus:
  enforcedTargetLimit: 10
  enforcedLabelLimit: 500
  enforcedLabelNameLengthLimit: 50
  enforcedLabelValueLengthLimit: 600
  logLevel: debug
  retention: 10h
  retentionSize: 15GB
  queryLogFile: /tmp/test.log
  tolerations:
    - operator: "Exists"
  externalLabels:
    datacenter: eu-west
  remoteWrite:
  - url: "https://test.remotewrite.com/api/write"
    sendExemplars: true
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
	)
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
					// Set by default.
					expectContainerArg("--enable-feature=extra-scrape-metrics,delayed-compaction,exemplar-storage", containerName),
					// Set via the config above.
					expectContainerArg("--log.level=debug", containerName),
					expectContainerArg("--storage.tsdb.retention.time=10h", containerName),
					expectContainerArg("--storage.tsdb.retention.size=15GB", containerName),
				},
			),
		},
		{
			name:      "assert external labels are present on the CR",
			assertion: assertExternalLabelExists(f.UserWorkloadMonitoringNs, crName, "datacenter", "eu-west"),
		},
		{
			name:      "assert external labels are present on the ThanosRuler CR",
			assertion: assertExternalLabelExistsThanosRuler(f.UserWorkloadMonitoringNs, crName, "datacenter", "eu-west"),
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
			name:      "assert enforced label limit is configured",
			assertion: assertEnforcedLabelLimit(500),
		},
		{
			name:      "assert enforced label name length limit is configured",
			assertion: assertEnforcedLabelNameLengthLimit(50),
		},
		{
			name:      "assert enforced label value length limit",
			assertion: assertEnforcedLabelValueLengthLimit(600),
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

	uwmCM := f.BuildUserWorkloadConfigMap(t,
		fmt.Sprintf(`thanosRuler:
  logLevel: debug
  retention: 15d
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
	)
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
				"app.kubernetes.io/name=thanos-ruler",
				[]framework.PodAssertion{
					expectCatchAllToleration(),
					expectMatchingRequests("*", containerName, mem, cpu),
					expectContainerArg("--tsdb.retention=15d", containerName),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

// checkMonitorConsolePluginReachable makes sure that one of the pods at least can serve /plugin-manifest.json
func checkMonitorConsolePluginReachable(t *testing.T, pluginName string) {
	err := framework.Poll(time.Second, 5*time.Minute, func() error {
		host, cleanUp, err := f.ForwardPort(t, f.Ns, pluginName, 9443)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanUp()

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
		resp, err := client.Get(fmt.Sprintf("https://%s/plugin-manifest.json", host))
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("fail to read response body: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expected status %d, got %d (%q)", resp.StatusCode, http.StatusOK, framework.ClampMax(b))
		}

		res, err := gabs.ParseJSON(b)
		if err != nil {
			return err
		}
		name, ok := res.Path("name").Data().(string)
		if !ok || name != pluginName {
			return fmt.Errorf("expected plugin name to be %q, got %q", pluginName, name)
		}
		return nil
	})
	require.NoError(t, err)
}

func TestClusterMonitorConsolePlugin(t *testing.T) {
	const (
		deploymentName = "monitoring-plugin"
		cpu            = "10m"
		mem            = "13Mi"
		labelSelector  = "app.kubernetes.io/name=monitoring-plugin"
		containerName  = "monitoring-plugin"
	)

	// ensure console-plugin is running and reachable before the change
	f.AssertDeploymentExistsAndRollout(deploymentName, f.Ns)(t)
	checkMonitorConsolePluginReachable(t, deploymentName)

	data := fmt.Sprintf(`
monitoringPlugin:
  resources:
    requests:
      cpu: %s
      memory: %s
  tolerations:
    - operator: "Exists"
`, cpu, mem)

	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))

	for _, tc := range []scenario{
		{
			name:      "assert that deployment is created and rolled out",
			assertion: f.AssertDeploymentExistsAndRollout(deploymentName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				labelSelector,
				[]framework.PodAssertion{
					expectTolerationsEqual(1),
					expectCatchAllToleration(),
					expectMatchingRequests("*", containerName, mem, cpu),
				},
			),
		},
		{
			name:      "assert one of the pods can serve /plugin-manifest.json",
			assertion: func(t *testing.T) { checkMonitorConsolePluginReachable(t, deploymentName) },
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestClusterMonitoringDeprecatedConfig(t *testing.T) {
	metricName := "cluster_monitoring_operator_deprecated_config_in_use"
	checkMetricValue := func(value float64) {
		t.Helper()
		f.PrometheusK8sClient.WaitForQueryReturn(
			t, 5*time.Minute, fmt.Sprintf(`%s{configmap="openshift-monitoring/cluster-monitoring-config", field="k8sPrometheusAdapter", deprecation_version="4.16"}`, metricName),
			func(v float64) error {
				if v != value {
					return fmt.Errorf("expected %s to be of value %f.", metricName, value)
				}
				return nil
			},
		)
	}
	// No deprecated config should have been used.
	checkMetricValue(0)

	// Set a field for k8sPrometheusAdapter.
	data := `
k8sPrometheusAdapter:
  audit:
    profile: Request`
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))
	checkMetricValue(1)

	// The metric should be reset to 0.
	data = `
k8sPrometheusAdapter:`
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))
	checkMetricValue(0)
}

// checks that the toleration is present
// this toleration will match all so will not affect rolling out workloads
func expectTolerationsEqual(exp int) framework.PodAssertion {
	return func(pod v1.Pod) error {
		if got := len(pod.Spec.Tolerations); got != exp {
			return fmt.Errorf("expected to find %d tolerations in %s but found %d", exp, pod.Name, got)
		}
		return nil
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
			if container.Name != containerName {
				continue
			}

			for _, mount := range container.VolumeMounts {
				if mount.Name == mountName {
					return nil
				}
			}
			return fmt.Errorf("expected volume mount %q not found in container %q", mountName, containerName)
		}

		return fmt.Errorf("container %q not found in pod %s/%s", containerName, pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
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

func assertExternalLabelExistsThanosRuler(namespace, crName, expectKey, expectValue string) func(t *testing.T) {
	return func(t *testing.T) {
		err := framework.Poll(time.Second, time.Minute*5, func() error {
			tr, err := f.MonitoringClient.ThanosRulers(namespace).Get(context.Background(), crName, metav1.GetOptions{})
			if err != nil {
				t.Fatal("failed to get required thanos ruler cr", err)
			}

			if tr.Spec.Labels == nil {
				return fmt.Errorf("external labels map is nil")
			}

			gotValue, ok := tr.Spec.Labels[expectKey]
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

func assertEnforcedLabelLimit(limit uint64) func(*testing.T) {
	ctx := context.Background()
	return func(t *testing.T) {
		err := framework.Poll(time.Second, 5*time.Minute, func() error {
			prom, err := f.MonitoringClient.Prometheuses(f.UserWorkloadMonitoringNs).Get(ctx, "user-workload", metav1.GetOptions{})
			if err != nil {
				return err
			}

			if prom.Spec.EnforcedLabelLimit == nil {
				return errors.New("EnforcedLabelLimit not set")
			} else if *prom.Spec.EnforcedLabelLimit != limit {
				return fmt.Errorf("expected EnforcedLabelLimit to be %d, but got %d", limit, *prom.Spec.EnforcedLabelLimit)
			}

			return nil
		})

		if err != nil {
			t.Fatalf("Timed out waiting for EnforcedLabelLimit configuration: %v", err)
		}
	}
}

func assertEnforcedLabelNameLengthLimit(limit uint64) func(*testing.T) {
	ctx := context.Background()
	return func(t *testing.T) {
		err := framework.Poll(time.Second, 5*time.Minute, func() error {
			prom, err := f.MonitoringClient.Prometheuses(f.UserWorkloadMonitoringNs).Get(ctx, "user-workload", metav1.GetOptions{})
			if err != nil {
				return err
			}

			if prom.Spec.EnforcedLabelNameLengthLimit == nil {
				return errors.New("EnforcedLabelNameLengthLimit not set")
			} else if *prom.Spec.EnforcedLabelNameLengthLimit != limit {
				return fmt.Errorf("expected EnforcedLabelNameLengthLimit to be %d, but got %d", limit, *prom.Spec.EnforcedLabelNameLengthLimit)
			}

			return nil
		})

		if err != nil {
			t.Fatalf("Timed out waiting for EnforcedLabelNameLengthLimit configuration: %v", err)
		}
	}
}

func assertEnforcedLabelValueLengthLimit(limit uint64) func(*testing.T) {
	ctx := context.Background()
	return func(t *testing.T) {
		err := framework.Poll(time.Second, 5*time.Minute, func() error {
			prom, err := f.MonitoringClient.Prometheuses(f.UserWorkloadMonitoringNs).Get(ctx, "user-workload", metav1.GetOptions{})
			if err != nil {
				return err
			}

			if prom.Spec.EnforcedLabelValueLengthLimit == nil {
				return errors.New("EnforcedLabelValueLengthLimit not set")
			} else if *prom.Spec.EnforcedLabelValueLengthLimit != limit {
				return fmt.Errorf("expected EnforcedLabelValueLengthLimit to be %d, but got %d", limit, *prom.Spec.EnforcedLabelValueLengthLimit)
			}

			return nil
		})

		if err != nil {
			t.Fatalf("Timed out waiting for EnforcedLabelValueLengthLimit configuration: %v", err)
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
