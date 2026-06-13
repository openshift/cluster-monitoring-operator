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

package e2e

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
)

var f *framework.Framework

// clusterMonitoringCRDAvailable is set once in testMain(); tests that require the
// ClusterMonitoring CRD (TechPreview / ClusterMonitoringConfig feature gate) should Skip when false.
var clusterMonitoringCRDAvailable bool

const (
	clusterMonitoringDenyAllTrafficNPName      = "deny-cluster-monitoring-operator-and-operands"
	userWorkloadMonitoringDenyAllTrafficNPName = "default-deny-user-workload-operands"
)

func TestMain(m *testing.M) {
	if err := testMain(m); err != nil {
		log.Fatal(err)
	}
}

// testMain circumvents the issue, that one can not call `defer` in TestMain, as
// `os.Exit` does not honor `defer` statements. For more details see:
// http://blog.englund.nu/golang,/testing/2017/03/12/using-defer-in-testmain.html
func testMain(m *testing.M) error {
	ctx := context.Background()
	defaultKubeConfig := clientcmd.RecommendedHomeFile
	if v := os.Getenv("KUBECONFIG"); v != "" {
		defaultKubeConfig = v
	}
	kubeConfigPath := flag.String(
		"kubeconfig",
		defaultKubeConfig,
		"kube config path, default: $KUBECONFIG or $HOME/.kube/config",
	)

	flag.Parse()

	var (
		err     error
		cleanUp func() error
	)
	f, cleanUp, err = framework.New(*kubeConfigPath)
	// Check cleanUp first, in case of an err, we still want to clean up.
	if cleanUp != nil {
		defer cleanUp()
	}
	if err != nil {
		return err
	}

	// Wait for Prometheus operator.
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.AppsV1().Deployments(f.Ns).Get(ctx, "prometheus-operator", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return err
	}

	// Wait for Prometheus.
	var loopErr error
	err = wait.Poll(5*time.Second, 1*time.Minute, func() (bool, error) {
		var (
			body []byte
			v    float64
		)
		body, loopErr = f.ThanosQuerierClient.PrometheusQuery("count(last_over_time(up{job=\"prometheus-k8s\"}[2m]))")
		if loopErr != nil {
			loopErr = fmt.Errorf("error executing prometheus query: %w", loopErr)
			return false, nil
		}

		v, loopErr = framework.GetFirstValueFromPromQuery(body)
		if loopErr != nil {
			loopErr = fmt.Errorf("error getting first value from prometheus response %q: %w", string(body), loopErr)
			return false, nil
		}

		i, loopErr := f.OperatorClient.GetInfrastructure(ctx)
		if loopErr != nil {
			loopErr = fmt.Errorf("error getting cluster infrastructure: %w", loopErr)
			return false, nil
		}

		var expected float64
		expected = 2
		if i.Status.InfrastructureTopology == configv1.SingleReplicaTopologyMode {
			expected = 1
		}
		if v != expected {
			loopErr = fmt.Errorf("expected %v Prometheus instances but got: %v", expected, v)
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		return fmt.Errorf("wait for prometheus-k8s: %w: %w", loopErr, err)
	}

	_, err = f.OpenShiftConfigClient.ConfigV1alpha1().ClusterMonitorings().List(ctx, metav1.ListOptions{Limit: 1})
	if err == nil {
		clusterMonitoringCRDAvailable = true
	}

	if m.Run() != 0 {
		return errors.New("tests failed")
	}

	return nil
}

func TestTargetsUp(t *testing.T) {
	ctx := context.Background()

	// Check that all targets are up initially.
	testTargetsUp(t)

	// Delete the client TLS certificate used by Prometheus to scrape endpoints.
	// CMO should recreate it and the new certificate should still be trusted
	// by the endpoints. If an endpoint remains down, it's probably because it
	// doesn't use the cluster CA bundle.
	// See https://issues.redhat.com/browse/OCPBUGS-4521.
	metricsClientCertSecret, err := f.ManifestsFactory.MetricsClientCerts()
	if err != nil {
		t.Fatal(err)
	}
	err = f.KubeClient.CoreV1().Secrets(metricsClientCertSecret.Namespace).Delete(ctx, metricsClientCertSecret.Name, metav1.DeleteOptions{})

	f.AssertSecretExistsFunc(metricsClientCertSecret.GetName(), f.Ns)(t)

	// We need to wait a bit before verifying that all targets are up because
	// it will take some time for the kubelet to propagate the new certificate
	// to the Prometheus container. 2 minutes should be more than enough.
	time.Sleep(120 * time.Second)
	testTargetsUp(t)
}

func testTargetsUp(t *testing.T) {
	// Don't run this test in parallel, as other tests might trigger scrape failures.
	t.Helper()

	targets := []string{
		"node-exporter",
		"kube-state-metrics",
		"kubelet",
		"prometheus-k8s",
		"prometheus-k8s-thanos-sidecar",
		"prometheus-operator",
		"alertmanager-main",
		"cluster-monitoring-operator",
		"openshift-state-metrics",
		"telemeter-client",
		"thanos-querier",
	}

	for _, target := range targets {
		f.ThanosQuerierClient.WaitForQueryReturnOne(
			t,
			time.Minute,
			"max(up{job=\""+target+"\"})",
		)
	}

}

// Once we have the need to test multiple recording rules, we can unite them in
// a single test function.
func TestMemoryUsageRecordingRule(t *testing.T) {
	f.ThanosQuerierClient.WaitForQueryReturnGreaterEqualOne(
		t,
		time.Minute,
		"count(namespace:container_memory_usage_bytes:sum)",
	)
}

// assertNetworkPolicyPortsAreNumeric verifies that all NetworkPolicy ports
// use numeric values, not named ports.
func assertNetworkPolicyPortsAreNumeric(t *testing.T, nps []networkingv1.NetworkPolicy) {
	t.Helper()

	for _, np := range nps {
		for _, rule := range np.Spec.Ingress {
			for _, p := range rule.Ports {
				require.Equalf(t, intstr.Int, p.Port.Type, "NetworkPolicy %s/%s has named port %q", np.Namespace, np.Name, p.Port.StrVal)
			}
		}
		for _, rule := range np.Spec.Egress {
			for _, p := range rule.Ports {
				require.Equalf(t, intstr.Int, p.Port.Type, "NetworkPolicy %s/%s has named port %q", np.Namespace, np.Name, p.Port.StrVal)
			}
		}
	}
}

// expectLabel returns a PodAssertion that checks a pod has the given label with the expected value.
func expectLabel(labelKey, expectedValue string) framework.PodAssertion {
	return func(pod v1.Pod) error {
		if value, ok := pod.Labels[labelKey]; ok {
			if value == expectedValue {
				return nil
			}
			return fmt.Errorf("pod %s has label %s with value %q, expected %q", pod.Name, labelKey, value, expectedValue)
		}
		return fmt.Errorf("pod %s is missing required label %s", pod.Name, labelKey)
	}
}

const npProbeNamespace = "e2e-test-np-connectivity"

// TestNetworkPolicy validates NetworkPolicy configuration and enforcement
// across all monitoring namespaces.
func TestNetworkPolicy(t *testing.T) {
	ctx := context.Background()

	setupUserWorkloadAssetsWithTeardownHook(t, f)

	// Enable the UWM Alertmanager so its NetworkPolicy is also tested.
	uwmCM := f.BuildUserWorkloadConfigMap(t, `alertmanager:
  enabled: true
`)
	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	t.Cleanup(func() { f.MustDeleteConfigMap(t, uwmCM) })
	f.AssertStatefulSetExistsAndRolloutFunc("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)

	cleanupNS, err := f.CreateNamespace(npProbeNamespace)
	require.NoError(t, err, "failed to create probe namespace")
	t.Cleanup(func() { require.NoError(t, cleanupNS(), "failed to cleanup probe namespace") })

	clusterMonitoringNPNames := []string{
		clusterMonitoringDenyAllTrafficNPName,
		"cluster-monitoring-operator",
		"alertmanager",
		"prometheus",
		"kube-state-metrics",
		"metrics-server",
		"monitoring-plugin",
		"openshift-state-metrics",
		"prometheus-operator",
		"prometheus-operator-admission-webhook",
		"telemeter-client",
		"thanos-querier",
	}
	uwmNPNames := []string{
		userWorkloadMonitoringDenyAllTrafficNPName,
		"alertmanager-user-workload",
		"prometheus-operator-user-workload",
		"prometheus-user-workload",
		"thanos-ruler",
	}

	expectedNPs := map[string][]string{
		f.Ns:                       clusterMonitoringNPNames,
		f.UserWorkloadMonitoringNs: uwmNPNames,
	}

	for _, ns := range []string{f.Ns, f.UserWorkloadMonitoringNs} {
		t.Run(fmt.Sprintf("%s/pod-labels", ns), func(t *testing.T) {
			f.AssertPodConfigurationFunc(ns, "", []framework.PodAssertion{
				expectLabel("app.kubernetes.io/part-of", "openshift-monitoring"),
			})(t)
		})

		expectedNPNames := expectedNPs[ns]

		t.Run(fmt.Sprintf("%s/existence", ns), func(t *testing.T) {
			for _, name := range expectedNPNames {
				t.Run(name, func(t *testing.T) {
					f.AssertNetworkPolicyExistsFunc(name, ns)(t)
				})
			}
		})

		nps, err := f.KubeClient.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		require.NoError(t, err, "failed to list NetworkPolicies in %s", ns)

		t.Run(fmt.Sprintf("%s/count", ns), func(t *testing.T) {
			require.Equal(t, len(expectedNPNames), len(nps.Items), "unexpected number of NetworkPolicies in %s", ns)
		})

		t.Run(fmt.Sprintf("%s/numeric-ports", ns), func(t *testing.T) {
			assertNetworkPolicyPortsAreNumeric(t, nps.Items)
		})

		for _, np := range nps.Items {
			if np.Name == clusterMonitoringDenyAllTrafficNPName || np.Name == userWorkloadMonitoringDenyAllTrafficNPName {
				continue
			}

			t.Run(fmt.Sprintf("connectivity/%s/%s", np.Namespace, np.Name), func(t *testing.T) {
				t.Parallel()

				sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
				require.NoError(t, err, "failed to parse pod selector for NP %s", np.Name)

				pods, err := f.KubeClient.CoreV1().Pods(np.Namespace).List(ctx, metav1.ListOptions{
					LabelSelector: sel.String(),
				})
				require.NoError(t, err, "failed to list pods for NP %s", np.Name)
				require.NotEmpty(t, pods.Items, "no pods matched NP %s selector %q", np.Name, sel.String())

				// All pods behind the same NP selector should be similar, pick any.
				pod := pods.Items[0]
				podIP := pod.Status.PodIP
				require.NotEmpty(t, podIP, "pod %s has no IP", pod.Name)

				var allowed []int32
				for _, rule := range np.Spec.Ingress {
					for _, p := range rule.Ports {
						allowed = append(allowed, p.Port.IntVal)
					}
				}

				var podPorts []int32
				for _, c := range pod.Spec.Containers {
					for _, cp := range c.Ports {
						port := cp.ContainerPort
						podPorts = append(podPorts, port)
						if slices.Contains(allowed, port) {
							t.Run(fmt.Sprintf("allow-%d", port), func(t *testing.T) {
								assertReachable(t, ctx, podIP, port)
							})
						} else {
							t.Run(fmt.Sprintf("deny-%d", port), func(t *testing.T) {
								assertBlocked(t, ctx, podIP, port)
							})
						}
					}
				}

				// Ensure NP ingress ports are a subset of the pod's container ports
				// to catch stale NP rules referencing ports the pod no longer exposes.
				require.Subset(t, podPorts, allowed, "NP %s allows ports not exposed by the pod", np.Name)
			})
		}
	}
}

// assertReachable verifies that a TCP connection to ip:port succeeds.
// Only TCP is supported.
func assertReachable(t *testing.T, ctx context.Context, ip string, port int32) {
	t.Helper()
	script := fmt.Sprintf("timeout 5 bash -c 'echo > /dev/tcp/%s/%d'", ip, port)
	runProbePod(t, ctx, script)
}

// assertBlocked verifies that a TCP connection to ip:port times out
// (exit code 124), indicating the packet was dropped by a NetworkPolicy.
// Only TCP is supported.
func assertBlocked(t *testing.T, ctx context.Context, ip string, port int32) {
	t.Helper()
	script := fmt.Sprintf("rc=0; timeout 5 bash -c 'echo > /dev/tcp/%s/%d' || rc=$?; [ \"$rc\" -eq 124 ]", ip, port)
	runProbePod(t, ctx, script)
}

// runProbePod creates an ephemeral pod that runs the given shell script and
// asserts it exits successfully.
func runProbePod(t *testing.T, ctx context.Context, script string) {
	t.Helper()

	probe := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "np-probe-",
			Namespace:    npProbeNamespace,
		},
		Spec: v1.PodSpec{
			RestartPolicy: v1.RestartPolicyNever,
			Containers: []v1.Container{{
				Name:            "probe",
				Image:           "image-registry.openshift-image-registry.svc:5000/openshift/cli:latest",
				ImagePullPolicy: v1.PullIfNotPresent,
				Command:         []string{"bash", "-c", script},
				SecurityContext: &v1.SecurityContext{
					Capabilities: &v1.Capabilities{
						Drop: []v1.Capability{"ALL"},
					},
					SeccompProfile: &v1.SeccompProfile{
						Type: v1.SeccompProfileTypeRuntimeDefault,
					},
				},
			}},
		},
	}

	pod, err := f.KubeClient.CoreV1().Pods(npProbeNamespace).Create(ctx, probe, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create probe pod")
	podName := pod.Name
	t.Cleanup(func() {
		_ = f.KubeClient.CoreV1().Pods(npProbeNamespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
	})

	var phase v1.PodPhase
	err = framework.Poll(time.Second, 2*time.Minute, func() error {
		p, err := f.KubeClient.CoreV1().Pods(npProbeNamespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		phase = p.Status.Phase
		if phase != v1.PodSucceeded && phase != v1.PodFailed {
			return fmt.Errorf("waiting for pod %s", podName)
		}
		return nil
	})
	require.NoError(t, err, "probe pod %s did not complete in time", podName)

	if phase != v1.PodSucceeded {
		logs, _ := f.GetLogs(npProbeNamespace, podName, "probe")
		require.Failf(t, "probe pod failed", "pod %s: %s", podName, logs)
	}
}
