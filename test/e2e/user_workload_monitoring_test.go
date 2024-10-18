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
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Jeffail/gabs"
	"github.com/stretchr/testify/require"

	configv1 "github.com/openshift/api/config/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/cert"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
)

type scenario struct {
	name      string
	assertion func(*testing.T)
}

func TestUserWorkloadMonitoringInvalidConfig(t *testing.T) {
	// Deploy an invalid UWM config
	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      framework.UserWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": `invalid config`,
		},
	}
	err := f.OperatorClient.CreateOrUpdateConfigMap(ctx, uwmCM)
	// The CMO validate webhook shouldn't allow that.
	require.True(t, apierrors.IsForbidden(err))

	// If the change isn't caught by the validate webhook (here we explicitly skip it),
	// CMO status will still reflect the failure.
	uwmCM.Labels["monitoringconfigmaps.openshift.io/skip-validate-webhook"] = "true"
	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	// Enable UWM
	cm := getUserWorkloadEnabledConfigMap(t, f)
	f.MustCreateOrUpdateConfigMap(t, cm)
	defer f.MustDeleteConfigMap(t, cm)

	f.AssertOperatorCondition(configv1.OperatorDegraded, configv1.ConditionTrue)(t)
	f.AssertOperatorCondition(configv1.OperatorAvailable, configv1.ConditionFalse)(t)
	f.AssertOperatorConditionReason(configv1.OperatorDegraded, "UserWorkloadInvalidConfiguration")
	f.AssertOperatorConditionReason(configv1.OperatorAvailable, "UserWorkloadInvalidConfiguration")
}

func TestUserWorkloadMonitoringMetrics(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	uwmCM := f.BuildUserWorkloadConfigMap(t,
		`prometheus:
  enforcedTargetLimit: 10
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 2Gi
`,
	)
	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
	if err := deployUserApplication(f); err != nil {
		t.Fatal(err)
	}

	for _, scenario := range []struct {
		name string
		f    func(*testing.T)
	}{
		{
			name: "assert metrics for user workload components",
			f:    assertMetricsForMonitoringComponents,
		},
		{
			name: "assert user workload metrics",
			f:    assertUserWorkloadMetrics,
		},
		{
			name: "assert tenancy model is enforced for metrics",
			f:    assertTenancyForMetrics,
		},
		{
			name: "assert tenancy model is enforced for series metadata",
			f:    assertTenancyForSeriesMetadata,
		},
		{
			name: "assert prometheus is not deployed in user namespace",
			f:    f.AssertStatefulsetDoesNotExist("prometheus-not-to-be-reconciled", userWorkloadTestNs),
		},
		{
			name: "assert alertmanager is not deployed in user namespace",
			f:    f.AssertStatefulsetDoesNotExist("alertmanager-not-to-be-reconciled", userWorkloadTestNs),
		},

		{
			name: "assert UWM federate endpoint is exposed",
			f:    assertUWMFederateEndpoint,
		},
	} {
		t.Run(scenario.name, scenario.f)
	}
}

func TestUserWorkloadMonitoringAlerting(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	uwmCM := f.BuildUserWorkloadConfigMap(t,
		fmt.Sprintf(`prometheus:
  enforcedTargetLimit: 10
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 2Gi
namespacesWithoutLabelEnforcement:
- %s
`, notEnforcedNs),
	)
	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)

	if err := deployUserApplication(f); err != nil {
		t.Fatal(err)
	}

	if err := deployGlobalRules(f); err != nil {
		t.Fatalf("failed to deploy global rules: %s", err)
	}

	if err := createPrometheusAlertmanagerInUserNamespace(f); err != nil {
		t.Fatalf("failed to create Alertmanager object in user namespace: %s", err)
	}

	for _, scenario := range []struct {
		name string
		f    func(*testing.T)
	}{
		{
			name: "assert user workload rules",
			f:    assertUserWorkloadRules,
		},
		{
			name: "assert tenancy model is enforced for rules and alerts",
			f:    assertTenancyForRulesAndAlerts,
		},
		{
			name: "assert rules without namespace enforcement",
			f:    assertGlobalRulesWithoutNamespaceEnforcement,
		},
		{
			name: "assert prometheus is not deployed in user namespace",
			f:    f.AssertStatefulsetDoesNotExist("prometheus-not-to-be-reconciled", userWorkloadTestNs),
		},
		{
			name: "assert alertmanager is not deployed in user namespace",
			f:    f.AssertStatefulsetDoesNotExist("alertmanager-not-to-be-reconciled", userWorkloadTestNs),
		},
	} {
		t.Run(scenario.name, scenario.f)
	}

	// Disable cross-namespace rules via the CMO config.
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, `enableUserWorkload: true
userWorkload:
  rulesWithoutLabelEnforcementAllowed: false
`))
	t.Run("assert cross-namespace rules are not allowed from CMO config", assertGlobalRulesWithNamespaceEnforcement)
}

func TestUserWorkloadMonitoringOptOut(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	uwmCM := f.BuildUserWorkloadConfigMap(t,
		`prometheus:
  enforcedTargetLimit: 10
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 2Gi
`,
	)
	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
	if err := deployUserApplication(f); err != nil {
		t.Fatal(err)
	}

	for _, scenario := range []struct {
		name string
		f    func(*testing.T)
	}{
		{"assert namespace opt out removes appropriate targets", assertNamespaceOptOut},
		{"assert service monitor opt out removes appropriate targets", assertServiceMonitorOptOut},
	} {
		t.Run(scenario.name, scenario.f)
	}
}

func TestUserWorkloadMonitoringGrpcSecrets(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	uwmCM := f.BuildUserWorkloadConfigMap(t,
		`prometheus:
  enforcedTargetLimit: 10
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 2Gi
`,
	)
	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	for _, scenario := range []struct {
		name string
		f    func(*testing.T)
	}{
		{"assert grpc tls rotation", assertGRPCTLSRotation},
	} {
		t.Run(scenario.name, scenario.f)
	}
}

func TestUserWorkloadMonitoringWithAdditionalAlertmanagerConfigs(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	if err := createSelfSignedCertificateSecret("alertmanager-tls"); err != nil {
		t.Fatal(err)
	}

	uwmCM := f.BuildUserWorkloadConfigMap(t,
		`prometheus:
  additionalAlertmanagerConfigs:
  - scheme: https
    pathPrefix: /prefix
    timeout: "30s"
    apiVersion: v1
    tlsConfig:
      key:
        name: alertmanager-tls
        key: tls.key
      cert:
        name: alertmanager-tls
        key: tls.crt
      ca:
        name: alertmanager-tls
        key: tls.ca
    staticConfigs: ["127.0.0.1", "127.0.0.2"]
`,
	)
	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)

	scenarios := []scenario{
		{"assert 4 alertmanagers are discovered (2 built-in and 2 from the additional configs)", assertAlertmanagerInstancesDiscovered(4)},
		{"disable additional alertmanagers", disableAdditionalAlertmanagerConfigs},
		{"assert 2 alertmanagers are discovered", assertAlertmanagerInstancesDiscovered(2)},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, scenario.assertion)
	}
}

func createSelfSignedCertificateSecret(secretName string) error {
	crt, key, err := cert.GenerateSelfSignedCertKey("host", []net.IP{}, []string{})
	if err != nil {
		return err
	}

	tlsSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		StringData: map[string]string{
			"tls.key": string(key),
			"tls.crt": string(crt),
			"tls.ca":  string(crt),
		},
	}

	secretsClient := f.KubeClient.CoreV1().Secrets(f.UserWorkloadMonitoringNs)
	err = secretsClient.Delete(context.Background(), "alertmanager-tls", metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if _, err := secretsClient.Create(context.Background(), tlsSecret, metav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func assertThanosRulerDeployment(t *testing.T) {
	ctx := context.Background()
	err := framework.Poll(time.Second, 5*time.Minute, func() error {
		_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(ctx, "thanos-ruler-user-workload", metav1.GetOptions{})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = f.OperatorClient.WaitForThanosRuler(ctx, &monitoringv1.ThanosRuler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-workload",
			Namespace: f.UserWorkloadMonitoringNs,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = f.OperatorClient.WaitForStatefulsetRollout(ctx, &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "thanos-ruler-user-workload",
			Namespace: f.UserWorkloadMonitoringNs,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

}

func assertMetricsForMonitoringComponents(t *testing.T) {
	for service, expected := range map[string]int{
		"prometheus-operator":                     1,
		"prometheus-user-workload":                2,
		"thanos-ruler":                            2,
		"prometheus-user-workload-thanos-sidecar": 2,
	} {
		t.Run(service, func(t *testing.T) {
			f.ThanosQuerierClient.WaitForQueryReturn(
				t, time.Minute, fmt.Sprintf(`count(up{service="%s",namespace="openshift-user-workload-monitoring"} == 1)`, service),
				func(v float64) error {
					if v == float64(expected) {
						return nil
					}

					return fmt.Errorf("expected %d targets to be up but got %f", expected, v)
				},
			)
		})
	}
}

func assertAlertmanagerInstancesDiscovered(expectedInstances int) func(_ *testing.T) {
	return func(t *testing.T) {
		query := `max by (job) (prometheus_notifications_alertmanagers_discovered{job="prometheus-user-workload"})`
		f.ThanosQuerierClient.WaitForQueryReturn(
			t, 5*time.Minute, query,
			func(v float64) error {
				if v == float64(expectedInstances) {
					return nil
				}

				return fmt.Errorf("expected %d targets to be up but got %f", expectedInstances, v)
			},
		)
	}
}

func disableAdditionalAlertmanagerConfigs(t *testing.T) {
	ctx := context.Background()
	uwmCM := f.BuildUserWorkloadConfigMap(t, `prometheus: {}`)

	if err := f.OperatorClient.CreateOrUpdateConfigMap(ctx, uwmCM); err != nil {
		t.Fatal(err)
	}
}

func assertUserWorkloadMetrics(t *testing.T) {
	// assert that the previously deployed user application metrics are available in thanos
	f.ThanosQuerierClient.WaitForQueryReturn(
		t, 10*time.Minute, fmt.Sprintf(`version{namespace="%s"}`, userWorkloadTestNs),
		func(v float64) error {
			if v == 1 {
				return nil
			}

			return fmt.Errorf("expected version metric from user application to be equal 1 but got %v", v)
		},
	)

	{
		var body []byte

		// assert that the same metric is not scraped by the cluster monitoring stack
		err := wait.PollImmediate(time.Second, time.Minute, func() (done bool, err error) {
			body, err = f.PrometheusK8sClient.PrometheusQuery(fmt.Sprintf(`version{namespace="%s"}`, userWorkloadTestNs))
			if err != nil {
				t.Logf("PrometheusQuery failed: %v", err)
				return false, nil
			}

			return true, nil
		})
		if err != nil {
			t.Fatal(err)
		}

		res, err := gabs.ParseJSON(body)
		if err != nil {
			t.Fatal(err)
		}

		count, err := res.ArrayCountP("data.result")
		if err != nil {
			t.Fatal(err)
		}

		if count > 0 {
			t.Fatalf("expected no user workload metric to be present in the cluster monitoring stack, but got %d", count)
		}
	}

	// assert that the user workload monitoring Prometheus instance is successfully scraped
	// by the cluster monitoring Prometheus instance.
	err := framework.Poll(5*time.Second, 5*time.Minute, func() error {
		var (
			body []byte
			v    float64
		)
		body, loopErr := f.PrometheusK8sClient.PrometheusQuery(`count(up{job="prometheus-user-workload"})`)
		if loopErr != nil {
			return loopErr
		}

		v, loopErr = framework.GetFirstValueFromPromQuery(body)
		if loopErr != nil {
			return loopErr
		}

		if v != 2 {
			return fmt.Errorf("expected 2 Prometheus instances but got: %v", v)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = framework.Poll(5*time.Second, 5*time.Minute, func() error {
		body, err := f.AlertmanagerClient.GetAlertmanagerAlerts(
			"filter", `alertname="VersionAlert"`,
			"active", "true",
		)
		if err != nil {
			return fmt.Errorf("error getting alerts from Alertmanager: %w", err)
		}

		res, err := gabs.ParseJSON(body)
		if err != nil {
			return fmt.Errorf("error parsing Alertmanager response: %s: %w", string(body), err)
		}

		count, err := res.ArrayCount()
		if err != nil {
			return fmt.Errorf("error getting count of items: %w", err)
		}

		if count == 1 {
			return nil
		}

		return fmt.Errorf("expected 1 fired VersionAlert, got %d", count)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Assert that recording rule is in thanos querier and we get it
	// via thanos ruler replica.
	f.ThanosQuerierClient.WaitForQueryReturn(
		t, 10*time.Minute, `version:blah:count{thanos_ruler_replica="thanos-ruler-user-workload-0"}`,
		func(v float64) error {
			if v == 1 {
				return nil
			}
			return fmt.Errorf("expected count of recording rule from user application to be equal 1 but got %v", v)
		},
	)

	// Assert that recording rule is in thanos querier and we get it
	// via user workload prometheus.
	f.ThanosQuerierClient.WaitForQueryReturn(
		t, 10*time.Minute, `version:blah:leaf:count{prometheus_replica="prometheus-user-workload-0"}`,
		func(v float64) error {
			if v == 1 {
				return nil
			}
			return fmt.Errorf("expected count of recording rule from user application to be equal 1 but got %v", v)
		},
	)

	// Assert that recording rule is not present in thanos ruler.
	err = framework.Poll(5*time.Second, 5*time.Minute, func() error {
		var (
			body []byte
			v    int
		)
		body, err := f.ThanosQuerierClient.PrometheusQuery(`version:blah:leaf:count{thanos_ruler_replica="thanos-ruler-user-workload-0"}`)
		if err != nil {
			return err
		}

		v, err = framework.GetResultSizeFromPromQuery(body)
		if err != nil {
			return err
		}

		if v != 0 {
			return fmt.Errorf("expected result size 0 but got: %v", v)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertUserWorkloadRules(t *testing.T) {
	f.ThanosQuerierClient.WaitForRulesReturn(
		t, 10*time.Minute,
		func(body []byte) error {
			return getThanosRules(body, "example", "VersionAlert")
		},
	)
}

// assertTenancyForMetrics ensures that a tenant can access metrics from her namespace (and only from this one).
func assertTenancyForMetrics(t *testing.T) {
	const testAccount = "test-metrics"

	err := framework.Poll(2*time.Second, 10*time.Second, func() error {
		_, err := f.CreateServiceAccount(userWorkloadTestNs, testAccount)
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var token string
	err = framework.Poll(5*time.Second, 5*time.Minute, func() error {
		token, err = f.GetServiceAccountToken(userWorkloadTestNs, testAccount)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Check that the service account can request the tenancy-aware /api/v1/query API endpoint using HTTP GET.
	for _, tc := range []struct {
		name      string
		query     string
		expStatus int
	}{
		{
			name:      "expect to add namespace label",
			query:     "up",
			expStatus: http.StatusOK,
		},
		{
			name:      "expect no change and status 200",
			query:     fmt.Sprintf(`up{namespace="%s"}`, userWorkloadTestNs),
			expStatus: http.StatusOK,
		},
		{
			name:      "expect to return HTTP 400 as it would overwrite the label value (we pass --error-on-replace to prom-label-proxy)",
			query:     `up{namespace="should-be-overwritten"}`,
			expStatus: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Running query %q", tc.query)

			var cleanupFn func() error
			// Grant just-enough permissions to the account, so it can read metrics.
			err = framework.Poll(2*time.Second, 10*time.Second, func() error {
				cleanupFn, err = f.CreateRoleBindingFromTypedRole(userWorkloadTestNs, testAccount, &rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{
						Name: "tenancy-test-metrics",
					},
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{"metrics.k8s.io"},
							Resources: []string{"pods"},
							Verbs:     []string{"get"},
						},
					},
				})
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := cleanupFn(); err != nil {
					t.Fatal(err)
				}
			}()

			err = framework.Poll(5*time.Second, time.Minute, func() error {
				// The tenancy port (9092) is only exposed in-cluster, so we need to use
				// port forwarding to access kube-rbac-proxy.
				host, cleanUp, err := f.ForwardPort(t, f.Ns, "thanos-querier", 9092)
				if err != nil {
					t.Fatal(err)
				}
				defer cleanUp()

				client := framework.NewPrometheusClient(
					host,
					token,
					&framework.QueryParameterInjector{
						Name:  "namespace",
						Value: userWorkloadTestNs,
					},
				)

				b, err := client.PrometheusQueryWithStatus(tc.query, tc.expStatus)
				if err != nil {
					return err
				}

				if tc.expStatus != http.StatusOK {
					// short circuit if we don't expect HTTP 200, as we
					// don't need to parse the response
					return nil
				}

				res, err := gabs.ParseJSON(b)
				if err != nil {
					return err
				}

				timeseries, err := res.ArrayElementP(0, "data.result")
				if err != nil {
					return err
				}

				labels, err := timeseries.Path("metric").ChildrenMap()
				if err != nil {
					return err
				}

				ns := labels["namespace"].Data().(string)
				if ns != userWorkloadTestNs {
					return fmt.Errorf("expecting 'namespace' label to be %q, got %q", userWorkloadTestNs, ns)
				}

				value, err := timeseries.ArrayElementP(1, "value")
				if err != nil {
					return err
				}

				if value.Data().(string) != "1" {
					return fmt.Errorf("expecting value '1', got %q", value.Data().(string))
				}

				return nil
			})
			if err != nil {
				t.Errorf("failed to query Thanos querier: %v", err)
			}
		})
	}

	// Check that the account doesn't have to access the rules and alerts endpoints.
	for _, path := range []string{"/api/v1/rules", "/api/v1/alerts"} {
		err = framework.Poll(5*time.Second, time.Minute, func() error {
			// The tenancy port (9092) is only exposed in-cluster, so we need to use
			// port forwarding to access kube-rbac-proxy.
			host, cleanUp, err := f.ForwardPort(t, f.Ns, "thanos-querier", 9092)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanUp()

			client := framework.NewPrometheusClient(
				host,
				token,
				&framework.QueryParameterInjector{
					Name:  "namespace",
					Value: userWorkloadTestNs,
				},
			)

			resp, err := client.Do("GET", path, nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			if resp.StatusCode/100 == 2 {
				return fmt.Errorf("expected request to be rejected, but got status code %d (%s)", resp.StatusCode, framework.ClampMax(b))
			}

			return nil
		})
		if err != nil {
			t.Fatalf("the account has access to the %q endpoint of Thanos querier: %v", path, err)
		}
	}

	for _, tc := range []struct {
		role               rbacv1.Role
		expectNotOKOnQuery bool
		desc               string
		method             string
	}{

		{
			role: rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tenancy-test-metrics",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"metrics.k8s.io"},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
			},
			method:             http.MethodPost,
			expectNotOKOnQuery: true,
			desc:               "should disallow POST queries to the endpoint for SA with no create permission",
		},
		{
			role: rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tenancy-test-metrics",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"metrics.k8s.io"},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
			},
			method: http.MethodGet,
			desc:   "should allow GET queries to the endpoint for SA with get permission",
		},
		{
			role: rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tenancy-test-metrics",
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{"metrics.k8s.io"},
						Resources: []string{"pods"},
						Verbs:     []string{"get", "create"},
					},
				},
			},
			method: http.MethodPost,
			desc:   "should allow POST queries to the endpoint for SA with get and create permission",
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			var cleanupFn framework.CleanUpFunc

			// Create a role binding for the test SA.
			err = framework.Poll(time.Second, time.Minute, func() error {
				cleanupFn, err = f.CreateRoleBindingFromTypedRole(userWorkloadTestNs, testAccount, &tc.role)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}

			// Remove associated artifacts.
			defer func() {
				if err := cleanupFn(); err != nil {
					t.Fatal(err)
				}
			}()

			// Forward the tenancy port.
			host, cleanUp, err := f.ForwardPort(t, f.Ns, "thanos-querier", 9092)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanUp()

			// Create a Prometheus client with the test SA token.
			client := framework.NewPrometheusClient(
				host,
				token,
				&framework.QueryParameterInjector{
					Name:  "namespace",
					Value: userWorkloadTestNs,
				},
			)

			// It might take some time for kube-rbac-proxy to catch up the updated permission.
			err = framework.Poll(time.Second, time.Minute, func() error {
				resp, err := client.Do(tc.method, "/api/v1/query?namespace="+userWorkloadTestNs+"&query=up", nil)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				// Body: {"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up",...},"value":[1695582946.784,"1"]}]}}
				respBodyBytes, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}

				if tc.expectNotOKOnQuery {
					if resp.StatusCode == http.StatusOK {
						return fmt.Errorf("expected request to be rejected, but succeeded")
					}
				} else {
					if resp.StatusCode != http.StatusOK {
						return fmt.Errorf("expected request to be accepted, but got status code %d (%s)", resp.StatusCode, respBodyBytes)
					}
				}

				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// assertTenancyForRulesAndAlerts ensures that a tenant can access rules and alerts from her namespace (and only from this one).
func assertTenancyForRulesAndAlerts(t *testing.T) {
	const testAccount = "test-rules"

	_, err := f.CreateServiceAccount(userWorkloadTestNs, testAccount)
	if err != nil {
		t.Fatal(err)
	}

	// Grant enough permissions to the account, so it can read rules.
	_, err = f.CreateRoleBindingFromClusterRole(userWorkloadTestNs, testAccount, "monitoring-rules-view")
	if err != nil {
		t.Fatal(err)
	}

	var token string
	err = framework.Poll(5*time.Second, 5*time.Minute, func() error {
		token, err = f.GetServiceAccountToken(userWorkloadTestNs, testAccount)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The tenancy port (9093) is only exposed in-cluster, so we need to use
	// port forwarding to access kube-rbac-proxy.
	host, cleanUp, err := f.ForwardPort(t, f.Ns, "thanos-querier", 9093)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUp()

	client := framework.NewPrometheusClient(
		host,
		token,
		&framework.QueryParameterInjector{
			Name:  "namespace",
			Value: userWorkloadTestNs,
		},
	)

	err = framework.Poll(5*time.Second, time.Minute, func() error {
		resp, err := client.Do("GET", "/api/v1/rules", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code response, want %d, got %d (%s)", http.StatusOK, resp.StatusCode, framework.ClampMax(b))
		}

		res, err := gabs.ParseJSON(b)
		if err != nil {
			return err
		}

		groups, err := res.Path("data.groups").Children()
		if err != nil {
			return err
		}

		if len(groups) != 2 {
			return fmt.Errorf("expecting 2 rules group, got %d", len(groups))
		}

		type testData struct {
			ruleType  string
			name      string
			namespace string
		}

		expected := []testData{
			{
				ruleType:  "recording",
				name:      "version:blah:leaf:count",
				namespace: "user-workload-test",
			},
			{
				ruleType:  "alerting",
				name:      "VersionAlert",
				namespace: "user-workload-test",
			},
			{
				ruleType:  "recording",
				name:      "version:blah:count",
				namespace: "user-workload-test",
			},
		}

		var got []testData

		for _, group := range groups {
			rules, err := group.Path("rules").Children()
			if err != nil {
				return err
			}

			for _, rule := range rules {
				labels, err := rule.Path("labels").ChildrenMap()
				if err != nil {
					return err
				}

				got = append(got, testData{
					ruleType:  rule.Path("type").Data().(string),
					name:      rule.Path("name").Data().(string),
					namespace: labels["namespace"].Data().(string),
				})
			}
		}

		if !reflect.DeepEqual(expected, got) {
			return fmt.Errorf("expected rules %v, got %v", expected, got)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("failed to query rules from Thanos querier: %v", err)
	}

	err = framework.Poll(5*time.Second, time.Minute, func() error {
		resp, err := client.Do("GET", "/api/v1/alerts", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code response, want %d, got %d (%s)", http.StatusOK, resp.StatusCode, framework.ClampMax(b))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to query alerts from Thanos querier: %v", err)
	}

	// Check that the account doesn't have to access the query endpoints.
	for _, path := range []string{"/api/v1/range?query=up", "/api/v1/query_range?query=up&start=0&end=0&step=1s"} {
		err = framework.Poll(5*time.Second, time.Minute, func() error {
			resp, err := client.Do("GET", path, nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			if resp.StatusCode/100 == 2 {
				return fmt.Errorf("unexpected status code response, got %d (%s)", resp.StatusCode, framework.ClampMax(b))
			}

			return nil
		})
		if err != nil {
			t.Fatalf("the account has access to the %q endpoint of Thanos querier: %v", path, err)
		}
	}
}

// assertGlobalRulesWithoutNamespaceEnforcement ensures that cross-namespace
// rules generate metrics without namespace label.
func assertGlobalRulesWithoutNamespaceEnforcement(t *testing.T) {
	t.Helper()

	for _, q := range []string{
		`count(test:pods:count{namespace=""})`,
		`count(test:up:count{namespace=""})`,
	} {
		f.ThanosQuerierClient.WaitForQueryReturn(
			t,
			5*time.Minute,
			q,
			func(v float64) error {
				if v == 1.0 {
					return nil
				}

				return fmt.Errorf("query %q: expected 1.0, got %f", q, v)
			},
		)
	}
}

// assertGlobalRulesWithNamespaceEnforcement ensures that cross-namespace rules
// don't generate metrics without namespace label.
func assertGlobalRulesWithNamespaceEnforcement(t *testing.T) {
	t.Helper()

	for _, q := range []string{
		`absent(test:pods:count{namespace=""})`,
		`absent(test:up:count{namespace=""})`,
	} {
		f.ThanosQuerierClient.WaitForQueryReturn(
			t,
			5*time.Minute,
			q,
			func(v float64) error {
				if v == 1.0 {
					return nil
				}

				return fmt.Errorf("query %q: expected 1.0, got %f", q, v)
			},
		)
	}
}

func assertUWMFederateEndpoint(t *testing.T) {
	ctx := context.Background()
	const testAccount = "test-uwm-federate"

	err := framework.Poll(2*time.Second, 10*time.Second, func() error {
		_, err := f.CreateServiceAccount(userWorkloadTestNs, testAccount)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Grant enough permissions to invoke /federate endpoint which is protected by kube-rbac-proxy.
	err = framework.Poll(2*time.Second, 10*time.Second, func() error {
		_, err = f.CreateClusterRoleBinding(userWorkloadTestNs, testAccount, "admin")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	var token string
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		token, err = f.GetServiceAccountToken(userWorkloadTestNs, testAccount)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// check /federate endpoint
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		federate := func(host string) error {
			client := framework.NewPrometheusClient(
				host,
				token,
				&framework.QueryParameterInjector{
					Name:  "match[]",
					Value: `up`,
				},
			)

			resp, err := client.Do("GET", "/federate", nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected status code response, want %d, got %d (%s)", http.StatusOK, resp.StatusCode, framework.ClampMax(b))
			}

			if !strings.Contains(string(b), "up") {
				return fmt.Errorf("'up' metric is missing, got (%s)", framework.ClampMax(b))
			}

			return nil
		}
		// The federate port (9092) is only exposed in-cluster, so we need to use
		// port forwarding to access kube-rbac-proxy.
		host, cleanUp, err := f.ForwardPort(t, f.UserWorkloadMonitoringNs, "prometheus-user-workload", 9092)
		if err != nil {
			return err
		}
		defer cleanUp()

		err = federate(host)
		if err != nil {
			return err
		}

		r, err := f.OpenShiftRouteClient.Routes(f.UserWorkloadMonitoringNs).Get(ctx, "federate", metav1.GetOptions{})
		if err != nil {
			return err
		}
		route, err := f.OperatorClient.GetRouteURL(ctx, r)
		if err != nil {
			return err
		}
		// Test the same through OpenShift Route.
		federateHost := fmt.Sprintf("%s:%s", route.Hostname(), route.Port())
		err = federate(federateHost)
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}
}

func assertTenancyForSeriesMetadata(t *testing.T) {
	const testAccount = "test-labels"

	err := framework.Poll(2*time.Second, 10*time.Second, func() error {
		_, err := f.CreateServiceAccount(userWorkloadTestNs, testAccount)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Grant enough permissions to read labels.
	err = framework.Poll(2*time.Second, 10*time.Second, func() error {
		_, err = f.CreateRoleBindingFromClusterRole(userWorkloadTestNs, testAccount, "admin")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	var token string
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		token, err = f.GetServiceAccountToken(userWorkloadTestNs, testAccount)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// check /api/v1/labels endpoint
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		// The tenancy port (9092) is only exposed in-cluster, so we need to use
		// port forwarding to access kube-rbac-proxy.
		host, cleanUp, err := f.ForwardPort(t, f.Ns, "thanos-querier", 9092)
		if err != nil {
			return err
		}
		defer cleanUp()

		client := framework.NewPrometheusClient(
			host,
			token,
			&framework.QueryParameterInjector{
				Name:  "namespace",
				Value: userWorkloadTestNs,
			},
		)

		resp, err := client.Do("GET", "/api/v1/labels", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code response, want %d, got %d (%s)", http.StatusOK, resp.StatusCode, framework.ClampMax(b))
		}

		res, err := gabs.ParseJSON(b)
		if err != nil {
			return err
		}

		labels, err := res.Path("data").Children()
		if err != nil {
			return err
		}

		if len(labels) == 0 {
			return fmt.Errorf("expecting a label list with at least one item, got zero")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("failed to query labels from Thanos querier: %v", err)
	}

	// Check the /api/v1/series endpoint.
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		// The tenancy port (9092) is only exposed in-cluster, so we need to use
		// port forwarding to access kube-rbac-proxy.
		host, cleanUp, err := f.ForwardPort(t, f.Ns, "thanos-querier", 9092)
		if err != nil {
			return err
		}
		defer cleanUp()

		client := framework.NewPrometheusClient(
			host,
			token,
			&framework.QueryParameterInjector{
				Name:  "namespace",
				Value: userWorkloadTestNs,
			},
		)

		resp, err := client.Do("GET", "/api/v1/series?match[]=up", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code response, want %d, got %d (%s)", http.StatusOK, resp.StatusCode, framework.ClampMax(b))
		}

		res, err := gabs.ParseJSON(b)
		if err != nil {
			return err
		}

		series, err := res.Path("data").Children()
		if err != nil {
			return err
		}

		if len(series) != 1 {
			return fmt.Errorf("expecting a series list with one item, got %d (%s)", len(series), framework.ClampMax(b))
		}

		return nil
	})
	if err != nil {
		t.Fatalf("failed to query series from Thanos querier: %v", err)
	}

	// Check that /api/v1/label/{namespace}/values returns a single value.
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		// The tenancy port (9092) is only exposed in-cluster, so we need to use
		// port forwarding to access kube-rbac-proxy.
		host, cleanUp, err := f.ForwardPort(t, f.Ns, "thanos-querier", 9092)
		if err != nil {
			return err
		}
		defer cleanUp()

		client := framework.NewPrometheusClient(
			host,
			token,
			&framework.QueryParameterInjector{
				Name:  "namespace",
				Value: userWorkloadTestNs,
			},
		)

		b, err := client.PrometheusLabel("namespace")
		if err != nil {
			return err
		}

		res, err := gabs.ParseJSON(b)
		if err != nil {
			return err
		}

		values, err := res.Path("data").Children()
		if err != nil {
			return err
		}

		if len(values) != 1 {
			return fmt.Errorf("expecting only 1 value for the 'namespace' label but got %d", len(values))
		}

		if values[0].Data().(string) != userWorkloadTestNs {
			return fmt.Errorf("expecting 'namespace' label value to be %q but got %q .", userWorkloadTestNs, values[0].Data().(string))
		}

		return nil
	})
	if err != nil {
		t.Fatalf("failed to query namespace label from Thanos querier: %v", err)
	}
}

func assertGRPCTLSRotation(t *testing.T) {
	ctx := context.Background()
	countGRPCSecrets := func(ns string) int {
		t.Helper()
		var result int
		err := framework.Poll(5*time.Second, time.Minute, func() error {
			s, err := f.KubeClient.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{LabelSelector: "monitoring.openshift.io/hash"})
			if err != nil {
				return err
			}

			for _, s := range s.Items {
				if strings.Contains(s.Name, "grpc-tls") {
					result++
				}
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	s, err := f.OperatorClient.WaitForSecret(ctx, &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-tls",
			Namespace: f.Ns,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
	})
	if err != nil {
		t.Fatalf("error waiting for grpc-tls secret: %v", err)
	}

	if s.Annotations == nil {
		s.Annotations = make(map[string]string)
	}

	s.Annotations["monitoring.openshift.io/grpc-tls-forced-rotate"] = "true"

	if err := f.OperatorClient.CreateOrUpdateSecret(ctx, s); err != nil {
		t.Fatalf("error saving grpc-tls secret: %v", err)
	}

	// We know the amount of expected secrets in forehand.
	// We should not calculate it on-the-fly as the calculation could be racy.
	//
	// 1. openshift-monitoring/prometheus-k8s-grpc-tls-[hash]
	// 2. openshift-user-workload-monitoring/prometheus-user-workload-grpc-tls-[hash]
	// 3. openshift-monitoring/thanos-querier-grpc-tls-[hash]
	// 4. openshift-user-workload-monitoring/thanos-ruler-grpc-tls-[hash]
	//
	// The central grpc-tls secret is verified independently by getting it directly
	// and verifying if the force-rotation annotation has been removed.
	const expectedGRPCSecretCount = 4

	err = framework.Poll(time.Second, 5*time.Minute, func() error {
		s, err := f.KubeClient.CoreV1().Secrets(f.Ns).Get(ctx, "grpc-tls", metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("error loading grpc-tls secret: %w", err)
		}

		if _, ok := s.Annotations["monitoring.openshift.io/grpc-tls-forced-rotate"]; ok {
			return errors.New("rotation did not execute: grpc-tls-forced-rotate annotation set")
		}

		got := countGRPCSecrets(f.Ns) + countGRPCSecrets(f.UserWorkloadMonitoringNs)
		if expectedGRPCSecretCount != got {
			return fmt.Errorf("expecting %d gRPC secrets, got %d", expectedGRPCSecretCount, got)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertNamespaceOptOut(t *testing.T) {
	ctx := context.Background()

	serviceMonitorJobName := fmt.Sprintf("serviceMonitor/%s/%s/0", userWorkloadTestNs, serviceMonitorTestName)

	// Ensure the target for the example ServiceMonitor exists.
	f.ThanosQuerierClient.WaitForTargetsReturn(t, 5*time.Minute, func(body []byte) error {
		return getActiveTarget(body, serviceMonitorJobName)
	})

	// Add opt-out label to namespace.
	ns, err := f.KubeClient.CoreV1().Namespaces().Get(ctx, userWorkloadTestNs, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to fetch user-workload namespace: %v", err)
	}

	labels := ns.GetLabels()
	labels["openshift.io/user-monitoring"] = "false"
	ns.SetLabels(labels)

	_, err = f.KubeClient.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to apply user-monitoring opt-out label: %v", err)
	}

	// Ensure the target for the example ServiceMonitor is removed.
	f.ThanosQuerierClient.WaitForTargetsReturn(t, 5*time.Minute, func(body []byte) error {
		if err := getActiveTarget(body, serviceMonitorJobName); err == nil {
			return fmt.Errorf("target '%s' exists, but should not", serviceMonitorJobName)
		}

		return nil
	})

	// Remove opt-out label from namespace.
	ns, err = f.KubeClient.CoreV1().Namespaces().Get(ctx, userWorkloadTestNs, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to fetch user-workload namespace: %v", err)
	}

	labels = ns.GetLabels()
	delete(labels, "openshift.io/user-monitoring")
	ns.SetLabels(labels)

	_, err = f.KubeClient.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to remove user-monitoring opt-out label: %v", err)
	}

	// Ensure the target for the example ServiceMonitor is recreated.
	f.ThanosQuerierClient.WaitForTargetsReturn(t, 5*time.Minute, func(body []byte) error {
		return getActiveTarget(body, serviceMonitorJobName)
	})
}

func assertServiceMonitorOptOut(t *testing.T) {
	ctx := context.Background()

	serviceMonitorJobName := fmt.Sprintf("serviceMonitor/%s/%s/0", userWorkloadTestNs, serviceMonitorTestName)

	// Ensure the target for the example ServiceMonitor exists.
	f.ThanosQuerierClient.WaitForTargetsReturn(t, 5*time.Minute, func(body []byte) error {
		return getActiveTarget(body, serviceMonitorJobName)
	})

	// Add opt-out label to service monitor.
	sm, err := f.MonitoringClient.ServiceMonitors(userWorkloadTestNs).Get(ctx, serviceMonitorTestName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to fetch user-workload service monitor: %v", err)
	}

	labels := sm.GetLabels()
	labels["openshift.io/user-monitoring"] = "false"
	sm.SetLabels(labels)

	_, err = f.MonitoringClient.ServiceMonitors(userWorkloadTestNs).Update(ctx, sm, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to apply user-monitoring opt-out label: %v", err)
	}

	// Ensure the target for the example ServiceMonitor is removed.
	f.ThanosQuerierClient.WaitForTargetsReturn(t, 5*time.Minute, func(body []byte) error {
		if err := getActiveTarget(body, serviceMonitorJobName); err == nil {
			return fmt.Errorf("target '%s' exists, but should not", serviceMonitorJobName)
		}

		return nil
	})

	// Remove opt-out label from namespace.
	sm, err = f.MonitoringClient.ServiceMonitors(userWorkloadTestNs).Get(ctx, serviceMonitorTestName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to fetch user-workload service monitor: %v", err)
	}

	labels = sm.GetLabels()
	delete(labels, "openshift.io/user-monitoring")
	sm.SetLabels(labels)

	_, err = f.MonitoringClient.ServiceMonitors(userWorkloadTestNs).Update(ctx, sm, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("Failed to remove user-monitoring opt-out label: %v", err)
	}

	// Ensure the target for the example ServiceMonitor is recreated.
	f.ThanosQuerierClient.WaitForTargetsReturn(t, 5*time.Minute, func(body []byte) error {
		return getActiveTarget(body, serviceMonitorJobName)
	})
}
