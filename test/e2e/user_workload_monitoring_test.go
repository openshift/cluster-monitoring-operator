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
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Jeffail/gabs"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/cert"
)

type scenario struct {
	name      string
	assertion func(*testing.T)
}

func TestUserWorkloadMonitoringMetrics(t *testing.T) {
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
			"config.yaml": `prometheus:
  enforcedTargetLimit: 10
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 2Gi
`,
		},
	}

	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
	setupUserApplication(t, f)

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
			name: "assert tenancy model is enforced for labels",
			f:    assertTenancyForLabels,
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
}

func TestUserWorkloadMonitoringAlerting(t *testing.T) {
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
			"config.yaml": `prometheus:
  enforcedTargetLimit: 10
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 2Gi
`,
		},
	}

	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
	setupUserApplication(t, f)

	for _, scenario := range []struct {
		name string
		f    func(*testing.T)
	}{
		{
			name: "assert user workload rules",
			f:    assertUserWorkloadRules,
		},
		{
			name: "assert tenancy model is enforced for rules",
			f:    assertTenancyForRules,
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
}

func TestUserWorkloadMonitoringOptOut(t *testing.T) {
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
			"config.yaml": `prometheus:
  enforcedTargetLimit: 10
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 2Gi
`,
		},
	}

	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
	setupUserApplication(t, f)

	for _, scenario := range []struct {
		name string
		f    func(*testing.T)
	}{
		{"assert namespace opt out removes appropriate targets", assertNamespaceOptOut},
	} {
		t.Run(scenario.name, scenario.f)
	}
}

func TestUserWorkloadMonitoringGrpcSecrets(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
		},
		Data: map[string]string{
			"config.yaml": `prometheus:
  enforcedTargetLimit: 10
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 2Gi
`,
		},
	}

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

	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": `prometheus:
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
		},
	}
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
				t, 10*time.Minute, fmt.Sprintf(`count(up{service="%s",namespace="openshift-user-workload-monitoring"} == 1)`, service),
				func(i int) error {
					if i == expected {
						return nil
					}

					return fmt.Errorf("expected %d targets to be up but got %d", expected, i)
				},
			)
		})
	}
}

func assertAlertmanagerInstancesDiscovered(expectedInstances int) func(_ *testing.T) {
	return func(t *testing.T) {
		query := `max by (job) (prometheus_notifications_alertmanagers_discovered{job="prometheus-user-workload"})`
		f.ThanosQuerierClient.WaitForQueryReturn(
			t, 15*time.Minute, query,
			func(i int) error {
				if i == expectedInstances {
					return nil
				}

				return fmt.Errorf("expected %d targets to be up but got %d", expectedInstances, i)
			},
		)
	}
}

func disableAdditionalAlertmanagerConfigs(t *testing.T) {
	ctx := context.Background()
	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": `prometheus: {}`,
		},
	}

	if err := f.OperatorClient.CreateOrUpdateConfigMap(ctx, uwmCM); err != nil {
		t.Fatal(err)
	}
}

func assertUserWorkloadMetrics(t *testing.T) {
	// assert that the previously deployed user application metrics are available in thanos
	f.ThanosQuerierClient.WaitForQueryReturn(
		t, 10*time.Minute, fmt.Sprintf(`version{namespace="%s"}`, userWorkloadTestNs),
		func(i int) error {
			if i == 1 {
				return nil
			}

			return fmt.Errorf("expected version metric from user application to be equal 1 but got %v", i)
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
			v    int
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
			return errors.Wrap(err, "error getting alerts from Alertmanager")
		}

		res, err := gabs.ParseJSON(body)
		if err != nil {
			return errors.Wrapf(err, "error parsing Alertmanager response: %s", string(body))
		}

		count, err := res.ArrayCount()
		if err != nil {
			return errors.Wrap(err, "error getting count of items")
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
		func(i int) error {
			if i == 1 {
				return nil
			}
			return fmt.Errorf("expected count of recording rule from user application to be equal 1 but got %v", i)
		},
	)

	// Assert that recording rule is in thanos querier and we get it
	// via user workload prometheus.
	f.ThanosQuerierClient.WaitForQueryReturn(
		t, 10*time.Minute, `version:blah:leaf:count{prometheus_replica="prometheus-user-workload-0"}`,
		func(i int) error {
			if i == 1 {
				return nil
			}
			return fmt.Errorf("expected count of recording rule from user application to be equal 1 but got %v", i)
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
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Grant enough permissions to the account so it can read metrics.
	err = framework.Poll(2*time.Second, 10*time.Second, func() error {
		_, err = f.CreateRoleBindingFromClusterRole(userWorkloadTestNs, testAccount, "admin")
		return err
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

			err = framework.Poll(5*time.Second, time.Minute, func() error {
				// The tenancy port (9092) is only exposed in-cluster so we need to use
				// port forwarding to access kube-rbac-proxy.
				host, cleanUp, err := f.ForwardPort(t, "thanos-querier", 9092)
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
					return errors.Errorf("expecting 'namespace' label to be %q, got %q", userWorkloadTestNs, ns)
				}

				value, err := timeseries.ArrayElementP(1, "value")
				if err != nil {
					return err
				}

				if value.Data().(string) != "1" {
					return errors.Errorf("expecting value '1', got %q", value.Data().(string))
				}

				return nil
			})
			if err != nil {
				t.Errorf("failed to query Thanos querier: %v", err)
			}
		})
	}

	// Check that the account doesn't have to access the rules endpoint.
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		// The tenancy port (9092) is only exposed in-cluster so we need to use
		// port forwarding to access kube-rbac-proxy.
		host, cleanUp, err := f.ForwardPort(t, "thanos-querier", 9092)
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

		resp, err := client.Do("GET", "/api/v1/rules", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode/100 == 2 {
			return fmt.Errorf("expected request to be rejected, but got status code %d (%s)", resp.StatusCode, framework.ClampMax(b))
		}

		return nil
	})
	if err != nil {
		t.Fatalf("the account has access to the rules endpoint of Thanos querier: %v", err)
	}
}

// assertTenancyForRules ensures that a tenant can access rules from her namespace (and only from this one).
func assertTenancyForRules(t *testing.T) {
	const testAccount = "test-rules"

	_, err := f.CreateServiceAccount(userWorkloadTestNs, testAccount)
	if err != nil {
		t.Fatal(err)
	}

	// Grant enough permissions to the account so it can read rules.
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

	// The tenancy port (9093) is only exposed in-cluster so we need to use
	// port forwarding to access kube-rbac-proxy.
	host, cleanUp, err := f.ForwardPort(t, "thanos-querier", 9093)
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

		b, err := ioutil.ReadAll(resp.Body)
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
			return errors.Errorf("expecting 2 rules group, got %d", len(groups))
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
			return errors.Errorf("expected rules %v, got %v", expected, got)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("failed to query rules from Thanos querier: %v", err)
	}

	// Check that the account doesn't have to access the query endpoints.
	for _, path := range []string{"/api/v1/range?query=up", "/api/v1/query_range?query=up&start=0&end=0&step=1s"} {
		err = framework.Poll(5*time.Second, time.Minute, func() error {
			resp, err := client.Do("GET", path, nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			b, err := ioutil.ReadAll(resp.Body)
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

func assertTenancyForLabels(t *testing.T) {
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
		// The tenancy port (9092) is only exposed in-cluster so we need to use
		// port forwarding to access kube-rbac-proxy.
		host, cleanUp, err := f.ForwardPort(t, "thanos-querier", 9092)
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

		b, err := ioutil.ReadAll(resp.Body)
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
			return errors.Errorf("expecting a label list with at least one item, got zero")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("failed to query labels from Thanos querier: %v", err)
	}

	// Check that /api/v1/label/namespace/values returns a single value.
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		// The tenancy port (9092) is only exposed in-cluster so we need to use
		// port forwarding to access kube-rbac-proxy.
		host, cleanUp, err := f.ForwardPort(t, "thanos-querier", 9092)
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
			return errors.Errorf("expecting only 1 value for the 'namespace' label but got %d", len(values))
		}

		if values[0].Data().(string) != userWorkloadTestNs {
			return errors.Errorf("expecting 'namespace' label value to be %q but got %q .", userWorkloadTestNs, values[0].Data().(string))
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
			return fmt.Errorf("error loading grpc-tls secret: %v", err)
		}

		if _, ok := s.Annotations["monitoring.openshift.io/grpc-tls-forced-rotate"]; ok {
			return errors.New("rotation did not execute: grpc-tls-forced-rotate annotation set")
		}

		got := countGRPCSecrets(f.Ns) + countGRPCSecrets(f.UserWorkloadMonitoringNs)
		if expectedGRPCSecretCount != got {
			return errors.Errorf("expecting %d gRPC secrets, got %d", expectedGRPCSecretCount, got)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertNamespaceOptOut(t *testing.T) {
	ctx := context.Background()

	serviceMonitorJobName := "serviceMonitor/user-workload-test/prometheus-example-monitor/0"

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
