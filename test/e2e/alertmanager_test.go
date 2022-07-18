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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
	"time"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringv1beta1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1beta1"

	"github.com/Jeffail/gabs/v2"
	statusv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
)

// TestAlertmanagerTenancyAPI ensures that the Alertmanager API exposed on the
// tenancy port enforces the namespace value.
func TestAlertmanagerTenancyAPI(t *testing.T) {
	for _, tc := range []struct {
		name               string
		config             string
		userWorkloadConfig string
		amName             string
		amNamespace        string
	}{
		{
			name: "platform-alertmanager",
			config: `alertmanagerMain:
  enableUserAlertmanagerConfig: true
enableUserWorkload: true`,
			userWorkloadConfig: "",
			amName:             "main",
			amNamespace:        f.Ns,
		},
		{
			name:   "user-workload-alertmanager",
			config: `enableUserWorkload: true`,
			userWorkloadConfig: `alertmanager:
  enableUserAlertmanagerConfig: true
  enabled: true`,
			amName:      "user-workload",
			amNamespace: f.UserWorkloadMonitoringNs,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clusterMonitorConfigMapName,
					Namespace: f.Ns,
					Labels: map[string]string{
						framework.E2eTestLabelName: framework.E2eTestLabelValue,
					},
				},
				Data: map[string]string{
					"config.yaml": tc.config,
				},
			}
			f.MustCreateOrUpdateConfigMap(t, cm)
			t.Cleanup(func() {
				f.MustDeleteConfigMap(t, cm)
			})

			uwmConfigMap := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userWorkloadMonitorConfigMapName,
					Namespace: f.UserWorkloadMonitoringNs,
					Labels: map[string]string{
						framework.E2eTestLabelName: framework.E2eTestLabelValue,
					},
				},
				Data: map[string]string{
					"config.yaml": tc.userWorkloadConfig,
				},
			}
			f.MustCreateOrUpdateConfigMap(t, uwmConfigMap)
			t.Cleanup(func() {
				f.MustDeleteConfigMap(t, uwmConfigMap)
			})
			testAlertmanagerReady(t, tc.amName, tc.amNamespace)

			// The tenancy port (9092) is only exposed in-cluster so we need to use
			// port forwarding to access kube-rbac-proxy.
			host, cleanUp, err := f.ForwardPort(t, tc.amNamespace, fmt.Sprintf("alertmanager-%s", tc.amName), 9092)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(cleanUp)

			testAlertmanagerTenancyAPI(t, host)
		})
	}
}

func testAlertmanagerReady(t *testing.T, name, namespace string) *monitoringv1.Alertmanager {
	t.Helper()

	var (
		am      *monitoringv1.Alertmanager
		lastErr error
	)

	if err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		am, lastErr = f.MonitoringClient.Alertmanagers(namespace).Get(ctx, name, metav1.GetOptions{})
		if lastErr != nil {
			lastErr = fmt.Errorf("%s/%s: %w", namespace, name, lastErr)
			return false, nil
		}

		return true, nil
	}); err != nil {
		t.Fatalf("%v: %v", err, lastErr)
	}

	if err := f.OperatorClient.WaitForAlertmanager(ctx, am); err != nil {
		t.Fatal(err)
	}

	return am
}

func testAlertmanagerTenancyAPI(t *testing.T, host string) {
	t.Helper()

	ctx := context.Background()
	const testNs = "tenancy-api-e2e-test"

	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
	}
	_, err := f.KubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		foreground := metav1.DeletePropagationForeground
		if err := f.KubeClient.CoreV1().Namespaces().Delete(ctx, testNs, metav1.DeleteOptions{PropagationPolicy: &foreground}); err != nil {
			t.Logf("err deleting namespace %s: %v", testNs, err)
		}
	})

	// Creating service accounts with different role bindings.
	clients := make(map[string]*framework.PrometheusClient)
	for sa, cr := range map[string]string{
		"editor":    "monitoring-rules-edit",
		"viewer":    "monitoring-rules-view",
		"anonymous": "",
	} {
		_, err = f.CreateServiceAccount(testNs, sa)
		if err != nil {
			t.Fatal(err)
		}

		if cr != "" {
			_, err = f.CreateRoleBindingFromClusterRole(testNs, sa, cr)
			if err != nil {
				t.Fatal(err)
			}
		}

		err = framework.Poll(5*time.Second, 5*time.Minute, func() error {
			token, err := f.GetServiceAccountToken(testNs, sa)
			if err != nil {
				return err
			}
			clients[sa] = framework.NewPrometheusClient(
				host,
				token,
				&framework.QueryParameterInjector{
					Name:  "namespace",
					Value: testNs,
				},
			)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Create a silence.
	now := time.Now()
	sil := []byte(fmt.Sprintf(
		`{"matchers":[{"name":"namespace","value":"openshift-monitoring","isRegex":false},{"name":"alertname","value":"Drill","isRegex":false}],"startsAt":"%s","endsAt":"%s","createdBy":"somebody","comment":"some comment"}`,
		now.Format(time.RFC3339),
		now.Add(time.Hour).Format(time.RFC3339),
	))

	assertDo := func(user string, expectedCode int, do func() (*http.Response, error)) []byte {
		t.Helper()

		resp, err := do()
		if err != nil {
			t.Fatalf("user[%s]: request failed: %v", user, err)
		}
		defer resp.Body.Close()

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("user[%s]: fail to read response body: %v", user, err)
		}

		if resp.StatusCode != expectedCode {
			t.Fatalf("user[%s]: expecting %d status code, got %d (%q)", user, expectedCode, resp.StatusCode, framework.ClampMax(b))
		}

		return b
	}

	for _, sa := range []string{"viewer", "anonymous"} {
		assertDo(
			sa,
			http.StatusForbidden,
			func() (*http.Response, error) {
				return clients[sa].Do("POST", "/api/v2/silences", sil)
			},
		)
	}

	b := assertDo(
		"editor",
		http.StatusOK,
		func() (*http.Response, error) {
			return clients["editor"].Do("POST", "/api/v2/silences", sil)
		},
	)

	// Save silence ID for deletion.
	parsed, err := gabs.ParseJSON(b)
	if err != nil {
		t.Fatalf("%v (data: %q)", err, string(b))
	}
	silID, ok := parsed.Path("silenceID").Data().(string)
	if !ok {
		t.Fatalf("couldn't get silenceID from response %q", string(b))
	}
	t.Cleanup(func() {
		resp, err := clients["editor"].Do("DELETE", fmt.Sprintf("/api/v2/silence/%s", silID), sil)
		if err != nil || resp.StatusCode != 200 {
			t.Logf("failed to delete silence HTTP: %q err: %v", resp.Status, err)
		}
	})

	assertDo(
		"anonymous",
		http.StatusForbidden,
		func() (*http.Response, error) {
			return clients["anonymous"].Do("GET", "/api/v2/silences", nil)
		},
	)

	// List silences and check that the 'namespace' label matcher has been overwritten.
	for _, sa := range []string{"viewer", "editor"} {
		b = assertDo(
			sa,
			http.StatusOK,
			func() (*http.Response, error) {
				return clients[sa].Do("GET", "/api/v2/silences", nil)
			},
		)

		parsed, err = gabs.ParseJSON(b)
		if err != nil {
			t.Fatalf("user[%s]: %v", sa, err)
		}

		count := 0
		for _, silence := range parsed.Children() {
			if val := silence.Path("status.state").String(); val != "expired" {
				count++
			}
		}

		if count != 1 {
			t.Fatalf("user[%s]: expecting 1 silence, got %d (%q)", sa, count, string(b))
		}

		var matchers *gabs.Container
		// grab matcher of first not expired silence for testing
		for _, silence := range parsed.Children() {
			if val := silence.Path("status.state").String(); val != "expired" {
				matchers = silence.Path("matchers")
				break
			}
		}
		var found bool
		for _, matcher := range matchers.Children() {
			name, ok := matcher.Path("name").Data().(string)
			if !ok {
				t.Fatalf("user[%s]: couldn't get matcher's name from response %q", sa, string(b))
			}
			value, ok := matcher.Path("value").Data().(string)
			if !ok {
				t.Fatalf("user[%s]: couldn't get matcher's value from response %q", sa, string(b))
			}
			isRegex, ok := matcher.Path("isRegex").Data().(bool)
			if !ok {
				t.Fatalf("user[%s]: couldn't get matcher's isRegex from response %q", sa, string(b))
			}
			if name == "namespace" && value == testNs && !isRegex {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("user[%s]: failed to find namespace=%q label matcher in silence (%q)", sa, testNs, string(b))
		}
	}

	// Try to delete the silence without permissions.
	for _, sa := range []string{"viewer", "anonymous"} {
		assertDo(
			sa,
			http.StatusForbidden,
			func() (*http.Response, error) {
				return clients[sa].Do("DELETE", fmt.Sprintf("/api/v2/silence/%s", silID), nil)
			},
		)
	}

	// Delete the silence with permissions.
	assertDo(
		"editor",
		http.StatusOK,
		func() (*http.Response, error) {
			return clients["editor"].Do("DELETE", fmt.Sprintf("/api/v2/silence/%s", silID), sil)
		},
	)
}

// Even when no persistent storage is configured, silences (and notifications)
// shouldn't be lost when new Alertmanager pods are rolled out.
func TestAlertmanagerDataReplication(t *testing.T) {
	const (
		silenceLabelName  = "test"
		silenceLabelValue = "AlertmanagerReplication"
	)

	// Create a silence.
	now := time.Now()
	sil := []byte(fmt.Sprintf(
		`{"matchers":[{"name":"%s","value":"%s","isRegex":false}],"startsAt":"%s","endsAt":"%s","createdBy":"somebody","comment":"some comment"}`,
		silenceLabelName,
		silenceLabelValue,
		now.Format(time.RFC3339),
		now.Add(time.Hour).Format(time.RFC3339),
	))
	err := framework.Poll(5*time.Second, time.Minute, func() error {
		resp, err := f.AlertmanagerClient.Do("POST", "/api/v2/silences", sil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "fail to read response body")
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expecting 200 status code, got %d (%q)", resp.StatusCode, framework.ClampMax(b))
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Trigger a rollout of the Alertmanager pods by changing the log level.
	const (
		statefulSetName = "alertmanager-main"
		containerName   = "alertmanager"
	)

	data := fmt.Sprintf(`alertmanagerMain:
  logLevel: warn
`)
	f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, data))

	for _, test := range []scenario{
		{
			name:      "test the alertmanager-main statefulset is rolled out",
			assertion: f.AssertStatefulSetExistsAndRollout(statefulSetName, f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=alertmanager,app.kubernetes.io/instance=main",
				[]framework.PodAssertion{
					expectContainerArg("--log.level=warn", containerName),
				},
			),
		},
	} {
		t.Run(test.name, test.assertion)
	}

	// Ensure that the silence has been preserved.
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		body, err := f.AlertmanagerClient.GetAlertmanagerSilences(
			"filter", fmt.Sprintf(`%s="%s"`, silenceLabelName, silenceLabelValue),
		)
		if err != nil {
			return errors.Wrap(err, "error getting silences from Alertmanager")
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

		return fmt.Errorf("expected 1 matching silence, got %d", count)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The Alertmanager API should be protected by the OAuth proxy.
func TestAlertmanagerOAuthProxy(t *testing.T) {
	err := framework.Poll(5*time.Second, 5*time.Minute, func() error {
		body, err := f.AlertmanagerClient.GetAlertmanagerAlerts(
			"filter", `alertname="Watchdog"`,
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

		return fmt.Errorf("expected 1 firing Watchdog alert, got %d", count)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Users should be able to disable Alertmanager through the cluster-monitoring-config
func TestAlertmanagerDisabling(t *testing.T) {
	// Disable alertmanager
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterMonitorConfigMapName,
			Namespace: f.Ns,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": `alertmanagerMain: { enabled: false }`,
		},
	}
	f.MustCreateOrUpdateConfigMap(t, cm)

	assertions := []struct {
		name      string
		assertion framework.AssertionFunc
	}{
		{name: "assert alertmanager does not exist", assertion: f.AssertStatefulsetDoesNotExist("alertmanager-main", f.Ns)},
		{name: "assert route does not exist", assertion: f.AssertRouteDoesNotExist("alertmanager-main", f.Ns)},
		{name: "assert alertmanager main config does not exist", assertion: f.AssertSecretDoesNotExist("alertmanager-main", f.Ns)},
		{name: "assert kube-rbac-proxy secret does not exist", assertion: f.AssertSecretDoesNotExist("alertmanager-kube-rbac-proxy", f.Ns)},
		{name: "assert service alertmanager-main does not exist", assertion: f.AssertServiceDoesNotExist("alertmanager-main", f.Ns)},
		{name: "assert service alertmanager-operated does not exist", assertion: f.AssertServiceDoesNotExist("alertmanager-operated", f.Ns)},
		{name: "assert serviceaccount alertmanager-main does not exist", assertion: f.AssertServiceAccountDoesNotExist("alertmanager-main", f.Ns)},
		{name: "assert role monitoring-alertmanager-edit does not exist", assertion: f.AssertRoleDoesNotExist("monitoring-alertmanager-edit", "openshift-monitoring")},
		{name: "assert rolebinding alertmanager-prometheusk8s does not exist", assertion: f.AssertRoleBindingDoesNotExist("alertmanager-prometheusk8s", "openshift-monitoring")},
		{name: "assert rolebinding alertmanager-prometheususer-workload does not exist", assertion: f.AssertRoleBindingDoesNotExist("alertmanager-prometheususer-workload", "openshift-monitoring")},
		{name: "assert rolebinding alertmanager-thanos-ruler does not exist", assertion: f.AssertRoleBindingDoesNotExist("alertmanager-thanos-ruler", "openshift-monitoring")},
		{name: "assert clusterrole alertmanager-main does not exist", assertion: f.AssertClusterRoleDoesNotExist("alertmanager-main")},
		{name: "assert clusterrolebinding alertmanager-main does not exist", assertion: f.AssertClusterRoleBindingDoesNotExist("alertmanager-main")},
		{name: "assert trusted-ca-bundle does not exist", assertion: f.AssertConfigmapDoesNotExist("alertmanager-trusted-ca-bundle", f.Ns)},
		{name: "assert prometheus rule does not exist", assertion: f.AssertPrometheusRuleDoesNotExist("alertmanager-main-rules", f.Ns)},
		{name: "assert service monitor does not exist", assertion: f.AssertServiceMonitorDoesNotExist("alertmanager-main", f.Ns)},
		{name: "assert old service monitor does not exists", assertion: f.AssertServiceMonitorDoesNotExist("alertmanager", f.Ns)},
		{name: "alertmanager public URL is unset", assertion: f.AssertValueInConfigMapEquals(
			"monitoring-shared-config", "openshift-config-managed", "alertmanagerPublicURL", "")},
		{name: "assert operator not degraded", assertion: f.AssertOperatorCondition(statusv1.OperatorDegraded, statusv1.ConditionFalse)},
	}
	t.Run("disable alertmanager", func(t *testing.T) {
		for _, assertion := range assertions {
			t.Run(assertion.name, assertion.assertion)
		}
	})

	// Re-enable alertmanager with user workload monitoring
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	assertions = []struct {
		name      string
		assertion framework.AssertionFunc
	}{
		{name: "assert alertmanager exists", assertion: f.AssertStatefulsetExists("alertmanager-main", f.Ns)},
		{name: "assert route exists", assertion: f.AssertRouteExists("alertmanager-main", f.Ns)},
		{name: "assert alertmanager main config exists", assertion: f.AssertSecretExists("alertmanager-main", f.Ns)},
		{name: "assert kube-rbac-proxy secret exists", assertion: f.AssertSecretExists("alertmanager-kube-rbac-proxy", f.Ns)},
		{name: "assert service alertmanager-main exists", assertion: f.AssertServiceExists("alertmanager-main", f.Ns)},
		{name: "assert service alertmanager-operated exists", assertion: f.AssertServiceExists("alertmanager-operated", f.Ns)},
		{name: "assert serviceaccount alertmanager exists", assertion: f.AssertServiceAccountExists("alertmanager-main", f.Ns)},
		{name: "assert role monitoring-alertmanager-edit exists", assertion: f.AssertRoleExists("monitoring-alertmanager-edit", "openshift-monitoring")},
		{name: "assert rolebinding alertmanager-prometheusk8s exists", assertion: f.AssertRoleBindingExists("alertmanager-prometheusk8s", "openshift-monitoring")},
		{name: "assert rolebinding alertmanager-prometheususer-workload exists", assertion: f.AssertRoleBindingExists("alertmanager-prometheususer-workload", "openshift-monitoring")},
		{name: "assert rolebinding alertmanager-thanos-ruler exists", assertion: f.AssertRoleBindingExists("alertmanager-thanos-ruler", "openshift-monitoring")},
		{name: "assert clusterrole alertmanager-main exists", assertion: f.AssertClusterRoleExists("alertmanager-main")},
		{name: "assert clusterrolebinding alertmanager-main exists", assertion: f.AssertClusterRoleBindingExists("alertmanager-main")},
		{name: "assert trusted-ca-bundle does not exist", assertion: f.AssertConfigmapDoesNotExist("alertmanager-trusted-ca-bundle", f.Ns)},
		{name: "assert prometheus rule exists", assertion: f.AssertPrometheusRuleExists("alertmanager-main-rules", f.Ns)},
		{name: "assert service monitor exists", assertion: f.AssertServiceMonitorExists("alertmanager-main", f.Ns)},
		{name: "assert old service monitor does not exists", assertion: f.AssertServiceMonitorDoesNotExist("alertmanager", f.Ns)},
		{name: "alertmanager public URL properly set", assertion: f.AssertValueInConfigMapNotEquals(
			"monitoring-shared-config", "openshift-config-managed", "alertmanagerPublicURL", "")},
		{name: "assert operator not degraded", assertion: f.AssertOperatorCondition(statusv1.OperatorDegraded, statusv1.ConditionFalse)},
	}
	t.Run("enable alertmanager", func(t *testing.T) {
		for _, assertion := range assertions {
			t.Run(assertion.name, assertion.assertion)
		}
	})
}

func TestAlertManagerHasAdditionalAlertRelabelConfigs(t *testing.T) {
	const (
		expectPlatformLabel      = "openshift_io_alert_source"
		expectPlatformLabelValue = "platform"
	)

	type Alerts []struct {
		Labels map[string]string `json:"labels"`
	}

	var alerts Alerts

	err := framework.Poll(5*time.Second, time.Minute, func() error {
		resp, err := f.AlertmanagerClient.Do("GET", "/api/v2/alerts", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expecting 200 status code, got %d (%q)", resp.StatusCode, resp.Body)
		}

		if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
			return fmt.Errorf("error decoding alert response")
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, alert := range alerts {
		v, found := alert.Labels[expectPlatformLabel]
		if !found {
			t.Fatal("expected correct label to be present")
		}

		if v != expectPlatformLabelValue {
			t.Fatalf("expected correct value for %s but got %s", expectPlatformLabel, v)
		}
	}
}

// TestAlertmanagerConfigPipeline ensures that the AlertManagerConfig CR's
// created in a user namespace can be reconciled and have alerts sent to the
// correct Alertmanager (depending on whether user-defined Alertmanager is
// enabled or not).
func TestAlertmanagerConfigPipeline(t *testing.T) {
	for _, tc := range []struct {
		name               string
		config             string
		userWorkloadConfig string
		amName             string
		amNamespace        string
	}{
		{
			name: "platform-alertmanager",
			config: `alertmanagerMain:
  enableUserAlertmanagerConfig: true
enableUserWorkload: true`,
			userWorkloadConfig: "",
			amName:             "main",
			amNamespace:        f.Ns,
		},
		{
			name:   "user-workload-alertmanager",
			config: `enableUserWorkload: true`,
			userWorkloadConfig: `alertmanager:
  enableAlertmanagerConfig: true
  enabled: true`,
			amName:      "user-workload",
			amNamespace: f.UserWorkloadMonitoringNs,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wr, err := setupWebhookReceiver(t, f, fmt.Sprintf("%s-webhook-e2e", tc.name))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				wr.tearDown(t, f)
			})

			cm := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clusterMonitorConfigMapName,
					Namespace: f.Ns,
					Labels: map[string]string{
						framework.E2eTestLabelName: framework.E2eTestLabelValue,
					},
				},
				Data: map[string]string{
					"config.yaml": tc.config,
				},
			}
			f.MustCreateOrUpdateConfigMap(t, cm)
			t.Cleanup(func() {
				f.MustDeleteConfigMap(t, cm)
			})

			uwmConfigMap := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userWorkloadMonitorConfigMapName,
					Namespace: f.UserWorkloadMonitoringNs,
					Labels: map[string]string{
						framework.E2eTestLabelName: framework.E2eTestLabelValue,
					},
				},
				Data: map[string]string{
					"config.yaml": tc.userWorkloadConfig,
				},
			}
			f.MustCreateOrUpdateConfigMap(t, uwmConfigMap)
			t.Cleanup(func() {
				f.MustDeleteConfigMap(t, uwmConfigMap)
			})

			am := testAlertmanagerReady(t, tc.amName, tc.amNamespace)

			testAlertmanagerConfigPipeline(t, wr, am)
		})
	}
}

func testAlertmanagerConfigPipeline(t *testing.T, wr *webhookReceiver, am *monitoringv1.Alertmanager) {
	const (
		ruleName               = "always-firing-tests-alertmanagerconfig-crd-e2e"
		alertManagerConfigName = "always-firing-tests-alertmanagerconfig-crd-e2e"
	)

	t.Helper()

	t.Cleanup(func() {
		if err := f.OperatorClient.DeletePrometheusRuleByNamespaceAndName(ctx, userWorkloadTestNs, ruleName); err != nil {
			t.Logf("failed to cleanup rule %s - err %v", ruleName, err)
		}

		if err := f.DeleteAlertManagerConfigByNamespaceAndName(ctx, userWorkloadTestNs, alertManagerConfigName); err != nil {
			t.Logf("failed to cleanup alertmanager config %s - err %v", alertManagerConfigName, err)
		}
	})

	// assert we have the correct match expressions on the Alertmanager object.
	if err := framework.Poll(time.Second, 5*time.Minute, func() error {
		last, err := f.MonitoringClient.Alertmanagers(am.Namespace).Get(ctx, am.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("%s/%s: %w", am.Namespace, am.Name, err)
		}

		if last.Spec.AlertmanagerConfigNamespaceSelector == nil {
			return errors.New("expecting non-nil alertmanagerConfigNamespaceSelector")
		}

		if err := assertLabelSelectorRequirement(
			last.Spec.AlertmanagerConfigNamespaceSelector.MatchExpressions,
			metav1.LabelSelectorRequirement{
				Key:      "openshift.io/cluster-monitoring",
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{"true"},
			},
		); err != nil {
			return err
		}

		if err := assertLabelSelectorRequirement(
			last.Spec.AlertmanagerConfigNamespaceSelector.MatchExpressions,
			metav1.LabelSelectorRequirement{
				Key:      "openshift.io/user-monitoring",
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{"false"},
			},
		); err != nil {
			return err
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := createUWMTestNsIfNotExist(t, f); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if err := f.OperatorClient.CreateOrUpdatePrometheusRule(ctx, &monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ruleName,
			Namespace: userWorkloadTestNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: []monitoringv1.RuleGroup{
				{
					Name: "test-alertmanagerconfig-crd-e2e",
					Rules: []monitoringv1.Rule{
						{
							Alert: "always-firing",
							Expr:  intstr.FromString("vector(1)"),
						},
					},
				},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := f.CreateOrUpdateAlertmanagerConfig(ctx, &monitoringv1beta1.AlertmanagerConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      alertManagerConfigName,
			Namespace: userWorkloadTestNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Spec: monitoringv1beta1.AlertmanagerConfigSpec{
			Route: &monitoringv1beta1.Route{
				Receiver: "test-receiver",
				Matchers: []monitoringv1beta1.Matcher{},
				Continue: true,
			},
			Receivers: []monitoringv1beta1.Receiver{
				{
					Name: "test-receiver",
					WebhookConfigs: []monitoringv1beta1.WebhookConfig{
						{
							URL: &wr.webhookURL,
						},
					},
				},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := framework.Poll(time.Second*10, time.Minute*5, func() error {
		alerts, err := wr.getAlertsByID("always-firing_user-workload-test")
		if err != nil {
			return err
		}

		if len(alerts) != 1 {
			return fmt.Errorf("expected 1 alert but got %d", len(alerts))
		}

		if alerts[0].Status != "firing" {
			return fmt.Errorf("expected alert to be status firing")
		}

		name, ok := alerts[0].Labels["alertname"]
		if !ok || name != "always-firing" {
			return fmt.Errorf("expected alert named 'always-firing' to exist")
		}

		ns, ok := alerts[0].Labels["namespace"]
		if !ok || ns != userWorkloadTestNs {
			return fmt.Errorf("expected namespace label on 'always-firing' to exist")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertLabelSelectorRequirement(reqs []metav1.LabelSelectorRequirement, mustInclude metav1.LabelSelectorRequirement) error {
	for _, req := range reqs {
		if reflect.DeepEqual(req, mustInclude) {
			return nil
		}
	}

	return fmt.Errorf("required label selector %v not found in %v", mustInclude, reqs)
}
