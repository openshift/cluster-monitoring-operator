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
	"errors"
	"fmt"
	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"io"
	"k8s.io/utils/ptr"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/Jeffail/gabs/v2"
	statusv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringv1beta1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1beta1"
	amapimodels "github.com/prometheus/alertmanager/api/v2/models"
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
			cm := f.BuildCMOConfigMap(t, tc.config)
			f.MustCreateOrUpdateConfigMap(t, cm)
			t.Cleanup(func() {
				f.MustDeleteConfigMap(t, cm)
			})

			uwmConfigMap := f.BuildUserWorkloadConfigMap(t, tc.userWorkloadConfig)
			f.MustCreateOrUpdateConfigMap(t, uwmConfigMap)
			t.Cleanup(func() {
				f.MustDeleteConfigMap(t, uwmConfigMap)
			})

			testAlertmanagerReady(t, tc.amName, tc.amNamespace)

			// The tenancy port (9092) is only exposed in-cluster, so we need to use
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

func testAlertmanagerReady(t *testing.T, name, ns string, validator ...validator) *monitoringv1.Alertmanager {
	t.Helper()

	var (
		am      *monitoringv1.Alertmanager
		lastErr error
	)

	if err := wait.Poll(time.Second, 10*time.Minute, func() (bool, error) {
		am, lastErr = f.MonitoringClient.Alertmanagers(ns).Get(ctx, name, metav1.GetOptions{})
		if lastErr != nil {
			lastErr = fmt.Errorf("%s/%s: %w", ns, name, lastErr)
			return false, nil
		}

		for _, v := range validator {
			if err := v.Validate(am); err != nil {
				lastErr = err
				return false, nil
			}
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
	ns, err := f.KubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
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

	do := func(user string, expectedCode int, do func() (*http.Response, error)) ([]byte, error) {
		var b []byte
		err := framework.Poll(5*time.Second, time.Minute, func() error {
			var err error
			resp, err := do()
			if err != nil {
				return fmt.Errorf("user[%s]: %s %s: request failed: %w", user, resp.Request.Method, resp.Request.URL.String(), err)
			}
			defer resp.Body.Close()

			b, err = io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("user[%s]: %s %s: fail to read response body: %w", user, resp.Request.Method, resp.Request.URL.String(), err)
			}

			if resp.StatusCode != expectedCode {
				return fmt.Errorf("user[%s]: %s %s: expecting %d status code, got %d (%q)", user, resp.Request.Method, resp.Request.URL.String(), expectedCode, resp.StatusCode, framework.ClampMax(b))
			}

			return nil
		})

		return b, err
	}

	for _, sa := range []string{"viewer", "anonymous"} {
		if _, err := do(
			sa,
			http.StatusForbidden,
			func() (*http.Response, error) {
				return clients[sa].Do("POST", "/api/v2/silences", sil)
			},
		); err != nil {
			t.Fatalf("user[%s]: %v", sa, err)
		}
	}

	b, err := do(
		"editor",
		http.StatusOK,
		func() (*http.Response, error) {
			return clients["editor"].Do("POST", "/api/v2/silences", sil)
		},
	)
	if err != nil {
		t.Fatalf("user[editor]: %v", err)
	}

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

	_, err = do(
		"anonymous",
		http.StatusForbidden,
		func() (*http.Response, error) {
			return clients["anonymous"].Do("GET", "/api/v2/silences", nil)
		},
	)
	if err != nil {
		t.Fatalf("user[anonymous]: %v", err)
	}

	// List silences and check that the 'namespace' label matcher has been overwritten.
	for _, sa := range []string{"viewer", "editor"} {
		b, err := do(
			sa,
			http.StatusOK,
			func() (*http.Response, error) {
				return clients[sa].Do("GET", "/api/v2/silences", nil)
			},
		)
		if err != nil {
			t.Fatalf("user[%s]: %v", sa, err)
		}

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
		_, err = do(
			sa,
			http.StatusForbidden,
			func() (*http.Response, error) {
				return clients[sa].Do("DELETE", fmt.Sprintf("/api/v2/silence/%s", silID), nil)
			},
		)
		if err != nil {
			t.Fatalf("user[%s]: %v", sa, err)
		}
	}

	// Delete the silence with permissions.
	_, err = do(
		"editor",
		http.StatusOK,
		func() (*http.Response, error) {
			return clients["editor"].Do("DELETE", fmt.Sprintf("/api/v2/silence/%s", silID), sil)
		},
	)
	if err != nil {
		t.Fatalf("user[editor]: %v", err)
	}
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

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("fail to read response body: %w", err)
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
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, data))

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
			return fmt.Errorf("error getting silences from Alertmanager: %w", err)
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

		return fmt.Errorf("expected 1 matching silence, got %d", count)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The Alertmanager API should be protected by authentication/authorization.
func TestAlertmanagerAPI(t *testing.T) {
	err := framework.Poll(5*time.Second, 5*time.Minute, func() error {
		body, err := f.AlertmanagerClient.GetAlertmanagerAlerts(
			"filter", `alertname="Watchdog"`,
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

		return fmt.Errorf("expected 1 firing Watchdog alert, got %d", count)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Check read and write access to the Alertmanager API.
	testAlertmanagerAPIAccess(t)
}

func testAlertmanagerAPIAccess(t *testing.T) {
	ctx := context.Background()
	const (
		monitoringNamespace = "openshift-monitoring"
		testNamespace       = "alertmanager-api-e2e-test"
	)
	namespaceObj := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
	}
	namespaceObj, err := f.KubeClient.CoreV1().Namespaces().Create(ctx, namespaceObj, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		foreground := metav1.DeletePropagationForeground
		if err = f.KubeClient.CoreV1().Namespaces().Delete(ctx, testNamespace, metav1.DeleteOptions{PropagationPolicy: &foreground}); err != nil {
			t.Logf("err deleting namespace %s: %v", testNamespace, err)
		}
	})

	// Check access to the Alertmanager API based on the reader and writer roles.
	const (
		sa = testNamespace + "-sa"
	)
	saCleanup, err := f.CreateServiceAccount(testNamespace, sa)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = saCleanup()
		if err != nil {
			t.Logf("failed to cleanup service account %s: %v", sa, err)
		}
	}()
	var client *framework.PrometheusClient
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		token, err := f.GetServiceAccountToken(testNamespace, sa)
		if err != nil {
			return err
		}
		client, err = framework.NewPrometheusClientFromRoute(
			ctx,
			f.OpenShiftRouteClient,
			monitoringNamespace,
			"alertmanager-main",
			token,
		)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	const (
		getURI    = "/api/v2/silences"
		postURI   = getURI
		deleteURI = "/api/v2/silence/" // /{silenceID}
	)
	postableSilence := amapimodels.PostableSilence{
		ID: "", // Empty ID to create a new silence.
		Silence: amapimodels.Silence{
			Matchers: []*amapimodels.Matcher{
				{
					Name:    ptr.To("t"),
					Value:   ptr.To("tt"),
					IsRegex: ptr.To(false),
				},
			},
			StartsAt:  ptr.To(strfmt.DateTime(time.Now().Add(time.Hour))),
			EndsAt:    ptr.To(strfmt.DateTime(time.Now().Add(time.Hour * 2))),
			CreatedBy: ptr.To("johndoe"),
			Comment:   ptr.To("lorem ipsum"),
		},
	}
	postPayload, err := json.Marshal(postableSilence)
	if err != nil {
		t.Fatal(err)
	}
	testcases := []struct {
		description       string
		allowedMethods    map[string][2]string
		disallowedMethods map[string][2]string
		role              string
	}{
		{
			description:       "read access to the Alertmanager API",
			allowedMethods:    map[string][2]string{http.MethodGet: {getURI}},
			disallowedMethods: map[string][2]string{http.MethodPost: {postURI, string(postPayload)}, http.MethodDelete: {deleteURI}},
			role:              "monitoring-alertmanager-view",
		},
		{
			description:       "write access to the Alertmanager API",
			allowedMethods:    map[string][2]string{http.MethodGet: {getURI}, http.MethodPost: {postURI, string(postPayload)}, http.MethodDelete: {deleteURI}},
			disallowedMethods: map[string][2]string{},
			role:              "monitoring-alertmanager-edit",
		},
	}
	for _, testcase := range testcases {
		rbCleanup, err := f.CreateRoleBindingFromRoleOtherNamespace(testNamespace, sa, testcase.role, monitoringNamespace)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			err = rbCleanup()
			if err != nil {
				t.Logf("failed to cleanup role binding %s: %v", sa, err)
			}
		})

		// Verify valid access to the Alertmanager API.
		if err := checkAlertmanagerAPIVerbs(t, client, testcase.description, testcase.allowedMethods, true); err != nil {
			t.Fatal(err)
		}

		// Verify invalid access to the Alertmanager API.
		if err := checkAlertmanagerAPIVerbs(t, client, testcase.description, testcase.disallowedMethods, false); err != nil {
			t.Fatal(err)
		}
	}
}

func checkAlertmanagerAPIVerbs(_ *testing.T, client *framework.PrometheusClient, desc string, methods map[string][2]string, allowed bool) error {
	var sid string
	return framework.Poll(5*time.Second, 5*time.Minute, func() error {
		for method, v := range methods {
			if method == http.MethodDelete {
				if !allowed {
					// Assign a random UUID to the silence ID when doing a DELETE if it's not allowed. This is because
					// DELETE will fail if the silence ID is not set, and POST will fail to get us one if we're not
					// allowed to do so.
					sid = uuid.New().String()
				}
				if sid == "" {
					return fmt.Errorf("no silence ID to delete")
				}
				v[0] += sid
			}
			r, err := client.Do(method, v[0], []byte(v[1]))
			if err != nil {
				return fmt.Errorf("failed to do %s: %v", method, err)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return fmt.Errorf("failed to read response body: %v", err)
			}
			if allowed && method == http.MethodPost {
				type silenceResponse struct {
					ID string `json:"silenceID"`
				}
				var silence silenceResponse
				if err := json.Unmarshal(body, &silence); err != nil {
					return fmt.Errorf("failed to unmarshal response body: %v", err)
				}
				sid = silence.ID
			}
			body = []byte(framework.ClampMax(body))
			_ = r.Body.Close()
			if allowed {
				if r.StatusCode != http.StatusOK {
					return fmt.Errorf("expected (%s) %s, got %d: %s", method, desc, r.StatusCode, body)
				}
			} else {
				if r.StatusCode == http.StatusOK {
					return fmt.Errorf("did not expect (%s) %s, got %d: %s", method, desc, r.StatusCode, body)
				}
			}
		}
		return nil
	})
}

// Users should be able to disable Alertmanager through the cluster-monitoring-config
func TestAlertmanagerDisabling(t *testing.T) {
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, "alertmanagerMain: { enabled: false }"))

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
		{name: "assert trusted-ca-bundle exists", assertion: f.AssertConfigmapExists("alertmanager-trusted-ca-bundle", f.Ns)},
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

			cm := f.BuildCMOConfigMap(t, tc.config)
			f.MustCreateOrUpdateConfigMap(t, cm)
			t.Cleanup(func() {
				f.MustDeleteConfigMap(t, cm)
			})

			uwmConfigMap := f.BuildUserWorkloadConfigMap(t, tc.userWorkloadConfig)
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

	if err := createNamespaceIfNotExist(f, userWorkloadTestNs); err != nil {
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

// TestAlertmanagerPlatformSecrets ensures secrets
// are mounted correctly in Platform AlertManager container
func TestAlertmanagerPlatformSecrets(t *testing.T) {
	amSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: f.Ns,
			Labels: map[string]string{
				"group":                    "amsecret-e2e",
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string][]byte{
			"username": []byte("admin"),
			"password": []byte("password"),
		},
	}

	if err := f.OperatorClient.CreateIfNotExistSecret(ctx, amSecret); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		f.OperatorClient.DeleteSecret(ctx, amSecret)
	})

	for _, tc := range []struct {
		name        string
		config      string
		amName      string
		amNamespace string
	}{
		{
			name: "platform-alertmanager-secrets",
			config: `alertmanagerMain:
  secrets:
  - test-secret`,
			amName:      "main",
			amNamespace: f.Ns,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			amGeneration := testAlertmanagerReady(t, tc.amName, tc.amNamespace).GetGeneration()

			cm := f.BuildCMOConfigMap(t, tc.config)
			f.MustCreateOrUpdateConfigMap(t, cm)
			t.Cleanup(func() {
				f.MustDeleteConfigMap(t, cm)
			})

			am := testAlertmanagerReady(t, tc.amName, tc.amNamespace, genChange(amGeneration))
			if !slices.Contains(am.Spec.Secrets, "test-secret") {
				t.Fatal("Alertmanager secret `test-secret` is not configured correctly")
			}

			amPods, err := f.KubeClient.CoreV1().Pods(f.Ns).List(ctx, metav1.ListOptions{
				LabelSelector: fmt.Sprintf("app.kubernetes.io/instance=%s", tc.amName),
				FieldSelector: "status.phase=Running",
			})
			if err != nil {
				t.Fatal(err)
			}

			amVolumeMounts := amPods.Items[0].Spec.Containers[0].VolumeMounts
			var secretsMountedCorrectly bool
			for _, vm := range amVolumeMounts {
				if vm.Name == "secret-test-secret" && vm.MountPath == "/etc/alertmanager/secrets/test-secret" {
					secretsMountedCorrectly = true
					break
				}
			}

			if !secretsMountedCorrectly {
				t.Fatalf("expected `test-secret` to be mounted correctly in alertmanager container")
			}
		})
	}
}

// TestAlertmanagerUWMSecrets ensures secrets
// are mounted correctly in UWM AlertManager container
func TestAlertmanagerUWMSecrets(t *testing.T) {
	amSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				"group":                    "amsecret-e2e",
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string][]byte{
			"username": []byte("admin"),
			"password": []byte("password"),
		},
	}

	if err := f.OperatorClient.CreateIfNotExistSecret(ctx, amSecret); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		f.OperatorClient.DeleteSecret(ctx, amSecret)
	})

	for _, tc := range []struct {
		name               string
		config             string
		userWorkloadConfig string
		amName             string
		amNamespace        string
	}{
		{
			name:   "user-workload-alertmanager-secrets",
			config: `enableUserWorkload: true`,
			userWorkloadConfig: `alertmanager:
  enabled: true
  secrets:
  - test-secret`,
			amName:      "user-workload",
			amNamespace: f.UserWorkloadMonitoringNs,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := getUserWorkloadEnabledConfigMap(t, f)
			f.MustCreateOrUpdateConfigMap(t, cm)
			t.Cleanup(func() {
				f.MustDeleteConfigMap(t, cm)
			})

			uwmConfigMap := f.BuildUserWorkloadConfigMap(t, tc.userWorkloadConfig)
			f.MustCreateOrUpdateConfigMap(t, uwmConfigMap)
			t.Cleanup(func() {
				f.MustDeleteConfigMap(t, uwmConfigMap)
			})

			am := testAlertmanagerReady(t, tc.amName, tc.amNamespace)
			if !slices.Contains(am.Spec.Secrets, "test-secret") {
				t.Fatal("Alertmanager secret `test-secret` is not configured correctly")
			}

			amPods, err := f.KubeClient.CoreV1().Pods(f.UserWorkloadMonitoringNs).List(ctx, metav1.ListOptions{
				LabelSelector: fmt.Sprintf("app.kubernetes.io/instance=%s", tc.amName),
				FieldSelector: "status.phase=Running",
			})
			if err != nil {
				t.Fatal(err)
			}

			amVolumeMounts := amPods.Items[0].Spec.Containers[0].VolumeMounts
			var secretMountedCorrectly bool
			for _, vm := range amVolumeMounts {
				if vm.Name == "secret-test-secret" && vm.MountPath == "/etc/alertmanager/secrets/test-secret" {
					secretMountedCorrectly = true
					break
				}
			}

			if !secretMountedCorrectly {
				t.Fatalf("expected `test-secret` to be mounted correctly in alertmanager container")
			}
		})
	}
}
