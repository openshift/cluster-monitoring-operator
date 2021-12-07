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
	"net/http"
	"testing"
	"time"

	"github.com/Jeffail/gabs/v2"
	statusv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestAlertmanagerTrustedCA(t *testing.T) {
	var (
		factory = manifests.NewFactory("openshift-monitoring", "", nil, nil, nil, manifests.NewAssets(assetsPath), &manifests.APIServerConfig{})
		newCM   *v1.ConfigMap
		lastErr error
	)

	cm := f.MustGetConfigMap(t, "alertmanager-trusted-ca-bundle", f.Ns)
	newCM, err := factory.HashTrustedCA(cm, "alertmanager")
	if err != nil {
		t.Fatal(errors.Wrap(err, "no trusted CA bundle data available"))
	}

	// Wait for the new hashed trusted CA bundle ConfigMap to be created
	f.AssertConfigmapExists(newCM.Name, f.Ns)(t)

	// Get Alertmanager StatefulSet and make sure it has a volume mounted.
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		ss := f.MustGetStatefulSet(t, "alertmanager-main", f.Ns)

		if len(ss.Spec.Template.Spec.Containers[0].VolumeMounts) == 0 {
			return false, errors.New("Could not find any VolumeMounts, expected at least 1")
		}

		for _, mount := range ss.Spec.Template.Spec.Containers[0].VolumeMounts {
			if mount.Name == "alertmanager-trusted-ca-bundle" {
				return true, nil
			}
		}

		lastErr = fmt.Errorf("no volume %s mounted", newCM.Name)
		return false, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}
}

// The Alertmanager API should be protected by kube-rbac-proxy (and prom-label-proxy).
func TestAlertmanagerKubeRbacProxy(t *testing.T) {
	ctx := context.Background()
	const testNs = "test-kube-rbac-proxy"

	// The tenancy port (9092) is only exposed in-cluster so we need to use
	// port forwarding to access kube-rbac-proxy.
	host, cleanUp, err := f.ForwardPort(t, "alertmanager-main", 9092)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)

	t.Logf("creating namespace %q", testNs)
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
	}
	ns, err = f.KubeClient.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.KubeClient.CoreV1().Namespaces().Delete(ctx, testNs, metav1.DeleteOptions{}); err != nil {
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
		t.Logf("creating service account %q", sa)
		_, err = f.CreateServiceAccount(testNs, sa)
		if err != nil {
			t.Fatal(err)
		}

		if cr != "" {
			t.Logf("creating role binding %q -> %q", sa, cr)
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

	assertDo := func(expectedCode int, do func() (*http.Response, error)) []byte {
		t.Helper()

		resp, err := do()
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("fail to read response body: %v", err)
		}

		if resp.StatusCode != expectedCode {
			t.Fatalf("expecting %d status code, got %d (%q)", expectedCode, resp.StatusCode, framework.ClampMax(b))
		}

		return b
	}

	for _, sa := range []string{"viewer", "anonymous"} {
		t.Logf("creating silence as %q (denied)", sa)
		assertDo(
			http.StatusForbidden,
			func() (*http.Response, error) {
				return clients[sa].Do("POST", "/api/v2/silences", sil)
			},
		)
	}

	t.Log("creating silence as 'editor' (allowed)")
	b := assertDo(
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
		if err != nil || resp.Status != "200" {
			t.Logf("failed to delete silence HTTP: %q err: %v", resp.Status, err)
		}
	})

	// List silences and check that the 'namespace' label matcher has been overwritten.
	t.Log("listing silences as 'anonymous' (denied)")
	assertDo(
		http.StatusForbidden,
		func() (*http.Response, error) {
			return clients["anonymous"].Do("GET", "/api/v2/silences", nil)
		},
	)

	for _, sa := range []string{"viewer", "editor"} {
		t.Logf("listing silences as %q (allowed)", sa)
		b = assertDo(
			http.StatusOK,
			func() (*http.Response, error) {
				return clients[sa].Do("GET", "/api/v2/silences", nil)
			},
		)

		parsed, err = gabs.ParseJSON(b)
		if err != nil {
			t.Fatal(err)
		}

		count := 0
		for _, silence := range parsed.Children() {
			if val := silence.Path("status.state").String(); val != "expired" {
				count++
			}
		}

		if count != 1 {
			t.Fatalf("expecting 1 silence, got %d (%q)", count, string(b))
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
				t.Fatalf("couldn't get matcher's name from response %q", string(b))
			}
			value, ok := matcher.Path("value").Data().(string)
			if !ok {
				t.Fatalf("couldn't get matcher's value from response %q", string(b))
			}
			isRegex, ok := matcher.Path("isRegex").Data().(bool)
			if !ok {
				t.Fatalf("couldn't get matcher's isRegex from response %q", string(b))
			}
			if name == "namespace" && value == testNs && !isRegex {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("failed to find namespace=%q label matcher in silence (%q)", testNs, string(b))
		}
	}

	// Delete the silence.
	for _, sa := range []string{"viewer", "anonymous"} {
		t.Logf("deleting silence as %q (denied)", sa)
		assertDo(
			http.StatusForbidden,
			func() (*http.Response, error) {
				return clients[sa].Do("DELETE", fmt.Sprintf("/api/v2/silence/%s", silID), nil)
			},
		)
	}

	t.Log("deleting silence as 'editor' (allowed)")
	assertDo(
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
		{name: "assert proxy secret does not exist", assertion: f.AssertSecretDoesNotExist("alertmanager-main-proxy", f.Ns)},
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
		{name: "assert proxy secret exists", assertion: f.AssertSecretExists("alertmanager-main-proxy", f.Ns)},
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
