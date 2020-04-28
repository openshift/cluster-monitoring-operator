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
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Jeffail/gabs"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestAlertmanagerVolumeClaim(t *testing.T) {
	err := f.OperatorClient.WaitForStatefulsetRollout(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alertmanager-main",
			Namespace: f.Ns,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-monitoring-config",
			Namespace: f.Ns,
		},
		Data: map[string]string{
			"config.yaml": `alertmanagerMain:
  volumeClaimTemplate:
    spec:
      storageClassName: gp2
      resources:
        requests:
          storage: 2Gi
`,
		},
	}

	if err := f.OperatorClient.CreateOrUpdateConfigMap(cm); err != nil {
		t.Fatal(err)
	}

	var lastErr error
	// Wait for persistent volume claim
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.CoreV1().PersistentVolumeClaims(f.Ns).Get("alertmanager-main-db-alertmanager-main-0", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting alertmanager persistent volume claim failed")
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}

	err = f.OperatorClient.WaitForStatefulsetRollout(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alertmanager-main",
			Namespace: f.Ns,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAlertmanagerTrustedCA(t *testing.T) {
	var (
		factory = manifests.NewFactory("openshift-monitoring", "", nil)
		newCM   *v1.ConfigMap
		lastErr error
	)

	// Wait for the new ConfigMap to be created
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		cm, err := f.KubeClient.CoreV1().ConfigMaps(f.Ns).Get("alertmanager-trusted-ca-bundle", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting new trusted CA ConfigMap failed")
		if err != nil {
			return false, nil
		}

		newCM, err = factory.HashTrustedCA(cm, "alertmanager")
		lastErr = errors.Wrap(err, "no trusted CA bundle data available")
		if err != nil {
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}

	// Wait for the new hashed trusted CA bundle ConfigMap to be created
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.CoreV1().ConfigMaps(f.Ns).Get(newCM.Name, metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting new CA ConfigMap failed")
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}

	// Get Alertmanager StatefulSet and make sure it has a volume mounted.
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		ss, err := f.KubeClient.AppsV1().StatefulSets(f.Ns).Get("alertmanager-main", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting Alertmanager StatefulSet failed")
		if err != nil {
			return false, nil
		}

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

type silenceClient struct {
	t         *testing.T
	host      string
	token     string
	namespace string
}

func (s silenceClient) do(method string, endpoint string, body []byte, expectedCode int) []byte {
	s.t.Helper()

	u := url.URL{
		Scheme:   "https",
		Host:     s.host,
		Path:     endpoint,
		RawQuery: url.Values{"namespace": []string{s.namespace}}.Encode(),
	}
	req, err := http.NewRequest(method, u.String(), bytes.NewBuffer(body))
	if err != nil {
		s.t.Fatal(err)
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", s.token))
	req.Header.Add("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		s.t.Fatalf("%s request to %q failed: %v", method, endpoint, err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatalf("fail to read response body from %s %q: %v", method, endpoint, err)
	}

	if resp.StatusCode != expectedCode {
		s.t.Fatalf("expecting %d status code in response to %s %q request, got %d (%q)", expectedCode, method, endpoint, resp.StatusCode, string(b))
	}

	return b
}

// The Alertmanager API should be protected by kube-rbac-proxy (and prom-label-proxy).
func TestAlertmanagerKubeRbacProxy(t *testing.T) {
	const testNs = "test-kube-rbac-proxy"

	// The tenancy port (9092) is only exposed in-cluster so we need to use
	// port forwarding to access kube-rbac-proxy.
	host, cleanUp, err := f.ForwardPort(t, "alertmanager-main", 9092)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUp()

	t.Logf("creating namespace %q", testNs)
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNs,
		},
	}
	ns, err = f.KubeClient.CoreV1().Namespaces().Create(ns)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := f.KubeClient.CoreV1().Namespaces().Delete(testNs, &metav1.DeleteOptions{})
		t.Logf("deleting namespace %s: %v", testNs, err)
	}()

	// Creating service accounts with different role bindings.
	clients := make(map[string]silenceClient)
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
			clients[sa] = silenceClient{
				t:         t,
				host:      host,
				token:     token,
				namespace: testNs,
			}
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

	for _, sa := range []string{"viewer", "anonymous"} {
		t.Logf("creating silence as %q (denied)", sa)
		_ = clients[sa].do("POST", "/api/v2/silences", sil, http.StatusForbidden)
	}

	t.Log("creating silence as 'editor' (allowed)")
	b := clients["editor"].do("POST", "/api/v2/silences", sil, http.StatusOK)

	// Save silence ID for deletion.
	parsed, err := gabs.ParseJSON(b)
	if err != nil {
		t.Fatalf("%v (data: %q)", err, string(b))
	}
	silID, ok := parsed.Path("silenceID").Data().(string)
	if !ok {
		t.Fatalf("couldn't get silenceID from response %q", string(b))
	}

	// List silences and check that the 'namespace' label matcher has been overwritten.
	t.Log("listing silences as 'anonymous' (denied)")
	clients["anonymous"].do("GET", "/api/v2/silences", nil, http.StatusForbidden)

	for _, sa := range []string{"viewer", "editor"} {
		t.Logf("listing silences as %q (allowed)", sa)
		b = clients[sa].do("GET", "/api/v2/silences", nil, http.StatusOK)

		parsed, err = gabs.ParseJSON(b)
		if err != nil {
			t.Fatal(err)
		}

		count, err := parsed.ArrayCount()
		if err != nil {
			t.Fatal(err)
		}

		if count != 1 {
			t.Fatalf("expecting 1 silence, got %d (%q)", count, string(b))
		}

		matchers, err := parsed.Index(0).Path("matchers").Children()
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, matcher := range matchers {
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
		_ = clients[sa].do("DELETE", fmt.Sprintf("/api/v2/silence/%s", silID), nil, http.StatusForbidden)
	}

	t.Log("deleting silence as 'editor' (allowed)")
	_ = clients["editor"].do("DELETE", fmt.Sprintf("/api/v2/silence/%s", silID), sil, http.StatusOK)
}

// The Alertmanager API should be protected by the OAuth proxy.
func TestAlertmanagerOAuthProxy(t *testing.T) {
	err := framework.Poll(5*time.Second, 5*time.Minute, func() error {
		body, err := f.AlertmanagerClient.AlertmanagerQueryAlerts(
			"filter", `alertname="Watchdog"`,
			"active", "true",
		)
		if err != nil {
			t.Fatal(err)
		}

		res, err := gabs.ParseJSON(body)
		if err != nil {
			return err
		}

		count, err := res.ArrayCount()
		if err != nil {
			return err
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
