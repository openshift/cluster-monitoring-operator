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
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/Jeffail/gabs"
	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/gogo/protobuf/proto"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
)

// The namespace where to deploy the test application.
const (
	userWorkloadTestNs = "user-workload-test"
	userWorkloadNs     = "openshift-user-workload-monitoring"
)

func TestUserWorkloadMonitoring(t *testing.T) {
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-monitoring-config",
			Namespace: f.Ns,
		},
		Data: map[string]string{
			"config.yaml": `techPreviewUserWorkload:
      enabled: true
`,
		},
	}

	for _, scenario := range []struct {
		name string
		f    func(*testing.T)
	}{
		{"enable user workload monitoring, assert prometheus rollout", createUserWorkloadAssets(cm)},
		{"assert thanos ruler deployment", assertThanosRulerDeployment},
		{"create and assert an user application is deployed", deployUserApplication},
		{"create prometheus and alertmanager in user namespace", createPrometheusAlertmanagerInUserNamespace},
		{"assert user workload metrics", assertUserWorkloadMetrics},
		{"assert user workload rules", assertUserWorkloadRules},
		{"assert tenancy model is enforced for metrics", assertTenancyForMetrics},
		{"assert tenancy model is enforced for rules", assertTenancyForRules},
		{"assert prometheus and alertmanager is not deployed in user namespace", assertPrometheusAlertmanagerInUserNamespace},
		{"assert grpc tls rotation", assertGRPCTLSRotation},
		{"assert user workload metrics", assertUserWorkloadMetrics},
		{"assert user workload rules", assertUserWorkloadRules},
		{"assert assets are deleted when user workload monitoring is disabled", assertDeletedUserWorkloadAssets(cm)},
	} {
		if ok := t.Run(scenario.name, scenario.f); !ok {
			t.Fatalf("scenario %q failed", scenario.name)
		}
	}
}

func TestUserWorkloadMonitoringNewConfig(t *testing.T) {
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-monitoring-config",
			Namespace: f.Ns,
		},
		Data: map[string]string{
			"config.yaml": `enableUserWorkload: true
`,
		},
	}

	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-workload-monitoring-config",
			Namespace: userWorkloadNs,
		},
		Data: map[string]string{
			"config.yaml": `prometheus:
  volumeClaimTemplate:
    spec:
      storageClassName: gp2
      resources:
        requests:
          storage: 2Gi
`,
		},
	}

	for _, scenario := range []struct {
		name string
		f    func(*testing.T)
	}{
		{"enable user workload monitoring, assert prometheus rollout", createUserWorkloadAssets(cm)},
		{"set VolumeClaimTemplate for prometheus CR, assert that it is created", assertPrometheusVCConfig(uwmCM)},
		{"assert assets are deleted when user workload monitoring is disabled", assertDeletedUserWorkloadAssets(cm)},
	} {
		if ok := t.Run(scenario.name, scenario.f); !ok {
			t.Fatalf("scenario %q failed", scenario.name)
		}
	}
}

func assertPrometheusVCConfig(cm *v1.ConfigMap) func(*testing.T) {
	return func(t *testing.T) {
		if err := f.OperatorClient.CreateOrUpdateConfigMap(cm); err != nil {
			t.Fatal(err)
		}

		var lastErr error
		// Wait for persistent volume claim
		err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
			_, err := f.KubeClient.CoreV1().PersistentVolumeClaims(userWorkloadNs).Get("prometheus-user-workload-db-prometheus-user-workload-0", metav1.GetOptions{})
			lastErr = errors.Wrap(err, "getting prometheus persistent volume claim failed")
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
				Name:      "prometheus-user-workload",
				Namespace: userWorkloadNs,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}

}

func createUserWorkloadAssets(cm *v1.ConfigMap) func(*testing.T) {
	return func(t *testing.T) {
		if err := f.OperatorClient.CreateOrUpdateConfigMap(cm); err != nil {
			t.Fatal(err)
		}

		err := framework.Poll(time.Second, 5*time.Minute, func() error {
			_, err := f.KubeClient.AppsV1().Deployments(f.UserWorkloadMonitoringNs).Get("prometheus-operator", metav1.GetOptions{})
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		err = framework.Poll(time.Second, 5*time.Minute, func() error {
			_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get("prometheus-user-workload", metav1.GetOptions{})
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		// this will only poll if the statefulset is there in the first place
		// otherwise it will fail immediately.
		err = f.OperatorClient.WaitForPrometheus(&monitoringv1.Prometheus{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "user-workload",
				Namespace: f.UserWorkloadMonitoringNs,
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		err = f.OperatorClient.WaitForStatefulsetRollout(&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "prometheus-user-workload",
				Namespace: f.UserWorkloadMonitoringNs,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertThanosRulerDeployment(t *testing.T) {
	err := framework.Poll(time.Second, 5*time.Minute, func() error {
		_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get("thanos-ruler-user-workload", metav1.GetOptions{})
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = f.OperatorClient.WaitForThanosRuler(&monitoringv1.ThanosRuler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user-workload",
			Namespace: f.UserWorkloadMonitoringNs,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = f.OperatorClient.WaitForStatefulsetRollout(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "thanos-ruler-user-workload",
			Namespace: f.UserWorkloadMonitoringNs,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

}

func deployUserApplication(t *testing.T) {
	_, err := f.KubeClient.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: userWorkloadTestNs,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = framework.Poll(time.Second, 5*time.Minute, func() error {
		_, err := f.KubeClient.CoreV1().Namespaces().Get(userWorkloadTestNs, metav1.GetOptions{})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	app, err := f.KubeClient.AppsV1().Deployments(userWorkloadTestNs).Create(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-app",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: proto.Int32(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "prometheus-example-app",
				},
			},
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  "prometheus-example-app",
							Image: "quay.io/brancz/prometheus-example-app:v0.2.0",
						},
					},
				},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "prometheus-example-app",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.KubeClient.CoreV1().Services(userWorkloadTestNs).Create(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-app",
			Labels: map[string]string{
				"app": "prometheus-example-app",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:       "web",
					Protocol:   "TCP",
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
				},
			},
			Selector: map[string]string{
				"app": "prometheus-example-app",
			},
			Type: v1.ServiceTypeClusterIP,
		},
	})

	_, err = f.MonitoringClient.ServiceMonitors(userWorkloadTestNs).Create(&monitoringv1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-monitor",
			Labels: map[string]string{
				"k8s-app": "prometheus-example-monitor",
			},
		},
		Spec: monitoringv1.ServiceMonitorSpec{
			Endpoints: []monitoringv1.Endpoint{
				{
					Port:     "web",
					Scheme:   "http",
					Interval: "30s",
				},
			},
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "prometheus-example-app",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.MonitoringClient.PrometheusRules(userWorkloadTestNs).Create(&monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-rule",
			Labels: map[string]string{
				"k8s-app": "prometheus-example-rule",
			},
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: []monitoringv1.RuleGroup{
				{
					Name: "example",
					Rules: []monitoringv1.Rule{
						{
							Record: "version:blah:count",
							Expr:   intstr.FromString(`count(version)`),
						},
						{
							Alert: "VersionAlert",
							Expr:  intstr.FromString(fmt.Sprintf(`version{namespace="%s",job="prometheus-example-app"} == 1`, userWorkloadTestNs)),
							For:   "1s",
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = f.OperatorClient.WaitForDeploymentRollout(app)
	if err != nil {
		t.Fatal(err)
	}
}

func createPrometheusAlertmanagerInUserNamespace(t *testing.T) {
	_, err := f.MonitoringClient.Alertmanagers(userWorkloadTestNs).Create(&monitoringv1.Alertmanager{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-to-be-reconciled",
		},
		Spec: monitoringv1.AlertmanagerSpec{
			Replicas: proto.Int32(1),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.MonitoringClient.Prometheuses(userWorkloadTestNs).Create(&monitoringv1.Prometheus{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-to-be-reconciled",
		},
		Spec: monitoringv1.PrometheusSpec{
			Replicas: proto.Int32(1),
		},
	})
	if err != nil {
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
		// assert that the same metric is not scraped by the cluster monitoring stack
		body, err := f.PrometheusK8sClient.PrometheusQuery(fmt.Sprintf(`version{namespace="%s"}`, userWorkloadTestNs))
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
		body, err := f.AlertmanagerClient.AlertmanagerQueryAlerts(
			"filter", `alertname="VersionAlert"`,
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
}

func assertUserWorkloadRules(t *testing.T) {
	f.ThanosQuerierClient.WaitForRulesReturn(
		t, 10*time.Minute,
		func(body []byte) error {
			j, err := gabs.ParseJSON([]byte(body))
			if err != nil {
				return err
			}

			groups, err := j.Path("data.groups").Children()
			if err != nil {
				return err
			}

			for i := 0; i < len(groups); i++ {
				groupName := groups[i].S("name").Data().(string)
				if groupName != "example" {
					continue
				}

				rules, err := groups[i].Path("rules").Children()
				if err != nil {
					return err
				}

				for j := 0; j < len(rules); j++ {
					ruleName := rules[j].S("name").Data().(string)
					if ruleName == "VersionAlert" {
						return nil
					}
				}
			}

			return errors.New("VersionAlert alert not found")
		},
	)
}

// assertTenancyForMetrics ensures that a tenant can access metrics from her namespace (and only from this one).
func assertTenancyForMetrics(t *testing.T) {
	const testAccount = "test-metrics"

	_, err := f.CreateServiceAccount(userWorkloadTestNs, testAccount)
	if err != nil {
		t.Fatal(err)
	}

	// Grant enough permissions to the account so it can read metrics.
	_, err = f.CreateRoleBindingFromClusterRole(userWorkloadTestNs, testAccount, "admin")
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

	for _, q := range []string{"up", `up{namespace="should-be-overwritten"}`, fmt.Sprintf(`up{namespace="%s"}`, userWorkloadTestNs)} {
		t.Logf("Running query %q", q)

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

			b, err := client.PrometheusQuery(q)
			if err != nil {
				return err
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
			t.Fatalf("failed to query Thanos querier: %v", err)
		}
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

	t.Logf("Retrieving rules")
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
		if len(groups) != 1 {
			return errors.Errorf("expecting 1 rules group, got %d", len(groups))
		}

		expected := []struct {
			ruleType string
			name     string
		}{
			{
				ruleType: "recording",
				name:     "version:blah:count",
			},
			{
				ruleType: "alerting",
				name:     "VersionAlert",
			},
		}
		rules, err := groups[0].Path("rules").Children()
		if len(rules) != len(expected) {
			return errors.Errorf("expecting %d rules, got %d", len(expected), len(rules))
		}

		for _, exp := range expected {
			var found bool
			for i := range rules {
				rule, err := rules[i].ChildrenMap()
				if err != nil {
					return err
				}

				if rule["type"].Data().(string) != exp.ruleType {
					continue
				}
				if rule["name"].Data().(string) != exp.name {
					continue
				}
				labels, err := rule["labels"].ChildrenMap()
				if err != nil {
					return err
				}
				if labels["namespace"].Data().(string) != userWorkloadTestNs {
					continue
				}
				found = true
				break
			}
			if !found {
				return errors.Errorf("couldn't find %s rule %q with label 'namespace=%q' in %q", exp.ruleType, exp.name, userWorkloadTestNs, string(b))
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("failed to query rules from Thanos querier: %v", err)
	}
}

func assertPrometheusAlertmanagerInUserNamespace(t *testing.T) {
	_, err := f.KubeClient.AppsV1().StatefulSets(userWorkloadTestNs).Get("prometheus-not-to-be-reconciled", metav1.GetOptions{})
	if err == nil {
		t.Fatal("expected no Prometheus statefulset to be deployed, but found one")
	}

	_, err = f.KubeClient.AppsV1().StatefulSets(userWorkloadTestNs).Get("alertmanager-not-to-be-reconciled", metav1.GetOptions{})
	if err == nil {
		t.Fatal("expected no Alertmanager statefulset to be deployed, but found one")
	}
}

func assertGRPCTLSRotation(t *testing.T) {
	s, err := f.OperatorClient.WaitForSecret(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-tls",
			Namespace: f.Ns,
		},
	})

	if err != nil {
		t.Fatalf("error waiting for grpc-tls secret: %v", err)
	}

	if s.Annotations == nil {
		s.Annotations = make(map[string]string)
	}

	s.Annotations["monitoring.openshift.io/grpc-tls-forced-rotate"] = "true"

	if err := f.OperatorClient.CreateOrUpdateSecret(s); err != nil {
		t.Fatalf("error saving grpc-tls secret: %v", err)
	}

	err = framework.Poll(time.Second, 5*time.Minute, func() error {
		s, err := f.KubeClient.CoreV1().Secrets(f.Ns).Get("grpc-tls", metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("error loading grpc-tls secret: %v", err)
		}

		if _, ok := s.Annotations["monitoring.openshift.io/grpc-tls-forced-rotate"]; ok {
			return errors.New("rotation did not execute: grpc-tls-forced-rotate annotation set")
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertDeletedUserWorkloadAssets(cm *v1.ConfigMap) func(*testing.T) {
	return func(t *testing.T) {
		err := f.OperatorClient.DeleteConfigMap(cm)
		if err != nil {
			t.Fatal(err)
		}

		err = framework.Poll(time.Second, 5*time.Minute, func() error {
			_, err := f.KubeClient.AppsV1().Deployments(f.UserWorkloadMonitoringNs).Get("prometheus-operator", metav1.GetOptions{})
			if err == nil {
				return errors.New("prometheus-operator deployment not deleted")
			}
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}

		err = framework.Poll(time.Second, 5*time.Minute, func() error {
			_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get("prometheus-user-workload", metav1.GetOptions{})
			if err == nil {
				return errors.New("prometheus statefulset not deleted")
			}
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
