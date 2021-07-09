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

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"k8s.io/client-go/util/cert"

	"github.com/Jeffail/gabs"
	"github.com/gogo/protobuf/proto"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
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
)

type scenario struct {
	name      string
	assertion func(*testing.T)
}

func TestUserWorkloadMonitoringWithStorage(t *testing.T) {
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterMonitorConfigMapName,
			Namespace: f.Ns,
		},
		Data: map[string]string{
			"config.yaml": `enableUserWorkload: true
`,
		},
	}

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

	if err := f.OperatorClient.CreateOrUpdateConfigMap(cm); err != nil {
		t.Fatal(err)
	}

	if err := f.OperatorClient.CreateOrUpdateConfigMap(uwmCM); err != nil {
		t.Fatal(err)
	}

	for _, scenario := range []struct {
		name string
		f    func(*testing.T)
	}{
		{"enable user workload monitoring, assert prometheus rollout", createUserWorkloadAssets(cm)},
		{"assert thanos ruler deployment", assertThanosRulerDeployment},
		{"assert metrics for user workload components", assertMetricsForMonitoringComponents},
		{"create and assert an user application is deployed", deployUserApplication},
		{"create prometheus and alertmanager in user namespace", createPrometheusAlertmanagerInUserNamespace},
		{"assert user workload metrics", assertUserWorkloadMetrics},
		{"assert user workload rules", assertUserWorkloadRules},
		{"assert tenancy model is enforced for metrics", assertTenancyForMetrics},
		{"assert tenancy model is enforced for rules", assertTenancyForRules},
		{"assert prometheus and alertmanager is not deployed in user namespace", assertPrometheusAlertmanagerInUserNamespace},
		{"assert grpc tls rotation", assertGRPCTLSRotation},
		{"assert enforced target limit is configured", assertEnforcedTargetLimit(10)},
		{"enable user workload monitoring, assert prometheus rollout", createUserWorkloadAssets(cm)},
		{"set VolumeClaimTemplate for prometheus CR, assert that it is created", assertVolumeClaimsConfigAndRollout(rolloutParams{
			namespace:       f.UserWorkloadMonitoringNs,
			claimName:       "prometheus-user-workload-db-prometheus-user-workload-0",
			statefulSetName: "prometheus-user-workload",
		})},
		{"assert assets are deleted when user workload monitoring is disabled", assertDeletedUserWorkloadAssets(cm)},
	} {
		t.Run(scenario.name, scenario.f)
	}
}

func TestUserWorkloadMonitoringWithAdditionalAlertmanagerConfigs(t *testing.T) {
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterMonitorConfigMapName,
			Namespace: f.Ns,
		},
		Data: map[string]string{
			"config.yaml": `enableUserWorkload: true
`,
		},
	}

	if err := createSelfSignedCertificateSecret("alertmanager-tls"); err != nil {
		t.Fatal(err)
	}

	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
		},
		Data: map[string]string{
			"config.yaml": `prometheus:
  additionalAlertManagerConfigs:
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

	scenarios := []scenario{
		{"enable user workload monitoring, assert rollout", createUserWorkloadAssets(cm)},
		{"enable 2 more alertmanagers", updateConfigmap(uwmCM)},
		{"assert 5 alertmanagers are discovered (3 built-in and 2 from the additional configs)", assertAlertmanagerInstancesDiscovered(5)},
		{"disable additional alertmanagers", disableAdditionalAlertmanagerConfigs},
		{"assert additional-alertmanager-configs secret is deleted", assertSecretDoesNotExist(manifests.PrometheusUWAdditionalAlertmanagerConfigSecretName, f.UserWorkloadMonitoringNs)},
		{"assert 3 alertmanagers are discovered", assertAlertmanagerInstancesDiscovered(3)},
		{"assert assets are deleted when user workload monitoring is disabled", assertDeletedUserWorkloadAssets(cm)},
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

func createUserWorkloadAssets(cm *v1.ConfigMap) func(*testing.T) {
	return func(t *testing.T) {
		if err := f.OperatorClient.CreateOrUpdateConfigMap(cm); err != nil {
			t.Fatal(err)
		}

		err := framework.Poll(time.Second, 5*time.Minute, func() error {
			_, err := f.KubeClient.AppsV1().Deployments(f.UserWorkloadMonitoringNs).Get(f.Ctx, "prometheus-operator", metav1.GetOptions{})
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}

		err = framework.Poll(time.Second, 5*time.Minute, func() error {
			_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(f.Ctx, "prometheus-user-workload", metav1.GetOptions{})
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
		_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(f.Ctx, "thanos-ruler-user-workload", metav1.GetOptions{})
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

func deployUserApplication(t *testing.T) {
	_, err := f.KubeClient.CoreV1().Namespaces().Create(f.Ctx, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: userWorkloadTestNs,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = framework.Poll(time.Second, 5*time.Minute, func() error {
		_, err := f.KubeClient.CoreV1().Namespaces().Get(f.Ctx, userWorkloadTestNs, metav1.GetOptions{})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	app, err := f.KubeClient.AppsV1().Deployments(userWorkloadTestNs).Create(f.Ctx, &appsv1.Deployment{
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
							Image: "ghcr.io/rhobs/prometheus-example-app:0.3.0",
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
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.KubeClient.CoreV1().Services(userWorkloadTestNs).Create(f.Ctx, &v1.Service{
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
	}, metav1.CreateOptions{})

	_, err = f.MonitoringClient.ServiceMonitors(userWorkloadTestNs).Create(f.Ctx, &monitoringv1.ServiceMonitor{
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
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.MonitoringClient.PrometheusRules(userWorkloadTestNs).Create(f.Ctx, &monitoringv1.PrometheusRule{
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
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.MonitoringClient.PrometheusRules(userWorkloadTestNs).Create(f.Ctx, &monitoringv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prometheus-example-rule-leaf",
			Labels: map[string]string{
				"k8s-app": "prometheus-example-rule-leaf",
				"openshift.io/prometheus-rule-evaluation-scope": "leaf-prometheus",
			},
		},
		Spec: monitoringv1.PrometheusRuleSpec{
			Groups: []monitoringv1.RuleGroup{
				{
					Name: "example",
					Rules: []monitoringv1.Rule{
						{
							Record: "version:blah:leaf:count",
							Expr:   intstr.FromString(`count(version)`),
						},
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	err = f.OperatorClient.WaitForDeploymentRollout(app)
	if err != nil {
		t.Fatal(err)
	}
}

func disableAdditionalAlertmanagerConfigs(t *testing.T) {
	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
		},
		Data: map[string]string{
			"config.yaml": `prometheus: {}`,
		},
	}

	if err := f.OperatorClient.CreateOrUpdateConfigMap(uwmCM); err != nil {
		t.Fatal(err)
	}
}

func createPrometheusAlertmanagerInUserNamespace(t *testing.T) {
	_, err := f.MonitoringClient.Alertmanagers(userWorkloadTestNs).Create(f.Ctx, &monitoringv1.Alertmanager{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-to-be-reconciled",
		},
		Spec: monitoringv1.AlertmanagerSpec{
			Replicas: proto.Int32(1),
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.MonitoringClient.Prometheuses(userWorkloadTestNs).Create(f.Ctx, &monitoringv1.Prometheus{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-to-be-reconciled",
		},
		Spec: monitoringv1.PrometheusSpec{
			Replicas: proto.Int32(1),
		},
	}, metav1.CreateOptions{})
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
		body, err := f.AlertmanagerClient.AlertmanagerQueryAlerts(
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
			file      string
			ruleType  string
			name      string
			namespace string
		}

		expected := []testData{
			{
				file:      "/etc/prometheus/rules/prometheus-user-workload-rulefiles-0/user-workload-test-prometheus-example-rule-leaf.yaml",
				ruleType:  "recording",
				name:      "version:blah:leaf:count",
				namespace: "user-workload-test",
			},
			{
				file:      "/etc/thanos/rules/thanos-ruler-user-workload-rulefiles-0/user-workload-test-prometheus-example-rule.yaml",
				ruleType:  "alerting",
				name:      "VersionAlert",
				namespace: "user-workload-test",
			},
			{
				file:      "/etc/thanos/rules/thanos-ruler-user-workload-rulefiles-0/user-workload-test-prometheus-example-rule.yaml",
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
					file:      group.Path("file").Data().(string),
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

func assertPrometheusAlertmanagerInUserNamespace(t *testing.T) {
	_, err := f.KubeClient.AppsV1().StatefulSets(userWorkloadTestNs).Get(f.Ctx, "prometheus-not-to-be-reconciled", metav1.GetOptions{})
	if err == nil {
		t.Fatal("expected no Prometheus statefulset to be deployed, but found one")
	}

	_, err = f.KubeClient.AppsV1().StatefulSets(userWorkloadTestNs).Get(f.Ctx, "alertmanager-not-to-be-reconciled", metav1.GetOptions{})
	if err == nil {
		t.Fatal("expected no Alertmanager statefulset to be deployed, but found one")
	}
}

func assertGRPCTLSRotation(t *testing.T) {
	countGRPCSecrets := func(ns string) int {
		t.Helper()
		var result int
		err := framework.Poll(5*time.Second, time.Minute, func() error {
			s, err := f.KubeClient.CoreV1().Secrets(ns).List(f.Ctx, metav1.ListOptions{LabelSelector: "monitoring.openshift.io/hash"})
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
		s, err := f.KubeClient.CoreV1().Secrets(f.Ns).Get(f.Ctx, "grpc-tls", metav1.GetOptions{})
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

func assertDeletedUserWorkloadAssets(cm *v1.ConfigMap) func(*testing.T) {
	return func(t *testing.T) {
		err := f.OperatorClient.DeleteConfigMap(cm)
		if err != nil {
			t.Fatal(err)
		}

		err = framework.Poll(time.Second, 10*time.Minute, func() error {
			_, err := f.KubeClient.AppsV1().Deployments(f.UserWorkloadMonitoringNs).Get(f.Ctx, "prometheus-operator", metav1.GetOptions{})
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

		err = framework.Poll(time.Second, 10*time.Minute, func() error {
			_, err := f.KubeClient.AppsV1().StatefulSets(f.UserWorkloadMonitoringNs).Get(f.Ctx, "prometheus-user-workload", metav1.GetOptions{})
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

		err = framework.Poll(time.Second, 10*time.Minute, func() error {
			_, err := f.KubeClient.CoreV1().Secrets(f.UserWorkloadMonitoringNs).Get(f.Ctx, manifests.PrometheusUWAdditionalAlertmanagerConfigSecretName, metav1.GetOptions{})
			if err == nil {
				return fmt.Errorf("secret %s/%s not deleted", manifests.PrometheusUWAdditionalAlertmanagerConfigSecretName, f.UserWorkloadMonitoringNs)
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

func assertSecretDoesNotExist(name string, namespace string) func(*testing.T) {
	return func(t *testing.T) {
		if err := framework.Poll(5*time.Second, 10*time.Minute, func() error {
			_, err := f.OperatorClient.GetSecret(namespace, name)
			if err == nil || apierrors.IsNotFound(err) {
				return nil
			}

			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func assertEnforcedTargetLimit(limit uint64) func(*testing.T) {
	return func(t *testing.T) {
		err := framework.Poll(time.Second, 5*time.Minute, func() error {
			prom, err := f.MonitoringClient.Prometheuses(f.UserWorkloadMonitoringNs).Get(f.Ctx, "user-workload", metav1.GetOptions{})
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

func updateConfigmap(cm *v1.ConfigMap) func(t *testing.T) {
	return func(t *testing.T) {
		if err := f.OperatorClient.CreateOrUpdateConfigMap(cm); err != nil {
			t.Fatal(err)
		}
	}
}
