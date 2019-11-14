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
		{"create and assert an user application is deployed", deployUserApplication},
		{"create prometheus and alertmanager in user namespace", createPrometheusAlertmanagerInUserNamespace},
		{"assert user workload metrics", assertUserWorkloadMetrics},
		{"assert prometheus and alertmanager is not deployed in user namespace", assertPrometheusAlertmanagerInUserNamespace},
		{"assert assets are deleted when user workload monitoring is disabled", assertDeletedUserWorkloadAssets(cm)},
	} {
		t.Run(scenario.name, scenario.f)
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
		// otherwise it will fail immediately
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

func deployUserApplication(t *testing.T) {
	_, err := f.KubeClient.CoreV1().Namespaces().Create(&v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user-workload",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	err = framework.Poll(time.Second, 5*time.Minute, func() error {
		_, err := f.KubeClient.CoreV1().Namespaces().Get("user-workload", metav1.GetOptions{})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	app, err := f.KubeClient.AppsV1().Deployments("user-workload").Create(&appsv1.Deployment{
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
							Image: "quay.io/brancz/prometheus-example-app:v0.1.0",
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

	_, err = f.KubeClient.CoreV1().Services("user-workload").Create(&v1.Service{
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

	_, err = f.MonitoringClient.ServiceMonitors("user-workload").Create(&monitoringv1.ServiceMonitor{
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

	err = f.OperatorClient.WaitForDeploymentRollout(app)
	if err != nil {
		t.Fatal(err)
	}
}

func createPrometheusAlertmanagerInUserNamespace(t *testing.T) {
	_, err := f.MonitoringClient.Alertmanagers("user-workload").Create(&monitoringv1.Alertmanager{
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

	_, err = f.MonitoringClient.Prometheuses("user-workload").Create(&monitoringv1.Prometheus{
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
		t, 10*time.Minute, `version{namespace="user-workload"}`,
		func(i int) error {
			if i == 0 {
				return nil
			}

			return fmt.Errorf("expected version metric from user application to be equal 0 but got %v", i)
		},
	)

	{
		// assert that the same metric is not scraped by the cluster monitoring stack
		body, err := f.PrometheusK8sClient.Query(`version{namespace="user-workload"}`)
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
	err := framework.Poll(time.Second, 5*time.Minute, func() error {
		var (
			body []byte
			v    int
		)
		body, loopErr := f.PrometheusK8sClient.Query(`count(up{job="prometheus-user-workload"})`)
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
}

func assertPrometheusAlertmanagerInUserNamespace(t *testing.T) {
	_, err := f.KubeClient.AppsV1beta2().StatefulSets("user-workload").Get("prometheus-not-to-be-reconciled", metav1.GetOptions{})
	if err == nil {
		t.Fatal("expected no Prometheus statefulset to be deployed, but found one")
	}

	_, err = f.KubeClient.AppsV1beta2().StatefulSets("user-workload").Get("alertmanager-not-to-be-reconciled", metav1.GetOptions{})
	if err == nil {
		t.Fatal("expected no Alertmanager statefulset to be deployed, but found one")
	}
}

func assertDeletedUserWorkloadAssets(cm *v1.ConfigMap) func(*testing.T) {
	return func(t *testing.T) {
		err := f.KubeClient.CoreV1().Namespaces().Delete("user-workload", &metav1.DeleteOptions{})
		if err != nil {
			t.Fatal(err)
		}

		err = f.OperatorClient.DeleteConfigMap(cm)
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
			_, err := f.KubeClient.AppsV1beta2().StatefulSets(f.UserWorkloadMonitoringNs).Get("prometheus-user-workload", metav1.GetOptions{})
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
