package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func assertDeploymentRollout(objName, namespace string) func(*testing.T) {
	return func(t *testing.T) {
		err := f.OperatorClient.WaitForDeploymentRollout(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      objName,
				Namespace: namespace,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertVolumeClaims(objName, namespace string) func(*testing.T) {
	return func(t *testing.T) {
		// Wait for persistent volume claim
		err := framework.Poll(time.Second, 5*time.Minute, func() error {
			_, err := f.KubeClient.CoreV1().PersistentVolumeClaims(namespace).Get(context.TODO(), objName, metav1.GetOptions{})
			if err != nil {
				return errors.Wrap(err, "getting persistent volume claim failed")

			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertStatefulSetExistsAndRollout(objName, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		err := framework.Poll(time.Second, 5*time.Minute, func() error {
			_, err := f.KubeClient.AppsV1().StatefulSets(namespace).Get(context.TODO(), objName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			return nil
		})

		if err != nil {
			t.Fatal(err)
		}

		err = f.OperatorClient.WaitForStatefulsetRollout(&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      objName,
				Namespace: namespace,
			},
		})

		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertThanosRulerIsCreated(namespace, objName string) func(t *testing.T) {
	return func(t *testing.T) {
		err := f.OperatorClient.WaitForThanosRuler(&monitoringv1.ThanosRuler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      objName,
				Namespace: namespace,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func assertPrometheusIsCreated(namespace, objName string) func(t *testing.T) {
	return func(t *testing.T) {
		err := f.OperatorClient.WaitForPrometheus(&monitoringv1.Prometheus{
			ObjectMeta: metav1.ObjectMeta{
				Name:      objName,
				Namespace: namespace,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// podConfigParams sets pod metadata
type podConfigParams struct {
	namespace, labelSelector string
}

type podAssertionCB func(pod v1.Pod) error

func assertPodConfiguration(params podConfigParams, asserts []podAssertionCB) func(*testing.T) {
	return func(t *testing.T) {
		err := framework.Poll(time.Second, 5*time.Minute, func() error {
			pods, err := f.KubeClient.CoreV1().Pods(params.namespace).List(context.TODO(), metav1.ListOptions{
				LabelSelector: params.labelSelector,
				FieldSelector: "status.phase=Running"},
			)

			if err != nil {
				return errors.Wrap(err, "failed to get Pods")
			}

			// for each pod in the list of matching labels run each assertion
			for _, p := range pods.Items {
				for _, assertion := range asserts {
					if err := assertion(p); err != nil {
						return fmt.Errorf("failed assertion for %s - %v", p.Name, err)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
