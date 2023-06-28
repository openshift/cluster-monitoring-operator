package framework

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var (
	ctx = context.Background()
)

type AssertionFunc func(t *testing.T)

func (f *Framework) AssertStatefulsetExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertStatefulsetDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRouteExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.OpenShiftRouteClient.Routes(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRouteDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.OpenShiftRouteClient.Routes(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertSecretExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertSecretDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertConfigmapExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertConfigmapDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceAccountExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceAccountDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRoleExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRoleDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRoleBindingExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().RoleBindings(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRoleBindingDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().RoleBindings(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertClusterRoleExists(name string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertClusterRoleDoesNotExist(name string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertClusterRoleBindingExists(name string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertClusterRoleBindingDoesNotExist(name string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertNamespaceExists(name string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertNamespaceDoesNotExist(name string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertPrometheusRuleExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.MonitoringClient.PrometheusRules(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertPrometheusRuleDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.MonitoringClient.PrometheusRules(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceMonitorExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.MonitoringClient.ServiceMonitors(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceMonitorDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.MonitoringClient.ServiceMonitors(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertDeploymentExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertDeploymentExistsAndRollout(name, namespace string) func(*testing.T) {
	return func(t *testing.T) {
		f.AssertDeploymentExists(name, namespace)(t)
		err := f.OperatorClient.WaitForDeploymentRollout(ctx, &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (f *Framework) AssertDeploymentDoesNotExist(name, namespace string) func(*testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertPersistentVolumeClaimsExist(name, namespace string) func(*testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertStatefulSetExistsAndRollout(name, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		f.AssertStatefulsetExists(name, namespace)(t)
		err := f.OperatorClient.WaitForStatefulsetRollout(ctx, &appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
		})

		if err != nil {
			t.Fatal(err)
		}
	}
}

func (f *Framework) AssertThanosRulerExists(name, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		err := f.OperatorClient.WaitForThanosRuler(ctx, &monitoringv1.ThanosRuler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (f *Framework) AssertPrometheusExists(name, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		err := f.OperatorClient.ValidatePrometheus(ctx, types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

type PodAssertion func(pod v1.Pod) error

// AssertPodConfiguration for each pod in the namespace that matches the label selector
// Each pod in the returned list will be run through the list of provided assertions
func (f *Framework) AssertPodConfiguration(namespace, labelSelector string, assertions []PodAssertion) func(*testing.T) {
	return func(t *testing.T) {
		err := Poll(time.Second, 5*time.Minute, func() error {
			pods, err := f.KubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
				FieldSelector: "status.phase=Running"},
			)

			if err != nil {
				return fmt.Errorf("%w - failed to get Pods", err)
			}

			if len(pods.Items) == 0 {
				return fmt.Errorf("failed to find pods matching %s in %s", labelSelector, namespace)
			}

			// for each pod in the list of matching labels run each assertion
			for _, p := range pods.Items {
				for _, assertion := range assertions {
					if err := assertion(p); err != nil {
						return fmt.Errorf("failed assertion for %s - %w", p.Name, err)
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

func (f *Framework) AssertOperatorCondition(conditionType configv1.ClusterStatusConditionType, conditionStatus configv1.ConditionStatus) func(t *testing.T) {
	return func(t *testing.T) {
		reporter := f.OperatorClient.StatusReporter()
		err := Poll(time.Second, 5*time.Minute, func() error {
			co, err := reporter.Get(ctx)
			if err != nil {
				return err
			}
			for _, c := range co.Status.Conditions {
				if c.Type == conditionType {
					if c.Status == conditionStatus {
						return nil
					}
					return fmt.Errorf("expecting condition %q to be %q, got %q", conditionType, conditionStatus, c.Status)
				}
			}
			return fmt.Errorf("failed to find condition %q", conditionType)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (f *Framework) AssertOperatorConditionReason(conditionType configv1.ClusterStatusConditionType, conditionReason string) func(t *testing.T) {
	return func(t *testing.T) {
		reporter := f.OperatorClient.StatusReporter()
		err := Poll(time.Second, 5*time.Minute, func() error {
			co, err := reporter.Get(ctx)
			if err != nil {
				return err
			}
			for _, c := range co.Status.Conditions {
				if c.Type == conditionType {
					if c.Reason == conditionReason {
						return nil
					}
					return fmt.Errorf("expecting condition %q to have reason %q, got %q", conditionType, conditionReason, c.Reason)
				}
			}
			return fmt.Errorf("failed to find condition %q", conditionType)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (f *Framework) AssertOperatorConditionMessage(conditionType configv1.ClusterStatusConditionType, conditionMessage string) func(t *testing.T) {
	return func(t *testing.T) {
		reporter := f.OperatorClient.StatusReporter()
		err := Poll(time.Second, 5*time.Minute, func() error {
			co, err := reporter.Get(ctx)
			if err != nil {
				return err
			}
			for _, c := range co.Status.Conditions {
				if c.Type == conditionType {
					if c.Message == conditionMessage {
						return nil
					}
					return fmt.Errorf("expecting condition %q to have message %q, got %q", conditionType, conditionMessage, c.Message)
				}
			}
			return fmt.Errorf("failed to find condition %q", conditionType)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (f *Framework) AssertOperatorConditionMessageContains(conditionType configv1.ClusterStatusConditionType, conditionMessage string) func(t *testing.T) {
	return func(t *testing.T) {
		reporter := f.OperatorClient.StatusReporter()
		err := Poll(time.Second, 5*time.Minute, func() error {
			co, err := reporter.Get(ctx)
			if err != nil {
				return err
			}
			for _, c := range co.Status.Conditions {
				if c.Type == conditionType {
					if strings.Index(c.Message, conditionMessage) >= 0 {
						return nil
					}
					return fmt.Errorf("expecting condition %q to have message %q, got %q", conditionType, conditionMessage, c.Message)
				}
			}
			return fmt.Errorf("failed to find condition %q", conditionType)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (f *Framework) AssertValueInConfigMapEquals(name, namespace, key, compareWith string) func(t *testing.T) {
	return func(t *testing.T) {
		cm := f.MustGetConfigMap(t, name, namespace)
		if cm.Data[key] != compareWith {
			t.Fatalf("wanted value %s for key %s but got %s", compareWith, key, cm.Data[key])
		}
	}
}

func (f *Framework) AssertValueInConfigMapNotEquals(name, namespace, key, compareWith string) func(t *testing.T) {
	return func(t *testing.T) {
		cm := f.MustGetConfigMap(t, name, namespace)
		if cm.Data[key] == compareWith {
			t.Fatalf("did not want value %s for key %s", compareWith, key)
		}
	}
}

func (f *Framework) AssertValueInSecretEquals(name, namespace, key, compareWith string) func(t *testing.T) {
	return func(t *testing.T) {
		s := f.MustGetSecret(t, name, namespace)
		if string(s.Data[key]) != compareWith {
			t.Fatalf("wanted value %s for key %s but got %s", compareWith, key, string(s.Data[key]))
		}
	}
}

func (f *Framework) AssertValueInSecretNotEquals(name, namespace, key, compareWith string) func(t *testing.T) {
	return func(t *testing.T) {
		s := f.MustGetSecret(t, name, namespace)
		if string(s.Data[key]) == compareWith {
			t.Fatalf("did not want value %s for key %s", compareWith, key)
		}
	}
}

type getResourceFunc func() (metav1.Object, error)

func assertResourceExists(t *testing.T, getResource getResourceFunc) {
	if err := Poll(5*time.Second, 10*time.Minute, func() error {
		_, err := getResource()
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func assertResourceDoesNotExists(t *testing.T, getResource getResourceFunc) {
	if err := Poll(5*time.Second, 10*time.Minute, func() error {
		_, err := getResource()
		if err == nil {
			return fmt.Errorf("expected resource to not exist")
		}
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
