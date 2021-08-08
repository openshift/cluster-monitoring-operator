package framework

import (
	"context"
	"fmt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

type AssertionFunc func(t *testing.T)

func (f *Framework) AssertStatefulsetExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.AppsV1().StatefulSets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertStatefulsetDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.AppsV1().StatefulSets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRouteExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.OpenShiftRouteClient.Routes(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRouteDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.OpenShiftRouteClient.Routes(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertSecretExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertSecretDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().Services(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().Services(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertConfigmapExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertConfigmapDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceAccountExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().ServiceAccounts(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceAccountDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.CoreV1().ServiceAccounts(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRoleExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().Roles(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRoleDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().Roles(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRoleBindingExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().RoleBindings(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertRoleBindingDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().RoleBindings(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertClusterRoleExists(name string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().ClusterRoles().Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertClusterRoleDoesNotExist(name string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().ClusterRoles().Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertClusterRoleBindingExists(name string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().ClusterRoleBindings().Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertClusterRoleBindingDoesNotExist(name string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.KubeClient.RbacV1().ClusterRoleBindings().Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertPrometheusRuleExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.MonitoringClient.PrometheusRules(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertPrometheusRuleDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.MonitoringClient.PrometheusRules(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceMonitorExists(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceExists(t, func() (metav1.Object, error) {
			return f.MonitoringClient.ServiceMonitors(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
	}
}

func (f *Framework) AssertServiceMonitorDoesNotExist(name string, namespace string) func(t *testing.T) {
	return func(t *testing.T) {
		assertResourceDoesNotExists(t, func() (metav1.Object, error) {
			return f.MonitoringClient.ServiceMonitors(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		})
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
