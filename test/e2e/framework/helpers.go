package framework

import (
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	ClusterMonitorConfigMapName      = "cluster-monitoring-config"
	UserWorkloadMonitorConfigMapName = "user-workload-monitoring-config"
	E2eTestLabelName                 = "app.kubernetes.io/created-by"
	E2eTestLabelValue                = "cmo-e2e-test"
	E2eTestLabel                     = E2eTestLabelName + ": " + E2eTestLabelValue
)

// MustCreateOrUpdateConfigMap or fail the test
func (f *Framework) MustCreateOrUpdateConfigMap(t *testing.T, cm *v1.ConfigMap) {
	t.Helper()
	ensureCreatedByTestLabel(cm)
	err := Poll(time.Second, 10*time.Second, func() error {
		return f.OperatorClient.CreateOrUpdateConfigMap(ctx, cm)
	})
	if err != nil {
		t.Fatalf("failed to create/update configmap - %s", err.Error())
	}
}

// MustDeleteConfigMap or fail the test
func (f *Framework) MustDeleteConfigMap(t *testing.T, cm *v1.ConfigMap) {
	t.Helper()
	err := Poll(time.Second, 10*time.Second, func() error {
		return f.OperatorClient.DeleteConfigMap(ctx, cm)
	})
	if err != nil {
		t.Fatalf("failed to delete configmap - %s", err.Error())
	}
}

// MustGetConfigMap `name` from `namespace` within 5 minutes or fail
func (f *Framework) MustGetConfigMap(t *testing.T, name, namespace string) *v1.ConfigMap {
	t.Helper()
	var clusterCm *v1.ConfigMap
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		cm, err := f.KubeClient.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		clusterCm = cm
		return true, nil
	})
	if err != nil {
		t.Fatalf("failed to get configmap %s in namespace %s - %s", name, namespace, err.Error())
	}
	return clusterCm
}

// MustGetStatefulSet `name` from `namespace` within 5 minutes or fail
func (f *Framework) MustGetStatefulSet(t *testing.T, name, namespace string) *appsv1.StatefulSet {
	t.Helper()
	var statefulSet *appsv1.StatefulSet
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		ss, err := f.KubeClient.AppsV1().StatefulSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}

		statefulSet = ss
		return true, nil
	})
	if err != nil {
		t.Fatalf("failed to get statefulset %s in namespace %s - %s", name, namespace, err.Error())
	}
	return statefulSet
}

// MustGetPods return all pods from `namespace` within 5 minutes or fail
func (f *Framework) MustGetPods(t *testing.T, namespace string) *v1.PodList {
	t.Helper()
	var pods *v1.PodList
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		pl, err := f.KubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, nil
		}

		pods = pl
		return true, nil
	})
	if err != nil {
		t.Fatalf("failed to get pods in namespace %s - %s", namespace, err.Error())
	}
	return pods
}

func ensureCreatedByTestLabel(obj metav1.Object) {
	// only add the label if it doesn't exist yet, leave existing values
	// untouched
	labels := obj.GetLabels()
	if labels == nil {
		obj.SetLabels(map[string]string{
			E2eTestLabelName: E2eTestLabelValue,
		})
		return
	}
	if _, ok := labels[E2eTestLabelName]; !ok {
		labels[E2eTestLabelName] = E2eTestLabelValue
	}
}
