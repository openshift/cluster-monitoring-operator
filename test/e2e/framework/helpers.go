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
)

// MustCreateOrUpdateConfigMap or fail the test
func (f *Framework) MustCreateOrUpdateConfigMap(t *testing.T, cm *v1.ConfigMap) {
	t.Helper()
	if err := f.OperatorClient.CreateOrUpdateConfigMap(ctx, cm); err != nil {
		t.Fatalf("failed to create/update configmap - %s", err.Error())
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
