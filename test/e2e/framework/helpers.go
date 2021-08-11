package framework

import (
	"testing"

	v1 "k8s.io/api/core/v1"
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
