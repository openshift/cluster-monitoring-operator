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
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	e2enetwork "k8s.io/kubernetes/test/e2e/framework/network"
	"testing"
	"time"
)

const (
	monitoringPluginNs    = "openshift-monitoring"
	monitoringService     = "monitoring-plugin"
	monitoringServicePort = 9443
)

// TestMonitoringPluginExists tests that the monitoring plugin service exists
func TestMonitoringPluginExists(t *testing.T) {
	assertions := []struct {
		name      string
		assertion framework.AssertionFunc
	}{
		{name: "assert Console Plugin Service exists", assertion: f.AssertServiceExists(monitoringService, monitoringPluginNs)},
	}
	t.Run("check-console-plugin-service", func(t *testing.T) {
		for _, assertion := range assertions {
			t.Run(assertion.name, assertion.assertion)
		}
	})
}

func TestMonitoringPluginReachable(t *testing.T) {
	service, err := f.KubeClient.CoreV1().Services(monitoringPluginNs).Get(context.TODO(), monitoringService, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Error getting service %s: %v", monitoringService, err)
	}
	serviceIP := service.Spec.ClusterIP
	err = wait.PollUntilContextTimeout(context.Background(), 5*time.Second, 2*time.Minute, false, func(ctx context.Context) (bool, error) {
		params := &e2enetwork.HTTPPokeParams{Timeout: 2 * time.Second}
		result := e2enetwork.PokeHTTP(serviceIP, monitoringServicePort, "", params)
		if result.Status != e2enetwork.HTTPSuccess {
			t.Fatalf("Error reaching service %s at %s and port %d: %v", monitoringService, serviceIP, monitoringServicePort, err)
		}
		if err != nil {
			return false, err
		}

		return true, nil
	})

	if err != nil {
		t.Fatalf("Error reaching service %s at %s and port %d: %v", monitoringService, serviceIP, monitoringServicePort, err)
	}
}
