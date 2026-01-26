// Copyright 2023 The Cluster Monitoring Operator Authors
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
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestUserWorkloadWithAlertmanager(t *testing.T) {

	setupUserWorkloadAssetsWithTeardownHook(t, f)

	uwmCM := f.BuildUserWorkloadConfigMap(t, `alertmanager:
  enabled: true
`)

	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	f.AssertStatefulSetExistsAndRollout("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)
	f.AssertServiceExists("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)

	// since this func enabled User Workload Alertmanager, check all NetworkPolicies are deployed
	// under UWM project and the total deployed NetworkPolicies count matches with the required
	// NetworkPolicies count, this also can avoid extra setup/teardown of UWM cycle
	ctx := context.Background()
	networkPolicyNames := []string{
		"alertmanager-user-workload",
		"default-deny-user-workload-operands",
		"prometheus-operator-user-workload",
		"prometheus-user-workload",
		"thanos-ruler",
	}

	for _, scenario := range []struct {
		name string
		f    func(*testing.T)
	}{
		{
			name: "assert UWM alert access",
			f:    assertUWMAlertsAccess,
		},
		{
			name: "check user workload monitoring NetworkPolicies",
			f: func(t *testing.T) {
				for _, netpol := range networkPolicyNames {
					t.Run(fmt.Sprintf("assert %s networkpolicy exists", netpol), func(t *testing.T) {
						f.AssertNetworkPolicyExists(netpol, f.UserWorkloadMonitoringNs)
					})
				}
			},
		},
		{
			name: "assert total deployed NetworkPolicies count matches",
			f: func(t *testing.T) {
				npList, err := f.KubeClient.NetworkingV1().NetworkPolicies(f.UserWorkloadMonitoringNs).List(ctx, metav1.ListOptions{})
				if err != nil {
					t.Fatalf("failed to list NetworkPolicies: %v", err)
				}

				if len(npList.Items) != len(networkPolicyNames) {
					t.Errorf("NetworkPolicies count = %d, want %d", len(npList.Items), len(networkPolicyNames))
				}
			},
		},
	} {
		t.Run(scenario.name, scenario.f)
	}
}

// assertUWMAlertsAccess ensures that a user can't access all alerts from the UWM alertmanager via the api.
func assertUWMAlertsAccess(t *testing.T) {

	const testAccount = "test-alerts"

	_, err := f.CreateServiceAccount(userWorkloadTestNs, testAccount)
	if err != nil {
		t.Fatal(err)
	}

	// Grant enough permissions to the account, so it can read rules.
	_, err = f.CreateRoleBindingFromClusterRole(userWorkloadTestNs, testAccount, "monitoring-rules-view")
	if err != nil {
		t.Fatal(err)
	}

	var token string
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		token, err = f.GetServiceAccountToken(userWorkloadTestNs, testAccount)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = framework.Poll(5*time.Second, time.Minute, func() error {
		// The uwm alerts port (9095) is only exposed in-cluster, so we need to use
		// port forwarding to access kube-rbac-proxy.
		host, cleanUp, err := f.ForwardPort(t, f.UserWorkloadMonitoringNs, "alertmanager-user-workload", 9095)
		if err != nil {
			return err
		}
		defer cleanUp()

		client := framework.NewPrometheusClient(host, token)
		resp, err := client.Do("GET", "/api/v2/alerts", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("unexpected status code response, want different of %d, (%s)", http.StatusOK, framework.ClampMax(b))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to query rules: %v", err)
	}
}
