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
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
)

func TestUserWorkloadAlertmanager(t *testing.T) {

	setupUserWorkloadAssetsWithTeardownHook(t, f)

	uwmCM := f.BuildUserWorkloadConfigMap(t, `alertmanager:
  enabled: true
`)

	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	f.AssertStatefulSetExistsAndRollout("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)
	f.AssertServiceExists("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)

	t.Run("assert UWM alert access", assertUWMAlertsAccess)
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
			t.Fatal(err)
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
