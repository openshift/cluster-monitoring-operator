// Copyright 2020 The Cluster Monitoring Operator Authors
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
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestThanosQuerierTrustedCA(t *testing.T) {
	ctx := context.Background()
	var (
		newCM   *v1.ConfigMap
		lastErr error
	)

	// Wait for the new ConfigMap to be created
	err := wait.PollUntilContextTimeout(context.Background(), time.Second, 5*time.Minute, true, func(context.Context) (bool, error) {
		cm, err := f.KubeClient.CoreV1().ConfigMaps(f.Ns).Get(ctx, "thanos-querier-trusted-ca-bundle", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting new trusted CA ConfigMap failed")
		if err != nil {
			return false, nil
		}

		newCM, err = f.ManifestsFactory.HashTrustedCA(cm, "thanos-querier")
		lastErr = errors.Wrap(err, "no trusted CA bundle data available")
		if err != nil {
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		if wait.Interrupted(err) && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}

	for _, tc := range []scenario{
		{
			name:      "Wait for the new hashed trusted CA bundle ConfigMap to be created",
			assertion: f.AssertConfigmapExists(newCM.Name, f.Ns),
		},
		{
			name:      "assert deployment rolls out",
			assertion: f.AssertDeploymentExistsAndRollout("thanos-querier", f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=thanos-query",
				[]framework.PodAssertion{
					expectVolumeMountsInContainer("oauth-proxy", "thanos-querier-trusted-ca-bundle"),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestThanosQueryCanQueryWatchdogAlert(t *testing.T) {
	// The 2 minute timeout is what console CI tests set.
	// If this test is flaky, we should increase until
	// we can fix the possible DNS resolve issues.
	f.ThanosQuerierClient.WaitForRulesReturn(
		t, 2*time.Minute,
		func(body []byte) error {
			return getThanosRules(body, "general.rules", "Watchdog")
		},
	)
}

const (
	roleNameTQ        = "cluster-monitoring-metrics-api"
	clusterRoleNameTQ = "cluster-monitoring-view"
	testNamespaceTQ   = "e2e-thanos-querier"
	routeNameTQ       = "thanos-querier"
)

func TestMonitoringApiRoles(t *testing.T) {

	cf, err := f.CreateNamespace(testNamespaceTQ)
	if err != nil {
		t.Fatal("Failed to create test namespace", err)
	}
	t.Cleanup(func() {
		err := cf()
		if err != nil {
			t.Logf("Failed to delete namespace %s: %v", testNamespaceTQ, err)
		}
	})

	for _, tc := range []scenario{
		{
			name:      fmt.Sprintf("assert %s role exists", roleNameTQ),
			assertion: f.AssertRoleExists("cluster-monitoring-metrics-api", f.Ns),
		},
		{
			name:      fmt.Sprintf("assert %s cluster role exists", clusterRoleNameTQ),
			assertion: f.AssertClusterRoleExists(clusterRoleNameTQ),
		},
		{
			name:      fmt.Sprintf("thanos querier API is accessible by role %s", roleNameTQ),
			assertion: testRoleAccessToThanosQuerier,
		},
		{
			name:      fmt.Sprintf("thanos querier API is accessible by cluster role %s", clusterRoleNameTQ),
			assertion: testClusterRoleAccessToThanosQuerier,
		},
		{
			name:      "thanos querier API is inaccessible without either role or cluster role",
			assertion: testBlockedAccessToThanosQuerier,
		},
	} {
		t.Run(tc.name, tc.assertion)
	}

}

func makePromClientWithSA(saName string, t *testing.T) (clientTQ *framework.PrometheusClient, err error) {

	cf, err := f.CreateServiceAccount(testNamespaceTQ, saName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := cf()
		if err != nil {
			t.Logf("Failed to delete service account %s, %v", saName, err)
		}
	})

	err = framework.Poll(5*time.Second, 5*time.Minute, func() error {
		token, err := f.GetServiceAccountToken(testNamespaceTQ, saName)
		if err != nil {
			return err
		}
		clientTQ, err = framework.NewPrometheusClientFromRoute(
			context.Background(),
			f.OpenShiftRouteClient,
			f.Ns,
			routeNameTQ,
			token,
		)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return clientTQ, nil
}

func testRoleAccessToThanosQuerier(t *testing.T) {
	const saName = "e2e-thanos-querier-role-access-test"

	clientTQ, err := makePromClientWithSA(saName, t)
	if err != nil {
		t.Fatal(err)
	}

	cf, err := f.CreateRoleBindingFromRoleOtherNamespace(testNamespaceTQ, saName, roleNameTQ, f.Ns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := cf()
		if err != nil {
			t.Logf("Failed to delete role binding for %s: %v", saName, err)
		}
	})

	err = framework.Poll(10*time.Second, 2*time.Minute, func() error {
		_, err = clientTQ.PrometheusQueryWithStatus("up{namespace=\"openshift-monitoring\"}", 200)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func testClusterRoleAccessToThanosQuerier(t *testing.T) {
	const saName = "e2e-thanos-querier-cluster-role-access-test"

	clientTQ, err := makePromClientWithSA(saName, t)
	if err != nil {
		t.Fatal(err)
	}

	cf, err := f.CreateClusterRoleBinding(testNamespaceTQ, saName, clusterRoleNameTQ)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := cf()
		if err != nil {
			t.Logf("Failed to delete cluster role binding for %s: %v", saName, err)
		}
	})

	err = framework.Poll(10*time.Second, 2*time.Minute, func() error {
		_, err = clientTQ.PrometheusQueryWithStatus("up{namespace=\"openshift-monitoring\"}", 200)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func testBlockedAccessToThanosQuerier(t *testing.T) {
	const saName = "e2e-thanos-querier-no-access-test"

	clientTQ, err := makePromClientWithSA(saName, t)
	if err != nil {
		t.Fatal(err)
	}

	err = framework.Poll(10*time.Second, 2*time.Minute, func() error {
		_, err := clientTQ.PrometheusQueryWithStatus("up{namespace=\"openshift-monitoring\"}", 403)
		return err
	})
	if err != nil {
		t.Fatal("expected error when accessing Thanos Querier API without role or cluster role", err)
	}
}
