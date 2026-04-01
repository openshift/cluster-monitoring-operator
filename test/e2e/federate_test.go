// Copyright 2024 The Cluster Monitoring Operator Authors
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
	"strings"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPlatformPrometheusFederateEndpoint(t *testing.T) {
	const (
		testAccount = "test-platform-federate"
		testNs      = "openshift-monitoring" // f.Ns
	)

	saCleanup, err := f.CreateServiceAccount(testNs, testAccount)
	require.NoError(t, err)
	defer func() { require.NoError(t, saCleanup()) }()

	// The old test uses `cluster-monitoring-view`.
	rbCleanup, err := f.CreateClusterRoleBinding(testNs, testAccount, "cluster-monitoring-view")
	require.NoError(t, err)
	defer func() { require.NoError(t, rbCleanup()) }()

	var token string
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		token, err = f.GetServiceAccountToken(testNs, testAccount)
		return err
	})
	require.NoError(t, err)

	// Test service endpoint
	t.Run("ServiceEndpoint", func(t *testing.T) {
		err := framework.Poll(5*time.Second, time.Minute, func() error {
			// port 9091 is the web port for prometheus-k8s
			host, cleanUp, err := f.ForwardPort(t, f.Ns, "prometheus-k8s", 9091)
			if err != nil {
				return err
			}
			defer cleanUp()

			client := framework.NewPrometheusClient(
				host,
				token,
				&framework.QueryParameterInjector{
					Name:  "match[]",
					Value: `prometheus_build_info`,
				},
			)

			resp, err := client.Do("GET", "/federate", nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected status code, want %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
			}

			if !strings.Contains(string(body), "prometheus_build_info") {
				return fmt.Errorf("metric 'prometheus_build_info' not found in response")
			}

			return nil
		})
		require.NoError(t, err)
	})

	// Test route endpoint.
	t.Run("RouteEndpoint", func(t *testing.T) {
		err = framework.Poll(5*time.Second, time.Minute, func() error {
			// Use the dedicated federate route
			route, err := f.OpenShiftRouteClient.Routes(f.Ns).Get(context.Background(), "prometheus-k8s-federate", metav1.GetOptions{})
			if err != nil {
				return err
			}

			client := framework.NewPrometheusClient(
				route.Spec.Host,
				token,
				&framework.QueryParameterInjector{
					Name:  "match[]",
					Value: `prometheus_build_info`,
				},
			)

			// The 'prometheus-k8s-federate' route has path '/federate', so the direct path is used.
			resp, err := client.Do("GET", "/federate", nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected status code, want %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
			}

			if !strings.Contains(string(body), "prometheus_build_info") {
				return fmt.Errorf("metric 'prometheus_build_info' not found in response")
			}

			return nil
		})
		require.NoError(t, err)
	})
}

func TestUserWorkloadPrometheusFederateEndpoint(t *testing.T) {
	setupUserWorkloadAssetsWithTeardownHook(t, f)
	require.NoError(t, deployUserApplication(f))

	const (
		testAccount = "test-uwm-federate"
		// The old test creates the rolebinding in the test namespace for the default SA.
		testNs = userWorkloadTestNs
	)

	saCleanup, err := f.CreateServiceAccount(testNs, testAccount)
	require.NoError(t, err)
	defer func() { require.NoError(t, saCleanup()) }()

	// The old test binds `cluster-monitoring-view` to default SA. Let's do that.
	rbCleanup, err := f.CreateClusterRoleBinding(testNs, testAccount, "cluster-monitoring-view")
	require.NoError(t, err)
	defer func() { require.NoError(t, rbCleanup()) }()

	var token string
	err = framework.Poll(5*time.Second, time.Minute, func() error {
		token, err = f.GetServiceAccountToken(testNs, testAccount)
		return err
	})
	require.NoError(t, err)

	// Test service endpoint
	t.Run("ServiceEndpoint", func(t *testing.T) {
		err := framework.Poll(5*time.Second, 2*time.Minute, func() error {
			// port 9092 is the web port for prometheus-user-workload
			host, cleanUp, err := f.ForwardPort(t, f.UserWorkloadMonitoringNs, "prometheus-user-workload", 9092)
			if err != nil {
				return err
			}
			defer cleanUp()

			client := framework.NewPrometheusClient(
				host,
				token,
				&framework.QueryParameterInjector{
					Name:  "match[]",
					Value: `version`, // from prometheus-example-app
				},
				// The tenancy proxy needs the namespace
				&framework.QueryParameterInjector{
					Name:  "namespace",
					Value: testNs,
				},
			)

			resp, err := client.Do("GET", "/federate", nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected status code, want %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
			}

			if !strings.Contains(string(body), `job="prometheus-example-app"`) {
				return fmt.Errorf("metric from 'prometheus-example-app' not found in response")
			}

			return nil
		})
		require.NoError(t, err)
	})

	// Test route endpoint
	t.Run("RouteEndpoint", func(t *testing.T) {
		err = framework.Poll(5*time.Second, 2*time.Minute, func() error {
			route, err := f.OpenShiftRouteClient.Routes(f.UserWorkloadMonitoringNs).Get(context.Background(), "federate", metav1.GetOptions{})
			if err != nil {
				return err
			}

			client := framework.NewPrometheusClient(
				route.Spec.Host,
				token,
				&framework.QueryParameterInjector{
					Name:  "match[]",
					Value: `version`, // from prometheus-example-app
				},
				// The tenancy proxy needs the namespace
				&framework.QueryParameterInjector{
					Name:  "namespace",
					Value: testNs,
				},
			)

			// For UWM federate route, let's assume it directly exposes the /federate endpoint
			// If it also has a path prefix, this would need adjustment as well.
			resp, err := client.Do("GET", "/federate", nil)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected status code, want %d, got %d. Body: %s", http.StatusOK, resp.StatusCode, string(body))
			}

			if !strings.Contains(string(body), `job="prometheus-example-app"`) {
				return fmt.Errorf("metric from 'prometheus-example-app' not found in response")
			}
			return nil
		})
		require.NoError(t, err)
	})
}
