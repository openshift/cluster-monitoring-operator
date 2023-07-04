// Copyright 2019 The Cluster Monitoring Operator Authors
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
	"net/http"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
)

func TestAlertmanagerPolicyHeaders(t *testing.T) {
	// The tenancy port (9092) is only exposed in-cluster so we need to use
	// port forwarding to access kube-rbac-proxy.
	host, cleanUp, err := f.ForwardPort(t, f.Ns, "alertmanager-main", 9092)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)

	checkHeaders(t, host, framework.E2eServiceAccount, "/api/v2/alerts")
}

func TestPrometheusPolicyHeaders(t *testing.T) {
	// The port (9092) is only exposed in-cluster so we need to use
	// port forwarding to access kube-rbac-proxy.
	host, cleanUp, err := f.ForwardPort(t, f.Ns, "prometheus-k8s", 9092)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)

	checkHeaders(t, host, "prometheus-k8s", "/metrics")
}

func checkHeaders(t *testing.T, host string, sa string, query string) {
	var client *framework.PrometheusClient

	err := framework.Poll(5*time.Second, 5*time.Minute, func() error {
		token, err := f.GetServiceAccountToken(f.Ns, sa)
		if err != nil {
			return err
		}
		client = framework.NewPrometheusClient(
			host,
			token,
			&framework.QueryParameterInjector{
				Name:  "namespace",
				Value: f.Ns,
			},
		)
		return nil
	})

	err = framework.Poll(5*time.Second, 1*time.Minute, func() error {
		resp, err := client.Do("GET", query, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("expecting 200 status code, got %d (%q)", resp.StatusCode, resp.Body)
		}

		if resp.Header == nil {
			return fmt.Errorf("expecting policy headers but is empty")
		}

		if resp.Header.Get("Content-Security-Policy") != "frame-ancestors 'none'" {
			return fmt.Errorf("expecting frame-ancestors 'none' policy headers, got %q", resp.Header["Content-Security-Policy"])
		}

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}
}
