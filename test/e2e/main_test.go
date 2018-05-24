// Copyright 2018 The Cluster Monitoring Operator Authors
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
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Jeffail/gabs"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/wait"
)

var client *promClient

func TestMain(m *testing.M) {
	tokenFileFlag := flag.String("token-file", "/var/run/secrets/kubernetes.io/serviceaccount/token", "path to a bearer token")
	endpointFlag := flag.String("endpoint", "https://prometheus-k8s.openshift-monitoring.svc:9090", "Prometheus service endpoint")
	flag.Parse()

	tokenBytes, err := ioutil.ReadFile(*tokenFileFlag)
	if err != nil {
		log.Fatalf("couldn't read token file %q: %v", *tokenFileFlag, err)
	}
	client = &promClient{
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		endpoint: *endpointFlag,
		token:    string(tokenBytes),
	}
	os.Exit(m.Run())
}

func TestQueryPrometheus(t *testing.T) {
	t.Parallel()
	queries := []struct {
		query   string
		expectN int
	}{
		{
			query:   `up{job="node-exporter"} == 1`,
			expectN: 1,
		},
		{
			query:   `up{job="kubelet"} == 1`,
			expectN: 1,
		},
		// Not supported in the origin 3.10 topology.
		// {
		// 	query:   `up{job="kube-scheduler"} == 1`,
		// 	expectN: 1,
		// },

		// Not supported in the origin 3.10 topology.
		// {
		// 	query:   `up{job="kube-controller-manager"} == 1`,
		// 	expectN: 1,
		// },
		{
			query:   `up{job="kube-controllers"} == 1`,
			expectN: 1,
		},
		{
			query:   `up{job="apiserver"} == 1`,
			expectN: 1,
		},
		{
			query:   `up{job="kube-state-metrics"} == 1`,
			expectN: 1,
		},
		{
			query:   `up{job="prometheus-k8s"} == 1`,
			expectN: 1,
		},
		{
			query:   `up{job="prometheus-operator"} == 1`,
			expectN: 1,
		},
		{
			query:   `up{job="alertmanager-main"} == 1`,
			expectN: 2,
		},
		{
			query:   `namespace:container_memory_usage_bytes:sum`,
			expectN: 1,
		},
	}

	// Wait for pod to respond at queries at all. Then start verifying their results.
	err := wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		_, err := client.query("up")
		return err == nil, nil
	})
	if err != nil {
		t.Fatal(errors.Wrap(err, "wait for prometheus-k8s"))
	}

	err = wait.Poll(5*time.Second, 20*time.Second, func() (bool, error) {
		defer t.Log("---------------------------\n")

		for _, q := range queries {
			response, err := client.query(q.query)
			res, err := gabs.ParseJSONBuffer(response.Body)
			if err != nil {
				t.Logf("error parsing response: %v", err)
				return false, nil
			}
			n, err := res.ArrayCountP("data.result")
			if n < q.expectN {
				// Don't return an error as targets may only become visible after a while.
				t.Logf("expected at least %d results for %q but got %d", q.expectN, q.query, n)
				return false, nil
			}
			t.Logf("query %q succeeded", q.query)
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type promClient struct {
	client   *http.Client
	endpoint string
	token    string
}

func (c *promClient) query(q string) (*http.Response, error) {
	url := fmt.Sprintf("%s/api/v1/query", c.endpoint)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	urlQuery := req.URL.Query()
	urlQuery.Add("query", q)
	req.URL.RawQuery = urlQuery.Encode()
	return c.client.Do(req)
}
