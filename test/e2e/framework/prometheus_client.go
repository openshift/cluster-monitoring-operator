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

package framework

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	routev1 "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"

	"github.com/Jeffail/gabs"
)

// PrometheusClient provides access to the prometheus-k8s statefulset via its
// public facing route.
type PrometheusClient struct {
	// Host address of Prometheus public route.
	host string
	// ServiceAccount bearer token to pass through Openshift oauth proxy.
	token string
}

// NewPrometheusClient creates and returns a new PrometheusClient.
func NewPrometheusClient(
	routeClient routev1.RouteV1Interface,
	kubeClient kubernetes.Interface,
) (*PrometheusClient, error) {
	route, err := routeClient.Routes("openshift-monitoring").Get("prometheus-k8s", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	host := route.Spec.Host

	secrets, err := kubeClient.CoreV1().Secrets("openshift-monitoring").List(metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var token string

	for _, secret := range secrets.Items {
		if strings.Contains(secret.Name, "cluster-monitoring-operator-e2e-token-") {
			token = string(secret.Data["token"])
		}
	}

	return &PrometheusClient{
		host:  host,
		token: token,
	}, nil
}

// Query runs an http get request against the Prometheus query api and returns
// the response body.
func (c *PrometheusClient) Query(query string) ([]byte, error) {
	// #nosec
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", "https://"+c.host+"/api/v1/query", nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("query", query)
	req.URL.RawQuery = q.Encode()

	req.Header.Add("Authorization", "Bearer "+c.token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// GetFirstValueFromPromQuery takes a query api response body and returns the
// value of the first timeseries. If body contains multiple timeseries
// GetFirstValueFromPromQuery errors.
func GetFirstValueFromPromQuery(body []byte) (int, error) {
	res, err := gabs.ParseJSON(body)
	if err != nil {
		return 0, err
	}

	count, err := res.ArrayCountP("data.result")
	if err != nil {
		return 0, err
	}

	if count != 1 {
		return 0, fmt.Errorf("expected body to contain single timeseries but got %v", count)
	}

	timeseries, err := res.ArrayElementP(0, "data.result")
	if err != nil {
		return 0, err
	}

	value, err := timeseries.ArrayElementP(1, "value")
	if err != nil {
		return 0, err
	}

	v, err := strconv.Atoi(value.Data().(string))
	if err != nil {
		return 0, fmt.Errorf("failed to parse query value: %v", err)
	}

	return v, nil
}

// WaitForQueryReturnGreaterEqualOne see WaitForQueryReturn.
func (c *PrometheusClient) WaitForQueryReturnGreaterEqualOne(t *testing.T, timeout time.Duration, query string) {
	c.WaitForQueryReturn(t, timeout, query, func(v int) error {
		if v >= 1 {
			return nil
		}

		return fmt.Errorf("expected value to equal or greater than 1 but got %v", v)
	})
}

// WaitForQueryReturnOne see WaitForQueryReturn.
func (c *PrometheusClient) WaitForQueryReturnOne(t *testing.T, timeout time.Duration, query string) {
	c.WaitForQueryReturn(t, timeout, query, func(v int) error {
		if v == 1 {
			return nil
		}

		return fmt.Errorf("expected value to equal 1 but got %v", v)
	})
}

// WaitForQueryReturn waits for a given PromQL query for a given time interval
// and validates the **first and only** result with the given validate function.
func (c *PrometheusClient) WaitForQueryReturn(t *testing.T, timeout time.Duration, query string, validate func(int) error) {
	err := wait.Poll(5*time.Second, timeout, func() (bool, error) {
		defer t.Log("---------------------------\n")
		body, err := c.Query(query)
		if err != nil {
			return false, err
		}

		v, err := GetFirstValueFromPromQuery(body)
		if err != nil {
			t.Logf("failed to extract first value from query response for query %q: %v", query, err)
			return false, nil
		}

		if err := validate(v); err != nil {
			t.Logf("unexpected value for query %q: %v", query, err)
			return false, nil
		}

		t.Logf("query %q succeeded", query)
		return true, nil
	})

	if err != nil {
		t.Fatal(err)
	}
}
