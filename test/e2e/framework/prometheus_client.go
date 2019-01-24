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
	"io/ioutil"
	"net/http"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// NewPrometheusClient returns creates and returns a new PrometheusClient.
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

// Query makes a request against the Prometheus /api/v1/query endpoint.
func (c *PrometheusClient) Query(query string) (int, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", "https://"+c.host+"/api/v1/query", nil)
	if err != nil {
		return 0, err
	}

	q := req.URL.Query()
	q.Add("query", query)
	req.URL.RawQuery = q.Encode()

	req.Header.Add("Authorization", "Bearer "+c.token)

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	res, err := gabs.ParseJSON(body)
	if err != nil {
		return 0, err
	}

	n, err := res.ArrayCountP("data.result")
	return n, err
}
