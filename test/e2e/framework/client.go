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
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/Jeffail/gabs"
	routev1 "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PrometheusClient provides access to the Prometheus, Thanos & Alertmanager API.
type PrometheusClient struct {
	// Host address of the endpoint.
	host string
	// Bearer token to use for authentication.
	token string
	// RoundTripper to use for HTTP transactions.
	rt http.RoundTripper
}

// NewPrometheusClientFromRoute creates and returns a new PrometheusClient from the given OpenShift route.
func NewPrometheusClientFromRoute(
	routeClient routev1.RouteV1Interface,
	namespace, name string,
	token string,
) (*PrometheusClient, error) {
	route, err := routeClient.Routes(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return NewPrometheusClient(route.Spec.Host, token), nil
}

// WrapTransporter wraps an http.RoundTripper with another.
type WrapTransporter interface {
	WrapTransport(rt http.RoundTripper) http.RoundTripper
}

// NewPrometheusClient creates and returns a new PrometheusClient.
func NewPrometheusClient(host, token string, wts ...WrapTransporter) *PrometheusClient {
	// #nosec
	var rt http.RoundTripper = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	rt = (&HeaderInjector{Name: "Authorization", Value: "Bearer " + token}).WrapTransport(rt)
	for i := range wts {
		rt = wts[i].WrapTransport(rt)
	}
	return &PrometheusClient{
		host: host,
		rt:   rt,
	}
}

// MaxLength is the maximum string length returned by ClampMax().
const MaxLength = 1000

// ClampMax converts a slice of bytes to a string truncated to MaxLength.
func ClampMax(b []byte) string {
	s := string(b)
	if len(s) <= MaxLength {
		return s
	}
	return s[0:MaxLength-3] + "..."
}

// Do sends an HTTP request to the remote endpoint and returns the response.
func (c *PrometheusClient) Do(method string, path string, body []byte) (*http.Response, error) {
	u, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	u.Host = c.host
	u.Scheme = "https"

	req, err := http.NewRequest(method, u.String(), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	return (&http.Client{Transport: c.rt}).Do(req)
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// HeaderInjector injects a fixed HTTP header into the inbound request.
type HeaderInjector struct {
	Name  string
	Value string
}

// WrapTransport implements the WrapTransporter interface.
func (h *HeaderInjector) WrapTransport(rt http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(
		func(req *http.Request) (*http.Response, error) {
			req.Header.Add(h.Name, h.Value)
			return rt.RoundTrip(req)
		},
	)
}

// QueryParameterInjector injects a fixed query parameter into the inbound request.
// It is typically used when querying kube-rbac-proxy.
type QueryParameterInjector struct {
	Name  string
	Value string
}

// WrapTransport implements the WrapTransporter interface.
func (qp *QueryParameterInjector) WrapTransport(rt http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(
		func(req *http.Request) (*http.Response, error) {
			q := req.URL.Query()
			q.Add(qp.Name, qp.Value)
			req.URL.RawQuery = q.Encode()
			return rt.RoundTrip(req)
		},
	)
}

// PrometheusQuery runs an HTTP GET request against the Prometheus query API and returns
// the response body.
func (c *PrometheusClient) PrometheusQuery(query string) ([]byte, error) {
	resp, err := c.Do("GET", fmt.Sprintf("/api/v1/query?query=%s", url.QueryEscape(query)), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code response, want %d, got %d (%q)", http.StatusOK, resp.StatusCode, ClampMax(body))
	}

	return body, nil
}

// PrometheusRules runs an HTTP GET request against the Prometheus rules API and returns
// the response body.
func (c *PrometheusClient) PrometheusRules() ([]byte, error) {
	resp, err := c.Do("GET", "/api/v1/rules", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code response, want %d, got %d (%q)", http.StatusOK, resp.StatusCode, ClampMax(body))
	}

	return body, nil
}

// AlertmanagerQueryAlerts runs an HTTP GET request against the Alertmanager
// /api/v2/alerts endpoint and returns the response body.
func (c *PrometheusClient) AlertmanagerQueryAlerts(kvs ...string) ([]byte, error) {
	q := make(url.Values)
	for i := 0; i < len(kvs)/2; i++ {
		q.Add(kvs[i*2], kvs[i*2+1])
	}
	u := url.URL{
		Path:     "/api/v2/alerts",
		RawQuery: q.Encode(),
	}

	resp, err := c.Do("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code response, want %d, got %d (%q)", http.StatusOK, resp.StatusCode, ClampMax(body))
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

// GetResultSizeFromPromQuery takes a query api response body and returns the
// size of the result vector.
func GetResultSizeFromPromQuery(body []byte) (int, error) {
	res, err := gabs.ParseJSON(body)
	if err != nil {
		return 0, err
	}

	count, err := res.ArrayCountP("data.result")
	if err != nil {
		return 0, err
	}

	return count, nil
}

// WaitForQueryReturnGreaterEqualOne see WaitForQueryReturn.
func (c *PrometheusClient) WaitForQueryReturnGreaterEqualOne(t *testing.T, timeout time.Duration, query string) {
	t.Helper()

	c.WaitForQueryReturn(t, timeout, query, func(v int) error {
		if v >= 1 {
			return nil
		}

		return fmt.Errorf("expected value to equal or greater than 1 but got %v", v)
	})
}

// WaitForQueryReturnOne see WaitForQueryReturn.
func (c *PrometheusClient) WaitForQueryReturnOne(t *testing.T, timeout time.Duration, query string) {
	t.Helper()

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
	t.Helper()

	err := Poll(5*time.Second, timeout, func() error {
		body, err := c.PrometheusQuery(query)
		if err != nil {
			t.Fatal(err)
		}

		v, err := GetFirstValueFromPromQuery(body)
		if err != nil {
			return errors.Wrapf(err, "error getting first value from response body %q for query %q", string(body), query)
		}

		if err := validate(v); err != nil {
			return errors.Wrapf(err, "error validating response body %q for query %q", string(body), query)
		}

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}
}

// WaitForRulesReturn waits for Prometheus rules for a given time interval
// and validates the **first and only** result with the given validate function.
func (c *PrometheusClient) WaitForRulesReturn(t *testing.T, timeout time.Duration, validate func([]byte) error) {
	t.Helper()

	err := Poll(5*time.Second, timeout, func() error {
		body, err := c.PrometheusRules()
		if err != nil {
			t.Fatal(err)
		}

		if err := validate(body); err != nil {
			return errors.Wrapf(err, "error validating response body %q", string(body))
		}

		return nil
	})

	if err != nil {
		t.Fatal(err)
	}
}
