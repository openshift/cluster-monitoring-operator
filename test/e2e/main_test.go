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
	"context"
	"flag"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/clientcmd"
)

var f *framework.Framework

func TestMain(m *testing.M) {
	if err := testMain(m); err != nil {
		log.Fatal(err)
	}
}

// testMain circumvents the issue, that one can not call `defer` in TestMain, as
// `os.Exit` does not honor `defer` statements. For more details see:
// http://blog.englund.nu/golang,/testing/2017/03/12/using-defer-in-testmain.html
func testMain(m *testing.M) error {
	ctx := context.Background()
	kubeConfigPath := flag.String(
		"kubeconfig",
		clientcmd.RecommendedHomeFile,
		"kube config path, default: $HOME/.kube/config",
	)

	flag.Parse()

	var (
		err     error
		cleanUp func() error
	)
	f, cleanUp, err = framework.New(*kubeConfigPath)
	// Check cleanUp first, in case of an err, we still want to clean up.
	if cleanUp != nil {
		defer cleanUp()
	}
	if err != nil {
		return err
	}

	// Wait for Prometheus operator.
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.AppsV1().Deployments(f.Ns).Get(ctx, "prometheus-operator", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		return err
	}

	// Wait for Prometheus.
	var loopErr error
	err = wait.Poll(5*time.Second, 1*time.Minute, func() (bool, error) {
		var (
			body []byte
			v    int
		)
		body, loopErr = f.ThanosQuerierClient.PrometheusQuery("count(last_over_time(up{job=\"prometheus-k8s\"}[2m]))")
		if loopErr != nil {
			loopErr = errors.Wrap(loopErr, "error executing prometheus query")
			return false, nil
		}

		v, loopErr = framework.GetFirstValueFromPromQuery(body)
		if loopErr != nil {
			loopErr = errors.Wrapf(loopErr, "error getting first value from prometheus response %q", string(body))
			return false, nil
		}

		if v != 2 {
			loopErr = fmt.Errorf("expected 2 Prometheus instances but got: %v", v)
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		return errors.Wrapf(err, "wait for prometheus-k8s: %v", loopErr)
	}

	if m.Run() != 0 {
		return errors.New("tests failed")
	}

	return nil
}

func TestTargetsUp(t *testing.T) {
	ctx := context.Background()

	// Check that all targets are up initially.
	testTargetsUp(t)

	// Delete the client TLS certificate used by Prometheus to scrape endpoints.
	// CMO should recreate it and the new certificate should still be trusted
	// by the endpoints. If a endpoint remains down, it's probably because it
	// doesn't use the cluster CA bundle.
	// See https://issues.redhat.com/browse/OCPBUGS-4521.
	metricsClientCertSecret, err := f.ManifestsFactory.MetricsClientCerts()
	if err != nil {
		t.Fatal(err)
	}
	err = f.KubeClient.CoreV1().Secrets(metricsClientCertSecret.Namespace).Delete(ctx, metricsClientCertSecret.Name, metav1.DeleteOptions{})

	f.AssertSecretExists(metricsClientCertSecret.GetName(), f.Ns)(t)

	// We need to wait a bit before verifying that all targets are up because
	// it will take some time for the kubelet to propagate the new certificate
	// to the Prometheus container. 2 minutes should be more than enough.
	time.Sleep(120 * time.Second)
	testTargetsUp(t)
}

func testTargetsUp(t *testing.T) {
	// Don't run this test in parallel, as other tests might trigger scrape failures.
	t.Helper()

	targets := []string{
		"node-exporter",
		"kube-state-metrics",
		"kubelet",
		"prometheus-k8s",
		"prometheus-k8s-thanos-sidecar",
		"prometheus-operator",
		"alertmanager-main",
		"cluster-monitoring-operator",
		"openshift-state-metrics",
		"telemeter-client",
		"thanos-querier",
	}

	for _, target := range targets {
		f.ThanosQuerierClient.WaitForQueryReturnOne(
			t,
			time.Minute,
			"max(up{job=\""+target+"\"})",
		)
	}

}

// Once we have the need to test multiple recording rules, we can unite them in
// a single test function.
func TestMemoryUsageRecordingRule(t *testing.T) {
	f.ThanosQuerierClient.WaitForQueryReturnGreaterEqualOne(
		t,
		time.Minute,
		"count(namespace:container_memory_usage_bytes:sum)",
	)
}
