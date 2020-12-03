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

const assetsPath = "../../assets"

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
		_, err := f.KubeClient.AppsV1().Deployments(f.Ns).Get(context.TODO(), "prometheus-operator", metav1.GetOptions{})
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
		body, loopErr = f.ThanosQuerierClient.PrometheusQuery("count(up{job=\"prometheus-k8s\"})")
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
	// Don't run this test in parallel, as metrics might be influenced by other
	// tests.

	targets := []string{
		"node-exporter",
		"kube-state-metrics",
		"prometheus-k8s",
		"prometheus-operator",
		"alertmanager-main",
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
