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
	"flag"
	"log"
	"os"
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
	os.Exit(testMain(m))
}

// testMain circumvents the issue, that one can not call `defer` in TestMain, as
// `os.Exit` does not honor `defer` statements. For more details see:
// http://blog.englund.nu/golang,/testing/2017/03/12/using-defer-in-testmain.html
func testMain(m *testing.M) int {
	kubeConfigPath := flag.String(
		"kubeconfig",
		clientcmd.RecommendedHomeFile,
		"kube config path, default: $HOME/.kube/config",
	)

	opImageName := flag.String(
		"operator-image",
		"",
		"operator image, e.g. quay.io/coreos/cluster-monitoring-operator",
	)

	flag.Parse()

	var err error
	f, err = framework.New(*kubeConfigPath, *opImageName)
	if err != nil {
		log.Fatal(err)
	}

	cleanUp, err := f.Setup()
	// Check cleanUp first, in case of an err, we still want to clean up.
	if cleanUp != nil {
		defer cleanUp()
	}
	if err != nil {
		log.Fatal(err)
	}

	// Wait for Prometheus operator.
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.Apps().Deployments(f.Ns).Get("prometheus-operator", metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		log.Fatal(err)
	}

	return m.Run()
}

func TestQueryPrometheus(t *testing.T) {
	t.Parallel()

	promClient, err := framework.NewPrometheusClient(f.OpenshiftRouteClient, f.KubeClient)
	if err != nil {
		t.Fatal(err)
	}

	queries := []struct {
		query   string
		expectN int
	}{
		{
			query:   `up{job="node-exporter"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="kubelet"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="scheduler"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="kube-controller-manager"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="apiserver"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="kube-state-metrics"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="prometheus-k8s"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="prometheus-operator"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="alertmanager-main"} == 1`,
			expectN: 2,
		}, {
			query:   `up{job="crio"} == 1`,
			expectN: 1,
		}, {
			query:   `namespace:container_memory_usage_bytes:sum`,
			expectN: 1,
		},
	}

	// Wait for pod to respond at queries at all. Then start verifying their results.
	var loopErr error
	err = wait.Poll(5*time.Second, 1*time.Minute, func() (bool, error) {
		_, loopErr := promClient.Query("up")
		return loopErr == nil, nil
	})
	if err != nil {
		t.Fatal(errors.Wrapf(err, "wait for prometheus-k8s: %v", loopErr))
	}

	err = wait.Poll(5*time.Second, 1*time.Minute, func() (bool, error) {
		defer t.Log("---------------------------\n")

		for _, q := range queries {
			n, err := promClient.Query(q.query)
			if err != nil {
				return false, err
			}
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
