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
	"strings"
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
	kubeConfigPath := flag.String("kubeconfig", clientcmd.RecommendedHomeFile, "kube config path, default: $HOME/.kube/config")
	opImageName := flag.String("operator-image", "", "operator image, e.g. quay.io/coreos/cluster-monitoring-operator")

	flag.Parse()

	var err error
	f, err = framework.New(*kubeConfigPath, *opImageName)
	if err != nil {
		log.Fatal(err)
	}

	list, err := f.KubeClient.CoreV1().Pods("kube-system").List(metav1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}

	if list == nil {
		log.Fatal("expected list of pods not to be nil")
	}

	podNames := []string{}
	for _, p := range list.Items {
		podNames = append(podNames, p.GetName())
	}
	log.Printf("Found the following pods in kube-system namespace: %v", strings.Join(podNames, ","))
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
		}, {
			query:   `up{job="kubelet"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="kube-scheduler"} == 1`,
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
			query:   `up{job="prometheus"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="prometheus-operator"} == 1`,
			expectN: 1,
		}, {
			query:   `up{job="alertmanager-main"} == 1`,
			expectN: 2,
		}, {
			query:   `namespace:container_memory_usage_bytes:sum`,
			expectN: 1,
		},
	}

	// Wait for pod to respond at queries at all. Then start verifying their results.
	err := wait.Poll(5*time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.QueryPrometheus("prometheus-k8s-0", "up")
		return err == nil, nil
	})
	if err != nil {
		t.Fatal(errors.Wrap(err, "wait for prometheus-k8s"))
	}

	err = wait.Poll(5*time.Second, 10*time.Minute, func() (bool, error) {
		defer t.Log("---------------------------\n")

		for _, q := range queries {
			n, err := f.QueryPrometheus("prometheus-k8s-0", q.query)
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
