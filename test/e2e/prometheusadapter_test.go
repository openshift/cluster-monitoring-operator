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
	"log"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestPrometheusAdapterCARotation(t *testing.T) {
	var lastErr error
	// Wait for Prometheus adapter
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.Apps().Deployments(f.Ns).Get("prometheus-adapter", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting prometheus-adapter deployment failed")
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		log.Fatal(err)
	}

	apiAuth, err := f.KubeClient.CoreV1().ConfigMaps("kube-system").Get("extension-apiserver-authentication", metav1.GetOptions{})
	if err != nil {
		log.Fatal(err)
	}

	tls, err := f.KubeClient.CoreV1().Secrets("openshift-monitoring").Get("prometheus-adapter-tls", metav1.GetOptions{})
	if err != nil {
		log.Fatal(err)
	}

	// Simulate rotation by simply adding a newline to existing certs.
	// This change will be propagated to the cluster monitoring operator,
	// causing a new secret to be created.
	apiAuth.Data["requestheader-client-ca-file"] = apiAuth.Data["requestheader-client-ca-file"] + "\n"
	apiAuth, err = f.KubeClient.CoreV1().ConfigMaps("kube-system").Update(apiAuth)
	if err != nil {
		log.Fatal(err)
	}

	factory := manifests.NewFactory("openshift-monitoring", nil)
	newSecret, err := factory.PrometheusAdapterSecret(tls, apiAuth)
	if err != nil {
		log.Fatal(err)
	}

	// Wait for the new secret to be created
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.CoreV1().Secrets(f.Ns).Get(newSecret.Name, metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting new api auth secret failed")
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		log.Fatal(err)
	}

	// Wait for new Prometheus adapter to roll out
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		d, err := f.KubeClient.Apps().Deployments(f.Ns).Get("prometheus-adapter", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting new prometheus adapter deployment failed")
		if err != nil {
			return false, nil
		}

		lastErr = fmt.Errorf("waiting for updated replica count=%d to be spec replica count=%d", d.Status.UpdatedReplicas, *d.Spec.Replicas)
		return d.Status.UpdatedReplicas == *d.Spec.Replicas, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		log.Fatal(err)
	}
}
