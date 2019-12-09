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
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"

	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestTelemeterTrustedCA(t *testing.T) {
	var (
		factory = manifests.NewFactory("openshift-monitoring", "", nil)
		newCM   *v1.ConfigMap
		lastErr error
	)

	// Wait for the new ConfigMap to be created
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		cm, err := f.KubeClient.CoreV1().ConfigMaps(f.Ns).Get("telemeter-trusted-ca-bundle", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting trusted CA ConfigMap failed")
		if err != nil {
			return false, nil
		}

		newCM = factory.HashTrustedCA(cm, "telemeter")
		if newCM == nil {
			lastErr = errors.New("no trusted CA bundle data available")
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}

	// Wait for the new hashed ConfigMap to be created
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		_, err := f.KubeClient.CoreV1().ConfigMaps(f.Ns).Get(newCM.Name, metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting new hashed trusted CA ConfigMap failed")
		if err != nil {
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}

	// Get telemeter-client deployment and make sure it has a volume mounted with
	// telemeter-trusted-ca-bundle name.
	err = wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		d, err := f.KubeClient.AppsV1().Deployments(f.Ns).Get("telemeter-client", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting telemeter deployment failed")
		if err != nil {
			return false, nil
		}

		if len(d.Spec.Template.Spec.Containers[0].VolumeMounts) == 0 {
			return false, errors.New("Could not find any VolumeMounts, expected at least 1")
		}

		for _, mount := range d.Spec.Template.Spec.Containers[0].VolumeMounts {
			if mount.Name == "telemeter-trusted-ca-bundle" {
				return true, nil
			}
		}

		lastErr = fmt.Errorf("no volume %s mounted", newCM.Name)
		return false, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		t.Fatal(err)
	}
}
