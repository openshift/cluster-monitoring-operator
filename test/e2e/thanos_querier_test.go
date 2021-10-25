// Copyright 2020 The Cluster Monitoring Operator Authors
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
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestThanosQuerierTrustedCA(t *testing.T) {
	ctx := context.Background()
	var (
		factory = manifests.NewFactory("openshift-monitoring", "", nil, nil, nil, manifests.NewAssets(assetsPath), &manifests.APIServerConfig{})
		newCM   *v1.ConfigMap
		lastErr error
	)

	// Wait for the new ConfigMap to be created
	err := wait.Poll(time.Second, 5*time.Minute, func() (bool, error) {
		cm, err := f.KubeClient.CoreV1().ConfigMaps(f.Ns).Get(ctx, "thanos-querier-trusted-ca-bundle", metav1.GetOptions{})
		lastErr = errors.Wrap(err, "getting new trusted CA ConfigMap failed")
		if err != nil {
			return false, nil
		}

		newCM, err = factory.HashTrustedCA(cm, "thanos-querier")
		lastErr = errors.Wrap(err, "no trusted CA bundle data available")
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

	for _, tc := range []scenario{
		{
			name:      "Wait for the new hashed trusted CA bundle ConfigMap to be created",
			assertion: f.AssertConfigmapExists(newCM.Name, f.Ns),
		},
		{
			name:      "assert deployment rolls out",
			assertion: f.AssertDeploymentExistsAndRollout("thanos-querier", f.Ns),
		},
		{
			name: "assert pod configuration is as expected",
			assertion: f.AssertPodConfiguration(
				f.Ns,
				"app.kubernetes.io/name=thanos-query",
				[]framework.PodAssertion{
					expectVolumeMountsInContainer("oauth-proxy", "thanos-querier-trusted-ca-bundle"),
				},
			),
		},
	} {
		t.Run(tc.name, tc.assertion)
	}
}

func TestThanosQueryCanQueryWatchdogAlert(t *testing.T) {
	// The 2 minute timeout is what console CI tests set.
	// If this test is flaky, we should increase until
	// we can fix the possible DNS resolve issues.
	f.ThanosQuerierClient.WaitForRulesReturn(
		t, 2*time.Minute,
		func(body []byte) error {
			return getThanosRules(body, "general.rules", "Watchdog")
		},
	)
}
