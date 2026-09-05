// Copyright 2026 The Cluster Monitoring Operator Authors
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
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const kubeletScrapeFailuresQuery = `sum(rate(metrics_server_kubelet_request_total{success="false"}[5m]))`

// TestMetricsServerKubeletScrapeFailures [apigroup:config.openshift.io] breaks kubelet
// client credentials and checks failed scrapes appear in Prometheus.
func TestMetricsServerKubeletScrapeFailures(t *testing.T) {
	const name = "metrics-server"
	ctx := context.Background()

	dep, err := f.KubeClient.AppsV1().Deployments(f.Ns).Get(ctx, name, metav1.GetOptions{})
	require.NoError(t, err, "getting metrics-server deployment")

	original := dep.DeepCopy()
	broken := dep.DeepCopy()
	found := false
	for i, c := range broken.Spec.Template.Spec.Containers {
		if c.Name != name {
			continue
		}
		for j, arg := range c.Args {
			if !strings.HasPrefix(arg, "--kubelet-client-certificate=") {
				continue
			}
			broken.Spec.Template.Spec.Containers[i].Args[j] = "--kubelet-client-certificate=/etc/tls/nonexistent/tls.crt"
			found = true
			break
		}
	}
	require.True(t, found, "metrics-server arg --kubelet-client-certificate not found")

	cv, err := f.GetClusterVersion("version")
	if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
		t.Skipf("ClusterVersion API unavailable: %v", err)
	}
	require.NoError(t, err, "getting ClusterVersion")

	originalOverrides, err := json.Marshal(cv.Spec.Overrides)
	require.NoError(t, err)

	overrides := append(append([]configv1.ComponentOverride{}, cv.Spec.Overrides...), configv1.ComponentOverride{
		Group: "apps", Kind: "Deployment", Name: name, Namespace: f.Ns, Unmanaged: true,
	})
	overridesJSON, err := json.Marshal(overrides)
	require.NoError(t, err)

	_, err = f.OpenShiftConfigClient.ConfigV1().ClusterVersions().Patch(ctx, "version", types.MergePatchType,
		[]byte(fmt.Sprintf(`{"spec":{"overrides":%s}}`, overridesJSON)), metav1.PatchOptions{})
	require.NoError(t, err, "marking metrics-server unmanaged")

	t.Cleanup(func() {
		t.Helper()
		_, err := f.KubeClient.AppsV1().Deployments(f.Ns).Update(ctx, original, metav1.UpdateOptions{})
		require.NoError(t, err, "restoring metrics-server deployment")
		f.AssertDeploymentExistsAndRolloutFunc(name, f.Ns)(t)

		restore := []byte(fmt.Sprintf(`{"spec":{"overrides":%s}}`, originalOverrides))
		_, err = f.OpenShiftConfigClient.ConfigV1().ClusterVersions().Patch(ctx, "version", types.MergePatchType, restore, metav1.PatchOptions{})
		require.NoError(t, err, "restoring ClusterVersion overrides")
	})

	_, err = f.KubeClient.AppsV1().Deployments(f.Ns).Update(ctx, broken, metav1.UpdateOptions{})
	require.NoError(t, err, "deploying broken metrics-server")
	f.AssertDeploymentExistsAndRolloutFunc(name, f.Ns)(t)

	f.PrometheusK8sClient.WaitForQueryReturnGreaterEqualOne(t, 8*time.Minute, kubeletScrapeFailuresQuery)
}
