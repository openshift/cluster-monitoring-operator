// Copyright 2024 The Cluster Monitoring Operator Authors
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
	"slices"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

const (
	// cmoManagedBySelector matches the Secrets and ConfigMaps that are created
	// and managed by the Cluster Monitoring Operator.
	cmoManagedBySelector = "app.kubernetes.io/managed-by=cluster-monitoring-operator"

	// reconcileMutationKey is the data key injected into an object to detect
	// whether CMO reconciles it back to its desired state.
	reconcileMutationKey = "cmo-e2e-reconcile-mutation"
)

// TestReconcileObjects verifies that CMO reconciles (restores) the Secrets and
// ConfigMaps it manages after they are mutated, while leaving the small set of
// user-owned objects untouched.
//
// Rather than maintaining an explicit list of every reconciled ("synced")
// object, the test only tracks the "unsynced" objects that CMO creates with
// CreateIfNotExist and never overwrites. Every other CMO-managed object
// (discovered via the app.kubernetes.io/managed-by=cluster-monitoring-operator
// label) is expected to be reconciled.
func TestReconcileObjects(t *testing.T) {
	// unsyncedSecrets are user-owned Secrets that CMO only creates when they
	// are missing (CreateIfNotExistSecret): the platform and user-workload
	// Alertmanager configurations.
	unsyncedSecrets := map[string][]string{
		f.Ns:                       {"alertmanager-main"},
		f.UserWorkloadMonitoringNs: {"alertmanager-user-workload"},
	}

	// unsyncedConfigMaps are ConfigMaps that CMO only creates when they are
	// missing (CreateIfNotExistConfigMap): the user-owned user-workload config
	// and the telemeter trusted CA bundle, whose content is injected and
	// maintained outside of CMO.
	unsyncedConfigMaps := map[string][]string{
		f.Ns:                       {"telemeter-trusted-ca-bundle"},
		f.UserWorkloadMonitoringNs: {"user-workload-monitoring-config"},
	}

	// Enable user-workload monitoring (and its Alertmanager) so that the
	// relevant objects exist in both namespaces, and register cleanup.
	setupUserWorkloadAssetsWithTeardownHook(t, f)

	uwmCM := f.BuildUserWorkloadConfigMap(t, `alertmanager:
  enabled: true
`)
	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	t.Cleanup(func() { f.MustDeleteConfigMap(t, uwmCM) })
	f.AssertStatefulSetExistsAndRolloutFunc("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)

	// trackedObject is a Secret or ConfigMap that the test mutated and will
	// later assert on.
	type trackedObject struct {
		kind      string // "Secret" or "ConfigMap"
		namespace string
		name      string
		synced    bool // true if CMO is expected to reconcile (restore) it
	}

	var tracked []trackedObject

	// addSecretMarker and addConfigMapMarker inject the mutation marker into an
	// object. Conflicts are retried because other controllers (service-ca,
	// cluster-network-operator, prometheus-operator) may be writing to these
	// objects concurrently.
	addSecretMarker := func(ns, name string) error {
		return retry.RetryOnConflict(retry.DefaultRetry, func() error {
			s, err := f.KubeClient.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if s.Data == nil {
				s.Data = make(map[string][]byte)
			}
			s.Data[reconcileMutationKey] = []byte("true")
			_, err = f.KubeClient.CoreV1().Secrets(ns).Update(ctx, s, metav1.UpdateOptions{})
			return err
		})
	}
	addConfigMapMarker := func(ns, name string) error {
		return retry.RetryOnConflict(retry.DefaultRetry, func() error {
			cm, err := f.KubeClient.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if cm.Data == nil {
				cm.Data = make(map[string]string)
			}
			cm.Data[reconcileMutationKey] = "true"
			_, err = f.KubeClient.CoreV1().ConfigMaps(ns).Update(ctx, cm, metav1.UpdateOptions{})
			return err
		})
	}

	// Step 1: mutate the explicitly-listed unsynced objects by name. These must
	// NOT be reconciled. Objects that do not exist on this cluster (for example
	// the telemeter bundle when telemetry is disabled) are skipped.
	mutateUnsynced := func(kind string, unsynced map[string][]string, add func(ns, name string) error) {
		for ns, names := range unsynced {
			for _, name := range names {
				err := add(ns, name)
				if apierrors.IsNotFound(err) {
					t.Logf("skipping absent unsynced %s %s/%s", kind, ns, name)
					continue
				}
				require.NoError(t, err, "mutating unsynced %s %s/%s", kind, ns, name)
				tracked = append(tracked, trackedObject{kind: kind, namespace: ns, name: name, synced: false})
			}
		}
	}
	mutateUnsynced("Secret", unsyncedSecrets, addSecretMarker)
	mutateUnsynced("ConfigMap", unsyncedConfigMaps, addConfigMapMarker)

	// Step 2: discover all CMO-managed objects and mutate the ones that are not
	// explicitly listed as unsynced. These are expected to be reconciled.
	for _, ns := range []string{f.Ns, f.UserWorkloadMonitoringNs} {
		secrets, err := f.KubeClient.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{LabelSelector: cmoManagedBySelector})
		require.NoError(t, err, "listing CMO-managed secrets in %s", ns)
		for _, s := range secrets.Items {
			if slices.Contains(unsyncedSecrets[ns], s.Name) {
				continue
			}
			require.NoError(t, addSecretMarker(ns, s.Name), "mutating synced secret %s/%s", ns, s.Name)
			tracked = append(tracked, trackedObject{kind: "Secret", namespace: ns, name: s.Name, synced: true})
		}

		cms, err := f.KubeClient.CoreV1().ConfigMaps(ns).List(ctx, metav1.ListOptions{LabelSelector: cmoManagedBySelector})
		require.NoError(t, err, "listing CMO-managed configmaps in %s", ns)
		for _, cm := range cms.Items {
			if slices.Contains(unsyncedConfigMaps[ns], cm.Name) {
				continue
			}
			require.NoError(t, addConfigMapMarker(ns, cm.Name), "mutating synced configmap %s/%s", ns, cm.Name)
			tracked = append(tracked, trackedObject{kind: "ConfigMap", namespace: ns, name: cm.Name, synced: true})
		}
	}

	// Sanity check: make sure the test is actually exercising both behaviours,
	// otherwise a mislabeled selector or empty namespace would make it pass
	// vacuously.
	var syncedSecrets, syncedConfigMaps, unsyncedTracked int
	for _, o := range tracked {
		switch {
		case !o.synced:
			unsyncedTracked++
		case o.kind == "Secret":
			syncedSecrets++
		default:
			syncedConfigMaps++
		}
	}
	require.Positive(t, syncedSecrets, "expected to discover at least one synced Secret")
	require.Positive(t, syncedConfigMaps, "expected to discover at least one synced ConfigMap")
	require.Positive(t, unsyncedTracked, "expected to mutate at least one unsynced object")

	// Step 3: trigger a reconciliation by updating the CMO configmap.
	f.MustCreateOrUpdateConfigMap(t, f.BuildCMOConfigMap(t, "enableUserWorkload: true"))

	markerPresent := func(o trackedObject) (bool, error) {
		switch o.kind {
		case "Secret":
			s, err := f.KubeClient.CoreV1().Secrets(o.namespace).Get(ctx, o.name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			_, ok := s.Data[reconcileMutationKey]
			return ok, nil
		default:
			cm, err := f.KubeClient.CoreV1().ConfigMaps(o.namespace).Get(ctx, o.name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			_, ok := cm.Data[reconcileMutationKey]
			return ok, nil
		}
	}

	// Step 4: wait until every synced object has had its marker removed. CMO
	// reconciles the whole object (library-go Apply* replaces the data), so the
	// marker disappearing proves the object was restored to its desired state.
	err := framework.Poll(5*time.Second, 5*time.Minute, func() error {
		for _, o := range tracked {
			if !o.synced {
				continue
			}
			present, err := markerPresent(o)
			if apierrors.IsNotFound(err) {
				// A synced object that CMO deleted/recreated counts as reconciled.
				continue
			}
			if err != nil {
				return fmt.Errorf("getting %s %s/%s: %w", o.kind, o.namespace, o.name, err)
			}
			if present {
				return fmt.Errorf("%s %s/%s still carries the %q marker", o.kind, o.namespace, o.name, reconcileMutationKey)
			}
		}
		return nil
	})
	require.NoError(t, err, "CMO did not reconcile all synced objects")

	// Step 5: the unsynced objects must have kept the marker (CMO must not
	// touch them).
	for _, o := range tracked {
		if o.synced {
			continue
		}
		present, err := markerPresent(o)
		require.NoError(t, err, "getting unsynced %s %s/%s", o.kind, o.namespace, o.name)
		require.True(t, present,
			"unsynced %s %s/%s should have kept the %q marker", o.kind, o.namespace, o.name, reconcileMutationKey)
	}
}
