package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
)

// TestSecretsReconciliation tests whether the secrets created by the operator are reconciled correctly. These include:
// * unsynced secrets: secrets that are deployed by, but not synced by the operator, and,
// * synced secrets: secrets that are deployed by, and should be synced by the operator.

func TestSecretsReconciliation(t *testing.T) {
	// Create assets under both scenarios for us to work with.
	setupUserWorkloadAssetsWithTeardownHook(t, f)
	userWorkloadConfigMap := f.BuildUserWorkloadConfigMap(t, `alertmanager:
  enabled: true
`)
	f.MustCreateOrUpdateConfigMap(t, userWorkloadConfigMap)
	defer f.MustDeleteConfigMap(t, userWorkloadConfigMap)

	f.AssertStatefulSetExistsAndRolloutFunc("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)
	f.AssertServiceExistsFunc("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)
	f.AssertSecretExistsFunc("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)

	// List of secrets that should not be synced during operator's reconciliation.
	unsyncedSecrets := []types.NamespacedName{
		{
			Name:      "alertmanager-main",
			Namespace: f.Ns,
		},
		{
			Name:      "alertmanager-user-workload",
			Namespace: f.UserWorkloadMonitoringNs,
		},
		{
			Name:      "thanos-ruler-user-workload-config",
			Namespace: f.UserWorkloadMonitoringNs,
		},
		{
			Name:      "thanos-ruler-user-workload-web-config",
			Namespace: f.UserWorkloadMonitoringNs,
		},
	}

	// Restore unsynced secrets to their original state after the test.
	// Synced secrets don't need restoration since the operator reconciles those.
	t.Cleanup(func() {
		for _, secret := range unsyncedSecrets {
			gotSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			require.NoError(t, err)
			data := gotSecret.Data
			for k, v := range data {
				if isSecretDataJSONEncoded(gotSecret) {
					var jsonData map[string]interface{}
					err := json.Unmarshal(v, &jsonData)
					require.NoErrorf(t, err, "failed to unmarshal JSON in %s", secret.String())
					delete(jsonData, t.Name())
					restored, err := json.Marshal(jsonData)
					require.NoErrorf(t, err, "failed to marshal JSON in %s", secret.String())
					data[k] = restored
				} else {
					data[k] = []byte(strings.TrimPrefix(string(v), t.Name()))
				}
			}
			_, err = f.KubeClient.CoreV1().Secrets(secret.Namespace).Update(context.Background(), gotSecret, metav1.UpdateOptions{})
			require.NoError(t, err)
		}
	})

	// Fetch all secrets since we are responsible for the whole namespace.
	var syncedSecrets []types.NamespacedName
	secretsNS, err := f.KubeClient.CoreV1().Secrets(f.Ns).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	secretsUWMNS, err := f.KubeClient.CoreV1().Secrets(f.UserWorkloadMonitoringNs).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)

	for _, secret := range append(secretsNS.Items, secretsUWMNS.Items...) {
		nn := types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		}
		if slices.Contains(unsyncedSecrets, nn) {
			continue
		}
		// Skip TLS secrets since they have hash suffixes and get rotated (replaced, not updated in-place).
		if strings.Contains(secret.Name, "tls") {
			continue
		}
		syncedSecrets = append(syncedSecrets, nn)
	}
	require.NotEmpty(t, syncedSecrets)

	secrets := append(syncedSecrets, unsyncedSecrets...)

	// Update the aforementioned secrets' data.
	for _, secret := range secrets {
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			gotSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			data := gotSecret.Data
			for k, v := range data {
				if isSecretDataJSONEncoded(gotSecret) {
					var jsonData map[string]interface{}
					if err := json.Unmarshal(v, &jsonData); err != nil {
						return err
					}
					jsonData[t.Name()] = t.Name()
					v, err = json.Marshal(jsonData)
					if err != nil {
						return err
					}
					data[k] = v
				} else {
					data[k] = []byte(t.Name() + string(v))
				}
				break
			}
			_, err = f.KubeClient.CoreV1().Secrets(secret.Namespace).Update(context.Background(), gotSecret, metav1.UpdateOptions{})
			return err
		})
		require.NoError(t, err)
	}

	// Trigger an operator reconciliation by annotating the cluster-monitoring-config
	// ConfigMap. The operator's event handler only enqueues reconciliation for a
	// specific set of ConfigMaps/Secrets, so mutating arbitrary secrets won't
	// trigger a sync on its own.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := f.KubeClient.CoreV1().ConfigMaps(f.Ns).Get(context.Background(), framework.ClusterMonitorConfigMapName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if cm.Annotations == nil {
			cm.Annotations = map[string]string{}
		}
		cm.Annotations["monitoring.openshift.io/trigger-reconciliation"] = time.Now().Format(time.RFC3339)
		_, err = f.KubeClient.CoreV1().ConfigMaps(f.Ns).Update(context.Background(), cm, metav1.UpdateOptions{})
		return err
	})
	require.NoError(t, err)

	// Check for reconciliation of secrets.
	for _, secret := range secrets {
		// Synced secrets should be reconciled, i.e., the test prefix must be removed.
		if slices.Contains(syncedSecrets, secret) {
			err := framework.Poll(10*time.Second, 5*time.Minute, func() error {
				updatedSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}

				data := updatedSecret.Data
				for _, v := range data {
					if !isSecretDataJSONEncoded(updatedSecret) {
						if strings.HasPrefix(string(v), t.Name()) {
							return fmt.Errorf("secret %s has unexpected data: %v", secret.String(), string(v))
						}
						// Don't return early. Since map iteration order is non-deterministic,
						// the mutated entry may not be the first one visited here.
						continue
					}

					var jsonData map[string]interface{}
					err = json.Unmarshal(v, &jsonData)
					if err != nil {
						return fmt.Errorf("failed to unmarshal JSON data in secret %s: %v", secret.String(), err)
					}
					if _, ok := jsonData[t.Name()]; ok {
						return fmt.Errorf("secret %s contains unexpected key %s", secret.String(), t.Name())
					}
				}

				return nil
			})
			require.NoError(t, err)
		}

		// Unsynced secrets should NOT be reconciled, i.e., the test prefix must still be present.
		// Only one entry was mutated, so we verify at least one entry still carries it.
		if slices.Contains(unsyncedSecrets, secret) {
			updatedSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			require.NoError(t, err)
			data := updatedSecret.Data
			found := false
			for _, v := range data {
				if isSecretDataJSONEncoded(updatedSecret) {
					var jsonData map[string]interface{}
					err := json.Unmarshal(v, &jsonData)
					require.NoErrorf(t, err, "failed to unmarshal JSON in %s", secret.String())
					if _, ok := jsonData[t.Name()]; ok {
						found = true
						break
					}
				} else if strings.HasPrefix(string(v), t.Name()) {
					found = true
					break
				}
			}
			require.True(t, found, fmt.Sprintf("secret %s was unexpectedly reconciled", secret.String()))
		}
	}
}

func isSecretDataJSONEncoded(secret *v1.Secret) bool {
	return secret.Type == v1.SecretTypeDockercfg || secret.Type == v1.SecretTypeDockerConfigJson
}
