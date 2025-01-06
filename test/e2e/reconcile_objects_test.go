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
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// TestSecretsReconciliation tests whether the secrets created by the operator are reconciled correctly. These include:
// * unsynced secrets: secrets that are deployed by, but not synced by the operator, and,
// * synced secrets: secrets that are deployed by, and should be synced by the operator.

// TODO: Exclude all secrets that are initially empty and populated by other operators.
func TestSecretsReconciliation(t *testing.T) {
	// Create assets under both scenarios for us to work with.
	setupUserWorkloadAssetsWithTeardownHook(t, f)
	userWorkloadConfigMap := f.BuildUserWorkloadConfigMap(t, `alertmanager:
  enabled: true
`)
	f.MustCreateOrUpdateConfigMap(t, userWorkloadConfigMap)
	defer f.MustDeleteConfigMap(t, userWorkloadConfigMap)

	f.AssertStatefulSetExistsAndRollout("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)
	f.AssertServiceExists("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)
	f.AssertSecretExists("alertmanager-user-workload", f.UserWorkloadMonitoringNs)(t)

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

	// Restore all unsynced secrets to their original state.
	cleanup := func() {
		for _, secret := range unsyncedSecrets {
			gotSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				continue
			}
			require.NoError(t, err)
			data := gotSecret.Data
			for k, v := range data {
				data[k] = []byte(strings.TrimPrefix(string(v), t.Name()))
			}
			_, err = f.KubeClient.CoreV1().Secrets(secret.Namespace).Update(context.Background(), gotSecret, metav1.UpdateOptions{})
			require.NoError(t, err)
		}
	}
	defer cleanup()

	var syncedSecrets []types.NamespacedName
	secretsNS, err := f.KubeClient.CoreV1().Secrets(f.Ns).List(context.Background(), metav1.ListOptions{
		// Intentionally commented out as we want to fetch all secrets.
		// LabelSelector: "app.kubernetes.io/managed-by=cluster-monitoring-operator",
	})
	require.NoError(t, err)

	secretsUWMNS, err := f.KubeClient.CoreV1().Secrets(f.UserWorkloadMonitoringNs).List(context.Background(), metav1.ListOptions{
		// Intentionally commented out as we want to fetch all secrets.
		// LabelSelector: "app.kubernetes.io/managed-by=cluster-monitoring-operator",
	})
	require.NoError(t, err)

	for _, secret := range append(secretsNS.Items, secretsUWMNS.Items...) {
		secretNamespacedName := types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		}
		if slices.Contains(unsyncedSecrets, secretNamespacedName) {
			continue
		}
		syncedSecrets = append(syncedSecrets, secretNamespacedName)
	}
	require.NotEmpty(t, syncedSecrets)

	secrets := append(syncedSecrets, unsyncedSecrets...)

	var filteredSecrets []types.NamespacedName
	for _, secret := range secrets {
		if strings.Contains(secret.Name, "tls") {
			continue
		}
		filteredSecrets = append(filteredSecrets, secret)
	}

	// Update the aforementioned secrets' data.
	for _, secret := range filteredSecrets {
		var gotSecret *v1.Secret
		gotSecret, err = f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		data := gotSecret.Data
		for k, v := range data {
			if isSecretDataJSONEncoded(gotSecret) {
				var jsonData map[string]interface{}
				err = json.Unmarshal(v, &jsonData)
				require.NoError(t, err)
				jsonData[t.Name()] = t.Name()
				v, err = json.Marshal(jsonData)
				require.NoError(t, err)
				data[k] = v
			} else {
				data[k] = []byte(t.Name() + string(v))
			}
			break
		}

		_, err = f.KubeClient.CoreV1().Secrets(secret.Namespace).Update(context.Background(), gotSecret, metav1.UpdateOptions{})
		require.NoError(t, err)
	}

	// Check for reconciliation of secrets.
	for _, secret := range filteredSecrets {
		// Check if the secrets were reconciled as expected.
		if slices.Contains(syncedSecrets, secret) {
			err = framework.Poll(10*time.Second, 5*time.Minute, func() error {
				var updatedSecret *v1.Secret
				updatedSecret, err = f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}

				data := updatedSecret.Data
				for _, v := range data {
					if !isSecretDataJSONEncoded(updatedSecret) {
						if strings.HasPrefix(string(v), t.Name()) {
							return fmt.Errorf("secret %s has unexpected data: %v", secret.String(), string(v))
						}
						return nil
					}

					var jsonData map[string]interface{}
					err = json.Unmarshal(v, &jsonData)
					if err != nil {
						return fmt.Errorf("failed to unmarshal JSON data in secret %s: %v", secret.String(), err)
					}
					if _, ok := jsonData[t.Name()]; ok {
						return fmt.Errorf("secret %s does contains unexpected key %s", secret.String(), t.Name())
					}
				}

				return nil
			})

			require.NoError(t, err)
		}

		// Check if the secrets were reconciled unexpectedly.
		if slices.Contains(unsyncedSecrets, secret) {
			var updatedSecret *v1.Secret
			updatedSecret, err = f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			require.NoError(t, err)
			data := updatedSecret.Data
			for _, v := range data {
				require.False(t, strings.HasPrefix(string(v), t.Name()), fmt.Sprintf("secret %s was unexpectedly reconciled", secret.String()))
			}
		}
	}
}

func isSecretDataJSONEncoded(secret *v1.Secret) bool {
	return secret.Type == v1.SecretTypeDockercfg || secret.Type == v1.SecretTypeDockerConfigJson
}
