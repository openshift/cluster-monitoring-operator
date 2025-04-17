package e2e

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	}

	// Restore all unsynced secrets to their original state.
	cleanup := func() {
		for _, secret := range unsyncedSecrets {
			gotSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			require.NoError(t, err)
			data := gotSecret.Data
			stringData := gotSecret.StringData
			for k, v := range data {
				data[k] = []byte(strings.TrimPrefix(string(v), t.Name()))
			}
			for k, v := range stringData {
				stringData[k] = strings.TrimPrefix(v, t.Name())
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

	// Update the aforementioned secrets' data.
	secrets := append(syncedSecrets, unsyncedSecrets...)
	for _, secret := range secrets {
		gotSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		data := gotSecret.Data
		stringData := gotSecret.StringData
		for k, v := range data {
			data[k] = []byte(t.Name() + string(v))
			break
		}
		for k, v := range stringData {
			stringData[k] = t.Name() + v
			break
		}
		_, err = f.KubeClient.CoreV1().Secrets(secret.Namespace).Update(context.Background(), gotSecret, metav1.UpdateOptions{})
		require.NoError(t, err)

		// Check if the secrets were reconciled as expected.
		if slices.Contains(syncedSecrets, secret) {
			err := framework.Poll(time.Second, 6*time.Minute, func() error {
				updatedSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				data := updatedSecret.Data
				stringData := updatedSecret.StringData
				for _, v := range data {
					if strings.HasPrefix(string(v), t.Name()) {
						return fmt.Errorf("secret %s has unexpected data", secret.String())
					}
				}
				for _, v := range stringData {
					if strings.HasPrefix(v, t.Name()) {
						return fmt.Errorf("secret %s has unexpected stringData", secret.String())
					}
				}
				return nil
			})
			require.NoError(t, err)
		}

		// Check if the secrets were reconciled unexpectedly.
		if slices.Contains(unsyncedSecrets, secret) {
			updatedSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			require.NoError(t, err)
			for _, v := range updatedSecret.Data {
				require.False(t, strings.HasPrefix(string(v), t.Name()), fmt.Sprintf("secret %s was unexpectedly reconciled", secret.String()))
			}
			for _, v := range updatedSecret.StringData {
				require.False(t, strings.HasPrefix(v, t.Name()), fmt.Sprintf("secret %s was unexpectedly reconciled", secret.String()))
			}
		}
	}
}
