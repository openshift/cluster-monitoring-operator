package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestSecretsReconciliation(t *testing.T) {
	// Create assets under both scenarios for us to work with.
	setupUserWorkloadAssetsWithTeardownHook(t, f)
	userWorkloadConfigMap := f.BuildUserWorkloadConfigMap(t, `alertmanager:
  enabled: true
`)
	f.MustCreateOrUpdateConfigMap(t, userWorkloadConfigMap)
	defer f.MustDeleteConfigMap(t, userWorkloadConfigMap)
	for _, secret := range []types.NamespacedName{
		{
			Name:      "alertmanager-kube-rbac-proxy-metric",
			Namespace: f.Ns,
		},
		{
			Name:      "alertmanager-kube-rbac-proxy-metric",
			Namespace: f.UserWorkloadMonitoringNs,
		},
	} {
		f.AssertSecretExists(secret.Name, secret.Namespace)(t)
	}

	// List of secrets that should not be synced during operator's reconciliation.
	unsyncedSecrets := []types.NamespacedName{
		{
			Name:      "telemeter-client",
			Namespace: f.Ns,
		},
		{
			Name:      "alertmanager-main",
			Namespace: f.Ns,
		},
		{
			Name:      "alertmanager-user-workload",
			Namespace: f.UserWorkloadMonitoringNs,
		},
	}
	cleanup := func() {
		// Restore all unsynced secrets to their original state.
		for _, secret := range unsyncedSecrets {
			gotSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					continue
				}
				require.NoError(t, err)
			}
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

	// Prepare synced secrets.
	var syncedSecrets []types.NamespacedName
	secretsNS, err := f.KubeClient.CoreV1().Secrets(f.Ns).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=cluster-monitoring-operator",
	})
	require.NoError(t, err)
	secretsUWMNS, err := f.KubeClient.CoreV1().Secrets(f.UserWorkloadMonitoringNs).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/managed-by=cluster-monitoring-operator",
	})
	require.NoError(t, err)
	for _, secret := range append(secretsNS.Items, secretsUWMNS.Items...) {
		encounteredUnsyncedSecret := false
		for _, unsyncedSecret := range unsyncedSecrets {
			if secret.Name == unsyncedSecret.Name &&
				secret.Namespace == unsyncedSecret.Namespace {
				encounteredUnsyncedSecret = true
				break
			}
		}
		if encounteredUnsyncedSecret {
			continue
		}
		syncedSecrets = append(syncedSecrets, types.NamespacedName{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		})
	}
	require.NotEmpty(t, syncedSecrets)

	// Update the aforementioned secrets' data.
	for _, secret := range append(syncedSecrets, unsyncedSecrets...) {
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
	}

	// Check if the secrets were reconciled as expected.
	for _, secret := range syncedSecrets {
		err := framework.Poll(time.Second, 6*time.Minute, func() error {
			updatedSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			data := updatedSecret.Data
			for _, v := range data {
				if strings.HasPrefix(string(v), t.Name()) {
					return fmt.Errorf("secret %s has unexpected data: %s", secret.String(), v)
				}
			}
			stringData := updatedSecret.StringData
			for _, v := range stringData {
				if strings.HasPrefix(v, t.Name()) {
					return fmt.Errorf("secret %s has unexpected stringData: %s", secret.String(), stringData)
				}
			}
			return nil
		})
		require.NoError(t, err)
	}

	// Check if the secrets were reconciled unexpectedly.
	for _, secret := range unsyncedSecrets {
		updatedSecret, err := f.KubeClient.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
		require.NoError(t, err)
		data, dataHasTestNamePrefix := updatedSecret.Data, false
		stringData, stringDataHasTestNamePrefix := updatedSecret.StringData, false
		for _, v := range data {
			if strings.HasPrefix(string(v), t.Name()) {
				dataHasTestNamePrefix = true
				break
			}
		}
		for _, v := range stringData {
			if strings.HasPrefix(v, t.Name()) {
				stringDataHasTestNamePrefix = true
				break
			}
		}
		require.True(t, dataHasTestNamePrefix || stringDataHasTestNamePrefix, fmt.Sprintf("secret %s was unexpectedly reconciled", secret.String()))
	}
}
