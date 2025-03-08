package e2e

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"
)

func extractNamespacedNameFromFile[T metav1.ObjectMetaAccessor](t *testing.T, file string) types.NamespacedName {
	t.Helper()

	data, err := os.ReadFile("../../assets/" + file)
	require.NoError(t, err)

	var s T
	require.NoError(t, yaml.Unmarshal(data, &s))
	return types.NamespacedName{
		Name:      s.GetObjectMeta().GetName(),
		Namespace: s.GetObjectMeta().GetNamespace(),
	}
}

func TestSecretsReconciliation(t *testing.T) {
	// List of secrets that should not be synced during operator's reconciliation.
	var (
		namespaceMonitoring                 = f.Ns
		namespaceUserWorkloadMonitoring     = f.UserWorkloadMonitoringNs
		extractNamespacedNameFromFileSecret = extractNamespacedNameFromFile[*v1.Secret]
	)
	unsyncedSecrets := []types.NamespacedName{
		extractNamespacedNameFromFileSecret(t, manifests.AlertmanagerConfig),
		extractNamespacedNameFromFileSecret(t, manifests.AlertmanagerUserWorkloadSecret),
	}
	syncedSecrets := []types.NamespacedName{
		extractNamespacedNameFromFileSecret(t, manifests.AlertmanagerRBACProxyMetricSecret),
		extractNamespacedNameFromFileSecret(t, manifests.AlertmanagerRBACProxySecret),
		extractNamespacedNameFromFileSecret(t, manifests.AlertmanagerRBACProxyWebSecret),
		extractNamespacedNameFromFileSecret(t, manifests.AlertmanagerUserWorkloadRBACProxyMetricSecret),
		extractNamespacedNameFromFileSecret(t, manifests.AlertmanagerUserWorkloadRBACProxySecret),
		extractNamespacedNameFromFileSecret(t, manifests.AlertmanagerUserWorkloadRBACProxyTenancySecret),
		extractNamespacedNameFromFileSecret(t, manifests.KubeStateMetricsKubeRbacProxySecret),
		extractNamespacedNameFromFileSecret(t, manifests.NodeExporterKubeRbacProxySecret),
		extractNamespacedNameFromFileSecret(t, manifests.OpenShiftStateMetricsKubeRbacProxySecret),
		extractNamespacedNameFromFileSecret(t, manifests.PrometheusK8sRBACProxyWebSecret),
		extractNamespacedNameFromFileSecret(t, manifests.PrometheusOperatorKubeRbacProxySecret),
		extractNamespacedNameFromFileSecret(t, manifests.PrometheusOperatorUserWorkloadKubeRbacProxySecret),
		extractNamespacedNameFromFileSecret(t, manifests.PrometheusRBACProxySecret),
		extractNamespacedNameFromFileSecret(t, manifests.PrometheusUserWorkloadRBACProxyFederateSecret),
		extractNamespacedNameFromFileSecret(t, manifests.PrometheusUserWorkloadRBACProxyMetricsSecret),
		extractNamespacedNameFromFileSecret(t, manifests.TelemeterClientKubeRbacProxySecret),
		extractNamespacedNameFromFileSecret(t, manifests.ThanosQuerierRBACProxyMetricsSecret),
		extractNamespacedNameFromFileSecret(t, manifests.ThanosQuerierRBACProxyRulesSecret),
		extractNamespacedNameFromFileSecret(t, manifests.ThanosQuerierRBACProxySecret),
		extractNamespacedNameFromFileSecret(t, manifests.ThanosQuerierRBACProxyWebSecret),
		extractNamespacedNameFromFileSecret(t, manifests.ThanosRulerAlertmanagerConfigSecret),
		extractNamespacedNameFromFileSecret(t, manifests.ThanosRulerQueryConfigSecret),
		extractNamespacedNameFromFileSecret(t, manifests.ThanosRulerRBACProxyMetricsSecret),
		extractNamespacedNameFromFileSecret(t, manifests.ThanosRulerRBACProxyWebSecret),
		{
			Name:      "alert-relabel-configs",
			Namespace: namespaceMonitoring,
		},
		{
			Name:      "prometheus-k8s-additional-alertmanager-configs",
			Namespace: namespaceMonitoring,
		},
		{
			Name:      "prometheus-user-workload-additional-alertmanager-configs",
			Namespace: namespaceUserWorkloadMonitoring,
		},
	}

	// Create assets under both scenarios for us to work with.
	setupUserWorkloadAssetsWithTeardownHook(t, f)
	userWorkloadConfigMap := f.BuildUserWorkloadConfigMap(t, `alertmanager:
  enabled: true
`)
	f.MustCreateOrUpdateConfigMap(t, userWorkloadConfigMap)
	defer f.MustDeleteConfigMap(t, userWorkloadConfigMap)
	for _, secret := range []types.NamespacedName{
		extractNamespacedNameFromFileSecret(t, manifests.AlertmanagerRBACProxyMetricSecret),
		extractNamespacedNameFromFileSecret(t, manifests.AlertmanagerUserWorkloadRBACProxyMetricSecret),
	} {
		f.AssertSecretExists(secret.Name, secret.Namespace)(t)
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
