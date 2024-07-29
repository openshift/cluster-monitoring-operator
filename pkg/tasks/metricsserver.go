package tasks

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type MetricsServerTask struct {
	client    *client.Client
	enabled   bool
	ctx       context.Context
	factory   *manifests.Factory
	config    *manifests.Config
	namespace string
}

func NewMetricsServerTask(ctx context.Context, namespace string, client *client.Client, metricsServerEnabled bool, factory *manifests.Factory, config *manifests.Config) *MetricsServerTask {
	return &MetricsServerTask{
		client:    client,
		enabled:   metricsServerEnabled,
		factory:   factory,
		config:    config,
		namespace: namespace,
		ctx:       ctx,
	}
}

func (t *MetricsServerTask) Run(ctx context.Context) error {
	if t.enabled {
		return t.create(ctx)
	}
	return nil
}

func (t *MetricsServerTask) create(ctx context.Context) error {
	{
		// TODO: This is a temporary workaround until the requirements for https://github.com/openshift/cluster-monitoring-operator/pull/2329
		// are ready.
		// Because the metrics-server Pods rely on the system:serviceaccount:openshift-monitoring:prometheus-k8s SA to reach kubelet,
		// the task needs to ensure that the necessary RBAC permissions for that SA are set up before starting the Pods to avoid scrape failures.
		// For detailed information, refer to: https://issues.redhat.com/browse/OCPBUGS-32510.
		cr, err := t.factory.PrometheusK8sClusterRole()
		if err != nil {
			return fmt.Errorf("initializing Prometheus ClusterRole failed: %w", err)
		}

		err = t.client.CreateOrUpdateClusterRole(ctx, cr)
		if err != nil {
			return fmt.Errorf("reconciling Prometheus ClusterRole failed: %w", err)
		}

		crb, err := t.factory.PrometheusK8sClusterRoleBinding()
		if err != nil {
			return fmt.Errorf("initializing Prometheus ClusterRoleBinding failed: %w", err)
		}

		err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
		if err != nil {
			return fmt.Errorf("reconciling Prometheus ClusterRoleBinding failed: %w", err)
		}
	}
	{
		sa, err := t.factory.MetricsServerServiceAccount()
		if err != nil {
			return fmt.Errorf("initializing MetricsServer ServiceAccount failed: %w", err)
		}

		err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
		if err != nil {
			return fmt.Errorf("reconciling MetricsServer ServiceAccount failed: %w", err)
		}
	}
	{
		cr, err := t.factory.MetricsServerClusterRole()
		if err != nil {
			return fmt.Errorf("initializing metrics-server ClusterRolefailed: %w", err)
		}

		err = t.client.CreateOrUpdateClusterRole(ctx, cr)
		if err != nil {
			return fmt.Errorf("reconciling metrics-server ClusterRole failed: %w", err)
		}
	}
	{
		crb, err := t.factory.MetricsServerClusterRoleBinding()
		if err != nil {
			return fmt.Errorf("initializing MetricsServer ClusterRoleBinding failed: %w", err)
		}

		err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
		if err != nil {
			return fmt.Errorf("reconciling MetricsServer ClusterRoleBinding failed: %w", err)
		}
	}
	{
		crb, err := t.factory.MetricsServerClusterRoleBindingAuthDelegator()
		if err != nil {
			return fmt.Errorf("initializing metrics-server:system:auth-delegator ClusterRoleBinding failed: %w", err)
		}

		err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
		if err != nil {
			return fmt.Errorf("reconciling metrics-server:system:auth-delegator ClusterRoleBinding failed: %w", err)
		}
	}
	{
		rb, err := t.factory.MetricsServerRoleBindingAuthReader()
		if err != nil {
			return fmt.Errorf("initializing  metrics-server-auth-reader RoleBinding failed: %w", err)
		}

		err = t.client.CreateOrUpdateRoleBinding(ctx, rb)
		if err != nil {
			return fmt.Errorf("reconciling  metrics-server-auth-reader RoleBinding failed: %w", err)
		}
	}
	{
		s, err := t.factory.MetricsServerService()
		if err != nil {
			return fmt.Errorf("initializing MetricsServer Service failed: %w", err)
		}

		err = t.client.CreateOrUpdateService(ctx, s)
		if err != nil {
			return fmt.Errorf("reconciling MetricsServer Service failed: %w", err)
		}

		cacm, err := t.factory.PrometheusK8sKubeletServingCABundle(map[string]string{})
		if err != nil {
			return fmt.Errorf("initializing kubelet serving CA Bundle ConfigMap failed: %w", err)
		}

		cacm, err = t.client.WaitForConfigMap(
			ctx,
			cacm,
		)
		if err != nil {
			return err
		}

		scas, err := t.client.WaitForSecretByNsName(
			ctx,
			types.NamespacedName{
				Namespace: s.Namespace,
				Name:      s.Annotations["service.beta.openshift.io/serving-cert-secret-name"],
			},
		)
		if err != nil {
			return err
		}

		mcs, err := t.factory.MetricsClientCerts()
		if err != nil {
			return fmt.Errorf("initializing metrics-client-cert failed: %w", err)
		}

		mcs, err = t.client.WaitForSecret(
			ctx,
			mcs,
		)
		if err != nil {
			return err
		}

		{
			cm, err := t.factory.MetricsServerConfigMapAuditPolicy()
			if err != nil {
				return fmt.Errorf("initializing MetricsServer AuditPolicy ConfigMap failed: %w", err)
			}

			err = t.client.CreateOrUpdateConfigMap(ctx, cm)
			if err != nil {
				return fmt.Errorf("reconciling MetricsServer AuditPolicy ConfigMap failed: %w", err)
			}
		}

		tlsSecret, err := t.client.WaitForSecretByNsName(ctx, types.NamespacedName{Namespace: t.namespace, Name: "metrics-server-tls"})
		if err != nil {
			return fmt.Errorf("failed to wait for metrics-server-tls secret: %w", err)
		}

		apiAuthConfigmap, err := t.client.WaitForConfigMapByNsName(ctx, types.NamespacedName{Namespace: "kube-system", Name: "extension-apiserver-authentication"})
		if err != nil {
			return fmt.Errorf("failed to wait for kube-system/extension-apiserver-authentication configmap: %w", err)
		}

		secret, err := t.factory.MetricsServerSecret(tlsSecret, apiAuthConfigmap)
		if err != nil {
			return fmt.Errorf("failed to create metrics-server secret: %w", err)
		}

		err = t.deleteOldMetricsServerSecrets(secret.Labels["monitoring.openshift.io/hash"])
		if err != nil {
			return fmt.Errorf("deleting old metrics-server secrets failed: %w", err)
		}

		err = t.client.CreateOrUpdateSecret(ctx, secret)
		if err != nil {
			return fmt.Errorf("reconciling MetricsServer Secret failed: %w", err)
		}

		dep, err := t.factory.MetricsServerDeployment(secret.Name, cacm, scas, mcs, apiAuthConfigmap.Data)
		if err != nil {
			return fmt.Errorf("initializing MetricsServer Deployment failed: %w", err)
		}

		err = t.client.CreateOrUpdateDeployment(ctx, dep)
		if err != nil {
			return fmt.Errorf("reconciling MetricsServer Deployment failed: %w", err)
		}
	}
	{
		sm, err := t.factory.MetricsServerServiceMonitor()
		if err != nil {
			return fmt.Errorf("initializing MetricsServer ServiceMonitors failed: %w", err)
		}

		err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
		if err != nil {
			return fmt.Errorf("reconciling %s/%s ServiceMonitor failed: %w", sm.Namespace, sm.Name, err)
		}
	}
	{
		pdb, err := t.factory.MetricsServerPodDisruptionBudget()
		if err != nil {
			return fmt.Errorf("initializing MetricsServer PodDisruptionBudget failed: %w", err)
		}

		if pdb != nil {
			err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
			if err != nil {
				return fmt.Errorf("reconciling MetricsServer PodDisruptionBudget failed: %w", err)
			}
		}
	}
	{
		api, err := t.factory.MetricsServerAPIService()
		if err != nil {
			return fmt.Errorf("initializing MetricsServer APIService failed: %w", err)
		}

		err = t.client.CreateOrUpdateAPIService(ctx, api)
		if err != nil {
			return fmt.Errorf("reconciling MetricsServer APIService failed: %w", err)
		}
	}

	return nil
}

func (t *MetricsServerTask) deleteOldMetricsServerSecrets(newHash string) error {
	secrets, err := t.client.KubernetesInterface().CoreV1().Secrets(t.namespace).List(t.ctx, metav1.ListOptions{
		LabelSelector: "monitoring.openshift.io/name=metrics-server,monitoring.openshift.io/hash!=" + newHash,
	})

	if err != nil {
		return fmt.Errorf("error listing metrics-server secrets: %w", err)
	}

	for i := range secrets.Items {
		err := t.client.KubernetesInterface().CoreV1().Secrets(t.namespace).Delete(t.ctx, secrets.Items[i].Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("error deleting secret: %s: %w", secrets.Items[i].Name, err)
		}
	}

	return nil
}
