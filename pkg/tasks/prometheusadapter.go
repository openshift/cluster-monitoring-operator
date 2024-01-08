package tasks

import (
	"context"
	"fmt"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type PrometheusAdapterTask struct {
	client    *client.Client
	enabled   bool
	ctx       context.Context
	factory   *manifests.Factory
	config    *manifests.Config
	namespace string
}

func NewPrometheusAdapterTask(ctx context.Context, namespace string, client *client.Client, enabled bool, factory *manifests.Factory, config *manifests.Config) *PrometheusAdapterTask {
	return &PrometheusAdapterTask{
		client:    client,
		enabled:   enabled,
		factory:   factory,
		config:    config,
		namespace: namespace,
		ctx:       ctx,
	}
}

func (t *PrometheusAdapterTask) Run(ctx context.Context) error {
	if t.enabled {
		return t.create(ctx)
	}
	return nil
}

func (t *PrometheusAdapterTask) create(ctx context.Context) error {
	{
		cr, err := t.factory.PrometheusAdapterClusterRole()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter ClusterRole failed: %w", err)
		}

		err = t.client.CreateOrUpdateClusterRole(ctx, cr)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter ClusterRole failed: %w", err)
		}
	}
	{
		cr, err := t.factory.PrometheusAdapterClusterRoleServerResources()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter ClusterRole for server resources failed: %w", err)
		}

		err = t.client.CreateOrUpdateClusterRole(ctx, cr)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter ClusterRole for server resources failed: %w", err)
		}
	}
	{
		crb, err := t.factory.PrometheusAdapterClusterRoleBinding()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter ClusterRoleBinding failed: %w", err)
		}

		err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter ClusterRoleBinding failed: %w", err)
		}
	}
	{
		crb, err := t.factory.PrometheusAdapterClusterRoleBindingDelegator()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter ClusterRoleBinding for delegator failed: %w", err)
		}

		err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter ClusterRoleBinding for delegator failed: %w", err)
		}
	}
	{
		crb, err := t.factory.PrometheusAdapterClusterRoleBindingView()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter ClusterRoleBinding for view failed: %w", err)
		}

		err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter ClusterRoleBinding for view failed: %w", err)
		}
	}
	{
		rb, err := t.factory.PrometheusAdapterRoleBindingAuthReader()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter RoleBinding for auth-reader failed: %w", err)
		}

		err = t.client.CreateOrUpdateRoleBinding(ctx, rb)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter RoleBinding for auth-reader failed: %w", err)
		}
	}
	{
		sa, err := t.factory.PrometheusAdapterServiceAccount()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter ServiceAccount failed: %w", err)
		}

		err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter ServiceAccount failed: %w", err)
		}
	}
	{
		cm, err := t.factory.PrometheusAdapterConfigMapAuditPolicy()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter AuditPolicy ConfigMap failed: %w", err)
		}

		err = t.client.CreateOrUpdateConfigMap(ctx, cm)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter AuditPolicy ConfigMap failed: %w", err)
		}
	}
	{
		cm, err := t.factory.PrometheusAdapterConfigMapPrometheus()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter ConfigMap for Prometheus failed: %w", err)
		}

		err = t.client.CreateOrUpdateConfigMap(ctx, cm)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter ConfigMap for Prometheus failed: %w", err)
		}
	}
	{
		s, err := t.factory.PrometheusAdapterService()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter Service failed: %w", err)
		}

		err = t.client.CreateOrUpdateService(ctx, s)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter Service failed: %w", err)
		}
	}
	{
		cm, err := t.factory.PrometheusAdapterConfigMap()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter ConfigMap failed: %w", err)
		}
		err = t.client.CreateOrUpdateConfigMap(ctx, cm)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter ConfigMap failed: %w", err)
		}

		tlsSecret, err := t.client.WaitForSecretByNsName(ctx, types.NamespacedName{Namespace: t.namespace, Name: "prometheus-adapter-tls"})
		if err != nil {
			return fmt.Errorf("failed to wait for prometheus-adapter-tls secret: %w", err)
		}

		apiAuthConfigmap, err := t.client.WaitForConfigMapByNsName(ctx, types.NamespacedName{Namespace: "kube-system", Name: "extension-apiserver-authentication"})
		if err != nil {
			return fmt.Errorf("failed to wait for kube-system/extension-apiserver-authentication configmap: %w", err)
		}

		secret, err := t.factory.PrometheusAdapterSecret(tlsSecret, apiAuthConfigmap)
		if err != nil {
			return fmt.Errorf("failed to create prometheus adapter secret: %w", err)
		}

		err = t.deleteOldPrometheusAdapterSecrets(secret.Labels["monitoring.openshift.io/hash"])
		if err != nil {
			return fmt.Errorf("deleting old prometheus adapter secrets failed: %w", err)
		}

		err = t.client.CreateOrUpdateSecret(ctx, secret)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter Secret failed: %w", err)
		}

		dep, err := t.factory.PrometheusAdapterDeployment(secret.Name, apiAuthConfigmap.Data)
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter Deployment failed: %w", err)
		}

		err = t.client.CreateOrUpdateDeployment(ctx, dep)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter Deployment failed: %w", err)
		}
	}
	{
		pdb, err := t.factory.PrometheusAdapterPodDisruptionBudget()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter PodDisruptionBudget failed: %w", err)
		}

		if pdb != nil {
			err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
			if err != nil {
				return fmt.Errorf("reconciling PrometheusAdapter PodDisruptionBudget failed: %w", err)
			}
		}
	}
	{
		sms, err := t.factory.PrometheusAdapterServiceMonitors()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter ServiceMonitors failed: %w", err)
		}

		for _, sm := range sms {
			err = t.client.CreateOrUpdateServiceMonitor(ctx, sm)
			if err != nil {
				return fmt.Errorf("reconciling %s/%s ServiceMonitor failed: %w", sm.Namespace, sm.Name, err)
			}
		}
	}
	{
		api, err := t.factory.PrometheusAdapterAPIService()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter APIService failed: %w", err)
		}

		err = t.client.CreateOrUpdateAPIService(ctx, api)
		if err != nil {
			return fmt.Errorf("reconciling PrometheusAdapter APIService failed: %w", err)
		}
	}

	return nil
}

func (t *PrometheusAdapterTask) deleteOldPrometheusAdapterSecrets(newHash string) error {
	secrets, err := t.client.KubernetesInterface().CoreV1().Secrets(t.namespace).List(t.ctx, metav1.ListOptions{
		LabelSelector: "monitoring.openshift.io/name=prometheus-adapter,monitoring.openshift.io/hash!=" + newHash,
	})

	if err != nil {
		return fmt.Errorf("error listing prometheus adapter secrets: %w", err)
	}

	for i := range secrets.Items {
		err := t.client.KubernetesInterface().CoreV1().Secrets(t.namespace).Delete(t.ctx, secrets.Items[i].Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("error deleting secret: %s: %w", secrets.Items[i].Name, err)
		}
	}

	return nil
}
