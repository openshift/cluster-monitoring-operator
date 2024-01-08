package tasks

import (
	"context"
	"fmt"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	}
	{
		dep, err := t.factory.MetricsServerDeployment()
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

	return t.removePrometheusAdapterResources(ctx)
}

func (t *MetricsServerTask) removePrometheusAdapterResources(ctx context.Context) error {
	pa := NewPrometheusAdapterTask(ctx, t.namespace, t.client, false, t.factory, t.config)
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus-adapter",
			Namespace: t.namespace,
		},
	}

	{
		pdb, err := pa.factory.PrometheusAdapterPodDisruptionBudget()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter PodDisruptionBudget failed: %w", err)
		}

		if pdb != nil {
			err = pa.client.DeletePodDisruptionBudget(ctx, pdb)
			if err != nil {
				return fmt.Errorf("deleting PrometheusAdapter PodDisruptionBudget failed: %w", err)
			}
		}
	}
	{
		sm, err := pa.factory.PrometheusAdapterServiceMonitor()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter ServiceMonitors failed: %w", err)
		}

		err = pa.client.DeleteServiceMonitor(ctx, sm)
		if err != nil {
			return fmt.Errorf("deleting %s/%s ServiceMonitor failed: %w", sm.Namespace, sm.Name, err)
		}
	}
	{
		s, err := pa.factory.PrometheusAdapterService()
		if err != nil {
			return fmt.Errorf("initializing PrometheusAdapter Service failed: %w", err)
		}

		err = pa.client.DeleteService(ctx, s)
		if err != nil {
			return fmt.Errorf("deleting PrometheusAdapter Service failed: %w", err)
		}
	}
	{
		err := pa.client.DeleteDeployment(ctx, d)
		if err != nil {
			return fmt.Errorf("deleting PrometheusAdapter Deployment failed: %w", err)
		}
	}

	// TODO(slashpai): Add steps to remove other resources if any
	return nil
}
