package tasks

import (
	"context"
	"fmt"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type UserKubeStateMetricsDenyListTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewUserKubeStateMetricsDenyListTask(client *client.Client, factory *manifests.Factory) *UserKubeStateMetricsDenyListTask {
	return &UserKubeStateMetricsDenyListTask{
		client:  client,
		factory: factory,
	}
}

func (t *UserKubeStateMetricsDenyListTask) Run(ctx context.Context) error {
	service, err := t.factory.KubeStateMetricsService()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics Service failed: %w", err)
	}

	deployment, err := t.factory.KubeStateMetricsDeployment()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics Deployment failed: %w", err)
	}

	serverTLS, err := t.client.GetSecret(ctx, deployment.Namespace, "kube-state-metrics-tls")
	if err != nil {
		return fmt.Errorf("getting kube-state-metrics-tls Secret failed: %w", err)
	}

	clientTLS, err := t.client.GetSecret(ctx, deployment.Namespace, "metrics-client-certs")
	if err != nil {
		return fmt.Errorf("getting metrics-client-certs Secret failed: %w", err)
	}

	rootCAs, err := t.client.GetConfigmap(ctx, deployment.Namespace, "metrics-client-ca")
	if err != nil {
		return fmt.Errorf("getting metrics-client-ca ConfigMap failed: %w", err)
	}

	responseData, err := t.client.QueryMetricsEndpoint(ctx, service, "https-main", rootCAs, clientTLS, serverTLS)
	if err != nil {
		return fmt.Errorf("querying kube-state-metrics /metrics endpoint failed: %w", err)
	}

	deployment, err = t.factory.KubeStateMetricsDenylistBoundsCheck(deployment, responseData)
	if err != nil {
		return fmt.Errorf("verifying kube-state-metrics deny-list bounds failed: %w", err)
	}

	err = t.client.CreateOrUpdateDeployment(ctx, deployment)
	if err != nil {
		return fmt.Errorf("reconciling kube-state-metrics Deployment failed: %w", err)
	}

	return nil
}
