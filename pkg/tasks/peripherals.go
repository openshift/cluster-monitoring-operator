package tasks

import (
	"context"
	"fmt"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type PeripheralsTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewPeripheralsTask(client *client.Client, factory *manifests.Factory) *PeripheralsTask {
	return &PeripheralsTask{
		client:  client,
		factory: factory,
	}
}

func (t *PeripheralsTask) Run(ctx context.Context) error {
	svc, err := t.factory.KubeStateMetricsService()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics Service failed: %w", err)
	}

	dep, err := t.factory.KubeStateMetricsDeployment()
	if err != nil {
		return fmt.Errorf("initializing kube-state-metrics Deployment failed: %w", err)
	}

	serverTLS, err := t.client.GetSecret(ctx, dep.Namespace, "kube-state-metrics-tls")
	if err != nil {
		return fmt.Errorf("getting kube-state-metrics-tls Secret failed: %w", err)
	}

	clientTLS, err := t.client.GetSecret(ctx, dep.Namespace, "metrics-client-certs")
	if err != nil {
		return fmt.Errorf("getting metrics-client-certs Secret failed: %w", err)
	}

	rootCAs, err := t.client.GetConfigmap(ctx, dep.Namespace, "metrics-client-ca")
	if err != nil {
		return fmt.Errorf("getting metrics-client-ca ConfigMap failed: %w", err)
	}

	dep, err = t.factory.KubeStateMetricsDenylistBoundsCheck(dep, svc, rootCAs, clientTLS, serverTLS)
	if err != nil {
		return fmt.Errorf("verifying kube-state-metrics deny-list bounds failed: %w", err)
	}

	err = t.client.CreateOrUpdateDeployment(ctx, dep)
	if err != nil {
		return fmt.Errorf("reconciling kube-state-metrics Deployment failed: %w", err)
	}

	return nil
}
