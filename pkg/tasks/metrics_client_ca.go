package tasks

import (
	"context"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
)

type MetricsClientCATask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

// NewMetricsClientCATask returns and instance of MetricsClientCATask which creates
// and updates the client-CA ConfigMap that is required by our deployments of the
// kube-rbac-proxy in order to be able to authenticate client-cert authenticated
// metrics requests
func NewMetricsClientCATask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *MetricsClientCATask {
	return &MetricsClientCATask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *MetricsClientCATask) Run(ctx context.Context) error {
	apiAuthConfigmap, err := t.client.GetConfigmap(ctx, "kube-system", "extension-apiserver-authentication")
	if err != nil {
		return errors.Wrap(err, "failed to load kube-system/extension-apiserver-authentication configmap")
	}

	cm, err := t.factory.MetricsClientCACM(apiAuthConfigmap)
	if err != nil {
		return errors.Wrap(err, "initializing Metrics Client CA failed")
	}

	err = t.client.CreateOrUpdateConfigMap(ctx, cm)
	if err != nil {
		return errors.Wrap(err, "reconciling Metrics Client CA ConfigMap failed")
	}

	return t.reconcileUWMConfigMap(ctx, apiAuthConfigmap)
}

func (t *MetricsClientCATask) reconcileUWMConfigMap(ctx context.Context, apiAuthConfigmap *v1.ConfigMap) error {
	cm, err := t.factory.UserWorkloadMetricsClientCACM(apiAuthConfigmap)
	if err != nil {
		return err
	}

	if t.config.ClusterMonitoringConfiguration.UserWorkloadEnabled {
		return t.client.CreateOrUpdateConfigMap(ctx, cm)
	}

	return t.client.DeleteConfigMap(ctx, cm)
}
