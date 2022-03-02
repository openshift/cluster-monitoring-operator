package tasks

import (
	"context"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
)

type AdmissionTask struct {
	client  *client.Client
	factory *manifests.Factory
	config  *manifests.Config
}

func NewAdmissionTask(client *client.Client, factory *manifests.Factory, config *manifests.Config) *AdmissionTask {
	return &AdmissionTask{
		client:  client,
		factory: factory,
		config:  config,
	}
}

func (t *AdmissionTask) Run(ctx context.Context) error {
	err := t.client.AssurePrometheusOperatorCRsExist(ctx)
	if err != nil {
		return errors.Wrap(err, "waiting for Prometheus Operator CRs to become available failed")
	}

	sa, err := t.factory.AdmissionServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing Admission Webhook Service Account failed")
	}

	if err := t.client.CreateOrUpdateServiceAccount(ctx, sa); err != nil {
		return errors.Wrap(err, "reconciling Admission Webhook Service Account failed")
	}

	svc, err := t.factory.AdmissionService()
	if err != nil {
		return errors.Wrap(err, "initializing Admission Webhook Service failed")
	}

	if err := t.client.CreateOrUpdateService(ctx, svc); err != nil {
		return errors.Wrap(err, "reconciling Admission Webhook Service failed")
	}

	deployment, err := t.factory.AdmissionDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing Admission Webhook Deployment failed")
	}

	if err := t.client.CreateOrUpdateDeployment(ctx, deployment); err != nil {
		return errors.Wrap(err, "reconciling Admission Webhook Deployment failed")
	}

	w, err := t.factory.AdmissionPrometheusRuleValidatingWebhook()
	if err != nil {
		return errors.Wrap(err, "initializing Admission Webhook Validating Webhook failed")
	}

	if err = t.client.CreateOrUpdateValidatingWebhookConfiguration(ctx, w); err != nil {
		return errors.Wrap(err, "reconciling Admission Webhook Validating Webhook failed")
	}

	sm, err := t.factory.AdmissionServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing Admission Webhook Service Monitor failed")
	}

	if err = t.client.CreateOrUpdateServiceMonitor(ctx, sm); err != nil {
		return errors.Wrap(err, "reconciling Admission Webhook Service Monitor failed")
	}

	return nil
}
