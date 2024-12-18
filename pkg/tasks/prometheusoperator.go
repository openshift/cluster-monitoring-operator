// Copyright 2018 The Cluster Monitoring Operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tasks

import (
	"context"
	"fmt"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

type PrometheusOperatorTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewPrometheusOperatorTask(client *client.Client, factory *manifests.Factory) *PrometheusOperatorTask {
	return &PrometheusOperatorTask{
		client:  client,
		factory: factory,
	}
}

func (t *PrometheusOperatorTask) Run(ctx context.Context) error {
	sa, err := t.factory.PrometheusOperatorServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator ServiceAccount failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Operator ServiceAccount failed: %w", err)
	}

	cr, err := t.factory.PrometheusOperatorClusterRole()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator ClusterRole failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRole(ctx, cr)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Operator ClusterRole failed: %w", err)
	}

	crb, err := t.factory.PrometheusOperatorClusterRoleBinding()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator ClusterRoleBinding failed: %w", err)
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(ctx, crb)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Operator ClusterRoleBinding failed: %w", err)
	}

	err = t.runAdmissionWebhook(ctx)
	if err != nil {
		return err
	}

	svc, err := t.factory.PrometheusOperatorService()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Operator Service failed: %w", err)
	}

	rs, err := t.factory.PrometheusOperatorRBACProxySecret()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator RBAC proxy Secret failed: %w", err)
	}

	err = t.client.CreateOrUpdateSecret(ctx, rs)
	if err != nil {
		return fmt.Errorf("creating Prometheus Operator RBAC proxy Secret failed: %w", err)
	}

	d, err := t.factory.PrometheusOperatorDeployment()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator Deployment failed: %w", err)
	}

	err = t.client.CreateOrUpdateDeployment(ctx, d)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Operator Deployment failed: %w", err)
	}

	err = t.client.AssurePrometheusOperatorCRsExist(ctx)
	if err != nil {
		return fmt.Errorf("waiting for Prometheus Operator CRs to become available failed: %w", err)
	}

	pr, err := t.factory.PrometheusOperatorPrometheusRule()
	if err != nil {
		return fmt.Errorf("initializing prometheus-operator rules PrometheusRule failed: %w", err)
	}
	err = t.client.CreateOrUpdatePrometheusRule(ctx, pr)
	if err != nil {
		return fmt.Errorf("reconciling prometheus-operator rules PrometheusRule failed: %w", err)
	}

	smpo, err := t.factory.PrometheusOperatorServiceMonitor()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator ServiceMonitor failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceMonitor(ctx, smpo)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Operator ServiceMonitor failed: %w", err)
	}
	return nil
}

func (t *PrometheusOperatorTask) runAdmissionWebhook(ctx context.Context) error {
	// Deploy manifests for the admission webhook service.
	sa, err := t.factory.PrometheusOperatorAdmissionWebhookServiceAccount()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator Admission Webhook ServiceAccount failed: %w", err)
	}

	err = t.client.CreateOrUpdateServiceAccount(ctx, sa)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Operator Admission Webhook ServiceAccount failed: %w", err)
	}

	svc, err := t.factory.PrometheusOperatorAdmissionWebhookService()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator Admission Webhook Service failed: %w", err)
	}

	err = t.client.CreateOrUpdateService(ctx, svc)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Operator Admission Webhook Service failed: %w", err)
	}

	pdb, err := t.factory.PrometheusOperatorAdmissionWebhookPodDisruptionBudget()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator Admission Webhook PodDisruptionBudget failed: %w", err)
	}

	if pdb != nil {
		err = t.client.CreateOrUpdatePodDisruptionBudget(ctx, pdb)
		if err != nil {
			return fmt.Errorf("reconciling Prometheus Operator Admission Webhook PodDisruptionBudget failed: %w", err)
		}
	}

	d, err := t.factory.PrometheusOperatorAdmissionWebhookDeployment()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Operator Admission Webhook Deployment failed: %w", err)
	}

	err = t.client.CreateOrUpdateDeployment(ctx, d)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Operator Admission Webhook Deployment failed: %w", err)
	}

	w, err := t.factory.PrometheusRuleValidatingWebhook()
	if err != nil {
		return fmt.Errorf("initializing Prometheus Rule Validating Webhook failed: %w", err)
	}

	err = t.client.CreateOrUpdateValidatingWebhookConfiguration(ctx, w)
	if err != nil {
		return fmt.Errorf("reconciling Prometheus Rule Validating Webhook failed: %w", err)
	}

	aw, err := t.factory.AlertManagerConfigValidatingWebhook()
	if err != nil {
		return fmt.Errorf("initializing AlertManagerConfig Validating Webhook failed: %w", err)
	}

	err = t.client.CreateOrUpdateValidatingWebhookConfiguration(ctx, aw)
	if err != nil {
		return fmt.Errorf("reconciling AlertManagerConfig Validating Webhook failed: %w", err)
	}

	return nil
}
