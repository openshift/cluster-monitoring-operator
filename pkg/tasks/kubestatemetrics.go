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
	"reflect"

	"k8s.io/api/core/v1"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type KubeStateMetricsTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewKubeStateMetricsTask(client *client.Client, factory *manifests.Factory) *KubeStateMetricsTask {
	return &KubeStateMetricsTask{
		client:  client,
		factory: factory,
	}
}

func (t *KubeStateMetricsTask) Run() error {
	sa, err := t.factory.KubeStateMetricsServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics Service failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics ServiceAccount failed")
	}

	cr, err := t.factory.KubeStateMetricsClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics ClusterRole failed")
	}

	crb, err := t.factory.KubeStateMetricsClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics ClusterRoleBinding failed")
	}

	arr, err := t.factory.KubeStateMetricsAddonResizerRole()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics addon-resizer Role failed")
	}

	err = t.client.CreateOrUpdateRole(arr)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics addon-resizer Role failed")
	}

	arrb, err := t.factory.KubeStateMetricsAddonResizerRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics addon-resizer RoleBinding failed")
	}

	err = t.client.CreateOrUpdateRoleBinding(arrb)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics addon-resizer RoleBinding failed")
	}

	svc, err := t.factory.KubeStateMetricsService()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics Service failed")
	}

	err = t.client.CreateOrUpdateService(svc)
	if err != nil {
		return errors.Wrap(err, "reconciling kube-state-metrics Service failed")
	}

	return errors.Wrap(t.reconcileKubeStateMetricsDeployments(), "reconciling kube-state-metrics Deployment failed")
}

func (t *KubeStateMetricsTask) reconcileKubeStateMetricsDeployments() error {
	d, err := t.factory.KubeStateMetricsDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics Deployment for comparison failed")
	}

	depl, err := t.client.KubernetesInterface().AppsV1beta2().Deployments(d.GetNamespace()).Get(d.GetName(), metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "retrieving kube-state-metrics Deployment for comparison failed")
	}

	// No need for comparing if deployment doesn't exist in the first place.
	if !apierrors.IsNotFound(err) {
		// kube-state-metrics is auto scaled, so we have to ignore the resources
		// configured when comparing them.
		d.Spec.Template.Spec.Containers[2].Resources = v1.ResourceRequirements{}
		depl.Spec.Template.Spec.Containers[2].Resources = v1.ResourceRequirements{}

		if reflect.DeepEqual(d.Spec, depl.Spec) {
			// Nothing to do, as the currently existing kube-state-metrics
			// deployment is equivalent to the one that would be applied.
			return nil
		}
	}

	d, err = t.factory.KubeStateMetricsDeployment()
	if err != nil {
		return errors.Wrap(err, "initializing kube-state-metrics Deployment failed")
	}

	err = t.client.CreateOrUpdateDeployment(d)
	return errors.Wrap(err, "reconciling kube-state-metrics Deployment failed")
}
