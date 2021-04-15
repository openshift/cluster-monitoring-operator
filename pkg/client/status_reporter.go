// Copyright 2019 The Cluster Monitoring Operator Authors
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

package client

import (
	"context"
	"fmt"

	"github.com/openshift/cluster-monitoring-operator/pkg/strings"

	v1 "github.com/openshift/api/config/v1"
	clientv1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const unavailableMessage string = "Rollout of the monitoring stack failed and is degraded. Please investigate the degraded status error."

type StatusReporter struct {
	client                clientv1.ClusterOperatorInterface
	clusterOperatorName   string
	namespace             string
	userWorkloadNamespace string
	version               string
}

func NewStatusReporter(client clientv1.ClusterOperatorInterface, name, namespace, userWorkloadNamespace, version string) *StatusReporter {
	return &StatusReporter{
		client:                client,
		clusterOperatorName:   name,
		namespace:             namespace,
		userWorkloadNamespace: userWorkloadNamespace,
		version:               version,
	}
}

func (r *StatusReporter) relatedObjects() []v1.ObjectReference {
	return []v1.ObjectReference{
		// Gather pods, services, daemonsets, deployments, replicasets, statefulsets, and routes.
		{Resource: "namespaces", Name: r.namespace},
		{Resource: "namespaces", Name: r.userWorkloadNamespace},
		// Gather all ServiceMonitors, PodMonitors, PrometheusRules, Alertmanagers, AlertmanagerConfigs, ThanosRulers and Prometheus CRs
		{Group: "monitoring.coreos.com", Resource: "servicemonitors"},
		{Group: "monitoring.coreos.com", Resource: "podmonitors"},
		{Group: "monitoring.coreos.com", Resource: "prometheusrules"},
		{Group: "monitoring.coreos.com", Resource: "alertmanagers"},
		{Group: "monitoring.coreos.com", Resource: "prometheuses"},
		{Group: "monitoring.coreos.com", Resource: "thanosrulers"},
		{Group: "monitoring.coreos.com", Resource: "alertmanagerconfigs"},
	}
}

func (r *StatusReporter) SetDone() error {
	co, err := r.client.Get(context.TODO(), r.clusterOperatorName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		co = r.newClusterOperator()
		co, err = r.client.Create(context.TODO(), co, metav1.CreateOptions{})
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	time := metav1.Now()

	conditions := newConditions(co.Status, r.version, time)
	conditions.setCondition(v1.OperatorAvailable, v1.ConditionTrue, "Successfully rolled out the stack.", "RollOutDone", time)
	conditions.setCondition(v1.OperatorProgressing, v1.ConditionFalse, "", "", time)
	conditions.setCondition(v1.OperatorDegraded, v1.ConditionFalse, "", "", time)
	conditions.setCondition(v1.OperatorUpgradeable, v1.ConditionTrue, "", "", time)
	co.Status.Conditions = conditions.entries()

	// If we have reached "level" for the operator, report that we are at the version
	// injected into us during update. We require that all components be rolled out
	// and available at the new version before reporting this value.
	if len(r.version) > 0 {
		co.Status.Versions = []v1.OperandVersion{
			{
				Name:    "operator",
				Version: r.version,
			},
		}
	} else {
		co.Status.Versions = nil
	}

	_, err = r.client.UpdateStatus(context.TODO(), co, metav1.UpdateOptions{})
	return err
}

// SetInProgress sets the OperatorProgressing condition to true, either:
// 1. If there has been no previous status yet
// 2. If the previous ClusterOperator OperatorAvailable condition was false
//
// This will ensure that the progressing state will be only set initially or in case of failure.
// Once controller operator versions are available, an additional check will be introduced that toggles
// the OperatorProgressing state in case of version upgrades.
func (r *StatusReporter) SetInProgress() error {
	co, err := r.client.Get(context.TODO(), r.clusterOperatorName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		co = r.newClusterOperator()
		co, err = r.client.Create(context.TODO(), co, metav1.CreateOptions{})
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	time := metav1.Now()
	reasonInProgress := "RollOutInProgress"
	conditions := newConditions(co.Status, r.version, time)
	conditions.setCondition(v1.OperatorProgressing, v1.ConditionTrue, "Rolling out the stack.", reasonInProgress, time)
	conditions.setCondition(v1.OperatorUpgradeable, v1.ConditionTrue,
		"Rollout of the monitoring stack is in progress. Please wait until it finishes.",
		reasonInProgress,
		time,
	)
	co.Status.Conditions = conditions.entries()
	co.Status.RelatedObjects = r.relatedObjects()

	_, err = r.client.UpdateStatus(context.TODO(), co, metav1.UpdateOptions{})
	return err
}

func (r *StatusReporter) Get() (*v1.ClusterOperator, error) {
	return r.client.Get(context.TODO(), r.clusterOperatorName, metav1.GetOptions{})
}

func (r *StatusReporter) SetFailed(statusErr error, reason string) error {
	co, err := r.client.Get(context.TODO(), r.clusterOperatorName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		co = r.newClusterOperator()
		co, err = r.client.Create(context.TODO(), co, metav1.CreateOptions{})
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	time := metav1.Now()
	// The Reason should be upper case camelCase (PascalCase) according to the API docs.
	reason = strings.ToPascalCase(reason)

	conditions := newConditions(co.Status, r.version, time)
	conditions.setCondition(v1.OperatorAvailable, v1.ConditionFalse, unavailableMessage, reason, time)
	conditions.setCondition(v1.OperatorProgressing, v1.ConditionFalse, unavailableMessage, reason, time)
	conditions.setCondition(v1.OperatorDegraded, v1.ConditionTrue, fmt.Sprintf("Failed to rollout the stack. Error: %v", statusErr), reason, time)
	conditions.setCondition(v1.OperatorUpgradeable, v1.ConditionTrue, unavailableMessage, reason, time)
	co.Status.Conditions = conditions.entries()

	_, err = r.client.UpdateStatus(context.TODO(), co, metav1.UpdateOptions{})
	return err
}

func (r *StatusReporter) newClusterOperator() *v1.ClusterOperator {
	time := metav1.Now()
	co := &v1.ClusterOperator{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "config.openshift.io/v1",
			Kind:       "ClusterOperator",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: r.clusterOperatorName,
		},
		Spec:   v1.ClusterOperatorSpec{},
		Status: v1.ClusterOperatorStatus{},
	}
	co.Status.RelatedObjects = r.relatedObjects()
	co.Status.Conditions = newConditions(co.Status, r.version, time).entries()

	return co
}
