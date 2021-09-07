// Copyright 2021 The Cluster Monitoring Operator Authors
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

package operator

import (
	"context"
	"fmt"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

// Upgradeable verifies whether the operator can be upgraded or not. It returns
// the ConditionStatus with optional reason and message.
func (o *Operator) Upgradeable(ctx context.Context) (configv1.ConditionStatus, string, string, error) {
	if !o.lastKnowInfrastructureConfig.HighlyAvailableInfrastructure() {
		return configv1.ConditionTrue, "", "", nil
	}

	balanced, reason, message, err := o.workloadsCorrectlyBalanced(ctx)
	if err != nil {
		return configv1.ConditionUnknown, "", "", err
	}

	if !balanced {
		return configv1.ConditionFalse, reason, message, nil
	}

	return configv1.ConditionTrue, reason, message, nil
}

func (o *Operator) workloadsCorrectlyBalanced(ctx context.Context) (bool, string, string, error) {
	type workload struct {
		namespace     string
		name          string
		labelSelector map[string]string
	}

	workloads := []workload{
		{
			namespace:     o.namespace,
			name:          "prometheus-k8s",
			labelSelector: map[string]string{"app.kubernetes.io/name": "prometheus"},
		},
		{
			namespace:     o.namespace,
			name:          "alertmanager-main",
			labelSelector: map[string]string{"app.kubernetes.io/name": "alertmanager"},
		},
	}

	if o.userWorkloadEnabled {
		workloads = append(workloads,
			workload{
				namespace:     o.namespaceUserWorkload,
				name:          "prometheus-user-workload",
				labelSelector: map[string]string{"app.kubernetes.io/name": "prometheus"},
			},
			workload{
				namespace:     o.namespaceUserWorkload,
				name:          "thanos-ruler-user-workload",
				labelSelector: map[string]string{"app.kubernetes.io/name": "thanos-ruler"},
			},
		)
	}

	var (
		messages             []string
		rebalancedByOperator bool
	)
	for _, workload := range workloads {
		balanced, err := o.workloadCorrectlyBalanced(ctx, workload.namespace, workload.labelSelector)
		if err != nil {
			return false, "", "", err
		}

		if balanced {
			continue
		}

		err = o.rebalanceWorkloads(ctx, workload.namespace, workload.labelSelector)
		if err != nil {
			return false, "", "", err
		}

		messages = append(
			messages,
			fmt.Sprintf("Highly-available workload %s/%s is incorrectly balanced across multiple nodes."+
				" You can run `oc get pvc -n %s -l %s=%s` to get all the PVCs attached to it.",
				workload.namespace, workload.name, workload.namespace, "app.kubernetes.io/name", workload.labelSelector["app.kubernetes.io/name"],
			),
		)
	}

	if len(messages) > 0 {
		msg := "Manual intervention is needed to upgrade to the next minor version. Please refer to the following documentation to fix this issue: https://github.com/openshift/runbooks/blob/master/alerts/HighlyAvailableWorkloadIncorrectlySpread.md."
		if rebalancedByOperator {
			msg += " The operator couldn't rebalance the pods automatically with the annotation, please refer to the runbook to fix this issue manually."
		}
		messages = append(messages, msg)
		return false, client.WorkloadIncorrectlySpreadReason, strings.Join(messages, "\n"), nil
	}

	return true, "", "", nil
}

// workloadCorrectlyBalanced returns whether the selected pods are balanced
// across different nodes ensuring proper high-availability.
// If the pods don't use persistent storage, it will always return true.
func (o *Operator) workloadCorrectlyBalanced(ctx context.Context, namespace string, sel map[string]string) (bool, error) {
	podList, err := o.client.ListPods(ctx, namespace, metav1.ListOptions{LabelSelector: labels.FormatLabels(sel), FieldSelector: "status.phase=Running"})
	if err != nil {
		return false, err
	}

	// Skip the check if we can't get enough pods. This prevents setting the status when the cluster is degraded.
	if len(podList.Items) <= 1 {
		return true, nil
	}

	// Skip workloads that don't have persistent storage enabled.
	hasPVC := false
	for _, vol := range podList.Items[0].Spec.Volumes {
		if vol.PersistentVolumeClaim != nil {
			hasPVC = true
			break
		}
	}
	if !hasPVC {
		return true, nil
	}

	nodes := make(map[string]struct{}, len(podList.Items))
	for _, pod := range podList.Items {
		nodes[pod.Spec.NodeName] = struct{}{}
	}

	return len(nodes) > 1, nil
}

func (o *Operator) rebalanceWorkloads(ctx context.Context, namespace string, sel map[string]string) error {
	podList, err := o.client.ListPods(ctx, namespace, metav1.ListOptions{LabelSelector: labels.FormatLabels(sel)})
	if err != nil {
		return err
	}

	if len(podList.Items) <= 1 {
		return nil
	}

	var (
		pvcsToDelete []v1.PersistentVolumeClaim
		podsToDelete []v1.Pod
	)
	for _, pod := range podList.Items {
		for _, vol := range pod.Spec.Volumes {
			if vol.PersistentVolumeClaim == nil {
				continue
			}
			pvc, err := o.client.GetPersistentVolumeClaim(ctx, pod.Namespace, vol.PersistentVolumeClaim.ClaimName)
			if apierrors.IsNotFound(err) {
				break
			}
			if err != nil {
				return err
			}

			dropPVC, ok := pvc.Annotations[dropPVCAnnotation]
			if !ok {
				break
			}
			if dropPVC == "yes" {
				pvcsToDelete = append(pvcsToDelete, *pvc)
				podsToDelete = append(podsToDelete, pod)
			}
		}
	}

	if len(pvcsToDelete) == 0 {
		return nil
	}

	for i, pod := range podsToDelete {
		pvc := pvcsToDelete[i]
		// Guard from deleting all PVCs to prevent complete data loss.
		if i == len(podList.Items)-1 {
			// Remove the annotation so that the PVC doesn't get deleted in future cycles.
			klog.V(4).Infof("Removing annotation %s from PersistentVolumeClaim %s/%s to avoid needlessly deleting all PVCs to rebalance a workload.", dropPVCAnnotation, pvc.Namespace, pvc.Name)
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				pvc, err := o.client.GetPersistentVolumeClaim(ctx, pvc.Namespace, pvc.Name)
				if err != nil {
					return err
				}
				delete(pvc.Annotations, dropPVCAnnotation)
				_, err = o.client.UpdatePersistentVolumeClaim(ctx, pvc)
				return err
			})
			if err != nil {
				return err
			}
			break
		}

		klog.V(4).Infof("Rebalancing pod %s/%s.", pod.Namespace, pod.Name)
		err := o.rebalanceWorkload(ctx, &pod, &pvc)
		if err != nil {
			return err
		}
	}

	// If the workloads were balanced by the operator, we wait for 5 minutes
	// before setting the status so that we don't set upgradeable=false after
	// balancing the pods.
	return wait.Poll(10*time.Second, 5*time.Minute, func() (bool, error) {
		klog.V(4).Info("Waiting until workload %s in namespace %s becomes correctly balanced.", sel, namespace)
		return o.workloadCorrectlyBalanced(ctx, namespace, sel)
	})
}

func (o *Operator) rebalanceWorkload(ctx context.Context, pod *v1.Pod, pvc *v1.PersistentVolumeClaim) error {
	err := o.client.CordonNode(ctx, o.drainer, pod.Spec.NodeName)
	if err != nil {
		return err
	}
	defer func() {
		err := o.client.UncordonNode(ctx, o.drainer, pod.Spec.NodeName)
		if err != nil {
			klog.Errorf("Couldn't uncordon node %v: %v.", pod.Spec.NodeName, err)
		}
	}()

	pv, err := o.client.GetPersistentVolume(ctx, pvc.Spec.VolumeName)
	if err != nil {
		return err
	}
	if pv.Labels != nil {
		// Do not delete the PVC if the storage provider hasn't set the topology.kubernetes.io/zone label on the PV.
		// In most cases, when the PV isn't zonal, pods can access it from a node in a different AZ so we don't need to delete it.
		if _, ok := pv.Labels[zonalTopologyAnnotation]; ok {
			klog.V(2).Infof("Deleting PersistentVolumeClaim %s/%s.", pvc.Namespace, pvc.Name)
			err = o.client.DeletePersistentVolumeClaim(ctx, pvc)
			if err != nil {
				return err
			}
		}
	}

	klog.V(2).Infof("Deleting pod %s/%s.", pod.Namespace, pod.Name)
	return o.client.DeletePod(ctx, pod)
}

func (o *Operator) ensureNodesAreUncordoned(ctx context.Context) error {
	nodeList, err := o.client.ListNodes(ctx, metav1.ListOptions{FieldSelector: "spec.unschedulable=true"})
	if err != nil {
		return err
	}

	for _, node := range nodeList.Items {
		err := o.client.UncordonNode(ctx, o.drainer, node.Name)
		if err != nil {
			return err
		}
	}
	return nil
}
