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

package rebalancer

import (
	"context"
	"time"

	"github.com/openshift/cluster-monitoring-operator/pkg/drain"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
)

const (
	CordonAnnotation        = "openshift.io/cluster-monitoring-cordoned"
	DropPVCAnnotation       = "openshift.io/cluster-monitoring-drop-pvc"
	zonalTopologyAnnotation = "topology.kubernetes.io/zone"
)

type Rebalancer struct {
	client  kubernetes.Interface
	drainer *drain.Helper
}

func NewRebalancer(ctx context.Context, client kubernetes.Interface) *Rebalancer {
	return &Rebalancer{
		client:  client,
		drainer: drain.NewHelper(ctx, client, CordonAnnotation),
	}
}

type Workload struct {
	Namespace     string
	Name          string
	LabelSelector map[string]string
}

// workloadCorrectlyBalanced returns whether the selected pods are balanced
// across different nodes ensuring proper high-availability.
// If the pods don't use persistent storage, it will always return true.
func (r *Rebalancer) WorkloadCorrectlyBalanced(ctx context.Context, workload *Workload) (bool, error) {
	podList, err := r.client.CoreV1().Pods(workload.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.FormatLabels(workload.LabelSelector), FieldSelector: "status.phase=Running"})
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

// RebalanceWorkloads rebalances the given workload across multiple nodes.
// If the workload has persistent storage enabled, this function verifies that
// the PVCs are annotated for deletion before trying to rebalance the pods.
// It returns whether the workload was rebalanced or not.
func (r *Rebalancer) RebalanceWorkloads(ctx context.Context, workload *Workload) (bool, error) {
	podList, err := r.client.CoreV1().Pods(workload.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.FormatLabels(workload.LabelSelector)})
	if err != nil {
		return false, err
	}

	if len(podList.Items) <= 1 {
		return false, nil
	}

	resourcesToDelete, err := r.resourcesToDelete(ctx, podList.Items)
	if err != nil {
		return false, err
	}

	if len(resourcesToDelete) == 0 {
		klog.V(4).Info("Couldn't find %q annotation on any of the PVCs attached to %s/%s which needs to be rebalanced.", DropPVCAnnotation, workload.Namespace, workload.Name)
		return false, nil
	}

	for i, rtd := range resourcesToDelete {
		// Guard from deleting all PVCs to prevent complete data loss.
		if i == len(podList.Items)-1 {
			// Remove the annotation so that the PVC doesn't get deleted in future cycles.
			klog.V(4).Infof("Removing annotation %q from PersistentVolumeClaim %s/%s to avoid needlessly deleting all PVCs to rebalance a workload.", DropPVCAnnotation, rtd.pvc.Namespace, rtd.pvc.Name)
			err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
				pvc, err := r.client.CoreV1().PersistentVolumeClaims(rtd.pvc.Namespace).Get(ctx, rtd.pvc.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				delete(pvc.Annotations, DropPVCAnnotation)
				_, err = r.client.CoreV1().PersistentVolumeClaims(pvc.Namespace).Update(ctx, pvc, metav1.UpdateOptions{})
				return err
			})
			if err != nil {
				return false, err
			}
			break
		}

		klog.V(4).Infof("Rebalancing pod %s/%s.", rtd.pod.Namespace, rtd.pod.Name)
		err := r.rebalanceWorkload(ctx, rtd.pod, rtd.pvc)
		if err != nil {
			return false, err
		}
	}

	// If the workloads were balanced by the operator, we wait for 5 minutes
	// before setting the status so that we don't set upgradeable=false after
	// balancing the pods.
	err = wait.Poll(10*time.Second, 5*time.Minute, func() (bool, error) {
		klog.V(4).Info("Waiting until workload %s in namespace %s becomes correctly balanced.", workload.Name, workload.Namespace)
		return r.WorkloadCorrectlyBalanced(ctx, workload)
	})
	return err == nil, err
}

// rebalanceWorkload rebalances the given pod on a different node. To make sure
// that the pod will be rescheduled on a different node, this function will
// first cordon the node in which the pod is scheduled. Then it will verify
// whether the PVC attached to the pod needs to be deleted or not. Only pods
// that have PVCs with a zonal topology need to be deleted since they might
// prevent the pod to be schedule on a node that is located in a different
// availability zone.
func (r *Rebalancer) rebalanceWorkload(ctx context.Context, pod *v1.Pod, pvc *v1.PersistentVolumeClaim) error {
	node, err := r.client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	err = drain.RunCordonOrUncordon(r.drainer, node, drain.Cordon)
	if err != nil {
		return err
	}
	defer func() {
		err := drain.RunCordonOrUncordon(r.drainer, node, drain.Uncordon)
		if err != nil {
			klog.Errorf("Couldn't uncordon node %v: %v.", pod.Spec.NodeName, err)
		}
	}()

	pv, err := r.client.CoreV1().PersistentVolumes().Get(ctx, pvc.Spec.VolumeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	// Do not delete the PVC if the storage provider hasn't set the topology.kubernetes.io/zone label on the PV.
	// In most cases, when the PV isn't zonal, pods can access it from a node in a different AZ so we don't need to delete it.
	if _, ok := pv.GetLabels()[zonalTopologyAnnotation]; ok {
		klog.V(2).Infof("Deleting PersistentVolumeClaim %s/%s.", pvc.Namespace, pvc.Name)
		err = r.client.CoreV1().PersistentVolumeClaims(pvc.Namespace).Delete(ctx, pvc.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	} else {
		klog.V(2).Infof("Keeping PersistentVolumeClaim %s/%s because it doesn't have the %q label", pvc.Namespace, pvc.Name, zonalTopologyAnnotation)
	}

	klog.V(2).Infof("Deleting pod %s/%s.", pod.Namespace, pod.Name)
	return r.client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
}

type resourcesToDelete struct {
	pod *v1.Pod
	pvc *v1.PersistentVolumeClaim
}

// resourcesToDelete returns the list of Kubernetes resources that should be
// deleted in order to rescheduled pods on different nodes. It only returns
// pods and annotated PVCs that were marked for deletion by the users with the
// openshift.io/cluster-monitoring-drop-pvc=yes annotation on the PVC.
func (r *Rebalancer) resourcesToDelete(ctx context.Context, pods []v1.Pod) ([]resourcesToDelete, error) {
	resources := make([]resourcesToDelete, 0)
	for i, pod := range pods {
		for _, vol := range pod.Spec.Volumes {
			if vol.PersistentVolumeClaim == nil {
				continue
			}
			pvc, err := r.client.CoreV1().PersistentVolumeClaims(pod.Namespace).Get(ctx, vol.PersistentVolumeClaim.ClaimName, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				break
			}
			if err != nil {
				return nil, err
			}

			dropPVC, ok := pvc.Annotations[DropPVCAnnotation]
			if !ok {
				break
			}
			if dropPVC == "yes" {
				resources = append(resources, resourcesToDelete{pod: &pods[i], pvc: pvc})
			}
		}
	}
	return resources, nil
}

// EnsureNodesAreUncordoned uncordon all the nodes that were cordoned by the operator.
func (r *Rebalancer) EnsureNodesAreUncordoned() error {
	nodeList, err := r.drainer.Client.CoreV1().Nodes().List(r.drainer.Ctx, metav1.ListOptions{
		LabelSelector: "!node-role.kubernetes.io/master",
		FieldSelector: "spec.unschedulable=true",
	})
	if err != nil {
		return err
	}

	for _, node := range nodeList.Items {
		err := drain.RunCordonOrUncordon(r.drainer, &node, drain.Uncordon)
		if err != nil {
			return err
		}
	}
	return nil
}
