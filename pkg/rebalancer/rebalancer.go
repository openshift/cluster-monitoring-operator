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
	"sort"
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

	// This function always preserves the data of at least one of the pods of the
	// workload, so it will not rebalance pods if we only have one. As such, we
	// can return early and preserve the annotation on the PVC.
	if len(podList.Items) <= 1 {
		return false, nil
	}

	resourcesToDelete, err := r.resourcesToDelete(ctx, podList.Items)
	if err != nil {
		return false, err
	}

	if len(resourcesToDelete) == 0 {
		klog.V(4).Infof("Couldn't find %q annotation on any of the PVCs attached to the workload in namespace %s with label %q which needs to be rebalanced.", DropPVCAnnotation, workload.Namespace, workload.LabelSelector)
		return false, nil
	}

	for _, rtd := range resourcesToDelete {
		klog.V(2).Infof("Rebalancing pod %s/%s.", rtd.pod.Namespace, rtd.pod.Name)
		err := r.rebalanceWorkload(ctx, rtd.pod, rtd.pvc)
		if err != nil {
			return false, err
		}
	}

	// If the workloads were balanced by the operator, we wait for 5 minutes
	// before setting the status so that we don't set upgradeable=false after
	// balancing the pods.
	err = wait.Poll(10*time.Second, 5*time.Minute, func() (bool, error) {
		klog.V(4).Infof("Waiting until workload in namespace %s with label %q becomes correctly balanced.", workload.Namespace, workload.LabelSelector)
		return r.WorkloadCorrectlyBalanced(ctx, workload)
	})
	if err != nil {
		return false, err
	}

	return true, r.ensurePVCsAreNotAnnotated(ctx, workload)
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

// byAge sorts resources by PVC creation time in reverse chronological order
// (most recent first).  In case of a tie it sorts the resources by the pod
// names in reverse alphabetical order (e.g. [pod-1, pod-0]).
type byAge []resourcesToDelete

func (r byAge) Len() int {
	return len(r)
}

func (r byAge) Less(i, j int) bool {
	if r[i].pvc.CreationTimestamp.Equal(&r[j].pvc.CreationTimestamp) {
		return r[i].pod.Name > r[j].pod.Name
	}
	return r[i].pvc.CreationTimestamp.After(r[j].pvc.CreationTimestamp.Time)
}

func (r byAge) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

// resourcesToDelete returns the list of Kubernetes resources that should be
// deleted in order to reschedule pods on different nodes. It only returns pods
// and annotated PVCs that were marked for deletion by the users with the
// openshift.io/cluster-monitoring-drop-pvc=yes annotation on the PVC.
// The resources will be returned sorted by their PVC creation timestamp, from
// the newest to the oldest to make the deletion consistent.
// If all the PVCs of the workload are annotated, the oldest one is kept and its
// annotation is removed to prevent complete data loss.
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

	// Sort PVCs by their creation timestamps, from the newest to the oldest to
	// make sure that the oldest PVC is retained in case all of them are
	// annotated. If some PVCs have the same creation timestamp, they will be
	// sorted based on their pod name.
	sort.Sort(byAge(resources))

	// Guard from deleting all PVCs to prevent complete data loss.
	if len(resources) == len(pods) {
		resources = resources[:len(resources)-1]
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

// EnsurePVCsAreNotAnnoted makes sure that none of the PVCs of the given
// workload have the openshift.io/cluster-monitoring-drop-pvc annotation after
// the rebalancing is done. In case one of the PVC has the annotation, it will
// be removed to prevent deleting the PVC in a future cycle.
func (r *Rebalancer) ensurePVCsAreNotAnnotated(ctx context.Context, workload *Workload) error {
	pvcList, err := r.client.CoreV1().PersistentVolumeClaims(workload.Namespace).List(ctx, metav1.ListOptions{LabelSelector: labels.FormatLabels(workload.LabelSelector)})
	if err != nil {
		return err
	}

	for _, pvc := range pvcList.Items {
		if _, found := pvc.GetAnnotations()[DropPVCAnnotation]; !found {
			continue
		}
		klog.V(2).Infof("Removing annotation %q from PersistentVolumeClaim %s/%s to avoid needlessly deleting all PVCs to rebalance a workload.", DropPVCAnnotation, pvc.Namespace, pvc.Name)
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			pvc, err := r.client.CoreV1().PersistentVolumeClaims(pvc.Namespace).Get(ctx, pvc.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			delete(pvc.Annotations, DropPVCAnnotation)
			_, err = r.client.CoreV1().PersistentVolumeClaims(pvc.Namespace).Update(ctx, pvc, metav1.UpdateOptions{})
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}
