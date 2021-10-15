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
	"reflect"
	"sort"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
)

func TestRebalanceWorkloads(t *testing.T) {
	var (
		namespace = "openshift-monitoring"
		workload  = Workload{Namespace: namespace, LabelSelector: map[string]string{"app.kubernetes.io/name": "prometheus"}}
		pods      = []v1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
				Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-k8s-db-prometheus-k8s-0"}}}}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
				Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-k8s-db-prometheus-k8s-1"}}}}},
			},
		}
		nodes = []v1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}}}
	)

	for _, tc := range []struct {
		name               string
		pvs                []v1.PersistentVolume
		pvcs               []v1.PersistentVolumeClaim
		expectedPods       []string
		expectedPVCs       []string
		expectedRebalanced bool
	}{
		{
			name: "Annotated workload with zonal PV",
			pvs: []v1.PersistentVolume{
				{ObjectMeta: metav1.ObjectMeta{Name: "pv-0", Labels: map[string]string{zonalTopologyAnnotation: "zone-0"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pv-1", Labels: map[string]string{zonalTopologyAnnotation: "zone-1"}}},
			},
			pvcs: []v1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PersistentVolumeClaimSpec{VolumeName: "pv-0"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}, Annotations: map[string]string{DropPVCAnnotation: "yes"}},
					Spec:       v1.PersistentVolumeClaimSpec{VolumeName: "pv-1"},
				},
			},
			expectedPods:       []string{"prometheus-k8s-0"},
			expectedPVCs:       []string{"prometheus-k8s-db-prometheus-k8s-0"},
			expectedRebalanced: true,
		},
		{
			name: "Annotated workload with non-zonal PV",
			pvs: []v1.PersistentVolume{
				{ObjectMeta: metav1.ObjectMeta{Name: "pv-0"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pv-1"}},
			},
			pvcs: []v1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PersistentVolumeClaimSpec{VolumeName: "pv-0"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}, Annotations: map[string]string{DropPVCAnnotation: "yes"}},
					Spec:       v1.PersistentVolumeClaimSpec{VolumeName: "pv-1"},
				},
			},
			expectedPods:       []string{"prometheus-k8s-0"},
			expectedPVCs:       []string{"prometheus-k8s-db-prometheus-k8s-0", "prometheus-k8s-db-prometheus-k8s-1"},
			expectedRebalanced: true,
		},
		{
			name: "Non-annotated workload with zonal PV",
			pvs: []v1.PersistentVolume{
				{ObjectMeta: metav1.ObjectMeta{Name: "pv-0", Labels: map[string]string{zonalTopologyAnnotation: "zone-0"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pv-1", Labels: map[string]string{zonalTopologyAnnotation: "zone-1"}}},
			},
			pvcs: []v1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PersistentVolumeClaimSpec{VolumeName: "pv-0"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PersistentVolumeClaimSpec{VolumeName: "pv-1"},
				},
			},
			expectedPods:       []string{"prometheus-k8s-0", "prometheus-k8s-1"},
			expectedPVCs:       []string{"prometheus-k8s-db-prometheus-k8s-0", "prometheus-k8s-db-prometheus-k8s-1"},
			expectedRebalanced: false,
		},
		{
			name: "Non-annotated workload with non-zonal PV",
			pvs: []v1.PersistentVolume{
				{ObjectMeta: metav1.ObjectMeta{Name: "pv-0"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pv-1"}},
			},
			pvcs: []v1.PersistentVolumeClaim{
				{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}}},
			},
			expectedPods:       []string{"prometheus-k8s-0", "prometheus-k8s-1"},
			expectedPVCs:       []string{"prometheus-k8s-db-prometheus-k8s-0", "prometheus-k8s-db-prometheus-k8s-1"},
			expectedRebalanced: false,
		},
		{
			name: "Should guard when all PVC are annotated",
			pvs: []v1.PersistentVolume{
				{ObjectMeta: metav1.ObjectMeta{Name: "pv-0", Labels: map[string]string{zonalTopologyAnnotation: "zone-0"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pv-1", Labels: map[string]string{zonalTopologyAnnotation: "zone-1"}}},
			},
			pvcs: []v1.PersistentVolumeClaim{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}, Annotations: map[string]string{DropPVCAnnotation: "yes"}},
					Spec:       v1.PersistentVolumeClaimSpec{VolumeName: "pv-0"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}, Annotations: map[string]string{DropPVCAnnotation: "yes"}},
					Spec:       v1.PersistentVolumeClaimSpec{VolumeName: "pv-1"},
				},
			},
			expectedPods:       []string{"prometheus-k8s-0"},
			expectedPVCs:       []string{"prometheus-k8s-db-prometheus-k8s-0"},
			expectedRebalanced: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeRebalancer := NewRebalancer(context.Background(), fake.NewSimpleClientset(
				&v1.PodList{Items: pods},
				&v1.PersistentVolumeClaimList{Items: tc.pvcs},
				&v1.PersistentVolumeList{Items: tc.pvs},
				&v1.NodeList{Items: nodes},
			))

			workloadRebalanced, err := fakeRebalancer.RebalanceWorkloads(context.Background(), &workload)
			if err != nil {
				t.Error(err)
			}

			if workloadRebalanced != tc.expectedRebalanced {
				t.Errorf("Expected workload rebalanced to be: %t, got: %t", tc.expectedRebalanced, workloadRebalanced)
			}

			pvcList, err := fakeRebalancer.client.CoreV1().PersistentVolumeClaims(namespace).List(context.Background(), metav1.ListOptions{})
			if err != nil {
				t.Error(err)
			}
			for _, pvc := range pvcList.Items {
				found := false
				for _, expectedPVC := range tc.expectedPVCs {
					if pvc.Name == expectedPVC {
						found = true
						continue
					}
				}
				if !found {
					t.Errorf("Found unexpected pvc that should have been deleted by the operator: %s/%s.", pvc.Namespace, pvc.Name)
				}
			}

			podList, err := fakeRebalancer.client.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
			if err != nil {
				t.Error(err)
			}
			for _, pod := range podList.Items {
				found := false
				for _, expectedPod := range tc.expectedPods {
					if pod.Name == expectedPod {
						found = true
						continue
					}
				}
				if !found {
					t.Errorf("Found unexpected pod that should have been deleted by the operator: %s/%s.", pod.Namespace, pod.Name)
				}
			}

			node, err := fakeRebalancer.client.CoreV1().Nodes().Get(context.Background(), "node-1", metav1.GetOptions{})
			if err != nil {
				t.Error(err)
			}
			// Make sure that the node is uncordon
			if node.Spec.Unschedulable {
				t.Errorf("Node %s is unschedulable.", node.Name)
			}
		})
	}
}

func TestEnsureNodesAreUncordonned(t *testing.T) {
	for _, tc := range []struct {
		name          string
		node          v1.Node
		unschedulable bool
	}{
		{
			name: "Node made unschedulable by CMO",
			node: v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1", Annotations: map[string]string{CordonAnnotation: "cordoned by CMO"}},
				Spec:       v1.NodeSpec{Unschedulable: true},
			},
			unschedulable: false,
		},
		{
			name: "Node not made unschedulable by CMO",
			node: v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
				Spec:       v1.NodeSpec{Unschedulable: true},
			},
			unschedulable: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset(tc.node.DeepCopy())
			fakeRebalancer := NewRebalancer(context.Background(), fakeClient)

			err := fakeRebalancer.EnsureNodesAreUncordoned()
			if err != nil {
				t.Error(err)
			}

			node, err := fakeClient.CoreV1().Nodes().Get(context.Background(), tc.node.Name, metav1.GetOptions{})
			if err != nil {
				t.Error(err)
			}

			if tc.unschedulable != node.Spec.Unschedulable {
				t.Errorf("Expected node %s unschedulable status to be: %t, got %t.", tc.node.Name, tc.unschedulable, node.Spec.Unschedulable)
			}
		})
	}
}

func TestEnsurePVCsAreNotAnnotated(t *testing.T) {
	workload := &Workload{Namespace: "openshift-monitoring", LabelSelector: map[string]string{"app.kubernetes.io/name": "prometheus"}}
	for _, tc := range []struct {
		name string
		pvcs []v1.PersistentVolumeClaim
	}{
		{
			name: "PVCs without the annotation",
			pvcs: []v1.PersistentVolumeClaim{
				{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-0", Namespace: workload.Namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-1", Namespace: workload.Namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}}},
			},
		},
		{
			name: "One PVC with annotation",
			pvcs: []v1.PersistentVolumeClaim{
				{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-0", Namespace: workload.Namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-1", Namespace: workload.Namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}, Annotations: map[string]string{DropPVCAnnotation: "yes"}}},
			},
		},
		{
			name: "All PVCs with annotation",
			pvcs: []v1.PersistentVolumeClaim{
				{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-0", Namespace: workload.Namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}, Annotations: map[string]string{DropPVCAnnotation: "yes"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-db-prometheus-k8s-1", Namespace: workload.Namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}, Annotations: map[string]string{DropPVCAnnotation: "yes"}}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeRebalancer := NewRebalancer(context.Background(), fake.NewSimpleClientset(&v1.PersistentVolumeClaimList{Items: tc.pvcs}))

			err := fakeRebalancer.ensurePVCsAreNotAnnotated(context.Background(), workload)
			if err != nil {
				t.Error(err)
			}

			pvcList, err := fakeRebalancer.client.CoreV1().PersistentVolumeClaims(workload.Namespace).List(context.Background(), metav1.ListOptions{LabelSelector: labels.FormatLabels(workload.LabelSelector)})
			if err != nil {
				t.Error(err)
			}

			for _, pvc := range pvcList.Items {
				if _, found := pvc.GetAnnotations()[DropPVCAnnotation]; found {
					t.Errorf("Expected PVC %s/%s not to have the %q annotation.", pvc.Namespace, pvc.Name, DropPVCAnnotation)
				}
			}
		})
	}
}

func TestResourcesToDeleteByAge(t *testing.T) {
	oldTS := metav1.Time{}
	newTS := metav1.NewTime(oldTS.Add(time.Hour))
	for _, tc := range []struct {
		name          string
		resources     []resourcesToDelete
		expectedOrder []string
	}{
		{
			name: "older pvc",
			resources: []resourcesToDelete{
				{pod: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-0"}}, pvc: &v1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: oldTS}}},
				{pod: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-1"}}, pvc: &v1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: newTS}}},
			},
			expectedOrder: []string{"prometheus-k8s-1", "prometheus-k8s-0"},
		},
		{
			name: "pvc with same age",
			resources: []resourcesToDelete{
				{pod: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-0"}}, pvc: &v1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: newTS}}},
				{pod: &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-1"}}, pvc: &v1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{CreationTimestamp: newTS}}},
			},
			expectedOrder: []string{"prometheus-k8s-1", "prometheus-k8s-0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sort.Sort(byAge(tc.resources))

			var order []string
			for _, r := range tc.resources {
				order = append(order, r.pod.Name)
			}

			if !reflect.DeepEqual(order, tc.expectedOrder) {
				t.Errorf("Expected resources to delete to be: %s got: %s", tc.expectedOrder, order)
			}
		})
	}
}
