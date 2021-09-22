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

package drain

import (
	"context"
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	cordonAnnotation = "openshift.io/cluster-monitoring-cordoned"
)

func TestCordonNode(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		node                  v1.Node
		expectedUnschedulable bool
		expectedAnnotations   map[string]string
	}{
		{
			name: "Schedulable node",
			node: v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1", Annotations: map[string]string{}},
				Spec:       v1.NodeSpec{Unschedulable: false},
			},
			expectedUnschedulable: true,
			expectedAnnotations:   map[string]string{cordonAnnotation: cordonAnnotationMessage},
		},
		{
			name: "Unschedulable node",
			node: v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-2", Annotations: map[string]string{}},
				Spec:       v1.NodeSpec{Unschedulable: true},
			},
			expectedUnschedulable: true,
			expectedAnnotations:   map[string]string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset(tc.node.DeepCopy())
			drainer := NewHelper(context.Background(), fakeClient, cordonAnnotation)

			err := RunCordonOrUncordon(drainer, &tc.node, Cordon)
			if err != nil {
				t.Error(err)
			}

			node, err := fakeClient.CoreV1().Nodes().Get(context.Background(), tc.node.Name, metav1.GetOptions{})
			if err != nil {
				t.Error(err)
			}

			if tc.expectedUnschedulable != node.Spec.Unschedulable {
				t.Errorf("Expected node %s unschedulable status to be: %t, got %t.", tc.node.Name, tc.expectedUnschedulable, node.Spec.Unschedulable)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, node.Annotations) {
				t.Errorf("Expected node %s annotations to be: %v, got %v.", tc.node.Name, tc.expectedAnnotations, node.Annotations)
			}
		})
	}
}

func TestUncordonNode(t *testing.T) {
	expectedAnnotations := map[string]string(nil)
	for _, tc := range []struct {
		name                  string
		node                  v1.Node
		expectedUnschedulable bool
	}{
		{
			name: "Schedulable node",
			node: v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
				Spec:       v1.NodeSpec{Unschedulable: false},
			},
			expectedUnschedulable: false,
		},
		{
			name: "Unschedulable node",
			node: v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
				Spec:       v1.NodeSpec{Unschedulable: true},
			},
			expectedUnschedulable: true,
		},
		{
			name: "Unschedulable node marked by CMO",
			node: v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-3", Annotations: map[string]string{cordonAnnotation: cordonAnnotationMessage}},
				Spec:       v1.NodeSpec{Unschedulable: true},
			},
			expectedUnschedulable: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewSimpleClientset(tc.node.DeepCopy())
			drainer := NewHelper(context.Background(), fakeClient, cordonAnnotation)

			err := RunCordonOrUncordon(drainer, &tc.node, Uncordon)
			if err != nil {
				t.Error(err)
			}

			node, err := fakeClient.CoreV1().Nodes().Get(context.Background(), tc.node.Name, metav1.GetOptions{})
			if err != nil {
				t.Error(err)
			}

			if tc.expectedUnschedulable != node.Spec.Unschedulable {
				t.Errorf("Expected node %s unschedulable status to be: %t, got %t.", tc.node.Name, tc.expectedUnschedulable, node.Spec.Unschedulable)
			}

			if !reflect.DeepEqual(expectedAnnotations, node.Annotations) {
				t.Errorf("Expected node %s annotations to be: %#v, got %#v.", tc.node.Name, expectedAnnotations, node.Annotations)
			}
		})
	}
}
