// Copyright 2020 The Cluster Monitoring Operator Authors
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
	"reflect"
	"testing"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCreateOrUpdateClusterRoleBinding(t *testing.T) {
	testCases := []struct {
		name           string
		expectedUpdate bool
		clientset      kubernetes.Interface
	}{
		{
			name:           "no change",
			expectedUpdate: false,
			clientset: fake.NewSimpleClientset(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "prometheus-k8s",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     "prometheus-k8s",
				},
				Subjects: []rbacv1.Subject{
					rbacv1.Subject{
						Kind:      "ServiceAccount",
						Name:      "prometheus-k8s",
						Namespace: "openshift-monitoring",
					},
				},
			}),
		},
		{
			name:           "roleref change",
			expectedUpdate: true,
			clientset: fake.NewSimpleClientset(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "prometheus-k8s",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     "prometheus-k8s-changed",
				},
				Subjects: []rbacv1.Subject{
					rbacv1.Subject{
						Kind:      "ServiceAccount",
						Name:      "prometheus-k8s",
						Namespace: "openshift-monitoring",
					},
				},
			}),
		},
		{
			name:           "subjects change",
			expectedUpdate: true,
			clientset: fake.NewSimpleClientset(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "prometheus-k8s",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     "prometheus-k8s",
				},
				Subjects: []rbacv1.Subject{
					rbacv1.Subject{
						Kind:      "ServiceAccount",
						Name:      "prometheus-k8s",
						Namespace: "openshift-monitoring",
					},
					rbacv1.Subject{
						Kind:      "ServiceAccount",
						Name:      "prometheus-k8s-new",
						Namespace: "openshift-monitoring",
					},
				},
			}),
		},
		{
			name:           "labels change",
			expectedUpdate: true,
			clientset: fake.NewSimpleClientset(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "prometheus-k8s",
					Labels: map[string]string{
						"label": "value",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     "prometheus-k8s",
				},
				Subjects: []rbacv1.Subject{
					rbacv1.Subject{
						Kind:      "ServiceAccount",
						Name:      "prometheus-k8s",
						Namespace: "openshift-monitoring",
					},
					rbacv1.Subject{
						Kind:      "ServiceAccount",
						Name:      "prometheus-k8s-new",
						Namespace: "openshift-monitoring",
					},
				},
			}),
		},
		{
			name:           "annotations change",
			expectedUpdate: false,
			clientset: fake.NewSimpleClientset(&rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "prometheus-k8s",
					Annotations: map[string]string{
						"annotation": "value",
					},
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     "prometheus-k8s",
				},
				Subjects: []rbacv1.Subject{
					rbacv1.Subject{
						Kind:      "ServiceAccount",
						Name:      "prometheus-k8s",
						Namespace: "openshift-monitoring",
					},
				},
			}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", manifests.NewDefaultConfig())
			crb, err := f.PrometheusK8sClusterRoleBinding()
			if err != nil {
				t.Fatal(err)
			}

			var c Client
			c.kclient = tc.clientset
			before, err := c.kclient.RbacV1().ClusterRoleBindings().Get(context.TODO(), "prometheus-k8s", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateClusterRoleBinding(crb)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.RbacV1().ClusterRoleBindings().Get(context.TODO(), "prometheus-k8s", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			unchanged := reflect.DeepEqual(before, after)

			if unchanged == tc.expectedUpdate {
				t.Logf("test for %s failed", tc.name)
				t.Fail()
			}
		})
	}
}
