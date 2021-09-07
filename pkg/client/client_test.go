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

	secv1 "github.com/openshift/api/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubectl/pkg/drain"

	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	ossfake "github.com/openshift/client-go/security/clientset/versioned/fake"
	monfake "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned/fake"
)

const (
	ns         = "openshift-monitoring"
	nsUWM      = "openshift-user-workload-monitoring"
	assetsPath = "../../assets"
)

func TestMergeMetadata(t *testing.T) {
	testCases := []struct {
		name     string
		expected map[string]string
		new      map[string]string
		old      map[string]string
	}{
		{
			name: "new annotation and label addition",
			expected: map[string]string{
				"old": "value",
				"new": "value",
			},
			old: map[string]string{
				"old": "value",
			},
			new: map[string]string{
				"new": "value",
			},
		},
		{
			name: "immutable annotation and label values",
			expected: map[string]string{
				"key": "old",
			},
			old: map[string]string{
				"key": "old",
			},
			new: map[string]string{
				"key": "new",
			},
		},
		{
			name: "annotation and label removal",
			expected: map[string]string{
				"key": "value",
			},
			old: map[string]string{
				"key": "value",
			},
			new: map[string]string{
				"monitoring.openshift.io/new": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			newMeta := metav1.ObjectMeta{
				Annotations: tc.new,
				Labels:      tc.new,
			}
			oldMeta := metav1.ObjectMeta{
				Annotations: tc.old,
				Labels:      tc.old,
			}

			mergeMetadata(&oldMeta, newMeta)

			if !reflect.DeepEqual(oldMeta.Annotations, tc.expected) {
				t.Errorf("expected old annotations %q, got %q", tc.expected, oldMeta.Annotations)
			}
			if !reflect.DeepEqual(oldMeta.Labels, tc.expected) {
				t.Errorf("expected old labels %q, got %q", tc.expected, oldMeta.Labels)
			}
		})
	}
}

func TestCreateOrUpdateDeployment(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialSpec         appsv1.DeploymentSpec
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedSpec         appsv1.DeploymentSpec
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty and no spec change",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels:      nil,
			expectedAnnotations: nil,
		},
		{
			name:        "inital labels/annotations are empty and spec change",
			initialSpec: appsv1.DeploymentSpec{Paused: true},
			updatedSpec: appsv1.DeploymentSpec{Paused: false},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name:        "label/annotation merge and spec change",
			initialSpec: appsv1.DeploymentSpec{Paused: true},
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedSpec: appsv1.DeploymentSpec{Paused: false},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "kube-state-metrics",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
				Spec: tc.initialSpec,
			}

			c := Client{
				kclient: fake.NewSimpleClientset(dep.DeepCopy()),
			}

			if _, err := c.kclient.AppsV1().Deployments(ns).Get(ctx, dep.Name, metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			dep.SetLabels(tc.updatedLabels)
			dep.SetAnnotations(tc.updatedAnnotations)
			dep.Spec = tc.updatedSpec
			if err := c.CreateOrUpdateDeployment(ctx, dep); err != nil {
				t.Fatal(err)
			}

			after, err := c.kclient.AppsV1().Deployments(ns).Get(ctx, dep.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}

			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateDaemonSet(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name: "label/annotation merge",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			ds := &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node-exporter",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}

			c := Client{
				kclient: fake.NewSimpleClientset(ds.DeepCopy()),
			}
			if _, err := c.kclient.AppsV1().DaemonSets(ns).Get(ctx, ds.Name, metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			ds.SetLabels(tc.updatedLabels)
			ds.SetAnnotations(tc.updatedAnnotations)
			if err := c.CreateOrUpdateDaemonSet(ctx, ds); err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.AppsV1().DaemonSets(ns).Get(ctx, ds.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateSecret(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name: "label/annotation merge",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			s := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "secret",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}

			c := Client{
				kclient: fake.NewSimpleClientset(s.DeepCopy()),
			}

			if _, err := c.kclient.CoreV1().Secrets(ns).Get(ctx, s.Name, metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			s.SetLabels(tc.updatedLabels)
			s.SetAnnotations(tc.updatedAnnotations)
			if err := c.CreateOrUpdateSecret(ctx, s); err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.CoreV1().Secrets(ns).Get(ctx, s.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateConfigMap(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name: "label/annotation merge",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			cm := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "cluster-monitoring-operator",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}

			c := Client{
				kclient: fake.NewSimpleClientset(cm),
			}

			if _, err := c.kclient.CoreV1().ConfigMaps(ns).Get(ctx, cm.Name, metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			cm.SetLabels(tc.updatedLabels)
			cm.SetAnnotations(tc.updatedAnnotations)
			if err := c.CreateOrUpdateConfigMap(ctx, cm); err != nil {
				t.Fatal(err)
			}

			after, err := c.kclient.CoreV1().ConfigMaps(ns).Get(ctx, cm.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateService(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                   string
		initialSessionAffinity v1.ServiceAffinity
		initialLabels          map[string]string
		initialAnnotations     map[string]string
		updatedSessionAffinity v1.ServiceAffinity
		updatedLabels          map[string]string
		updatedAnnotations     map[string]string
		expectedUpdate         bool
		expectedLabels         map[string]string
		expectedAnnotations    map[string]string
	}{
		{
			name:                   "inital labels/annotations are empty and no spec change",
			initialSessionAffinity: v1.ServiceAffinityClientIP,
			updatedSessionAffinity: v1.ServiceAffinityClientIP,
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels:      nil,
			expectedAnnotations: nil,
			expectedUpdate:      false,
		},
		{
			name:                   "inital labels/annotations are empty and spec change",
			initialSessionAffinity: v1.ServiceAffinityNone,
			updatedSessionAffinity: v1.ServiceAffinityClientIP,
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedUpdate: true,
		},
		{
			name:                   "label/annotation merge and spec change",
			initialSessionAffinity: v1.ServiceAffinityNone,
			updatedSessionAffinity: v1.ServiceAffinityClientIP,
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
			expectedUpdate: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			svc := &v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
				Spec: v1.ServiceSpec{
					Ports: []v1.ServicePort{
						{
							Name:       "web",
							Port:       9091,
							TargetPort: intstr.IntOrString{Type: 1, StrVal: "web"},
						},
						{
							Name:       "tenancy",
							Port:       9092,
							TargetPort: intstr.IntOrString{Type: 1, StrVal: "tenancy"},
						},
					},
					Selector: map[string]string{
						"app":                          "prometheus",
						"prometheus":                   "k8s",
						"app.kubernetes.io/component":  "prometheus",
						"app.kubernetes.io/managed-by": "cluster-monitoring-operator",
						"app.kubernetes.io/name":       "prometheus",
						"app.kubernetes.io/part-of":    "openshift-monitoring",
					},
					SessionAffinity: tc.initialSessionAffinity,
					Type:            v1.ServiceTypeClusterIP,
					ClusterIP:       "None",
				},
			}

			c := Client{
				kclient: fake.NewSimpleClientset(svc.DeepCopy()),
			}

			before, err := c.kclient.CoreV1().Services(ns).Get(ctx, svc.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			svc.SetLabels(tc.updatedLabels)
			svc.SetAnnotations(tc.updatedAnnotations)
			svc.Spec.SessionAffinity = v1.ServiceAffinityClientIP
			if err := c.CreateOrUpdateService(ctx, svc); err != nil {
				t.Fatal(err)
			}

			after, err := c.kclient.CoreV1().Services(ns).Get(ctx, svc.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if tc.expectedUpdate == reflect.DeepEqual(before, after) {
				t.Errorf("expected update %v, got none", tc.expectedUpdate)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateRole(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name: "label/annotation merge",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s-config",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}
			c := Client{
				kclient: fake.NewSimpleClientset(role.DeepCopy()),
			}
			if _, err := c.kclient.RbacV1().Roles(ns).Get(ctx, role.Name, metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			role.SetLabels(tc.updatedLabels)
			role.SetAnnotations(tc.updatedAnnotations)
			if err := c.CreateOrUpdateRole(ctx, role); err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.RbacV1().Roles(ns).Get(ctx, role.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateRoleBinding(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name               string
		initialLabels      map[string]string
		initialAnnotations map[string]string
		initialRoleRef     rbacv1.RoleRef
		initialSubjects    []rbacv1.Subject

		updatedLabels      map[string]string
		updatedAnnotations map[string]string
		updatedRoleRef     rbacv1.RoleRef
		updatedSubjects    []rbacv1.Subject

		expectedUpdate      bool
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty and no spec change",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels:      nil,
			expectedAnnotations: nil,
			expectedUpdate:      false,
		},
		{
			name: "label/annotation merge and RoleRef change",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			updatedRoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "prometheus",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
			expectedUpdate: true,
		},
		{
			name: "label/annotation merge and Subjects change",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			updatedSubjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus",
					Namespace: ns,
				},
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
			expectedUpdate: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			roleBinding := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s-config",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
				RoleRef:  tc.initialRoleRef,
				Subjects: tc.initialSubjects,
			}
			c := Client{
				kclient: fake.NewSimpleClientset(roleBinding.DeepCopy()),
			}
			before, err := c.kclient.RbacV1().RoleBindings(ns).Get(ctx, roleBinding.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			roleBinding.SetLabels(tc.updatedLabels)
			roleBinding.SetAnnotations(tc.updatedAnnotations)
			roleBinding.RoleRef = tc.updatedRoleRef
			roleBinding.Subjects = tc.updatedSubjects
			err = c.CreateOrUpdateRoleBinding(ctx, roleBinding)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.RbacV1().RoleBindings(ns).Get(ctx, roleBinding.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if tc.expectedUpdate == reflect.DeepEqual(before, after) {
				t.Errorf("expected update %v, got none", tc.expectedUpdate)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("test %s for expected annotations %q, got %q", tc.name, tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("test %s for expected labels %q, got %q", tc.name, tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateClusterRole(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name: "label/annotation merge",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			clusterRole := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s",
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}
			c := Client{
				kclient: fake.NewSimpleClientset(clusterRole.DeepCopy()),
			}
			if _, err := c.kclient.RbacV1().ClusterRoles().Get(ctx, clusterRole.Name, metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			clusterRole.SetLabels(tc.updatedLabels)
			clusterRole.SetAnnotations(tc.updatedAnnotations)
			if err := c.CreateOrUpdateClusterRole(ctx, clusterRole); err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.RbacV1().ClusterRoles().Get(ctx, clusterRole.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("test %s for expected annotations %q, got %q", tc.name, tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("test %s for expected labels %q, got %q", tc.name, tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateClusterRoleBinding(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name               string
		initialLabels      map[string]string
		initialAnnotations map[string]string
		initialRoleRef     rbacv1.RoleRef
		initialSubjects    []rbacv1.Subject

		updatedLabels      map[string]string
		updatedAnnotations map[string]string
		updatedRoleRef     rbacv1.RoleRef
		updatedSubjects    []rbacv1.Subject

		expectedUpdate      bool
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty and no spec change",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels:      nil,
			expectedAnnotations: nil,
			expectedUpdate:      false,
		},
		{
			name: "label/annotation merge and RoleRef change",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			updatedRoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "prometheus",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
			expectedUpdate: true,
		},
		{
			name: "label/annotation merge and Subjects change",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			updatedSubjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus",
					Namespace: ns,
				},
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
			expectedUpdate: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			clusterRoleBinding := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s",
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
				RoleRef:  tc.initialRoleRef,
				Subjects: tc.initialSubjects,
			}

			c := Client{
				kclient: fake.NewSimpleClientset(clusterRoleBinding.DeepCopy()),
			}
			before, err := c.kclient.RbacV1().ClusterRoleBindings().Get(ctx, clusterRoleBinding.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			clusterRoleBinding.SetLabels(tc.updatedLabels)
			clusterRoleBinding.SetAnnotations(tc.updatedAnnotations)
			clusterRoleBinding.RoleRef = tc.updatedRoleRef
			clusterRoleBinding.Subjects = tc.updatedSubjects
			if err := c.CreateOrUpdateClusterRoleBinding(ctx, clusterRoleBinding); err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.RbacV1().ClusterRoleBindings().Get(ctx, clusterRoleBinding.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if tc.expectedUpdate == reflect.DeepEqual(before, after) {
				t.Errorf("expected update %v, got none", tc.expectedUpdate)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("test %s for expected annotations %q, got %q", tc.name, tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("test %s for expected labels %q, got %q", tc.name, tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateSecurityContextConstraints(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name: "label/annotation merge",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			scc := &secv1.SecurityContextConstraints{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node-exporter",
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}

			c := Client{
				ossclient: ossfake.NewSimpleClientset(),
			}
			c.ossclient.SecurityV1().SecurityContextConstraints().Create(ctx, scc.DeepCopy(), metav1.CreateOptions{})

			if _, err := c.ossclient.SecurityV1().SecurityContextConstraints().Get(ctx, scc.GetName(), metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			scc.SetLabels(tc.updatedLabels)
			scc.SetAnnotations(tc.updatedAnnotations)
			if err := c.CreateOrUpdateSecurityContextConstraints(ctx, scc); err != nil {
				t.Fatal(err)
			}

			after, err := c.ossclient.SecurityV1().SecurityContextConstraints().Get(ctx, scc.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateServiceMonitor(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name: "label/annotation merge",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			serviceMonitor := &monv1.ServiceMonitor{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}

			c := Client{
				mclient: monfake.NewSimpleClientset(serviceMonitor.DeepCopy()),
			}
			if _, err := c.mclient.MonitoringV1().ServiceMonitors(ns).Get(ctx, serviceMonitor.GetName(), metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			serviceMonitor.SetLabels(tc.updatedLabels)
			serviceMonitor.SetAnnotations(tc.updatedAnnotations)
			if err := c.CreateOrUpdateServiceMonitor(ctx, serviceMonitor); err != nil {
				t.Fatal(err)
			}
			after, err := c.mclient.MonitoringV1().ServiceMonitors(ns).Get(ctx, serviceMonitor.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdatePrometheusRule(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name: "label/annotation merge",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			rule := &monv1.PrometheusRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}

			c := Client{
				mclient: monfake.NewSimpleClientset(rule.DeepCopy()),
			}
			if _, err := c.mclient.MonitoringV1().PrometheusRules(ns).Get(ctx, rule.GetName(), metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			rule.SetLabels(tc.updatedLabels)
			rule.SetAnnotations(tc.updatedAnnotations)
			if err := c.CreateOrUpdatePrometheusRule(ctx, rule); err != nil {
				t.Fatal(err)
			}
			after, err := c.mclient.MonitoringV1().PrometheusRules(ns).Get(ctx, rule.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdatePrometheus(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name: "label/annotation merge",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			prometheus := &monv1.Prometheus{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "k8s",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}

			c := Client{
				mclient: monfake.NewSimpleClientset(prometheus.DeepCopy()),
			}
			if _, err := c.mclient.MonitoringV1().Prometheuses(ns).Get(ctx, prometheus.GetName(), metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			prometheus.SetLabels(tc.updatedLabels)
			prometheus.SetAnnotations(tc.updatedAnnotations)
			if err := c.CreateOrUpdatePrometheus(ctx, prometheus); err != nil {
				t.Fatal(err)
			}

			after, err := c.mclient.MonitoringV1().Prometheuses(ns).Get(ctx, prometheus.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateAlertmanager(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name: "inital labels/annotations are empty",
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name: "label/annotation merge",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			alertmanager := &monv1.Alertmanager{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "main",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}

			c := Client{
				mclient: monfake.NewSimpleClientset(alertmanager.DeepCopy()),
			}
			if _, err := c.mclient.MonitoringV1().Alertmanagers(ns).Get(ctx, alertmanager.GetName(), metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			alertmanager.SetLabels(tc.updatedLabels)
			alertmanager.SetAnnotations(tc.updatedAnnotations)
			if err := c.CreateOrUpdateAlertmanager(ctx, alertmanager); err != nil {
				t.Fatal(err)
			}

			after, err := c.mclient.MonitoringV1().Alertmanagers(ns).Get(ctx, alertmanager.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

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
			c := Client{
				kclient: fake.NewSimpleClientset(tc.node.DeepCopy()),
			}
			drainer := drain.Helper{Ctx: context.Background(), Client: c.KubernetesInterface()}

			err := c.CordonNode(context.Background(), &drainer, tc.node.Name)
			if err != nil {
				t.Error(err)
			}

			node, err := c.GetNode(context.Background(), tc.node.Name)
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
	expectedAnnotations := map[string]string{}
	for _, tc := range []struct {
		name                  string
		node                  v1.Node
		expectedUnschedulable bool
	}{
		{
			name: "Schedulable node",
			node: v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-1", Annotations: map[string]string{}},
				Spec:       v1.NodeSpec{Unschedulable: false},
			},
			expectedUnschedulable: false,
		},
		{
			name: "Unschedulable node",
			node: v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-2", Annotations: map[string]string{}},
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
			c := Client{
				kclient: fake.NewSimpleClientset(tc.node.DeepCopy()),
			}
			drainer := drain.Helper{Ctx: context.Background(), Client: c.KubernetesInterface()}

			err := c.UncordonNode(context.Background(), &drainer, tc.node.Name)
			if err != nil {
				t.Error(err)
			}

			node, err := c.GetNode(context.Background(), tc.node.Name)
			if err != nil {
				t.Error(err)
			}

			if tc.expectedUnschedulable != node.Spec.Unschedulable {
				t.Errorf("Expected node %s unschedulable status to be: %t, got %t.", tc.node.Name, tc.expectedUnschedulable, node.Spec.Unschedulable)
			}

			if !reflect.DeepEqual(expectedAnnotations, node.Annotations) {
				t.Errorf("Expected node %s annotations to be: %v, got %v.", tc.node.Name, expectedAnnotations, node.Annotations)
			}
		})
	}

}
