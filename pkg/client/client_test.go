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
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	monv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"

	monfake "github.com/coreos/prometheus-operator/pkg/client/versioned/fake"
	ossfake "github.com/openshift/client-go/security/clientset/versioned/fake"
)

const (
	ns    = "openshift-monitoring"
	nsUWM = "openshift-user-workload-monitoring"
)

func TestMain(m *testing.M) {
	manifests.Manifests.SetDirectoryPath("../../assets")
}

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
	testCases := []struct {
		name                string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name: "no change",
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "kube-state-metrics",
			},
		},
		{
			name: "labels change",
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "kube-state-metrics",
				"label":                  "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
		},
		{
			name: "annotations change",
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "kube-state-metrics",
			},
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			dep, err := f.KubeStateMetricsDeployment()
			if err != nil {
				t.Fatal(err)
			}
			// Overriding labels to prevent changing tests with each upgrade of kube-state-metrics version
			// as our DaemonSet contains "app.kubernetes.io/version" label
			dep.SetLabels(map[string]string{"app.kubernetes.io/name": "kube-state-metrics"})

			data := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "kube-state-metrics",
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}
			var c Client
			c.kclient = fake.NewSimpleClientset(data)
			_, err = c.kclient.AppsV1().Deployments(ns).Get(context.TODO(), "kube-state-metrics", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateDeployment(dep)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.AppsV1().Deployments(ns).Get(context.TODO(), "kube-state-metrics", metav1.GetOptions{})
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
	testCases := []struct {
		name                string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name: "no change",
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "node-exporter",
			},
		},
		{
			name: "labels change",
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "node-exporter",
				"label":                  "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
		},
		{
			name: "annotations change",
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "node-exporter",
			},
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			ds, err := f.NodeExporterDaemonSet()
			// Overriding labels to prevent changing tests with each upgrade of node-exporter version
			// as our DaemonSet contains "app.kubernetes.io/version" label
			ds.SetLabels(map[string]string{"app.kubernetes.io/name": "node-exporter"})
			if err != nil {
				t.Fatal(err)
			}

			data := &appsv1.DaemonSet{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "node-exporter",
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}
			var c Client
			c.kclient = fake.NewSimpleClientset(data)
			_, err = c.kclient.AppsV1().DaemonSets(ns).Get(context.TODO(), "node-exporter", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateDaemonSet(ds)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.AppsV1().DaemonSets(ns).Get(context.TODO(), "node-exporter", metav1.GetOptions{})
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
	testCases := []struct {
		name                string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name: "no change",
			expectedLabels: map[string]string{
				"k8s-app": "prometheus-k8s",
			},
		},
		{
			name: "labels change",
			expectedLabels: map[string]string{
				"k8s-app": "prometheus-k8s",
				"label":   "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
		},
		{
			name: "annotations change",
			expectedLabels: map[string]string{
				"k8s-app": "prometheus-k8s",
			},
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			s, err := f.PrometheusK8sGrpcTLSSecret()
			if err != nil {
				t.Fatal(err)
			}

			data := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s-grpc-tls",
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}
			var c Client
			c.kclient = fake.NewSimpleClientset(data)
			_, err = c.kclient.CoreV1().Secrets(ns).Get(context.TODO(), "prometheus-k8s-grpc-tls", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateSecret(s)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.CoreV1().Secrets(ns).Get(context.TODO(), "prometheus-k8s-grpc-tls", metav1.GetOptions{})
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
	testCases := []struct {
		name                string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name: "no change",
			expectedLabels: map[string]string{
				"config.openshift.io/inject-trusted-cabundle": "true",
			},
		},
		{
			name: "labels change",
			expectedLabels: map[string]string{
				"config.openshift.io/inject-trusted-cabundle": "true",
				"label": "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
		},
		{
			name: "annotations change",
			expectedLabels: map[string]string{
				"config.openshift.io/inject-trusted-cabundle": "true",
			},
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			cm, err := f.AlertmanagerTrustedCABundle() // using CA bundle as this is one of ConfigMaps with labels set
			if err != nil {
				t.Fatal(err)
			}

			data := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "alertmanager-trusted-ca-bundle",
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}
			var c Client
			c.kclient = fake.NewSimpleClientset(data)
			_, err = c.kclient.CoreV1().ConfigMaps(ns).Get(context.TODO(), "alertmanager-trusted-ca-bundle", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateConfigMap(cm)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.CoreV1().ConfigMaps(ns).Get(context.TODO(), "alertmanager-trusted-ca-bundle", metav1.GetOptions{})
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
	testCases := []struct {
		name                string
		expectedUpdate      bool
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
		sessionAffinity     v1.ServiceAffinity
	}{
		{
			name:           "no change",
			expectedUpdate: false,
			expectedLabels: map[string]string{
				"prometheus": "k8s",
			},
			expectedAnnotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": "prometheus-k8s-tls",
			},
			sessionAffinity: v1.ServiceAffinityClientIP,
		},
		{
			name:           "spec change",
			expectedUpdate: true,
			expectedLabels: map[string]string{
				"prometheus": "k8s",
			},
			expectedAnnotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": "prometheus-k8s-tls",
			},
			sessionAffinity: v1.ServiceAffinityNone,
		},
		{
			name:           "labels and spec change",
			expectedUpdate: true,
			expectedLabels: map[string]string{
				"prometheus": "k8s",
				"label":      "value",
			},
			expectedAnnotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": "prometheus-k8s-tls",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
			sessionAffinity: v1.ServiceAffinityNone,
		},
		{
			name:           "annotation and spec change",
			expectedUpdate: true,
			expectedLabels: map[string]string{
				"prometheus": "k8s",
			},
			expectedAnnotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": "prometheus-k8s-tls",
				"label": "value",
			},
			addedAnnotations: map[string]string{
				"label": "value",
			},
			sessionAffinity: v1.ServiceAffinityNone,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			s, err := f.PrometheusK8sService()
			if err != nil {
				t.Fatal(err)
			}

			data := &v1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s",
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
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
						"app":        "prometheus",
						"prometheus": "k8s",
					},
					SessionAffinity: tc.sessionAffinity,
					Type:            v1.ServiceTypeClusterIP,
				},
			}

			var c Client
			c.kclient = fake.NewSimpleClientset(data)
			before, err := c.kclient.CoreV1().Services(ns).Get(context.TODO(), "prometheus-k8s", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateService(s)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.CoreV1().Services(ns).Get(context.TODO(), "prometheus-k8s", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			unchanged := reflect.DeepEqual(before, after)

			if unchanged == tc.expectedUpdate {
				t.Errorf("expected update %t, got %t", tc.expectedUpdate, unchanged)
			}

			if !unchanged && !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !unchanged && !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
		})
	}
}

func TestCreateOrUpdateRole(t *testing.T) {
	testCases := []struct {
		name                string
		roleName            string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name:     "no change",
			roleName: "prometheus-k8s-config",
		},
		{
			name:     "annotations change",
			roleName: "prometheus-k8s-config",
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
		{
			name:     "labels change",
			roleName: "prometheus-k8s-config",
			expectedLabels: map[string]string{
				"label": "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			r, err := f.PrometheusK8sRoleConfig()
			if err != nil {
				t.Fatal(err)
			}

			data := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s-config",
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}
			var c Client
			c.kclient = fake.NewSimpleClientset(data)
			_, err = c.kclient.RbacV1().Roles(ns).Get(context.TODO(), "prometheus-k8s-config", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateRole(r)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.RbacV1().Roles(ns).Get(context.TODO(), "prometheus-k8s-config", metav1.GetOptions{})
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
	testCases := []struct {
		name                string
		expectedUpdate      bool
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
		roleref             rbacv1.RoleRef
		subjects            []rbacv1.Subject
	}{
		{
			name:           "no change",
			expectedUpdate: false,
			roleref: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "prometheus-k8s-config",
			},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus-k8s",
					Namespace: ns,
				},
			},
		},
		{
			name:           "roleref change",
			expectedUpdate: true,
			roleref:        rbacv1.RoleRef{},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus-k8s",
					Namespace: ns,
				},
			},
		},
		{
			name:           "subjects change",
			expectedUpdate: true,
			roleref: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "prometheus-k8s-config",
			},
			subjects: []rbacv1.Subject{},
		},
		{
			name:           "annotations change",
			expectedUpdate: false,
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
			roleref: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "prometheus-k8s-config",
			},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus-k8s",
					Namespace: ns,
				},
			},
		},
		{
			name:           "labels change",
			expectedUpdate: false,
			expectedLabels: map[string]string{
				"label": "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
			roleref: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "prometheus-k8s-config",
			},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus-k8s",
					Namespace: ns,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			rb, err := f.PrometheusK8sRoleBindingConfig()
			if err != nil {
				t.Fatal(err)
			}

			data := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s-config",
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
				RoleRef:  tc.roleref,
				Subjects: tc.subjects,
			}
			var c Client
			c.kclient = fake.NewSimpleClientset(data)
			before, err := c.kclient.RbacV1().RoleBindings(ns).Get(context.TODO(), "prometheus-k8s-config", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateRoleBinding(rb)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.RbacV1().RoleBindings(ns).Get(context.TODO(), "prometheus-k8s-config", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			unchanged := reflect.DeepEqual(before, after)

			if unchanged == tc.expectedUpdate {
				t.Logf("test for %s failed", tc.name)
				t.Fail()
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

func TestCreateOrUpdateClusterRole(t *testing.T) {
	testCases := []struct {
		name                string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name: "no change",
		},
		{
			name: "labels change",
			expectedLabels: map[string]string{
				"label": "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
		},
		{
			name: "annotations change",
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			cr, err := f.PrometheusK8sClusterRole()
			if err != nil {
				t.Fatal(err)
			}

			data := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s",
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}
			var c Client
			c.kclient = fake.NewSimpleClientset(data)
			_, err = c.kclient.RbacV1().ClusterRoles().Get(context.TODO(), "prometheus-k8s", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateClusterRole(cr)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.kclient.RbacV1().ClusterRoles().Get(context.TODO(), "prometheus-k8s", metav1.GetOptions{})
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

func TestCreateOrUpdateClusterRoleBinding(t *testing.T) {
	testCases := []struct {
		name                string
		expectedUpdate      bool
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
		roleref             rbacv1.RoleRef
		subjects            []rbacv1.Subject
	}{
		{
			name:           "no change",
			expectedUpdate: false,
			roleref: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "prometheus-k8s",
			},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus-k8s",
					Namespace: ns,
				},
			},
		},
		{
			name:           "roleref change",
			expectedUpdate: true,
			roleref:        rbacv1.RoleRef{},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus-k8s",
					Namespace: ns,
				},
			},
		},
		{
			name:           "subjects change",
			expectedUpdate: true,
			roleref: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "prometheus-k8s",
			},
			subjects: []rbacv1.Subject{},
		},
		{
			name:           "labels change",
			expectedUpdate: false,
			expectedLabels: map[string]string{
				"label": "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
			roleref: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "prometheus-k8s",
			},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus-k8s",
					Namespace: ns,
				},
			},
		},
		{
			name:           "annotations change",
			expectedUpdate: false,
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
			roleref: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "prometheus-k8s",
			},
			subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus-k8s",
					Namespace: ns,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			crb, err := f.PrometheusK8sClusterRoleBinding()
			if err != nil {
				t.Fatal(err)
			}

			data := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s",
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
				RoleRef:  tc.roleref,
				Subjects: tc.subjects,
			}

			var c Client
			c.kclient = fake.NewSimpleClientset(data)
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
				t.Errorf("expected update %t, got %t", tc.expectedUpdate, unchanged)
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

func TestCreateOrUpdateSecurityContextConstraints(t *testing.T) {
	testCases := []struct {
		name                string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name: "no change",
			expectedAnnotations: map[string]string{
				"kubernetes.io/description": "node-exporter scc is used for the Prometheus node exporter",
			},
		},
		{
			name: "labels change",
			expectedLabels: map[string]string{
				"label": "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
			expectedAnnotations: map[string]string{
				"kubernetes.io/description": "node-exporter scc is used for the Prometheus node exporter",
			},
		},
		{
			name: "annotations change",
			expectedAnnotations: map[string]string{
				"annotation":                "value",
				"kubernetes.io/description": "node-exporter scc is used for the Prometheus node exporter",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			scc, err := f.NodeExporterSecurityContextConstraints()
			if err != nil {
				t.Fatal(err)
			}

			data := &secv1.SecurityContextConstraints{
				ObjectMeta: metav1.ObjectMeta{
					Name:        scc.GetName(),
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}

			var c Client
			c.ossclient = ossfake.NewSimpleClientset()
			c.ossclient.SecurityV1().SecurityContextConstraints().Create(context.TODO(), data, metav1.CreateOptions{})

			_, err = c.ossclient.SecurityV1().SecurityContextConstraints().Get(context.TODO(), scc.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateSecurityContextConstraints(scc)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.ossclient.SecurityV1().SecurityContextConstraints().Get(context.TODO(), scc.GetName(), metav1.GetOptions{})
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
	testCases := []struct {
		name                string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name: "no change",
			expectedLabels: map[string]string{
				"k8s-app": "prometheus",
			},
		},
		{
			name: "labels change",
			expectedLabels: map[string]string{
				"k8s-app": "prometheus",
				"label":   "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
		},
		{
			name: "annotations change",
			expectedLabels: map[string]string{
				"k8s-app": "prometheus",
			},
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			sm, err := f.PrometheusK8sPrometheusServiceMonitor()
			if err != nil {
				t.Fatal(err)
			}

			data := &monv1.ServiceMonitor{
				ObjectMeta: metav1.ObjectMeta{
					Name:        sm.GetName(),
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}

			var c Client
			c.mclient = monfake.NewSimpleClientset(data)
			_, err = c.mclient.MonitoringV1().ServiceMonitors(ns).Get(context.TODO(), sm.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateServiceMonitor(sm)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.mclient.MonitoringV1().ServiceMonitors(ns).Get(context.TODO(), sm.GetName(), metav1.GetOptions{})
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
	testCases := []struct {
		name                string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name: "no change",
			expectedLabels: map[string]string{
				"prometheus": "k8s",
				"role":       "alert-rules",
			},
		},
		{
			name: "labels change",
			expectedLabels: map[string]string{
				"prometheus": "k8s",
				"role":       "alert-rules",
				"label":      "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
		},
		{
			name: "annotations change",
			expectedLabels: map[string]string{
				"prometheus": "k8s",
				"role":       "alert-rules",
			},
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			pr, err := f.PrometheusK8sRules()
			if err != nil {
				t.Fatal(err)
			}

			data := &monv1.PrometheusRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:        pr.GetName(),
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}

			var c Client
			c.mclient = monfake.NewSimpleClientset(data)
			_, err = c.mclient.MonitoringV1().PrometheusRules(ns).Get(context.TODO(), pr.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdatePrometheusRule(pr)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.mclient.MonitoringV1().PrometheusRules(ns).Get(context.TODO(), pr.GetName(), metav1.GetOptions{})
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
	testCases := []struct {
		name                string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name: "no change",
			expectedLabels: map[string]string{
				"prometheus": "k8s",
			},
		},
		{
			name: "labels change",
			expectedLabels: map[string]string{
				"prometheus": "k8s",
				"label":      "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
		},
		{
			name: "annotations change",
			expectedLabels: map[string]string{
				"prometheus": "k8s",
			},
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			pr, err := f.PrometheusK8s("prometheus-k8s.openshift-monitoring.svc", &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "foo"}}, nil)
			if err != nil {
				t.Fatal(err)
			}

			data := &monv1.Prometheus{
				ObjectMeta: metav1.ObjectMeta{
					Name:        pr.GetName(),
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}

			var c Client
			c.mclient = monfake.NewSimpleClientset(data)
			_, err = c.mclient.MonitoringV1().Prometheuses(ns).Get(context.TODO(), pr.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdatePrometheus(pr)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.mclient.MonitoringV1().Prometheuses(ns).Get(context.TODO(), pr.GetName(), metav1.GetOptions{})
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
	testCases := []struct {
		name                string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		addedLabels         map[string]string
		addedAnnotations    map[string]string
	}{
		{
			name: "no change",
			expectedLabels: map[string]string{
				"alertmanager": "main",
			},
		},
		{
			name: "labels change",
			expectedLabels: map[string]string{
				"alertmanager": "main",
				"label":        "value",
			},
			addedLabels: map[string]string{
				"label": "value",
			},
		},
		{
			name: "annotations change",
			expectedLabels: map[string]string{
				"alertmanager": "main",
			},
			expectedAnnotations: map[string]string{
				"annotation": "value",
			},
			addedAnnotations: map[string]string{
				"annotation": "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			f := manifests.NewFactory(ns, nsUWM, manifests.NewDefaultConfig())
			pr, err := f.AlertmanagerMain("alertmanager-main.openshift-monitoring.svc", &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "foo"}})
			if err != nil {
				t.Fatal(err)
			}

			data := &monv1.Alertmanager{
				ObjectMeta: metav1.ObjectMeta{
					Name:        pr.GetName(),
					Namespace:   ns,
					Labels:      tc.addedLabels,
					Annotations: tc.addedAnnotations,
				},
			}

			var c Client
			c.mclient = monfake.NewSimpleClientset(data)
			_, err = c.mclient.MonitoringV1().Alertmanagers(ns).Get(context.TODO(), pr.GetName(), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			err = c.CreateOrUpdateAlertmanager(pr)
			if err != nil {
				t.Fatal(err)
			}
			after, err := c.mclient.MonitoringV1().Alertmanagers(ns).Get(context.TODO(), pr.GetName(), metav1.GetOptions{})
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
