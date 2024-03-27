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
	"fmt"
	"reflect"
	"testing"
	"time"

	routev1 "github.com/openshift/api/route/v1"
	secv1 "github.com/openshift/api/security/v1"
	osrfake "github.com/openshift/client-go/route/clientset/versioned/fake"
	ossfake "github.com/openshift/client-go/security/clientset/versioned/fake"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	monfake "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned/fake"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
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

func TestCreateOrUpdateRoute(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialSpec         routev1.RouteSpec
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		updatedSpec         routev1.RouteSpec
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		expectedSpec        routev1.RouteSpec
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
	}{
		{
			name:        "inital labels/annotations are empty and spec change",
			initialSpec: routev1.RouteSpec{Host: "foo.com"},
			updatedSpec: routev1.RouteSpec{Host: "bar.com"},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedSpec: routev1.RouteSpec{Host: "bar.com"},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
		},
		{
			name:        "label/annotation merge and spec change",
			initialSpec: routev1.RouteSpec{Host: "foo.com"},
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"monitoring.openshift.io/bar": "",
				"annotation":                  "value",
			},
			updatedSpec: routev1.RouteSpec{Host: "bar.com"},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
			},
			expectedSpec: routev1.RouteSpec{Host: "bar.com"},
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
			route := &routev1.Route{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "foo-bar-route",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
				Spec: tc.initialSpec,
			}

			c := Client{
				osrclient: osrfake.NewSimpleClientset(route.DeepCopy()),
			}

			if _, err := c.osrclient.RouteV1().Routes(ns).Get(ctx, route.Name, metav1.GetOptions{}); err != nil {
				t.Fatal(err)
			}

			route.SetLabels(tc.updatedLabels)
			route.SetAnnotations(tc.updatedAnnotations)
			route.Spec = tc.updatedSpec
			if err := c.CreateOrUpdateRoute(ctx, route); err != nil {
				t.Fatal(err)
			}

			after, err := c.osrclient.RouteV1().Routes(ns).Get(ctx, route.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}

			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}

			if !reflect.DeepEqual(tc.expectedSpec, after.Spec) {
				t.Errorf("expected spec %q, got %q", tc.expectedLabels, after.Labels)
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
		initialData         map[string][]byte
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		updatedData         map[string][]byte
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		expectedData        map[string][]byte
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
			expectedData: map[string][]byte{},
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
				// dropping an annotation or a label requires 2 steps.
				"monitoring.openshift.io/bar-": "",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "bar",
				"annotation":                  "value",
			},
			expectedData: map[string][]byte{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			initial := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "secret",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
				Data: tc.initialData,
			}

			c := Client{
				kclient:       fake.NewSimpleClientset(initial),
				eventRecorder: events.NewInMemoryRecorder("cluster-monitoring-operator"),
			}

			_, err := c.kclient.CoreV1().Secrets(ns).Get(ctx, initial.Name, metav1.GetOptions{})
			require.NoError(t, err)

			required := initial.DeepCopy()
			required.SetLabels(tc.updatedLabels)
			required.SetAnnotations(tc.updatedAnnotations)
			required.Data = tc.updatedData
			err = c.CreateOrUpdateSecret(ctx, required)
			require.NoError(t, err)
			final, err := c.kclient.CoreV1().Secrets(ns).Get(ctx, required.Name, metav1.GetOptions{})
			require.NoError(t, err)

			require.Equal(t, tc.expectedAnnotations, final.Annotations)
			require.Equal(t, tc.expectedLabels, final.Labels)
			require.Equal(t, tc.expectedData, final.Data)
		})
	}
}

func TestCreateOrUpdateConfigMap(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		initialData         map[string]string
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		updatedData         map[string]string
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		expectedData        map[string]string
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
				// dropping an annotation or a label requires 2 steps.
				"monitoring.openshift.io/bar-": "",
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
		{
			name: "retain existing service-ca.crt",
			initialAnnotations: map[string]string{
				"service.beta.openshift.io/inject-cabundle": "true",
			},
			initialData: map[string]string{
				"service-ca.crt": "foocrt",
			},
			updatedAnnotations: map[string]string{
				"service.beta.openshift.io/inject-cabundle": "true",
			},
			updatedData: map[string]string{},
			expectedAnnotations: map[string]string{
				"service.beta.openshift.io/inject-cabundle": "true",
			},
			expectedData: map[string]string{
				"service-ca.crt": "foocrt",
			},
		},
		{
			name: "drop existing service-ca.crt when annotation is missing",
			initialData: map[string]string{
				"service-ca.crt": "foocrt",
			},
			updatedData:         map[string]string{},
			expectedLabels:      map[string]string{},
			expectedAnnotations: map[string]string{},
			expectedData:        map[string]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			initial := &v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "cluster-monitoring-operator",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
				Data: tc.initialData,
			}

			c := Client{
				kclient:       fake.NewSimpleClientset(initial),
				eventRecorder: events.NewInMemoryRecorder("cluster-monitoring-operator"),
			}

			_, err := c.kclient.CoreV1().ConfigMaps(ns).Get(ctx, initial.Name, metav1.GetOptions{})
			require.NoError(t, err)

			required := initial.DeepCopy()
			required.SetLabels(tc.updatedLabels)
			required.SetAnnotations(tc.updatedAnnotations)
			required.Data = tc.updatedData
			err = c.CreateOrUpdateConfigMap(ctx, required)
			require.NoError(t, err)

			final, err := c.kclient.CoreV1().ConfigMaps(ns).Get(ctx, required.Name, metav1.GetOptions{})
			require.NoError(t, err)

			require.Equal(t, tc.expectedAnnotations, final.Annotations)
			require.Equal(t, tc.expectedLabels, final.Labels)
			require.Equal(t, tc.expectedData, final.Data)
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

		expectedUpdate      bool
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
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
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo":     "bar",
				"operator.openshift.io/spec-hash": "ef98a3bf71ba50f21b3121fbf6ef73901a2df315d6b4ac90c36e051f240d9dc0",
			},
			expectedUpdate: false,
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
				"monitoring.openshift.io/foo":     "bar",
				"operator.openshift.io/spec-hash": "ef98a3bf71ba50f21b3121fbf6ef73901a2df315d6b4ac90c36e051f240d9dc0",
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
				"monitoring.openshift.io/foo":  "bar",
				"monitoring.openshift.io/bar-": "",
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo":     "bar",
				"annotation":                      "value",
				"operator.openshift.io/spec-hash": "ef98a3bf71ba50f21b3121fbf6ef73901a2df315d6b4ac90c36e051f240d9dc0",
			},
			expectedUpdate: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			initial := &v1.Service{
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
				kclient:       fake.NewSimpleClientset(initial),
				eventRecorder: events.NewInMemoryRecorder("cluster-monitoring-operator"),
			}

			initial, err := c.kclient.CoreV1().Services(ns).Get(ctx, initial.Name, metav1.GetOptions{})
			require.NoError(t, err)

			required := initial.DeepCopy()
			required.SetLabels(tc.updatedLabels)
			required.SetAnnotations(tc.updatedAnnotations)
			required.Spec.SessionAffinity = tc.updatedSessionAffinity
			err = c.CreateOrUpdateService(ctx, required)
			require.NoError(t, err)

			final, err := c.kclient.CoreV1().Services(ns).Get(ctx, required.Name, metav1.GetOptions{})
			require.NoError(t, err)

			require.Equal(t, tc.expectedAnnotations, final.Annotations)
			require.Equal(t, tc.expectedLabels, final.Labels)
			if tc.expectedUpdate {
				require.Equal(t, required.Spec, final.Spec)
			} else {
				require.Equal(t, initial.Spec, final.Spec)
			}
		})
	}
}

func TestCreateOrUpdateServiceAccount(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                string
		initialLabels       map[string]string
		initialAnnotations  map[string]string
		initialSecrets      []v1.ObjectReference
		updatedLabels       map[string]string
		updatedAnnotations  map[string]string
		updatedSecrets      []v1.ObjectReference
		expectedLabels      map[string]string
		expectedAnnotations map[string]string
		expectedSecrets     []v1.ObjectReference
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
		{
			name: "label/annotation/secret unchanged when secrets change",
			initialLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			initialAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"annotation":                  "value",
			},
			initialSecrets: []v1.ObjectReference{
				{Namespace: ns, Name: "foo"},
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"annotation":                  "value",
			},
			updatedSecrets: []v1.ObjectReference{
				{Namespace: ns, Name: "bar"},
			},
			expectedLabels: map[string]string{
				"app.kubernetes.io/name": "",
				"label":                  "value",
			},
			expectedAnnotations: map[string]string{
				"monitoring.openshift.io/foo": "",
				"annotation":                  "value",
			},
			expectedSecrets: []v1.ObjectReference{
				{Namespace: ns, Name: "foo"},
			},
		},
	}

	eventRecorder := events.NewInMemoryRecorder("cluster-monitoring-operator")
	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			sa := &v1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
				Secrets: tc.initialSecrets,
			}

			var c Client
			if tc.initialAnnotations == nil && tc.initialLabels == nil {
				c = Client{
					kclient:       fake.NewSimpleClientset(),
					eventRecorder: eventRecorder,
					resourceCache: resourceapply.NewResourceCache(),
				}
			} else {
				c = Client{
					kclient:       fake.NewSimpleClientset(sa.DeepCopy()),
					eventRecorder: eventRecorder,
					resourceCache: resourceapply.NewResourceCache(),
				}
				_, err := c.kclient.CoreV1().ServiceAccounts(ns).Get(ctx, sa.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
			}

			sa.SetLabels(tc.updatedLabels)
			sa.SetAnnotations(tc.updatedAnnotations)
			sa.Secrets = tc.updatedSecrets
			if err := c.CreateOrUpdateServiceAccount(ctx, sa); err != nil {
				t.Fatal(err)
			}

			after, err := c.kclient.CoreV1().ServiceAccounts(ns).Get(ctx, sa.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(tc.expectedAnnotations, after.Annotations) {
				t.Errorf("expected annotations %q, got %q", tc.expectedAnnotations, after.Annotations)
			}
			if !reflect.DeepEqual(tc.expectedLabels, after.Labels) {
				t.Errorf("expected labels %q, got %q", tc.expectedLabels, after.Labels)
			}
			if !reflect.DeepEqual(tc.expectedSecrets, after.Secrets) {
				t.Errorf("expected labels %v, got %v", tc.expectedSecrets, after.Secrets)
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
				"monitoring.openshift.io/foo":  "bar",
				"monitoring.openshift.io/bar-": "",
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
			initial := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s-config",
					Namespace:   ns,
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}
			c := Client{
				kclient:       fake.NewSimpleClientset(initial),
				eventRecorder: events.NewInMemoryRecorder("cluster-monitoring-operator"),
			}
			_, err := c.kclient.RbacV1().Roles(ns).Get(ctx, initial.Name, metav1.GetOptions{})
			require.NoError(t, err)

			required := initial.DeepCopy()
			required.SetLabels(tc.updatedLabels)
			required.SetAnnotations(tc.updatedAnnotations)
			err = c.CreateOrUpdateRole(ctx, required)
			require.NoError(t, err)

			final, err := c.kclient.RbacV1().Roles(ns).Get(ctx, required.Name, metav1.GetOptions{})
			require.NoError(t, err)

			require.Equal(t, tc.expectedAnnotations, final.Annotations)
			require.Equal(t, tc.expectedLabels, final.Labels)
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
			// This is the default value.
			initialRoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
			},
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
			expectedUpdate: false,
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
				"monitoring.openshift.io/foo":  "bar",
				"monitoring.openshift.io/bar-": "",
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
			// This is the default value and it's enforced by CreateOrUpdateRoleBinding.
			initialRoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
			},
			updatedLabels: map[string]string{
				"app.kubernetes.io/name": "app",
			},
			updatedAnnotations: map[string]string{
				"monitoring.openshift.io/foo":  "bar",
				"monitoring.openshift.io/bar-": "",
			},
			updatedSubjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "prometheus",
					Namespace: ns,
				},
			},
			// This is the default value and it's enforced by CreateOrUpdateRoleBinding.
			updatedRoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
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
			initial := &rbacv1.RoleBinding{
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
				kclient:       fake.NewSimpleClientset(initial),
				eventRecorder: events.NewInMemoryRecorder("cluster-monitoring-operator"),
			}
			initial, err := c.kclient.RbacV1().RoleBindings(ns).Get(ctx, initial.Name, metav1.GetOptions{})
			require.NoError(t, err)

			required := initial.DeepCopy()
			required.SetLabels(tc.updatedLabels)
			required.SetAnnotations(tc.updatedAnnotations)
			required.RoleRef = tc.updatedRoleRef
			required.Subjects = tc.updatedSubjects
			err = c.CreateOrUpdateRoleBinding(ctx, required)
			require.NoError(t, err)
			final, err := c.kclient.RbacV1().RoleBindings(ns).Get(ctx, required.Name, metav1.GetOptions{})
			require.NoError(t, err)

			require.Equal(t, tc.expectedAnnotations, final.Annotations)
			require.Equal(t, tc.expectedLabels, final.Labels)
			if tc.expectedUpdate {
				require.Equal(t, required.RoleRef, final.RoleRef)
				require.Equal(t, required.Subjects, final.Subjects)
			} else {
				require.Equal(t, initial.RoleRef, final.RoleRef)
				require.Equal(t, initial.Subjects, final.Subjects)
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
				"monitoring.openshift.io/foo":  "bar",
				"monitoring.openshift.io/bar-": "",
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
			initial := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s",
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
			}
			c := Client{
				kclient:       fake.NewSimpleClientset(initial),
				eventRecorder: events.NewInMemoryRecorder("cluster-monitoring-operator"),
			}
			_, err := c.kclient.RbacV1().ClusterRoles().Get(ctx, initial.Name, metav1.GetOptions{})
			require.NoError(t, err)

			required := initial.DeepCopy()
			required.SetLabels(tc.updatedLabels)
			required.SetAnnotations(tc.updatedAnnotations)
			err = c.CreateOrUpdateClusterRole(ctx, required)
			require.NoError(t, err)

			final, err := c.kclient.RbacV1().ClusterRoles().Get(ctx, required.Name, metav1.GetOptions{})
			require.NoError(t, err)

			require.Equal(t, tc.expectedAnnotations, final.Annotations)
			require.Equal(t, tc.expectedLabels, final.Labels)
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
			// This is the default value.
			initialRoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
			},
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
			expectedUpdate: false,
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
				"monitoring.openshift.io/foo":  "bar",
				"monitoring.openshift.io/bar-": "",
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
			// This is the default value and it's enforced by CreateOrUpdateRoleBinding.
			updatedRoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
			},
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
				"monitoring.openshift.io/foo":  "bar",
				"monitoring.openshift.io/bar-": "",
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
			initial := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "prometheus-k8s",
					Labels:      tc.initialLabels,
					Annotations: tc.initialAnnotations,
				},
				RoleRef:  tc.initialRoleRef,
				Subjects: tc.initialSubjects,
			}

			c := Client{
				kclient:       fake.NewSimpleClientset(initial.DeepCopy()),
				eventRecorder: events.NewInMemoryRecorder("cluster-monitoring-operator"),
			}
			initial, err := c.kclient.RbacV1().ClusterRoleBindings().Get(ctx, initial.Name, metav1.GetOptions{})
			require.NoError(t, err)

			required := initial.DeepCopy()
			required.SetLabels(tc.updatedLabels)
			required.SetAnnotations(tc.updatedAnnotations)
			required.RoleRef = tc.updatedRoleRef
			required.Subjects = tc.updatedSubjects
			err = c.CreateOrUpdateClusterRoleBinding(ctx, required)
			require.NoError(t, err)

			final, err := c.kclient.RbacV1().ClusterRoleBindings().Get(ctx, required.Name, metav1.GetOptions{})
			require.NoError(t, err)

			require.Equal(t, tc.expectedAnnotations, final.Annotations)
			require.Equal(t, tc.expectedLabels, final.Labels)
			if tc.expectedUpdate {
				require.Equal(t, required.RoleRef, final.RoleRef)
				require.Equal(t, required.Subjects, final.Subjects)
			} else {
				require.Equal(t, initial.RoleRef, final.RoleRef)
				require.Equal(t, initial.Subjects, final.Subjects)
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

func TestCreateOrUpdateValidatingWebhookConfiguration(t *testing.T) {
	ctx := context.Background()
	webhook := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "openshift-monitoring",
			},
			Annotations: map[string]string{
				"foo": "bar",
			},
		},
		Webhooks: []admissionv1.ValidatingWebhook{
			{
				ClientConfig: admissionv1.WebhookClientConfig{
					CABundle: []byte("<PEM-encoded CA bundle>"),
				},
			},
		},
	}

	c := Client{
		kclient:       fake.NewSimpleClientset(webhook.DeepCopy()),
		eventRecorder: events.NewInMemoryRecorder("cluster-monitoring-operator"),
		resourceCache: resourceapply.NewResourceCache(),
	}

	if _, err := c.kclient.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, webhook.Name, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}

	// Labels and annotations should be merged.
	webhook.Labels = map[string]string{
		"app.kubernetes.io/name": "prometheus-operator",
	}
	webhook.Annotations = map[string]string{
		"service.beta.openshift.io/inject-cabundle": "true",
	}
	// CA bundle should be retained.
	webhook.Webhooks[0].ClientConfig.CABundle = nil
	// Failure policy should be overwritten.
	webhook.Webhooks[0].FailurePolicy = ptr.To(admissionv1.Ignore)

	if err := c.CreateOrUpdateValidatingWebhookConfiguration(ctx, webhook); err != nil {
		t.Fatal(err)
	}

	newWebhook, err := c.kclient.AdmissionregistrationV1().ValidatingWebhookConfigurations().Get(ctx, webhook.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if string(newWebhook.Webhooks[0].ClientConfig.CABundle) != "<PEM-encoded CA bundle>" {
		t.Fatalf("expected CABundle %q, got %q", "<PEM-encoded CA bundle>", newWebhook.Webhooks[0].ClientConfig.CABundle)
	}

	expected := map[string]string{
		"app.kubernetes.io/name":    "prometheus-operator",
		"app.kubernetes.io/part-of": "openshift-monitoring",
	}
	if !reflect.DeepEqual(newWebhook.Labels, expected) {
		t.Fatalf("expected labels %v, got %v", expected, newWebhook.Labels)
	}

	expected = map[string]string{
		"foo": "bar",
		"service.beta.openshift.io/inject-cabundle": "true",
	}
	if !reflect.DeepEqual(newWebhook.Annotations, expected) {
		t.Fatalf("expected annotations %v, got %v", expected, newWebhook.Annotations)
	}

	if newWebhook.Webhooks[0].FailurePolicy == nil {
		t.Fatal("expected non-nil failure policy")
	}

	if *newWebhook.Webhooks[0].FailurePolicy != admissionv1.Ignore {
		t.Fatalf("expected failure policy %q, got %q", admissionv1.Ignore, *newWebhook.Webhooks[0].FailurePolicy)
	}
}

func TestPodCapacity(t *testing.T) {
	ctx := context.Background()
	node1 := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
		},
		Status: v1.NodeStatus{
			Capacity: v1.ResourceList{
				v1.ResourcePods: resource.MustParse("100"),
			},
		},
	}
	node2 := v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
		},
		Status: v1.NodeStatus{
			Capacity: v1.ResourceList{
				v1.ResourcePods: resource.MustParse("50"),
			},
		},
	}
	nodeList := v1.NodeList{
		Items: []v1.Node{
			node1,
			node2,
		},
	}
	t.Run("sum 2 nodes pod capacity", func(st *testing.T) {

		c := Client{
			kclient: fake.NewSimpleClientset(nodeList.DeepCopy()),
		}

		podCapacity, err := c.PodCapacity(ctx)

		if err != nil {
			t.Fatal(err)
		}

		if podCapacity != 150 {
			t.Fatalf("expected pods capacity 150, got %d", podCapacity)
		}
	})

}

func TestValidatePrometheusAbsent(t *testing.T) {
	ctx := context.Background()

	c := Client{
		mclient: monfake.NewSimpleClientset(),
	}

	prom := types.NamespacedName{Namespace: ns, Name: "k8s"}
	stop, errs := c.validatePrometheusResource(ctx, prom)
	if stop {
		t.Errorf("Expected prometheus missing to return stop = false but got %v", stop)
	}

	if len(errs) != 2 {
		t.Errorf("Expected prometheus missing to return 2 errors but not %d", len(errs))
	}
}

func TestValidatePrometheus(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name   string
		status monv1.PrometheusStatus
		errs   []error
		stop   bool
	}{
		{
			name: "prometheus missing conditions",
			// status: nil,
			errs: []error{
				NewUnknownAvailabiltyError("prometheus: failed to find condition type \"Available\""),
				NewUnknownDegradedError("prometheus: failed to find condition type \"Available\""),
			},
		}, {
			name: "prometheus availabe but missing reconciled",
			status: monv1.PrometheusStatus{
				Conditions: []monv1.Condition{
					{
						Type:   monv1.Available,
						Status: monv1.ConditionTrue,
					},
				},
			},
			errs: []error{
				NewUnknownDegradedError("prometheus: failed to find condition type \"Reconciled\""),
			},
		}, {
			name: "prometheus availabe but not reconciled",
			status: monv1.PrometheusStatus{
				Conditions: []monv1.Condition{
					{
						Type:   monv1.Available,
						Status: monv1.ConditionTrue,
					}, {
						Type:    monv1.Reconciled,
						Status:  monv1.ConditionUnknown,
						Reason:  "reason",
						Message: "human readable message",
					},
				},
			},
			errs: []error{
				NewDegradedError("reason: human readable message"),
			},
		}, {
			name: "prometheus not availabe",
			status: monv1.PrometheusStatus{
				Conditions: []monv1.Condition{
					{
						Type:    monv1.Available,
						Status:  monv1.ConditionFalse,
						Reason:  "reason",
						Message: "human readable message",
					},
				},
			},
			errs: []error{
				NewDegradedError("reason: human readable message"),
				NewAvailabilityError("reason: human readable message"),
			},
		}, {
			name: "prometheus availabe and reconciled",
			stop: true,
			status: monv1.PrometheusStatus{
				Conditions: []monv1.Condition{
					{
						Type:   monv1.Available,
						Status: monv1.ConditionTrue,
					}, {
						Type:   monv1.Reconciled,
						Status: monv1.ConditionTrue,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(st *testing.T) {
			prom := types.NamespacedName{Namespace: ns, Name: "k8s"}

			prometheus := &monv1.Prometheus{
				ObjectMeta: metav1.ObjectMeta{Name: prom.Name, Namespace: prom.Namespace},
				Status:     tc.status,
			}
			c := Client{
				mclient: monfake.NewSimpleClientset(prometheus),
			}

			stop, errs := c.validatePrometheusResource(ctx, prom)
			if stop != tc.stop {
				t.Errorf("expected stop to be %v but got %v", tc.stop, stop)
			}

			assertErrorsMatch(t, tc.errs, errs)
		})
	}
}

func assertErrorsMatch(t *testing.T, want, got []error) {
	t.Helper()
	if len(want) != len(got) {
		t.Errorf(`expected: %d errors but got: %d
		want: %s
		got : %s`, len(want), len(got), want, got)
	}

	for i, w := range want {
		if i >= len(got) {
			return
		}

		g := got[i]
		if w.Error() != g.Error() {
			t.Errorf(`Error [%d / %d] does not match
			want: %q
			got : %q`, i+1, len(want), w, g)
		}
	}
}

func TestPollUntil(t *testing.T) {
	testPoll := func(ctx context.Context, condition wait.ConditionWithContextFunc, err *error) error {
		return Poll(ctx, condition, WithPollInterval(100*time.Millisecond), WithPollTimeout(150*time.Millisecond), WithLastError(err))
	}

	// condition is met.
	var lastErr1 error
	err := testPoll(context.Background(), func(ctx context.Context) (bool, error) {
		return true, nil
	}, &lastErr1)
	require.NoError(t, err)

	// condition is met, lastErr isn't used.
	err = testPoll(context.Background(), func(ctx context.Context) (bool, error) {
		return true, nil
	}, nil)
	require.NoError(t, err)

	// condition is eventually met.
	var lastErr2 error
	err = testPoll(context.Background(), func(ctx context.Context) (bool, error) {
		lastErr2 = fmt.Errorf("INSIDE ERROR")
		return true, nil
	}, &lastErr2)
	require.NoError(t, err)

	// condition returns an error before timeout.
	// lastError not added as not relevant.
	var lastErr3 error
	err = testPoll(context.Background(), func(ctx context.Context) (bool, error) {
		insideError := fmt.Errorf("INSIDE ERROR")
		lastErr3 = insideError
		return false, insideError
	}, &lastErr3)
	require.ErrorContains(t, err, "INSIDE ERROR")

	// the poll times out.
	var lastErr4 error
	err = testPoll(context.Background(), func(ctx context.Context) (bool, error) {
		lastErr4 = fmt.Errorf("INSIDE ERROR")
		return false, nil
	}, &lastErr4)
	require.ErrorContains(t, err, "context deadline exceeded: INSIDE ERROR")

	// the poll times out.
	// lastError not added as not relevant.
	var lastErr5 error
	err = testPoll(context.Background(), func(ctx context.Context) (bool, error) {
		lastErr5 = context.DeadlineExceeded
		return false, nil
	}, &lastErr5)
	require.ErrorContains(t, err, "context deadline exceeded")

	// the poll times out.
	err = testPoll(context.Background(), func(ctx context.Context) (bool, error) {
		return false, nil
	}, nil)
	require.ErrorContains(t, err, "context deadline exceeded")

	// the parent context times out.
	var lastErr6 error
	parentCtx, parentCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer parentCancel()
	err = testPoll(parentCtx, func(ctx context.Context) (bool, error) {
		return false, nil
	}, &lastErr6)
	require.Error(t, parentCtx.Err())
	require.ErrorContains(t, err, "context deadline exceeded")
}
