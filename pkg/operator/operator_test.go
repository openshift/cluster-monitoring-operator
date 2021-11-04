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
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/rebalancer"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewInfrastructureConfig(t *testing.T) {
	for _, tc := range []struct {
		name               string
		infrastructure     configv1.Infrastructure
		hostedControlPlane bool
		haInfrastructure   bool
	}{
		{
			name:               "empty infrastructure",
			infrastructure:     configv1.Infrastructure{},
			hostedControlPlane: false,
			haInfrastructure:   true,
		},
		{
			name: "External control plane",
			infrastructure: configv1.Infrastructure{
				Status: configv1.InfrastructureStatus{
					ControlPlaneTopology: configv1.ExternalTopologyMode,
				},
			},
			hostedControlPlane: true,
			haInfrastructure:   true,
		},
		{
			name: "Single-node infrastructure",
			infrastructure: configv1.Infrastructure{
				Status: configv1.InfrastructureStatus{
					InfrastructureTopology: configv1.SingleReplicaTopologyMode,
				},
			},
			hostedControlPlane: false,
			haInfrastructure:   false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewInfrastructureConfig(&tc.infrastructure)

			if c.HostedControlPlane() != tc.hostedControlPlane {
				t.Errorf("expected hosted control plane: %v, got %v", tc.hostedControlPlane, c.HostedControlPlane())
			}

			if c.HighlyAvailableInfrastructure() != tc.haInfrastructure {
				t.Errorf("expected HA infrastructure: %v, got %v", tc.haInfrastructure, c.HighlyAvailableInfrastructure())
			}
		})
	}
}

type proxyConfigCheckFunc func(*ProxyConfig) error

func proxyConfigChecks(fs ...proxyConfigCheckFunc) proxyConfigCheckFunc {
	return proxyConfigCheckFunc(func(c *ProxyConfig) error {
		for _, f := range fs {
			if err := f(c); err != nil {
				return err
			}
		}
		return nil
	})
}

func TestNewProxyConfig(t *testing.T) {
	hasHTTPProxy := func(expected string) proxyConfigCheckFunc {
		return proxyConfigCheckFunc(func(c *ProxyConfig) error {
			if got := c.HTTPProxy(); got != expected {
				return errors.Errorf("want http proxy %v, got %v", expected, got)
			}
			return nil
		})
	}

	hasHTTPSProxy := func(expected string) proxyConfigCheckFunc {
		return proxyConfigCheckFunc(func(c *ProxyConfig) error {
			if got := c.HTTPSProxy(); got != expected {
				return errors.Errorf("want https proxy %v, got %v", expected, got)
			}
			return nil
		})
	}

	hasNoProxy := func(expected string) proxyConfigCheckFunc {
		return proxyConfigCheckFunc(func(c *ProxyConfig) error {
			if got := c.NoProxy(); got != expected {
				return errors.Errorf("want noproxy %v, got %v", expected, got)
			}
			return nil
		})
	}

	for _, tc := range []struct {
		name  string
		p     *configv1.Proxy
		check proxyConfigCheckFunc
	}{
		{
			name: "empty spec",
			p:    &configv1.Proxy{},
			check: proxyConfigChecks(
				hasHTTPProxy(""),
				hasHTTPSProxy(""),
				hasNoProxy(""),
			),
		},
		{
			name: "proxies",
			p: &configv1.Proxy{
				Status: configv1.ProxyStatus{
					HTTPProxy:  "http://proxy",
					HTTPSProxy: "https://proxy",
					NoProxy:    "localhost,svc.cluster",
				},
			},
			check: proxyConfigChecks(
				hasHTTPProxy("http://proxy"),
				hasHTTPSProxy("https://proxy"),
				hasNoProxy("localhost,svc.cluster"),
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewProxyConfig(tc.p)

			if err := tc.check(c); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestUpgradeableStatus(t *testing.T) {
	var (
		haInfrastructure      = InfrastructureConfig{highlyAvailableInfrastructure: true}
		nonHAInfrastructure   = InfrastructureConfig{highlyAvailableInfrastructure: false}
		namespace             = "openshift-monitoring"
		namespaceUserWorkload = "openshift-user-workload-monitoring"
		nodes                 = []v1.Node{
			{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "node-2"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "node-3"}},
		}
	)

	for _, tc := range []struct {
		name        string
		infra       InfrastructureConfig
		uwm         bool
		pods        []v1.Pod
		upgradeable configv1.ConditionStatus
	}{
		{
			name:        "Non HA infrastructures are always Upgradeable",
			infra:       nonHAInfrastructure,
			pods:        []v1.Pod{},
			upgradeable: configv1.ConditionTrue,
		},
		{
			name:  "Prometheus k8s correctly balanced",
			infra: haInfrastructure,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-k8s-db-prometheus-k8s-0"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-2", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-k8s-db-prometheus-k8s-1"}}}}},
				},
			},
			upgradeable: configv1.ConditionTrue,
		},
		{
			name:  "Prometheus k8s incorrectly balanced",
			infra: haInfrastructure,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-k8s-db-prometheus-k8s-0"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-k8s-db-prometheus-k8s-1"}}}}},
				},
			},
			upgradeable: configv1.ConditionFalse,
		},
		{
			name:  "Prometheus k8s not successfully scheduled",
			infra: haInfrastructure,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-k8s-db-prometheus-k8s-0"}}}}},
				},
			},
			upgradeable: configv1.ConditionTrue,
		},
		{
			name:  "Alertmanager correctly balanced",
			infra: haInfrastructure,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-main-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "alertmanager"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "alertmanager-main-db-alertmanager-main-0"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-main-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "alertmanager"}},
					Spec:       v1.PodSpec{NodeName: "node-2", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "alertmanager-main-db-alertmanager-main-1"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-main-2", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "alertmanager"}},
					Spec:       v1.PodSpec{NodeName: "node-3", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "alertmanager-main-db-alertmanager-main-2"}}}}},
				},
			},
			upgradeable: configv1.ConditionTrue,
		},
		{
			name:  "Alertmanager correctly balanced between 2 nodes",
			infra: haInfrastructure,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-main-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "alertmanager"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "alertmanager-main-db-alertmanager-main-0"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-main-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "alertmanager"}},
					Spec:       v1.PodSpec{NodeName: "node-2", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "alertmanager-main-db-alertmanager-main-1"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-main-2", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "alertmanager"}},
					Spec:       v1.PodSpec{NodeName: "node-2", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "alertmanager-main-db-alertmanager-main-2"}}}}},
				},
			},
			upgradeable: configv1.ConditionTrue,
		},
		{
			name:  "Alertmanager incorrectly balanced",
			infra: haInfrastructure,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-main-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "alertmanager"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "alertmanager-main-db-alertmanager-main-0"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-main-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "alertmanager"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "alertmanager-main-db-alertmanager-main-1"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "alertmanager-main-2", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "alertmanager"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "alertmanager-main-db-alertmanager-main-2"}}}}},
				},
			},
			upgradeable: configv1.ConditionFalse,
		},
		{
			name:  "Prometheus UWM correctly balanced",
			infra: haInfrastructure,
			uwm:   true,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-user-workload-0", Namespace: namespaceUserWorkload, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-user-workload-db-prometheus-user-workload-0"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-user-workload-1", Namespace: namespaceUserWorkload, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-2", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-user-workload-db-prometheus-user-workload-1"}}}}},
				},
			},
			upgradeable: configv1.ConditionTrue,
		},
		{
			name:  "Prometheus UWM incorrectly balanced",
			infra: haInfrastructure,
			uwm:   true,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-user-workload-0", Namespace: namespaceUserWorkload, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-user-workload-db-prometheus-user-workload-0"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-user-workload-1", Namespace: namespaceUserWorkload, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "prometheus-user-workload-db-prometheus-user-workload-1"}}}}},
				},
			},
			upgradeable: configv1.ConditionFalse,
		},
		{
			name:  "Thanos ruler correctly balanced",
			infra: haInfrastructure,
			uwm:   true,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "thanos-ruler-user-workload-0", Namespace: namespaceUserWorkload, Labels: map[string]string{"app.kubernetes.io/name": "thanos-ruler"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "thanos-ruler-user-workload-data-thanos-ruler-user-workload-0"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "thanos-ruler-user-workload-1", Namespace: namespaceUserWorkload, Labels: map[string]string{"app.kubernetes.io/name": "thanos-ruler"}},
					Spec:       v1.PodSpec{NodeName: "node-2", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "thanos-ruler-user-workload-data-thanos-ruler-user-workload-1"}}}}},
				},
			},
			upgradeable: configv1.ConditionTrue,
		},
		{
			name:  "Thanos ruler incorrectly balanced",
			infra: haInfrastructure,
			uwm:   true,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "thanos-ruler-user-workload-0", Namespace: namespaceUserWorkload, Labels: map[string]string{"app.kubernetes.io/name": "thanos-ruler"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "thanos-ruler-user-workload-data-thanos-ruler-user-workload-0"}}}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "thanos-ruler-user-workload-1", Namespace: namespaceUserWorkload, Labels: map[string]string{"app.kubernetes.io/name": "thanos-ruler"}},
					Spec:       v1.PodSpec{NodeName: "node-1", Volumes: []v1.Volume{{VolumeSource: v1.VolumeSource{PersistentVolumeClaim: &v1.PersistentVolumeClaimVolumeSource{ClaimName: "thanos-ruler-user-workload-data-thanos-ruler-user-workload-1"}}}}},
				},
			},
			upgradeable: configv1.ConditionFalse,
		},
		{
			name:  "Workload incorrectly balanced without PVC",
			infra: haInfrastructure,
			pods: []v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-1"},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "prometheus-k8s-1", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": "prometheus"}},
					Spec:       v1.PodSpec{NodeName: "node-1"},
				},
			},
			upgradeable: configv1.ConditionTrue,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeOperator := &Operator{
				client: client.New(
					"",
					"",
					"",
					client.KubernetesClient(
						fake.NewSimpleClientset(
							&v1.PodList{Items: tc.pods},
							&v1.NodeList{Items: nodes},
						),
					)),
				lastKnowInfrastructureConfig: &tc.infra,
				userWorkloadEnabled:          tc.uwm,
				namespace:                    namespace,
				namespaceUserWorkload:        namespaceUserWorkload,
			}
			fakeOperator.rebalancer = rebalancer.NewRebalancer(context.Background(), fakeOperator.client.KubernetesInterface())

			var message, reason string
			upgradeable, message, reason, err := fakeOperator.Upgradeable(context.Background())
			if err != nil {
				t.Error(err)
			}

			if tc.upgradeable != upgradeable {
				t.Errorf("Unexpected ClusterOperator Upgradeable status: expected: %v, got: %v with reason: %v and message: %v.", tc.upgradeable, upgradeable, reason, message)
			}
		})
	}
}
