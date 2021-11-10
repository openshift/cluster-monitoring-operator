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

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/openshift/library-go/pkg/crypto"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestTLSSecurityProfileConfiguration(t *testing.T) {
	testCases := []struct {
		name                  string
		profile               *configv1.TLSSecurityProfile
		expectedCipherSuite   []string
		expectedMinTLSVersion string
	}{
		{
			name:                  "no profile",
			profile:               nil,
			expectedCipherSuite:   manifests.APIServerDefaultTLSCiphers,
			expectedMinTLSVersion: "VersionTLS12",
		},
		{
			name: "old profile",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
				Old:  &configv1.OldTLSProfile{},
			},
			expectedCipherSuite:   configv1.TLSProfiles[configv1.TLSProfileOldType].Ciphers,
			expectedMinTLSVersion: "VersionTLS10",
		},
		{
			name: "intermediate profile",
			profile: &configv1.TLSSecurityProfile{
				Type:         configv1.TLSProfileIntermediateType,
				Intermediate: &configv1.IntermediateTLSProfile{},
			},
			expectedCipherSuite:   configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers,
			expectedMinTLSVersion: "VersionTLS12",
		},
		{
			name: "custom profile",
			profile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers: []string{
							"ECDHE-RSA-AES128-GCM-SHA256",
							"ECDHE-ECDSA-AES256-GCM-SHA384",
						},
						MinTLSVersion: "VersionTLS10",
					},
				},
			},
			expectedCipherSuite: []string{
				"ECDHE-RSA-AES128-GCM-SHA256",
				"ECDHE-ECDSA-AES256-GCM-SHA384",
			},
			expectedMinTLSVersion: "VersionTLS10",
		},
	}

	for _, tt := range testCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			setTLSSecurityProfile(t, tt.profile)
			assertCorrectTLSConfiguration(t, "prometheus-operator", "deployment",
				manifests.PrometheusOperatorWebTLSCipherSuitesFlag,
				manifests.PrometheusOperatorWebTLSMinTLSVersionFlag, tt.expectedCipherSuite, tt.expectedMinTLSVersion)
			assertCorrectTLSConfiguration(t, "prometheus-adapter", "deployment",
				manifests.PrometheusAdapterTLSCipherSuitesFlag,
				manifests.PrometheusAdapterTLSMinTLSVersionFlag, tt.expectedCipherSuite, tt.expectedMinTLSVersion)
			assertCorrectTLSConfiguration(t, "kube-state-metrics", "deployment",
				manifests.KubeRbacProxyTLSCipherSuitesFlag,
				manifests.KubeRbacProxyMinTLSVersionFlag, tt.expectedCipherSuite, tt.expectedMinTLSVersion)
			assertCorrectTLSConfiguration(t, "openshift-state-metrics", "deployment",
				manifests.KubeRbacProxyTLSCipherSuitesFlag,
				manifests.KubeRbacProxyMinTLSVersionFlag, tt.expectedCipherSuite, tt.expectedMinTLSVersion)
			assertCorrectTLSConfiguration(t, "node-exporter", "daemonset",
				manifests.KubeRbacProxyTLSCipherSuitesFlag,
				manifests.KubeRbacProxyMinTLSVersionFlag, tt.expectedCipherSuite, tt.expectedMinTLSVersion)
			assertCorrectTLSConfiguration(t, "telemeter-client", "deployment",
				manifests.KubeRbacProxyTLSCipherSuitesFlag,
				manifests.KubeRbacProxyMinTLSVersionFlag, tt.expectedCipherSuite, tt.expectedMinTLSVersion)
			assertCorrectTLSConfiguration(t, "thanos-querier", "deployment",
				manifests.KubeRbacProxyTLSCipherSuitesFlag,
				manifests.KubeRbacProxyMinTLSVersionFlag, tt.expectedCipherSuite, tt.expectedMinTLSVersion)
			assertCorrectTLSConfiguration(t, "grafana", "deployment",
				manifests.KubeRbacProxyTLSCipherSuitesFlag,
				manifests.KubeRbacProxyMinTLSVersionFlag, tt.expectedCipherSuite, tt.expectedMinTLSVersion)
			assertCorrectTLSConfiguration(t, "alertmanager-main", "statefulset",
				manifests.KubeRbacProxyTLSCipherSuitesFlag,
				manifests.KubeRbacProxyMinTLSVersionFlag, tt.expectedCipherSuite, tt.expectedMinTLSVersion)
			assertCorrectTLSConfiguration(t, "prometheus-k8s", "statefulset",
				manifests.KubeRbacProxyTLSCipherSuitesFlag,
				manifests.KubeRbacProxyMinTLSVersionFlag, tt.expectedCipherSuite, tt.expectedMinTLSVersion)
		})
	}
}

func assertCorrectTLSConfiguration(t *testing.T, componentName, objectType, tlsCipherSuiteFlag, tlsMinTLSVersionFlag string, expectedCipherSuite []string, expectedTLSVersion string) {
	ctx := context.Background()
	var containers []v1.Container

	if err := framework.Poll(5*time.Second, 5*time.Minute, func() (err error) {
		switch objectType {
		case "deployment":
			d, err := f.KubeClient.AppsV1().Deployments("openshift-monitoring").Get(ctx, componentName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			containers = d.Spec.Template.Spec.Containers
		case "daemonset":
			ds, err := f.KubeClient.AppsV1().DaemonSets("openshift-monitoring").Get(ctx, componentName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			containers = ds.Spec.Template.Spec.Containers
		case "statefulset":
			sts, err := f.KubeClient.AppsV1().StatefulSets("openshift-monitoring").Get(ctx, componentName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			containers = sts.Spec.Template.Spec.Containers
		}

		isCipherSuiteArgCorrect := correctCipherSuiteArg(tlsCipherSuiteFlag, expectedCipherSuite, containers)
		if !isCipherSuiteArgCorrect {
			return fmt.Errorf("invalid cipher suite set for %s in openshift-monitoring namespace", componentName)
		}

		validTLSVersion := correctMinTLSVersion(tlsMinTLSVersionFlag, expectedTLSVersion, containers)
		if !validTLSVersion {
			return fmt.Errorf("invalid tls version set for %s in openshift-monitoring namespace", componentName)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func correctCipherSuiteArg(tlsCipherSuitesArg string, ciphers []string, containers []v1.Container) bool {
	expectedCiphersArg := fmt.Sprintf(
		"%s%s",
		tlsCipherSuitesArg,
		strings.Join(crypto.OpenSSLToIANACipherSuites(ciphers), ","),
	)

	for _, c := range containers {
		for _, arg := range c.Args {
			if arg == expectedCiphersArg {
				return true
			}
		}
	}
	return false
}

func correctMinTLSVersion(minTLSVersionArg, tlsVersion string, containers []v1.Container) bool {
	expectedVersionArg := fmt.Sprintf("%s%s", minTLSVersionArg, tlsVersion)
	for _, c := range containers {
		for _, arg := range c.Args {
			if arg == expectedVersionArg {
				return true
			}
		}
	}
	return false
}

func setTLSSecurityProfile(t *testing.T, tlsSecurityProfile *configv1.TLSSecurityProfile) {
	ctx := context.Background()
	apiserverConfig, err := f.OpenShiftConfigClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	apiserverConfig.Spec.TLSSecurityProfile = tlsSecurityProfile
	if _, err := f.OpenShiftConfigClient.ConfigV1().APIServers().Update(ctx, apiserverConfig, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}
