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

func atLeastVersionTLS12(v string) string {
	if crypto.TLSVersionOrDie(v) < crypto.TLSVersionOrDie("VersionTLS12") {
		return "VersionTLS12"
	}

	return v
}

func TestDefaultTLSSecurityProfileConfiguration(t *testing.T) {
	// The admission webhook supports only TLS versions >= 1.2.
	assertCorrectTLSConfiguration(t, "prometheus-operator-admission-webhook", "deployment",
		manifests.PrometheusOperatorWebTLSCipherSuitesFlag,
		manifests.PrometheusOperatorWebTLSMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers,
		atLeastVersionTLS12("VersionTLS12"))
	assertCorrectTLSConfiguration(t, "prometheus-operator", "deployment",
		manifests.KubeRbacProxyTLSCipherSuitesFlag,
		manifests.KubeRbacProxyMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers, "VersionTLS12")
	assertCorrectTLSConfiguration(t, "kube-state-metrics", "deployment",
		manifests.KubeRbacProxyTLSCipherSuitesFlag,
		manifests.KubeRbacProxyMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers, "VersionTLS12")
	assertCorrectTLSConfiguration(t, "openshift-state-metrics", "deployment",
		manifests.KubeRbacProxyTLSCipherSuitesFlag,
		manifests.KubeRbacProxyMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers, "VersionTLS12")
	assertCorrectTLSConfiguration(t, "node-exporter", "daemonset",
		manifests.KubeRbacProxyTLSCipherSuitesFlag,
		manifests.KubeRbacProxyMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers, "VersionTLS12")
	assertCorrectTLSConfiguration(t, "telemeter-client", "deployment",
		manifests.KubeRbacProxyTLSCipherSuitesFlag,
		manifests.KubeRbacProxyMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers, "VersionTLS12")
	assertCorrectTLSConfiguration(t, "thanos-querier", "deployment",
		manifests.KubeRbacProxyTLSCipherSuitesFlag,
		manifests.KubeRbacProxyMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers, "VersionTLS12")
	assertCorrectTLSConfiguration(t, "alertmanager-main", "statefulset",
		manifests.KubeRbacProxyTLSCipherSuitesFlag,
		manifests.KubeRbacProxyMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers, "VersionTLS12")
	assertCorrectTLSConfiguration(t, "prometheus-k8s", "statefulset",
		manifests.KubeRbacProxyTLSCipherSuitesFlag,
		manifests.KubeRbacProxyMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers, "VersionTLS12")
	assertCorrectTLSConfiguration(t, "metrics-server", "deployment",
		manifests.MetricsServerTLSCipherSuitesFlag,
		manifests.MetricsServerTLSMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers, "VersionTLS12")
	assertCorrectTLSConfiguration(t, "monitoring-plugin", "deployment",
		manifests.MonitoringPluginTLSCipherSuitesFlag,
		manifests.MonitoringPluginTLSMinTLSVersionFlag, configv1.TLSProfiles[configv1.TLSProfileIntermediateType].Ciphers, "VersionTLS12")
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
