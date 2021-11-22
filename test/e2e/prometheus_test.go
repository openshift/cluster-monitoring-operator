// Copyright 2019 The Cluster Monitoring Operator Authors
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
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	osConfigv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
)

func TestPrometheusMetrics(t *testing.T) {
	for service, expected := range map[string]int{
		"prometheus-operator":           1,
		"prometheus-k8s":                2,
		"prometheus-k8s-thanos-sidecar": 2,
		"thanos-querier":                2,
		"prometheus-adapter":            2,
		"alertmanager-main":             2,
		"kube-state-metrics":            2, // one for the kube metrics + one for the metrics of the process itself.
		"openshift-state-metrics":       2, // ditto.
		"telemeter-client":              1,
		"grafana":                       1,
	} {
		t.Run(service, func(t *testing.T) {
			f.ThanosQuerierClient.WaitForQueryReturn(
				t, 10*time.Minute, fmt.Sprintf(`count(up{service="%s",namespace="openshift-monitoring"} == 1)`, service),
				func(i int) error {
					if i != expected {
						return fmt.Errorf("expected %d targets to be up but got %d", expected, i)
					}

					return nil
				},
			)
		})
	}
}

func TestAntiAffinity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		instance string
	}{
		{
			name:     "alertmanager",
			instance: "main",
		},
		{
			name:     "prometheus",
			instance: "k8s",
		},
	} {
		t.Run(fmt.Sprintf("name=%q", tc.name), func(t *testing.T) {
			ctx := context.Background()
			pods, err := f.KubeClient.CoreV1().Pods(f.Ns).List(ctx, metav1.ListOptions{
				LabelSelector: fmt.Sprintf("app.kubernetes.io/instance=%s,app.kubernetes.io/name=%s", tc.instance, tc.name),
				FieldSelector: "status.phase=Running",
			})
			if err != nil {
				t.Fatal(err)
			}

			if len(pods.Items) != 2 {
				t.Fatalf("expecting 2 pods, got %d", len(pods.Items))
			}

			pod := pods.Items[0]
			if pod.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
				t.Fatal("pod doesn't define requiredDuringSchedulingIgnoredDuringExecution")
			}
		})
	}
}

func TestPrometheusRemoteWrite(t *testing.T) {
	ctx := context.Background()

	name := "remote-write-e2e-test"

	// deploy a service for our remote write target
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"group":                    name,
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
			Namespace: f.Ns,
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					Name: "web",
					Port: 8080,
				},
				{
					Name: "mtls",
					Port: 8081,
				},
			},
			Selector: map[string]string{
				"group": name,
			},
		},
	}

	if err := f.OperatorClient.CreateOrUpdateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	deployedService, err := f.KubeClient.CoreV1().Services(f.Ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// setup a self-signed ca and store the artifacts in a secret
	tlsSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "selfsigned-mtls-bundle",
			Namespace: f.Ns,
			Labels: map[string]string{
				"group":                    name,
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string][]byte{
			"client-cert-name": []byte("test-client"),
			"serving-cert-url": []byte(deployedService.Spec.ClusterIP),
		},
	}
	if err := createSelfSignedMTLSArtifacts(tlsSecret); err != nil {
		t.Fatal(err)
	}
	if err := f.OperatorClient.CreateOrUpdateSecret(ctx, tlsSecret); err != nil {
		t.Fatal(err)
	}

	// deploy remote write target
	targetDeployment := fmt.Sprintf(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: instrumented-sample-app
  namespace: openshift-monitoring
  labels:
    group: %[1]s
    %[2]s
spec:
  replicas: 1
  selector:
    matchLabels:
      group: %[1]s
  template:
    metadata:
      labels:
        group: %[1]s
    spec:
      containers:
      - name: example-app
        args:
        - --cert-path=/etc/certs
        image: quay.io/coreos/instrumented-sample-app:0.2.0-bearer-mtls-1
        imagePullPolicy: IfNotPresent
        ports:
        - name: web
          containerPort: 8080
        - name: mtls
          containerPort: 8081
        volumeMounts:
        - mountPath: /etc/certs
          name: certs
      volumes:
      - name: certs
        secret:
          secretName: selfsigned-mtls-bundle
          items:
          - key: server-ca.pem
            path: cert.pem
          - key: server.key
            path: key.pem
`, name, framework.E2eTestLabel)
	rwTestDeployment, err := manifests.NewDeployment(bytes.NewReader([]byte(targetDeployment)))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.OperatorClient.CreateOrUpdateDeployment(ctx, rwTestDeployment); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name   string
		port   string
		rwSpec string
	}{
		// check remote write logs
		{
			name: "assert remote write to http works",
			port: "8080",
			rwSpec: `
  - url: http://%s`,
		},
		{
			name: "assert mtls remote write works",
			port: "8081",
			rwSpec: `
  - url: https://%s
    tlsConfig:
      ca:
        secret:
          name: selfsigned-mtls-bundle
          key: ca.crt
      cert:
        secret:
          name: selfsigned-mtls-bundle
          key: client.crt
      keySecret:
        name: selfsigned-mtls-bundle
        key: client.key
`,
		},
	} {
		rw := fmt.Sprintf(scenario.rwSpec, deployedService.Spec.ClusterIP+":"+scenario.port)

		cmoConfigMap := fmt.Sprintf(`prometheusK8s:
  logLevel: debug
  remoteWrite: %s
`, rw)
		f.MustCreateOrUpdateConfigMap(t, configMapWithData(t, cmoConfigMap))

		f.AssertOperatorCondition(osConfigv1.OperatorDegraded, osConfigv1.ConditionFalse)
		f.AssertOperatorCondition(osConfigv1.OperatorProgressing, osConfigv1.ConditionTrue)

		t.Run(scenario.name, checkRemoteWrite(name, ctx))
	}
}

func checkRemoteWrite(rwEndpointName string, ctx context.Context) func(*testing.T) {
	return func(t *testing.T) {
		remoteWriteCheckLogs(ctx, rwEndpointName, t)

		remoteWriteCheckMetrics(ctx, t)
	}
}

func remoteWriteCheckLogs(ctx context.Context, rwEndpointName string, t *testing.T) {
	promLogs0, err := f.GetLogs(f.Ns, "prometheus-k8s-0", "prometheus")
	if err != nil {
		t.Fatal(err)
	}

	promLogs1, err := f.GetLogs(f.Ns, "prometheus-k8s-1", "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	var promLogs strings.Builder
	promLogErr := "prometheus logs are empty, expected to find log messages"
	if i, _ := promLogs.WriteString(promLogs0); i == 0 {
		t.Fatal(promLogErr)
	}
	if i, _ := promLogs.WriteString(promLogs1); i == 0 {
		t.Fatal(promLogErr)
	}

	rwEndpointOpts := metav1.ListOptions{LabelSelector: labels.FormatLabels(map[string]string{"group": rwEndpointName})}

	rwEndpointPodList, err := f.KubeClient.CoreV1().Pods(f.Ns).List(ctx, rwEndpointOpts)
	if err != nil {
		t.Fatal(err)
	}
	rwEndpointLogs, err := f.GetLogs(f.Ns, rwEndpointPodList.Items[0].ObjectMeta.Name, "")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(promLogs.String(), `msg="Failed to send batch, retrying`) {
		t.Fatal("unexpected prometheus log message, failed to send batch to remote write endpoint")
	}
	if strings.Contains(rwEndpointLogs, "remote error: tls: bad certificate") {
		t.Fatal("remote write tls endpoint sees bad or no certificate")
	}
}

func remoteWriteCheckMetrics(ctx context.Context, t *testing.T) {
	time.Sleep(1 * time.Minute)
	for _, pod := range []string{
		"prometheus-k8s-0",
		"prometheus-k8s-1",
	} {
		f.ThanosQuerierClient.WaitForQueryReturn(
			t, 1*time.Minute, fmt.Sprintf(`ceil(delta(prometheus_remote_storage_samples_pending{pod="%s"}[1m]))`, pod),
			func(v int) error {
				if v == 0 {
					return fmt.Errorf("prometheus_remote_storage_samples_pending indicates no remote write progress, expected a continuously changing delta")
				}

				return nil
			},
		)
	}
}
