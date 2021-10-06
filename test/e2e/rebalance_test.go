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
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"

	cmodrain "github.com/openshift/cluster-monitoring-operator/pkg/drain"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/pkg/rebalancer"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubectl/pkg/drain"
)

func TestRebalanceWorkloads(t *testing.T) {
	ctx := context.Background()
	r := rebalancer.NewRebalancer(ctx, f.KubeClient)
	workload := &rebalancer.Workload{Namespace: f.Ns, LabelSelector: map[string]string{"app.kubernetes.io/name": "prometheus"}}

	// Enable persistent storage
	err := enablePersistentStorage()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := disablePersistentStorage()
		if err != nil {
			t.Fatal(err)
		}
	}()

	// Rebalance all prometheus-k8s pods on the same node to setup the scenario
	// where pods needs to be rebalanced by the operator
	err = incorrectlyRebalanceWorkload(ctx, r, workload)
	if err != nil {
		t.Fatal(err)
	}

	// Annotate prometheus-k8s-0 PVC for deletion
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		pvc, err := f.KubeClient.CoreV1().PersistentVolumeClaims(f.Ns).Get(ctx, "prometheus-k8s-db-prometheus-k8s-0", metav1.GetOptions{})
		if err != nil {
			return err
		}
		pvc.Annotations[rebalancer.DropPVCAnnotation] = "yes"
		_, err = f.KubeClient.CoreV1().PersistentVolumeClaims(f.Ns).Update(ctx, pvc, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	// Wait until CMO rebalances the pods and starts reporting Upgradeable=true
	// again.
	err = framework.Poll(time.Second, 5*time.Minute, func() error {
		clusterOperator, err := f.OpenshiftConfigClient.ConfigV1().ClusterOperators().Get(ctx, "monitoring", metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, condition := range clusterOperator.Status.Conditions {
			if condition.Type != configv1.OperatorUpgradeable {
				continue
			}
			if condition.Status != configv1.ConditionTrue {
				return fmt.Errorf("Expected CMO to report Upgradeable=true, got %s", condition.Status)
			}
			return nil
		}
		return fmt.Errorf("Expected CMO to report Upgradeable=true")
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the PVC isn't annotated anymore
	pvc, err := f.KubeClient.CoreV1().PersistentVolumeClaims(f.Ns).Get(ctx, "prometheus-k8s-db-prometheus-k8s-0", metav1.GetOptions{})
	if _, found := pvc.Annotations[rebalancer.DropPVCAnnotation]; found {
		t.Fatalf("Expected %s annotation to have been removed from the PVC %s/%s", rebalancer.DropPVCAnnotation, f.Ns, "prometheus-k8s-db-prometheus-k8s-0")
	}

	// Verify that no node was left unschedulable by CMO
	nodeList, err := f.KubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "!node-role.kubernetes.io/master"})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodeList.Items {
		_, cordonedByOperator := node.Annotations[rebalancer.CordonAnnotation]
		if node.Spec.Unschedulable && cordonedByOperator {
			t.Fatalf("Expected node %s cordoned by CMO to have been uncordoned after rebalancing the pods", node.Name)
		}
	}
}

func incorrectlyRebalanceWorkload(ctx context.Context, r *rebalancer.Rebalancer, workload *rebalancer.Workload) error {
	// Cordon all nodes except one
	nodeList, err := f.KubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "!node-role.kubernetes.io/master"})
	if err != nil {
		return err
	}
	drainer := &drain.Helper{Ctx: ctx, Client: f.KubeClient}
	for _, node := range nodeList.Items[1:] {
		err = drain.RunCordonOrUncordon(drainer, &node, cmodrain.Cordon)
		if err != nil {
			return err
		}
	}

	// Uncordon all the nodes once the pods are scheduled on the same node
	defer func() {
		nodeList, err = f.KubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "!node-role.kubernetes.io/master"})
		for _, node := range nodeList.Items {
			drain.RunCordonOrUncordon(drainer, &node, cmodrain.Uncordon)
		}
	}()

	// Reschedule prometheus-k8s pods to the only schedulable node
	err = f.KubeClient.CoreV1().PersistentVolumeClaims(f.Ns).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=prometheus"})
	if err != nil {
		return err
	}
	err = f.KubeClient.CoreV1().Pods(f.Ns).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=prometheus"})
	if err != nil {
		return err
	}

	// Force operator sync by annotating the cluster-monitoring-config.
	// This is needed in order to make the operator reevaluate its Upgradeable
	// status and thus make the check for Upgradeable=false more consistent.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		config, err := f.KubeClient.CoreV1().ConfigMaps(f.Ns).Get(ctx, "cluster-monitoring-config", metav1.GetOptions{})
		if err != nil {
			return err
		}
		config.Annotations = map[string]string{"force-operator-sync": ""}
		_, err = f.KubeClient.CoreV1().ConfigMaps(f.Ns).Update(ctx, config, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return err
	}

	// Wait until CMO starts reporting Upgradeable=false because all the replicas
	// of Prometheus are scheduled on the same node.
	return framework.Poll(time.Second, 5*time.Minute, func() error {
		clusterOperator, err := f.OpenshiftConfigClient.ConfigV1().ClusterOperators().Get(ctx, "monitoring", metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, condition := range clusterOperator.Status.Conditions {
			if condition.Type != configv1.OperatorUpgradeable {
				continue
			}
			if condition.Status != configv1.ConditionFalse {
				return fmt.Errorf("Expected CMO to report Upgradeable=false, got %s", condition.Status)
			}
			return nil
		}
		return fmt.Errorf("Expected CMO to report Upgradeable=false")
	})
}

func enablePersistentStorage() error {
	cfg, err := manifests.NewConfigMap(bytes.NewReader([]byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    prometheusK8s:
      volumeClaimTemplate:
        spec:
          resources:
            requests:
              storage: 40Gi
`)))
	if err != nil {
		return err
	}
	err = f.OperatorClient.CreateOrUpdateConfigMap(ctx, cfg)
	if err != nil {
		return err
	}

	// Make sure that persistent storage was enabled on prometheus-k8s pods
	var pod *v1.Pod
	framework.Poll(time.Second, 5*time.Minute, func() error {
		pod, err = f.KubeClient.CoreV1().Pods(f.Ns).Get(ctx, "prometheus-k8s-0", metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, v := range pod.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				return nil
			}
		}
		return fmt.Errorf("Expected pod %s/%s to have a persistent storage configured", pod.Namespace, pod.Name)
	})
	return err
}

func disablePersistentStorage() error {
	return f.KubeClient.CoreV1().ConfigMaps(f.Ns).Delete(ctx, "cluster-monitoring-config", metav1.DeleteOptions{})
}
