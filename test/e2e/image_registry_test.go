package e2e

import (
	"net/url"
	"strings"
	"testing"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestImageRegistryPods(t *testing.T) {
	var pods *v1.PodList

	// Get all pods in openshift-monitoring namespace.
	var urlRegistry string
	pods = f.MustGetPods(t, f.Ns)

	// use CMO image's registry as a reference for all other containers
	for _, pod := range pods.Items {
		if strings.Contains(pod.Name, "cluster-monitoring-operator") {
			imageUrl, err := url.Parse("stubheader://" + pod.Spec.Containers[0].Image)
			if err != nil {
				t.Fatalf("Fail to decode host: %v", err)
			}
			urlRegistry = imageUrl.Host
			break
		}
	}

	if urlRegistry == "" {
		t.Fatalf("CMO pod not found")
	}

	for _, pod := range pods.Items {

		for _, container := range pod.Spec.Containers {

			// We consider the hostname part of image URL be the image registry
			imageUrl, err := url.Parse("stubheader://" + container.Image)
			if err != nil {
				t.Fatalf("Fail to decode host: %v", err)
			}

			if imageUrl.Host != urlRegistry {
				t.Fatalf("Pod %s Container %s registry %s differs from CMO registry %s", pod.Name, container.Name, imageUrl.Host, urlRegistry)
			}
		}

	}

	setupUserWorkloadAssetsWithTeardownHook(t, f)
	uwmCM := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userWorkloadMonitorConfigMapName,
			Namespace: f.UserWorkloadMonitoringNs,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Data: map[string]string{
			"config.yaml": `prometheus:
  enforcedTargetLimit: 10
  volumeClaimTemplate:
    spec:
      resources:
        requests:
          storage: 2Gi
`,
		},
	}

	f.MustCreateOrUpdateConfigMap(t, uwmCM)
	defer f.MustDeleteConfigMap(t, uwmCM)

	f.AssertStatefulSetExistsAndRollout("prometheus-user-workload", f.UserWorkloadMonitoringNs)(t)
	setupUserApplication(t, f)

	pods = f.MustGetPods(t, f.UserWorkloadMonitoringNs)

	for _, pod := range pods.Items {

		for _, container := range pod.Spec.Containers {

			// We consider the hostname part of image URL be the image registry
			imageUrl, err := url.Parse("stubheader://" + container.Image)
			if err != nil {
				t.Fatalf("Fail to decode host: %v", err)
			}

			if imageUrl.Host != urlRegistry {
				t.Fatalf("UWM Pod %s Container %s registry %s differs from CMO registry %s", pod.Name, container.Name, imageUrl.Host, urlRegistry)
			}
		}

	}

}
