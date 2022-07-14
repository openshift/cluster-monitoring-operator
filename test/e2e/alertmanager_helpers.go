package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	routev1 "github.com/openshift/api/route/v1"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	webhookReceiverService = "alertmanager-webhook-e2e-testutil"
	webhookReceiverImage   = "quay.io/philipgough/alertmanager-test-webhook-receiver:2da8ff713d42dc80b4d8096ffc08f8024f156495"
)

type webhookReceiver struct {
	namespace  string
	webhookURL string
	pollURL    string
}

type alert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint,omitempty"`
}

// setupWebhookReceiver deploys a http server to the provided namespace, which is created
// if it does not exist
func setupWebhookReceiver(t *testing.T, f *framework.Framework, namespace string) (*webhookReceiver, error) {
	t.Helper()

	_, err := f.KubeClient.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return nil, err
	}

	f.AssertNamespaceExists(namespace)(t)

	if err := f.OperatorClient.CreateOrUpdateService(ctx, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: webhookReceiverService,
			Labels: map[string]string{
				"app":                      webhookReceiverService,
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
			Namespace: namespace,
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Name:       "web",
					Protocol:   "TCP",
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
				},
			},
			Selector: map[string]string{
				"app": webhookReceiverService,
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}); err != nil {
		return nil, err
	}

	if err := f.OperatorClient.CreateOrUpdateDeployment(ctx, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: webhookReceiverService,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
			Namespace: namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: toInt32(1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": webhookReceiverService,
				},
			},
			Template: v1.PodTemplateSpec{
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  webhookReceiverService,
							Image: webhookReceiverImage,
							Args: []string{
								"--log.level=debug",
								`--id.template={{ .CommonLabels.alertname }}_{{ .CommonLabels.namespace }}`,
							},
							SecurityContext: getSecurityContextRestrictedProfile(),
						},
					},
				},
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": webhookReceiverService,
					},
				},
			},
		},
	}); err != nil {
		return nil, err
	}

	route := &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e",
			Labels: map[string]string{
				"app":                      webhookReceiverService,
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
			Namespace: namespace,
		},
		Spec: routev1.RouteSpec{
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: webhookReceiverService,
			},
			Port: &routev1.RoutePort{TargetPort: intstr.FromInt(8080)},
		},
	}
	if err := f.OperatorClient.CreateOrUpdateRoute(ctx, route); err != nil {
		return nil, err
	}
	host, err := f.OperatorClient.WaitForRouteReady(ctx, route)
	if err != nil {
		return nil, err
	}

	return &webhookReceiver{
		namespace:  namespace,
		webhookURL: "http://" + host + "/webhook",
		pollURL:    "http://" + host + "/history/",
	}, nil
}

func (wr *webhookReceiver) getAlertsByID(id string) ([]alert, error) {
	var into []alert
	err := framework.Poll(time.Second*10, time.Minute, func() error {
		resp, err := http.DefaultClient.Get(wr.pollURL + id)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("non 200 response")
		}

		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&into); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return into, nil
}

// teardown the webhookReceiver by deleting the namespace
func (wr *webhookReceiver) tearDown(t *testing.T, f *framework.Framework) {
	t.Helper()
	err := framework.Poll(time.Second, 5*time.Minute, func() error {
		return f.OperatorClient.DeleteIfExists(ctx, wr.namespace)
	})

	if err != nil {
		t.Fatal(err)
	}

	f.AssertNamespaceDoesNotExist(wr.namespace)(t)
}
