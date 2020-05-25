// Copyright 2018 The Cluster Monitoring Operator Authors
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
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
)

type eventRecorder string

func (e *eventRecorder) Event(reason, message string) {
	fmt.Println(">>> reason:", reason)
	fmt.Println(">>> message:", message)
}

func (e *eventRecorder) Eventf(reason, messageFmt string, args ...interface{}) {
	fmt.Println(">>> reason ", reason)
	fmt.Printf(">>> "+messageFmt+"\n", args...)
}

func (e *eventRecorder) Warning(reason, message string) {
	fmt.Println("*** reason:", reason)
	fmt.Println("*** message:", message)
}

func (e *eventRecorder) Warningf(reason, messageFmt string, args ...interface{}) {
	fmt.Println("*** reason ", reason)
	fmt.Printf("*** "+messageFmt+"\n", args...)
}

func (e *eventRecorder) Shutdown() {}

// ForComponent allows to fiddle the component name before sending the event to sink.
// Making more unique components will prevent the spam filter in upstream event sink from dropping
// events.
func (e *eventRecorder) ForComponent(componentName string) events.Recorder {
	newEr := eventRecorder(componentName)
	return &newEr
}

// WithComponentSuffix is similar to ForComponent except it just suffix the current component name instead of overriding.
func (e *eventRecorder) WithComponentSuffix(componentNameSuffix string) events.Recorder {
	newEr := eventRecorder(string(*e) + "-" + componentNameSuffix)
	return &newEr
}

// ComponentName returns the current source component name for the event.
func (e *eventRecorder) ComponentName() string {
	return string(*e)
}

type TLSRotationController struct {
	name, namespace string
	hostnames       []string
	kubeClient      *kubernetes.Clientset
	informer        informers.SharedInformerFactory
	eventRecorder   eventRecorder
	controller      factory.Controller
	ctx             context.Context
}

func NewTLSRotationController(config *rest.Config,
	namespace string,
	name string,
	hostnames []string) (*TLSRotationController, error) {

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	inf := informers.NewSharedInformerFactoryWithOptions(
		kubeClient,
		1*time.Hour,
		informers.WithNamespace(namespace),
	)

	er := eventRecorder("cmo" + name)

	crc := certrotation.NewCertRotationController(
		name+"CertRotationController",
		certrotation.SigningRotation{
			Namespace:     namespace,
			Name:          name + "-signer-ca",
			Refresh:       15 * 24 * time.Hour,
			Validity:      30 * 24 * time.Hour,
			Informer:      inf.Core().V1().Secrets(),
			Lister:        inf.Core().V1().Secrets().Lister(),
			Client:        kubeClient.CoreV1(),
			EventRecorder: &er,
		},
		certrotation.CABundleRotation{
			Namespace:     namespace,
			Name:          name + "-ca-bundle",
			Informer:      inf.Core().V1().ConfigMaps(),
			Lister:        inf.Core().V1().ConfigMaps().Lister(),
			Client:        kubeClient.CoreV1(),
			EventRecorder: &er,
		},
		certrotation.TargetRotation{
			Namespace: namespace,
			Name:      name + "-cert",
			Refresh:   24 * time.Hour,
			Validity:  2 * 24 * time.Hour,
			CertCreator: &certrotation.ServingRotation{
				Hostnames: func() []string {
					klog.V(4).Info("get Hostnames")
					return []string{"prometheus-grpc", "thanos-querier"}
				},
			},
			Informer:      inf.Core().V1().Secrets(),
			Lister:        inf.Core().V1().Secrets().Lister(),
			Client:        kubeClient.CoreV1(),
			EventRecorder: &er,
		},
		nil,
		&er,
	)

	ctx := context.WithValue(context.TODO(), certrotation.RunOnceContextKey, true)

	rc := &TLSRotationController{
		name:          name,
		hostnames:     hostnames,
		kubeClient:    kubeClient,
		controller:    crc,
		informer:      inf,
		eventRecorder: er,
		ctx:           ctx,
	}

	return rc, nil
}

func (rc *TLSRotationController) Sync() error {
	klog.V(4).Info("Running cert rotation sync")
	err := rc.controller.Sync(rc.ctx, factory.NewSyncContext(rc.name, &rc.eventRecorder))
	if err != nil {
		klog.V(4).Info("Cert rotation sync unsuccessful")
		return err
	}
	klog.V(4).Info("Cert rotation sync finished")
	return nil
}
