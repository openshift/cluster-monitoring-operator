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

package framework

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Jeffail/gabs"
	monClient "github.com/coreos/prometheus-operator/pkg/client/versioned/typed/monitoring/v1"
	"github.com/pkg/errors"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	crdc "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
)

var namespaceName = "openshift-monitoring"

type Framework struct {
	CRDClient        crdc.CustomResourceDefinitionInterface
	KubeClient       kubernetes.Interface
	MonitoringClient *monClient.MonitoringV1Client
	Ns               string
	OpImageName      string
}

func New(kubeConfigPath string, opImageName string) (*Framework, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, err
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "creating kubeClient failed")
	}

	mClient, err := monClient.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "creating monitoring client failed")
	}

	eclient, err := apiextensionsclient.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "creating extensions client failed")
	}
	crdClient := eclient.ApiextensionsV1beta1().CustomResourceDefinitions()

	f := &Framework{
		KubeClient:       kubeClient,
		CRDClient:        crdClient,
		MonitoringClient: mClient,
		Ns:               namespaceName,
		OpImageName:      opImageName,
	}

	return f, nil
}

func (f *Framework) QueryPrometheus(name, query string) (int, error) {
	req := f.KubeClient.CoreV1().RESTClient().Get().
		Prefix("proxy").
		Namespace(namespaceName).
		Resource("pods").Name(name+":9090").
		Suffix("/api/v1/query").Param("query", query)

	b, err := req.DoRaw()
	if err != nil {
		return 0, err
	}

	res, err := gabs.ParseJSON(b)
	if err != nil {
		return 0, err
	}

	n, err := res.ArrayCountP("data.result")
	return n, err
}
