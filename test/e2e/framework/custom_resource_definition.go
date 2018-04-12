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
	"time"

	poTestFramework "github.com/coreos/prometheus-operator/test/framework"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	crdc "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
)

func CreateAndWaitForCustomResourceDefinition(kubeClient kubernetes.Interface, crdClient crdc.CustomResourceDefinitionInterface, relativePath string, apiPath string) error {
	tpr, err := parseTPRYaml(relativePath)
	if err != nil {
		return err
	}

	_, err = crdClient.Create(tpr)
	if err != nil {
		return err
	}

	if err := WaitForCustomResourceDefinition(kubeClient, crdClient, apiPath); err != nil {
		return err
	}

	return nil
}

func parseTPRYaml(relativePath string) (*v1beta1.CustomResourceDefinition, error) {
	manifest, err := poTestFramework.PathToOSFile(relativePath)
	if err != nil {
		return nil, err
	}

	appVersion := v1beta1.CustomResourceDefinition{}
	if err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&appVersion); err != nil {
		return nil, err
	}

	return &appVersion, nil
}

func WaitForCustomResourceDefinition(kubeClient kubernetes.Interface, crdClient crdc.CustomResourceDefinitionInterface, apiPath string) error {
	return wait.Poll(time.Second, time.Minute, func() (bool, error) {
		res := kubeClient.CoreV1().RESTClient().Get().AbsPath(apiPath).Do()

		if res.Error() != nil {
			return false, nil
		}

		return true, nil
	})
}
