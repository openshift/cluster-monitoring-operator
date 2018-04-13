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
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"

	poTestFramework "github.com/coreos/prometheus-operator/test/framework"
	"github.com/pkg/errors"
)

func CreateSecret(kubeClient kubernetes.Interface, namespace string, relativePath string) error {
	secret, err := parseSecretYaml(relativePath)
	if err != nil {
		return errors.Wrap(err, "parsing secret failed")
	}

	if _, err := kubeClient.CoreV1().Secrets(namespace).Create(secret); err != nil {
		return errors.Wrap(err, "creating secret failed")
	}

	return nil
}

func parseSecretYaml(relativePath string) (*v1.Secret, error) {
	manifest, err := poTestFramework.PathToOSFile(relativePath)
	if err != nil {
		return nil, err
	}

	secret := v1.Secret{}
	if err := yaml.NewYAMLOrJSONDecoder(manifest, 100).Decode(&secret); err != nil {
		return nil, err
	}
	return &secret, nil
}
