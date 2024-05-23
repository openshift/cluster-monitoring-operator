/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1 "github.com/openshift/cluster-monitoring-operator/pkg/generated/clientset/versioned/typed/cmo/v1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeCmoV1 struct {
	*testing.Fake
}

func (c *FakeCmoV1) ClusterMonitoringOperators(namespace string) v1.ClusterMonitoringOperatorInterface {
	return &FakeClusterMonitoringOperators{c, namespace}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeCmoV1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
