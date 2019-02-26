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
	"strings"

	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	routev1 "github.com/openshift/client-go/route/clientset/versioned/typed/route/v1"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"

	monClient "github.com/coreos/prometheus-operator/pkg/client/versioned/typed/monitoring/v1"
	"github.com/pkg/errors"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	crdc "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/typed/apiextensions/v1beta1"
)

var namespaceName = "openshift-monitoring"

type Framework struct {
	OperatorClient      *client.Client
	CRDClient           crdc.CustomResourceDefinitionInterface
	KubeClient          kubernetes.Interface
	PrometheusK8sClient *PrometheusClient

	MonitoringClient *monClient.MonitoringV1Client
	Ns               string
}

// New returns a new cluster monitoring operator end-to-end test framework and
// triggers all the setup logic.
func New(kubeConfigPath string) (*Framework, cleanUpFunc, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, nil, err
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating kubeClient failed")
	}

	// So far only necessary for prometheusK8sClient.
	openshiftRouteClient, err := routev1.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating openshiftClient failed")
	}

	mClient, err := monClient.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating monitoring client failed")
	}

	eclient, err := apiextensionsclient.NewForConfig(config)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating extensions client failed")
	}
	crdClient := eclient.ApiextensionsV1beta1().CustomResourceDefinitions()

	operatorClient, err := client.New(config, "", namespaceName, "")
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating operator client failed")
	}

	f := &Framework{
		OperatorClient:   operatorClient,
		KubeClient:       kubeClient,
		CRDClient:        crdClient,
		MonitoringClient: mClient,
		Ns:               namespaceName,
	}

	cleanUp, err := f.setup()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to setup test framework")
	}

	// Prometheus client depends on setup above.
	f.PrometheusK8sClient, err = NewPrometheusClient(openshiftRouteClient, kubeClient)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating prometheusK8sClient failed")
	}

	return f, cleanUp, nil
}

type cleanUpFunc func() error

// setup creates everything necessary to use the test framework.
func (f *Framework) setup() (cleanUpFunc, error) {
	cleanUpFuncs := []cleanUpFunc{}

	cf, err := f.CreateServiceAccount()
	if err != nil {
		return nil, err
	}

	cleanUpFuncs = append(cleanUpFuncs, cf)

	cf, err = f.CreateClusterRoleBinding()
	if err != nil {
		return nil, err
	}

	cleanUpFuncs = append(cleanUpFuncs, cf)

	return func() error {
		var errs []error
		for _, f := range cleanUpFuncs {
			err := f()
			if err != nil {
				errs = append(errs, err)
			}
		}

		if len(errs) != 0 {
			var combined []string
			for _, err := range errs {
				combined = append(combined, err.Error())
			}
			return errors.Errorf("failed to run clean up functions of clean up function: %v", strings.Join(combined, ","))
		}

		return nil
	}, nil
}

func (f *Framework) CreateServiceAccount() (cleanUpFunc, error) {
	serviceAccount := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cluster-monitoring-operator-e2e",
			Namespace: "openshift-monitoring",
		},
	}

	serviceAccount, err := f.KubeClient.CoreV1().ServiceAccounts("openshift-monitoring").Create(serviceAccount)
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.CoreV1().ServiceAccounts("openshift-monitoring").Delete(serviceAccount.Name, &metav1.DeleteOptions{})
	}, nil
}

func (f *Framework) CreateClusterRoleBinding() (cleanUpFunc, error) {
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-monitoring-operator-e2e",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "cluster-monitoring-operator-e2e",
				Namespace: "openshift-monitoring",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "cluster-monitoring-view",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}

	clusterRoleBinding, err := f.KubeClient.RbacV1().ClusterRoleBindings().Create(clusterRoleBinding)
	if err != nil {
		return nil, err
	}

	return func() error {
		return f.KubeClient.RbacV1().ClusterRoleBindings().Delete(clusterRoleBinding.Name, &metav1.DeleteOptions{})
	}, nil
}
