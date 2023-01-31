// Copyright 2023 The Cluster Monitoring Operator Authors
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

package metrics

import (
	"context"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"github.com/openshift/library-go/pkg/authorization/hardcodedauthorizer"
	"github.com/openshift/library-go/pkg/config/configdefaults"
	"github.com/openshift/library-go/pkg/config/serving"
	"k8s.io/apiserver/pkg/authorization/union"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

type Server struct {
	name              string
	kubeClient        *kubernetes.Clientset
	kubeConfig        string
	certFile, keyFile string
}

// NewServer returns a functional Server.
func NewServer(name string, config *rest.Config, kubeConfig, certFile, keyFile string) (*Server, error) {
	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Server{
		name:       name,
		kubeClient: kubeClient,
		kubeConfig: kubeConfig,
		certFile:   certFile,
		keyFile:    keyFile,
	}, nil
}

// Run starts the HTTPS server exposing the Prometheus /metrics endpoint on port :8443.
// The server performs authn/authz as prescribed by
// https://github.com/openshift/enhancements/blob/master/enhancements/monitoring/client-cert-scraping.md.
func (s *Server) Run(ctx context.Context) error {
	var server *genericapiserver.GenericAPIServer

	servingInfo := configv1.HTTPServingInfo{}
	configdefaults.SetRecommendedHTTPServingInfoDefaults(&servingInfo)
	servingInfo.ServingInfo.CertInfo.CertFile = s.certFile
	servingInfo.ServingInfo.CertInfo.KeyFile = s.keyFile
	// Don't set a CA file for client certificates because the CA is read from
	// the kube-system/extension-apiserver-authentication ConfigMap.
	servingInfo.ServingInfo.ClientCA = ""

	serverConfig, err := serving.ToServerConfig(
		ctx,
		servingInfo,
		operatorv1alpha1.DelegatedAuthentication{},
		operatorv1alpha1.DelegatedAuthorization{},
		s.kubeConfig,
		s.kubeClient,
		nil, // disable leader election
	)
	if err != nil {
		return err
	}

	serverConfig.Authorization.Authorizer = union.New(
		// prefix the authorizer with the permissions for metrics scraping which are well known.
		// openshift RBAC policy will always allow this user to read metrics.
		hardcodedauthorizer.NewHardCodedMetricsAuthorizer(),
		serverConfig.Authorization.Authorizer,
	)

	server, err = serverConfig.Complete(nil).New(s.name, genericapiserver.NewEmptyDelegate())
	if err != nil {
		return err
	}

	go func() {
		if err := server.PrepareRun().Run(ctx.Done()); err != nil {
			klog.Fatal(err)
		}
		klog.Info("server exited")
	}()

	<-ctx.Done()

	return nil
}
