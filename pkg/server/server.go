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

package server

import (
	"context"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"github.com/openshift/library-go/pkg/authorization/hardcodedauthorizer"
	"github.com/openshift/library-go/pkg/config/configdefaults"
	"github.com/openshift/library-go/pkg/config/serving"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/util/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/configvalidate"
)

const webhookPathPrefix = "/validate-webhook"

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

// Run starts the HTTPS server exposing the Prometheus /metrics and validate webhook endpoints on port :8443.
// The server performs authn/authz as prescribed by
// https://github.com/openshift/enhancements/blob/master/enhancements/monitoring/client-cert-scraping.md.
func (s *Server) Run(ctx context.Context, collectionProfilesEnabled bool) error {
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
		nil,   // disable leader election
		false, // disable http2
	)
	if err != nil {
		return err
	}
	// Mitigate CVE-2023-44487 by disabling HTTP2 until the Go standard library
	// and golang.org/x/net are fully fixed.
	// Since the web server is only used to expose the metrics endpoint,
	// downgrading to HTTP/1.1 doesn't bring any performance penalty.
	serverConfig.SecureServing.DisableHTTP2 = true

	serverConfig.Authorization.Authorizer = union.New(
		// prefix the authorizer with the permissions for metrics scraping which are well known.
		// openshift RBAC policy will always allow this user to read metrics.
		hardcodedauthorizer.NewHardCodedMetricsAuthorizer(),
		// disable auth on the validate webhook paths.
		&validateWebhookAuthorizer{},
		serverConfig.Authorization.Authorizer,
	)

	serverConfig.EffectiveVersion = version.DefaultBuildEffectiveVersion()

	server, err = serverConfig.Complete(nil).New(s.name, genericapiserver.NewEmptyDelegate())
	if err != nil {
		return err
	}

	// This is a temporary measure until the CRD-based configuration is GA.
	// Following tge fail-early paradigm makes configuration failures easily detectable by users.
	// This will also aid in the transition to CRD by providing a preview of the future configuration process.
	handler := configvalidate.MustNewConfigmapsValidatorHandler(collectionProfilesEnabled)
	server.Handler.NonGoRestfulMux.Handle(
		fmt.Sprintf("%s/monitoringconfigmaps", webhookPathPrefix),
		*handler,
	)

	go func() {
		if err := server.PrepareRun().RunWithContext(ctx); err != nil {
			klog.Fatal(err)
		}
		klog.Info("server exited")
	}()

	<-ctx.Done()

	return nil
}

type validateWebhookAuthorizer struct{}

func (validateWebhookAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	if !a.IsResourceRequest() &&
		a.GetVerb() == "post" &&
		strings.HasPrefix(a.GetPath(), fmt.Sprintf("%s/", webhookPathPrefix)) {
		return authorizer.DecisionAllow, "requesting webhook is allowed", nil
	}

	return authorizer.DecisionNoOpinion, "", nil
}
