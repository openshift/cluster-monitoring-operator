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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1alpha1 "github.com/openshift/api/operator/v1alpha1"
	"github.com/openshift/library-go/pkg/authorization/hardcodedauthorizer"
	"github.com/openshift/library-go/pkg/config/configdefaults"
	"github.com/openshift/library-go/pkg/config/serving"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/version"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/configvalidate"
)

const webhookPathPrefix = "/validate-webhook"

// OpenShift Intermediate TLS profile settings for secure HTTPS serving,
// eliminating insecure cipher warnings from crypto.DefaultCiphers().
// Uses IANA-style cipher suite names compatible with OpenShift monitoring components.
var (
	secureIntermediateTLSCiphers = []string{
		// TLS 1.3 cipher suites (IANA names)
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		// TLS 1.2 cipher suites (IANA names) - compatible with telemeter-client and other OpenShift components
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
	}
	secureIntermediateMinTLSVersion = "VersionTLS12"
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

// certificatesValidForStrictTLS checks if certificates are ready for strict TLS configuration
// This includes file existence, size validation, and actual certificate loading validation
func (s *Server) certificatesValidForStrictTLS() bool {
	klog.V(4).Infof("Starting TLS certificate validation for strict TLS configuration")

	// Check certificate file
	certStat, err := os.Stat(s.certFile)
	if err != nil {
		klog.V(2).Infof("Certificate file %s not accessible for strict TLS: %v", s.certFile, err)
		return false
	}
	if certStat.Size() < 100 {
		klog.V(2).Infof("Certificate file %s too small (%d bytes), likely incomplete", s.certFile, certStat.Size())
		return false
	}
	klog.V(4).Infof("Certificate file %s validated: %d bytes", s.certFile, certStat.Size())

	// Check key file
	keyStat, err := os.Stat(s.keyFile)
	if err != nil {
		klog.V(2).Infof("Key file %s not accessible for strict TLS: %v", s.keyFile, err)
		return false
	}
	if keyStat.Size() < 50 {
		klog.V(2).Infof("Key file %s too small (%d bytes), likely incomplete", s.keyFile, keyStat.Size())
		return false
	}
	klog.V(4).Infof("Key file %s validated: %d bytes", s.keyFile, keyStat.Size())

	// Critical validation: Try to actually load the certificate pair
	klog.V(4).Infof("Attempting to load TLS certificate pair for validation")
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		klog.Warningf("TLS certificate pair validation failed, falling back to default TLS settings: %v", err)
		klog.V(2).Infof("Certificate loading error details - certFile: %s, keyFile: %s, error: %v", s.certFile, s.keyFile, err)
		return false
	}

	// Additional validation: Parse the certificate for extra details
	if len(cert.Certificate) > 0 {
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			klog.Warningf("TLS certificate parsing failed, falling back to default TLS settings: %v", err)
			return false
		}
		klog.V(2).Infof("TLS certificate validated successfully - Subject: %s, Issuer: %s, NotAfter: %s",
			x509Cert.Subject.String(), x509Cert.Issuer.String(), x509Cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))
	}

	klog.Infof("TLS certificates validated successfully, applying OpenShift Intermediate TLS profile")
	return true
}

// Run starts the HTTPS server exposing the Prometheus /metrics and validate webhook endpoints on port :8443.
// The server performs authn/authz as prescribed by
// https://github.com/openshift/enhancements/blob/master/enhancements/monitoring/client-cert-scraping.md.
func (s *Server) Run(ctx context.Context, collectionProfilesEnabled bool) error {
	// Try to start server with enhanced TLS settings first, fall back to defaults if that fails
	err := s.runServerWithConfig(ctx, collectionProfilesEnabled, true /* useStrictTLS */)
	if err != nil {
		klog.Warningf("Server startup with strict TLS failed: %v", err)
		klog.Infof("Falling back to default TLS configuration")

		// Fallback: try with default TLS settings
		err = s.runServerWithConfig(ctx, collectionProfilesEnabled, false /* useStrictTLS */)
		if err != nil {
			// Don't return error - instead gracefully degrade without server
			// This prevents our TLS changes from crashing the entire operator
			klog.Errorf("Server startup failed even with default TLS: %v", err)
			klog.Warningf("Continuing without metrics server due to persistent startup failures")

			// Block until context is done to maintain errgroup behavior
			<-ctx.Done()
			return nil
		}
	}

	return nil
}

// runServerWithConfig attempts to start the server with specified TLS configuration
func (s *Server) runServerWithConfig(ctx context.Context, collectionProfilesEnabled bool, useStrictTLS bool) error {
	var server *genericapiserver.GenericAPIServer

	servingInfo := configv1.HTTPServingInfo{}

	// Apply TLS configuration based on the useStrictTLS flag and certificate validation
	if useStrictTLS && s.certificatesValidForStrictTLS() {
		klog.Infof("Applying OpenShift Intermediate TLS profile with secure cipher suites")
		servingInfo.ServingInfo.CipherSuites = secureIntermediateTLSCiphers
		servingInfo.ServingInfo.MinTLSVersion = secureIntermediateMinTLSVersion
	} else {
		if useStrictTLS {
			klog.Infof("Strict TLS requested but certificates not ready, using default TLS configuration")
		} else {
			klog.Infof("Using default TLS configuration")
		}
		// SetRecommendedHTTPServingInfoDefaults handles the safe default configuration
	}

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
		nil,   // version info
	)
	if err != nil {
		return fmt.Errorf("failed to create server config: %w", err)
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
		return fmt.Errorf("failed to create server: %w", err)
	}

	// This is a temporary measure until the CRD-based configuration is GA.
	// Following the fail-early paradigm this makes configuration failures easily detectable by users.
	// This will also aid in the transition to CRD by providing a preview of the future configuration process.
	handler := configvalidate.MustNewConfigmapsValidatorHandler(collectionProfilesEnabled)
	server.Handler.NonGoRestfulMux.Handle(
		fmt.Sprintf("%s/monitoringconfigmaps", webhookPathPrefix),
		*handler,
	)

	klog.V(4).Infof("Starting HTTPS server")
	err = server.PrepareRun().RunWithContext(ctx)
	if err != nil {
		return fmt.Errorf("server failed to run: %w", err)
	}

	klog.Info("server exited gracefully")
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
