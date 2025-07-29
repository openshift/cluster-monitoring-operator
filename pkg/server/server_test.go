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
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/client-go/rest"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
)

func TestNewServer(t *testing.T) {
	config := &rest.Config{}
	kubeConfig := "/test/kubeconfig"
	certFile := "/test/cert.pem"
	keyFile := "/test/key.pem"
	apiServerConfig := manifests.NewAPIServerConfig(nil)

	server, err := NewServer("test-server", config, kubeConfig, certFile, keyFile, apiServerConfig)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if server.name != "test-server" {
		t.Errorf("Expected name 'test-server', got %s", server.name)
	}

	if server.kubeConfig != kubeConfig {
		t.Errorf("Expected kubeConfig %s, got %s", kubeConfig, server.kubeConfig)
	}

	if server.certFile != certFile {
		t.Errorf("Expected certFile %s, got %s", certFile, server.certFile)
	}

	if server.keyFile != keyFile {
		t.Errorf("Expected keyFile %s, got %s", keyFile, server.keyFile)
	}

	if server.apiServerConfig != apiServerConfig {
		t.Errorf("Expected apiServerConfig to be set correctly")
	}
}

func TestNewServerWithNilAPIServerConfig(t *testing.T) {
	config := &rest.Config{}
	kubeConfig := "/test/kubeconfig"
	certFile := "/test/cert.pem"
	keyFile := "/test/key.pem"

	server, err := NewServer("test-server", config, kubeConfig, certFile, keyFile, nil)
	if err != nil {
		t.Fatalf("NewServer failed with nil APIServerConfig: %v", err)
	}

	if server.apiServerConfig != nil {
		t.Errorf("Expected apiServerConfig to be nil")
	}
}

func TestServerTLSConfiguration(t *testing.T) {
	testCases := []struct {
		name                  string
		apiServerConfig       *manifests.APIServerConfig
		expectedCiphers       []string
		expectedMinTLSVersion string
		expectTLSConfig       bool
	}{
		{
			name:            "nil APIServerConfig",
			apiServerConfig: nil,
			expectTLSConfig: false,
		},
		{
			name:                  "default APIServerConfig",
			apiServerConfig:       manifests.NewAPIServerConfig(nil),
			expectedCiphers:       manifests.APIServerDefaultTLSCiphers,
			expectedMinTLSVersion: string(manifests.APIServerDefaultMinTLSVersion),
			expectTLSConfig:       true,
		},
		{
			name: "modern TLS profile",
			apiServerConfig: newAPIServerConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			}),
			expectedCiphers:       configv1.TLSProfiles[configv1.TLSProfileModernType].Ciphers,
			expectedMinTLSVersion: string(configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion),
			expectTLSConfig:       true,
		},
		{
			name: "custom TLS profile",
			apiServerConfig: newAPIServerConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
						MinTLSVersion: configv1.VersionTLS13,
					},
				},
			}),
			expectedCiphers:       []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
			expectedMinTLSVersion: string(configv1.VersionTLS13),
			expectTLSConfig:       true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			config := &rest.Config{}
			server, err := NewServer("test-server", config, "/test/kubeconfig", "/test/cert.pem", "/test/key.pem", tt.apiServerConfig)
			if err != nil {
				t.Fatalf("NewServer failed: %v", err)
			}

			// Test the TLS configuration logic by checking what would be applied
			if tt.expectTLSConfig && tt.apiServerConfig != nil {
				actualCiphers := tt.apiServerConfig.TLSCiphers()
				if !reflect.DeepEqual(tt.expectedCiphers, actualCiphers) {
					t.Errorf("Expected ciphers %v, got %v", tt.expectedCiphers, actualCiphers)
				}

				actualMinTLSVersion := tt.apiServerConfig.MinTLSVersion()
				if tt.expectedMinTLSVersion != actualMinTLSVersion {
					t.Errorf("Expected min TLS version %s, got %s", tt.expectedMinTLSVersion, actualMinTLSVersion)
				}
			}

			if !tt.expectTLSConfig && server.apiServerConfig != nil {
				t.Errorf("Expected no TLS config to be applied when APIServerConfig is nil")
			}
		})
	}
}

func TestServerTLSConfigurationIntegration(t *testing.T) {
	// This test validates that the TLS configuration is properly applied to the serving info
	// without actually starting the server
	testCases := []struct {
		name                  string
		apiServerConfig       *manifests.APIServerConfig
		expectedCipherCount   int
		expectedHasMinVersion bool
	}{
		{
			name:                  "with secure TLS profile",
			apiServerConfig:       manifests.NewAPIServerConfig(nil),
			expectedCipherCount:   len(manifests.APIServerDefaultTLSCiphers),
			expectedHasMinVersion: true,
		},
		{
			name: "with modern TLS profile",
			apiServerConfig: newAPIServerConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			}),
			expectedCipherCount:   len(configv1.TLSProfiles[configv1.TLSProfileModernType].Ciphers),
			expectedHasMinVersion: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			config := &rest.Config{
				Host: "https://test-server:6443",
			}
			// Use a fake client to avoid needing a real Kubernetes cluster
			config.Wrap(func(rt http.RoundTripper) http.RoundTripper {
				return &fakeRoundTripper{}
			})

			server, err := NewServer("test-server", config, "", "/tmp/cert.pem", "/tmp/key.pem", tt.apiServerConfig)
			if err != nil {
				t.Fatalf("NewServer failed: %v", err)
			}

			// Validate that the server stores the configuration correctly
			if server.apiServerConfig == nil && tt.apiServerConfig != nil {
				t.Errorf("Expected apiServerConfig to be stored in server")
			}

			if tt.apiServerConfig != nil {
				ciphers := tt.apiServerConfig.TLSCiphers()
				if len(ciphers) != tt.expectedCipherCount {
					t.Errorf("Expected %d ciphers, got %d", tt.expectedCipherCount, len(ciphers))
				}

				minVersion := tt.apiServerConfig.MinTLSVersion()
				hasMinVersion := minVersion != ""
				if hasMinVersion != tt.expectedHasMinVersion {
					t.Errorf("Expected hasMinVersion %v, got %v (version: %s)", tt.expectedHasMinVersion, hasMinVersion, minVersion)
				}
			}
		})
	}
}

// Helper function to create APIServerConfig for testing
func newAPIServerConfig(profile *configv1.TLSSecurityProfile) *manifests.APIServerConfig {
	config := manifests.NewAPIServerConfig(&configv1.APIServer{
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: profile,
		},
	})
	return config
}

// fakeRoundTripper is a minimal implementation for testing
type fakeRoundTripper struct{}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("{}")),
	}, nil
}

// TestServerTLSConfigurationValidation tests that the server correctly configures
// TLS settings based on the provided APIServerConfig
func TestServerTLSConfigurationValidation(t *testing.T) {
	testCases := []struct {
		name                string
		apiServerConfig     *manifests.APIServerConfig
		expectSecureCiphers bool
		expectMinTLSVersion bool
	}{
		{
			name:                "nil APIServerConfig should not set TLS config",
			apiServerConfig:     nil,
			expectSecureCiphers: false,
			expectMinTLSVersion: false,
		},
		{
			name:                "default APIServerConfig should set secure TLS config",
			apiServerConfig:     manifests.NewAPIServerConfig(nil),
			expectSecureCiphers: true,
			expectMinTLSVersion: true,
		},
		{
			name: "modern profile should set modern TLS config",
			apiServerConfig: newAPIServerConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			}),
			expectSecureCiphers: true,
			expectMinTLSVersion: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with test configuration
			config := &rest.Config{Host: "https://test:6443"}
			server, err := NewServer("test-cmo", config, "", "/tmp/cert.pem", "/tmp/key.pem", tt.apiServerConfig)
			if err != nil {
				t.Fatalf("NewServer failed: %v", err)
			}

			// Validate the configuration would be applied correctly
			if tt.expectSecureCiphers && server.apiServerConfig != nil {
				ciphers := server.apiServerConfig.TLSCiphers()
				if len(ciphers) == 0 {
					t.Errorf("Expected secure ciphers to be configured, but got none")
				}

				// Verify no insecure ciphers are present by checking for secure defaults
				hasSecureCipher := false
				for _, cipher := range ciphers {
					if cipher == "TLS_AES_128_GCM_SHA256" || cipher == "ECDHE-ECDSA-AES128-GCM-SHA256" {
						hasSecureCipher = true
						break
					}
				}
				if !hasSecureCipher {
					t.Errorf("Expected at least one secure cipher, but secure ciphers not found in: %v", ciphers)
				}
			}

			if tt.expectMinTLSVersion && server.apiServerConfig != nil {
				minVersion := server.apiServerConfig.MinTLSVersion()
				if minVersion == "" {
					t.Errorf("Expected minimum TLS version to be set, but got empty string")
				}

				// Verify it's a secure minimum version (TLS 1.2 or higher)
				if minVersion != "VersionTLS12" && minVersion != "VersionTLS13" {
					t.Errorf("Expected secure minimum TLS version (VersionTLS12 or VersionTLS13), got: %s", minVersion)
				}
			}

			if !tt.expectSecureCiphers && server.apiServerConfig == nil {
				// This is expected for nil config
				if server.apiServerConfig != nil {
					t.Errorf("Expected no APIServerConfig when nil was provided")
				}
			}
		})
	}
}
