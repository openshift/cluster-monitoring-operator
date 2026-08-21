// Copyright 2021 The Cluster Monitoring Operator Authors
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

package manifests

import (
	"reflect"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestGetTLSCiphers(t *testing.T) {
	defaultCiphers := APIServerDefaultTLSCiphers
	defaultTLSVersion := APIServerDefaultMinTLSVersion

	testCases := []struct {
		name                  string
		config                *APIServerConfig
		expectedCiphers       []string
		expectedMinTLSVersion configv1.TLSProtocolVersion
	}{
		{
			name:                  "nil config",
			config:                nil,
			expectedCiphers:       defaultCiphers,
			expectedMinTLSVersion: defaultTLSVersion,
		},
		{
			name:                  "nil config",
			config:                NewAPIServerConfig(nil),
			expectedCiphers:       defaultCiphers,
			expectedMinTLSVersion: defaultTLSVersion,
		},
		{
			name:                  "nil profile",
			config:                newApiserverConfig(nil),
			expectedCiphers:       defaultCiphers,
			expectedMinTLSVersion: defaultTLSVersion,
		},
		{
			name: "empty profile",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: "",
			}),
			expectedCiphers:       defaultCiphers,
			expectedMinTLSVersion: defaultTLSVersion,
		},
		{
			name: "invalid profile",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: "invalid-profile",
			}),
			expectedCiphers:       defaultCiphers,
			expectedMinTLSVersion: defaultTLSVersion,
		},
		{
			name: "old profile",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
			}),
			expectedCiphers:       configv1.TLSProfiles[configv1.TLSProfileOldType].Ciphers,
			expectedMinTLSVersion: configv1.TLSProfiles[configv1.TLSProfileOldType].MinTLSVersion,
		},
		{
			name: "intermediate profile",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			}),
			expectedCiphers:       defaultCiphers,
			expectedMinTLSVersion: defaultTLSVersion,
		},
		{
			name: "modern profile",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			}),
			expectedCiphers:       configv1.TLSProfiles[configv1.TLSProfileModernType].Ciphers,
			expectedMinTLSVersion: configv1.TLSProfiles[configv1.TLSProfileModernType].MinTLSVersion,
		},
		{
			name: "custom profile without TLS configuration",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
			}),
			expectedCiphers:       defaultCiphers,
			expectedMinTLSVersion: defaultTLSVersion,
		},
		{
			name: "custom profile without ciphers and min tls version",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type:   configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{},
			}),
			expectedCiphers:       defaultCiphers,
			expectedMinTLSVersion: defaultTLSVersion,
		},
		{
			name: "custom profile nil ciphers and empty min tls version",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       nil,
						MinTLSVersion: "",
					},
				},
			}),
			expectedCiphers:       defaultCiphers,
			expectedMinTLSVersion: defaultTLSVersion,
		},
		{
			name: "custom profile with ciphers and min tls version",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       []string{"cipher-1", "cipher-2"},
						MinTLSVersion: configv1.VersionTLS11,
					},
				},
			}),
			expectedCiphers:       []string{"cipher-1", "cipher-2"},
			expectedMinTLSVersion: configv1.VersionTLS11,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			actualCiphers := tt.config.TLSCiphers()
			if !reflect.DeepEqual(tt.expectedCiphers, actualCiphers) {
				t.Fatalf("invalid ciphers, got %s, want %s", strings.Join(actualCiphers, ", "), strings.Join(tt.expectedCiphers, ", "))
			}

			actualTLSVersion := tt.config.MinTLSVersion()
			if string(tt.expectedMinTLSVersion) != actualTLSVersion {
				t.Fatalf("invalid min TLS version, got %s, want %s", actualTLSVersion, tt.expectedMinTLSVersion)
			}
		})
	}
}

func TestTLSCurves(t *testing.T) {
	defaultCurves := []string{"X25519MLKEM768", "X25519", "CurveP256", "CurveP384"}

	testCases := []struct {
		name           string
		config         *APIServerConfig
		expectedCurves []string
	}{
		{
			name:           "nil config",
			config:         nil,
			expectedCurves: defaultCurves,
		},
		{
			name:           "nil APIServer",
			config:         NewAPIServerConfig(nil),
			expectedCurves: defaultCurves,
		},
		{
			name:           "nil profile",
			config:         newApiserverConfig(nil),
			expectedCurves: defaultCurves,
		},
		{
			name: "intermediate profile",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileIntermediateType,
			}),
			expectedCurves: defaultCurves,
		},
		{
			name: "old profile",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileOldType,
			}),
			expectedCurves: defaultCurves,
		},
		{
			name: "modern profile",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			}),
			expectedCurves: defaultCurves,
		},
		{
			name: "custom profile without groups",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       []string{"cipher-1"},
						MinTLSVersion: configv1.VersionTLS12,
					},
				},
			}),
			expectedCurves: nil,
		},
		{
			name: "custom profile with known groups",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       []string{"cipher-1"},
						MinTLSVersion: configv1.VersionTLS12,
						Groups: []configv1.TLSGroup{
							configv1.TLSGroupX25519,
							configv1.TLSGroupSecP256r1,
						},
					},
				},
			}),
			expectedCurves: []string{"X25519", "CurveP256"},
		},
		{
			name: "custom profile with all supported groups",
			config: newApiserverConfig(&configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{
					TLSProfileSpec: configv1.TLSProfileSpec{
						Ciphers:       []string{"cipher-1"},
						MinTLSVersion: configv1.VersionTLS12,
						Groups: []configv1.TLSGroup{
							configv1.TLSGroupX25519,
							configv1.TLSGroupSecP256r1MLKEM768,
						},
					},
				},
			}),
			expectedCurves: []string{"X25519", "SecP256r1MLKEM768"},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			actualCurves := tt.config.TLSCurves()
			if !reflect.DeepEqual(tt.expectedCurves, actualCurves) {
				t.Fatalf("invalid curves, got %v, want %v", actualCurves, tt.expectedCurves)
			}
		})
	}
}

func newApiserverConfig(profile *configv1.TLSSecurityProfile) *APIServerConfig {
	config := NewAPIServerConfig(&configv1.APIServer{
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: profile,
		},
	})

	return config
}
