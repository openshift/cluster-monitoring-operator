// Copyright 2019 The Cluster Monitoring Operator Authors
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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/pki"
)

func TestRotateGRPCSecretKeyAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		name        string
		pkiProvider pki.PKIProfileProvider
		wantCAKey   string
		wantLeafKey string
	}{
		{
			name:        "nil provider uses RSA-2048",
			pkiProvider: nil,
			wantCAKey:   "RSA",
			wantLeafKey: "RSA",
		},
		{
			name: "default PKI profile uses ECDSA",
			pkiProvider: func() pki.PKIProfileProvider {
				profile := pki.DefaultPKIProfile()
				return pki.NewStaticPKIProfileProvider(&profile)
			}(),
			wantCAKey:   "ECDSA",
			wantLeafKey: "ECDSA",
		},
		{
			name: "custom RSA-4096 profile",
			pkiProvider: pki.NewStaticPKIProfileProvider(&configv1alpha1.PKIProfile{
				Defaults: configv1alpha1.DefaultCertificateConfig{
					Key: configv1alpha1.KeyConfig{
						Algorithm: configv1alpha1.KeyAlgorithmRSA,
						RSA:       configv1alpha1.RSAKeyConfig{KeySize: 4096},
					},
				},
			}),
			wantCAKey:   "RSA",
			wantLeafKey: "RSA",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", mustDefaultConfig(), defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath), &APIServerConfig{}, &configv1.Console{})
			s, err := f.GRPCSecret()
			if err != nil {
				t.Fatal(err)
			}

			if err := RotateGRPCSecret(s, tc.pkiProvider); err != nil {
				t.Fatal(err)
			}

			caKeyAlg := keyAlgorithm(t, s.Data["ca.key"])
			if caKeyAlg != tc.wantCAKey {
				t.Errorf("CA key: got %s, want %s", caKeyAlg, tc.wantCAKey)
			}

			clientKeyAlg := keyAlgorithm(t, s.Data["thanos-querier-client.key"])
			if clientKeyAlg != tc.wantLeafKey {
				t.Errorf("client key: got %s, want %s", clientKeyAlg, tc.wantLeafKey)
			}

			serverKeyAlg := keyAlgorithm(t, s.Data["prometheus-server.key"])
			if serverKeyAlg != tc.wantLeafKey {
				t.Errorf("server key: got %s, want %s", serverKeyAlg, tc.wantLeafKey)
			}
		})
	}
}

// keyAlgorithm parses a PEM-encoded private key and returns "RSA" or "ECDSA".
func keyAlgorithm(t *testing.T, pemBytes []byte) string {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fall back to type-specific parsers.
		if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			_ = rsaKey
			return "RSA"
		}
		if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			_ = ecKey
			return "ECDSA"
		}
		t.Fatalf("failed to parse private key: %v", err)
	}

	switch key.(type) {
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "ECDSA"
	default:
		t.Fatalf("unexpected key type: %T", key)
	}
	return ""
}

func assertCertValidityWithCa(cert []byte, ca []byte) error {
	certBlock, _ := pem.Decode(cert)
	if certBlock == nil {
		return errors.New("Failed to decode certificate")
	}
	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}
	root := x509.NewCertPool()
	root.AppendCertsFromPEM(ca)
	_, err = x509Cert.Verify(x509.VerifyOptions{
		Roots: root,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	})
	if err != nil {
		return err
	}
	return nil
}
