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
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/klog/v2"
)

const certificateLifetime = time.Duration(crypto.DefaultCertificateLifetimeInDays) * 24 * time.Hour

// Taken from
// https://github.com/openshift/library-go/blob/08c2fd1b452520da35ad210930ea9d100545589a/pkg/operator/certrotation/signer.go#L68-L86
// without refresh time handling. We just take care of rotation if we reach 1/5 of the validity timespan before expiration.
func needsNewCert(notBefore, notAfter time.Time, now func() time.Time) bool {
	maxWait := notAfter.Sub(notBefore) / 5
	latestTime := notAfter.Add(-maxWait)
	return now().After(latestTime)
}

func (f *Factory) GRPCSecret() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetSlice(ClusterMonitoringGrpcTLSSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace
	s.Data = make(map[string][]byte)
	s.Annotations = make(map[string]string)

	return s, nil
}

func (f *Factory) MetricsServerClientCerts() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetSlice(ClusterMonitoringMetricsServerClientCertsSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace
	s.Data = make(map[string][]byte)
	s.Annotations = make(map[string]string)

	return s, nil
}

func (f *Factory) MetricsClientCerts() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetSlice(ClusterMonitoringMetricsClientCertsSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace
	s.Data = make(map[string][]byte)
	s.Annotations = make(map[string]string)

	return s, nil
}

func (f *Factory) FederateClientCerts() (*v1.Secret, error) {
	s, err := f.NewSecret(f.assets.MustNewAssetSlice(ClusterMonitoringFederateClientCertsSecret))
	if err != nil {
		return nil, err
	}

	s.Namespace = f.namespace
	s.Data = make(map[string][]byte)
	s.Annotations = make(map[string]string)

	return s, nil
}

func (f *Factory) MetricsClientCACM(apiAuthConfigmap *v1.ConfigMap) (*v1.ConfigMap, error) {
	cm, err := f.NewConfigMap(f.assets.MustNewAssetSlice(ClusterMonitoringMetricsClientCACM))
	if err != nil {
		return nil, err
	}

	cm.Namespace = f.namespace
	cm.Data = make(map[string]string)
	cm.Annotations = make(map[string]string)

	clientCA, ok := apiAuthConfigmap.Data["client-ca-file"]
	if !ok {
		return nil, errors.New("missing client-ca-file")
	}

	cm.Data["client-ca.crt"] = clientCA

	return cm, nil
}

func (f *Factory) UserWorkloadMetricsClientCACM(apiAuthConfigmap *v1.ConfigMap) (*v1.ConfigMap, error) {
	cm, err := f.MetricsClientCACM(apiAuthConfigmap)
	if err != nil {
		return nil, err
	}

	cm.Namespace = f.namespaceUserWorkload

	return cm, nil
}

// RotateGRPCSecret rotates key material for Thanos GRPC TLS based communication.
//
// If no key material is present, it creates it.
// It "rotates" the CA and all server and client certificates and keys 1/5 before the expiry timespan.
//
// The rotation scheme here assumes the following threat model:
//
//  1. CA certificates could be compromised as they are being mounted into multiple pods
//     reachable externally i.e. via routes.
//     This is addressed by expiry and time based rotation.
//  2. Client and server certificates as well as their private key could be compromised
//     as they are being mounted into multiple pods reachable externally i.e. via routes.
//     This is addressed by re-issuing them at the same time the CA expires.
//  3. The CA's private key is left out of the thread model as it is not mounted in any pod.
//     This implementation assumes it can stay immutable and does not need rotation.
func RotateGRPCSecret(s *v1.Secret) error {
	var (
		curCA, newCA              *crypto.CA
		curCABytes, crtPresent    = s.Data["ca.crt"]
		curCAKeyBytes, keyPresent = s.Data["ca.key"]
		rotate                    = !crtPresent || !keyPresent
	)

	if crtPresent && keyPresent {
		var err error
		curCA, err = crypto.GetCAFromBytes(curCABytes, curCAKeyBytes)
		if err != nil {
			klog.Warningf("generating a new CA due to error reading CA: %v", err)
			rotate = true
		} else if needsNewCert(curCA.Config.Certs[0].NotBefore, curCA.Config.Certs[0].NotAfter, time.Now) {
			rotate = true
		}
	}

	// This is not documented and only used in tests.
	if _, ok := s.Annotations["monitoring.openshift.io/grpc-tls-forced-rotate"]; ok {
		rotate = true
		// Remove the annotation from the manifest and request its removal on the API.
		// Ideally, this should be handled by the function's caller. However, for simplicity, the function itself manages this task.
		delete(s.Annotations, "monitoring.openshift.io/grpc-tls-forced-rotate")
		s.Annotations["monitoring.openshift.io/grpc-tls-forced-rotate-"] = ""
	}

	if !rotate {
		return nil
	}

	if curCA == nil {
		newCAConfig, err := crypto.MakeSelfSignedCAConfig(
			fmt.Sprintf("%s@%d", "openshift-cluster-monitoring", time.Now().Unix()),
			crypto.DefaultCertificateLifetimeInDays,
		)
		if err != nil {
			return fmt.Errorf("error generating self signed CA: %w", err)
		}

		newCA = &crypto.CA{
			SerialGenerator: &crypto.RandomSerialGenerator{},
			Config:          newCAConfig,
		}
	} else {
		template := curCA.Config.Certs[0]
		now := time.Now()
		template.NotBefore = now.Add(-1 * time.Second)
		template.NotAfter = now.Add(certificateLifetime)
		template.SerialNumber = template.SerialNumber.Add(template.SerialNumber, big.NewInt(1))

		newCACert, err := createCertificate(template, template, template.PublicKey, curCA.Config.Key)
		if err != nil {
			return fmt.Errorf("error rotating CA: %w", err)
		}

		newCA = &crypto.CA{
			SerialGenerator: &crypto.RandomSerialGenerator{},
			Config: &crypto.TLSCertificateConfig{
				Certs: []*x509.Certificate{newCACert},
				Key:   curCA.Config.Key,
			},
		}
	}

	newCABytes, newCAKeyBytes, err := newCA.Config.GetPEMBytes()
	if err != nil {
		return fmt.Errorf("error getting PEM bytes from CA: %w", err)
	}

	s.Data["ca.crt"] = newCABytes
	s.Data["ca.key"] = newCAKeyBytes

	{
		cfg, err := newCA.MakeClientCertificateForDuration(
			&user.DefaultInfo{
				Name: "thanos-querier",
			},
			time.Duration(crypto.DefaultCertificateLifetimeInDays)*24*time.Hour,
		)
		if err != nil {
			return fmt.Errorf("error making client certificate: %w", err)
		}

		crt, key, err := cfg.GetPEMBytes()
		if err != nil {
			return fmt.Errorf("error getting PEM bytes for thanos querier client certificate: %w", err)
		}
		s.Data["thanos-querier-client.crt"] = crt
		s.Data["thanos-querier-client.key"] = key
	}

	{
		cfg, err := newCA.MakeServerCert(
			sets.NewString("prometheus-grpc"),
			crypto.DefaultCertificateLifetimeInDays,
		)
		if err != nil {
			return fmt.Errorf("error making server certificate: %w", err)
		}

		crt, key, err := cfg.GetPEMBytes()
		if err != nil {
			return fmt.Errorf("error getting PEM bytes for prometheus-k8s server certificate: %w", err)
		}
		s.Data["prometheus-server.crt"] = crt
		s.Data["prometheus-server.key"] = key
	}

	return nil
}

// createCertificate creates a new certificate and returns it in x509.Certificate form.
func createCertificate(template, parent *x509.Certificate, pub, priv interface{}) (*x509.Certificate, error) {
	rawCert, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate: %w", err)
	}
	parsedCerts, err := x509.ParseCertificates(rawCert)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %w", err)
	}
	return parsedCerts[0], nil
}
