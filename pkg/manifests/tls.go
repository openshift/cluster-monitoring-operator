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
	"fmt"
	"time"

	"k8s.io/klog"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

// Taken from
// https://github.com/openshift/library-go/blob/08c2fd1b452520da35ad210930ea9d100545589a/pkg/operator/certrotation/signer.go#L68-L86
// without refresh time handling. We just take care of rotation if we reach 1/5 of the validity timespan before expiration.
func needsNewCert(notBefore, notAfter time.Time, now func() time.Time) bool {
	maxWait := notAfter.Sub(notBefore) / 5
	latestTime := notAfter.Add(-maxWait)
	return now().After(latestTime)
}

// This method creates a central secret containing GRPC TLS key material
// if the given secret is nil
// or updates it if the CA present in the given secret is about to expire.
//
// It "rotates" the CA 1/5 before the expiry timespan.
// The rotation scheme is very naive, it simply creates a new self signed CA
// and refreshes all the subsequent GRPC server/client certs.
// For simplicity, the CA as well as all certificates have the same expiration,
// that is crypto.DefaultCertificateLifetimeInDays = 2 years
// in order to align rotation.
func (f *Factory) GRPCSecret(s *v1.Secret) (*v1.Secret, error) {
	if s == nil {
		var err error
		s, err = f.NewSecret(MustAssetReader(ClusterMonitoringGrpcTLSSecret))
		if err != nil {
			return nil, err
		}
		s.Namespace = f.namespace
		s.Data = make(map[string][]byte)
		s.Annotations = make(map[string]string)
	}

	crt, crtPresent := s.Data["ca.crt"]
	key, keyPresent := s.Data["ca.key"]

	if crtPresent && keyPresent {
		ca, err := crypto.GetCAFromBytes(crt, key)
		if err != nil {
			klog.Warningf("creating a new CA due to error reading CA: %v", err)
		} else if !needsNewCert(ca.Config.Certs[0].NotBefore, ca.Config.Certs[0].NotAfter, time.Now) {
			return s, nil
		}
	}

	cfg, err := crypto.MakeSelfSignedCAConfig(
		fmt.Sprintf("%s@%d", "openshift-cluster-monitoring", time.Now().Unix()),
		crypto.DefaultCertificateLifetimeInDays,
	)
	if err != nil {
		return nil, errors.Wrap(err, "error creating self signed CA")
	}

	crt, key, err = cfg.GetPEMBytes()
	if err != nil {
		return nil, err
	}

	s.Data["ca.crt"] = crt
	s.Data["ca.key"] = key

	ca := &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          cfg,
	}

	{
		cfg, err := ca.MakeClientCertificateForDuration(
			&user.DefaultInfo{
				Name: "thanos-querier",
			},
			time.Duration(crypto.DefaultCertificateLifetimeInDays)*24*time.Hour,
		)
		if err != nil {
			return nil, errors.Wrap(err, "error making thanos querier client certificate")
		}
		crt, key, err := cfg.GetPEMBytes()
		if err != nil {
			return nil, errors.Wrap(err, "error getting PEM bytes for thanos querier client certificate")
		}
		s.Data["thanos-querier-client.crt"] = crt
		s.Data["thanos-querier-client.key"] = key
	}

	{
		cfg, err := ca.MakeServerCert(
			sets.NewString("prometheus-grpc"),
			crypto.DefaultCertificateLifetimeInDays,
		)
		if err != nil {
			return nil, errors.Wrap(err, "error making prometheus-k8s server certificate")
		}
		crt, key, err := cfg.GetPEMBytes()
		if err != nil {
			return nil, errors.Wrap(err, "error getting PEM bytes for prometheus-k8s server certificate")
		}
		s.Data["prometheus-server.crt"] = crt
		s.Data["prometheus-server.key"] = key
	}

	return s, nil
}
