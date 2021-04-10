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
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	v1 "k8s.io/api/core/v1"
)

func TestNeedsNewCert(t *testing.T) {
	for _, tt := range []struct {
		name                     string
		notBefore, notAfter, now string
		needsRotation            bool
	}{
		{
			name:          "now before notBefore",
			notBefore:     "2000-01-01T00:00:00+00:00",
			notAfter:      "2005-01-01T00:00:00+00:00",
			now:           "1999-01-01T00:00:00+00:00",
			needsRotation: false,
		},
		{
			name:          "now at notBefore",
			notBefore:     "2000-01-01T00:00:00+00:00",
			notAfter:      "2005-01-01T00:00:00+00:00",
			now:           "2000-01-01T00:00:00+00:00",
			needsRotation: false,
		},
		{
			name:          "now in the middle between notBefore-notAfter",
			notBefore:     "2000-01-01T00:00:00+00:00",
			notAfter:      "2005-01-01T00:00:00+00:00",
			now:           "2002-01-01T00:00:00+00:00",
			needsRotation: false,
		},
		{
			name:          "now at 4/5 between notBefore-notAfter",
			notBefore:     "2000-01-01T00:00:00+00:00",
			notAfter:      "2005-01-01T00:00:00+00:00",
			now:           "2004-01-02T00:00:00+00:00",
			needsRotation: true,
		},
		{
			name:          "now at notAfter",
			notBefore:     "2000-01-01T00:00:00+00:00",
			notAfter:      "2005-01-01T00:00:00+00:00",
			now:           "2005-01-01T00:00:00+00:00",
			needsRotation: true,
		},
		{
			name:          "now after notAfter",
			notBefore:     "2000-01-01T00:00:00+00:00",
			notAfter:      "2005-01-01T00:00:00+00:00",
			now:           "2010-01-01T00:00:00+00:00",
			needsRotation: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			notAfter, err := time.Parse(time.RFC3339, tt.notAfter)
			notBefore, err := time.Parse(time.RFC3339, tt.notBefore)
			now, err := time.Parse(time.RFC3339, tt.now)
			if err != nil {
				t.Fatal("error parsing test data", err)
			}
			got := needsNewCert(notBefore, notAfter, func() time.Time { return now })
			if got != tt.needsRotation {
				t.Errorf("expected needsRotation %t, got %t", tt.needsRotation, got)
			}
		})
	}
}

func TestRotateGrpcTLSSecret(t *testing.T) {
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath))

	for _, tc := range []struct {
		name  string
		setup func(*v1.Secret)
		test  func(spre, spost *v1.Secret) error
	}{
		{
			name: "no rotation without modification",
			test: func(spre, spost *v1.Secret) error {
				if !reflect.DeepEqual(spre.Data, spost.Data) {
					return fmt.Errorf("expected certificate data to be equal, but it isn't, pre-rotation key material %v, post-rotation key material %v", spre, spost)
				}
				return nil
			},
		},
		{
			name: "force rotation",
			setup: func(s *v1.Secret) {
				s.Annotations["monitoring.openshift.io/grpc-tls-forced-rotate"] = "true"
				// Introduce a delay to make sure that the initial and rotated
				// certificates aren't created within the same second.
				time.Sleep(1 * time.Second)
			},
			test: func(spre, spost *v1.Secret) error {
				if bytes.Compare(spre.Data["ca.crt"], spost.Data["ca.crt"]) == 0 {
					return fmt.Errorf("expected certificate data not to be equal, but it is")
				}

				preCA, err := crypto.GetCAFromBytes(spre.Data["ca.crt"], spre.Data["ca.key"])
				if err != nil {
					return err
				}

				postCA, err := crypto.GetCAFromBytes(spost.Data["ca.crt"], spost.Data["ca.key"])
				if err != nil {
					return err
				}

				preCert, postCert := preCA.Config.Certs[0], postCA.Config.Certs[0]

				if postCert.NotAfter.Before(preCert.NotAfter) || postCert.NotAfter.Equal(preCert.NotAfter) {
					return fmt.Errorf("expected renewed certificate to expire after old certificate but %s is before or equal to %s",
						postCert.NotAfter, preCert.NotAfter)
				}

				if postCert.NotAfter.Sub(postCert.NotBefore) > certificateLifetime+time.Second {
					return fmt.Errorf("expected certificate lifetime to be less than %s but it is valid between %s and %s",
						certificateLifetime+time.Second, postCert.NotBefore, postCert.NotAfter)
				}
				return nil
			},
		},
		{
			name: "force rotation",
			setup: func(s *v1.Secret) {
				s.Annotations["foo/bar"] = "true"
			},
			test: func(spre, spost *v1.Secret) error {
				if bytes.Compare(spre.Data["ca.crt"], spost.Data["ca.crt"]) != 0 {
					return fmt.Errorf("expected certificate data to be equal, but they aren't")
				}
				return nil
			},
		},
		{
			name: "broken certificate",
			setup: func(s *v1.Secret) {
				s.Data["ca.crt"] = []byte("broken certificate")
			},
			test: func(spre, spost *v1.Secret) error {
				if string(spost.Data["ca.crt"]) == "broken certificate" {
					return errors.New("expected certificate data to have rotated, but it wasn't")
				}

				if bytes.Compare(spre.Data["ca.crt"], spost.Data["ca.crt"]) == 0 {
					return errors.New("expected certificate data not to be equal, but they are")
				}

				return nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spre, err := f.GRPCSecret()
			if err != nil {
				t.Fatal(err)
			}

			err = RotateGRPCSecret(spre)
			if err != nil {
				t.Fatal(err)
			}

			spost := spre.DeepCopy()
			if tc.setup != nil {
				tc.setup(spost)
			}

			err = RotateGRPCSecret(spost)
			if err != nil {
				t.Fatal(err)
			}

			if err := tc.test(spre, spost); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestUnconfiguredGRPCManifests(t *testing.T) {
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig(), defaultInfrastructureReader(), &fakeProxyReader{}, NewAssets(assetsPath))
	_, err := f.AlertmanagerConfig()
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.GRPCSecret()
	if err != nil {
		t.Fatal(err)
	}
}
