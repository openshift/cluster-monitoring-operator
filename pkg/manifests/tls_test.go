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
	"reflect"
	"testing"
	"time"
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
	f := NewFactory("openshift-monitoring", "openshift-user-workload-monitoring", NewDefaultConfig())

	s, err := f.GRPCSecret(nil)
	if err != nil {
		t.Fatal(err)
	}

	// as the certs are still valid for a second reconcilation run,
	// we do not expect them to be rotated.
	// Unfortunately we cannot mock time in the underlying library,
	// so we cannot test the rotation case.
	// The rotation decision though is tested in TestNeedsNewCert.
	s2 := s.DeepCopy()
	s2, err = f.GRPCSecret(s2)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(s.Data, s2.Data) {
		t.Errorf("expected certificate data to be equal, but it isn't, got %v, expected %v", s2, s)
	}
}
