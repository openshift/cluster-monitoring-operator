// Copyright 2018 The Cluster Monitoring Operator Authors
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
	"os"
	"testing"
)

func TestConfigParsing(t *testing.T) {
	f, err := os.Open("../../examples/config/config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewConfig(f)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEmptyConfigIsValid(t *testing.T) {
	_, err := NewConfigFromString("")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTelemeterClientConfig(t *testing.T) {
	truev, falsev := true, false

	tcs := []struct {
		enabled bool
		cfg     *TelemeterClientConfig
	}{
		{
			cfg:     nil,
			enabled: false,
		},
		{
			cfg:     &TelemeterClientConfig{},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				Enabled: &truev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				Enabled: &falsev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
				Enabled:   &falsev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
				Enabled:   &truev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				Token: "test",
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				Token:   "test",
				Enabled: &falsev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				Token:   "test",
				Enabled: &truev,
			},
			enabled: false,
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
				Token:     "test",
			},
			enabled: true, // opt-in by default
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
				Token:     "test",
				Enabled:   &truev,
			},
			enabled: true,
		},
		{
			cfg: &TelemeterClientConfig{
				ClusterID: "test",
				Token:     "test",
				Enabled:   &falsev, // explicitely opt-out
			},
			enabled: false,
		},
	}

	for i, tc := range tcs {
		if got := tc.cfg.IsEnabled(); got != tc.enabled {
			t.Errorf("testcase %d: expected enabled %t, got %t", i, tc.enabled, got)
		}
	}
}
