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
	"errors"
	"fmt"
	"os"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
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

func TestEtcdDefaultsToDisabled(t *testing.T) {
	c, err := NewConfigFromString("")
	if err != nil {
		t.Fatal(err)
	}
	if c.EtcdConfig.IsEnabled() {
		t.Error("an empty configuration should have etcd disabled")
	}
	c, err = NewConfigFromString(`{"etcd":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.EtcdConfig.IsEnabled() {
		t.Error("an empty etcd configuration should have etcd disabled")
	}
}

type configCheckFunc func(*Config, error) error

func configChecks(fs ...configCheckFunc) configCheckFunc {
	return configCheckFunc(func(c *Config, err error) error {
		for _, f := range fs {
			if e := f(c, err); e != nil {
				return e
			}
		}
		return nil
	})
}

func hasError(expected bool) configCheckFunc {
	return configCheckFunc(func(_ *Config, err error) error {
		if got := err != nil; got != expected {
			return fmt.Errorf("expected error %t, got %t", expected, got)
		}
		return nil
	})
}

func TestLoadProxy(t *testing.T) {
	hasHTTPProxy := func(expected string) configCheckFunc {
		return configCheckFunc(func(c *Config, _ error) error {
			if got := c.HTTPConfig.HTTPProxy; got != expected {
				return fmt.Errorf("want http proxy %v, got %v", expected, got)
			}
			return nil
		})
	}

	hasHTTPSProxy := func(expected string) configCheckFunc {
		return configCheckFunc(func(c *Config, _ error) error {
			if got := c.HTTPConfig.HTTPSProxy; got != expected {
				return fmt.Errorf("want https proxy %v, got %v", expected, got)
			}
			return nil
		})
	}

	hasNoProxy := func(expected string) configCheckFunc {
		return configCheckFunc(func(c *Config, _ error) error {
			if got := c.HTTPConfig.NoProxy; got != expected {
				return fmt.Errorf("want noproxy %v, got %v", expected, got)
			}
			return nil
		})
	}

	for _, tc := range []struct {
		name  string
		load  func() (*configv1.Proxy, error)
		check configCheckFunc
	}{
		{
			name: "error loading proxy",
			load: func() (*configv1.Proxy, error) { return nil, errors.New("failure") },
			check: configChecks(
				hasHTTPProxy(""),
				hasHTTPSProxy(""),
				hasNoProxy(""),
				hasError(true),
			),
		},
		{
			name: "empty spec",
			load: func() (*configv1.Proxy, error) { return &configv1.Proxy{}, nil },
			check: configChecks(
				hasHTTPProxy(""),
				hasHTTPSProxy(""),
				hasNoProxy(""),
				hasError(false),
			),
		},
		{
			name: "proxies",
			load: func() (*configv1.Proxy, error) {
				return &configv1.Proxy{
					Status: configv1.ProxyStatus{
						HTTPProxy:  "http://proxy",
						HTTPSProxy: "https://proxy",
						NoProxy:    "localhost,svc.cluster",
					},
				}, nil
			},
			check: configChecks(
				hasHTTPProxy("http://proxy"),
				hasHTTPSProxy("https://proxy"),
				hasNoProxy("localhost,svc.cluster"),
				hasError(false),
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewDefaultConfig()
			err := c.LoadProxy(tc.load)

			if err := tc.check(c, err); err != nil {
				t.Error(err)
			}
		})
	}
}
