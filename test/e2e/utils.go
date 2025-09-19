// Copyright 2020 The Cluster Monitoring Operator Authors
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

package e2e

import (
	"errors"
	"fmt"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/openshift/library-go/pkg/crypto"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

func getActiveTarget(body []byte, jobName string) error {
	j, err := gabs.ParseJSON([]byte(body))
	if err != nil {
		return err
	}

	activeJobs := j.Path("data.activeTargets").Children()
	if activeJobs == nil {
		return errors.New("data.activeTargets not found")
	}

	for _, job := range activeJobs {
		name := job.S("scrapePool").Data().(string)

		if name == jobName {
			return nil
		}
	}

	return fmt.Errorf("job name '%s' not found in active targets", jobName)
}

func getThanosRules(body []byte, expGroupName, expRuleName string) error {
	j, err := gabs.ParseJSON([]byte(body))
	if err != nil {
		return err
	}

	groups := j.Path("data.groups").Children()
	if groups == nil {
		return errors.New("data.groups not found")
	}

	for i := 0; i < len(groups); i++ {
		groupName := groups[i].S("name").Data().(string)
		if groupName != expGroupName {
			continue
		}

		rules := groups[i].Path("rules").Children()
		for j := 0; j < len(rules); j++ {
			ruleName := rules[j].S("name").Data().(string)
			if ruleName == expRuleName {
				return nil
			}
		}
	}

	return fmt.Errorf("'%s' alert not found in '%s' group", expRuleName, expGroupName)
}

func createSelfSignedMTLSArtifacts(s *v1.Secret) error {
	newCAConfig, err := crypto.MakeSelfSignedCAConfig(
		fmt.Sprintf("%s@%d", "openshift-cluster-monitoring-test", time.Now().Unix()),
		crypto.DefaultCertificateLifetimeDuration,
	)
	if err != nil {
		return fmt.Errorf("error generating self signed CA: %w", err)
	}

	newCA := &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          newCAConfig,
	}

	newCABytes, newCAKeyBytes, err := newCA.Config.GetPEMBytes()
	if err != nil {
		return fmt.Errorf("error getting PEM bytes from CA: %w", err)
	}

	s.Data["ca.crt"] = newCABytes
	s.Data["ca.key"] = newCAKeyBytes
	// create serving cert and key
	{
		cfg, err := newCA.MakeServerCert(
			sets.New(string(s.Data["serving-cert-url"])),
			crypto.DefaultCertificateLifetimeDuration,
		)
		if err != nil {
			return fmt.Errorf("error making server certificate: %w", err)
		}

		crt, key, err := cfg.GetPEMBytes()
		if err != nil {
			return fmt.Errorf("error getting PEM bytes for server certificate: %w", err)
		}
		s.Data["server.crt"] = crt
		s.Data["server.key"] = key
		s.Data["server-ca.pem"] = append(crt, newCABytes...)
	}
	// create client cert and key
	{
		cfg, err := newCA.MakeClientCertificateForDuration(
			&user.DefaultInfo{
				Name: string(s.Data["client-cert-name"]),
			},
			crypto.DefaultCertificateLifetimeDuration,
		)
		if err != nil {
			return fmt.Errorf("error making client certificate: %w", err)
		}

		crt, key, err := cfg.GetPEMBytes()
		if err != nil {
			return fmt.Errorf("error getting PEM bytes for client certificate: %w", err)
		}
		s.Data["client.crt"] = crt
		s.Data["client.key"] = key
	}

	return nil
}

func getSecurityContextRestrictedProfile() *v1.SecurityContext {
	allowPrivilegeEscalation := false
	runAsNonRoot := true

	return &v1.SecurityContext{
		AllowPrivilegeEscalation: &allowPrivilegeEscalation,
		Capabilities: &v1.Capabilities{
			Drop: []v1.Capability{"ALL"},
		},
		RunAsNonRoot: &runAsNonRoot,
		SeccompProfile: &v1.SeccompProfile{
			Type: v1.SeccompProfileTypeRuntimeDefault,
		},
	}
}
