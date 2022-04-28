// Copyright 2022 The Cluster Monitoring Operator Authors
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
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	osmv1alpha1 "github.com/openshift/api/monitoring/v1alpha1"
	"github.com/pkg/errors"
	"github.com/prometheus/prometheus/model/relabel"
	"gopkg.in/yaml.v2"

	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
)

const (
	relabelSecretName = "alert-relabel-configs"
	relabelSecretKey  = "config.yaml"
)

func TestAlertRelabelConfig(t *testing.T) {
	ctx := context.Background()

	arcName := framework.E2eTestLabelValue

	arc := &osmv1alpha1.AlertRelabelConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      arcName,
			Namespace: f.Ns,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Spec: osmv1alpha1.AlertRelabelConfigSpec{
			Configs: []osmv1alpha1.RelabelConfig{
				{
					SourceLabels: []osmv1alpha1.LabelName{"alertname", "severity"},
					Regex:        "Watchdog;none",
					TargetLabel:  "severity",
					Replacement:  "critical",
					Action:       "Replace",
				},
			},
		},
	}

	relabelConfigs := f.OpenShiftMonitoringClient.MonitoringV1alpha1().AlertRelabelConfigs(f.Ns)
	secrets := f.KubeClient.CoreV1().Secrets(f.Ns)

	// Create an AlertRelabelConfig.
	_, err := relabelConfigs.Create(ctx, arc, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to create AlertRelabelConfig"))
	}

	// Check that it is added to the secret.
	err = framework.Poll(time.Second, 2*time.Minute, func() error {
		s, err := secrets.Get(ctx, relabelSecretName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		var configsFromSecret []relabel.Config
		err = yaml.Unmarshal([]byte(s.Data[relabelSecretKey]), &configsFromSecret)
		if err != nil {
			t.Fatal(errors.Wrap(err, "failed to unmarshal AlertRelabelConfig from secret"))
		}

		err = relabelConfigsEqual(arc.Spec.Configs[0], configsFromSecret[0])
		if err != nil {
			t.Fatal(errors.Wrap(err, "AlertRelabelConfig from secret doesn't match resource"))
		}

		return nil
	})

	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to confirm relabel was added to secret"))
	}

	// Delete the AlertRelabelConfig.
	err = relabelConfigs.Delete(ctx, arcName, metav1.DeleteOptions{})
	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to delete AlertRelabelConfig"))
	}

	// Check that it is removed from the secret.
	err = framework.Poll(time.Second, 2*time.Minute, func() error {
		s, err := secrets.Get(ctx, relabelSecretName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		var configsFromSecret []relabel.Config
		err = yaml.Unmarshal([]byte(s.Data[relabelSecretKey]), &configsFromSecret)
		if err != nil {
			t.Fatal(errors.Wrap(err, "failed to unmarshal AlertRelabelConfig from secret"))
		}

		// Should only have the default config.
		if len(configsFromSecret) != 1 {
			return fmt.Errorf("Secret contains %d relabel configs, but only 1 expected",
				len(configsFromSecret))
		}

		return nil
	})

	if err != nil {
		t.Fatal(errors.Wrap(err, "failed to confirm relabel was removed from secret"))
	}
}

func relabelConfigsEqual(arc osmv1alpha1.RelabelConfig, fromSecret relabel.Config) error {
	if len(arc.SourceLabels) != len(fromSecret.SourceLabels) {
		return fmt.Errorf("SourceLabels have different lengths (%d != %d)",
			len(arc.SourceLabels), len(fromSecret.SourceLabels))
	}

	for i := range arc.SourceLabels {
		if string(arc.SourceLabels[i]) != string(fromSecret.SourceLabels[i]) {
			return fmt.Errorf("SourceLabel %d does not match", i)
		}
	}

	if arc.Separator == "" {
		arc.Separator = ";"
	}

	if arc.Separator != fromSecret.Separator {
		return fmt.Errorf("Seperator does not match (%q != %q)", arc.Separator, fromSecret.Separator)
	}

	if arc.TargetLabel != fromSecret.TargetLabel {
		return fmt.Errorf("TargetLabel does not match (%q != %q)", arc.TargetLabel, fromSecret.TargetLabel)
	}

	arcRegex, err := relabel.NewRegexp(arc.Regex)
	if err != nil {
		return errors.Wrap(err, "failed to compile RegEx from AlertRelabelConfig")
	}

	if arcRegex.String() != fromSecret.Regex.String() {
		return fmt.Errorf("Regex does not match (%q != %q)", arcRegex.String(), fromSecret.Regex.String())
	}

	if arc.Modulus != fromSecret.Modulus {
		return fmt.Errorf("Modulus does not match (%d != %d)", arc.Modulus, fromSecret.Modulus)
	}

	if arc.Replacement != fromSecret.Replacement {
		return fmt.Errorf("Modulus does not match (%q != %q)", arc.Replacement, fromSecret.Replacement)
	}

	if !strings.EqualFold(arc.Action, string(fromSecret.Action)) {
		return fmt.Errorf("Action does not match (%q != %q)",
			strings.ToLower(arc.Replacement), strings.ToLower(string(fromSecret.Replacement)))
	}

	return nil
}
