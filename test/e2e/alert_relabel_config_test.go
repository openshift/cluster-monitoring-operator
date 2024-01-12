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
	"errors"
	"fmt"
	"testing"
	"time"

	osmv1 "github.com/openshift/api/monitoring/v1"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/relabel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	relabelConfigName          = "test-relabel-config"
	relabelSecretName          = "alert-relabel-configs"
	relabelSecretKey           = "config.yaml"
	prometheusConfigSecretName = "prometheus-k8s"
)

func TestAlertRelabelConfig(t *testing.T) {
	initialRelabelConfig := prometheusRelabelConfig(t)

	// By default we drop prometheus_replica label + add openshift_io_alert_source = 2
	require.Len(t, initialRelabelConfig, 2)

	ctx := context.Background()
	arc := &osmv1.AlertRelabelConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      relabelConfigName,
			Namespace: f.Ns,
			Labels: map[string]string{
				framework.E2eTestLabelName: framework.E2eTestLabelValue,
			},
		},
		Spec: osmv1.AlertRelabelConfigSpec{
			Configs: []osmv1.RelabelConfig{
				{
					SourceLabels: []osmv1.LabelName{"alertname", "severity"},
					Regex:        "Watchdog;none",
					TargetLabel:  "severity",
					Replacement:  "critical",
					Action:       "Wrong",
				},
			},
		},
	}

	relabelConfigs := f.OpenShiftMonitoringClient.MonitoringV1().AlertRelabelConfigs(f.Ns)

	// Try to create an invalid AlertRelabelConfig.
	_, err := relabelConfigs.Create(ctx, arc, metav1.CreateOptions{})
	if !apierrors.IsInvalid(err) {
		t.Fatal(fmt.Errorf("invalid AlertRelabelConfig wasn't rejected.: %w", err))
	}

	// Create a valid AlertRelabelConfig.
	arc.Spec.Configs[0].Action = "Replace"
	_, err = relabelConfigs.Create(ctx, arc, metav1.CreateOptions{})
	require.NoError(t, err, "failed to create valid AlertRelabelConfig.")

	// Check Prometheus config is taking the AlertRelabelConfig into account.
	validateCurrentRelabelConfig(t, append(initialRelabelConfig, &relabel.Config{
		SourceLabels: model.LabelNames{"alertname", "severity"},
		Regex:        relabel.MustNewRegexp("Watchdog;none"),
		TargetLabel:  "severity",
		Replacement:  "critical",
		Action:       "replace",
		Separator:    ";",
	}))

	// Delete the AlertRelabelConfig.
	err = relabelConfigs.Delete(ctx, arc.Name, metav1.DeleteOptions{})
	require.NoError(t, err, "failed to delete AlertRelabelConfig")

	// Check Prometheus config forgot about the deleted AlertRelabelConfig.
	validateCurrentRelabelConfig(t, initialRelabelConfig)
}

// prometheusRelabelConfig returns the alert relabel configuration part used by Prometheus config
func prometheusRelabelConfig(t *testing.T) []*relabel.Config {
	t.Helper()
	prometheusConfig := f.PrometheusConfigFromSecret(t, f.Ns, prometheusConfigSecretName)
	return prometheusConfig.AlertingConfig.AlertRelabelConfigs
}

// validateCurrentRelabelConfig ensures that Prometheus config is using the expected relabel config
func validateCurrentRelabelConfig(t *testing.T, expectedRelabelConfig []*relabel.Config) {
	err := framework.Poll(time.Second, 1*time.Minute, func() error {
		currentRelabelConfig := prometheusRelabelConfig(t)
		if !assert.ElementsMatch(t, expectedRelabelConfig, currentRelabelConfig) {
			return errors.New("the expected relabel config is not applied yet.")
		}
		return nil
	})

	require.NoError(t, err, "Failed to validate relabel config in use.")
}
