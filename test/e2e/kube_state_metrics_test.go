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

package e2e

import (
	"regexp"
	"testing"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/openshift/cluster-monitoring-operator/test/e2e/framework"
	"github.com/pkg/errors"
)

func TestKSMMetricsSuppression(t *testing.T) {

	suppressedPattern, _ := regexp.Compile("kube_.*_annotations")

	err := framework.PollImmediate(time.Second, time.Minute, func() error {

		client := f.PrometheusK8sClient

		b, err := client.PrometheusLabel("__name__")
		if err != nil {
			return err
		}

		response, err := gabs.ParseJSON(b)
		if err != nil {
			return err
		}

		status, ok := response.Path("status").Data().(string)
		if !ok {
			return errors.New("status not found")
		}

		if status != "success" {
			t.Errorf("Prometheus returned unexpected status: %s", status)
		}

		for _, name := range response.Search("data").Children() {
			metricName := name.Data().(string)
			if suppressedPattern.Match([]byte(metricName)) {
				t.Errorf("Metric should be suppressed: %s", metricName)
			}
		}

		return nil
	})
	if err != nil {
		t.Errorf("failed to query Prometheus: %v", err)
	}

}
