// Copyright 2023 The Cluster Monitoring Operator Authors
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

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"sigs.k8s.io/yaml"
)

var (
	minimalMetricsFilePath *string
)

func init() {
	minimalMetricsFilePath = flag.String("minimal-metrics-file", "", "Path to a file containing a list of metrics that will be kept in the minimal collection profile")
}

func main() {
	flag.Parse()

	if *minimalMetricsFilePath == "" {
		log.Fatalf("arg minimal-metrics-file cannot be unset")
	}
	metrics, err := readFileByLine(*minimalMetricsFilePath)
	if err != nil {
		log.Fatalf("failed to update metrics to keep from file: %e", err)
	}

	relabelConfig := keepMetrics(metrics)

	yamlData, err := yaml.Marshal(relabelConfig)
	if err != nil {
		log.Fatalf("failed marsahling monitor: %e", err)
	}

	fmt.Println("metricRelabelings:")
	fmt.Println(string(yamlData))
}

// keepMetrics goes through the metrics in the slice metrics and joins
// in a string with "|", them returns a relabelConfig with action "keep" and the
// joined metrics in the regex field.
func keepMetrics(metrics []string) []monitoringv1.RelabelConfig {
	jointMetrics := metrics[0]
	for i := 1; i < len(metrics); i++ {
		jointMetrics = jointMetrics + "|" + metrics[i]
	}

	return []monitoringv1.RelabelConfig{
		{
			Action: "keep",
			SourceLabels: []monitoringv1.LabelName{
				"__name__",
			},
			Regex: fmt.Sprintf("(%s)", jointMetrics),
		},
	}
}

func readFileByLine(path string) ([]string, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read metrics file: %e", err)
	}
	return strings.Split(string(f), "\n"), nil
}
