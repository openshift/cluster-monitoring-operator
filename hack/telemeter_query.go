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

// +build ignore

package main

import (
	"bytes"
	"fmt"
	"os"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/openshift/cluster-monitoring-operator/pkg/promqlgen"
)

type telemetryConfig struct {
	Matches []string `json:"matches"`
}

func main() {
	if len(os.Args) < 2 {
		panic("expecting at least 1 argument, got 0")
	}

	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var cm v1.ConfigMap
	err = yaml.NewYAMLOrJSONDecoder(f, 100).Decode(&cm)
	if err != nil {
		panic(fmt.Sprintf("could not decode telemetry config map: %v", err))
	}

	s, found := cm.Data["metrics.yaml"]
	if !found {
		panic("could not find metrics.yaml entry in telemetry config map")
	}
	cfg := telemetryConfig{}
	err = yaml.NewYAMLOrJSONDecoder(bytes.NewBufferString(s), 100).Decode(&cfg)
	if err != nil {
		panic(fmt.Sprintf("could not parse telemetry config file: %v", err))
	}

	s, err = promqlgen.GroupLabelSelectors(cfg.Matches)
	if err != nil {
		panic(fmt.Sprintf("could not generate telemetry query: %v", err))
	}
	fmt.Println(s)
}

//go:generate go run -mod=vendor telemeter_query.go ../manifests/0000_50_cluster-monitoring-operator_04-config.yaml
