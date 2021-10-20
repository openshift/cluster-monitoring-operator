// Copyright 2021 The Cluster Monitoring Operator Authors
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
	"encoding/json"
	"fmt"
	"os"
	"sort"

	promql "github.com/prometheus/prometheus/promql/parser"
)

type Rule struct {
	Expr string `json:"expr"`
}

type RuleGroup struct {
	Rules []Rule `json:"rules"`
}

type RuleGroups struct {
	Groups []RuleGroup `json:"groups"`
}

func extractMetricNamesNew(fileName string) ([]string, error) {

	var metricNames []string
	metricNamesMap := map[string]struct{}{}
	var ruleGroups RuleGroups

	fileContent, _ := os.ReadFile(fileName)
	err := json.Unmarshal(fileContent, &ruleGroups)
	if err != nil {
		return metricNames, err
	}

	for _, group := range ruleGroups.Groups {
		for _, rule := range group.Rules {
			expr, err := promql.ParseExpr(rule.Expr)
			if err != nil {
				return nil, err
			}
			promql.Inspect(expr, func(node promql.Node, _ []promql.Node) error {
				vs, ok := node.(*promql.VectorSelector)
				if ok {
					metricNamesMap[vs.Name] = struct{}{}
				}
				return nil
			})
		}
	}

	for key := range metricNamesMap {
		metricNames = append(metricNames, key)
	}
	sort.Strings(metricNames)

	return metricNames, nil
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

	metricNames, err := extractMetricNamesNew(os.Args[1])

	if err != nil {
		panic(err)
	}

	for _, metricName := range metricNames {
		fmt.Printf("%s\n", metricName)
	}
}
