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

package promqlgen

import (
	"sort"
	"strings"

	"github.com/pkg/errors"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/prometheus/prometheus/pkg/labels"
	promql "github.com/prometheus/prometheus/promql/parser"
)

func LabelSelectorsToRelabelConfig(matches []string) (*monv1.RelabelConfig, error) {
	labelSets, err := parseMetricSelectorFromArray(matches)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse metric selectors from matches array")
	}

	labelPositions := map[string]int{}
	sourceLabels := []string{}
	i := 0
	for _, ls := range labelSets {
		for _, lm := range ls {
			_, exists := labelPositions[lm.Name]
			if exists {
				continue
			}

			sourceLabels = append(sourceLabels, lm.Name)
			labelPositions[lm.Name] = i
			i++
		}
	}

	regexParts := []string{}
	for _, ls := range labelSets {
		labelValues := make([]string, len(sourceLabels))
		for _, lm := range ls {
			labelValues[labelPositions[lm.Name]] = lm.Value
		}
		regexParts = append(regexParts, strings.Join(labelValues, ";"))
	}
	regex := "(" + strings.Join(regexParts, "|") + ")"

	return &monv1.RelabelConfig{
		Action:       "keep",
		SourceLabels: sourceLabels,
		Regex:        regex,
	}, nil
}

func GroupLabelSelectors(matches []string) (string, error) {
	labelSets, err := parseMetricSelectorFromArray(matches)
	if err != nil {
		return "", errors.Wrap(err, "could not parse metric selectors from matches array")
	}
	newLabelSet := map[string][]string{}
	for _, ls := range labelSets {
		for _, lm := range ls {
			_, exists := newLabelSet[lm.Name]
			if exists {
				newLabelSet[lm.Name] = append(newLabelSet[lm.Name], lm.Value)
			} else {
				newLabelSet[lm.Name] = []string{lm.Value}
			}
		}

	}

	keys := make([]string, 0, len(newLabelSet))
	for k := range newLabelSet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	res := "{"
	i := 0
	for _, k := range keys {
		res += k + `=~"`
		res += strings.Join(newLabelSet[k], "|")
		i++
		if k != "__name__" {
			res += `|`
		}
		if i == len(newLabelSet) {
			res += `"`
			continue
		}
		res += `",`
	}

	return res + "}", nil
}

func parseMetricSelectorFromArray(matches []string) ([][]*labels.Matcher, error) {
	labelSets := make([][]*labels.Matcher, len(matches))
	var err error
	for i, m := range matches {
		labelSets[i], err = promql.ParseMetricSelector(m)
		if err != nil {
			return nil, err
		}
	}
	return labelSets, nil
}
