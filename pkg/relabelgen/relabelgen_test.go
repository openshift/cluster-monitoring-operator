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

package relabelgen

import (
	"reflect"
	"testing"

	monv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
)

func TestLabelSelectorsToRelabelConfig(t *testing.T) {
	matches := []string{
		`{__name__="metric1"}`,
		`{__name__="ALERTS",alertstate="firing"}`,
		`{__name__="metric2"}`,
	}
	r, err := LabelSelectorsToRelabelConfig(matches)
	if err != nil {
		t.Fatal(err)
	}

	expected := &monv1.RelabelConfig{
		Action:       "keep",
		SourceLabels: []string{"__name__", "alertstate"},
		Regex:        "(metric1;|ALERTS;firing|metric2;)",
	}
	if !reflect.DeepEqual(expected, r) {
		t.Fatal("unexpected result")
	}
}
