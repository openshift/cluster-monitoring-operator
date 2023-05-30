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

package client

import (
	"sort"

	v1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type conditions struct {
	entryMap                      map[v1.ClusterStatusConditionType]v1.ClusterOperatorStatusCondition
	currentVersion, targetVersion string
}

func newConditions(cos v1.ClusterOperatorStatus, targetVersion string, time metav1.Time) *conditions {
	entries := map[v1.ClusterStatusConditionType]v1.ClusterOperatorStatusCondition{
		v1.OperatorAvailable: {
			Type:               v1.OperatorAvailable,
			Status:             v1.ConditionUnknown,
			LastTransitionTime: time,
			Reason:             "",
		},
		v1.OperatorProgressing: {
			Type:               v1.OperatorProgressing,
			Status:             v1.ConditionUnknown,
			LastTransitionTime: time,
			Reason:             "",
		},
		v1.OperatorDegraded: {
			Type:               v1.OperatorDegraded,
			Status:             v1.ConditionUnknown,
			LastTransitionTime: time,
			Reason:             "",
		},
		v1.OperatorUpgradeable: {
			Type:               v1.OperatorUpgradeable,
			Status:             v1.ConditionUnknown,
			LastTransitionTime: time,
			Reason:             "",
		},
	}

	for _, c := range cos.Conditions {
		entries[c.Type] = c
	}

	cs := &conditions{
		entryMap: entries,
	}

	if len(cos.Versions) > 0 {
		cs.currentVersion = cos.Versions[0].Version
	}

	cs.targetVersion = targetVersion

	return cs
}

func (cs *conditions) setCondition(condition v1.ClusterStatusConditionType, status v1.ConditionStatus, message, reason string, time metav1.Time) {
	entries := make(map[v1.ClusterStatusConditionType]v1.ClusterOperatorStatusCondition)
	for k, v := range cs.entryMap {
		entries[k] = v
	}

	c, ok := cs.entryMap[condition]

	if !ok || c.Status != status || c.Message != message {
		entries[condition] = v1.ClusterOperatorStatusCondition{
			Type:               condition,
			Status:             status,
			LastTransitionTime: time,
			Message:            message,
			Reason:             reason,
		}
	}

	wantsProgressing := condition == v1.OperatorProgressing && status == v1.ConditionTrue
	available, hasAvailable := cs.entryMap[v1.OperatorAvailable]

	// If the operator is already available, don't set it into progressing state again.
	// If the target and current versions differ in this case though, set it to progressing.
	abort := wantsProgressing && hasAvailable && available.Status == v1.ConditionTrue
	abort = abort && cs.targetVersion == cs.currentVersion

	if abort {
		return
	}

	cs.entryMap = entries
}

// entries returns a sorted list of status conditions from the mapped values.
// The list is sorted by  by type ClusterStatusConditionType to ensure consistent ordering for deep equal checks.
func (cs *conditions) entries() []v1.ClusterOperatorStatusCondition {
	var res []v1.ClusterOperatorStatusCondition
	for _, v := range cs.entryMap {
		res = append(res, v)
	}
	sort.SliceStable(res, func(i, j int) bool {
		return string(res[i].Type) < string(res[j].Type)
	})
	return res
}
