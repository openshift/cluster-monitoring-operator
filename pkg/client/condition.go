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
	v1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type conditions struct {
	entryMap map[v1.ClusterStatusConditionType]v1.ClusterOperatorStatusCondition
}

func newConditions(cs []v1.ClusterOperatorStatusCondition, time metav1.Time) *conditions {
	entries := map[v1.ClusterStatusConditionType]v1.ClusterOperatorStatusCondition{
		v1.OperatorAvailable: {
			Type:               v1.OperatorAvailable,
			Status:             v1.ConditionUnknown,
			LastTransitionTime: time,
		},
		v1.OperatorProgressing: {
			Type:               v1.OperatorProgressing,
			Status:             v1.ConditionUnknown,
			LastTransitionTime: time,
		},
		v1.OperatorFailing: {
			Type:               v1.OperatorFailing,
			Status:             v1.ConditionUnknown,
			LastTransitionTime: time,
		},
	}

	for _, c := range cs {
		entries[c.Type] = c
	}

	return &conditions{
		entryMap: entries,
	}
}

func (cs *conditions) setCondition(condition v1.ClusterStatusConditionType, status v1.ConditionStatus, message string, time metav1.Time) {
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
		}
	}

	// If the operator is already available, we don't set it into progressing state again.
	if condition == v1.OperatorProgressing && status == v1.ConditionTrue {
		available, ok := cs.entryMap[v1.OperatorAvailable]
		if ok && available.Status == v1.ConditionTrue {
			return
		}
	}

	cs.entryMap = entries
}

func (cs *conditions) entries() []v1.ClusterOperatorStatusCondition {
	var res []v1.ClusterOperatorStatusCondition
	for _, v := range cs.entryMap {
		res = append(res, v)
	}
	return res
}

type byType []v1.ClusterOperatorStatusCondition

func (b byType) Len() int           { return len(b) }
func (b byType) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }
func (b byType) Less(i, j int) bool { return b[i].Type < b[j].Type }
