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
	"fmt"
	"reflect"
	"sort"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConditions(t *testing.T) {
	type checkFunc func(*conditions) error

	hasConditions := func(want []configv1.ClusterOperatorStatusCondition) checkFunc {
		return func(cs *conditions) error {
			got := cs.entries()
			sort.Sort(byType(got))
			sort.Sort(byType(want))
			if !reflect.DeepEqual(got, want) {
				return fmt.Errorf("got conditions\n%+v\nwant\n%+v", got, want)
			}
			return nil
		}
	}

	allUnknown := hasConditions([]configv1.ClusterOperatorStatusCondition{
		{
			Type:               configv1.OperatorProgressing,
			Status:             configv1.ConditionUnknown,
			LastTransitionTime: v1.Time{},
			Message:            "",
			Reason:             "",
		},
		{
			Type:               configv1.OperatorAvailable,
			Status:             configv1.ConditionUnknown,
			LastTransitionTime: v1.Time{},
			Message:            "",
			Reason:             "",
		},
		{
			Type:               configv1.OperatorDegraded,
			Status:             configv1.ConditionUnknown,
			LastTransitionTime: v1.Time{},
			Message:            "",
			Reason:             "",
		},
		{
			Type:               configv1.OperatorUpgradeable,
			Status:             configv1.ConditionUnknown,
			LastTransitionTime: v1.Time{},
			Message:            "",
			Reason:             "",
		},
	})

	for _, tc := range []struct {
		name       string
		conditions func() *conditions
		check      checkFunc
	}{
		{
			name: "initial nil conditions",
			conditions: func() *conditions {
				return newConditions(configv1.ClusterOperatorStatus{}, "", v1.Time{})
			},
			check: allUnknown,
		},
		{
			name: "initial empty conditions",
			conditions: func() *conditions {
				return newConditions(
					configv1.ClusterOperatorStatus{Conditions: []configv1.ClusterOperatorStatusCondition{}}, "", v1.Time{},
				)
			},
			check: allUnknown,
		},
		{
			name: "initial failing condition",
			conditions: func() *conditions {
				return newConditions(
					configv1.ClusterOperatorStatus{
						Conditions: []configv1.ClusterOperatorStatusCondition{
							{
								Type:   configv1.OperatorDegraded,
								Status: configv1.ConditionTrue,
							},
						},
					}, "", v1.Time{},
				)
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
			}),
		},
		{
			name: "progressing, previously unknown availability",
			conditions: func() *conditions {
				cs := newConditions(
					configv1.ClusterOperatorStatus{}, "", v1.Time{},
				)
				cs.setCondition(configv1.OperatorProgressing, configv1.ConditionTrue, "", "", v1.Unix(0, 0))
				return cs
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Unix(0, 0),
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
			}),
		}, {
			name: "progressing, previously unavailable",
			conditions: func() *conditions {
				cs := newConditions(
					configv1.ClusterOperatorStatus{}, "", v1.Time{},
				)
				cs.setCondition(configv1.OperatorAvailable, configv1.ConditionFalse, "", "", v1.Time{})
				cs.setCondition(configv1.OperatorDegraded, configv1.ConditionFalse, "", "", v1.Time{})
				cs.setCondition(configv1.OperatorUpgradeable, configv1.ConditionFalse, "", "", v1.Time{})
				cs.setCondition(configv1.OperatorProgressing, configv1.ConditionTrue, "", "", v1.Unix(0, 0))
				return cs
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Unix(0, 0),
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
			}),
		}, {
			name: "not progressing, previously available",
			conditions: func() *conditions {
				cs := newConditions(
					configv1.ClusterOperatorStatus{
						Conditions: []configv1.ClusterOperatorStatusCondition{
							{
								Type:   configv1.OperatorDegraded,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorAvailable,
								Status: configv1.ConditionTrue,
							},
							{
								Type:   configv1.OperatorProgressing,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorUpgradeable,
								Status: configv1.ConditionTrue,
							},
						},
					},
					"", v1.Time{},
				)
				cs.setCondition(configv1.OperatorProgressing, configv1.ConditionTrue, "", "", v1.Unix(0, 0))
				return cs
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
			}),
		}, {
			name: "not progressing, previously available, same version",
			conditions: func() *conditions {
				cs := newConditions(
					configv1.ClusterOperatorStatus{
						Versions: []configv1.OperandVersion{{Version: "1.0"}},
						Conditions: []configv1.ClusterOperatorStatusCondition{
							{
								Type:   configv1.OperatorDegraded,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorAvailable,
								Status: configv1.ConditionTrue,
							},
							{
								Type:   configv1.OperatorProgressing,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorUpgradeable,
								Status: configv1.ConditionTrue,
							},
						},
					},
					"1.0", v1.Time{},
				)
				cs.setCondition(configv1.OperatorProgressing, configv1.ConditionTrue, "", "", v1.Unix(0, 0))
				return cs
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
			}),
		}, {
			name: "progressing, previously available, different version",
			conditions: func() *conditions {
				cs := newConditions(
					configv1.ClusterOperatorStatus{
						Versions: []configv1.OperandVersion{{Version: "1.0"}},
						Conditions: []configv1.ClusterOperatorStatusCondition{
							{
								Type:   configv1.OperatorDegraded,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorAvailable,
								Status: configv1.ConditionTrue,
							},
							{
								Type:   configv1.OperatorProgressing,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorUpgradeable,
								Status: configv1.ConditionTrue,
							},
						},
					},
					"1.1", v1.Time{},
				)
				cs.setCondition(configv1.OperatorProgressing, configv1.ConditionTrue, "", "", v1.Unix(0, 0))
				cs.setCondition(configv1.OperatorUpgradeable, configv1.ConditionFalse, "", "", v1.Unix(0, 0))
				return cs
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Unix(0, 0),
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Unix(0, 0),
					Message:            "",
					Reason:             "",
				},
			}),
		}, {
			name: "progressing, previously unavailable, different version",
			conditions: func() *conditions {
				cs := newConditions(
					configv1.ClusterOperatorStatus{
						Versions: []configv1.OperandVersion{{Version: "1.0"}},
						Conditions: []configv1.ClusterOperatorStatusCondition{
							{
								Type:   configv1.OperatorDegraded,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorAvailable,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorProgressing,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorUpgradeable,
								Status: configv1.ConditionTrue,
							},
						},
					},
					"1.1", v1.Time{},
				)
				cs.setCondition(configv1.OperatorProgressing, configv1.ConditionTrue, "", "", v1.Unix(0, 0))
				cs.setCondition(configv1.OperatorUpgradeable, configv1.ConditionFalse, "", "", v1.Unix(0, 0))
				return cs
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Unix(0, 0),
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Unix(0, 0),
					Message:            "",
					Reason:             "",
				},
			}),
		}, {
			name: "progressing, previously unavailable, same version",
			conditions: func() *conditions {
				cs := newConditions(
					configv1.ClusterOperatorStatus{
						Versions: []configv1.OperandVersion{{Version: "1.0"}},
						Conditions: []configv1.ClusterOperatorStatusCondition{
							{
								Type:   configv1.OperatorDegraded,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorAvailable,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorProgressing,
								Status: configv1.ConditionFalse,
							},
							{
								Type:   configv1.OperatorUpgradeable,
								Status: configv1.ConditionFalse,
							},
						},
					},
					"1.0", v1.Time{},
				)
				cs.setCondition(configv1.OperatorProgressing, configv1.ConditionTrue, "", "", v1.Unix(0, 0))
				return cs
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Unix(0, 0),
					Message:            "",
				},
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
			}),
		}, {
			name: "change due to message change",
			conditions: func() *conditions {
				cs := newConditions(
					configv1.ClusterOperatorStatus{
						Conditions: []configv1.ClusterOperatorStatusCondition{
							{
								Type:               configv1.OperatorAvailable,
								Status:             configv1.ConditionTrue,
								Message:            "foo",
								LastTransitionTime: v1.Time{},
							},
						},
					}, "", v1.Time{},
				)
				cs.setCondition(configv1.OperatorAvailable, configv1.ConditionTrue, "bar", "foo", v1.Unix(0, 0))
				return cs
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Unix(0, 0),
					Message:            "bar",
					Reason:             "foo",
				},
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
			}),
		}, {
			name: "change due to status change",
			conditions: func() *conditions {
				cs := newConditions(
					configv1.ClusterOperatorStatus{
						Conditions: []configv1.ClusterOperatorStatusCondition{
							{
								Type:               configv1.OperatorAvailable,
								Status:             configv1.ConditionTrue,
								Message:            "foo",
								LastTransitionTime: v1.Time{},
							},
						},
					}, "", v1.Time{},
				)
				cs.setCondition(configv1.OperatorAvailable, configv1.ConditionFalse, "foo", "bar", v1.Unix(0, 0))
				return cs
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionFalse,
					LastTransitionTime: v1.Unix(0, 0),
					Message:            "foo",
					Reason:             "bar",
				},
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
			}),
		}, {
			name: "no change due to no message/status change",
			conditions: func() *conditions {
				cs := newConditions(
					configv1.ClusterOperatorStatus{
						Conditions: []configv1.ClusterOperatorStatusCondition{
							{
								Type:               configv1.OperatorAvailable,
								Status:             configv1.ConditionTrue,
								Message:            "foo",
								Reason:             "bar",
								LastTransitionTime: v1.Time{},
							},
						},
					}, "", v1.Time{},
				)
				cs.setCondition(configv1.OperatorAvailable, configv1.ConditionTrue, "foo", "bar", v1.Unix(0, 0))
				return cs
			},
			check: hasConditions([]configv1.ClusterOperatorStatusCondition{
				{
					Type:               configv1.OperatorAvailable,
					Status:             configv1.ConditionTrue,
					LastTransitionTime: v1.Time{},
					Message:            "foo",
					Reason:             "bar",
				},
				{
					Type:               configv1.OperatorProgressing,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorDegraded,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
				{
					Type:               configv1.OperatorUpgradeable,
					Status:             configv1.ConditionUnknown,
					LastTransitionTime: v1.Time{},
					Message:            "",
					Reason:             "",
				},
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(tc.conditions()); err != nil {
				t.Error(err)
			}
		})
	}
}
