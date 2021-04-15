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

package client

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	v1 "github.com/openshift/api/config/v1"
	clientv1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

func TestStatusReporterSetDone(t *testing.T) {
	for _, tc := range []struct {
		name  string
		given givenStatusReporter
		when  []whenFunc
		check []checkFunc
	}{
		{
			name: "not found",

			given: givenStatusReporter{
				operatorName:          "foo",
				namespace:             "bar",
				userWorkloadNamespace: "fred",
				version:               "1.0",
			},

			when: []whenFunc{
				getReturnsError(&apierrors.StatusError{
					ErrStatus: metav1.Status{Reason: metav1.StatusReasonNotFound},
				}),
				createReturnsError(nil),
				updateStatusReturnsError(nil),
			},

			check: []checkFunc{
				hasCreated(true),
				hasUpdatedStatus(true),
				hasUpdatedStatusVersions("1.0"),
				hasUpdatedStatusConditions(
					"Available", "True",
					"Degraded", "False",
					"Progressing", "False",
					"Upgradeable", "True",
				),
			},
		},
		{
			name: "found",

			given: givenStatusReporter{
				operatorName:          "foo",
				namespace:             "bar",
				userWorkloadNamespace: "fred",
				version:               "1.0",
			},

			when: []whenFunc{
				getReturnsClusterOperator(&v1.ClusterOperator{}),
				updateStatusReturnsError(nil),
			},

			check: []checkFunc{
				hasCreated(false),
				hasUpdatedStatus(true),
				hasUpdatedStatusVersions("1.0"),
				hasUpdatedStatusConditions(
					"Available", "True",
					"Degraded", "False",
					"Progressing", "False",
					"Upgradeable", "True",
				),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &clusterOperatorMock{}

			sr := NewStatusReporter(
				mock,
				tc.given.operatorName,
				tc.given.namespace,
				tc.given.userWorkloadNamespace,
				tc.given.version,
			)

			for _, w := range tc.when {
				w(mock)
			}

			got := sr.SetDone()

			for _, check := range tc.check {
				if err := check(mock, got); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestStatusReporterSetInProgress(t *testing.T) {
	for _, tc := range []struct {
		name  string
		given givenStatusReporter
		when  []whenFunc
		check []checkFunc
	}{
		{
			name: "not found",

			given: givenStatusReporter{
				operatorName:          "foo",
				namespace:             "bar",
				userWorkloadNamespace: "fred",
				version:               "1.0",
			},

			when: []whenFunc{
				getReturnsError(&apierrors.StatusError{
					ErrStatus: metav1.Status{Reason: metav1.StatusReasonNotFound},
				}),
				createReturnsError(nil),
				updateStatusReturnsError(nil),
			},

			check: []checkFunc{
				hasCreated(true),
				hasUpdatedStatus(true),
				hasUpdatedStatusVersions(),
				hasUpdatedStatusConditions(
					"Available", "Unknown",
					"Degraded", "Unknown",
					"Progressing", "True",
					"Upgradeable", "True",
				),
			},
		},
		{
			name: "found",

			given: givenStatusReporter{
				operatorName:          "foo",
				namespace:             "bar",
				userWorkloadNamespace: "fred",
				version:               "1.0",
			},

			when: []whenFunc{
				getReturnsClusterOperator(&v1.ClusterOperator{}),
				updateStatusReturnsError(nil),
			},

			check: []checkFunc{
				hasCreated(false),
				hasUpdatedStatus(true),
				hasUpdatedStatusVersions(),
				hasUpdatedStatusConditions(
					"Available", "Unknown",
					"Degraded", "Unknown",
					"Progressing", "True",
					"Upgradeable", "True",
				),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &clusterOperatorMock{}

			sr := NewStatusReporter(
				mock,
				tc.given.operatorName,
				tc.given.namespace,
				tc.given.userWorkloadNamespace,
				tc.given.version,
			)

			for _, w := range tc.when {
				w(mock)
			}

			got := sr.SetInProgress()

			for _, check := range tc.check {
				if err := check(mock, got); err != nil {
					t.Errorf("test case name '%s' failed with error: %v", tc.name, err)
				}
			}
		})
	}
}

func TestStatusReporterSetFailed(t *testing.T) {
	failedErr := errors.New("foo")

	for _, tc := range []struct {
		name  string
		given givenStatusReporter
		when  []whenFunc
		check []checkFunc
	}{
		{
			name: "not found",

			given: givenStatusReporter{
				operatorName:          "foo",
				namespace:             "bar",
				userWorkloadNamespace: "fred",
				version:               "1.0",
				err:                   failedErr,
			},

			when: []whenFunc{
				getReturnsError(&apierrors.StatusError{
					ErrStatus: metav1.Status{Reason: metav1.StatusReasonNotFound},
				}),
				createReturnsError(nil),
				updateStatusReturnsError(nil),
			},

			check: []checkFunc{
				hasCreated(true),
				hasUpdatedStatus(true),
				hasUpdatedStatusVersions(),
				hasUpdatedStatusConditions(
					"Available", "False",
					"Degraded", "True",
					"Progressing", "False",
					"Upgradeable", "True",
				),
				hasUnavailableMessage(),
			},
		},
		{
			name: "found",

			given: givenStatusReporter{
				operatorName:          "foo",
				namespace:             "bar",
				userWorkloadNamespace: "fred",
				version:               "1.0",
			},

			when: []whenFunc{
				getReturnsClusterOperator(&v1.ClusterOperator{}),
				updateStatusReturnsError(nil),
			},

			check: []checkFunc{
				hasCreated(false),
				hasUpdatedStatus(true),
				hasUpdatedStatusVersions(),
				hasUpdatedStatusConditions(
					"Available", "False",
					"Degraded", "True",
					"Progressing", "False",
					"Upgradeable", "True",
				),
				hasUnavailableMessage(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &clusterOperatorMock{}

			sr := NewStatusReporter(
				mock,
				tc.given.operatorName,
				tc.given.namespace,
				tc.given.userWorkloadNamespace,
				tc.given.version,
			)

			for _, w := range tc.when {
				w(mock)
			}

			got := sr.SetFailed(tc.given.err, "")

			for _, check := range tc.check {
				if err := check(mock, got); err != nil {
					t.Errorf("test case name '%s' failed with error: %v", tc.name, err)
				}
			}
		})
	}
}

type givenStatusReporter struct {
	operatorName, namespace, userWorkloadNamespace, version string
	err                                                     error
}

type checkFunc func(*clusterOperatorMock, error) error

func hasCreated(want bool) checkFunc {
	return func(mock *clusterOperatorMock, _ error) error {
		if got := mock.created != nil; got != want {
			return fmt.Errorf("want created %t, got %t", want, got)
		}
		return nil
	}
}

func hasUpdatedStatus(want bool) checkFunc {
	return func(mock *clusterOperatorMock, _ error) error {
		if got := mock.statusUpdated != nil; got != want {
			return fmt.Errorf("want status updated %t, got %t", want, got)
		}
		return nil
	}
}

func hasUpdatedStatusVersions(want ...string) checkFunc {
	return func(mock *clusterOperatorMock, _ error) error {
		var got []string
		for _, s := range mock.statusUpdated.Status.Versions {
			got = append(got, s.Version)
		}
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("want versions to be equal, but they aren't: want %q got %q", want, got)
		}
		return nil
	}
}

func hasUpdatedStatusConditions(want ...string) checkFunc {
	return func(mock *clusterOperatorMock, _ error) error {
		sort.Sort(byType(mock.statusUpdated.Status.Conditions))
		var got []string
		for _, c := range mock.statusUpdated.Status.Conditions {
			got = append(got, string(c.Type))
			got = append(got, string(c.Status))
		}
		if !reflect.DeepEqual(got, want) {
			return fmt.Errorf("want conditions to be equal, but they aren't: want %q got %q", want, got)
		}
		return nil
	}
}

func hasUnavailableMessage() checkFunc {
	return func(mock *clusterOperatorMock, _ error) error {
		sort.Sort(byType(mock.statusUpdated.Status.Conditions))
		for _, c := range mock.statusUpdated.Status.Conditions {
			if c.Type == v1.OperatorAvailable && c.Status == v1.ConditionFalse && c.Message == "" {
				return fmt.Errorf("want a message if available status is false, got %q", c.Message)
			}
		}
		return nil
	}
}

type whenFunc func(*clusterOperatorMock)

func getReturnsClusterOperator(co *v1.ClusterOperator) whenFunc {
	return func(mock *clusterOperatorMock) {
		mock.getFunc = func(string, metav1.GetOptions) (*v1.ClusterOperator, error) {
			return co, nil
		}
	}
}

func getReturnsError(e error) whenFunc {
	return func(mock *clusterOperatorMock) {
		mock.getFunc = func(string, metav1.GetOptions) (*v1.ClusterOperator, error) {
			return nil, e
		}
	}
}

func createReturnsError(e error) whenFunc {
	return func(mock *clusterOperatorMock) {
		mock.createFunc = func(co *v1.ClusterOperator) (*v1.ClusterOperator, error) {
			return co, e
		}
	}
}

func updateStatusReturnsError(e error) whenFunc {
	return func(mock *clusterOperatorMock) {
		mock.updateStatusFunc = func(co *v1.ClusterOperator) (*v1.ClusterOperator, error) {
			return co, e
		}
	}
}

type clusterOperatorMock struct {
	createFunc, updateFunc, updateStatusFunc func(*v1.ClusterOperator) (*v1.ClusterOperator, error)
	getFunc                                  func(string, metav1.GetOptions) (*v1.ClusterOperator, error)

	created, updated, statusUpdated *v1.ClusterOperator
}

// ensure the mock satisfies the ClusterOperatorInterface interface.
var _ clientv1.ClusterOperatorInterface = (*clusterOperatorMock)(nil)

func (com *clusterOperatorMock) Create(ctx context.Context, co *v1.ClusterOperator, opts metav1.CreateOptions) (*v1.ClusterOperator, error) {
	com.created = co
	return com.createFunc(co)
}

func (com *clusterOperatorMock) Update(ctx context.Context, co *v1.ClusterOperator, opts metav1.UpdateOptions) (*v1.ClusterOperator, error) {
	com.updated = co
	return com.updateFunc(co)
}

func (com *clusterOperatorMock) UpdateStatus(ctx context.Context, co *v1.ClusterOperator, opts metav1.UpdateOptions) (*v1.ClusterOperator, error) {
	com.statusUpdated = co
	return com.updateStatusFunc(co)
}

func (com *clusterOperatorMock) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return nil
}

func (com *clusterOperatorMock) DeleteCollection(ctx context.Context, options metav1.DeleteOptions, listOptions metav1.ListOptions) error {
	return nil
}

func (com *clusterOperatorMock) Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.ClusterOperator, error) {
	return com.getFunc(name, opts)
}

func (com *clusterOperatorMock) List(ctx context.Context, opts metav1.ListOptions) (*v1.ClusterOperatorList, error) {
	return nil, nil
}

func (com *clusterOperatorMock) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return nil, nil
}

func (com *clusterOperatorMock) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ClusterOperator, err error) {
	return nil, nil
}
