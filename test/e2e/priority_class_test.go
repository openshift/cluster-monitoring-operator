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

package e2e

import (
	"context"
	"testing"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This makes sure that the priority class we create is
// present and lower than the system priority classes. Example:
// openshift-user-critical   1000000000   false            66m
// system-cluster-critical   2000000000   false            114m
// system-node-critical      2000001000   false            114m
func TestToEnsureUserPriorityClassIsPresentAndLower(t *testing.T) {
	// Get system priority class values.
	systemClusterPriorityClass, err := f.SchedulingClient.PriorityClasses().Get(context.TODO(), "system-cluster-critical", v1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	systemNodePriorityClass, err := f.SchedulingClient.PriorityClasses().Get(context.TODO(), "system-node-critical", v1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Get our user priority class value.
	userPriorityClass, err := f.SchedulingClient.PriorityClasses().Get(context.TODO(), "openshift-user-critical", v1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Ensure our is a lower value than the system class' ones.
	if userPriorityClass.Value >= systemClusterPriorityClass.Value || userPriorityClass.Value >= systemNodePriorityClass.Value {
		t.Fatalf("openshift-user-critical was higher priority than existing classes: %d", userPriorityClass.Value)
	}
}
