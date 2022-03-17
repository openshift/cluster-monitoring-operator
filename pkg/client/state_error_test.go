// Copyright 2022 The Cluster Monitoring Operator Authors
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

import "testing"

func TestStateErrorEmpty(t *testing.T) {
	nilErr := (*StateError)(nil)
	if nilErr.IsEmpty() != true {
		t.Errorf("nil error must be empty")
	}

	se := NewStateError()
	if se.IsEmpty() != true {
		t.Errorf("NewStateError must be empty")
	}

	degraded := NewDegradedError()
	if degraded.IsEmpty() != false {
		t.Errorf("degraded error must not be empty")
	}
}

func TestStateError(t *testing.T) {
	nilErr := (*StateError)(nil)
	if nilErr.IsEmpty() != true {
		t.Errorf("nil error must be empty")
	}

	se := NewStateError()
	if se.IsEmpty() != true {
		t.Errorf("NewStateError must be empty")
	}

	degraded := NewDegradedError()
	if degraded.IsEmpty() != false {
		t.Errorf("degraded error must not be empty")
	}
}

func TestStateErrorMergeNil(t *testing.T) {
	degradedErr := NewDegradedError("test")
	nilErr := (*StateError)(nil)
	degradedErr.Merge(nilErr)

	degraded, found := degradedErr.states[Degraded]
	if !found {
		t.Errorf("expected to find degraded state in merged but was absent")
	}
	if reasons := len(degraded.Reasons); reasons != 1 {
		t.Errorf("expected to find degraded state to have only one reason but was found %d", reasons)
	}
}

func TestStateErrorEmptyMerge(t *testing.T) {
	empty := &StateError{}
	degradedErr := NewDegradedError("test")
	empty.Merge(degradedErr)

	degraded, found := empty.states[Degraded]
	if !found {
		t.Errorf("expected to find degraded state in merged but was absent")
	}
	if reasons := len(degraded.Reasons); reasons != 1 {
		t.Errorf("expected to find degraded state to have only one reason but was found %d", reasons)
	}
}

func TestStateErrorMergeAnother(t *testing.T) {
	degradedErr := NewDegradedError("test")
	another := NewDegradedError("test 2")
	degradedErr.Merge(another)

	degraded, found := degradedErr.states[Degraded]
	if !found {
		t.Errorf("expected to find degraded state in merged but is absent")
	}
	if reasons := len(degraded.Reasons); reasons != 2 {
		t.Errorf("expected to find degraded state to have 2 reasons but found %d", reasons)
	}
}

func TestStateErrorMergeDifferent(t *testing.T) {
	degradedErr := NewDegradedError("test")
	availabilityErr := NewAvailabilityError("test 2")
	degradedErr.Merge(availabilityErr)

	degraded, found := degradedErr.states[Degraded]
	if !found {
		t.Errorf("expected to find degraded state in merged but is  absent")
	}
	if reasons := len(degraded.Reasons); reasons != 1 {
		t.Errorf("expected to find degraded state to have 1 reason but found %d", reasons)
	}

	unavailable, found := degradedErr.states[Unavailable]
	if !found {
		t.Errorf("expected to find degraded state in merged but is  absent")
	}
	if reasons := len(unavailable.Reasons); reasons != 1 {
		t.Errorf("expected to find unavailable state to have 1 reason but found %d", reasons)
	}

}
