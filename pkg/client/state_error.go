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

import (
	"strings"
)

type StateType int

const (
	Degraded    StateType = iota
	Unavailable StateType = iota
)

// StateError indicates if an operation performed by the client has
// resulted in an invalid state such as Degraded, Unavailable, Unknown
type State struct {
	Type    StateType
	Unknown bool
	Reasons []string
}

func (s *State) AddReasons(reasons ...string) {
	s.Reasons = append(s.Reasons, reasons...)
}

func (s *State) Merge(other *State) {
	// Degraded (true) > Degraded (Unknown)
	// overwrite Unknown only if it is set; i.e: Unknown is true, thus
	// merge: true + Any(true|false) => Any
	// merge: true + true|false => true

	if s.Unknown {
		s.Unknown = other.Unknown
	}
	s.AddReasons(other.Reasons...)
}

type StateError struct {
	states map[StateType]*State
}

var _ error = (*StateError)(nil)

func NewStateError() *StateError {
	return &StateError{states: map[StateType]*State{}}
}

func NewDegradedError(reasons ...string) *StateError {
	return NewStateErrorForType(Degraded, reasons...)
}

func NewAvailabilityError(reasons ...string) *StateError {
	return NewStateErrorForType(Unavailable, reasons...)
}

func NewStateErrorForType(t StateType, reasons ...string) *StateError {
	se := &StateError{states: map[StateType]*State{}}
	se.State(t).AddReasons(reasons...)
	return se
}

func newUnkownStateError(t StateType, reasons ...string) *StateError {
	se := NewStateErrorForType(t, reasons...)
	se.State(t).Unknown = true
	return se
}

func (se *StateError) IsEmpty() bool {
	return se == nil || len(se.states) == 0
}

func (se *StateError) Cleaned() *StateError {
	if se.IsEmpty() {
		return nil
	}
	return se
}

func (se *StateError) State(t StateType) *State {
	if se.states == nil {
		se.states = map[StateType]*State{}
	}

	if s, ok := se.states[t]; ok {
		return s
	}
	s := &State{Type: t, Unknown: false, Reasons: []string{}}
	se.states[t] = s
	return s
}

func (se *StateError) Degraded(reasons ...string) *State {
	degraded := se.State(Degraded)
	degraded.Reasons = append(degraded.Reasons, reasons...)

	return degraded
}

func (se *StateError) IsDegraded() bool {
	_, exists := se.states[Degraded]
	return exists
}

func (se *StateError) IsUnavailable() bool {
	_, exists := se.states[Unavailable]
	return exists
}

func (se *StateError) Unavailable(reasons ...string) *State {
	unavailable := se.State(Unavailable)
	unavailable.Reasons = append(unavailable.Reasons, reasons...)
	return unavailable
}

func (se *StateError) Reasons(t StateType) []string {
	s, ok := se.states[t]
	if !ok {
		return nil
	}
	return s.Reasons
}

func (se *StateError) Merge(other *StateError) {
	if other == nil {
		return
	}

	for t, state := range other.states {
		se.State(t).Merge(state)
	}
}

func (se *StateError) Error() string {
	if se.IsEmpty() {
		return ""
	}

	sb := strings.Builder{}

	sb.WriteString("status: ")
	unavailable := se.IsUnavailable()
	degraded := se.IsDegraded()
	switch {
	case unavailable && degraded:
		sb.WriteString("unavailable, degraded; reasons: ")
		sb.WriteString(strings.Join(se.Reasons(Unavailable), ", "))
		sb.WriteString(strings.Join(se.Reasons(Degraded), ", "))
	case unavailable:
		sb.WriteString("unavailable; reasons: ")
		sb.WriteString(strings.Join(se.Reasons(Unavailable), ", "))
	case degraded:
		sb.WriteString("degraded; reasons: ")
		sb.WriteString(strings.Join(se.Reasons(Degraded), ", "))
	}

	return sb.String()
}

// MergeStateErrors returns a StateError given many errors
func MergeStateErrors(errs ...*StateError) *StateError {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}

	ret := NewStateError()
	for _, err := range errs {
		ret.Merge(err)
	}

	if ret.IsEmpty() {
		return nil
	}

	return ret
}
