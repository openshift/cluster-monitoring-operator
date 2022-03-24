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

import "fmt"

type State string

const (
	Degraded    State = "degraded"
	Unavailable State = "unavailable"
)

// StateError indicates if an operation performed by the client has
// resulted in an invalid state such as Degraded, Unavailable, Unknown
type StateError struct {
	State   State
	Unknown bool
	Reason  string
}

func (se StateError) Error() string {
	unknown := ""
	if se.Unknown {
		unknown = " (unknown)"
	}
	return fmt.Sprintf("%s%s: %s", se.State, unknown, se.Reason)
}

func NewDegradedError(reason string) *StateError {
	return &StateError{State: Degraded, Unknown: false, Reason: reason}
}

func NewUnavailableError(reason string) *StateError {
	return &StateError{State: Unavailable, Unknown: false, Reason: reason}
}

type StateErrors []*StateError

func (serrs StateErrors) Contains(s State) bool {
	for _, err := range serrs {
		if err.State == s {
			return true
		}
	}
	return false
}

type StateErrorBuilder struct {
	errors StateErrors
}

func (b *StateErrorBuilder) Add(s State, unknown bool, reason string) *StateErrorBuilder {
	b.errors = append(b.errors, &StateError{State: s, Unknown: unknown, Reason: reason})
	return b
}

func (b *StateErrorBuilder) AddUnknown(s State, reason string) *StateErrorBuilder {
	return b.Add(s, true, reason)
}

func (b *StateErrorBuilder) AddDegraded(reason string) *StateErrorBuilder {
	return b.Add(Degraded, false, reason)

}
func (b *StateErrorBuilder) AddUnavailable(reason string) *StateErrorBuilder {
	return b.Add(Unavailable, false, reason)
}

func (b *StateErrorBuilder) AddError(s State, err error) *StateErrorBuilder {
	if err == nil {
		return b
	}

	return b.Add(s, false, err.Error())
}

func (b *StateErrorBuilder) AddStateErrors(serrs StateErrors) *StateErrorBuilder {
	if len(serrs) == 0 {
		return b
	}

	b.errors = append(b.errors, serrs...)
	return b
}

func (b *StateErrorBuilder) Errors() StateErrors {
	return b.errors
}

func ToStateErrors(errs ...*StateError) StateErrors {
	return errs
}

// func (s *State) AddReasons(reasons ...string) {
//   s.Reasons = append(s.Reasons, reasons...)
// }

// func (s *State) Merge(other *State) {
//   // Degraded (true) > Degraded (Unknown)
//   // overwrite Unknown only if it is set; i.e: Unknown is true, thus
//   // merge: true + Any(true|false) => Any
//   // merge: true + true|false => true

//   if s.Unknown {
//     s.Unknown = other.Unknown
//   }
//   s.AddReasons(other.Reasons...)
// }

// type StateError struct {
//   states map[StateType]*State
// }

// var _ error = (*StateError)(nil)

// func NewStateError() *StateError {
//   return &StateError{states: map[StateType]*State{}}
// }

// func NewDegradedError(reasons ...string) *StateError {
//   return NewStateErrorForType(Degraded, reasons...)
// }

// func NewAvailabilityError(reasons ...string) *StateError {
//   return NewStateErrorForType(Unavailable, reasons...)
// }

// func NewStateErrorForType(t StateType, reasons ...string) *StateError {
//   se := &StateError{states: map[StateType]*State{}}
//   se.State(t).AddReasons(reasons...)
//   return se
// }

// func newUnkownStateError(t StateType, reasons ...string) *StateError {
//   se := NewStateErrorForType(t, reasons...)
//   se.State(t).Unknown = true
//   return se
// }

// func (se *StateError) IsEmpty() bool {
//   return se == nil || len(se.states) == 0
// }

// func (se *StateError) Cleaned() *StateError {
//   if se.IsEmpty() {
//     return nil
//   }
//   return se
// }

// func (se *StateError) State(t StateType) *State {
//   if se.states == nil {
//     se.states = map[StateType]*State{}
//   }

//   if s, ok := se.states[t]; ok {
//     return s
//   }
//   s := &{Unknown: false, Reasons: []string{}}
//   se.states[t] = s
//   return s
// }

// func (se *StateError) Degraded(reasons ...string) *State {
//   degraded := se.State(Degraded)
//   degraded.Reasons = append(degraded.Reasons, reasons...)

//   return degraded
// }

// func (se *StateError) IsDegraded() bool {
//   _, exists := se.states[Degraded]
//   return exists
// }

// func (se *StateError) IsUnavailable() bool {
//   _, exists := se.states[Unavailable]
//   return exists
// }

// func (se *StateError) Unavailable(reasons ...string) *State {
//   unavailable := se.State(Unavailable)
//   unavailable.Reasons = append(unavailable.Reasons, reasons...)
//   return unavailable
// }

// func (se *StateError) Reasons(t StateType) []string {
//   s, ok := se.states[t]
//   if !ok {
//     return nil
//   }
//   return s.Reasons
// }

// func (se *StateError) Merge(other *StateError) {
//   if other == nil {
//     return
//   }

//   for t, state := range other.states {
//     se.State(t).Merge(state)
//   }
// }

// func (se *StateError) Error() string {
//   if se.IsEmpty() {
//     return ""
//   }

//   sb := strings.Builder{}

//   sb.WriteString("status: ")
//   unavailable := se.IsUnavailable()
//   degraded := se.IsDegraded()
//   switch {
//   case unavailable && degraded:
//     sb.WriteString("unavailable, degraded; reasons: ")
//     sb.WriteString(strings.Join(se.Reasons(Unavailable), ", "))
//     sb.WriteString(strings.Join(se.Reasons(Degraded), ", "))
//   case unavailable:
//     sb.WriteString("unavailable; reasons: ")
//     sb.WriteString(strings.Join(se.Reasons(Unavailable), ", "))
//   case degraded:
//     sb.WriteString("degraded; reasons: ")
//     sb.WriteString(strings.Join(se.Reasons(Degraded), ", "))
//   }

//   return sb.string()
// }

// // MergeStateErrors returns a StateError given many errors
// func MergeStateErrors(errs ...*StateError) *StateError {
//   if len(errs) == 0 {
//     return nil
//   }
//   if len(errs) == 1 {
//     return errs[0]
//   }

//   ret := NewStateError()
//   for _, err := range errs {
//     ret.Merge(err)
//   }

//   if ret.IsEmpty() {
//     return nil
//   }

//   return ret
// }
