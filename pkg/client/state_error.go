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
	"errors"
	"fmt"
	"strings"
)

type State string

const (
	DegradedState    State = "degraded"
	UnavailableState State = "unavailable"
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
	return &StateError{State: DegradedState, Unknown: false, Reason: reason}
}

func NewUnavailableError(reason string) *StateError {
	return &StateError{State: UnavailableState, Unknown: false, Reason: reason}
}

func NewUnknownStateError(s State, reason string) *StateError {
	return &StateError{State: s, Unknown: true, Reason: reason}
}

// ToStateError converts an error to a StateError if error itself isn't a StateError
func ToStateError(s State, err error) *StateError {
	if err == nil {
		return nil
	}

	var serr *StateError
	if errors.As(err, &serr) {
		return serr
	}

	return &StateError{State: s, Reason: err.Error()}
}

type StateErrors []*StateError

func (serrs StateErrors) Error() string {
	if len(serrs) == 0 {
		// return the same output as a nil error
		return fmt.Sprint((error)(nil))
	}

	degradedUnknown := false
	degradedReasons := []string{}

	unavailableUnknown := false
	unavailableReasons := []string{}

	for _, err := range serrs {
		switch err.State {
		case DegradedState:
			degradedReasons = append(degradedReasons, err.Reason)
			degradedUnknown = degradedUnknown || err.Unknown

		case UnavailableState:
			unavailableReasons = append(unavailableReasons, err.Reason)
			unavailableUnknown = unavailableUnknown || err.Unknown
		}
	}

	sb := strings.Builder{}
	sb.WriteString("state: ")

	if len(unavailableReasons) > 0 {
		sb.WriteString("unavailable")
		if unavailableUnknown {
			sb.WriteString("(unknown)")
		}
	}

	if len(degradedReasons) > 0 {
		sb.WriteString("degraded")
		if degradedUnknown {
			sb.WriteString("(unknown)")
		}
	}

	sb.WriteString("; reasons: ")
	sb.WriteString(strings.Join(unavailableReasons, ", "))
	sb.WriteString("; ")
	sb.WriteString(strings.Join(degradedReasons, ", "))
	return sb.String()
}

type StateErrorBuilder struct {
	errors StateErrors
}

func (b *StateErrorBuilder) add(s State, unknown bool, reason string) {
	b.errors = append(b.errors, &StateError{State: s, Unknown: unknown, Reason: reason})
}

func (b *StateErrorBuilder) AddUnknown(s State, reason string) {
	b.add(s, true, reason)
}

func (b *StateErrorBuilder) AddDegraded(reason string) {
	b.add(DegradedState, false, reason)

}
func (b *StateErrorBuilder) AddUnavailable(reason string) {
	b.add(UnavailableState, false, reason)
}

func (b *StateErrorBuilder) AddError(err error, s State) {
	if err == nil {
		return
	}

	var serrs StateErrors
	if errors.As(err, &serrs) {
		b.AddStateErrors(serrs)
		return
	}

	var se *StateError
	if errors.As(err, &se) {
		b.AddStateError(se)
		return
	}

	b.add(s, false, err.Error())
}

func (b *StateErrorBuilder) MustAddStateError(err error) {
	if err == nil {
		return
	}

	var se *StateError
	if !errors.As(err, &se) {
		panic(fmt.Sprintf("%v is not a StateError", err))
	}

	b.AddStateError(se)
}

func (b *StateErrorBuilder) MustAddStateErrors(err error) {
	if err == nil {
		return
	}

	serrs := StateErrors{}
	if !errors.As(err, &serrs) {
		panic(fmt.Sprintf("%v is not StateErrors", err))
	}

	b.errors = append(b.errors, serrs...)
}

func (b *StateErrorBuilder) AddStateError(serr *StateError) {
	if serr == nil {
		return
	}

	b.errors = append(b.errors, serr)
}

func (b *StateErrorBuilder) AddStateErrors(serrs StateErrors) *StateErrorBuilder {
	if len(serrs) == 0 {
		return b
	}

	b.errors = append(b.errors, serrs...)
	return b
}

func (b *StateErrorBuilder) StateErrors() StateErrors {
	if len(b.errors) == 0 {
		return nil
	}

	return b.errors
}

func (b *StateErrorBuilder) ToError() error {
	if len(b.errors) == 0 {
		return nil
	}
	if len(b.errors) == 1 {
		return b.errors[0]
	}

	return b.errors
}

func ToStateErrors(errs ...*StateError) StateErrors {
	return errs
}
