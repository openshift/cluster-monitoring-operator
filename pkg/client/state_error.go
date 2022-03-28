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

// ToStateError converts an error to a StateError if error itself isn't a StateError
func ToStateError(s State, err error) *StateError {
	if err == nil {
		return nil
	}

	serr, ok := err.(*StateError)
	if ok {
		return serr
	}

	return &StateError{State: s, Reason: err.Error()}
}

type StateErrors []*StateError

func (serrs StateErrors) Error() string {
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

	isUnavailable := len(unavailableReasons) > 0
	isDegraded := len(degradedReasons) > 0

	sb := strings.Builder{}
	sb.WriteString("state: ")
	switch {
	case isUnavailable && isDegraded:
		sb.WriteString("unavailable, degraded")
	case isDegraded:
		sb.WriteString("degraded")
	case isUnavailable:
		sb.WriteString("unavailable")
	}

	sb.WriteString("; reasons: ")
	sb.WriteString(strings.Join(unavailableReasons, ", "))
	sb.WriteString(strings.Join(degradedReasons, ", "))
	return sb.String()
}

type StateErrorBuilder struct {
	errors StateErrors
}

func (b *StateErrorBuilder) add(s State, unknown bool, reason string) *StateErrorBuilder {
	b.errors = append(b.errors, &StateError{State: s, Unknown: unknown, Reason: reason})
	return b
}

func (b *StateErrorBuilder) AddUnknown(s State, reason string) *StateErrorBuilder {
	return b.add(s, true, reason)
}

func (b *StateErrorBuilder) AddDegraded(reason string) *StateErrorBuilder {
	return b.add(DegradedState, false, reason)

}
func (b *StateErrorBuilder) AddUnavailable(reason string) *StateErrorBuilder {
	return b.add(UnavailableState, false, reason)
}

func (b *StateErrorBuilder) AddError(s State, err error) *StateErrorBuilder {
	if err == nil {
		return b
	}

	return b.add(s, false, err.Error())
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
