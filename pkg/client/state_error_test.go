package client

import (
	"errors"
	"testing"
)

func TestStateErrorBuilderHandleNilStateErrors(t *testing.T) {

	var nilErr error = StateErrors(nil)

	if nilErr == nil {
		t.Errorf("expected err to be non nil interface but is nil")
	}

	b := StateErrorBuilder{}
	b.AddError(nilErr, DegradedState)

	if err := b.ToError(); err != nil {
		t.Errorf("expected builder to return nil but returned %v", err)
	}

}

func TestStateErrorBuilderHandleNilStateError(t *testing.T) {

	var nilErr error = (*StateError)(nil)

	if nilErr == nil {
		t.Errorf("expected err to be non nil interface but is nil")
	}

	b := StateErrorBuilder{}
	b.MustAddStateError(nilErr)

	if err := b.ToError(); err != nil {
		t.Errorf("expected builder to return nil but returned %v", err)
	}
}

func TestStateErrorBuilderMustAdd(t *testing.T) {

	b := StateErrorBuilder{}
	assertNoPanic(t, func() { b.MustAddStateError(nil) })
	assertNoPanic(t, func() { b.MustAddStateErrors(nil) })

	assertNoPanic(t, func() { b.MustAddStateError((*StateError)(nil)) })
	assertNoPanic(t, func() { b.MustAddStateErrors(StateErrors(nil)) })
}

func TestStateErrorBuilderAddNilError(t *testing.T) {
	errs := []error{
		nil,
		(*StateError)(nil),
		(StateErrors)(nil),
		StateErrors{}, // empty
	}

	for _, err := range errs {
		b := StateErrorBuilder{}
		b.AddError(err, DegradedState)
		if err := b.ToError(); err != nil {
			t.Errorf("expected builder to return nil but returned %v", err)
		}
	}
}

func TestStateErrorBuilderSingleError(t *testing.T) {

	b := StateErrorBuilder{}
	expected := NewUnavailableError("foobar")
	b.AddStateError(expected)

	err := b.ToError()

	var actual *StateError
	if !errors.As(err, &actual) {
		t.Errorf("expected %v to be a StateError", err)
	}

	assertStateError(t, *actual, *expected)
}

func TestStateErrorBuilderMultipleErrors(t *testing.T) {

	b := StateErrorBuilder{}
	expected := StateErrors{
		NewDegradedError("first"),
		NewUnavailableError("second"),
	}

	b.AddStateErrors(expected)

	err := b.ToError()

	var actual StateErrors
	if !errors.As(err, &actual) {
		t.Errorf("expected %v to be a StateErrors", err)
	}

	assertStateErrors(t, expected, actual)
}

func TestStateErrorBuilderStateErrorTakesPrecedence(t *testing.T) {

	b := StateErrorBuilder{}
	var err error = NewUnavailableError("foobar")

	// StateError should take precedence over generic errors and should store
	// Unavailable error instead of DegradedState
	b.AddError(err, DegradedState)

	serrs := b.StateErrors()
	if n := len(serrs); n != 1 {
		t.Errorf("expected builder to hold 1 stateerror but got %d", n)
	}

	actual := serrs[0]

	var serr *StateError
	errors.As(err, &serr)

	if serr.State != UnavailableState {
		t.Errorf("expected %v to be unavailable but got %s", serr, serr.State)
	}

	assertStateError(t, *serr, *actual)
}

func TestStateErrorBuilderStateErrorsTakesPrecedence(t *testing.T) {

	b := StateErrorBuilder{}
	expected := StateErrors{
		NewUnavailableError("first"),
		NewUnavailableError("second"),
	}

	// StateErrors should take precedence over generic errors and
	// DegradedState should be ignored
	b.AddError(expected, DegradedState)

	more := StateErrors{
		NewUnavailableError("third"),
		NewUnavailableError("fourth"),
	}

	b.AddError(more, DegradedState)
	expected = append(expected, more...)

	actual := b.StateErrors()
	assertStateErrors(t, expected, actual)
}

func assertPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		t.Helper()
		if r := recover(); r == nil {
			t.Errorf("code did not panic when it was expected to panic")
		}
	}()
	f()
}

func assertNoPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		t.Helper()
		if r := recover(); r != nil {
			t.Errorf("paniced when not expected to panic")
		}
	}()
	f()
}

func assertStateError(t *testing.T, expected, actual StateError) {
	t.Helper()
	if actual.Reason != expected.Reason ||
		actual.State != expected.State ||
		actual.Unknown != expected.Unknown {
		t.Errorf("expected builder to return %v but returned %v", expected, actual)
	}
}

func assertStateErrors(t *testing.T, expected, actual StateErrors) {
	t.Helper()
	if n := len(actual); n != len(expected) {
		t.Errorf("expected builder to hold %d stateerror but got %d", len(expected), n)
	}

	for i := range expected {
		assertStateError(t, *expected[i], *actual[i])
	}
}
