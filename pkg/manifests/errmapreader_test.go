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

package manifests

import (
	"fmt"
	"reflect"
	"testing"
)

func TestErrMapReader(t *testing.T) {
	type checkFunc func(*errMapReader) error

	checks := func(cs ...checkFunc) checkFunc {
		return func(em *errMapReader) error {
			for _, c := range cs {
				if e := c(em); e != nil {
					return e
				}
			}
			return nil
		}
	}

	hasValue := func(key, want string) checkFunc {
		return checkFunc(func(em *errMapReader) error {
			if got := em.value(key); got != want {
				return fmt.Errorf("want value %v, got %v", want, got)
			}
			return nil
		})
	}

	hasSlice := func(key string, want []string) checkFunc {
		return checkFunc(func(em *errMapReader) error {
			if got := em.slice(key); !reflect.DeepEqual(got, want) {
				return fmt.Errorf("want slice %v, got %v", want, got)
			}
			return nil
		})
	}

	hasError := func(want string) checkFunc {
		return checkFunc(func(em *errMapReader) error {
			var got string
			if err := em.Error(); err != nil {
				got = err.Error()
			}
			if got != want {
				return fmt.Errorf("want error %v, got %v", want, got)
			}
			return nil
		})
	}

	for _, tc := range []struct {
		name  string
		init  func() *errMapReader
		check checkFunc
	}{
		{
			name:  "empty map",
			init:  func() *errMapReader { return newErrMapReader(nil) },
			check: hasError(""),
		},
		{
			name: "empty map slice first",
			init: func() *errMapReader {
				em := newErrMapReader(nil)
				em.slice("slice")
				em.value("value")
				return em
			},
			check: hasError("key slice is missing"),
		},
		{
			name: "empty map value first",
			init: func() *errMapReader {
				em := newErrMapReader(nil)
				em.value("value")
				em.slice("slice")
				return em
			},
			check: hasError("key value is missing"),
		},
		{
			name: "valid value invalid slice",
			init: func() *errMapReader {
				em := newErrMapReader(map[string]string{"value": "foo"})
				em.value("value")
				em.slice("slice")
				return em
			},
			check: checks(
				hasError("key slice is missing"),
				hasValue("value", ""),
			),
		},
		{
			name: "one valid value one invalid value",
			init: func() *errMapReader {
				em := newErrMapReader(map[string]string{"value": "foo"})
				em.value("value")
				em.value("na")
				return em
			},
			check: checks(
				hasError("key na is missing"),
				hasValue("value", ""),
			),
		},
		{
			name: "one valid value",
			init: func() *errMapReader {
				em := newErrMapReader(map[string]string{"value": "foo"})
				em.value("value")
				return em
			},
			check: hasValue("value", "foo"),
		},
		{
			name: "invalid slice",
			init: func() *errMapReader {
				em := newErrMapReader(map[string]string{"slice": "invalid"})
				em.slice("slice")
				return em
			},
			check: checks(
				hasError("invalid character 'i' looking for beginning of value"),
				hasSlice("slice", nil),
			),
		},
		{
			name: "empty slice value",
			init: func() *errMapReader {
				em := newErrMapReader(map[string]string{"slice": ""})
				em.slice("slice")
				return em
			},
			check: checks(
				hasError(""),
				hasValue("slice", ""),
				hasSlice("slice", nil),
			),
		},
		{
			name: "empty slice",
			init: func() *errMapReader {
				em := newErrMapReader(map[string]string{"slice": `[]`})
				em.slice("slice")
				return em
			},
			check: checks(
				hasError(""),
				hasValue("slice", `[]`),
				hasSlice("slice", []string{}),
			),
		},
		{
			name: "valid slice",
			init: func() *errMapReader {
				em := newErrMapReader(map[string]string{"slice": `["foo","bar"]`})
				em.slice("slice")
				return em
			},
			check: checks(
				hasError(""),
				hasValue("slice", `["foo","bar"]`),
				hasSlice("slice", []string{"foo", "bar"}),
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			em := tc.init()
			if err := tc.check(em); err != nil {
				t.Error(err)
			}
		})
	}
}
