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

package strings

import (
	"testing"
)

func TestToPascalCase(t *testing.T) {
	cases := [][]string{
		{"taskNumber- one", "TaskNumberOne"},
		{"foo_bar", "FooBar"},
		{"foo", "Foo"},
		{"FooBar", "FooBar"},
		{"   foo bar   ", "FooBar"},
		{"", ""},
		{"foooo_foo_bar", "FooooFooBar"},
		{"AnyKind of_string", "AnyKindOfString"},
		{"foo-barRa", "FooBarRa"},
		{"numbers2And55with000", "Numbers2And55With000"},
	}
	for n, i := range cases {
		in := i[0]
		expected := i[1]
		result := ToPascalCase(in)
		if result != expected {
			t.Errorf("test case number: %d got: "+result+" expected: "+expected+"", n)
		}
	}

}
