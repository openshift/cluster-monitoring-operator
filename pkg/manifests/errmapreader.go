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
	"encoding/json"
	"fmt"
)

// errMapReader wraps a map[string]string and exposes read methods
// for values and slices.
// It tracks the first occured error in errMapReader.err
// when reading values from the underlying map.
type errMapReader struct {
	src map[string]string
	err error
}

func newErrMapReader(src map[string]string) *errMapReader {
	return &errMapReader{src: src}
}

// value returns the value from the underlying map if it is present.
// If it is not present, an error is generated, errMapReader.err is updated
// and empty string is returned.
// If an error already occured in a previous call, empty string is returned.
func (r *errMapReader) value(key string) string {
	if r.err != nil {
		return ""
	}

	result, ok := r.src[key]
	if !ok {
		r.err = fmt.Errorf("key %s is missing", key)
		return ""
	}

	return result
}

// slice calls errMapReader.Value(key) and parses the resulting string as a JSON list of strings.
// If an error already occured in a previous call, empty string is returned.
// If an error occurs during parsing, errMapReader.err is updated
// and nil is returned.
func (r *errMapReader) slice(key string) []string {
	if r.err != nil {
		return nil
	}

	v := r.value(key)
	if r.err != nil {
		return nil
	}

	if len(v) == 0 {
		return nil
	}

	var ret []string
	if err := json.Unmarshal([]byte(v), &ret); err != nil {
		r.err = err
		return nil
	}

	return ret
}

// Error returns the first error that occured
// when reading values from the underlying map.
func (r *errMapReader) Error() error {
	return r.err
}
