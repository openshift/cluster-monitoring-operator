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
	"fmt"

	"github.com/Jeffail/gabs"
)

func getThanosRules(body []byte, expGroupName, expRuleName string) error {
	j, err := gabs.ParseJSON([]byte(body))
	if err != nil {
		return err
	}

	groups, err := j.Path("data.groups").Children()
	if err != nil {
		return err
	}

	for i := 0; i < len(groups); i++ {
		groupName := groups[i].S("name").Data().(string)
		if groupName != expGroupName {
			continue
		}

		rules, err := groups[i].Path("rules").Children()
		if err != nil {
			return err
		}

		for j := 0; j < len(rules); j++ {
			ruleName := rules[j].S("name").Data().(string)
			if ruleName == expRuleName {
				return nil
			}
		}
	}
	return fmt.Errorf("'%s' alert not found in '%s' group", expRuleName, expGroupName)
}
