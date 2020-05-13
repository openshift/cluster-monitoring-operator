package framework

import (
	"encoding/json"
	"path"
)

type RuleGroups struct {
	Groups []ruleGroup `json:"groups" yaml:"groups"`
}

type ruleGroup struct {
	Name     string      `json:"name" yaml:"name"`
	File     string      `json:"file" yaml:"file,omitempty"`
	Interval json.Number `json:"interval,omitempty" yaml:"interval,omitempty"`
	Rules    []rule      `json:"rules" yaml:"rules"`
}

type rule struct {
	Name        string            `json:"name" yaml:"name,omitempty"`
	Record      string            `yaml:"record,omitempty"`
	Alert       string            `yaml:"alert,omitempty"`
	Alerts      []interface{}     `json:"alerts,omitempty" yaml:"alerts,omitempty"`
	Expr        string            `json:"query" yaml:"expr"`
	For         json.Number       `json:"duration,omitempty" yaml:"for,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

func apiRuleGroupsToManifestFormat(groups RuleGroups) RuleGroups {
	for gIdx, group := range groups.Groups {
		for rIdx, rule := range group.Rules {
			// Set alert and record properly.
			if rule.Alerts != nil {
				rule.Alert = rule.Name
				rule.Alerts = nil
			} else {
				rule.Record = rule.Name
			}
			rule.Name = ""

			// Convert float64 duration to duration in second.
			if rule.For != "" {
				rule.For = rule.For + "s"
			}
			group.Rules[rIdx] = rule
		}
		// Convert float64 duration to duration in second.
		if group.Interval != "" {
			group.Interval = group.Interval + "s"
		}
		groups.Groups[gIdx] = group
	}
	return groups
}

func ruleGroupsPerFile(groups RuleGroups) map[string]RuleGroups {
	fileGroups := make(map[string]RuleGroups)

	for _, group := range groups.Groups {
		file := path.Base(group.File)

		// Empty File so that it is not marshal.
		group.File = ""

		fileGroup, exist := fileGroups[file]
		if !exist {
			fileGroups[file] = RuleGroups{[]ruleGroup{group}}
		} else {
			fileGroup.Groups = append(fileGroup.Groups, group)
			fileGroups[file] = fileGroup
		}
	}

	return fileGroups
}

// PrometheusRulesManifests returns a map of the rules manifests and their
// content from data exposed by the Prometheus /api/v1/rules endpoint.
func PrometheusRulesManifests(raw []byte) (map[string]RuleGroups, error) {
	var j map[string]json.RawMessage
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return nil, err
	}

	var groups RuleGroups
	err = json.Unmarshal(j["data"], &groups)
	if err != nil {
		return nil, err
	}

	groups = apiRuleGroupsToManifestFormat(groups)
	fileGroups := ruleGroupsPerFile(groups)

	return fileGroups, nil
}
