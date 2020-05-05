package framework

import (
	"encoding/json"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type ruleGroups struct {
	Groups []ruleGroup `json:"groups" yaml:"groups"`
}

type ruleGroup struct {
	Name     string      `json:"name" yaml:"name"`
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

func apiRuleGroupsToManifestFormat(groups ruleGroups) ruleGroups {
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

// CreatePrometheusRulesManifest creates a yaml manifest containing alerting
// and recording rules from the data exposed by the Prometheus /api/v1/rules
// endpoint.
func CreatePrometheusRulesManifest(manifest string, raw []byte) error {
	var j map[string]json.RawMessage
	err := json.Unmarshal(raw, &j)
	if err != nil {
		return err
	}

	var groups ruleGroups
	err = json.Unmarshal(j["data"], &groups)
	if err != nil {
		return err
	}

	groups = apiRuleGroupsToManifestFormat(groups)

	yamlGroups, err := yaml.Marshal(groups)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(manifest, yamlGroups, 0644)
	if err != nil {
		return err
	}

	return nil
}
