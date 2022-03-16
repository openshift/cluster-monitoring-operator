package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// NOTE: The AlertingRule type is a direct copy of the upstream PrometheusRule
// type from prometheus-operator.  The only difference at the moment is that we
// don't allow recording rules in OpenShift.  All rules must be alerting rules,
// but outside of that restriction, each AlertingRule will result in a 1:1 alike
// PrometheusRule object being created.
//
// See the upstream docs here:
// - https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md

// AlertingRule represents a set of user-defined Prometheus rule groups containing
// alerting rules -- recording rules are not allowed.
//
// Compatibility level 4: No compatibility is provided, the API can change at any point for any reason. These capabilities should not be used by applications needing long term support.
// +openshift:compatibility-gen:level=4
// +genclient
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:subresource:status
type AlertingRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec describes the desired state of this AlertingRule object.
	Spec AlertingRuleSpec `json:"spec"`

	// status describes the current state of this AlertOverrides object.
	//
	// +optional
	Status AlertingRuleStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AlertingRuleList is a list of AlertingRule objects.
//
// Compatibility level 4: No compatibility is provided, the API can change at any point for any reason. These capabilities should not be used by applications needing long term support.
// +openshift:compatibility-gen:level=4
// +k8s:openapi-gen=true
type AlertingRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// items is a list of AlertingRule objects.
	Items []AlertingRule `json:"items"`
}

// AlertingRuleSpec is the desired state of an AlertingRule resource.
//
// +k8s:openapi-gen=true
type AlertingRuleSpec struct {
	// groups is a list of grouped alerting rules.
	//
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems:=1
	Groups []RuleGroup `json:"groups"`
}

// RuleGroup is a list of sequentially evaluated alerting rules.
//
// +k8s:openapi-gen=true
type RuleGroup struct {
	// name is the name of the group.
	//
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// interval is how often rules in the group are evaluated.  If not specified,
	// it defaults to the global.evaluation_interval configured in Prometheus,
	// which itself defaults to 1 minute.  This is represented as a Prometheus
	// duration, for details on the format see:
	// - https://prometheus.io/docs/prometheus/latest/configuration/configuration/#duration
	//
	// +kubebuilder:validation:Pattern:="((([0-9]+)y)?(([0-9]+)w)?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?|0)"
	// +optional
	Interval string `json:"interval,omitempty"`

	// rules is a list of sequentially evaluated alerting rules.
	//
	// +kubebuilder:validation:MinItems:=1
	Rules []Rule `json:"rules"`
}

// Rule describes an alerting rule.
// See Prometheus documentation:
// - https://www.prometheus.io/docs/prometheus/latest/configuration/alerting_rules
//
// +k8s:openapi-gen=true
type Rule struct {
	// alert is the name of the alert. Must be a valid label value, i.e. only
	// contain ASCII letters, numbers, and underscores.
	//
	// +kubebuilder:validation:Pattern:="^[a-zA-Z_][a-zA-Z0-9_]*$"
	Alert string `json:"alert"`

	// expr is the PromQL expression to evaluate. Every evaluation cycle this is
	// evaluated at the current time, and all resultant time series become
	// pending/firing alerts.
	Expr intstr.IntOrString `json:"expr"`

	// for is the time period after which alerts are considered firing after first
	// returning results.  Alerts which have not yet fired for long enough are
	// considered pending. This is represented as a Prometheus duration, for
	// details on the format see:
	// - https://prometheus.io/docs/prometheus/latest/configuration/configuration/#duration
	//
	// +kubebuilder:validation:Pattern:="((([0-9]+)y)?(([0-9]+)w)?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?|0)"
	// +optional
	For string `json:"for,omitempty"`

	// labels to add or overwrite for each alert.
	//
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// annotations to add to each alert.
	//
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// AlertingRuleStatus is the status of an AlertingRule resource.
type AlertingRuleStatus struct {
	// observedGeneration is the last generation change you've dealt with.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// prometheusRule is the generated PrometheusRule for this AlertingRule.
	//
	// +optional
	PrometheusRule string `json:"prometheusRule,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:subresource:status

// AlertRelabelConfig defines a set of relabel configs for alerts.
//
// Compatibility level 4: No compatibility is provided, the API can change at any point for any reason. These capabilities should not be used by applications needing long term support.
// +openshift:compatibility-gen:level=4
// +k8s:openapi-gen=true
type AlertRelabelConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec describes the desired state of this AlertRelabelConfig object.
	Spec AlertRelabelConfigSpec `json:"spec"`

	// status describes the current state of this AlertRelabelConfig object.
	//
	// +optional
	Status AlertRelabelConfigStatus `json:"status,omitempty"`
}

// AlertRelabelConfigsSpec is the desired state of an AlertRelabelConfig resource.
//
// +k8s:openapi-gen=true
type AlertRelabelConfigSpec struct {
	// configs is a list of sequentially evaluated alert relabel configs.
	//
	// +kubebuilder:validation:MinItems:=1
	Configs []RelabelConfig `json:"configs"`
}

// AlertRelabelConfigStatus is the status of an AlertRelabelConfig resource.
type AlertRelabelConfigStatus struct {
	// conditions contains details on the state of the AlertRelabelConfig, may be
	// empty.
	//
	// +optional
	Conditions []AlertRelabelConfigCondition `json:"conditions,omitempty"`
}

// AlertRelabelConfigConditionType is a valid value for the type field of an
// AlertRelabelConfigCondition.
type AlertRelabelConfigConditionType string

const (
	// AlertRelabelConfigReady is the condition type indicating readiness.
	AlertRelabelConfigReady AlertRelabelConfigConditionType = "Ready"
)

// AlertRelabelConfigCondition details a status condition of an AlertRelabelConfig.
type AlertRelabelConfigCondition struct {
	// type is the type of the condition.
	Type AlertRelabelConfigConditionType `json:"type"`
	// status is the status of the condition. May be True, False, or Unknown.
	Status corev1.ConditionStatus `json:"status"`
	// reason for the condition's last transition. Usually a machine and human
	// readable constant.
	Reason string `json:"reason,omitempty"`
	// message is a human readable message indicating details about the last
	// transition.
	Message string `json:"message,omitempty"`
	// RFC 3339 date and time when this condition last transitioned.
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AlertRelabelConfigList is a list of AlertRelabelConfigs.
//
// Compatibility level 4: No compatibility is provided, the API can change at any point for any reason. These capabilities should not be used by applications needing long term support.
// +openshift:compatibility-gen:level=4
// +k8s:openapi-gen=true
type AlertRelabelConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// items is a list of AlertRelabelConfigs.
	Items []*AlertRelabelConfig `json:"items"`
}

// LabelName is a valid Prometheus label name which may only contain ASCII
// letters, numbers, and underscores.
//
// +kubebuilder:validation:Pattern:="^[a-zA-Z_][a-zA-Z0-9_]*$"
type LabelName string

// RelabelConfig allows dynamic rewriting of label sets for alerts.
// See Prometheus documentation:
// - https://prometheus.io/docs/prometheus/latest/configuration/configuration/#alert_relabel_configs
// - https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config
//
// +k8s:openapi-gen=true
type RelabelConfig struct {
	// sourceLabels select values from existing labels. Their content is
	// concatenated using the configured separator and matched against the
	// configured regular expression for the replace, keep, and drop actions.
	//
	// +optional
	SourceLabels []LabelName `json:"sourceLabels,omitempty"`

	// separator placed between concatenated source label values. When omitted,
	// Prometheus will use its default value of ';'.
	//
	// +optional
	Separator string `json:"separator,omitempty"`

	// targetLabel to which the resulting value is written in a replace action.
	// It is mandatory for 'replace' and 'hashmod' actions. Regex capture groups
	// are available.
	//
	// +optional
	TargetLabel string `json:"targetLabel,omitempty"`

	// regex against which the extracted value is matched. Default is: '(.*)'
	//
	// +optional
	Regex string `json:"regex,omitempty"`

	// modulus to take of the hash of the source label values.  This can be
	// combined with the 'hashmod' action to set 'target_label' to the 'modulus'
	// of a hash of the concatenated 'source_labels'.
	//
	// +optional
	Modulus uint64 `json:"modulus,omitempty"`

	// replacement value against which a regex replace is performed if the regular
	// expression matches. This is required if the action is 'replace' or
	// 'labelmap'. Regex capture groups are available. Default is: '$1'
	//
	// +optional
	Replacement string `json:"replacement,omitempty"`

	// action to perform based on regex matching. Must be one of: replace, keep,
	// drop, hashmod, labelmap, labeldrop, or labelkeep.  Default is: 'replace'
	//
	// +kubebuilder:validation:Enum=Replace;Keep;Drop;HashMod;LabelMap;LabelDrop;LabelKeep
	// +kubebuilder:default=Replace
	// +optional
	Action string `json:"action,omitempty"`
}
