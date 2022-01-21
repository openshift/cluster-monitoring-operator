package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AlertOverrides ... TODO(bison)
//
// Compatibility level 4: No compatibility is provided, the API can change at any point for any reason. These capabilities should not be used by applications needing long term support.
// +openshift:compatibility-gen:level=4
type AlertOverrides struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec describes the desired state of this AlertOverrides object.
	Spec AlertOverridesSpec `json:"spec"`

	// status describes the current state of this AlertOverrides object.
	// +optional
	Status AlertOverridesStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AlertOverridesList is a list of AlertOverrides objects.
//
// Compatibility level 4: No compatibility is provided, the API can change at any point for any reason. These capabilities should not be used by applications needing long term support.
// +openshift:compatibility-gen:level=4
type AlertOverridesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	// items is a list of AlertOverrides objects.
	Items []AlertOverrides `json:"items"`
}

// AlertOverridesSpec ... TODO(bison)
type AlertOverridesSpec struct {
	// overrides ... TODO(bison)
	Overrides []AlertOverride `json:"overrides,omitempty"`

	// rules ... TODO(bison)
	Rules []AlertRule `json:"rules,omitempty"`
}

// AlertOverridesStatus ... TODO(bison)
type AlertOverridesStatus struct {
	// conditions is a list of conditions and their status
	// +optional
	Conditions []AlertOverridesCondition `json:"conditions,omitempty"`
}

// AlertOverrideActionType ... TODO(bison)
type AlertOverrideActionType string

const (
	// PatchActionType ... TODO(bison)
	PatchActionType AlertOverrideActionType = "patch"

	// DropActionType ... TODO(bison)
	DropActionType AlertOverrideActionType = "drop"
)

// AlertOverride ... TOOD(bison)
type AlertRule struct {
	Alert       string              `json:"alert"`
	For         *string             `json:"for,omitempty"`
	Expr        *intstr.IntOrString `json:"expr,omitempty"`
	Labels      map[string]string   `json:"labels,omitempty"`
	Annotations map[string]string   `json:"annotations,omitempty"`
}

// AlertOverride ... TOOD(bison)
type AlertOverride struct {
	// selector ... TODO(bison)
	Selector AlertSelector `json:"selector"`

	// action ... TODO(bison)
	Action AlertOverrideActionType `json:"action"`

	For         *string             `json:"for,omitempty"`
	Expr        *intstr.IntOrString `json:"expr,omitempty"`
	Labels      map[string]string   `json:"labels,omitempty"`
	Annotations map[string]string   `json:"annotations,omitempty"`
}

// AlertSelector ... TODO(bison)
type AlertSelector struct {
	// alert is the name of the targeted alerting rule.
	Alert string `json:"alert"`

	// matchLabels is the set of labels that must match the *static* labels of
	// the targeted alert.  This is optional, but overrides can only target a
	// single alerting rule, so the slector must find a unique match.  If this
	// is omitted, the given alert name must be unique.
	// +optional
	MatchLabels map[string]string `json:"matchLabels"`
}

// AlertOverridesCondition ... TODO(bison)
type AlertOverridesCondition struct {
	Type               string          `json:"type"`
	Status             ConditionStatus `json:"status"`
	LastTransitionTime metav1.Time     `json:"lastTransitionTime,omitempty"`
	Reason             string          `json:"reason,omitempty"`
	Message            string          `json:"message,omitempty"`
}

type ConditionStatus string

const (
	ConditionTrue    ConditionStatus = "True"
	ConditionFalse   ConditionStatus = "False"
	ConditionUnknown ConditionStatus = "Unknown"
)
