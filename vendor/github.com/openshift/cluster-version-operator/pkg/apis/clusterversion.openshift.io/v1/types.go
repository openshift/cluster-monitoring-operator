package v1

import (
	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CVOConfigList is a list of CVOConfig resources.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CVOConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []CVOConfig `json:"items"`
}

// CVOConfig is the configuration for the ClusterVersionOperator. This is where
// parameters related to automatic updates can be set.
// +genclient
type CVOConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Upstream  URL       `json:"upstream"`
	Channel   string    `json:"channel"`
	ClusterID uuid.UUID `json:"clusterId"`

	DesiredUpdate Update `json:"desiredUpdate"`
}

// URL is a thin wrapper around string that ensures the string is a valid URL.
type URL string

// CVOStatus contains information specific to the ClusterVersionOperator. This
// object is inserted into the Extension attribute of the generic
// OperatorStatus object.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CVOStatus struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	AvailableUpdates []Update `json:"availableUpdates"`
}

// Update represents a release of the ClusterVersionOperator, referenced by the
// Payload member.
type Update struct {
	Version string `json:"version"`
	Payload string `json:"payload"`
}
