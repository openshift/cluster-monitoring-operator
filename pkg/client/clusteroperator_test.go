package client

import (
	"reflect"
	"testing"

	v1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSetConditions(t *testing.T) {
	time := metav1.Time{}
	conditions := ensureConditionsInitialized([]v1.ClusterOperatorStatusCondition{}, time)
	conditions = setCondition(conditions, v1.OperatorAvailable, v1.ConditionFalse, "", time)
	conditions = setCondition(conditions, v1.OperatorProgressing, v1.ConditionTrue, "", time)
	conditions = setCondition(conditions, v1.OperatorFailing, v1.ConditionFalse, "", time)

	expectedConditions := []v1.ClusterOperatorStatusCondition{
		{
			Type:               v1.OperatorAvailable,
			Status:             v1.ConditionFalse,
			LastTransitionTime: time,
			Message:            "",
		},
		{
			Type:               v1.OperatorProgressing,
			Status:             v1.ConditionTrue,
			LastTransitionTime: time,
			Message:            "",
		},
		{
			Type:               v1.OperatorFailing,
			Status:             v1.ConditionFalse,
			LastTransitionTime: time,
			Message:            "",
		},
	}

	if !reflect.DeepEqual(conditions, expectedConditions) {
		t.Fatal("Unexpected conditons set. Expected only to be progressing.")
	}
}
