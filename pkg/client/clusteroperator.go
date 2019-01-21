package client

import (
	v1 "github.com/openshift/api/config/v1"
	clientv1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type StatusReporter struct {
	client              clientv1.ClusterOperatorInterface
	clusterOperatorName string
}

func NewStatusReporter(client clientv1.ClusterOperatorInterface, name string) *StatusReporter {
	return &StatusReporter{
		client:              client,
		clusterOperatorName: name,
	}
}

func (r *StatusReporter) SetDone() error {
	co, err := r.client.Get(r.clusterOperatorName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	time := metav1.Now()

	conditions := ensureConditionsInitialized(co.Status.Conditions, time)
	conditions = setCondition(conditions, v1.OperatorAvailable, v1.ConditionTrue, time)
	conditions = setCondition(conditions, v1.OperatorProgressing, v1.ConditionFalse, time)
	conditions = setCondition(conditions, v1.OperatorFailing, v1.ConditionFalse, time)
	co.Status.Conditions = conditions

	_, err = r.client.UpdateStatus(co)
	return err
}

func (r *StatusReporter) SetInProgress() error {
	co, err := r.client.Get(r.clusterOperatorName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	time := metav1.Now()

	conditions := ensureConditionsInitialized(co.Status.Conditions, time)
	conditions = setCondition(conditions, v1.OperatorProgressing, v1.ConditionTrue, time)
	co.Status.Conditions = conditions

	_, err = r.client.UpdateStatus(co)
	return err
}

func (r *StatusReporter) SetFailed() error {
	co, err := r.client.Get(r.clusterOperatorName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	time := metav1.Now()

	conditions := ensureConditionsInitialized(co.Status.Conditions, time)
	conditions = setCondition(conditions, v1.OperatorAvailable, v1.ConditionFalse, time)
	conditions = setCondition(conditions, v1.OperatorProgressing, v1.ConditionFalse, time)
	conditions = setCondition(conditions, v1.OperatorFailing, v1.ConditionTrue, time)
	co.Status.Conditions = conditions

	_, err = r.client.UpdateStatus(co)
	return err
}

func ensureConditionsInitialized(conditions []v1.ClusterOperatorStatusCondition, time metav1.Time) []v1.ClusterOperatorStatusCondition {
	if len(conditions) == 0 {
		return []v1.ClusterOperatorStatusCondition{
			{
				Type:               v1.OperatorAvailable,
				Status:             v1.ConditionUnknown,
				LastTransitionTime: time,
			},
			{
				Type:               v1.OperatorProgressing,
				Status:             v1.ConditionUnknown,
				LastTransitionTime: time,
			},
			{
				Type:               v1.OperatorFailing,
				Status:             v1.ConditionUnknown,
				LastTransitionTime: time,
			},
		}
	}

	return conditions
}

func setCondition(conditions []v1.ClusterOperatorStatusCondition, condition v1.ClusterStatusConditionType, status v1.ConditionStatus, time metav1.Time) []v1.ClusterOperatorStatusCondition {
	newConditions := []v1.ClusterOperatorStatusCondition{}
	found := false
	for _, c := range conditions {
		if c.Type == condition {
			found = true

			if c.Status != status {
				newConditions = append(newConditions, v1.ClusterOperatorStatusCondition{
					Type:               condition,
					Status:             status,
					LastTransitionTime: time,
				})
				continue
			}
		}
		newConditions = append(newConditions, c)
	}
	if !found {
		newConditions = append(newConditions, v1.ClusterOperatorStatusCondition{
			Type:               condition,
			Status:             status,
			LastTransitionTime: time,
		})
	}

	return newConditions
}
