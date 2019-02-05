package client

import (
	"fmt"

	v1 "github.com/openshift/api/config/v1"
	clientv1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type StatusReporter struct {
	client              clientv1.ClusterOperatorInterface
	clusterOperatorName string
	version             string
}

func NewStatusReporter(client clientv1.ClusterOperatorInterface, name, version string) *StatusReporter {
	return &StatusReporter{
		client:              client,
		clusterOperatorName: name,
		version:             version,
	}
}

func (r *StatusReporter) SetDone() error {
	co, err := r.client.Get(r.clusterOperatorName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		co = r.newClusterOperator()
		co, err = r.client.Create(co)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	time := metav1.Now()

	conditions := ensureConditionsInitialized(co.Status.Conditions, time)
	conditions = setCondition(conditions, v1.OperatorAvailable, v1.ConditionTrue, "Successfully rolled out the stack.", time)
	conditions = setCondition(conditions, v1.OperatorProgressing, v1.ConditionFalse, "", time)
	conditions = setCondition(conditions, v1.OperatorFailing, v1.ConditionFalse, "", time)
	co.Status.Conditions = conditions
	//co.Status.Version = r.version

	_, err = r.client.UpdateStatus(co)
	return err
}

func (r *StatusReporter) SetInProgress() error {
	co, err := r.client.Get(r.clusterOperatorName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		co = r.newClusterOperator()
		co, err = r.client.Create(co)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	time := metav1.Now()

	conditions := ensureConditionsInitialized(co.Status.Conditions, time)
	conditions = setCondition(conditions, v1.OperatorProgressing, v1.ConditionTrue, "Rolling out the stack.", time)
	co.Status.Conditions = conditions
	//co.Status.Version = r.version

	_, err = r.client.UpdateStatus(co)
	return err
}

func (r *StatusReporter) SetFailed(statusErr error) error {
	co, err := r.client.Get(r.clusterOperatorName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		co = r.newClusterOperator()
		co, err = r.client.Create(co)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	time := metav1.Now()

	conditions := ensureConditionsInitialized(co.Status.Conditions, time)
	conditions = setCondition(conditions, v1.OperatorAvailable, v1.ConditionFalse, "", time)
	conditions = setCondition(conditions, v1.OperatorProgressing, v1.ConditionFalse, "", time)
	conditions = setCondition(conditions, v1.OperatorFailing, v1.ConditionTrue, fmt.Sprintf("Failed to rollout the stack. Error: %v", statusErr), time)
	co.Status.Conditions = conditions
	//co.Status.Version = r.version

	_, err = r.client.UpdateStatus(co)
	return err
}

func (r *StatusReporter) newClusterOperator() *v1.ClusterOperator {
	time := metav1.Now()
	co := &v1.ClusterOperator{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "config.openshift.io/v1",
			Kind:       "ClusterOperator",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: r.clusterOperatorName,
		},
		Spec:   v1.ClusterOperatorSpec{},
		Status: v1.ClusterOperatorStatus{},
	}
	co.Status.Conditions = ensureConditionsInitialized(co.Status.Conditions, time)

	return co
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

func setCondition(conditions []v1.ClusterOperatorStatusCondition, condition v1.ClusterStatusConditionType, status v1.ConditionStatus, message string, time metav1.Time) []v1.ClusterOperatorStatusCondition {
	newConditions := []v1.ClusterOperatorStatusCondition{}
	found := false
	for _, c := range conditions {
		if c.Type == condition {
			found = true

			if c.Status != status || c.Message != message {
				newConditions = append(newConditions, v1.ClusterOperatorStatusCondition{
					Type:               condition,
					Status:             status,
					LastTransitionTime: time,
					Message:            message,
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
			Message:            message,
		})
	}

	return newConditions
}
