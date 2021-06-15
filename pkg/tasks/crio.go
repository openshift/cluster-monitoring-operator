package tasks

import (
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/v2"
)

type CrioTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewCrioTask(client *client.Client, factory *manifests.Factory) *CrioTask {
	return &CrioTask{
		client:  client,
		factory: factory,
	}
}

func (t *CrioTask) Run() error {
	scc, err := t.factory.CrioSecurityContextConstraints()
	if err != nil {
		return errors.Wrap(err, "initializing CRI-O SecurityContextConstraints failed")
	}

	err = t.client.CreateOrUpdateSecurityContextConstraints(scc)
	if err != nil {
		return errors.Wrap(err, "reconciling CRI-O SecurityContextConstraints failed")
	}

	sa, err := t.factory.CrioServiceAccount()
	if err != nil {
		return errors.Wrap(err, "initializing CRI-O Service failed")
	}

	err = t.client.CreateOrUpdateServiceAccount(sa)
	if err != nil {
		return errors.Wrap(err, "reconciling CRI-O ServiceAccount failed")
	}

	cr, err := t.factory.CrioClusterRole()
	if err != nil {
		return errors.Wrap(err, "initializing CRI-O ClusterRole failed")
	}

	err = t.client.CreateOrUpdateClusterRole(cr)
	if err != nil {
		return errors.Wrap(err, "reconciling CRI-O ClusterRole failed")
	}

	crb, err := t.factory.CrioClusterRoleBinding()
	if err != nil {
		return errors.Wrap(err, "initializing CRI-O ClusterRoleBinding failed")
	}

	err = t.client.CreateOrUpdateClusterRoleBinding(crb)
	if err != nil {
		return errors.Wrap(err, "reconciling CRI-O ClusterRoleBinding failed")
	}

	s, err := t.factory.CrioSecret()
	if err != nil {
		return errors.Wrap(err, "initializing CRI-O secret failed")
	}

	loaded, err := t.client.GetSecret(s.Namespace, s.Name)
	switch {
	case apierrors.IsNotFound(err):
		klog.V(5).Info("creating new CRI-O secret")
	case err == nil:
		s = loaded
		klog.V(5).Info("found existing CRI-O secret")
	default:
		return errors.Wrap(err, "reading CRI-O secret")
	}

	err = manifests.RotateCrioSecret(s)
	if err != nil {
		return errors.Wrap(err, "rotating CRI-O secret")
	}

	err = t.client.CreateOrUpdateSecret(s)
	if err != nil {
		return errors.Wrap(err, "reconciling CRI-O secret failed")
	}

	srv, err := t.factory.CrioService()
	if err != nil {
		return errors.Wrap(err, "initializing CRI-O service failed")
	}

	err = t.client.CreateOrUpdateService(srv)
	if err != nil {
		return errors.Wrap(err, "reconciling CRI-O service failed")
	}

	sm, err := t.factory.CrioServiceMonitor()
	if err != nil {
		return errors.Wrap(err, "initializing CRI-O service monitor failed")
	}

	err = t.client.CreateOrUpdateServiceMonitor(sm)
	if err != nil {
		return errors.Wrap(err, "reconciling CRI-O service monitor failed")
	}

	ds, err := t.factory.CrioDaemonSet()
	if err != nil {
		return errors.Wrap(err, "initializing CRI-O DaemonSet failed")
	}

	err = t.client.CreateOrUpdateDaemonSet(ds)
	if err != nil {
		return errors.Wrap(err, "reconciling CRI-O DaemonSet failed")
	}

	return nil
}
