package tasks

import (
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
)

type PrometheusAdapterTask struct {
	client  *client.Client
	factory *manifests.Factory
}

func NewPrometheusAdapterTaks(client *client.Client, factory *manifests.Factory) *PrometheusAdapterTask {
	return &PrometheusAdapterTask{
		client:  client,
		factory: factory,
	}
}

func (t *PrometheusAdapterTask) Run() error {
	{
		cr, err := t.factory.PrometheusAdapterClusterRole()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter ClusterRole failed")
		}

		err = t.client.CreateOrUpdateClusterRole(cr)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter ClusterRole failed")
		}
	}
	{
		cr, err := t.factory.PrometheusAdapterClusterRoleServerResources()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter ClusterRole for server resources failed")
		}

		err = t.client.CreateOrUpdateClusterRole(cr)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter ClusterRole for server resources failed")
		}
	}
	{
		crb, err := t.factory.PrometheusAdapterClusterRoleBinding()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter ClusterRoleBinding failed")
		}

		err = t.client.CreateOrUpdateClusterRoleBinding(crb)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter ClusterRoleBinding failed")
		}
	}
	{
		crb, err := t.factory.PrometheusAdapterClusterRoleBindingDelegator()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter ClusterRoleBinding for delegator failed")
		}

		err = t.client.CreateOrUpdateClusterRoleBinding(crb)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter ClusterRoleBinding for delegator failed")
		}
	}
	{
		crb, err := t.factory.PrometheusAdapterClusterRoleBindingView()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter ClusterRoleBinding for view failed")
		}

		err = t.client.CreateOrUpdateClusterRoleBinding(crb)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter ClusterRoleBinding for view failed")
		}
	}
	{
		rb, err := t.factory.PrometheusAdapterRoleBindingAuthReader()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter RoleBinding for auth-reader failed")
		}

		err = t.client.CreateOrUpdateRoleBinding(rb)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter RoleBinding for auth-reader failed")
		}
	}
	{
		sa, err := t.factory.PrometheusAdapterServiceAccount()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter ServiceAccount failed")
		}

		err = t.client.CreateOrUpdateServiceAccount(sa)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter ServiceAccount failed")
		}
	}
	{
		cm, err := t.factory.PrometheusAdapterConfigMap()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter ConfigMap failed")
		}

		err = t.client.CreateOrUpdateConfigMap(cm)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter ConfigMap failed")
		}
	}
	{
		s, err := t.factory.PrometheusAdapterService()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter Service failed")
		}

		err = t.client.CreateOrUpdateService(s)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter Service failed")
		}
	}
	{
		dep, err := t.factory.PrometheusAdapterDeployment()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter Deployment failed")
		}

		err = t.client.CreateOrUpdateDeployment(dep)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter Deployment failed")
		}
	}
	{
		api, err := t.factory.PrometheusAdapterAPIService()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter APIService failed")
		}

		err = t.client.CreateOrUpdateAPIService(api)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter APIService failed")
		}
	}

	return nil
}
