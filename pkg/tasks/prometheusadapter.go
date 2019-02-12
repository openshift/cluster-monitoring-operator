package tasks

import (
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PrometheusAdapterTask struct {
	client    *client.Client
	factory   *manifests.Factory
	namespace string
}

func NewPrometheusAdapterTaks(namespace string, client *client.Client, factory *manifests.Factory) *PrometheusAdapterTask {
	return &PrometheusAdapterTask{
		client:    client,
		factory:   factory,
		namespace: namespace,
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
		cm, err := t.factory.PrometheusAdapterConfigMapPrometheus()
		if err != nil {
			return errors.Wrap(err, "initializing PrometheusAdapter ConfigMap for Prometheus failed")
		}

		err = t.client.CreateOrUpdateConfigMap(cm)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter ConfigMap for Prometheus failed")
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
		apiAuthConfigmap, err := t.client.GetConfigmap("kube-system", "extension-apiserver-authentication")
		if err != nil {
			return errors.Wrap(err, "failed to load kube-system/extension-apiserver-authentication configmap")
		}

		apiAuthSecret, err := t.factory.PrometheusAdapterAPIAuthSecret(apiAuthConfigmap.Data)
		if err != nil {
			return errors.Wrap(err, "failed to create prometheus adapter api auth secret")
		}

		err = t.deleteOldPrometheusAdapterAPIAuthenticationSecret(apiAuthSecret.Name)
		if err != nil {
			return errors.Wrap(err, "deleting existing API authentication secret failed")
		}

		err = t.client.CreateOrUpdateSecret(apiAuthSecret)
		if err != nil {
			return errors.Wrap(err, "reconciling PrometheusAdapter Deployment failed")
		}

		dep, err := t.factory.PrometheusAdapterDeployment(apiAuthSecret.Name, apiAuthConfigmap.Data)
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

func (t *PrometheusAdapterTask) deleteOldPrometheusAdapterAPIAuthenticationSecret(newName string) error {
	deployment, err := t.client.KubernetesInterface().AppsV1beta2().Deployments(t.namespace).Get("prometheus-adapter", metav1.GetOptions{})

	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		return err
	}

	var name string
	vs := deployment.Spec.Template.Spec.Volumes
	for i := range vs {
		if vs[i].Name == "api-auth" && vs[i].Secret != nil {
			name = vs[i].Secret.SecretName
			break
		}
	}

	if name == "" || name == newName {
		return nil
	}

	return t.client.KubernetesInterface().CoreV1().Secrets(t.namespace).Delete(name, &metav1.DeleteOptions{})
}
