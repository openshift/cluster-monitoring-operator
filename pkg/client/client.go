// Copyright 2018 The Cluster Monitoring Operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"fmt"
	"net/url"
	"reflect"
	"time"

	"github.com/coreos/prometheus-operator/pkg/alertmanager"
	mon "github.com/coreos/prometheus-operator/pkg/apis/monitoring"
	monv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	monitoring "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"github.com/coreos/prometheus-operator/pkg/k8sutil"
	prometheusoperator "github.com/coreos/prometheus-operator/pkg/prometheus"
	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	secv1 "github.com/openshift/api/security/v1"
	openshiftconfigclientset "github.com/openshift/client-go/config/clientset/versioned"
	openshiftrouteclientset "github.com/openshift/client-go/route/clientset/versioned"
	openshiftsecurityclientset "github.com/openshift/client-go/security/clientset/versioned"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1beta2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	v1betaextensions "k8s.io/api/extensions/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	extensionsobj "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	apiregistrationv1beta1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

const (
	deploymentCreateTimeout = 5 * time.Minute
)

type Client struct {
	version           string
	namespace         string
	namespaceSelector string
	kclient           kubernetes.Interface
	oscclient         openshiftconfigclientset.Interface
	ossclient         openshiftsecurityclientset.Interface
	osrclient         openshiftrouteclientset.Interface
	mclient           monitoring.Interface
	eclient           apiextensionsclient.Interface
	aggclient         aggregatorclient.Interface
}

func New(cfg *rest.Config, version string, namespace string, namespaceSelector string) (*Client, error) {
	mclient, err := monitoring.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	kclient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "creating kubernetes clientset client")
	}

	eclient, err := apiextensionsclient.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "creating apiextensions client")
	}

	oscclient, err := openshiftconfigclientset.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "creating openshift config client")
	}

	// SCC moved to CRD and CRD does not handle protobuf. Force the SCC client to use JSON instead.
	jsonClientConfig := rest.CopyConfig(cfg)
	jsonClientConfig.ContentConfig.AcceptContentTypes = "application/json"
	jsonClientConfig.ContentConfig.ContentType = "application/json"

	ossclient, err := openshiftsecurityclientset.NewForConfig(jsonClientConfig)
	if err != nil {
		return nil, errors.Wrap(err, "creating openshift security client")
	}

	osrclient, err := openshiftrouteclientset.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "creating openshift route client")
	}

	aggclient, err := aggregatorclient.NewForConfig(cfg)
	if err != nil {
		return nil, errors.Wrap(err, "creating kubernetes aggregator")
	}

	return &Client{
		version:           version,
		namespace:         namespace,
		namespaceSelector: namespaceSelector,
		kclient:           kclient,
		oscclient:         oscclient,
		ossclient:         ossclient,
		osrclient:         osrclient,
		mclient:           mclient,
		eclient:           eclient,
		aggclient:         aggclient,
	}, nil
}

func (c *Client) KubernetesInterface() kubernetes.Interface {
	return c.kclient
}

func (c *Client) Namespace() string {
	return c.namespace
}

// ConfigMapListWatch returns a new ListWatch on the ConfigMap resource.
func (c *Client) ConfigMapListWatch() *cache.ListWatch {
	return c.ConfigMapListWatchForNamespace(c.namespace)
}

func (c *Client) ConfigMapListWatchForNamespace(ns string) *cache.ListWatch {
	return cache.NewListWatchFromClient(c.kclient.CoreV1().RESTClient(), "configmaps", ns, fields.Everything())
}

func (c *Client) SecretListWatchForNamespace(ns string) *cache.ListWatch {
	return cache.NewListWatchFromClient(c.kclient.CoreV1().RESTClient(), "secrets", ns, fields.Everything())
}

func (c *Client) WaitForPrometheusOperatorCRDsReady() error {
	return wait.Poll(time.Second, time.Minute*5, func() (bool, error) {
		err := c.WaitForCRDReady(k8sutil.NewCustomResourceDefinition(monv1.DefaultCrdKinds.Prometheus, mon.GroupName, map[string]string{}, false))
		if err != nil {
			return false, err
		}

		err = c.WaitForCRDReady(k8sutil.NewCustomResourceDefinition(monv1.DefaultCrdKinds.Alertmanager, mon.GroupName, map[string]string{}, false))
		if err != nil {
			return false, err
		}

		err = c.WaitForCRDReady(k8sutil.NewCustomResourceDefinition(monv1.DefaultCrdKinds.ServiceMonitor, mon.GroupName, map[string]string{}, false))
		if err != nil {
			return false, err
		}

		_, err = c.mclient.MonitoringV1().Prometheuses(c.namespace).List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		_, err = c.mclient.MonitoringV1().Alertmanagers(c.namespace).List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		_, err = c.mclient.MonitoringV1().ServiceMonitors(c.namespace).List(metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		return true, nil
	})
}

func (c *Client) CreateOrUpdateSecurityContextConstraints(s *secv1.SecurityContextConstraints) error {
	sccclient := c.ossclient.SecurityV1().SecurityContextConstraints()
	existing, err := sccclient.Get(s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sccclient.Create(s)
		return errors.Wrap(err, "creating SecurityContextConstraints object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving SecurityContextConstraints object failed")
	}

	// the CRD version of SCC appears to require this.  We can try to chase why later.
	required := s.DeepCopy()
	required.ResourceVersion = existing.ResourceVersion

	_, err = sccclient.Update(required)
	return errors.Wrap(err, "updating SecurityContextConstraints object failed")
}

func (c *Client) CreateRouteIfNotExists(r *routev1.Route) error {
	rclient := c.osrclient.RouteV1().Routes(r.GetNamespace())
	_, err := rclient.Get(r.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := rclient.Create(r)
		return errors.Wrap(err, "creating Route object failed")
	}
	return nil
}

func (c *Client) GetRouteURL(r *routev1.Route) (*url.URL, error) {
	rclient := c.osrclient.RouteV1().Routes(r.GetNamespace())
	newRoute, err := rclient.Get(r.GetName(), metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "getting Route object failed")
	}
	u := &url.URL{
		Scheme: "http",
		Host:   newRoute.Spec.Host,
		Path:   newRoute.Spec.Path,
	}

	if newRoute.Spec.TLS != nil && newRoute.Spec.TLS.Termination != "" {
		u.Scheme = "https"
	}

	return u, nil
}

func (c *Client) GetClusterVersion(name string) (*configv1.ClusterVersion, error) {
	return c.oscclient.ConfigV1().ClusterVersions().Get(name, metav1.GetOptions{})
}

func (c *Client) GetProxy(name string) (*configv1.Proxy, error) {
	return c.oscclient.ConfigV1().Proxies().Get(name, metav1.GetOptions{})
}

func (c *Client) GetConfigmap(namespace, name string) (*v1.ConfigMap, error) {
	return c.kclient.CoreV1().ConfigMaps(namespace).Get(name, metav1.GetOptions{})
}

func (c *Client) GetSecret(namespace, name string) (*v1.Secret, error) {
	return c.kclient.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
}

func (c *Client) NamespacesToMonitor() ([]string, error) {
	namespaces, err := c.kclient.CoreV1().Namespaces().List(metav1.ListOptions{
		LabelSelector: c.namespaceSelector,
	})
	if err != nil {
		return nil, errors.Wrap(err, "listing namespaces failed")
	}

	namespaceNames := make([]string, len(namespaces.Items))
	for i, namespace := range namespaces.Items {
		namespaceNames[i] = namespace.Name
	}

	return namespaceNames, nil
}

func (c *Client) CreateOrUpdatePrometheus(p *monv1.Prometheus) error {
	pclient := c.mclient.MonitoringV1().Prometheuses(p.GetNamespace())
	oldProm, err := pclient.Get(p.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := pclient.Create(p)
		return errors.Wrap(err, "creating Prometheus object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Prometheus object failed")
	}

	p.ResourceVersion = oldProm.ResourceVersion
	if p.Spec.Storage != nil {
		p.Spec.Storage.VolumeClaimTemplate.CreationTimestamp = metav1.Unix(0, 0)
	}
	_, err = pclient.Update(p)
	return errors.Wrap(err, "updating Prometheus object failed")
}

func (c *Client) CreateOrUpdatePrometheusRule(p *monv1.PrometheusRule) error {
	pclient := c.mclient.MonitoringV1().PrometheusRules(p.GetNamespace())
	oldRule, err := pclient.Get(p.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := pclient.Create(p)
		return errors.Wrap(err, "creating PrometheusRule object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving PrometheusRule object failed")
	}

	p.ResourceVersion = oldRule.ResourceVersion

	_, err = pclient.Update(p)
	return errors.Wrap(err, "updating PrometheusRule object failed")
}

func (c *Client) CreateOrUpdateAlertmanager(a *monv1.Alertmanager) error {
	aclient := c.mclient.MonitoringV1().Alertmanagers(a.GetNamespace())
	oldAm, err := aclient.Get(a.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := aclient.Create(a)
		return errors.Wrap(err, "creating Alertmanager object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Alertmanager object failed")
	}

	a.ResourceVersion = oldAm.ResourceVersion
	if a.Spec.Storage != nil {
		a.Spec.Storage.VolumeClaimTemplate.CreationTimestamp = metav1.Unix(0, 0)
	}

	_, err = aclient.Update(a)
	return errors.Wrap(err, "updating Alertmanager object failed")
}

func (c *Client) DeleteConfigMap(cm *v1.ConfigMap) error {
	err := c.kclient.CoreV1().ConfigMaps(cm.GetNamespace()).Delete(cm.GetName(), &metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteDeployment(d *appsv1.Deployment) error {
	p := metav1.DeletePropagationForeground
	err := c.kclient.AppsV1beta2().Deployments(d.GetNamespace()).Delete(d.GetName(), &metav1.DeleteOptions{PropagationPolicy: &p})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeletePrometheus(p *monv1.Prometheus) error {
	pclient := c.mclient.MonitoringV1().Prometheuses(p.GetNamespace())

	err := pclient.Delete(p.GetName(), nil)
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "deleting Prometheus object failed")
	}

	var lastErr error
	if err := wait.Poll(time.Second*10, time.Minute*10, func() (bool, error) {
		pods, err := c.KubernetesInterface().CoreV1().Pods(p.GetNamespace()).List(prometheusoperator.ListOptions(p.GetName()))
		if err != nil {
			return false, errors.Wrap(err, "retrieving pods during polling failed")
		}

		klog.V(6).Infof("waiting for %d Pods to be deleted", len(pods.Items))
		klog.V(6).Infof("done waiting? %t", len(pods.Items) == 0)

		lastErr = fmt.Errorf("waiting for %d Pods to be deleted", len(pods.Items))
		return len(pods.Items) == 0, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrap(err, "waiting for Prometheus Pods to be gone failed")
	}

	return nil
}

func (c *Client) DeleteDaemonSet(d *v1beta1.DaemonSet) error {
	orphanDependents := false
	err := c.kclient.AppsV1beta2().DaemonSets(d.GetNamespace()).Delete(d.GetName(), &metav1.DeleteOptions{OrphanDependents: &orphanDependents})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteServiceMonitor(sm *monv1.ServiceMonitor) error {
	sclient := c.mclient.MonitoringV1().ServiceMonitors(sm.Namespace)

	err := sclient.Delete(sm.GetName(), nil)
	// if the object does not exist then everything is good here
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "deleting ServiceMonitor object failed")
	}

	return nil
}

func (c *Client) DeleteServiceAccount(sa *v1.ServiceAccount) error {
	err := c.kclient.CoreV1().ServiceAccounts(sa.Namespace).Delete(sa.GetName(), &metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteClusterRole(cr *rbacv1.ClusterRole) error {
	err := c.kclient.RbacV1().ClusterRoles().Delete(cr.GetName(), &metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteClusterRoleBinding(crb *rbacv1.ClusterRoleBinding) error {
	err := c.kclient.RbacV1().ClusterRoleBindings().Delete(crb.GetName(), &metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteService(svc *v1.Service) error {
	err := c.kclient.CoreV1().Services(svc.Namespace).Delete(svc.GetName(), &metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteSecret(s *v1.Secret) error {
	err := c.kclient.CoreV1().Secrets(s.Namespace).Delete(s.GetName(), &metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) WaitForPrometheus(p *monv1.Prometheus) error {
	var lastErr error
	if err := wait.Poll(time.Second*10, time.Minute*5, func() (bool, error) {
		p, err := c.mclient.MonitoringV1().Prometheuses(p.GetNamespace()).Get(p.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, errors.Wrap(err, "retrieving Prometheus object failed")
		}
		status, _, err := prometheusoperator.PrometheusStatus(c.kclient.(*kubernetes.Clientset), p)
		if err != nil {
			return false, errors.Wrap(err, "retrieving Prometheus status failed")
		}

		expectedReplicas := *p.Spec.Replicas
		if status.UpdatedReplicas == expectedReplicas && status.AvailableReplicas >= expectedReplicas {
			return true, nil
		}
		lastErr = fmt.Errorf("expected %d replicas, updated %d and available %d", expectedReplicas, status.UpdatedReplicas, status.AvailableReplicas)
		return false, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrap(err, "waiting for Prometheus")
	}
	return nil
}

func (c *Client) WaitForAlertmanager(a *monv1.Alertmanager) error {
	var lastErr error
	if err := wait.Poll(time.Second*10, time.Minute*5, func() (bool, error) {
		a, err := c.mclient.MonitoringV1().Alertmanagers(a.GetNamespace()).Get(a.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, errors.Wrap(err, "retrieving Alertmanager object failed")
		}
		status, _, err := alertmanager.AlertmanagerStatus(c.kclient.(*kubernetes.Clientset), a)
		if err != nil {
			return false, errors.Wrap(err, "retrieving Alertmanager status failed")
		}

		expectedReplicas := *a.Spec.Replicas
		if status.UpdatedReplicas == expectedReplicas && status.AvailableReplicas >= expectedReplicas {
			return true, nil
		}
		lastErr = fmt.Errorf("expected %d replicas, updated %d and available %d", expectedReplicas, status.UpdatedReplicas, status.AvailableReplicas)
		return false, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrap(err, "waiting for Alertmanager")
	}
	return nil
}

func (c *Client) CreateOrUpdateDeployment(dep *appsv1.Deployment) error {
	d, err := c.kclient.AppsV1beta2().Deployments(dep.GetNamespace()).Get(dep.GetName(), metav1.GetOptions{})

	if apierrors.IsNotFound(err) {
		err = c.CreateDeployment(dep)
		return errors.Wrap(err, "creating deployment object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving deployment object failed")
	}
	if reflect.DeepEqual(dep.Spec, d.Spec) {
		// Nothing to do, as the currently existing Telemeter client
		// deployment is equivalent to the one that would be applied.
		return nil
	}

	err = c.UpdateDeployment(dep)
	return errors.Wrap(err, "updating deployment object failed")
}

func (c *Client) CreateDeployment(dep *appsv1.Deployment) error {
	d, err := c.kclient.AppsV1beta2().Deployments(dep.GetNamespace()).Create(dep)
	if err != nil {
		return err
	}

	return c.WaitForDeploymentRollout(d)
}

func (c *Client) UpdateDeployment(dep *appsv1.Deployment) error {
	updated, err := c.kclient.AppsV1beta2().Deployments(dep.GetNamespace()).Update(dep)
	if err != nil {
		return err
	}

	return c.WaitForDeploymentRollout(updated)
}

func (c *Client) WaitForDeploymentRollout(dep *appsv1.Deployment) error {
	var lastErr error
	if err := wait.Poll(time.Second, deploymentCreateTimeout, func() (bool, error) {
		d, err := c.kclient.AppsV1beta2().Deployments(dep.GetNamespace()).Get(dep.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if d.Generation <= d.Status.ObservedGeneration && d.Status.UpdatedReplicas == d.Status.Replicas && d.Status.UnavailableReplicas == 0 {
			return true, nil
		}
		lastErr = fmt.Errorf("deployment %s is not ready. status: (replicas: %d, updated: %d, ready: %d, unavailable: %d)",
			d.Name, d.Status.Replicas, d.Status.UpdatedReplicas, d.Status.ReadyReplicas, d.Status.UnavailableReplicas)
		return false, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for DeploymentRollout of %s", dep.GetName())
	}
	return nil
}

func (c *Client) WaitForStatefulsetRollout(sts *appsv1.StatefulSet) error {
	var lastErr error
	if err := wait.Poll(time.Second, deploymentCreateTimeout, func() (bool, error) {
		d, err := c.kclient.AppsV1beta2().StatefulSets(sts.GetNamespace()).Get(sts.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if d.Generation <= d.Status.ObservedGeneration && d.Status.UpdatedReplicas == d.Status.Replicas && d.Status.ReadyReplicas == d.Status.Replicas {
			return true, nil
		}
		lastErr = fmt.Errorf("statefulset %s is not ready. status: (replicas: %d, updated: %d, ready: %d)",
			d.Name, d.Status.Replicas, d.Status.UpdatedReplicas, d.Status.ReadyReplicas)
		return false, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for StatefulsetRollout of %s", sts.GetName())
	}
	return nil
}

func (c *Client) WaitForRouteReady(r *routev1.Route) (string, error) {
	host := ""
	var lastErr error
	if err := wait.Poll(time.Second, deploymentCreateTimeout, func() (bool, error) {
		newRoute, err := c.osrclient.RouteV1().Routes(r.GetNamespace()).Get(r.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if len(newRoute.Status.Ingress) == 0 {
			lastErr = fmt.Errorf("no status available for %s", newRoute.GetName())
			return false, nil
		}
		for _, c := range newRoute.Status.Ingress[0].Conditions {
			if c.Type == "Admitted" && c.Status == "True" {
				host = newRoute.Spec.Host
				return true, nil
			}
		}
		lastErr = fmt.Errorf("route %s is not yet Admitted", newRoute.GetName())
		return false, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return host, errors.Wrapf(err, "waiting for RouteReady of %s", r.GetName())
	}
	return host, nil
}

func (c *Client) CreateOrUpdateDaemonSet(ds *appsv1.DaemonSet) error {
	_, err := c.kclient.AppsV1beta2().DaemonSets(ds.GetNamespace()).Get(ds.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		err = c.CreateDaemonSet(ds)
		return errors.Wrap(err, "creating DaemonSet object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving DaemonSet object failed")
	}

	err = c.UpdateDaemonSet(ds)
	return errors.Wrap(err, "updating DaemonSet object failed")
}

func (c *Client) CreateDaemonSet(ds *appsv1.DaemonSet) error {
	d, err := c.kclient.AppsV1beta2().DaemonSets(ds.GetNamespace()).Create(ds)
	if err != nil {
		return err
	}

	return c.WaitForDaemonSetRollout(d)
}

func (c *Client) UpdateDaemonSet(ds *appsv1.DaemonSet) error {
	updated, err := c.kclient.AppsV1beta2().DaemonSets(ds.GetNamespace()).Update(ds)
	if err != nil {
		return err
	}

	return c.WaitForDaemonSetRollout(updated)
}

func (c *Client) WaitForDaemonSetRollout(ds *appsv1.DaemonSet) error {
	var lastErr error
	if err := wait.Poll(time.Second, deploymentCreateTimeout, func() (bool, error) {
		d, err := c.kclient.AppsV1beta2().DaemonSets(ds.GetNamespace()).Get(ds.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if d.Generation <= d.Status.ObservedGeneration && d.Status.UpdatedNumberScheduled == d.Status.DesiredNumberScheduled && d.Status.NumberUnavailable == 0 {
			return true, nil
		}
		lastErr = fmt.Errorf("daemonset %s is not ready. status: (desired: %d, updated: %d, ready: %d, unavailable: %d)",
			d.Name, d.Status.DesiredNumberScheduled, d.Status.UpdatedNumberScheduled, d.Status.NumberReady, d.Status.NumberAvailable)
		return false, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for DaemonSetRollout of %s", ds.GetName())
	}
	return nil
}

func (c *Client) CreateOrUpdateSecret(s *v1.Secret) error {
	sClient := c.kclient.CoreV1().Secrets(s.GetNamespace())
	_, err := sClient.Get(s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sClient.Create(s)
		return errors.Wrap(err, "creating Secret object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Secret object failed")
	}

	_, err = sClient.Update(s)
	return errors.Wrap(err, "updating Secret object failed")
}

func (c *Client) CreateIfNotExistSecret(s *v1.Secret) error {
	sClient := c.kclient.CoreV1().Secrets(s.GetNamespace())
	_, err := sClient.Get(s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sClient.Create(s)
		return errors.Wrap(err, "creating Secret object failed")
	}

	return errors.Wrap(err, "retrieving Secret object failed")
}

func (c *Client) CreateOrUpdateConfigMapList(cml *v1.ConfigMapList) error {
	for _, cm := range cml.Items {
		err := c.CreateOrUpdateConfigMap(&cm)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) CreateOrUpdateConfigMap(cm *v1.ConfigMap) error {
	cmClient := c.kclient.CoreV1().ConfigMaps(cm.GetNamespace())
	_, err := cmClient.Get(cm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := cmClient.Create(cm)
		return errors.Wrap(err, "creating ConfigMap object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ConfigMap object failed")
	}

	_, err = cmClient.Update(cm)
	return errors.Wrap(err, "updating ConfigMap object failed")
}

func (c *Client) CreateOrUpdateNamespace(n *v1.Namespace) error {
	nClient := c.kclient.CoreV1().Namespaces()
	_, err := nClient.Get(n.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := nClient.Create(n)
		return errors.Wrap(err, "creating Namespace object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Namespace object failed")
	}

	_, err = nClient.Update(n)
	return errors.Wrap(err, "updating ConfigMap object failed")
}

func (c *Client) DeleteIfExists(nsName string) error {
	nClient := c.kclient.CoreV1().Namespaces()
	_, err := nClient.Get(nsName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Namespace already deleted
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Namespace object failed")
	}

	err = nClient.Delete(nsName, &metav1.DeleteOptions{})
	return errors.Wrap(err, "deleting ConfigMap object failed")
}

func (c *Client) CreateIfNotExistConfigMap(cm *v1.ConfigMap) (*v1.ConfigMap, error) {
	cClient := c.kclient.CoreV1().ConfigMaps(cm.GetNamespace())
	res, err := cClient.Get(cm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		res, err := cClient.Create(cm)
		if err != nil {
			return nil, errors.Wrap(err, "creating ConfigMap object failed")
		}
		return res, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "retrieving ConfigMap object failed")
	}
	return res, nil
}

func (c *Client) CreateOrUpdateService(svc *v1.Service) error {
	sclient := c.kclient.CoreV1().Services(svc.GetNamespace())
	s, err := sclient.Get(svc.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = sclient.Create(svc)
		return errors.Wrap(err, "creating Service object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Service object failed")
	}

	svc.ResourceVersion = s.ResourceVersion
	if svc.Spec.Type == v1.ServiceTypeClusterIP {
		svc.Spec.ClusterIP = s.Spec.ClusterIP
	}

	if reflect.DeepEqual(svc.Spec, s.Spec) && reflect.DeepEqual(svc.Annotations, s.Annotations) && reflect.DeepEqual(svc.Labels, s.Labels) {
		return nil
	}

	_, err = sclient.Update(svc)
	return errors.Wrap(err, "updating Service object failed")
}

func (c *Client) CreateOrUpdateEndpoints(endpoints *v1.Endpoints) error {
	eclient := c.kclient.CoreV1().Endpoints(endpoints.GetNamespace())
	e, err := eclient.Get(endpoints.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = eclient.Create(endpoints)
		return errors.Wrap(err, "creating Endpoints object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Endpoints object failed")
	}

	endpoints.ResourceVersion = e.ResourceVersion
	_, err = eclient.Update(endpoints)
	return errors.Wrap(err, "updating Endpoints object failed")
}

func (c *Client) CreateOrUpdateRoleBinding(rb *rbacv1.RoleBinding) error {
	rbClient := c.kclient.RbacV1().RoleBindings(rb.GetNamespace())
	r, err := rbClient.Get(rb.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := rbClient.Create(rb)
		return errors.Wrap(err, "creating RoleBinding object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving RoleBinding object failed")
	}

	if reflect.DeepEqual(rb.RoleRef, r.RoleRef) &&
		reflect.DeepEqual(rb.Subjects, r.Subjects) &&
		reflect.DeepEqual(rb.Labels, r.Labels) &&
		reflect.DeepEqual(rb.Annotations, r.Annotations) {
		return nil
	}

	_, err = rbClient.Update(rb)
	return errors.Wrap(err, "updating RoleBinding object failed")
}

func (c *Client) CreateOrUpdateRole(r *rbacv1.Role) error {
	rClient := c.kclient.RbacV1().Roles(r.GetNamespace())
	_, err := rClient.Get(r.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := rClient.Create(r)
		return errors.Wrap(err, "creating Role object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Role object failed")
	}

	_, err = rClient.Update(r)
	return errors.Wrap(err, "updating Role object failed")
}

func (c *Client) CreateOrUpdateClusterRole(cr *rbacv1.ClusterRole) error {
	crClient := c.kclient.RbacV1().ClusterRoles()
	_, err := crClient.Get(cr.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := crClient.Create(cr)
		return errors.Wrap(err, "creating ClusterRole object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ClusterRole object failed")
	}

	_, err = crClient.Update(cr)
	return errors.Wrap(err, "updating ClusterRole object failed")
}

func (c *Client) CreateOrUpdateClusterRoleBinding(crb *rbacv1.ClusterRoleBinding) error {
	crbClient := c.kclient.RbacV1().ClusterRoleBindings()
	_, err := crbClient.Get(crb.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := crbClient.Create(crb)
		return errors.Wrap(err, "creating ClusterRoleBinding object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ClusterRoleBinding object failed")
	}

	_, err = crbClient.Update(crb)
	return errors.Wrap(err, "updating ClusterRoleBinding object failed")
}

func (c *Client) CreateOrUpdateServiceAccount(sa *v1.ServiceAccount) error {
	sClient := c.kclient.CoreV1().ServiceAccounts(sa.GetNamespace())
	_, err := sClient.Get(sa.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sClient.Create(sa)
		return errors.Wrap(err, "creating ServiceAccount object failed")
	}
	return errors.Wrap(err, "retrieving ServiceAccount object failed")

	// TODO(brancz): Use Patch instead of Update
	//
	// ServiceAccounts get a new secret generated whenever they are updated, even
	// if nothing has changed. This is likely due to "Update" performing a PUT
	// call signifying, that this may be a new ServiceAccount, therefore a new
	// token is needed. The expectation is that Patch does not cause this,
	// however, currently there has been no need to update ServiceAccounts,
	// therefore we are skipping this effort for now until we actually need to
	// change the ServiceAccount.
	//
	//if err != nil {
	//	return errors.Wrap(err, "retrieving ServiceAccount object failed")
	//}
	//
	//_, err = sClient.Update(sa)
	//return errors.Wrap(err, "updating ServiceAccount object failed")
}

func (c *Client) CreateOrUpdateServiceMonitor(sm *monv1.ServiceMonitor) error {
	smClient := c.mclient.MonitoringV1().ServiceMonitors(sm.GetNamespace())
	oldSm, err := smClient.Get(sm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := smClient.Create(sm)
		return errors.Wrap(err, "creating ServiceMonitor object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ServiceMonitor object failed")
	}

	sm.ResourceVersion = oldSm.ResourceVersion
	_, err = smClient.Update(sm)
	return errors.Wrap(err, "updating ServiceMonitor object failed")
}

func (c *Client) CreateOrUpdateIngress(ing *v1betaextensions.Ingress) error {
	ic := c.kclient.ExtensionsV1beta1().Ingresses(ing.GetNamespace())
	_, err := ic.Get(ing.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = ic.Create(ing)
		return errors.Wrap(err, "creating Ingress object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Ingress object failed")
	}

	_, err = ic.Update(ing)
	return errors.Wrap(err, "updating Ingress object failed")
}

func (c *Client) CreateOrUpdateAPIService(apiService *apiregistrationv1beta1.APIService) error {
	apsc := c.aggclient.ApiregistrationV1beta1().APIServices()
	oldAPIService, err := apsc.Get(apiService.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = apsc.Create(apiService)
		return errors.Wrap(err, "creating APIService object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving APIService object failed")
	}

	apiService.ResourceVersion = oldAPIService.ResourceVersion
	if len(oldAPIService.Spec.CABundle) > 0 {
		apiService.Spec.CABundle = oldAPIService.Spec.CABundle
	}
	_, err = apsc.Update(apiService)
	return errors.Wrap(err, "updating APIService object failed")

}

func (c *Client) WaitForCRDReady(crd *extensionsobj.CustomResourceDefinition) error {
	return wait.Poll(5*time.Second, 5*time.Minute, func() (bool, error) {
		return c.CRDReady(crd)
	})
}

func (c *Client) CRDReady(crd *extensionsobj.CustomResourceDefinition) (bool, error) {
	crdClient := c.eclient.ApiextensionsV1beta1().CustomResourceDefinitions()

	crdEst, err := crdClient.Get(crd.ObjectMeta.Name, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	for _, cond := range crdEst.Status.Conditions {
		switch cond.Type {
		case extensionsobj.Established:
			if cond.Status == extensionsobj.ConditionTrue {
				return true, err
			}
		case extensionsobj.NamesAccepted:
			if cond.Status == extensionsobj.ConditionFalse {
				return false, fmt.Errorf("CRD naming conflict (%s): %v", crd.ObjectMeta.Name, cond.Reason)
			}
		}
	}
	return false, err
}

func (c *Client) StatusReporter() *StatusReporter {
	return NewStatusReporter(c.oscclient.Config().ClusterOperators(), "monitoring", c.namespace, c.version)
}
