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
	"context"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/imdario/mergo"
	"github.com/pkg/errors"

	configv1 "github.com/openshift/api/config/v1"
	routev1 "github.com/openshift/api/route/v1"
	secv1 "github.com/openshift/api/security/v1"
	openshiftconfigclientset "github.com/openshift/client-go/config/clientset/versioned"
	openshiftrouteclientset "github.com/openshift/client-go/route/clientset/versioned"
	openshiftsecurityclientset "github.com/openshift/client-go/security/clientset/versioned"
	"github.com/prometheus-operator/prometheus-operator/pkg/alertmanager"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	monitoring "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned"
	prometheusoperator "github.com/prometheus-operator/prometheus-operator/pkg/prometheus"
	"github.com/prometheus-operator/prometheus-operator/pkg/thanos"
	thanosoperator "github.com/prometheus-operator/prometheus-operator/pkg/thanos"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	extensionsobj "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

const (
	deploymentCreateTimeout = 5 * time.Minute
	metadataPrefix          = "monitoring.openshift.io/"
)

type Client struct {
	version               string
	namespace             string
	userWorkloadNamespace string
	kclient               kubernetes.Interface
	oscclient             openshiftconfigclientset.Interface
	ossclient             openshiftsecurityclientset.Interface
	osrclient             openshiftrouteclientset.Interface
	mclient               monitoring.Interface
	eclient               apiextensionsclient.Interface
	aggclient             aggregatorclient.Interface
}

func New(cfg *rest.Config, version string, namespace, userWorkloadNamespace string) (*Client, error) {
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
		version:               version,
		namespace:             namespace,
		userWorkloadNamespace: userWorkloadNamespace,
		kclient:               kclient,
		oscclient:             oscclient,
		ossclient:             ossclient,
		osrclient:             osrclient,
		mclient:               mclient,
		eclient:               eclient,
		aggclient:             aggclient,
	}, nil
}

func (c *Client) KubernetesInterface() kubernetes.Interface {
	return c.kclient
}

func (c *Client) Namespace() string {
	return c.namespace
}

func (c *Client) UserWorkloadNamespace() string {
	return c.userWorkloadNamespace
}

func (c *Client) ConfigMapListWatchForNamespace(ns string) *cache.ListWatch {
	return cache.NewListWatchFromClient(c.kclient.CoreV1().RESTClient(), "configmaps", ns, fields.Everything())
}

func (c *Client) SecretListWatchForNamespace(ns string) *cache.ListWatch {
	return cache.NewListWatchFromClient(c.kclient.CoreV1().RESTClient(), "secrets", ns, fields.Everything())
}

func (c *Client) InfrastructureListWatchForResource(ctx context.Context, resource string) *cache.ListWatch {
	infrastructure := c.oscclient.ConfigV1().Infrastructures()

	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return infrastructure.List(
				ctx,
				metav1.ListOptions{
					FieldSelector: fields.OneTermEqualSelector("metadata.name", resource).String(),
				},
			)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return infrastructure.Watch(
				ctx,
				metav1.ListOptions{
					FieldSelector: fields.OneTermEqualSelector("metadata.name", resource).String(),
				},
			)
		},
	}
}

func (c *Client) AssurePrometheusOperatorCRsExist() error {
	return wait.Poll(time.Second, time.Minute*5, func() (bool, error) {
		_, err := c.mclient.MonitoringV1().Prometheuses(c.namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		_, err = c.mclient.MonitoringV1().Alertmanagers(c.namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		_, err = c.mclient.MonitoringV1().ServiceMonitors(c.namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return false, err
		}

		return true, nil
	})
}

func (c *Client) CreateOrUpdateValidatingWebhookConfiguration(w *admissionv1.ValidatingWebhookConfiguration) error {
	admclient := c.kclient.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	existing, err := admclient.Get(context.TODO(), w.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := admclient.Create(context.TODO(), w, metav1.CreateOptions{})
		return errors.Wrap(err, "creating ValidatingWebhookConfiguration object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ValidatingWebhookConfiguration object failed")
	}

	required := w.DeepCopy()
	required.ResourceVersion = existing.ResourceVersion
	_, err = admclient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating ValidatingWebhookConfiguration object failed")
}

func (c *Client) CreateOrUpdateSecurityContextConstraints(s *secv1.SecurityContextConstraints) error {
	sccclient := c.ossclient.SecurityV1().SecurityContextConstraints()
	existing, err := sccclient.Get(context.TODO(), s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sccclient.Create(context.TODO(), s, metav1.CreateOptions{})
		return errors.Wrap(err, "creating SecurityContextConstraints object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving SecurityContextConstraints object failed")
	}

	// the CRD version of SCC appears to require this.  We can try to chase why later.
	required := s.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	required.ResourceVersion = existing.ResourceVersion

	_, err = sccclient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating SecurityContextConstraints object failed")
}

func (c *Client) CreateRouteIfNotExists(r *routev1.Route) error {
	rclient := c.osrclient.RouteV1().Routes(r.GetNamespace())
	_, err := rclient.Get(context.TODO(), r.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := rclient.Create(context.TODO(), r, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Route object failed")
	}
	return nil
}

func (c *Client) GetRouteURL(r *routev1.Route) (*url.URL, error) {
	rclient := c.osrclient.RouteV1().Routes(r.GetNamespace())
	newRoute, err := rclient.Get(context.TODO(), r.GetName(), metav1.GetOptions{})
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
	return c.oscclient.ConfigV1().ClusterVersions().Get(context.TODO(), name, metav1.GetOptions{})
}

func (c *Client) GetProxy(name string) (*configv1.Proxy, error) {
	return c.oscclient.ConfigV1().Proxies().Get(context.TODO(), name, metav1.GetOptions{})
}

func (c *Client) GetInfrastructure(name string) (*configv1.Infrastructure, error) {
	return c.oscclient.ConfigV1().Infrastructures().Get(context.TODO(), name, metav1.GetOptions{})
}

func (c *Client) GetConfigmap(namespace, name string) (*v1.ConfigMap, error) {
	return c.kclient.CoreV1().ConfigMaps(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

func (c *Client) GetSecret(namespace, name string) (*v1.Secret, error) {
	return c.kclient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
}

func (c *Client) CreateOrUpdatePrometheus(p *monv1.Prometheus) error {
	pclient := c.mclient.MonitoringV1().Prometheuses(p.GetNamespace())
	existing, err := pclient.Get(context.TODO(), p.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := pclient.Create(context.TODO(), p, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Prometheus object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Prometheus object failed")
	}

	required := p.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion
	_, err = pclient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Prometheus object failed")
}

func (c *Client) CreateOrUpdatePrometheusRule(p *monv1.PrometheusRule) error {
	pclient := c.mclient.MonitoringV1().PrometheusRules(p.GetNamespace())
	existing, err := pclient.Get(context.TODO(), p.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := pclient.Create(context.TODO(), p, metav1.CreateOptions{})
		return errors.Wrap(err, "creating PrometheusRule object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving PrometheusRule object failed")
	}

	required := p.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion

	_, err = pclient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating PrometheusRule object failed")
}

func (c *Client) CreateOrUpdateAlertmanager(a *monv1.Alertmanager) error {
	aclient := c.mclient.MonitoringV1().Alertmanagers(a.GetNamespace())
	existing, err := aclient.Get(context.TODO(), a.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := aclient.Create(context.TODO(), a, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Alertmanager object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Alertmanager object failed")
	}

	required := a.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion

	_, err = aclient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Alertmanager object failed")
}

func (c *Client) CreateOrUpdateThanosRuler(t *monv1.ThanosRuler) error {
	trclient := c.mclient.MonitoringV1().ThanosRulers(t.GetNamespace())
	existing, err := trclient.Get(context.TODO(), t.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := trclient.Create(context.TODO(), t, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Thanos Ruler object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Thanos Ruler object failed")
	}

	required := t.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	required.ResourceVersion = existing.ResourceVersion

	_, err = trclient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Thanos Ruler object failed")
}

func (c *Client) DeleteConfigMap(cm *v1.ConfigMap) error {
	err := c.kclient.CoreV1().ConfigMaps(cm.GetNamespace()).Delete(context.TODO(), cm.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

// DeleteHashedConfigMap deletes all configmaps in the given namespace which have
// the specified prefix, and DO NOT have the given hash.
func (c *Client) DeleteHashedConfigMap(namespace, prefix, newHash string) error {
	ls := "monitoring.openshift.io/name=" + prefix + ",monitoring.openshift.io/hash!=" + newHash
	configMaps, err := c.KubernetesInterface().CoreV1().ConfigMaps(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: ls,
	})
	if err != nil {
		return errors.Wrapf(err, "error listing configmaps in namespace %s with label selector %s", namespace, ls)
	}

	for _, cm := range configMaps.Items {
		err := c.KubernetesInterface().CoreV1().ConfigMaps(namespace).Delete(context.TODO(), cm.Name, metav1.DeleteOptions{})
		if err != nil {
			return errors.Wrapf(err, "error deleting configmap: %s/%s", namespace, cm.Name)
		}
	}

	return nil
}

// DeleteHashedSecret deletes all secrets in the given namespace which have
// the specified prefix, and DO NOT have the given hash.
func (c *Client) DeleteHashedSecret(namespace, prefix, newHash string) error {
	ls := "monitoring.openshift.io/name=" + prefix + ",monitoring.openshift.io/hash!=" + newHash
	secrets, err := c.KubernetesInterface().CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: ls,
	})
	if err != nil {
		return errors.Wrapf(err, "error listing secrets in namespace %s with label selector %s", namespace, ls)
	}

	for _, s := range secrets.Items {
		err := c.KubernetesInterface().CoreV1().Secrets(namespace).Delete(context.TODO(), s.Name, metav1.DeleteOptions{})
		if err != nil {
			return errors.Wrapf(err, "error deleting secret: %s/%s", namespace, s.Name)
		}
	}

	return nil
}

func (c *Client) DeleteValidatingWebhook(w *admissionv1.ValidatingWebhookConfiguration) error {
	err := c.kclient.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(context.TODO(), w.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteDeployment(d *appsv1.Deployment) error {
	p := metav1.DeletePropagationForeground
	err := c.kclient.AppsV1().Deployments(d.GetNamespace()).Delete(context.TODO(), d.GetName(), metav1.DeleteOptions{PropagationPolicy: &p})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeletePodDisruptionBudget(pdb *policyv1.PodDisruptionBudget) error {
	p := metav1.DeletePropagationForeground
	err := c.kclient.PolicyV1().PodDisruptionBudgets(pdb.GetNamespace()).Delete(context.TODO(), pdb.GetName(), metav1.DeleteOptions{PropagationPolicy: &p})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeletePrometheus(p *monv1.Prometheus) error {
	pclient := c.mclient.MonitoringV1().Prometheuses(p.GetNamespace())

	err := pclient.Delete(context.TODO(), p.GetName(), metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "deleting Prometheus object failed")
	}

	var lastErr error
	if err := wait.Poll(time.Second*10, time.Minute*10, func() (bool, error) {
		pods, err := c.KubernetesInterface().CoreV1().Pods(p.GetNamespace()).List(context.TODO(), prometheusoperator.ListOptions(p.GetName()))
		if err != nil {
			return false, errors.Wrap(err, "retrieving pods during polling failed")
		}

		klog.V(6).Infof("waiting for %d Pods to be deleted", len(pods.Items))
		klog.V(6).Infof("done waiting? %t", len(pods.Items) == 0)

		lastErr = errors.Errorf("%d pods still present", len(pods.Items))
		return len(pods.Items) == 0, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for Prometheus %s/%s deletion", p.GetNamespace(), p.GetName())
	}

	return nil
}

func (c *Client) DeleteThanosRuler(tr *monv1.ThanosRuler) error {
	trclient := c.mclient.MonitoringV1().ThanosRulers(tr.GetNamespace())

	err := trclient.Delete(context.TODO(), tr.GetName(), metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "deleting Thanos Ruler object failed")
	}

	var lastErr error
	if err := wait.Poll(time.Second*10, time.Minute*10, func() (bool, error) {
		pods, err := c.KubernetesInterface().CoreV1().Pods(tr.GetNamespace()).List(context.TODO(), thanosoperator.ListOptions(tr.GetName()))
		if err != nil {
			return false, errors.Wrap(err, "retrieving pods during polling failed")
		}

		klog.V(6).Infof("waiting for %d Pods to be deleted", len(pods.Items))
		klog.V(6).Infof("done waiting? %t", len(pods.Items) == 0)

		lastErr = errors.Errorf("%d pods still present", len(pods.Items))
		return len(pods.Items) == 0, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for Thanos Ruler %s/%s deletion", tr.GetNamespace(), tr.GetName())
	}

	return nil
}

func (c *Client) DeleteDaemonSet(d *appsv1.DaemonSet) error {
	orphanDependents := false
	err := c.kclient.AppsV1().DaemonSets(d.GetNamespace()).Delete(context.TODO(), d.GetName(), metav1.DeleteOptions{OrphanDependents: &orphanDependents})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteServiceMonitor(sm *monv1.ServiceMonitor) error {
	return c.DeleteServiceMonitorByNamespaceAndName(sm.Namespace, sm.GetName())
}

func (c *Client) DeleteServiceMonitorByNamespaceAndName(namespace, name string) error {
	sclient := c.mclient.MonitoringV1().ServiceMonitors(namespace)

	err := sclient.Delete(context.TODO(), name, metav1.DeleteOptions{})
	// if the object does not exist then everything is good here
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "deleting ServiceMonitor object failed")
	}

	return nil
}

func (c *Client) DeleteServiceAccount(sa *v1.ServiceAccount) error {
	err := c.kclient.CoreV1().ServiceAccounts(sa.Namespace).Delete(context.TODO(), sa.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteClusterRole(cr *rbacv1.ClusterRole) error {
	err := c.kclient.RbacV1().ClusterRoles().Delete(context.TODO(), cr.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteClusterRoleBinding(crb *rbacv1.ClusterRoleBinding) error {
	err := c.kclient.RbacV1().ClusterRoleBindings().Delete(context.TODO(), crb.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteService(svc *v1.Service) error {
	err := c.kclient.CoreV1().Services(svc.Namespace).Delete(context.TODO(), svc.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteRoute(r *routev1.Route) error {
	err := c.osrclient.RouteV1().Routes(r.GetNamespace()).Delete(context.TODO(), r.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) DeletePrometheusRule(rule *monv1.PrometheusRule) error {
	return c.DeletePrometheusRuleByNamespaceAndName(rule.Namespace, rule.GetName())
}

func (c *Client) DeletePrometheusRuleByNamespaceAndName(namespace, name string) error {
	sclient := c.mclient.MonitoringV1().PrometheusRules(namespace)

	err := sclient.Delete(context.TODO(), name, metav1.DeleteOptions{})
	// if the object does not exist then everything is good here
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "deleting PrometheusRule object failed")
	}

	return nil
}

func (c *Client) DeleteSecret(s *v1.Secret) error {
	err := c.kclient.CoreV1().Secrets(s.Namespace).Delete(context.TODO(), s.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) WaitForPrometheus(p *monv1.Prometheus) error {
	var lastErr error
	if err := wait.Poll(time.Second*10, time.Minute*5, func() (bool, error) {
		p, err := c.mclient.MonitoringV1().Prometheuses(p.GetNamespace()).Get(context.TODO(), p.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, errors.Wrap(err, "retrieving Prometheus object failed")
		}
		status, _, err := prometheusoperator.Status(context.TODO(), c.kclient.(*kubernetes.Clientset), p)
		if err != nil {
			return false, errors.Wrap(err, "retrieving Prometheus status failed")
		}

		expectedReplicas := *p.Spec.Replicas
		if expectedReplicas != status.UpdatedReplicas {
			lastErr = errors.Errorf("expected %d replicas, got %d updated replicas",
				expectedReplicas, status.UpdatedReplicas)
			return false, nil
		}
		if status.AvailableReplicas < expectedReplicas {
			lastErr = errors.Errorf("expected %d replicas, got %d available replicas",
				expectedReplicas, status.AvailableReplicas)
			return false, nil
		}
		return true, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for Prometheus %s/%s", p.GetNamespace(), p.GetName())
	}
	return nil
}

func (c *Client) WaitForAlertmanager(a *monv1.Alertmanager) error {
	var lastErr error
	if err := wait.Poll(time.Second*10, time.Minute*5, func() (bool, error) {
		a, err := c.mclient.MonitoringV1().Alertmanagers(a.GetNamespace()).Get(context.TODO(), a.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, errors.Wrap(err, "retrieving Alertmanager object failed")
		}
		status, _, err := alertmanager.Status(context.TODO(), c.kclient.(*kubernetes.Clientset), a)
		if err != nil {
			return false, errors.Wrap(err, "retrieving Alertmanager status failed")
		}

		expectedReplicas := *a.Spec.Replicas
		if expectedReplicas != status.UpdatedReplicas {
			lastErr = errors.Errorf("expected %d replicas, got %d updated replicas",
				expectedReplicas, status.UpdatedReplicas)
			return false, nil
		}
		if status.AvailableReplicas < expectedReplicas {
			lastErr = errors.Errorf("expected %d replicas, got %d available replicas",
				expectedReplicas, status.AvailableReplicas)
			return false, nil
		}
		return true, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for Alertmanager %s/%s", a.GetNamespace(), a.GetName())
	}
	return nil
}

func (c *Client) WaitForThanosRuler(t *monv1.ThanosRuler) error {
	var lastErr error
	if err := wait.Poll(time.Second*10, time.Minute*5, func() (bool, error) {
		tr, err := c.mclient.MonitoringV1().ThanosRulers(t.GetNamespace()).Get(context.TODO(), t.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, errors.Wrap(err, "retrieving Thanos Ruler object failed")
		}
		status, _, err := thanos.RulerStatus(context.TODO(), c.kclient.(*kubernetes.Clientset), tr)
		if err != nil {
			return false, errors.Wrap(err, "retrieving Thanos Ruler status failed")
		}

		expectedReplicas := *tr.Spec.Replicas
		if expectedReplicas != status.UpdatedReplicas {
			lastErr = errors.Errorf("expected %d replicas, got %d updated replicas",
				expectedReplicas, status.UpdatedReplicas)
			return false, nil
		}
		if status.AvailableReplicas < expectedReplicas {
			lastErr = errors.Errorf("expected %d replicas, got %d available replicas",
				expectedReplicas, status.AvailableReplicas)
			return false, nil
		}
		return true, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for Thanos Ruler %s/%s", t.GetNamespace(), t.GetName())
	}
	return nil
}

func (c *Client) CreateOrUpdateDeployment(dep *appsv1.Deployment) error {
	existing, err := c.kclient.AppsV1().Deployments(dep.GetNamespace()).Get(context.TODO(), dep.GetName(), metav1.GetOptions{})

	if apierrors.IsNotFound(err) {
		err = c.CreateDeployment(dep)
		return errors.Wrap(err, "creating Deployment object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Deployment object failed")
	}
	if reflect.DeepEqual(dep.Spec, existing.Spec) {
		// Nothing to do, as the currently existing deployment is equivalent to the one that would be applied.
		return nil
	}

	required := dep.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	err = c.UpdateDeployment(required)
	if err != nil {
		uErr, ok := err.(*apierrors.StatusError)
		if ok && uErr.ErrStatus.Code == 422 && uErr.ErrStatus.Reason == metav1.StatusReasonInvalid {
			// try to delete Deployment
			err = c.DeleteDeployment(existing)
			if err != nil {
				return errors.Wrap(err, "deleting Deployment object failed")
			}
			err = c.CreateDeployment(required)
			if err != nil {
				return errors.Wrap(err, "creating Deployment object failed after update failed")
			}
		}
		return errors.Wrap(err, "updating Deployment object failed")
	}
	return nil
}

func (c *Client) CreateDeployment(dep *appsv1.Deployment) error {
	d, err := c.kclient.AppsV1().Deployments(dep.GetNamespace()).Create(context.TODO(), dep, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return c.WaitForDeploymentRollout(d)
}

func (c *Client) UpdateDeployment(dep *appsv1.Deployment) error {
	updated, err := c.kclient.AppsV1().Deployments(dep.GetNamespace()).Update(context.TODO(), dep, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return c.WaitForDeploymentRollout(updated)
}

func (c *Client) WaitForDeploymentRollout(dep *appsv1.Deployment) error {
	var lastErr error
	if err := wait.Poll(time.Second, deploymentCreateTimeout, func() (bool, error) {
		d, err := c.kclient.AppsV1().Deployments(dep.GetNamespace()).Get(context.TODO(), dep.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if d.Generation > d.Status.ObservedGeneration {
			lastErr = errors.Errorf("current generation %d, observed generation %d",
				d.Generation, d.Status.ObservedGeneration)
			return false, nil
		}
		if d.Status.UpdatedReplicas != d.Status.Replicas {
			lastErr = errors.Errorf("expected %d replicas, got %d updated replicas",
				d.Status.Replicas, d.Status.UpdatedReplicas)
			return false, nil
		}
		if d.Status.UnavailableReplicas != 0 {
			lastErr = errors.Errorf("got %d unavailable replicas",
				d.Status.UnavailableReplicas)
			return false, nil
		}
		return true, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for DeploymentRollout of %s/%s", dep.GetNamespace(), dep.GetName())
	}
	return nil
}

func (c *Client) WaitForStatefulsetRollout(sts *appsv1.StatefulSet) error {
	var lastErr error
	if err := wait.Poll(time.Second, deploymentCreateTimeout, func() (bool, error) {
		s, err := c.kclient.AppsV1().StatefulSets(sts.GetNamespace()).Get(context.TODO(), sts.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if s.Generation > s.Status.ObservedGeneration {
			lastErr = errors.Errorf("expected generation %d, observed generation: %d",
				s.Generation, s.Status.ObservedGeneration)
			return false, nil
		}
		if s.Status.UpdatedReplicas != s.Status.Replicas {
			lastErr = errors.Errorf("expected %d replicas, got %d updated replicas",
				s.Status.Replicas, s.Status.UpdatedReplicas)
			return false, nil
		}
		if s.Status.ReadyReplicas != s.Status.Replicas {
			lastErr = errors.Errorf("expected %d replicas, got %d ready replicas",
				s.Status.Replicas, s.Status.ReadyReplicas)
			return false, nil
		}
		return true, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for StatefulsetRollout of %s/%s", sts.GetNamespace(), sts.GetName())
	}
	return nil
}

func (c *Client) WaitForSecret(s *v1.Secret) (*v1.Secret, error) {
	var result *v1.Secret
	var lastErr error
	if err := wait.Poll(1*time.Second, 5*time.Minute, func() (bool, error) {
		var err error
		result, err = c.kclient.CoreV1().Secrets(s.Namespace).Get(context.TODO(), s.Name, metav1.GetOptions{})

		if apierrors.IsNotFound(err) {
			lastErr = err
			return false, nil
		}

		if err != nil {
			return false, err
		}

		for _, v := range result.Data {
			if len(v) == 0 {
				lastErr = errors.New("secret contains no data")
				return false, nil
			}
		}

		return true, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return nil, errors.Wrapf(err, "waiting for secret %s/%s", s.GetNamespace(), s.GetName())
	}

	return result, nil
}

func (c *Client) WaitForRouteReady(r *routev1.Route) (string, error) {
	host := ""
	var lastErr error
	if err := wait.Poll(time.Second, deploymentCreateTimeout, func() (bool, error) {
		newRoute, err := c.osrclient.RouteV1().Routes(r.GetNamespace()).Get(context.TODO(), r.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if len(newRoute.Status.Ingress) == 0 {
			lastErr = errors.New("no status available")
			return false, nil
		}
		for _, c := range newRoute.Status.Ingress[0].Conditions {
			if c.Type == "Admitted" && c.Status == "True" {
				host = newRoute.Spec.Host
				return true, nil
			}
		}
		lastErr = errors.New("route is not yet Admitted")
		return false, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return host, errors.Wrapf(err, "waiting for route %s/%s", r.GetNamespace(), r.GetName())
	}
	return host, nil
}

func (c *Client) CreateOrUpdateDaemonSet(ds *appsv1.DaemonSet) error {
	existing, err := c.kclient.AppsV1().DaemonSets(ds.GetNamespace()).Get(context.TODO(), ds.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		err = c.CreateDaemonSet(ds)
		return errors.Wrap(err, "creating DaemonSet object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving DaemonSet object failed")
	}

	required := ds.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	err = c.UpdateDaemonSet(required)
	if err != nil {
		uErr, ok := err.(*apierrors.StatusError)
		if ok && uErr.ErrStatus.Code == 422 && uErr.ErrStatus.Reason == metav1.StatusReasonInvalid {
			// try to delete DaemonSet
			err = c.DeleteDaemonSet(existing)
			if err != nil {
				return errors.Wrap(err, "deleting DaemonSet object failed")
			}
			err = c.CreateDaemonSet(required)
			if err != nil {
				return errors.Wrap(err, "creating DaemonSet object failed after update failed")
			}
		}
		return errors.Wrap(err, "updating DaemonSet object failed")
	}
	return nil
}

func (c *Client) CreateDaemonSet(ds *appsv1.DaemonSet) error {
	d, err := c.kclient.AppsV1().DaemonSets(ds.GetNamespace()).Create(context.TODO(), ds, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return c.WaitForDaemonSetRollout(d)
}

func (c *Client) UpdateDaemonSet(ds *appsv1.DaemonSet) error {
	updated, err := c.kclient.AppsV1().DaemonSets(ds.GetNamespace()).Update(context.TODO(), ds, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return c.WaitForDaemonSetRollout(updated)
}

func (c *Client) WaitForDaemonSetRollout(ds *appsv1.DaemonSet) error {
	var lastErr error
	if err := wait.Poll(time.Second, deploymentCreateTimeout, func() (bool, error) {
		d, err := c.kclient.AppsV1().DaemonSets(ds.GetNamespace()).Get(context.TODO(), ds.GetName(), metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if d.Generation > d.Status.ObservedGeneration {
			lastErr = errors.Errorf("current generation %d, observed generation: %d",
				d.Generation, d.Status.ObservedGeneration)
			return false, nil
		}
		if d.Status.UpdatedNumberScheduled != d.Status.DesiredNumberScheduled {
			lastErr = errors.Errorf("expected %d desired scheduled nodes, got %d updated scheduled nodes",
				d.Status.DesiredNumberScheduled, d.Status.UpdatedNumberScheduled)
			return false, nil
		}
		if d.Status.NumberUnavailable != 0 {
			lastErr = errors.Errorf("got %d unavailable nodes",
				d.Status.NumberUnavailable)
			return false, nil
		}
		return true, nil
	}); err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for DaemonSetRollout of %s/%s", ds.GetNamespace(), ds.GetName())
	}
	return nil
}

func (c *Client) CreateOrUpdateSecret(s *v1.Secret) error {
	sClient := c.kclient.CoreV1().Secrets(s.GetNamespace())
	existing, err := sClient.Get(context.TODO(), s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sClient.Create(context.TODO(), s, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Secret object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Secret object failed")
	}

	required := s.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	_, err = sClient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Secret object failed")
}

func (c *Client) CreateIfNotExistSecret(s *v1.Secret) error {
	sClient := c.kclient.CoreV1().Secrets(s.GetNamespace())
	_, err := sClient.Get(context.TODO(), s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sClient.Create(context.TODO(), s, metav1.CreateOptions{})
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
	existing, err := cmClient.Get(context.TODO(), cm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := cmClient.Create(context.TODO(), cm, metav1.CreateOptions{})
		return errors.Wrap(err, "creating ConfigMap object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ConfigMap object failed")
	}

	required := cm.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	_, err = cmClient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating ConfigMap object failed")
}

func (c *Client) DeleteIfExists(nsName string) error {
	nClient := c.kclient.CoreV1().Namespaces()
	_, err := nClient.Get(context.TODO(), nsName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Namespace already deleted
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Namespace object failed")
	}

	err = nClient.Delete(context.TODO(), nsName, metav1.DeleteOptions{})
	return errors.Wrap(err, "deleting ConfigMap object failed")
}

func (c *Client) CreateIfNotExistConfigMap(cm *v1.ConfigMap) (*v1.ConfigMap, error) {
	cClient := c.kclient.CoreV1().ConfigMaps(cm.GetNamespace())
	res, err := cClient.Get(context.TODO(), cm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		res, err := cClient.Create(context.TODO(), cm, metav1.CreateOptions{})
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

func (c *Client) CreateOrUpdatePodDisruptionBudget(pdb *policyv1.PodDisruptionBudget) error {
	pdbClient := c.kclient.PolicyV1().PodDisruptionBudgets(pdb.Namespace)
	existing, err := pdbClient.Get(context.TODO(), pdb.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := pdbClient.Create(context.TODO(), pdb, metav1.CreateOptions{})
		return errors.Wrap(err, "creating PodDisruptionBudget object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving PodDisruptionBudget object failed")
	}

	required := pdb.DeepCopy()
	required.ResourceVersion = existing.ResourceVersion

	if reflect.DeepEqual(&required.ObjectMeta, &existing.ObjectMeta) {
		return nil
	}

	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	_, err = pdbClient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating PodDisruptionBudget object failed")
}

func (c *Client) CreateOrUpdateService(svc *v1.Service) error {
	sclient := c.kclient.CoreV1().Services(svc.GetNamespace())
	existing, err := sclient.Get(context.TODO(), svc.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = sclient.Create(context.TODO(), svc, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Service object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Service object failed")
	}

	required := svc.DeepCopy()
	required.ResourceVersion = existing.ResourceVersion
	if required.Spec.Type == v1.ServiceTypeClusterIP {
		required.Spec.ClusterIP = existing.Spec.ClusterIP
	}

	if reflect.DeepEqual(required.Spec, existing.Spec) {
		return nil
	}

	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	_, err = sclient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Service object failed")
}

func (c *Client) CreateOrUpdateRoleBinding(rb *rbacv1.RoleBinding) error {
	rbClient := c.kclient.RbacV1().RoleBindings(rb.GetNamespace())
	existing, err := rbClient.Get(context.TODO(), rb.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := rbClient.Create(context.TODO(), rb, metav1.CreateOptions{})
		return errors.Wrap(err, "creating RoleBinding object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving RoleBinding object failed")
	}

	if reflect.DeepEqual(rb.RoleRef, existing.RoleRef) &&
		reflect.DeepEqual(rb.Subjects, existing.Subjects) {
		return nil
	}

	required := rb.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	_, err = rbClient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating RoleBinding object failed")
}

func (c *Client) CreateOrUpdateRole(r *rbacv1.Role) error {
	rClient := c.kclient.RbacV1().Roles(r.GetNamespace())
	existing, err := rClient.Get(context.TODO(), r.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := rClient.Create(context.TODO(), r, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Role object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Role object failed")
	}

	required := r.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	_, err = rClient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Role object failed")
}

func (c *Client) CreateOrUpdateClusterRole(cr *rbacv1.ClusterRole) error {
	crClient := c.kclient.RbacV1().ClusterRoles()
	existing, err := crClient.Get(context.TODO(), cr.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := crClient.Create(context.TODO(), cr, metav1.CreateOptions{})
		return errors.Wrap(err, "creating ClusterRole object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ClusterRole object failed")
	}

	required := cr.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	_, err = crClient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating ClusterRole object failed")
}

func (c *Client) CreateOrUpdateClusterRoleBinding(crb *rbacv1.ClusterRoleBinding) error {
	crbClient := c.kclient.RbacV1().ClusterRoleBindings()
	existing, err := crbClient.Get(context.TODO(), crb.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := crbClient.Create(context.TODO(), crb, metav1.CreateOptions{})
		return errors.Wrap(err, "creating ClusterRoleBinding object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ClusterRoleBinding object failed")
	}

	if reflect.DeepEqual(crb.RoleRef, existing.RoleRef) &&
		reflect.DeepEqual(crb.Subjects, existing.Subjects) {
		return nil
	}

	required := crb.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	err = crbClient.Delete(context.TODO(), crb.Name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrap(err, "deleting ClusterRoleBinding object failed")
	}

	_, err = crbClient.Create(context.TODO(), required, metav1.CreateOptions{})
	return errors.Wrap(err, "updating ClusterRoleBinding object failed")
}

func (c *Client) CreateOrUpdateServiceAccount(sa *v1.ServiceAccount) error {
	sClient := c.kclient.CoreV1().ServiceAccounts(sa.GetNamespace())
	_, err := sClient.Get(context.TODO(), sa.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sClient.Create(context.TODO(), sa, metav1.CreateOptions{})
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
	existing, err := smClient.Get(context.TODO(), sm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := smClient.Create(context.TODO(), sm, metav1.CreateOptions{})
		return errors.Wrap(err, "creating ServiceMonitor object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ServiceMonitor object failed")
	}

	required := sm.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion
	_, err = smClient.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating ServiceMonitor object failed")
}

func (c *Client) CreateOrUpdateAPIService(apiService *apiregistrationv1.APIService) error {
	apsc := c.aggclient.ApiregistrationV1().APIServices()
	existing, err := apsc.Get(context.TODO(), apiService.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = apsc.Create(context.TODO(), apiService, metav1.CreateOptions{})
		return errors.Wrap(err, "creating APIService object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving APIService object failed")
	}

	required := apiService.DeepCopy()
	required.ResourceVersion = existing.ResourceVersion
	if len(existing.Spec.CABundle) > 0 {
		required.Spec.CABundle = existing.Spec.CABundle
	}
	_, err = apsc.Update(context.TODO(), required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating APIService object failed")

}

func (c *Client) WaitForCRDReady(crd *extensionsobj.CustomResourceDefinition) error {
	return wait.Poll(5*time.Second, 5*time.Minute, func() (bool, error) {
		return c.CRDReady(crd)
	})
}

func (c *Client) CRDReady(crd *extensionsobj.CustomResourceDefinition) (bool, error) {
	crdClient := c.eclient.ApiextensionsV1beta1().CustomResourceDefinitions()

	crdEst, err := crdClient.Get(context.TODO(), crd.ObjectMeta.Name, metav1.GetOptions{})
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
				return false, errors.Errorf("CRD naming conflict (%s): %v", crd.ObjectMeta.Name, cond.Reason)
			}
		}
	}
	return false, err
}

func (c *Client) StatusReporter() *StatusReporter {
	return NewStatusReporter(c.oscclient.ConfigV1().ClusterOperators(), "monitoring", c.namespace, c.userWorkloadNamespace, c.version)
}

func (c *Client) DeleteRoleBinding(binding *rbacv1.RoleBinding) error {
	err := c.kclient.RbacV1().RoleBindings(binding.Namespace).Delete(context.TODO(), binding.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteRole(role *rbacv1.Role) error {
	err := c.kclient.RbacV1().Roles(role.Namespace).Delete(context.TODO(), role.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

// mergeMetadata merges labels and annotations from `existing` map into `required` one where `required` has precedence
// over `existing` keys and values. Additionally function performs filtering of labels and annotations from `exiting` map
// where keys starting from string defined in `metadataPrefix` are deleted. This prevents issues with preserving stale
// metadata defined by the operator
func mergeMetadata(required *metav1.ObjectMeta, existing metav1.ObjectMeta) {
	for k := range existing.Annotations {
		if strings.HasPrefix(k, metadataPrefix) {
			delete(existing.Annotations, k)
		}
	}

	for k := range existing.Labels {
		if strings.HasPrefix(k, metadataPrefix) {
			delete(existing.Labels, k)
		}
	}

	mergo.Merge(&required.Annotations, existing.Annotations)
	mergo.Merge(&required.Labels, existing.Labels)
}
