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
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/imdario/mergo"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"

	configv1 "github.com/openshift/api/config/v1"
	consolev1 "github.com/openshift/api/console/v1"
	osmv1 "github.com/openshift/api/monitoring/v1"
	routev1 "github.com/openshift/api/route/v1"
	secv1 "github.com/openshift/api/security/v1"

	openshiftconfigclientset "github.com/openshift/client-go/config/clientset/versioned"
	openshiftconsoleclientset "github.com/openshift/client-go/console/clientset/versioned"
	openshiftmonitoringclientset "github.com/openshift/client-go/monitoring/clientset/versioned"
	openshiftoperatorclientset "github.com/openshift/client-go/operator/clientset/versioned"
	openshiftrouteclientset "github.com/openshift/client-go/route/clientset/versioned"
	openshiftsecurityclientset "github.com/openshift/client-go/security/clientset/versioned"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	monitoring "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	extensionsobj "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	apiutilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

const (
	deploymentCreateTimeout = 5 * time.Minute
	deploymentDeleteTimeout = 5 * time.Minute
	metadataPrefix          = "monitoring.openshift.io/"
	clusterConsole          = "cluster"
)

type Client struct {
	version               string
	namespace             string
	userWorkloadNamespace string

	kclient     kubernetes.Interface
	mdataclient metadata.Interface
	osmclient   openshiftmonitoringclientset.Interface
	oscclient   openshiftconfigclientset.Interface
	ossclient   openshiftsecurityclientset.Interface
	osrclient   openshiftrouteclientset.Interface
	osopclient  openshiftoperatorclientset.Interface
	osconclient openshiftconsoleclientset.Interface
	mclient     monitoring.Interface
	eclient     apiextensionsclient.Interface
	aggclient   aggregatorclient.Interface

	eventRecorder events.Recorder
}

func NewForConfig(cfg *rest.Config, version string, namespace, userWorkloadNamespace string, options ...Option) (*Client, error) {
	client := New(version, namespace, userWorkloadNamespace, options...)

	if client.kclient == nil {
		kclient, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "creating kubernetes clientset client")
		}
		client.kclient = kclient
	}

	if client.eclient == nil {
		eclient, err := apiextensionsclient.NewForConfig(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "creating apiextensions client")
		}
		client.eclient = eclient
	}

	if client.mclient == nil {
		mclient, err := monitoring.NewForConfig(cfg)
		if err != nil {
			return nil, err
		}
		client.mclient = mclient
	}

	if client.osmclient == nil {
		osmclient, err := openshiftmonitoringclientset.NewForConfig(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "creating openshift monitoring client")
		}
		client.osmclient = osmclient
	}

	if client.oscclient == nil {
		oscclient, err := openshiftconfigclientset.NewForConfig(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "creating openshift config client")
		}
		client.oscclient = oscclient
	}

	if client.ossclient == nil {
		// SCC moved to CRD and CRD does not handle protobuf. Force the SCC client to use JSON instead.
		jsonClientConfig := rest.CopyConfig(cfg)
		jsonClientConfig.ContentConfig.AcceptContentTypes = "application/json"
		jsonClientConfig.ContentConfig.ContentType = "application/json"

		ossclient, err := openshiftsecurityclientset.NewForConfig(jsonClientConfig)
		if err != nil {
			return nil, errors.Wrap(err, "creating openshift security client")
		}
		client.ossclient = ossclient
	}

	if client.osrclient == nil {
		osrclient, err := openshiftrouteclientset.NewForConfig(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "creating openshift route client")
		}
		client.osrclient = osrclient
	}

	if client.aggclient == nil {
		aggclient, err := aggregatorclient.NewForConfig(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "creating kubernetes aggregator")
		}
		client.aggclient = aggclient
	}

	if client.osopclient == nil {
		osopclient, err := openshiftoperatorclientset.NewForConfig(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "creating openshift operator client")
		}
		client.osopclient = osopclient
	}

	if client.osconclient == nil {
		osconclient, err := openshiftconsoleclientset.NewForConfig(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "creating openshift console client")
		}
		client.osconclient = osconclient
	}

	if client.mdataclient == nil {
		mdataclient, err := metadata.NewForConfig(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "creating metadata clientset client")
		}
		client.mdataclient = mdataclient
	}

	return client, nil
}

type Option = func(*Client)

func KubernetesClient(kclient kubernetes.Interface) Option {
	return func(c *Client) {
		c.kclient = kclient
	}
}

func OpenshiftMonitoringClient(osmclient openshiftmonitoringclientset.Interface) Option {
	return func(c *Client) {
		c.osmclient = osmclient
	}
}

func OpenshiftConfigClient(oscclient openshiftconfigclientset.Interface) Option {
	return func(c *Client) {
		c.oscclient = oscclient
	}
}

func OpenshiftSecurityClient(ossclient openshiftsecurityclientset.Interface) Option {
	return func(c *Client) {
		c.ossclient = ossclient
	}
}

func OpenshiftRouteClient(osrclient openshiftrouteclientset.Interface) Option {
	return func(c *Client) {
		c.osrclient = osrclient
	}
}

func OpenshiftOperatorClient(osopclient openshiftoperatorclientset.Interface) Option {
	return func(c *Client) {
		c.osopclient = osopclient
	}
}

func MonitoringClient(mclient monitoring.Interface) Option {
	return func(c *Client) {
		c.mclient = mclient
	}
}

func ApiExtensionsClient(eclient apiextensionsclient.Interface) Option {
	return func(c *Client) {
		c.eclient = eclient
	}
}

func AggregatorClient(aggclient aggregatorclient.Interface) Option {
	return func(c *Client) {
		c.aggclient = aggclient
	}
}

func EventRecorder(eventRecorder events.Recorder) Option {
	return func(c *Client) {
		c.eventRecorder = eventRecorder
	}
}

func New(version string, namespace, userWorkloadNamespace string, options ...Option) *Client {
	c := &Client{
		version:               version,
		namespace:             namespace,
		userWorkloadNamespace: userWorkloadNamespace,
	}

	for _, opt := range options {
		opt(c)
	}

	return c
}

func (c *Client) KubernetesInterface() kubernetes.Interface {
	return c.kclient
}

func (c *Client) EventRecorder() events.Recorder {
	return c.eventRecorder
}

func (c *Client) Namespace() string {
	return c.namespace
}

func (c *Client) UserWorkloadNamespace() string {
	return c.userWorkloadNamespace
}

func (c *Client) AlertingRuleListWatchForNamespace(ns string) *cache.ListWatch {
	return cache.NewListWatchFromClient(c.osmclient.MonitoringV1().RESTClient(), "alertingrules", ns, fields.Everything())
}

func (c *Client) PrometheusRuleListWatchForNamespace(ns string) *cache.ListWatch {
	return cache.NewListWatchFromClient(c.mclient.MonitoringV1().RESTClient(), "prometheusrules", ns, fields.Everything())
}

func (c *Client) AlertRelabelConfigListWatchForNamespace(ns string) *cache.ListWatch {
	return cache.NewListWatchFromClient(
		c.osmclient.MonitoringV1().RESTClient(),
		"alertrelabelconfigs",
		ns,
		fields.Everything(),
	)
}

func (c *Client) ConfigMapListWatchForNamespace(ns string) *cache.ListWatch {
	return cache.NewListWatchFromClient(c.kclient.CoreV1().RESTClient(), "configmaps", ns, fields.Everything())
}

func (c *Client) SecretListWatchForNamespace(ns string) *cache.ListWatch {
	return cache.NewListWatchFromClient(c.kclient.CoreV1().RESTClient(), "secrets", ns, fields.Everything())
}

func (c *Client) SecretListWatchForResource(namespace, name string) *cache.ListWatch {
	return cache.NewListWatchFromClient(
		c.kclient.CoreV1().RESTClient(),
		"secrets",
		namespace,
		fields.OneTermEqualSelector("metadata.name", name),
	)
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

func (c *Client) ApiServersListWatchForResource(ctx context.Context, resource string) *cache.ListWatch {
	apiServerInterface := c.oscclient.ConfigV1().APIServers()

	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return apiServerInterface.List(
				ctx,
				metav1.ListOptions{
					FieldSelector: fields.OneTermEqualSelector("metadata.name", resource).String(),
				},
			)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return apiServerInterface.Watch(
				ctx,
				metav1.ListOptions{
					FieldSelector: fields.OneTermEqualSelector("metadata.name", resource).String(),
				},
			)
		},
	}
}

func (c *Client) ConsoleListWatch(ctx context.Context) *cache.ListWatch {
	consoleInterface := c.oscclient.ConfigV1().Consoles()

	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return consoleInterface.List(ctx, metav1.ListOptions{})
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return consoleInterface.Watch(ctx, options)
		},
	}
}

func (c *Client) ClusterVersionListWatch(ctx context.Context, name string) *cache.ListWatch {
	clusterVersionInterface := c.oscclient.ConfigV1().ClusterVersions()

	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return clusterVersionInterface.List(ctx,
				metav1.ListOptions{
					FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String(),
				})
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return clusterVersionInterface.Watch(ctx,
				metav1.ListOptions{
					FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String(),
				})
		},
	}
}

func (c *Client) ClusterOperatorListWatch(ctx context.Context, name string) *cache.ListWatch {
	ClusterOperatorInterface := c.oscclient.ConfigV1().ClusterOperators()

	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return ClusterOperatorInterface.List(ctx,
				metav1.ListOptions{
					FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String(),
				})
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return ClusterOperatorInterface.Watch(ctx,
				metav1.ListOptions{
					FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String(),
				})
		},
	}
}

func (c *Client) HasRouteCapability(ctx context.Context) (bool, error) {
	_, err := c.oscclient.ConfigV1().ClusterOperators().Get(ctx, "ingress", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return true, err
}

func (c *Client) EnsurePrometheusUserWorkloadConfigMapExists(ctx context.Context, cm *v1.ConfigMap) error {
	_, err := c.CreateIfNotExistConfigMap(ctx, cm)
	return errors.Wrapf(err, "creating empty  ConfigMap object fauled")
}

func (c *Client) AssurePrometheusOperatorCRsExist(ctx context.Context) error {
	return wait.PollUntilContextTimeout(ctx, time.Second, time.Minute*5, false, func(ctx context.Context) (bool, error) {
		_, err := c.mclient.MonitoringV1().Prometheuses(c.namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			klog.V(4).ErrorS(err, "AssurePrometheusOperatorCRsExist: failed to list Prometheuses")
			return false, nil
		}

		_, err = c.mclient.MonitoringV1().Alertmanagers(c.namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			klog.V(4).ErrorS(err, "AssurePrometheusOperatorCRsExist: failed to list Alertmanagers")
			return false, nil
		}

		_, err = c.mclient.MonitoringV1().ServiceMonitors(c.namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			klog.V(4).ErrorS(err, "AssurePrometheusOperatorCRsExist: failed to list ServiceMonitors")
			return false, nil
		}

		return true, nil
	})
}

func (c *Client) UpdateAlertingRuleStatus(ctx context.Context, rule *osmv1.AlertingRule) error {
	ns := rule.GetNamespace()

	_, err := c.osmclient.MonitoringV1().AlertingRules(ns).UpdateStatus(ctx, rule, metav1.UpdateOptions{})
	return err
}

func (c *Client) CreateOrUpdateAlertRelabelConfig(ctx context.Context, arc *osmv1.AlertRelabelConfig) error {
	arcClient := c.osmclient.MonitoringV1().AlertRelabelConfigs(arc.GetNamespace())
	existing, err := arcClient.Get(ctx, arc.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := arcClient.Create(ctx, arc, metav1.CreateOptions{})
		return errors.Wrap(err, "creating AlertRelabelConfig object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving AlertRelabelConfig object failed")
	}

	required := arc.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion

	_, err = arcClient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating AlertRelabelConfig object failed")
}

func (c *Client) CreateOrUpdateValidatingWebhookConfiguration(ctx context.Context, w *admissionv1.ValidatingWebhookConfiguration) error {
	admclient := c.kclient.AdmissionregistrationV1().ValidatingWebhookConfigurations()
	existing, err := admclient.Get(ctx, w.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := admclient.Create(ctx, w, metav1.CreateOptions{})
		return errors.Wrap(err, "creating ValidatingWebhookConfiguration object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ValidatingWebhookConfiguration object failed")
	}

	required := w.DeepCopy()
	required.ResourceVersion = existing.ResourceVersion
	// retain the CABundle that service-ca-operator created if the proper annotation is found
	if val, ok := required.Annotations["service.beta.openshift.io/inject-cabundle"]; ok && val == "true" {
		for i := range required.Webhooks {
			if len(existing.Webhooks[i].ClientConfig.CABundle) > 0 {
				required.Webhooks[i].ClientConfig.CABundle = existing.Webhooks[i].ClientConfig.CABundle
			}
		}
	}
	_, err = admclient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating ValidatingWebhookConfiguration object failed")
}

func (c *Client) CreateOrUpdateSecurityContextConstraints(ctx context.Context, s *secv1.SecurityContextConstraints) error {
	sccclient := c.ossclient.SecurityV1().SecurityContextConstraints()
	existing, err := sccclient.Get(ctx, s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sccclient.Create(ctx, s, metav1.CreateOptions{})
		return errors.Wrap(err, "creating SecurityContextConstraints object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving SecurityContextConstraints object failed")
	}

	// the CRD version of SCC appears to require this.  We can try to chase why later.
	required := s.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	required.ResourceVersion = existing.ResourceVersion

	_, err = sccclient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating SecurityContextConstraints object failed")
}

func (c *Client) CreateOrUpdateRoute(ctx context.Context, r *routev1.Route) error {
	rclient := c.osrclient.RouteV1().Routes(r.GetNamespace())
	existing, err := rclient.Get(ctx, r.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := rclient.Create(ctx, r, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Route object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Route object failed")
	}

	required := r.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	required.ResourceVersion = existing.ResourceVersion

	_, err = rclient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Route object failed")
}

func (c *Client) GetRouteURL(ctx context.Context, r *routev1.Route) (*url.URL, error) {
	rclient := c.osrclient.RouteV1().Routes(r.GetNamespace())
	newRoute, err := rclient.Get(ctx, r.GetName(), metav1.GetOptions{})
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

func (c *Client) GetClusterVersion(ctx context.Context, name string) (*configv1.ClusterVersion, error) {
	return c.oscclient.ConfigV1().ClusterVersions().Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) GetProxy(ctx context.Context, name string) (*configv1.Proxy, error) {
	return c.oscclient.ConfigV1().Proxies().Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) GetInfrastructure(ctx context.Context, name string) (*configv1.Infrastructure, error) {
	return c.oscclient.ConfigV1().Infrastructures().Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) GetAPIServerConfig(ctx context.Context, name string) (*configv1.APIServer, error) {
	return c.oscclient.ConfigV1().APIServers().Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) GetConsoleConfig(ctx context.Context, name string) (*configv1.Console, error) {
	return c.oscclient.ConfigV1().Consoles().Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) TechPreviewEnabled(ctx context.Context) (bool, error) {
	fg, err := c.oscclient.ConfigV1().FeatureGates().Get(ctx, "cluster", metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	return fg.Spec.FeatureSet == configv1.TechPreviewNoUpgrade, nil
}

func (c *Client) GetConfigmap(ctx context.Context, namespace, name string) (*v1.ConfigMap, error) {
	return c.kclient.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) GetSecret(ctx context.Context, namespace, name string) (*v1.Secret, error) {
	return c.kclient.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) GetPrometheusRule(ctx context.Context, namespace, name string) (*monv1.PrometheusRule, error) {
	return c.mclient.MonitoringV1().PrometheusRules(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) GetAlertingRule(ctx context.Context, namespace, name string) (*osmv1.AlertingRule, error) {
	return c.osmclient.MonitoringV1().AlertingRules(namespace).Get(ctx, name, metav1.GetOptions{})
}

func (c *Client) CreateOrUpdatePrometheus(ctx context.Context, p *monv1.Prometheus) error {
	namespace := p.GetNamespace()
	name := p.GetName()
	pclient := c.mclient.MonitoringV1().Prometheuses(namespace)
	existing, err := pclient.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := pclient.Create(ctx, p, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Prometheus object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Prometheus object failed")
	}

	required := p.DeepCopy()
	existing.TypeMeta = required.TypeMeta // not sure why, but for some reason this isn't populated by Get?
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	annotations := required.ObjectMeta.Annotations
	labels := required.ObjectMeta.Labels
	required.ObjectMeta = existing.ObjectMeta
	required.ObjectMeta.Annotations = annotations
	required.ObjectMeta.Labels = labels
	required.Status = existing.Status

	// localize some server-side defaults, so DeepEqual doesn't get confused and think we need to stomp them
	if required.Spec.CommonPrometheusFields.ScrapeInterval == "" {
		required.Spec.CommonPrometheusFields.ScrapeInterval = "30s"
	}
	if len(required.Spec.CommonPrometheusFields.ExternalLabels) == 0 {
		required.Spec.CommonPrometheusFields.ExternalLabels = nil
	}
	if len(required.Spec.CommonPrometheusFields.EnableFeatures) == 0 {
		required.Spec.CommonPrometheusFields.EnableFeatures = nil
	}
	for i, container := range required.Spec.CommonPrometheusFields.Containers {
		for j, port := range container.Ports {
			if port.Protocol == "" {
				required.Spec.CommonPrometheusFields.Containers[i].Ports[j].Protocol = "TCP"
			}
		}
	}
	if required.Spec.CommonPrometheusFields.PortName == "" {
		required.Spec.CommonPrometheusFields.PortName = "web"
	}
	if required.Spec.Thanos == nil {
		required.Spec.Thanos = &monv1.ThanosSpec{}
	}
	if required.Spec.Thanos.BlockDuration == "" {
		required.Spec.Thanos.BlockDuration = "2h"
	}
	if required.Spec.EvaluationInterval == "" {
		required.Spec.EvaluationInterval = "30s"
	}

	if reflect.DeepEqual(existing, required) {
		// Nothing to do, as the currently existing resource is equivalent to the one that would be applied.
		return nil
	}

	if diff := cmp.Diff(existing, required); diff != "" {
		klog.V(2).Infof("Updating Prometheus %s/%s to apply: %v", namespace, name, diff)
	} else {
		klog.V(2).Infof("Updating Prometheus %s/%s with empty diff: possible hotloop after wrong comparison", namespace, name)
	}

	_, err = pclient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Prometheus object failed")
}

func (c *Client) CreateOrUpdatePrometheusRule(ctx context.Context, p *monv1.PrometheusRule) error {
	pclient := c.mclient.MonitoringV1().PrometheusRules(p.GetNamespace())
	existing, err := pclient.Get(ctx, p.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := pclient.Create(ctx, p, metav1.CreateOptions{})
		return errors.Wrap(err, "creating PrometheusRule object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving PrometheusRule object failed")
	}

	required := p.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion

	_, err = pclient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating PrometheusRule object failed")
}

func (c *Client) CreateOrUpdateAlertmanager(ctx context.Context, a *monv1.Alertmanager) error {
	aclient := c.mclient.MonitoringV1().Alertmanagers(a.GetNamespace())
	existing, err := aclient.Get(ctx, a.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := aclient.Create(ctx, a, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Alertmanager object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Alertmanager object failed")
	}

	required := a.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion

	_, err = aclient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Alertmanager object failed")
}

func (c *Client) DeleteAlertmanager(ctx context.Context, a *monv1.Alertmanager) error {
	return c.deleteResourceUntilGone(ctx, monv1.SchemeGroupVersion.WithResource("alertmanagers"), a, 10*time.Minute)
}

func (c *Client) CreateOrUpdateThanosRuler(ctx context.Context, t *monv1.ThanosRuler) error {
	trclient := c.mclient.MonitoringV1().ThanosRulers(t.GetNamespace())
	existing, err := trclient.Get(ctx, t.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := trclient.Create(ctx, t, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Thanos Ruler object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Thanos Ruler object failed")
	}

	required := t.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	required.ResourceVersion = existing.ResourceVersion

	_, err = trclient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Thanos Ruler object failed")
}

func (c *Client) DeleteConfigMap(ctx context.Context, cm *v1.ConfigMap) error {
	err := c.kclient.CoreV1().ConfigMaps(cm.GetNamespace()).Delete(ctx, cm.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

// DeleteHashedConfigMap deletes all configmaps in the given namespace which have
// the specified prefix, and DO NOT have the given hash.
func (c *Client) DeleteHashedConfigMap(ctx context.Context, namespace, prefix, newHash string) error {
	ls := "monitoring.openshift.io/name=" + prefix + ",monitoring.openshift.io/hash!=" + newHash
	configMaps, err := c.KubernetesInterface().CoreV1().ConfigMaps(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: ls,
	})
	if err != nil {
		return errors.Wrapf(err, "error listing configmaps in namespace %s with label selector %s", namespace, ls)
	}

	for _, cm := range configMaps.Items {
		err := c.KubernetesInterface().CoreV1().ConfigMaps(namespace).Delete(ctx, cm.Name, metav1.DeleteOptions{})
		if err != nil {
			return errors.Wrapf(err, "error deleting configmap: %s/%s", namespace, cm.Name)
		}
	}

	return nil
}

// DeleteHashedSecret deletes all secrets in the given namespace which have
// the specified prefix, and DO NOT have the given hash.
func (c *Client) DeleteHashedSecret(ctx context.Context, namespace, prefix, newHash string) error {
	ls := "monitoring.openshift.io/name=" + prefix + ",monitoring.openshift.io/hash!=" + newHash
	secrets, err := c.KubernetesInterface().CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: ls,
	})
	if err != nil {
		return errors.Wrapf(err, "error listing secrets in namespace %s with label selector %s", namespace, ls)
	}

	for _, s := range secrets.Items {
		err := c.KubernetesInterface().CoreV1().Secrets(namespace).Delete(ctx, s.Name, metav1.DeleteOptions{})
		if err != nil {
			return errors.Wrapf(err, "error deleting secret: %s/%s", namespace, s.Name)
		}
	}

	return nil
}

func (c *Client) DeleteValidatingWebhook(ctx context.Context, w *admissionv1.ValidatingWebhookConfiguration) error {
	err := c.kclient.AdmissionregistrationV1().ValidatingWebhookConfigurations().Delete(ctx, w.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteDeployment(ctx context.Context, d *appsv1.Deployment) error {
	return c.deleteResourceUntilGone(ctx, appsv1.SchemeGroupVersion.WithResource("deployments"), d, deploymentDeleteTimeout)
}

func (c *Client) DeletePodDisruptionBudget(ctx context.Context, pdb *policyv1.PodDisruptionBudget) error {
	err := c.kclient.PolicyV1().PodDisruptionBudgets(pdb.GetNamespace()).Delete(ctx, pdb.GetName(), deleteOptions(metav1.DeletePropagationForeground))
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeletePrometheus(ctx context.Context, p *monv1.Prometheus) error {
	return c.deleteResourceUntilGone(ctx, monv1.SchemeGroupVersion.WithResource("prometheuses"), p, 10*time.Minute)
}

func (c *Client) DeleteThanosRuler(ctx context.Context, tr *monv1.ThanosRuler) error {
	return c.deleteResourceUntilGone(ctx, monv1.SchemeGroupVersion.WithResource("thanosrulers"), tr, 10*time.Minute)
}

func (c *Client) DeleteDaemonSet(ctx context.Context, d *appsv1.DaemonSet) error {
	err := c.kclient.AppsV1().DaemonSets(d.GetNamespace()).Delete(ctx, d.GetName(), deleteOptions(metav1.DeletePropagationForeground))
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteServiceMonitor(ctx context.Context, sm *monv1.ServiceMonitor) error {
	return c.DeleteServiceMonitorByNamespaceAndName(ctx, sm.Namespace, sm.GetName())
}

func (c *Client) DeleteServiceMonitorByNamespaceAndName(ctx context.Context, namespace, name string) error {
	sclient := c.mclient.MonitoringV1().ServiceMonitors(namespace)

	err := sclient.Delete(ctx, name, metav1.DeleteOptions{})
	// if the object does not exist then everything is good here
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "deleting ServiceMonitor object failed")
	}

	return nil
}

func (c *Client) DeleteServiceAccount(ctx context.Context, sa *v1.ServiceAccount) error {
	err := c.kclient.CoreV1().ServiceAccounts(sa.Namespace).Delete(ctx, sa.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteClusterRole(ctx context.Context, cr *rbacv1.ClusterRole) error {
	err := c.kclient.RbacV1().ClusterRoles().Delete(ctx, cr.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteClusterRoleBinding(ctx context.Context, crb *rbacv1.ClusterRoleBinding) error {
	err := c.kclient.RbacV1().ClusterRoleBindings().Delete(ctx, crb.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteService(ctx context.Context, svc *v1.Service) error {
	err := c.kclient.CoreV1().Services(svc.Namespace).Delete(ctx, svc.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteRoute(ctx context.Context, r *routev1.Route) error {
	err := c.osrclient.RouteV1().Routes(r.GetNamespace()).Delete(ctx, r.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) DeletePrometheusRule(ctx context.Context, rule *monv1.PrometheusRule) error {
	return c.DeletePrometheusRuleByNamespaceAndName(ctx, rule.Namespace, rule.GetName())
}

func (c *Client) DeletePrometheusRuleByNamespaceAndName(ctx context.Context, namespace, name string) error {
	sclient := c.mclient.MonitoringV1().PrometheusRules(namespace)

	err := sclient.Delete(ctx, name, metav1.DeleteOptions{})
	// if the object does not exist then everything is good here
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "deleting PrometheusRule object failed")
	}

	return nil
}

func (c *Client) DeleteSecret(ctx context.Context, s *v1.Secret) error {
	err := c.kclient.CoreV1().Secrets(s.Namespace).Delete(ctx, s.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

// NOTE: this is only used during 4.13->4.14 upgrade, will be removed after.
// TODO: remove this
func (c *Client) DeleteSecretByNamespaceAndName(ctx context.Context, namespace, name string) error {
	err := c.kclient.CoreV1().Secrets(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	// if the object does not exist then everything is good here
	if err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrap(err, "deleting Secret object failed")
	}

	return nil
}

// validatePrometheusResource is a helper method for ValidatePrometheus.
// NOTE: this function is refactored out of wait.Poll for testing
func (c Client) validatePrometheusResource(ctx context.Context, prom types.NamespacedName) (bool, []error) {
	p, err := c.mclient.MonitoringV1().Prometheuses(prom.Namespace).Get(ctx, prom.Name, metav1.GetOptions{})
	if err != nil {
		// failing to get Prometheus -> Degraded: Unknown & Unavailable: Unknown
		klog.V(4).Info("validate prometheus failed to get prometheus: ", err)
		return false, []error{
			NewUnknownAvailabiltyError(err.Error()),
			NewUnknownDegradedError(err.Error()),
		}
	}

	avail, err := getMonitoringCondition(p.Status.Conditions, monv1.Available)
	if err != nil {
		err = fmt.Errorf("prometheus: %w", err)
		// failing to get Prometheus.Status.Condtion -> Degraded: Unknown & Unavailable: Unknown
		return false, []error{
			NewUnknownAvailabiltyError(err.Error()),
			NewUnknownDegradedError(err.Error()),
		}
	}

	if avail.Status == monv1.ConditionTrue {
		// Prometheus is Available; check reconciled Condition as well
		reconciled, err := getMonitoringCondition(p.Status.Conditions, monv1.Reconciled)
		if err != nil {
			err = fmt.Errorf("prometheus: %w", err)
			// failing to get Prometheus.Status.Condtion -> Degraded: Unknown
			return false, []error{NewUnknownDegradedError(err.Error())}
		} else if reconciled.Status != monv1.ConditionTrue {
			klog.V(4).Info("validate prometheus failed reconciled condition: ", reconciled.Status)
			msg := fmt.Sprintf("%s: %s", reconciled.Reason, reconciled.Message)
			return false, []error{NewDegradedError(msg)}
		}

		// terminate if available & reconciled
		return true, nil
	}

	// return reason for failure as state-errors - Degraded: True & Unavailable: True
	// since prometheus is Unavailable

	msg := fmt.Sprintf("%s: %s", avail.Reason, avail.Message)
	errs := []error{NewDegradedError(msg)}

	if avail.Status == monv1.ConditionFalse {
		// prometheus not available should result in a Degraded and Unavailable error
		errs = append(errs, NewAvailabilityError(msg))
	}
	return false, errs
}

// ValidatePrometheus returns nil error if Prometheus is fully available.
// Otherwise, it returns
// Degraded(True) and Unavailable(True) if Prometheus is not running
// Degraded(Unknown)  and Unavailable(Unknown) if it fails to retrieve Prometheus status
func (c *Client) ValidatePrometheus(ctx context.Context, promNsName types.NamespacedName) error {
	validationErrors := []error{}

	pollErr := wait.PollUntilContextTimeout(ctx, 10*time.Second, 5*time.Minute, false, func(ctx context.Context) (bool, error) {
		stop, errs := c.validatePrometheusResource(ctx, promNsName)
		validationErrors = errs
		return stop, nil
	})

	if pollErr != nil {
		return apiutilerrors.NewAggregate(validationErrors)
	}

	return nil
}

func getMonitoringCondition(conditions []monv1.Condition, t monv1.ConditionType) (monv1.Condition, error) {
	for _, c := range conditions {
		if c.Type == t {
			return c, nil
		}
	}
	return monv1.Condition{}, fmt.Errorf("failed to find condition type %q", t)
}

// validateMonitoringResource returns an error if the monitoring resource
// (Prometheus, Alertmanager, ThanosRuler) isn't fully available.
func validateMonitoringResource(expectedReplicas, updatedReplicas, availableReplicas int32, generation int64, conditions []monv1.Condition) error {
	if expectedReplicas != updatedReplicas {
		return fmt.Errorf("expected %d replicas, got %d updated replicas", expectedReplicas, updatedReplicas)
	}

	if availableReplicas < expectedReplicas {
		return fmt.Errorf("expected %d replicas, got %d available replicas", expectedReplicas, availableReplicas)
	}

	for _, ct := range []monv1.ConditionType{
		monv1.Reconciled,
		monv1.Available,
	} {
		cond, err := getMonitoringCondition(conditions, ct)
		if err != nil {
			return err
		}

		if generation != cond.ObservedGeneration {
			return fmt.Errorf("condition %s: generation (%d) and observed generation (%d) mismatch", cond.Type, generation, cond.ObservedGeneration)
		}

		if cond.Status != monv1.ConditionTrue {
			return fmt.Errorf("condition %s: status %s: reason %s: %s", cond.Type, cond.Status, cond.Reason, cond.Message)
		}
	}

	return nil
}

func (c *Client) WaitForAlertmanager(ctx context.Context, a *monv1.Alertmanager) error {
	var lastErr error
	if err := wait.PollUntilContextTimeout(ctx, time.Second*10, time.Minute*5, false, func(ctx context.Context) (bool, error) {
		a, err := c.mclient.MonitoringV1().Alertmanagers(a.GetNamespace()).Get(ctx, a.GetName(), metav1.GetOptions{})
		if err != nil {
			lastErr = err
			klog.V(4).ErrorS(err, "WaitForAlertmanager: failed to get AlertManager")
			return false, nil
		}

		lastErr = validateMonitoringResource(
			*a.Spec.Replicas,
			a.Status.UpdatedReplicas,
			a.Status.AvailableReplicas,
			a.Generation,
			a.Status.Conditions,
		)
		if lastErr != nil {
			return false, nil
		}

		return true, nil
	}); err != nil {
		if ctx.Err() != nil && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for Alertmanager %s/%s", a.GetNamespace(), a.GetName())
	}
	return nil
}

func (c *Client) WaitForThanosRuler(ctx context.Context, t *monv1.ThanosRuler) error {
	var lastErr error
	if err := wait.PollUntilContextTimeout(ctx, time.Second*10, time.Minute*5, false, func(ctx context.Context) (bool, error) {
		tr, err := c.mclient.MonitoringV1().ThanosRulers(t.GetNamespace()).Get(ctx, t.GetName(), metav1.GetOptions{})
		if err != nil {
			lastErr = err
			klog.V(4).ErrorS(err, "WaitForThanosRuler: failed to get ThanosRuler")
			return false, nil
		}

		lastErr = validateMonitoringResource(
			*tr.Spec.Replicas,
			tr.Status.UpdatedReplicas,
			tr.Status.AvailableReplicas,
			tr.Generation,
			tr.Status.Conditions,
		)
		if lastErr != nil {
			return false, nil
		}

		return true, nil
	}); err != nil {
		if ctx.Err() != nil && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for Thanos Ruler %s/%s", t.GetNamespace(), t.GetName())
	}
	return nil
}

func (c *Client) CreateOrUpdateDeployment(ctx context.Context, dep *appsv1.Deployment) error {
	existing, err := c.kclient.AppsV1().Deployments(dep.GetNamespace()).Get(ctx, dep.GetName(), metav1.GetOptions{})

	if apierrors.IsNotFound(err) {
		err = c.CreateDeployment(ctx, dep)
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

	err = c.UpdateDeployment(ctx, required)
	if err != nil {
		uErr, ok := err.(*apierrors.StatusError)
		if ok && uErr.ErrStatus.Code == 422 && uErr.ErrStatus.Reason == metav1.StatusReasonInvalid {
			// try to delete Deployment
			err = c.DeleteDeployment(ctx, existing)
			if err != nil {
				return errors.Wrap(err, "deleting Deployment object failed")
			}
			err = c.CreateDeployment(ctx, required)
			if err != nil {
				return errors.Wrap(err, "creating Deployment object failed after update failed")
			}
		}
		return errors.Wrap(err, "updating Deployment object failed")
	}
	return nil
}

func (c *Client) CreateDeployment(ctx context.Context, dep *appsv1.Deployment) error {
	d, err := c.kclient.AppsV1().Deployments(dep.GetNamespace()).Create(ctx, dep, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return c.WaitForDeploymentRollout(ctx, d)
}

func (c *Client) UpdateDeployment(ctx context.Context, dep *appsv1.Deployment) error {
	updated, err := c.kclient.AppsV1().Deployments(dep.GetNamespace()).Update(ctx, dep, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return c.WaitForDeploymentRollout(ctx, updated)
}

func (c *Client) WaitForDeploymentRollout(ctx context.Context, dep *appsv1.Deployment) error {
	var lastErr error
	if err := wait.PollUntilContextTimeout(ctx, time.Second, deploymentCreateTimeout, false, func(ctx context.Context) (bool, error) {
		d, err := c.kclient.AppsV1().Deployments(dep.GetNamespace()).Get(ctx, dep.GetName(), metav1.GetOptions{})
		if err != nil {
			lastErr = err
			klog.V(4).ErrorS(err, "WaitForDeploymentRollout: failed to get Deployment")
			return false, nil
		}
		if d.Generation > d.Status.ObservedGeneration {
			lastErr = errors.Errorf("current generation %d, observed generation %d",
				d.Generation, d.Status.ObservedGeneration)
			return false, nil
		}
		if d.Status.UpdatedReplicas != d.Status.Replicas {
			lastErr = errors.Errorf("the number of pods targeted by the deployment (%d pods) is different "+
				"from the number of pods targeted by the deployment that have the desired template spec (%d pods)",
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
		if ctx.Err() != nil && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for DeploymentRollout of %s/%s", dep.GetNamespace(), dep.GetName())
	}
	return nil
}

// deleteResourceUntilGone deletes the provided resource with the foreground
// policy and will block until the resource is effectively deleted.
func (c *Client) deleteResourceUntilGone(ctx context.Context, gvr schema.GroupVersionResource, obj metav1.Object, timeout time.Duration) error {
	client := c.mdataclient.Resource(gvr).Namespace(obj.GetNamespace())
	err := client.Delete(ctx, obj.GetName(), deleteOptions(metav1.DeletePropagationForeground))
	if apierrors.IsNotFound(err) {
		return nil
	}

	var lastErr error
	if err := wait.PollUntilContextTimeout(ctx, time.Second, timeout, false, func(ctx context.Context) (bool, error) {
		_, err := client.Get(ctx, obj.GetName(), metav1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return true, nil
			}

			lastErr = err
			return false, nil
		}

		lastErr = fmt.Errorf("not deleted yet")
		return false, nil
	}); err != nil {
		if ctx.Err() != nil && lastErr != nil {
			err = lastErr
		}
		return fmt.Errorf("waiting for deletion of %s %s/%s: %w", gvr.String(), obj.GetNamespace(), obj.GetName(), err)
	}

	return nil
}

func (c *Client) WaitForStatefulsetRollout(ctx context.Context, sts *appsv1.StatefulSet) error {
	var lastErr error
	if err := wait.PollUntilContextTimeout(ctx, time.Second, deploymentCreateTimeout, false, func(ctx context.Context) (bool, error) {
		s, err := c.kclient.AppsV1().StatefulSets(sts.GetNamespace()).Get(ctx, sts.GetName(), metav1.GetOptions{})
		if err != nil {
			lastErr = err
			klog.V(4).ErrorS(err, "WaitForStatefulsetRollout: failed to get StatefulSet")
			return false, nil
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
		if ctx.Err() != nil && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for StatefulsetRollout of %s/%s", sts.GetNamespace(), sts.GetName())
	}
	return nil
}

func (c *Client) WaitForSecret(ctx context.Context, s *v1.Secret) (*v1.Secret, error) {
	var result *v1.Secret
	var lastErr error
	if err := wait.PollUntilContextTimeout(ctx, 1*time.Second, 5*time.Minute, false, func(ctx context.Context) (bool, error) {
		var err error

		result, err = c.kclient.CoreV1().Secrets(s.Namespace).Get(ctx, s.Name, metav1.GetOptions{})
		if err != nil {
			lastErr = err
			return false, nil
		}

		if len(result.Data) == 0 {
			lastErr = errors.New("secret contains no data")
			return false, nil
		}

		for k, v := range result.Data {
			if len(v) == 0 {
				lastErr = fmt.Errorf("%q key has empty value", k)
				return false, nil
			}
		}

		return true, nil
	}); err != nil {
		if ctx.Err() != nil && lastErr != nil {
			err = lastErr
		}
		return nil, errors.Wrapf(err, "waiting for secret %s/%s", s.GetNamespace(), s.GetName())
	}

	return result, nil
}

func (c *Client) WaitForSecretByNsName(ctx context.Context, obj types.NamespacedName) (*v1.Secret, error) {
	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      obj.Name,
			Namespace: obj.Namespace,
		},
	}
	return c.WaitForSecret(ctx, &secret)
}

func (c *Client) WaitForConfigMap(ctx context.Context, cm *v1.ConfigMap) (*v1.ConfigMap, error) {
	var result *v1.ConfigMap
	var lastErr error
	if err := wait.PollUntilContextTimeout(ctx, 1*time.Second, 5*time.Minute, false, func(ctx context.Context) (bool, error) {
		var err error

		result, err = c.kclient.CoreV1().ConfigMaps(cm.Namespace).Get(ctx, cm.Name, metav1.GetOptions{})
		if err != nil {
			lastErr = err
			return false, nil
		}

		if len(result.Data) == 0 {
			lastErr = errors.New("configmap contains no data")
			return false, nil
		}

		for k, v := range result.Data {
			if len(v) == 0 {
				lastErr = fmt.Errorf("%q key has empty value", k)
				return false, nil
			}
		}

		return true, nil
	}); err != nil {
		if ctx.Err() != nil && lastErr != nil {
			err = lastErr
		}
		return nil, errors.Wrapf(err, "waiting for ConfigMap %s/%s", cm.GetNamespace(), cm.GetName())
	}

	return result, nil
}

func (c *Client) WaitForConfigMapByNsName(ctx context.Context, obj types.NamespacedName) (*v1.ConfigMap, error) {
	return c.WaitForConfigMap(
		ctx,
		&v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      obj.Name,
				Namespace: obj.Namespace,
			},
		})
}

func (c *Client) WaitForRouteReady(ctx context.Context, r *routev1.Route) (string, error) {
	host := ""
	var lastErr error
	if err := wait.PollUntilContextTimeout(ctx, time.Second, deploymentCreateTimeout, false, func(ctx context.Context) (bool, error) {
		newRoute, err := c.osrclient.RouteV1().Routes(r.GetNamespace()).Get(ctx, r.GetName(), metav1.GetOptions{})
		if err != nil {
			lastErr = err
			klog.V(4).ErrorS(err, "WaitForRouteReady: failed to get Route")
			return false, nil
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
		if ctx.Err() != nil && lastErr != nil {
			err = lastErr
		}
		return host, errors.Wrapf(err, "waiting for route %s/%s", r.GetNamespace(), r.GetName())
	}
	return host, nil
}

func (c *Client) CreateOrUpdateDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) error {
	existing, err := c.kclient.AppsV1().DaemonSets(ds.GetNamespace()).Get(ctx, ds.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		err = c.CreateDaemonSet(ctx, ds)
		return errors.Wrap(err, "creating DaemonSet object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving DaemonSet object failed")
	}

	required := ds.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	err = c.UpdateDaemonSet(ctx, required)
	if err != nil {
		uErr, ok := err.(*apierrors.StatusError)
		if ok && uErr.ErrStatus.Code == 422 && uErr.ErrStatus.Reason == metav1.StatusReasonInvalid {
			// try to delete DaemonSet
			err = c.DeleteDaemonSet(ctx, existing)
			if err != nil {
				return errors.Wrap(err, "deleting DaemonSet object failed")
			}

			err = c.CreateDaemonSet(ctx, required)
			if err != nil {
				return errors.Wrap(err, "creating DaemonSet object failed after update failed")
			}
		}
		return errors.Wrap(err, "updating DaemonSet object failed")
	}
	return nil
}

func (c *Client) CreateDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) error {
	d, err := c.kclient.AppsV1().DaemonSets(ds.GetNamespace()).Create(ctx, ds, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return c.WaitForDaemonSetRollout(ctx, d)
}

func (c *Client) UpdateDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) error {
	updated, err := c.kclient.AppsV1().DaemonSets(ds.GetNamespace()).Update(ctx, ds, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return c.WaitForDaemonSetRollout(ctx, updated)
}

func (c *Client) WaitForDaemonSetRollout(ctx context.Context, ds *appsv1.DaemonSet) error {
	var lastErr error
	if err := wait.PollUntilContextTimeout(ctx, time.Second, deploymentCreateTimeout, false, func(ctx context.Context) (bool, error) {
		d, err := c.kclient.AppsV1().DaemonSets(ds.GetNamespace()).Get(ctx, ds.GetName(), metav1.GetOptions{})
		if err != nil {
			lastErr = err
			klog.V(4).ErrorS(err, "WaitForDaemonSetRollout: failed to get DaemonSet")
			return false, nil
		}
		want := d.Status.DesiredNumberScheduled
		have := d.Status.NumberAvailable
		numberUnavailable := want - have
		maxUnavailableIntStr := intstr.FromInt(1)

		if d.Generation > d.Status.ObservedGeneration {
			lastErr = errors.Errorf("current generation %d, observed generation: %d",
				d.Generation, d.Status.ObservedGeneration)
			return false, nil
		}

		if d.Spec.UpdateStrategy.RollingUpdate != nil && d.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable != nil {
			maxUnavailableIntStr = *d.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable
		}
		maxUnavailable, intstrErr := intstr.GetScaledValueFromIntOrPercent(&maxUnavailableIntStr, int(want), true)

		if intstrErr != nil {
			lastErr = errors.Errorf("The daemonset has an invalid MaxUnavailable value: %v", intstrErr)
			return false, nil
		}

		if int(numberUnavailable) > maxUnavailable {
			lastErr = errors.Errorf("Too many daemonset pods are unavailable (%d > %d max unavailable).", numberUnavailable, maxUnavailable)
			return false, nil
		}
		return true, nil
	}); err != nil {
		if ctx.Err() != nil && lastErr != nil {
			err = lastErr
		}
		return errors.Wrapf(err, "waiting for DaemonSetRollout of %s/%s", ds.GetNamespace(), ds.GetName())
	}
	return nil
}

func (c *Client) CreateOrUpdateSecret(ctx context.Context, s *v1.Secret) error {
	sClient := c.kclient.CoreV1().Secrets(s.GetNamespace())
	existing, err := sClient.Get(ctx, s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sClient.Create(ctx, s, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Secret object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Secret object failed")
	}

	required := s.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	// Check if the Secret has an owner reference to a Service, that carries
	// the annotation with key
	// service.beta.openshift.io/serving-cert-secret-name and the Secrets
	// name as the value.
	// This means that service-ca-operator controls and populates the two
	// data fields tls.crt and tls.key. We want to retain those on updates
	// if they exist and are not empty.
	if c.maybeHasServiceCAData(ctx, required) {
		if v, ok := existing.Data["tls.crt"]; ok && len(v) > 0 {
			required.Data["tls.crt"] = v
		}
		if v, ok := existing.Data["tls.key"]; ok && len(v) > 0 {
			required.Data["tls.key"] = v
		}
	}
	_, err = sClient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Secret object failed")
}

// maybeHasServiceCAData checks if the passed Secret s has at least one owner reference that
// points to a Service with the annotation service.beta.openshift.io/serving-cert-secret-name: s.name
func (c *Client) maybeHasServiceCAData(ctx context.Context, s *v1.Secret) bool {
	for _, owner := range s.OwnerReferences {
		if owner.Kind != "Service" {
			continue
		}
		sclient := c.kclient.CoreV1().Services(s.GetNamespace())
		svc, err := sclient.Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			continue
		}
		if secName, ok := svc.Annotations["service.beta.openshift.io/serving-cert-secret-name"]; ok && secName == s.Name {
			return true
		}
	}
	return false
}

func (c *Client) CreateIfNotExistSecret(ctx context.Context, s *v1.Secret) error {
	sClient := c.kclient.CoreV1().Secrets(s.GetNamespace())
	_, err := sClient.Get(ctx, s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sClient.Create(ctx, s, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Secret object failed")
	}

	return errors.Wrap(err, "retrieving Secret object failed")
}

func (c *Client) CreateOrUpdateConfigMapList(ctx context.Context, cml *v1.ConfigMapList) error {
	for _, cm := range cml.Items {
		err := c.CreateOrUpdateConfigMap(ctx, &cm)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) DeleteConfigMapList(ctx context.Context, cml *v1.ConfigMapList) error {
	for _, cm := range cml.Items {
		err := c.DeleteConfigMap(ctx, &cm)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) CreateOrUpdateConfigMap(ctx context.Context, cm *v1.ConfigMap) error {
	cmClient := c.kclient.CoreV1().ConfigMaps(cm.GetNamespace())
	existing, err := cmClient.Get(ctx, cm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := cmClient.Create(ctx, cm, metav1.CreateOptions{})
		return errors.Wrap(err, "creating ConfigMap object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ConfigMap object failed")
	}

	required := cm.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	if val, ok := required.Annotations["service.beta.openshift.io/inject-cabundle"]; ok && val == "true" {
		// retain any service-ca data that service-ca-operator has created
		if v, ok := existing.Data["service-ca.crt"]; ok && len(v) > 0 {
			required.Data["service-ca.crt"] = v
		}
	}

	_, err = cmClient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating ConfigMap object failed")
}

func (c *Client) DeleteIfExists(ctx context.Context, nsName string) error {
	nClient := c.kclient.CoreV1().Namespaces()
	_, err := nClient.Get(ctx, nsName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// Namespace already deleted
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Namespace object failed")
	}

	err = nClient.Delete(ctx, nsName, metav1.DeleteOptions{})
	return errors.Wrap(err, "deleting ConfigMap object failed")
}

func (c *Client) CreateIfNotExistConfigMap(ctx context.Context, cm *v1.ConfigMap) (*v1.ConfigMap, error) {
	cClient := c.kclient.CoreV1().ConfigMaps(cm.GetNamespace())
	res, err := cClient.Get(ctx, cm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		res, err := cClient.Create(ctx, cm, metav1.CreateOptions{})
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

func (c *Client) CreateOrUpdatePodDisruptionBudget(ctx context.Context, pdb *policyv1.PodDisruptionBudget) error {
	pdbClient := c.kclient.PolicyV1().PodDisruptionBudgets(pdb.Namespace)
	existing, err := pdbClient.Get(ctx, pdb.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := pdbClient.Create(ctx, pdb, metav1.CreateOptions{})
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

	_, err = pdbClient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating PodDisruptionBudget object failed")
}

func (c *Client) CreateOrUpdateService(ctx context.Context, svc *v1.Service) error {
	sclient := c.kclient.CoreV1().Services(svc.GetNamespace())
	existing, err := sclient.Get(ctx, svc.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = sclient.Create(ctx, svc, metav1.CreateOptions{})
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

	_, err = sclient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Service object failed")
}

func (c *Client) CreateOrUpdateRoleBinding(ctx context.Context, rb *rbacv1.RoleBinding) error {
	rbClient := c.kclient.RbacV1().RoleBindings(rb.GetNamespace())
	existing, err := rbClient.Get(ctx, rb.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := rbClient.Create(ctx, rb, metav1.CreateOptions{})
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

	_, err = rbClient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating RoleBinding object failed")
}

func (c *Client) CreateOrUpdateRole(ctx context.Context, r *rbacv1.Role) error {
	rClient := c.kclient.RbacV1().Roles(r.GetNamespace())
	existing, err := rClient.Get(ctx, r.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := rClient.Create(ctx, r, metav1.CreateOptions{})
		return errors.Wrap(err, "creating Role object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving Role object failed")
	}

	required := r.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	_, err = rClient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating Role object failed")
}

func (c *Client) CreateOrUpdateClusterRole(ctx context.Context, cr *rbacv1.ClusterRole) error {
	crClient := c.kclient.RbacV1().ClusterRoles()
	existing, err := crClient.Get(ctx, cr.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := crClient.Create(ctx, cr, metav1.CreateOptions{})
		return errors.Wrap(err, "creating ClusterRole object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ClusterRole object failed")
	}

	required := cr.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	_, err = crClient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating ClusterRole object failed")
}

func (c *Client) CreateOrUpdateClusterRoleBinding(ctx context.Context, crb *rbacv1.ClusterRoleBinding) error {
	crbClient := c.kclient.RbacV1().ClusterRoleBindings()
	existing, err := crbClient.Get(ctx, crb.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := crbClient.Create(ctx, crb, metav1.CreateOptions{})
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

	err = crbClient.Delete(ctx, crb.Name, metav1.DeleteOptions{})
	if err != nil {
		return errors.Wrap(err, "deleting ClusterRoleBinding object failed")
	}

	_, err = crbClient.Create(ctx, required, metav1.CreateOptions{})
	return errors.Wrap(err, "updating ClusterRoleBinding object failed")
}

func (c *Client) CreateOrUpdateServiceAccount(ctx context.Context, sa *v1.ServiceAccount) error {
	_, _, err := resourceapply.ApplyServiceAccount(ctx, c.kclient.CoreV1(), c.eventRecorder, sa)
	return errors.Wrap(err, "patching ServiceAccount object failed")
}

func (c *Client) CreateOrUpdateServiceMonitor(ctx context.Context, sm *monv1.ServiceMonitor) error {
	smClient := c.mclient.MonitoringV1().ServiceMonitors(sm.GetNamespace())
	existing, err := smClient.Get(ctx, sm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := smClient.Create(ctx, sm, metav1.CreateOptions{})
		return errors.Wrap(err, "creating ServiceMonitor object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ServiceMonitor object failed")
	}

	required := sm.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion
	_, err = smClient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating ServiceMonitor object failed")
}

func (c *Client) CreateOrUpdateAPIService(ctx context.Context, apiService *apiregistrationv1.APIService) error {
	apsc := c.aggclient.ApiregistrationV1().APIServices()
	existing, err := apsc.Get(ctx, apiService.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = apsc.Create(ctx, apiService, metav1.CreateOptions{})
		return errors.Wrap(err, "creating APIService object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving APIService object failed")
	}

	required := apiService.DeepCopy()
	required.ResourceVersion = existing.ResourceVersion
	if val, ok := required.Annotations["service.beta.openshift.io/inject-cabundle"]; ok && val == "true" {
		if len(existing.Spec.CABundle) > 0 {
			required.Spec.CABundle = existing.Spec.CABundle
		}
	}
	_, err = apsc.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating APIService object failed")
}

func (c *Client) WaitForCRDReady(ctx context.Context, crd *extensionsobj.CustomResourceDefinition) error {
	return wait.PollUntilContextTimeout(ctx, 5*time.Second, 5*time.Minute, false, func(ctx context.Context) (bool, error) {
		return c.CRDReady(ctx, crd)
	})
}

func (c *Client) CRDReady(ctx context.Context, crd *extensionsobj.CustomResourceDefinition) (bool, error) {
	crdClient := c.eclient.ApiextensionsV1().CustomResourceDefinitions()

	crdEst, err := crdClient.Get(ctx, crd.ObjectMeta.Name, metav1.GetOptions{})
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

func (c *Client) DeleteRoleBinding(ctx context.Context, binding *rbacv1.RoleBinding) error {
	err := c.kclient.RbacV1().RoleBindings(binding.Namespace).Delete(ctx, binding.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeleteRole(ctx context.Context, role *rbacv1.Role) error {
	err := c.kclient.RbacV1().Roles(role.Namespace).Delete(ctx, role.GetName(), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) PodCapacity(ctx context.Context) (int, error) {
	nodes, err := c.kclient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	var podCapacityTotal int64
	for _, node := range nodes.Items {
		podsCount, succeeded := node.Status.Capacity.Pods().AsInt64()
		if !succeeded {
			klog.Warningf("Cannot get pod capacity from node: %s. Error: %v", node.Name, err)
			continue
		}
		podCapacityTotal += podsCount
	}

	return int(podCapacityTotal), nil
}

func (c *Client) HasClusterCapability(ctx context.Context, capability configv1.ClusterVersionCapability) (bool, error) {
	version, err := c.oscclient.ConfigV1().ClusterVersions().Get(ctx, "version", metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	return slices.Contains(version.Status.Capabilities.EnabledCapabilities, capability), nil
}

func (c *Client) HasConsoleCapability(ctx context.Context) (bool, error) {
	return c.HasClusterCapability(ctx, configv1.ClusterVersionCapabilityConsole)
}

func (c *Client) CreateOrUpdateConsolePlugin(ctx context.Context, plg *consolev1.ConsolePlugin) error {
	conClient := c.osconclient.ConsoleV1().ConsolePlugins()
	existing, err := conClient.Get(ctx, plg.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := conClient.Create(ctx, plg, metav1.CreateOptions{})
		return errors.Wrap(err, "creating ConsolePlugin object failed")
	}
	if err != nil {
		return errors.Wrap(err, "retrieving ConsolePlugin object failed")
	}

	required := plg.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	required.ResourceVersion = existing.ResourceVersion

	_, err = conClient.Update(ctx, required, metav1.UpdateOptions{})
	return errors.Wrap(err, "updating ConsolePlugin object failed")
}

func (c *Client) RegisterConsolePlugin(ctx context.Context, name string) error {
	consoleClient := c.osopclient.OperatorV1().Consoles()

	console, err := consoleClient.Get(ctx, clusterConsole, metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "retrieving console %q failed", clusterConsole)
	}

	if slices.Contains(console.Spec.Plugins, name) {
		klog.V(5).Info("console already contains plugin", name)
		return nil
	}

	var patches []jsonPatch

	if console.Spec.Plugins == nil {
		patches = []jsonPatch{{
			Op:    "add",
			Path:  "/spec/plugins",
			Value: []string{name},
		}}
	} else {
		patches = []jsonPatch{{
			Op:    "add",
			Path:  "/spec/plugins/-",
			Value: name,
		}}
	}

	patchBytes, err := json.Marshal(patches)
	if err != nil {
		panic(err)
	}

	_, err = consoleClient.Patch(ctx, clusterConsole, types.JSONPatchType, patchBytes, metav1.PatchOptions{})
	return errors.Wrapf(err, "registering console-plugin %q with console %q failed", name, clusterConsole)
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

	_ = mergo.Merge(&required.Annotations, existing.Annotations)
	_ = mergo.Merge(&required.Labels, existing.Labels)
}

type jsonPatch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func deleteOptions(dp metav1.DeletionPropagation) metav1.DeleteOptions {
	return metav1.DeleteOptions{
		PropagationPolicy: &dp,
	}
}
