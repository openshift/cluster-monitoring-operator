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
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/imdario/mergo"
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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	apiutilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
	"k8s.io/utils/ptr"
)

const (
	deleteTimeout                        = 10 * time.Minute
	metadataPrefix                       = "monitoring.openshift.io/"
	clusterConsole                       = "cluster"
	VerticalPodAutoscalerCRDMetadataName = "verticalpodautoscalers.autoscaling.k8s.io"
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
	resourceCache resourceapply.ResourceCache
}

func NewForConfig(cfg *rest.Config, version string, namespace, userWorkloadNamespace string, options ...Option) (*Client, error) {
	client := New(version, namespace, userWorkloadNamespace, options...)

	if client.kclient == nil {
		cfg = rest.CopyConfig(cfg)
		cfg.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
		cfg.ContentType = "application/vnd.kubernetes.protobuf"
		kclient, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating kubernetes clientset client: %w", err)
		}
		client.kclient = kclient
	}

	if client.eclient == nil {
		eclient, err := apiextensionsclient.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating apiextensions client: %w", err)
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
			return nil, fmt.Errorf("creating openshift monitoring client: %w", err)
		}
		client.osmclient = osmclient
	}

	if client.oscclient == nil {
		oscclient, err := openshiftconfigclientset.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating openshift config client: %w", err)
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
			return nil, fmt.Errorf("creating openshift security client: %w", err)
		}
		client.ossclient = ossclient
	}

	if client.osrclient == nil {
		osrclient, err := openshiftrouteclientset.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating openshift route client: %w", err)
		}
		client.osrclient = osrclient
	}

	if client.aggclient == nil {
		aggclient, err := aggregatorclient.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating kubernetes aggregator: %w", err)
		}
		client.aggclient = aggclient
	}

	if client.osopclient == nil {
		osopclient, err := openshiftoperatorclientset.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating openshift operator client: %w", err)
		}
		client.osopclient = osopclient
	}

	if client.osconclient == nil {
		osconclient, err := openshiftconsoleclientset.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating openshift console client: %w", err)
		}
		client.osconclient = osconclient
	}

	if client.mdataclient == nil {
		mdataclient, err := metadata.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("creating metadata clientset client: %w", err)
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
		resourceCache:         resourceapply.NewResourceCache(),
	}

	for _, opt := range options {
		opt(c)
	}

	return c
}

func (c *Client) KubernetesInterface() kubernetes.Interface {
	return c.kclient
}

func (c *Client) ApiExtensionsInterface() apiextensionsclient.Interface {
	return c.eclient
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

func (c *Client) VerticalPodAutoscalerCRDListWatch(ctx context.Context) *cache.ListWatch {
	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return c.eclient.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{
				FieldSelector: fields.OneTermEqualSelector("metadata.name", VerticalPodAutoscalerCRDMetadataName).String(),
			})
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return c.eclient.ApiextensionsV1().CustomResourceDefinitions().Watch(ctx, metav1.ListOptions{
				FieldSelector: fields.OneTermEqualSelector("metadata.name", VerticalPodAutoscalerCRDMetadataName).String(),
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
	if err != nil {
		return fmt.Errorf("creating empty ConfigMap object failed: %w", err)
	}
	return nil
}

func (c *Client) AssurePrometheusOperatorCRsExist(ctx context.Context) error {
	return Poll(ctx, func(ctx context.Context) (bool, error) {
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
		if err != nil {
			return fmt.Errorf("creating AlertRelabelConfig object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving AlertRelabelConfig object failed: %w", err)
	}

	required := arc.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion

	_, err = arcClient.Update(ctx, required, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating AlertRelabelConfig object failed: %w", err)
	}
	return nil
}

func (c *Client) CreateOrUpdateValidatingWebhookConfiguration(ctx context.Context, w *admissionv1.ValidatingWebhookConfiguration) error {
	_, _, err := resourceapply.ApplyValidatingWebhookConfigurationImproved(
		ctx,
		c.kclient.AdmissionregistrationV1(),
		c.eventRecorder,
		w,
		c.resourceCache,
	)
	if err != nil {
		return fmt.Errorf("updating ValidatingWebhookConfiguration object failed: %w", err)
	}

	return nil
}

func (c *Client) CreateOrUpdateSecurityContextConstraints(ctx context.Context, s *secv1.SecurityContextConstraints) error {
	sccclient := c.ossclient.SecurityV1().SecurityContextConstraints()
	existing, err := sccclient.Get(ctx, s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sccclient.Create(ctx, s, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating SecurityContextConstraints object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving SecurityContextConstraints object failed: %w", err)
	}

	// the CRD version of SCC appears to require this.  We can try to chase why later.
	required := s.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	required.ResourceVersion = existing.ResourceVersion

	_, err = sccclient.Update(ctx, required, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating SecurityContextConstraints object failed: %w", err)
	}
	return nil
}

func (c *Client) CreateOrUpdateRoute(ctx context.Context, r *routev1.Route) error {
	rclient := c.osrclient.RouteV1().Routes(r.GetNamespace())
	existing, err := rclient.Get(ctx, r.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := rclient.Create(ctx, r, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating Route object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving Route object failed: %w", err)
	}

	required := r.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	required.ResourceVersion = existing.ResourceVersion

	_, err = rclient.Update(ctx, required, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating Route object failed: %w", err)
	}
	return nil
}

func (c *Client) GetRouteURL(ctx context.Context, r *routev1.Route) (*url.URL, error) {
	rclient := c.osrclient.RouteV1().Routes(r.GetNamespace())
	newRoute, err := rclient.Get(ctx, r.GetName(), metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting Route object failed: %w", err)
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
	pclient := c.mclient.MonitoringV1().Prometheuses(p.GetNamespace())
	existing, err := pclient.Get(ctx, p.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := pclient.Create(ctx, p, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating Prometheus object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving Prometheus object failed: %w", err)
	}

	required := p.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion
	_, err = pclient.Update(ctx, required, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating Prometheus object failed: %w", err)
	}
	return nil
}

func (c *Client) CreateOrUpdatePrometheusRule(ctx context.Context, p *monv1.PrometheusRule) error {
	pclient := c.mclient.MonitoringV1().PrometheusRules(p.GetNamespace())
	existing, err := pclient.Get(ctx, p.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := pclient.Create(ctx, p, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating PrometheusRule object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving PrometheusRule object failed: %w", err)
	}

	required := p.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion

	_, err = pclient.Update(ctx, required, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating PrometheusRule object failed: %w", err)
	}
	return nil
}

func (c *Client) CreateOrUpdateAlertmanager(ctx context.Context, a *monv1.Alertmanager) error {
	aclient := c.mclient.MonitoringV1().Alertmanagers(a.GetNamespace())
	existing, err := aclient.Get(ctx, a.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := aclient.Create(ctx, a, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating Alertmanager object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving Alertmanager object failed: %w", err)
	}

	required := a.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion

	_, err = aclient.Update(ctx, required, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating Alertmanager object failed: %w", err)
	}
	return nil
}

func (c *Client) DeleteAlertmanager(ctx context.Context, a *monv1.Alertmanager) error {
	return c.deleteResourceUntilGone(ctx, monv1.SchemeGroupVersion.WithResource("alertmanagers"), a, deleteTimeout)
}

func (c *Client) CreateOrUpdateThanosRuler(ctx context.Context, t *monv1.ThanosRuler) error {
	trclient := c.mclient.MonitoringV1().ThanosRulers(t.GetNamespace())
	existing, err := trclient.Get(ctx, t.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := trclient.Create(ctx, t, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating Thanos Ruler object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving Thanos Ruler object failed: %w", err)
	}

	required := t.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
	required.ResourceVersion = existing.ResourceVersion

	_, err = trclient.Update(ctx, required, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("retrieving Thanos Ruler object failed: %w", err)
	}
	return nil
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
		return fmt.Errorf("error listing configmaps in namespace %s with label selector %s: %w", namespace, ls, err)
	}

	for _, cm := range configMaps.Items {
		err := c.KubernetesInterface().CoreV1().ConfigMaps(namespace).Delete(ctx, cm.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("error deleting configmap: %s/%s: %w", namespace, cm.Name, err)
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
		return fmt.Errorf("error listing secrets in namespace %s with label selector %s: %w", namespace, ls, err)
	}

	for _, s := range secrets.Items {
		err := c.KubernetesInterface().CoreV1().Secrets(namespace).Delete(ctx, s.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("error deleting secret: %s/%s: %w", namespace, s.Name, err)
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
	return c.deleteResourceUntilGone(ctx, appsv1.SchemeGroupVersion.WithResource("deployments"), d, 5*time.Minute)
}

func (c *Client) DeletePodDisruptionBudget(ctx context.Context, pdb *policyv1.PodDisruptionBudget) error {
	err := c.kclient.PolicyV1().PodDisruptionBudgets(pdb.GetNamespace()).Delete(ctx, pdb.GetName(), deleteOptions(metav1.DeletePropagationForeground))
	if apierrors.IsNotFound(err) {
		return nil
	}

	return err
}

func (c *Client) DeletePrometheus(ctx context.Context, p *monv1.Prometheus) error {
	return c.deleteResourceUntilGone(ctx, monv1.SchemeGroupVersion.WithResource("prometheuses"), p, deleteTimeout)
}

func (c *Client) DeleteThanosRuler(ctx context.Context, tr *monv1.ThanosRuler) error {
	return c.deleteResourceUntilGone(ctx, monv1.SchemeGroupVersion.WithResource("thanosrulers"), tr, deleteTimeout)
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
		return fmt.Errorf("deleting ServiceMonitor object failed: %w", err)
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
		return fmt.Errorf("deleting PrometheusRule object failed: %w", err)
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

func wrapWithResource(kind string, name types.NamespacedName, err error) error {
	return wrapWithResourcef(kind, name, "%w", err)
}

func wrapWithResourcef(kind string, name types.NamespacedName, format string, a ...any) error {
	return fmt.Errorf("%s %q: %w", kind, name.String(), fmt.Errorf(format, a...))
}

// validatePrometheusResource is a helper method for ValidatePrometheus.
// It returns true only when the Prometheus resource is available and reconciled.
// NOTE: this function is refactored out of wait.Poll for testing
func (c Client) validatePrometheusResource(ctx context.Context, prom types.NamespacedName) (bool, []error) {
	p, err := c.mclient.MonitoringV1().Prometheuses(prom.Namespace).Get(ctx, prom.Name, metav1.GetOptions{})
	if err != nil {
		err = wrapWithResourcef("Prometheus", prom, "failed to get: %w", err)
		// Report Degraded=Unknown and Unavailable=Unknown if the API request failed.
		return false, []error{
			NewUnknownAvailabiltyError(err.Error()),
			NewUnknownDegradedError(err.Error()),
		}
	}

	avail, err := getMonitoringCondition(p.Status.Conditions, monv1.Available)
	if err != nil {
		// Report Degraded=Unknown and Unavailable=Unknown if the condition can't be found.
		err = wrapWithResource("Prometheus", prom, err)
		return false, []error{
			NewUnknownAvailabiltyError(err.Error()),
			NewUnknownDegradedError(err.Error()),
		}
	}

	if avail.Status == monv1.ConditionTrue {
		// Check the Reconciled condition.
		reconciled, err := getMonitoringCondition(p.Status.Conditions, monv1.Reconciled)
		if err != nil {
			// Report Degraded=Unknown if the condition can't be found.
			err = wrapWithResource("Prometheus", prom, err)
			return false, []error{NewUnknownDegradedError(err.Error())}
		}

		if reconciled.Status != monv1.ConditionTrue {
			err = wrapWithResourcef("Prometheus", prom, "%s: %s", reconciled.Reason, reconciled.Message)
			return false, []error{NewDegradedError(err.Error())}
		}

		// At this point, Prometheus is Available=True and Reconciled=True, stop
		// there.
		return true, nil
	}

	// Always report Degraded=True.
	err = wrapWithResourcef("Prometheus", prom, "%s: %s", avail.Reason, avail.Message)
	errs := []error{NewDegradedError(err.Error())}

	if avail.Status == monv1.ConditionFalse {
		// Report Available=False too when Prometheus is Available=False.
		errs = append(errs, NewAvailabilityError(err.Error()))
	}

	return false, errs
}

// ValidatePrometheus returns a nil error if the Prometheus object is fully available.
// Otherwise, it returns an aggregated error with one or multiple StateErrors.
func (c *Client) ValidatePrometheus(ctx context.Context, promNsName types.NamespacedName) error {
	validationErrors := []error{}

	pollErr := Poll(ctx, func(ctx context.Context) (bool, error) {
		var done bool
		done, validationErrors = c.validatePrometheusResource(ctx, promNsName)

		return done, nil
	}, WithPollInterval(10*time.Second))

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
	if err := Poll(ctx, func(ctx context.Context) (bool, error) {
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
	}, WithPollInterval(10*time.Second), WithLastError(&lastErr)); err != nil {
		return fmt.Errorf("waiting for Alertmanager %s/%s: %w", a.GetNamespace(), a.GetName(), err)
	}

	return nil
}

func (c *Client) WaitForThanosRuler(ctx context.Context, t *monv1.ThanosRuler) error {
	var lastErr error
	if err := Poll(ctx, func(ctx context.Context) (bool, error) {
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
	}, WithPollInterval(10*time.Second), WithLastError(&lastErr)); err != nil {
		return fmt.Errorf("waiting for Thanos Ruler %s/%s: %w", t.GetNamespace(), t.GetName(), err)
	}

	return nil
}

func (c *Client) CreateOrUpdateDeployment(ctx context.Context, dep *appsv1.Deployment) error {
	existing, err := c.kclient.AppsV1().Deployments(dep.GetNamespace()).Get(ctx, dep.GetName(), metav1.GetOptions{})

	if apierrors.IsNotFound(err) {
		err = c.CreateDeployment(ctx, dep)
		if err != nil {
			return fmt.Errorf("creating Deployment object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving Deployment object failed: %w", err)
	}
	if reflect.DeepEqual(dep.Spec, existing.Spec) {
		// Nothing to do, as the currently existing deployment is equivalent to the one that would be applied.
		return nil
	}

	required := dep.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	err = c.UpdateDeployment(ctx, required)
	if err != nil {
		var statusErr *apierrors.StatusError
		if errors.As(err, &statusErr) && statusErr.ErrStatus.Code == 422 && statusErr.ErrStatus.Reason == metav1.StatusReasonInvalid {
			// try to delete Deployment
			err = c.DeleteDeployment(ctx, existing)
			if err != nil {
				return fmt.Errorf("deleting Deployment object failed: %w", err)
			}
			err = c.CreateDeployment(ctx, required)
			if err != nil {
				return fmt.Errorf("creating Deployment object failed after update failed: %w", err)
			}
		}
		return fmt.Errorf("updating Deployment object failed: %w", err)
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
	if err := Poll(ctx, func(ctx context.Context) (bool, error) {
		d, err := c.kclient.AppsV1().Deployments(dep.GetNamespace()).Get(ctx, dep.GetName(), metav1.GetOptions{})
		if err != nil {
			lastErr = err
			klog.V(4).ErrorS(err, "WaitForDeploymentRollout: failed to get Deployment")
			return false, nil
		}

		if d.Generation > d.Status.ObservedGeneration {
			lastErr = fmt.Errorf("current generation %d, observed generation %d",
				d.Generation, d.Status.ObservedGeneration)
			return false, nil
		}

		if d.Status.UpdatedReplicas != d.Status.Replicas {
			lastErr = fmt.Errorf("the number of pods targeted by the deployment (%d pods) is different "+
				"from the number of pods targeted by the deployment that have the desired template spec (%d pods)",
				d.Status.Replicas, d.Status.UpdatedReplicas)
			return false, nil
		}

		if d.Status.UnavailableReplicas != 0 {
			lastErr = fmt.Errorf("got %d unavailable replicas",
				d.Status.UnavailableReplicas)
			return false, nil
		}

		return true, nil
	}, WithLastError(&lastErr)); err != nil {
		return fmt.Errorf("waiting for DeploymentRollout of %s/%s: %w", dep.GetNamespace(), dep.GetName(), err)
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
	if err := Poll(ctx, func(ctx context.Context) (bool, error) {
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
	}, WithPollTimeout(timeout), WithLastError(&lastErr)); err != nil {
		return fmt.Errorf("waiting for deletion of %s %s/%s: %w", gvr.String(), obj.GetNamespace(), obj.GetName(), err)
	}

	return nil
}

func (c *Client) WaitForStatefulsetRollout(ctx context.Context, sts *appsv1.StatefulSet) error {
	var lastErr error
	if err := Poll(ctx, func(ctx context.Context) (bool, error) {
		s, err := c.kclient.AppsV1().StatefulSets(sts.GetNamespace()).Get(ctx, sts.GetName(), metav1.GetOptions{})
		if err != nil {
			lastErr = err
			klog.V(4).ErrorS(err, "WaitForStatefulsetRollout: failed to get StatefulSet")
			return false, nil
		}
		if s.Generation > s.Status.ObservedGeneration {
			lastErr = fmt.Errorf("expected generation %d, observed generation: %d",
				s.Generation, s.Status.ObservedGeneration)
			return false, nil
		}
		if s.Status.UpdatedReplicas != s.Status.Replicas {
			lastErr = fmt.Errorf("expected %d replicas, got %d updated replicas",
				s.Status.Replicas, s.Status.UpdatedReplicas)
			return false, nil
		}
		if s.Status.ReadyReplicas != s.Status.Replicas {
			lastErr = fmt.Errorf("expected %d replicas, got %d ready replicas",
				s.Status.Replicas, s.Status.ReadyReplicas)
			return false, nil
		}
		return true, nil
	}, WithLastError(&lastErr)); err != nil {
		return fmt.Errorf("waiting for StatefulsetRollout of %s/%s: %w", sts.GetNamespace(), sts.GetName(), err)
	}
	return nil
}

func (c *Client) WaitForSecret(ctx context.Context, s *v1.Secret) (*v1.Secret, error) {
	var result *v1.Secret
	var lastErr error
	if err := Poll(ctx, func(ctx context.Context) (bool, error) {
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
	}, WithLastError(&lastErr)); err != nil {
		return nil, fmt.Errorf("waiting for secret %s/%s: %w", s.GetNamespace(), s.GetName(), err)
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
	if err := Poll(ctx, func(ctx context.Context) (bool, error) {
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
	}, WithLastError(&lastErr)); err != nil {
		return nil, fmt.Errorf("waiting for ConfigMap %s/%s: %w", cm.GetNamespace(), cm.GetName(), err)
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
	if err := Poll(ctx, func(ctx context.Context) (bool, error) {
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
	}, WithLastError(&lastErr)); err != nil {
		return host, fmt.Errorf("waiting for route %s/%s: %w", r.GetNamespace(), r.GetName(), err)
	}

	return host, nil
}

func (c *Client) CreateOrUpdateDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) error {
	existing, err := c.kclient.AppsV1().DaemonSets(ds.GetNamespace()).Get(ctx, ds.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		err = c.CreateDaemonSet(ctx, ds)
		if err != nil {
			return fmt.Errorf("creating DaemonSet object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving DaemonSet object failed: %w", err)
	}

	required := ds.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	err = c.UpdateDaemonSet(ctx, required)
	if err != nil {
		var statusErr *apierrors.StatusError
		if errors.As(err, &statusErr) && statusErr.ErrStatus.Code == 422 && statusErr.ErrStatus.Reason == metav1.StatusReasonInvalid {
			// try to delete DaemonSet
			err = c.DeleteDaemonSet(ctx, existing)
			if err != nil {
				return fmt.Errorf("deleting DaemonSet object failed: %w", err)
			}

			err = c.CreateDaemonSet(ctx, required)
			if err != nil {
				return fmt.Errorf("creating DaemonSet object failed after update failed: %w", err)
			}
		}
		return fmt.Errorf("updating DaemonSet object failed: %w", err)
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
	if err := Poll(ctx, func(ctx context.Context) (bool, error) {
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
			lastErr = fmt.Errorf("current generation %d, observed generation: %d",
				d.Generation, d.Status.ObservedGeneration)
			return false, nil
		}

		if d.Spec.UpdateStrategy.RollingUpdate != nil && d.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable != nil {
			maxUnavailableIntStr = *d.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable
		}
		maxUnavailable, intstrErr := intstr.GetScaledValueFromIntOrPercent(&maxUnavailableIntStr, int(want), true)

		if intstrErr != nil {
			lastErr = fmt.Errorf("The daemonset has an invalid MaxUnavailable value: %w", intstrErr)
			return false, nil
		}

		if int(numberUnavailable) > maxUnavailable {
			lastErr = fmt.Errorf("Too many daemonset pods are unavailable (%d > %d max unavailable).", numberUnavailable, maxUnavailable)
			return false, nil
		}
		return true, nil
	}, WithLastError(&lastErr)); err != nil {
		return fmt.Errorf("waiting for DaemonSetRollout of %s/%s: %w", ds.GetNamespace(), ds.GetName(), err)
	}

	return nil
}

func (c *Client) CreateOrUpdateSecret(ctx context.Context, s *v1.Secret) error {
	_, _, err := resourceapply.ApplySecret(ctx, c.kclient.CoreV1(), c.eventRecorder, s)
	return err
}

func (c *Client) CreateIfNotExistSecret(ctx context.Context, s *v1.Secret) error {
	sClient := c.kclient.CoreV1().Secrets(s.GetNamespace())
	_, err := sClient.Get(ctx, s.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := sClient.Create(ctx, s, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating Secret object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving Secret object failed: %w", err)
	}
	return nil
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
	_, _, err := resourceapply.ApplyConfigMap(ctx, c.kclient.CoreV1(), c.eventRecorder, cm)
	return err
}

func (c *Client) CreateIfNotExistConfigMap(ctx context.Context, cm *v1.ConfigMap) (*v1.ConfigMap, error) {
	cClient := c.kclient.CoreV1().ConfigMaps(cm.GetNamespace())
	res, err := cClient.Get(ctx, cm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		res, err := cClient.Create(ctx, cm, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("creating ConfigMap object failed: %w", err)
		}
		return res, nil
	}
	if err != nil {
		return nil, fmt.Errorf("retrieving ConfigMap object failed: %w", err)
	}
	return res, nil
}

func (c *Client) CreateOrUpdatePodDisruptionBudget(ctx context.Context, pdb *policyv1.PodDisruptionBudget) error {
	_, _, err := resourceapply.ApplyPodDisruptionBudget(ctx, c.kclient.PolicyV1(), c.eventRecorder, pdb)
	return err
}

func (c *Client) CreateOrUpdateService(ctx context.Context, svc *v1.Service) error {
	_, _, err := resourceapply.ApplyService(ctx, c.kclient.CoreV1(), c.eventRecorder, svc)
	return err
}

func (c *Client) CreateOrUpdateRoleBinding(ctx context.Context, rb *rbacv1.RoleBinding) error {
	_, _, err := resourceapply.ApplyRoleBinding(ctx, c.kclient.RbacV1(), c.eventRecorder, rb)
	return err
}

func (c *Client) CreateOrUpdateRole(ctx context.Context, r *rbacv1.Role) error {
	_, _, err := resourceapply.ApplyRole(ctx, c.kclient.RbacV1(), c.eventRecorder, r)
	return err
}

func (c *Client) CreateOrUpdateClusterRole(ctx context.Context, cr *rbacv1.ClusterRole) error {
	_, _, err := resourceapply.ApplyClusterRole(ctx, c.kclient.RbacV1(), c.eventRecorder, cr)
	return err
}

func (c *Client) CreateOrUpdateClusterRoleBinding(ctx context.Context, crb *rbacv1.ClusterRoleBinding) error {
	_, _, err := resourceapply.ApplyClusterRoleBinding(ctx, c.kclient.RbacV1(), c.eventRecorder, crb)
	return err
}

func (c *Client) CreateOrUpdateServiceAccount(ctx context.Context, sa *v1.ServiceAccount) error {
	_, _, err := resourceapply.ApplyServiceAccountImproved(
		ctx,
		c.kclient.CoreV1(),
		c.eventRecorder,
		sa,
		c.resourceCache,
	)

	if err != nil {
		return fmt.Errorf("updating ServiceAccount object failed: %w", err)
	}
	return nil
}

func (c *Client) CreateOrUpdateServiceMonitor(ctx context.Context, sm *monv1.ServiceMonitor) error {
	smClient := c.mclient.MonitoringV1().ServiceMonitors(sm.GetNamespace())
	existing, err := smClient.Get(ctx, sm.GetName(), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err := smClient.Create(ctx, sm, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("creating ServiceMonitor object failed: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("retrieving ServiceMonitor object failed: %w", err)
	}

	required := sm.DeepCopy()
	mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)

	required.ResourceVersion = existing.ResourceVersion
	_, err = smClient.Update(ctx, required, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating ServiceMonitor object failed: %w", err)
	}
	return nil
}

func (c *Client) CreateOrUpdateAPIService(ctx context.Context, apiService *apiregistrationv1.APIService) error {
	_, _, err := resourceapply.ApplyAPIService(ctx, c.aggclient.ApiregistrationV1(), c.eventRecorder, apiService)
	return err
}

func (c *Client) WaitForCRDReady(ctx context.Context, crd *extensionsobj.CustomResourceDefinition) error {
	return Poll(ctx, func(ctx context.Context) (bool, error) {
		return c.CRDReady(ctx, crd)
	}, WithPollInterval(5*time.Second))
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
				return false, fmt.Errorf("CRD naming conflict (%s): %v", crd.ObjectMeta.Name, cond.Reason)
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

// CreateOrUpdateConsolePlugin function uses retries because API requests related to the ConsolePlugin resource
// may depend on the availability of a conversion container. This container is part of the console-operator Pod, which is not duplicated.
// If this pod is down (due to restarts for upgrades or other reasons), transient failures will be reported.
// This is a temporary mitigation. The availability of the conversion container will be improved in the future.
// For more information, see: https://issues.redhat.com/browse/OCPBUGS-25803
func (c *Client) CreateOrUpdateConsolePlugin(ctx context.Context, plg *consolev1.ConsolePlugin) error {
	conClient := c.osconclient.ConsoleV1().ConsolePlugins()

	var lastErr error
	if err := Poll(ctx, func(context.Context) (bool, error) {
		existing, err := conClient.Get(ctx, plg.GetName(), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err = conClient.Create(ctx, plg, metav1.CreateOptions{})
			if err != nil {
				lastErr = fmt.Errorf("creating ConsolePlugin object failed: %w", err)
				return false, nil
			}
			return true, nil
		}
		if err != nil {
			lastErr = fmt.Errorf("retrieving ConsolePlugin object failed: %w", err)
			return false, nil
		}

		required := plg.DeepCopy()
		mergeMetadata(&required.ObjectMeta, existing.ObjectMeta)
		required.ResourceVersion = existing.ResourceVersion

		_, err = conClient.Update(ctx, required, metav1.UpdateOptions{})
		if err != nil {
			lastErr = fmt.Errorf("updating ConsolePlugin object failed: %w", err)
			return false, nil
		}
		return true, nil
	}, WithPollInterval(5*time.Second), WithLastError(&lastErr)); err != nil {
		return fmt.Errorf("waiting for ConsolePlugin failed: %w", err)
	}
	return nil
}

func (c *Client) RegisterConsolePlugin(ctx context.Context, name string) error {
	consoleClient := c.osopclient.OperatorV1().Consoles()

	console, err := consoleClient.Get(ctx, clusterConsole, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("retrieving console %q failed: %w", clusterConsole, err)
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
	if err != nil {
		return fmt.Errorf("registering console-plugin %q with console %q failed: %w", name, clusterConsole, err)
	}
	return nil
}

// VPACustomResourceDefinitionPresent checks if VerticalPodAutoscaler CRD is present in the cluster.
func (c *Client) VPACustomResourceDefinitionPresent(ctx context.Context, lastKnownVPACustomResourceDefinitionPresent *bool) (*bool, error) {
	_, err := c.ApiExtensionsInterface().ApiextensionsV1().CustomResourceDefinitions().Get(ctx, VerticalPodAutoscalerCRDMetadataName, metav1.GetOptions{})
	if err != nil {
		// VPA CRD is absent.
		if apierrors.IsNotFound(err) {
			return ptr.To(false), nil
		}

		// See if we have an idea of the state of the CRD's presence before the transient error occurred.
		// If we do, resort to that since we do not want this to cause unnecessary reconciles.
		if lastKnownVPACustomResourceDefinitionPresent != nil {
			return lastKnownVPACustomResourceDefinitionPresent, nil
		}

		// If we don't, throw.
		return nil, fmt.Errorf("failed to get %s CRD: %w", VerticalPodAutoscalerCRDMetadataName, err)
	}

	// VPA CRD is present.
	return ptr.To(true), nil
}

// mergeMetadata merges labels and annotations from `existing` map into `required` one where `required` has precedence
// over `existing` keys and values. Additionally, function performs filtering of labels and annotations from `exiting` map
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

type pollOptions struct {
	timeout   time.Duration
	interval  time.Duration
	lastError *error
}

func WithPollTimeout(d time.Duration) func(o *pollOptions) {
	return func(o *pollOptions) {
		o.timeout = d
	}
}

func WithPollInterval(d time.Duration) func(o *pollOptions) {
	return func(o *pollOptions) {
		o.interval = d
	}
}

func WithLastError(e *error) func(o *pollOptions) {
	return func(o *pollOptions) {
		o.lastError = e
	}
}

// Poll is a wrapper around wait.PollUntilContextTimeout that allows adding the
// passed lastError into the final error if set by the condition, adding more
// context to the "context deadline exceeded" error.
// By design the condition function receives a context which is NOT canceled
// when the poll operation times out.
func Poll(ctx context.Context, condition wait.ConditionWithContextFunc, options ...func(o *pollOptions)) error {
	opts := pollOptions{
		timeout:  5 * time.Minute,
		interval: time.Second,
	}
	for _, o := range options {
		o(&opts)
	}

	var (
		conditionErr error
		done         bool
	)
	if err := wait.PollUntilContextTimeout(ctx, opts.interval, opts.timeout, false, func(_ context.Context) (bool, error) {
		// Don't use the context passed to the condition function to avoid
		// errors when the condition function calls the API server.
		done, conditionErr = condition(ctx)

		return done, conditionErr
	}); err != nil {
		// Add the last error when available and relevant.
		if opts.lastError != nil && *opts.lastError != nil && !errors.Is(*opts.lastError, err) {
			return fmt.Errorf("%w: %w", err, *opts.lastError)
		}

		if !errors.Is(err, conditionErr) {
			err = fmt.Errorf("%w: %w", err, conditionErr)
		}

		return err
	}

	return nil
}
