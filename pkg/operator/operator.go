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

package operator

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blang/semver/v4"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/api/features"
	configv1client "github.com/openshift/client-go/config/clientset/versioned"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/csr"
	"github.com/openshift/library-go/pkg/operator/events"
	certapiv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	apiutilerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/alert"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/pkg/metrics"
	"github.com/openshift/cluster-monitoring-operator/pkg/tasks"
)

// InfrastructureConfig stores information about the cluster infrastructure
// which is useful for the operator.
type InfrastructureConfig struct {
	highlyAvailableInfrastructure bool
	hostedControlPlane            bool
}

var (
	// The cluster-policy-controller will automatically approve the
	// CertificateSigningRequest resources issued for the prometheus-k8s
	// service account.
	// See https://github.com/openshift/cluster-policy-controller/blob/cc787e1b1e177696817b66689a03471914083a67/pkg/cmd/controller/csr.go#L21-L46.
	csrOption = csr.CSROption{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "system:openshift:openshift-monitoring-",
			Labels: map[string]string{
				"metrics.openshift.io/csr.subject": "prometheus",
			},
		},
		Subject:    &pkix.Name{CommonName: "system:serviceaccount:openshift-monitoring:prometheus-k8s"},
		SignerName: certapiv1.KubeAPIServerClientSignerName,
	}

	// To identify "invalid UWM config only" failures
	ErrUserWorkloadInvalidConfiguration = fmt.Errorf("invalid UWM configuration")
)

// NewDefaultInfrastructureConfig returns a default InfrastructureConfig.
func NewDefaultInfrastructureConfig() *InfrastructureConfig {
	return &InfrastructureConfig{
		highlyAvailableInfrastructure: true,
		hostedControlPlane:            false,
	}
}

// NewInfrastructureConfig returns a new InfrastructureConfig from the given config.openshift.io/Infrastructure resource.
func NewInfrastructureConfig(i *configv1.Infrastructure) *InfrastructureConfig {
	ic := NewDefaultInfrastructureConfig()

	if i.Status.InfrastructureTopology == configv1.SingleReplicaTopologyMode {
		ic.highlyAvailableInfrastructure = false
	}
	if i.Status.ControlPlaneTopology == configv1.ExternalTopologyMode {
		ic.hostedControlPlane = true
	}

	return ic
}

// HighlyAvailableInfrastructure implements the InfrastructureReader interface.
func (ic *InfrastructureConfig) HighlyAvailableInfrastructure() bool {
	return ic.highlyAvailableInfrastructure
}

// HostedControlPlane implements the InfrastructureReader interface.
func (ic *InfrastructureConfig) HostedControlPlane() bool {
	return ic.hostedControlPlane
}

// ProxyConfig stores information about the proxy configuration.
type ProxyConfig struct {
	httpProxy  string
	httpsProxy string
	noProxy    string
}

// NewProxyConfig returns a new ProxyConfig from the given config.openshift.io/Proxy resource.
func NewProxyConfig(p *configv1.Proxy) *ProxyConfig {
	return &ProxyConfig{
		httpProxy:  p.Status.HTTPProxy,
		httpsProxy: p.Status.HTTPSProxy,
		noProxy:    p.Status.NoProxy,
	}
}

// HTTPProxy implements the ProxyReader interface.
func (pc *ProxyConfig) HTTPProxy() string {
	return pc.httpProxy
}

// HTTPSProxy implements the ProxyReader interface.
func (pc *ProxyConfig) HTTPSProxy() string {
	return pc.httpsProxy
}

// NoProxy implements the ProxyReader interface.
func (pc *ProxyConfig) NoProxy() string {
	return pc.noProxy
}

const (
	resyncPeriod         = 15 * time.Minute
	reconciliationPeriod = 5 * time.Minute

	// see https://github.com/kubernetes/apiserver/blob/b571c70e6e823fd78910c3f5b9be895a756f4cbb/pkg/server/options/authentication.go#L239
	apiAuthenticationConfigMap    = "kube-system/extension-apiserver-authentication"
	kubeletServingCAConfigMap     = "openshift-config-managed/kubelet-serving-ca"
	telemeterCABundleConfigMap    = "openshift-monitoring/telemeter-trusted-ca-bundle"
	alertmanagerCABundleConfigMap = "openshift-monitoring/alertmanager-trusted-ca-bundle"
	grpcTLS                       = "openshift-monitoring/grpc-tls"
	metricsClientCerts            = "openshift-monitoring/metrics-client-certs"
	federateClientCerts           = "openshift-monitoring/federate-client-certs"

	// Canonical name of the cluster-wide infrastructure resource.
	clusterResourceName = "cluster"

	UWMTaskPrefix = "UpdatingUserWorkload"
)

type Operator struct {
	namespace, namespaceUserWorkload string

	configMapName             string
	userWorkloadConfigMapName string
	images                    map[string]string
	telemetryMatches          []string
	remoteWrite               bool
	CollectionProfilesEnabled bool

	lastKnowInfrastructureConfig *InfrastructureConfig
	lastKnowProxyConfig          *ProxyConfig
	lastKnownApiServerConfig     *manifests.APIServerConfig
	lastKnownConsoleConfig       *configv1.Console

	client *client.Client

	cmapInf              cache.SharedIndexInformer
	informers            []cache.SharedIndexInformer
	informerFactories    []informers.SharedInformerFactory
	controllersToRunFunc []func(ctx context.Context, workers int)

	queue workqueue.TypedRateLimitingInterface[string]

	failedReconcileAttempts int

	assets *manifests.Assets

	ruleController    *alert.RuleController
	relabelController *alert.RelabelConfigController

	// lastKnownVPACustomResourceDefinitionPresent is a boolean pointer that
	// remembers the presence of the VPA CRD in the cluster between
	// kube-state-metrics task reconciliations. It is used to determine
	// whether to enable kube-state-metrics custom-resource-state-based
	// metrics for VPA CRs, even in cases where the Kube API may emit a
	// transient error (errors excluding `IsNotFound`) on the VPA CRD `GET`
	// requests (to determine its presence).
	// * `true` indicates that the VPA CRD is already present in the
	// cluster, and the custom-resource-state-based metrics can be safely
	// enabled.
	// * `false` indicates that the VPA CRD is not present in the cluster,
	// and enabling the custom-resource-state-based metrics will cause
	// kube-state-metrics to error (affecting `KubeStateMetricsListErrors`).
	// * `nil` indicates that the presence of the VPA CRD is unknown, and
	// the operator will attempt to determine the presence of the VPA CRD in
	// the current reconciliation cycle, and remember its state in the next
	// one. In the case where the VPA CRD is added or removed between
	// reconciliations, the variable "forgets" it, and is set to `nil`,
	// triggering a check on the next cycle.
	lastKnownVPACustomResourceDefinitionPresent *bool
}

func New(
	ctx context.Context,
	config *rest.Config,
	version, namespace, namespaceUserWorkload, configMapName, userWorkloadConfigMapName string,
	remoteWrite bool,
	images map[string]string,
	telemetryMatches []string,
	a *manifests.Assets,
) (*Operator, error) {
	kclient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes clientset client: %w", err)
	}
	controllerRef, err := events.GetControllerReferenceForCurrentPod(ctx, kclient, namespace, nil)
	if err != nil {
		klog.Warningf("unable to get owner reference (falling back to namespace): %v", err)
	}

	eventRecorder := events.NewKubeRecorderWithOptions(
		kclient.CoreV1().Events(namespace),
		events.RecommendedClusterSingletonCorrelatorOptions(),
		"cluster-monitoring-operator",
		controllerRef,
	)

	configClient, err := configv1client.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	c, err := client.NewForConfig(config, version, namespace, namespaceUserWorkload, client.KubernetesClient(kclient), client.OpenshiftConfigClient(configClient), client.EventRecorder(eventRecorder))
	if err != nil {
		return nil, err
	}

	ruleController, err := alert.NewRuleController(ctx, c, version)
	if err != nil {
		return nil, fmt.Errorf("failed to create alerting rule controller: %w", err)
	}

	relabelController, err := alert.NewRelabelConfigController(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("failed to create alert relabel config controller: %w", err)
	}

	o := &Operator{
		images:                    images,
		telemetryMatches:          telemetryMatches,
		configMapName:             configMapName,
		userWorkloadConfigMapName: userWorkloadConfigMapName,
		remoteWrite:               remoteWrite,
		CollectionProfilesEnabled: false,
		namespace:                 namespace,
		namespaceUserWorkload:     namespaceUserWorkload,
		client:                    c,
		queue: workqueue.NewTypedRateLimitingQueueWithConfig[string](
			workqueue.NewTypedItemExponentialFailureRateLimiter[string](50*time.Millisecond, 3*time.Minute),
			workqueue.TypedRateLimitingQueueConfig[string]{Name: "cluster-monitoring"},
		),
		informers:            make([]cache.SharedIndexInformer, 0),
		assets:               a,
		informerFactories:    make([]informers.SharedInformerFactory, 0),
		controllersToRunFunc: make([]func(context.Context, int), 0),
		ruleController:       ruleController,
		relabelController:    relabelController,
	}

	informer := cache.NewSharedIndexInformer(
		o.client.SecretListWatchForNamespace(namespace), &v1.Secret{}, resyncPeriod, cache.Indexers{},
	)
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    o.handleEvent,
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
		DeleteFunc: o.handleEvent,
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	o.cmapInf = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace(namespace), &v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	_, err = o.cmapInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    o.handleEvent,
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
		DeleteFunc: o.handleEvent,
	})
	if err != nil {
		return nil, err
	}

	informer = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace(namespaceUserWorkload), &v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    o.handleEvent,
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
		DeleteFunc: o.handleEvent,
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace("kube-system"),
		&v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace("openshift-config-managed"),
		&v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace("openshift-config"),
		&v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.InfrastructureListWatchForResource(ctx, clusterResourceName),
		&configv1.Infrastructure{}, resyncPeriod, cache.Indexers{},
	)
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ApiServersListWatchForResource(ctx, clusterResourceName),
		&configv1.APIServer{}, resyncPeriod, cache.Indexers{},
	)

	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) {
			o.handleEvent(newObj)
		},
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ConsoleListWatch(ctx),
		&configv1.Console{}, resyncPeriod, cache.Indexers{},
	)

	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) {
			o.handleEvent(newObj)
		},
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ClusterOperatorListWatch(ctx, "ingress"),
		&configv1.ClusterOperator{}, resyncPeriod, cache.Indexers{},
	)

	// According to the component-selection enhancement proposal [1] the
	// ingress cluster operator (or capability) could be added after an
	// installation where this functionality was initially turned off. The
	// other way around is not possible (install with ingress and deactivate
	// later).
	// So we only add a watch for the add event here.
	// [1] https://github.com/openshift/enhancements/blob/ab2b0aea4291cb74a49bca1983013d154d386cb7/enhancements/installer/component-selection.m#capabilities-can-be-installed
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: o.handleEvent,
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	// Many of the cluster capabilities such as Console can be enabled after
	// installation. So this watches for any updates to the ClusterVersion - version
	informer = cache.NewSharedIndexInformer(
		o.client.ClusterVersionListWatch(ctx, "version"),
		&configv1.ClusterVersion{}, resyncPeriod, cache.Indexers{},
	)
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.VerticalPodAutoscalerCRDListWatch(ctx),
		&apiextv1.CustomResourceDefinition{}, resyncPeriod, cache.Indexers{},
	)
	// Only trigger reconciliation on the addition or removal of VPA CRDs.
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    o.handleEvent,
		DeleteFunc: o.handleEvent,
	})
	if err != nil {
		return nil, err
	}
	o.informers = append(o.informers, informer)

	kubeInformersOperatorNS := informers.NewSharedInformerFactoryWithOptions(
		c.KubernetesInterface(),
		resyncPeriod,
		informers.WithNamespace(namespace),
	)
	o.informerFactories = append(o.informerFactories, kubeInformersOperatorNS)

	configInformers := configv1informers.NewSharedInformerFactory(configClient, 10*time.Minute)
	missingVersion := "0.0.1-snapshot"

	// By default, when the enabled/disabled list of featuregates changes,
	// os.Exit is called which will trigger a restart of the container and
	// the new container will get the updated value.
	featureGateAccessor := featuregates.NewFeatureGateAccess(
		version, missingVersion,
		configInformers.Config().V1().ClusterVersions(),
		configInformers.Config().V1().FeatureGates(),
		eventRecorder,
	)
	go featureGateAccessor.Run(ctx)
	go configInformers.Start(ctx.Done())

	select {
	case <-featureGateAccessor.InitialFeatureGatesObserved():
		featureGates, err := featureGateAccessor.CurrentFeatureGates()
		if err != nil {
			return nil, err
		}
		o.CollectionProfilesEnabled = featureGates.Enabled(features.FeatureGateMetricsCollectionProfiles)
	case <-time.After(1 * time.Minute):
		return nil, fmt.Errorf("timed out waiting for FeatureGate detection")
	}

	// csrController runs a controller that requests a client TLS certificate
	// for Prometheus k8s. This certificate is used to authenticate against the
	// /metrics endpoint of the targets.
	csrController, err := csr.NewClientCertificateController(
		csr.ClientCertOption{
			SecretNamespace: "openshift-monitoring",
			SecretName:      "metrics-client-certs",
			AdditionalAnnotations: certrotation.AdditionalAnnotations{
				JiraComponent: "Monitoring",
			},
		},
		csrOption,
		kubeInformersOperatorNS.Certificates().V1().CertificateSigningRequests(),
		o.client.KubernetesInterface().CertificatesV1().CertificateSigningRequests(),
		kubeInformersOperatorNS.Core().V1().Secrets(),
		o.client.KubernetesInterface().CoreV1(),
		o.client.EventRecorder(),
		"OpenShiftMonitoringClientCertRequester",
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate controller: %w", err)
	}

	// csrFederateController runs a controller that requests a client TLS
	// certificate for the telemeter client. This certificate is used to
	// authenticate against the Prometheus /federate API endpoint.
	csrFederateController, err := csr.NewClientCertificateController(
		csr.ClientCertOption{
			SecretNamespace: "openshift-monitoring",
			SecretName:      "federate-client-certs",
			AdditionalAnnotations: certrotation.AdditionalAnnotations{
				JiraComponent: "Monitoring",
			},
		},
		csrOption,
		kubeInformersOperatorNS.Certificates().V1().CertificateSigningRequests(),
		o.client.KubernetesInterface().CertificatesV1().CertificateSigningRequests(),
		kubeInformersOperatorNS.Core().V1().Secrets(),
		o.client.KubernetesInterface().CoreV1(),
		o.client.EventRecorder(),
		"OpenShiftMonitoringTelemeterClientCertRequester",
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create federate certificate controller: %w", err)
	}

	o.controllersToRunFunc = append(o.controllersToRunFunc, csrFederateController.Run, csrController.Run)

	o.controllersToRunFunc = append(o.controllersToRunFunc, o.ruleController.Run, o.relabelController.Run)

	return o, nil
}

// Run the controller.
func (o *Operator) Run(ctx context.Context) error {
	stopc := ctx.Done()
	defer o.queue.ShutDown()

	errChan := make(chan error)
	go func() {
		v, err := o.client.KubernetesInterface().Discovery().ServerVersion()
		if err != nil {
			errChan <- fmt.Errorf("communicating with server failed: %w", err)
			return
		}
		klog.V(4).Infof("Connection established (cluster-version: %s)", v)

		errChan <- nil
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return err
		}
	case <-stopc:
		return nil
	}

	go o.cmapInf.Run(stopc)
	synced := []cache.InformerSynced{o.cmapInf.HasSynced}
	for _, inf := range o.informers {
		go inf.Run(stopc)
		synced = append(synced, inf.HasSynced)
	}
	for _, f := range o.informerFactories {
		f.Start(stopc)
	}

	klog.V(4).Info("Waiting for initial cache sync.")
	ok := cache.WaitForCacheSync(stopc, synced...)
	if !ok {
		return errors.New("failed to sync informers")
	}
	for _, f := range o.informerFactories {
		f.WaitForCacheSync(stopc)
	}
	klog.V(4).Info("Initial cache sync done.")

	for _, r := range o.controllersToRunFunc {
		go r(ctx, 1)
	}

	go o.worker(ctx)

	ticker := time.NewTicker(reconciliationPeriod)
	defer ticker.Stop()

	key := o.namespace + "/" + o.configMapName
	_, exists, _ := o.cmapInf.GetStore().GetByKey(key)
	if !exists {
		klog.Infof("ConfigMap to configure stack does not exist. Reconciling with default config every %s.", reconciliationPeriod)
		o.enqueue(key)
	}

	for {
		select {
		case <-stopc:
			return nil
		case <-ticker.C:
			_, exists, _ := o.cmapInf.GetStore().GetByKey(key)
			if !exists {
				klog.Infof("ConfigMap to configure stack does not exist. Reconciling with default config every %s.", reconciliationPeriod)
				o.enqueue(key)
			}
		}
	}
}

func (o *Operator) keyFunc(obj interface{}) (string, bool) {
	k, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("creating key failed, err: %s", err)
		return k, false
	}
	return k, true
}

func (o *Operator) handleEvent(obj interface{}) {
	cmoConfigMap := o.namespace + "/" + o.configMapName

	switch obj.(type) {
	case *configv1.Infrastructure,
		*configv1.APIServer,
		*configv1.Console,
		*configv1.ClusterOperator,
		*configv1.ClusterVersion,
		// Currently, the CRDs that trigger reconciliation are:
		// * verticalpodautoscalers.autoscaling.k8s.io
		*apiextv1.CustomResourceDefinition:
		// Log GroupKind and Name of the obj
		rtObj := obj.(k8sruntime.Object)
		gk := rtObj.GetObjectKind().GroupVersionKind().GroupKind()
		metaObj := obj.(metav1.Object)
		name := metaObj.GetName()
		if ns := metaObj.GetNamespace(); ns != "" {
			name = ns + "/" + name
		}
		// NOTE: use %T to print the type if the gv information is absent
		objKind := gk.String()
		if objKind == "" {
			objKind = fmt.Sprintf("%T", obj)
		}
		klog.Infof("Triggering an update due to a change in %s/%s", objKind, name)
		o.enqueue(cmoConfigMap)
		return
	}

	// key represents the "namespace/name" of the object.
	key, ok := o.keyFunc(obj)
	if !ok {
		return
	}

	klog.V(5).Infof("ConfigMap or Secret updated: %s", key)

	uwmConfigMap := o.namespaceUserWorkload + "/" + o.userWorkloadConfigMapName

	switch key {
	case cmoConfigMap:
	case apiAuthenticationConfigMap:
	case kubeletServingCAConfigMap:
	case telemeterCABundleConfigMap:
	case alertmanagerCABundleConfigMap:
	case grpcTLS:
	case metricsClientCerts:
	case federateClientCerts:
	case uwmConfigMap:
	default:
		klog.V(5).Infof("ConfigMap or Secret (%s) not triggering an update.", key)
		return
	}

	klog.Infof("Triggering an update due to ConfigMap or Secret: %s", key)

	// Always enqueue the cluster monitoring operator configmap.
	// That way we reuse the same synchronization logic for all triggering object changes.
	o.enqueue(cmoConfigMap)
}

func (o *Operator) worker(ctx context.Context) {
	for o.processNextWorkItem(ctx) {
	}
}

func (o *Operator) processNextWorkItem(ctx context.Context) bool {
	key, quit := o.queue.Get()
	if quit {
		return false
	}
	defer o.queue.Done(key)

	metrics.ReconcileAttempts.Inc()
	err := o.sync(ctx, key)
	if err == nil {
		metrics.ReconcileStatus.Set(1)
		o.queue.Forget(key)
		return true
	}

	metrics.ReconcileStatus.Set(0)
	klog.Errorf("Syncing %q failed", key)
	utilruntime.HandleError(fmt.Errorf("sync %q failed: %w", key, err))
	o.queue.AddRateLimited(key)

	return true
}

func (o *Operator) enqueue(obj interface{}) {
	if obj == nil {
		return
	}

	key, ok := obj.(string)
	if !ok {
		key, ok = o.keyFunc(obj)
		if !ok {
			return
		}
	}

	o.queue.Add(key)
}

type proxyConfigSupplier func(context.Context) (*ProxyConfig, error)

func getProxyReader(ctx context.Context, config *manifests.Config, proxyConfigSupplier proxyConfigSupplier) manifests.ProxyReader {
	if config.HTTPProxy() != "" || config.HTTPSProxy() != "" || config.NoProxy() != "" {
		return config
	}

	clusterProxyConfig, err := proxyConfigSupplier(ctx)
	if err != nil {
		klog.Warningf("Proxy config in CMO configmap is empty and fallback to cluster proxy config failed - no proxy will be used: %v", err)
		return config
	}

	return clusterProxyConfig
}

func newTaskSpec(targetName string, task tasks.Task) *tasks.TaskSpec {
	return tasks.NewTaskSpec("Updating"+targetName, task)
}

func newUWMTaskSpec(targetName string, task tasks.Task) *tasks.TaskSpec {
	return tasks.NewTaskSpec(UWMTaskPrefix+targetName, task)
}

func (o *Operator) sync(ctx context.Context, key string) error {
	config, err := o.Config(ctx, key)
	if err != nil {
		reason := "InvalidConfiguration"
		if errors.Is(err, ErrUserWorkloadInvalidConfiguration) {
			reason = "UserWorkloadInvalidConfiguration"
		}
		o.reportFailed(ctx, newRunReportForError(reason, err))
		return err
	}
	config.SetImages(o.images)
	config.SetTelemetryMatches(o.telemetryMatches)
	config.SetRemoteWrite(o.remoteWrite)

	var proxyConfig = getProxyReader(ctx, config, o.loadProxyConfig)

	var apiServerConfig *manifests.APIServerConfig
	apiServerConfig, err = o.loadApiServerConfig(ctx)

	if err != nil {
		o.reportFailed(ctx, newRunReportForError("APIServerConfigError", err))
		return err
	}

	consoleConfig, err := o.loadConsoleConfig(ctx)
	if err != nil {
		klog.Warningf("Fail to load ConsoleConfig, AlertManager's externalURL may be outdated")
	}

	// Enable kube-state-metrics' custom-resource-state-based metrics if VPA CRD is installed within the cluster.
	o.lastKnownVPACustomResourceDefinitionPresent, err = o.client.VPACustomResourceDefinitionPresent(ctx, o.lastKnownVPACustomResourceDefinitionPresent)
	if err != nil {
		// Throw on all transient errors.
		return fmt.Errorf("unable to guess the desired state for kube-state-metrics' custom-resource-state metrics enablement: %w", err)
	} else {
		// If we didn't get an error, we can safely assume that the CRD is deterministically either present or absent.
		if *o.lastKnownVPACustomResourceDefinitionPresent {
			klog.Infof("%s CRD found, enabling kube-state-metrics' custom-resource-state-based metrics", client.VerticalPodAutoscalerCRDMetadataName)
		}
	}

	factory := manifests.NewFactory(
		o.namespace,
		o.namespaceUserWorkload,
		config,
		o.loadInfrastructureConfig(ctx),
		proxyConfig,
		o.assets,
		apiServerConfig,
		consoleConfig,
	)

	tl := tasks.NewTaskRunner(
		o.client,
		// Update prometheus-operator before anything else because it is
		// responsible for managing many other resources (e.g. Prometheus,
		// Alertmanager, Thanos Ruler, ...). The metrics scraping client CA
		// should also be created first because it is referenced by Prometheus.
		tasks.NewTaskGroup(
			[]*tasks.TaskSpec{
				newTaskSpec("MetricsScrapingClientCA", tasks.NewMetricsClientCATask(o.client, factory, config)),
				newTaskSpec("PrometheusOperator", tasks.NewPrometheusOperatorTask(o.client, factory)),
			}),
		tasks.NewTaskGroup(
			[]*tasks.TaskSpec{
				newTaskSpec("ClusterMonitoringOperatorDeps", tasks.NewClusterMonitoringOperatorTask(o.client, factory, config)),
				newTaskSpec("Prometheus", tasks.NewPrometheusTask(o.client, factory, config)),
				newTaskSpec("Alertmanager", tasks.NewAlertmanagerTask(o.client, factory, config)),
				newTaskSpec("NodeExporter", tasks.NewNodeExporterTask(o.client, factory)),
				newTaskSpec("KubeStateMetrics", tasks.NewKubeStateMetricsTask(o.client, factory, *o.lastKnownVPACustomResourceDefinitionPresent)),
				newTaskSpec("OpenshiftStateMetrics", tasks.NewOpenShiftStateMetricsTask(o.client, factory)),
				newTaskSpec("MetricsServer", tasks.NewMetricsServerTask(ctx, o.namespace, o.client, factory, config)),
				newTaskSpec("TelemeterClient", tasks.NewTelemeterClientTask(o.client, factory, config)),
				newTaskSpec("ThanosQuerier", tasks.NewThanosQuerierTask(o.client, factory, config)),
				newTaskSpec("ControlPlaneComponents", tasks.NewControlPlaneTask(o.client, factory, config)),
				newTaskSpec("ConsolePluginComponents", tasks.NewMonitoringPluginTask(o.client, factory, config)),
				// Tried to run the UWM prom-operator in the first group, but some e2e tests started failing.
				newUWMTaskSpec("PrometheusOperator", tasks.NewPrometheusOperatorUserWorkloadTask(o.client, factory, config)),
				newUWMTaskSpec("Prometheus", tasks.NewPrometheusUserWorkloadTask(o.client, factory, config)),
				newUWMTaskSpec("Alertmanager", tasks.NewAlertmanagerUserWorkloadTask(o.client, factory, config)),
				newUWMTaskSpec("ThanosRuler", tasks.NewThanosRulerUserWorkloadTask(o.client, factory, config)),
			}),
		// The shared configmap depends on resources being created by the previous tasks hence run it last.
		tasks.NewTaskGroup(
			[]*tasks.TaskSpec{
				newTaskSpec("ConfigurationSharing", tasks.NewConfigSharingTask(o.client, factory, config)),
			},
		),
	)
	klog.Info("Updating ClusterOperator status to InProgress.")
	err = o.client.StatusReporter().SetRollOutInProgress(ctx)
	if err != nil {
		klog.Errorf("error occurred while setting status to InProgress: %v", err)
	}

	if taskErrors := tl.RunAll(ctx); len(taskErrors) > 0 {
		report := generateRunReportFromTaskErrors(taskErrors)
		o.reportFailed(ctx, report)
		return fmt.Errorf("cluster monitoring update failed (reason: %s)", report.available.Reason())
	}

	var degradedConditionMessage, degradedConditionReason string
	if !config.IsStorageConfigured() {
		degradedConditionMessage = o.storageNotConfiguredMessage()
		degradedConditionReason = client.StorageNotConfiguredReason
	} else if config.HasInconsistentAlertmanagerConfigurations() {
		degradedConditionMessage = client.UserAlermanagerConfigMisconfiguredMessage
		degradedConditionReason = client.UserAlermanagerConfigMisconfiguredReason
	}

	klog.Info("Updating ClusterOperator status to done.")
	o.failedReconcileAttempts = 0
	err = o.client.StatusReporter().SetRollOutDone(ctx, degradedConditionMessage, degradedConditionReason)
	if err != nil {
		klog.Errorf("error occurred while setting status to done: %v", err)
	}

	// CMO always reports Upgradeable=True.
	err = o.client.StatusReporter().SetUpgradeable(ctx, configv1.ConditionTrue, "", "")
	if err != nil {
		klog.Errorf("error occurred while setting Upgradeable status: %v", err)
	}

	return nil
}

func (o *Operator) reportFailed(ctx context.Context, report runReport) {
	o.failedReconcileAttempts++

	// Rate limit to avoid unnecessary status updates for temporary or transient errors that may resolve themselves within a few attempts.
	// Ensure you have thoroughly considered all implications before adjusting the threshold.
	// See: https://issues.redhat.com/browse/OCPBUGS-23745
	maxAttempts := 3
	if o.failedReconcileAttempts < maxAttempts {
		klog.Infof("%d reconciliation(s) failed, %d more attempt(s) will be made before reporting failures.", o.failedReconcileAttempts, maxAttempts-o.failedReconcileAttempts)
		return
	} else {
		klog.Infof("%d reconciliations failed in a row, the threshold of %d attempts has been reached, failures will be reported.", o.failedReconcileAttempts, maxAttempts)
	}

	if err := o.client.StatusReporter().ReportState(ctx, report); err != nil {
		klog.ErrorS(err, "failed to update cluster operator status")
	}
}

func (o *Operator) loadInfrastructureConfig(ctx context.Context) *InfrastructureConfig {
	var infrastructureConfig *InfrastructureConfig

	infrastructure, err := o.client.GetInfrastructure(ctx, clusterResourceName)
	if err != nil {
		klog.Warningf("Error getting cluster infrastructure: %v", err)

		if o.lastKnowInfrastructureConfig == nil {
			klog.Warning("No last known infrastructure configuration, assuming default configuration")
			return NewDefaultInfrastructureConfig()
		}

		klog.Info("Using last known infrastructure configuration")
	} else {
		klog.V(5).Infof("Cluster infrastructure: plaform=%v controlPlaneTopology=%v infrastructureTopology=%v", infrastructure.Status.PlatformStatus, infrastructure.Status.ControlPlaneTopology, infrastructure.Status.InfrastructureTopology)

		infrastructureConfig = NewInfrastructureConfig(infrastructure)
		o.lastKnowInfrastructureConfig = infrastructureConfig
	}

	return o.lastKnowInfrastructureConfig
}

func (o *Operator) loadProxyConfig(ctx context.Context) (*ProxyConfig, error) {
	var proxyConfig *ProxyConfig

	proxy, err := o.client.GetProxy(ctx, clusterResourceName)
	if err != nil {
		klog.Warningf("Error getting cluster proxy configuration: %v", err)

		if o.lastKnowProxyConfig == nil {
			return nil, fmt.Errorf("no last known cluster proxy configuration")
		}

		klog.Info("Using last known proxy configuration")
	} else {
		proxyConfig = NewProxyConfig(proxy)
		o.lastKnowProxyConfig = proxyConfig
	}

	return o.lastKnowProxyConfig, nil
}

func (o *Operator) loadApiServerConfig(ctx context.Context) (*manifests.APIServerConfig, error) {
	config, err := o.client.GetAPIServerConfig(ctx, "cluster")
	if err != nil {
		klog.Warningf("failed to get api server config: %v", err)

		if o.lastKnownApiServerConfig == nil {
			return nil, fmt.Errorf("no last known api server configuration")
		}
	} else {
		o.lastKnownApiServerConfig = manifests.NewAPIServerConfig(config)
	}
	return o.lastKnownApiServerConfig, nil
}

func (o *Operator) loadConsoleConfig(ctx context.Context) (*configv1.Console, error) {
	config, err := o.client.GetConsoleConfig(ctx, "cluster")
	if err == nil {
		o.lastKnownConsoleConfig = config
	}
	return o.lastKnownConsoleConfig, err
}

func (o *Operator) loadUserWorkloadConfig(ctx context.Context) (*manifests.UserWorkloadConfiguration, error) {
	cmKey := fmt.Sprintf("%s/%s", o.namespaceUserWorkload, o.userWorkloadConfigMapName)

	userCM, err := o.client.GetConfigmap(ctx, o.namespaceUserWorkload, o.userWorkloadConfigMapName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			klog.Warningf("User Workload Monitoring %q ConfigMap not found. Using defaults.", cmKey)
			return manifests.NewDefaultUserWorkloadMonitoringConfig(), nil
		}
		klog.Warningf("Error loading User Workload Monitoring %q ConfigMap. Error: %v", cmKey, err)
		return nil, fmt.Errorf("the User Workload Monitoring %q ConfigMap could not be loaded: %w", cmKey, err)
	}

	return manifests.NewUserConfigFromConfigMap(userCM)
}

func (o *Operator) loadConfig(key string) (*manifests.Config, error) {
	obj, found, err := o.cmapInf.GetStore().GetByKey(key)
	if err != nil {
		return nil, fmt.Errorf("an error occurred when retrieving the Cluster Monitoring ConfigMap: %w", err)
	}

	if !found {
		klog.Warning("No Cluster Monitoring ConfigMap was found. Using defaults.")
		return manifests.NewDefaultConfig(), nil
	}

	cmap := obj.(*v1.ConfigMap)
	return manifests.NewConfigFromConfigMap(cmap, o.CollectionProfilesEnabled)
}

func (o *Operator) Config(ctx context.Context, key string) (*manifests.Config, error) {
	c, err := o.loadConfig(key)
	if err != nil {
		return nil, err
	}
	err = c.Precheck()
	if err != nil {
		return nil, err
	}

	// Only use User Workload Monitoring ConfigMap from user ns and populate if
	// it's enabled by admin via Cluster Monitoring ConfigMap.  The above
	// loadConfig() already initializes the structs with nil values for
	// UserWorkloadConfiguration struct.
	if *c.ClusterMonitoringConfiguration.UserWorkloadEnabled {
		c.UserWorkloadConfiguration, err = o.loadUserWorkloadConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUserWorkloadInvalidConfiguration, err)
		}
	}

	err = c.LoadEnforcedBodySizeLimit(o.client, ctx)
	if err != nil {
		c.ClusterMonitoringConfiguration.PrometheusK8sConfig.EnforcedBodySizeLimit = ""
		klog.Warningf("Error loading enforced body size limit, no body size limit will be enforced: %v", err)
	}

	// Only fetch the token and cluster ID if they have not been specified in the config.
	if c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID == "" || c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token == "" {
		err := c.LoadClusterID(func() (*configv1.ClusterVersion, error) {
			return o.client.GetClusterVersion(ctx, "version")
		})

		if err != nil {
			klog.Warningf("Could not fetch cluster version from API. Proceeding without it: %v", err)
		}

		err = c.LoadToken(func() (*v1.Secret, error) {
			return o.client.KubernetesInterface().CoreV1().Secrets("openshift-config").Get(ctx, "pull-secret", metav1.GetOptions{})
		})

		if err != nil {
			klog.Warningf("Error loading token from API. Proceeding without it: %v", err)
		}
	}
	return c, nil
}

// storageNotConfiguredMessage returns the message to be set if a pvc has not
// been configured for Prometheus. This messages includes a link to the
// documentation on configuring monitoring stack. If the current cluster
// version can be computed, the link will point to the documentation for that
// version, else it will point to latest documentation.
func (o Operator) storageNotConfiguredMessage() string {
	const docURL = "https://docs.openshift.com/container-platform/%s/observability/monitoring/configuring-the-monitoring-stack.html"

	latestDocMsg := client.StorageNotConfiguredMessage + fmt.Sprintf(docURL, "latest")

	// if cluster version cannot be obtained due to any failure, point to the
	// latest documentation
	cv, err := o.client.GetClusterVersion(context.Background(), "version")
	if err != nil {
		klog.Warningf("failed to find the cluster version: %s", err)
		return latestDocMsg
	}

	v, err := semver.Make(cv.Status.Desired.Version)
	if err != nil {
		klog.Warningf("failed to parse  cluster version: %s", err)
		return latestDocMsg
	}

	return client.StorageNotConfiguredMessage + fmt.Sprintf(docURL, fmt.Sprintf("%d.%d", v.Major, v.Minor))
}

// stateErrorOrUnavailable converts an error to Unavailable & Degraded
// StateErrors if it is not already a StateError.
func stateErrorOrUnavailable(err error) []*client.StateError {
	// unpack aggregate before converting to state errors
	var serr *client.StateError
	if errors.As(err, &serr) {
		return []*client.StateError{serr}
	}

	// convert any generic error to 2 state-errors -> Unavailable & Degraded
	return []*client.StateError{
		client.NewAvailabilityError(err.Error()),
		client.NewDegradedError(err.Error()),
	}
}

func toStateErrors(err error) []*client.StateError {
	serrs := []*client.StateError{}

	var aggregate apiutilerrors.Aggregate
	if errors.As(err, &aggregate) {
		// unpack aggregate before converting to state errors
		errs := apiutilerrors.Flatten(aggregate).Errors()
		for _, err := range errs {
			serrs = append(serrs, stateErrorOrUnavailable(err)...)
		}
	} else {
		serrs = append(serrs, stateErrorOrUnavailable(err)...)
	}
	return serrs
}

func isUWMTaskErr(taskError tasks.TaskErr) bool {
	return strings.HasPrefix(taskError.Name, UWMTaskPrefix)
}

// generateRunReportFromTaskErrors goes through the tasks errors and constructs a runReport
// with the appropriate Degraded and Available conditions.
// Check TestGenerateRunReportFromTaskErrors to learn more about what we're expecting from this.
func generateRunReportFromTaskErrors(tasksErrors tasks.TaskGroupErrors) runReport {
	defaultReason := "MultipleTasksFailed"
	// Count errors per state: degraded/unavailable
	var unavailableErrCount, degradedErrCount, unavailableUWMErrCount, degradedUWMErrCount int

	degraded := &stateInfo{reason: defaultReason, status: client.UnknownStatus}
	unavailable := &stateInfo{reason: defaultReason, status: client.UnknownStatus}

	for _, terr := range tasksErrors {
		// each task can return a single or multiple errors (as an Aggregate)
		// each error can be a StateError or a generic error (fmt.Errorf)
		for _, serr := range toStateErrors(terr.Err) {
			switch serr.State {
			case client.DegradedState:
				degradedErrCount++
				if isUWMTaskErr(terr) {
					degradedUWMErrCount++
				}
				degraded.messages = append(degraded.messages, fmt.Sprintf("%s: %s", terr.Name, serr.Reason))
				if !serr.Unknown {
					degraded.status = client.TrueStatus
				}

			case client.UnavailableState:
				unavailableErrCount++
				if isUWMTaskErr(terr) {
					unavailableUWMErrCount++
				}
				unavailable.messages = append(unavailable.messages, fmt.Sprintf("%s: %s", terr.Name, serr.Reason))
				if !serr.Unknown {
					unavailable.status = client.FalseStatus
				}
			default:
				klog.Errorf("StateError with an unsupported State: %s", serr.State)
			}
		}
	}

	// uwmErrCount and errCount are error counts per state (degraded/unavailable)
	inferReasonForState := func(uwmErrCount, errCount int) string {
		switch {
		// Only one task is failing, use its name as the reason
		case len(tasksErrors) == 1:
			return tasksErrors[0].Name + "Failed"
		case uwmErrCount == errCount:
			return "UserWorkloadTasksFailed"
		case uwmErrCount == 0:
			return "PlatformTasksFailed"
		default:
			// If no errors to report, this will be ignored anyway
			return defaultReason
		}
	}

	rpt := runReport{degraded: asExpected(client.FalseStatus), available: asExpected(client.TrueStatus)}
	if degradedErrCount != 0 {
		rpt.degraded = &stateInfo{reason: inferReasonForState(degradedUWMErrCount, degradedErrCount), status: degraded.status, messages: degraded.messages}
	}
	if unavailableErrCount != 0 {
		rpt.available = &stateInfo{reason: inferReasonForState(unavailableUWMErrCount, unavailableErrCount), status: unavailable.status, messages: unavailable.messages}
	}

	return rpt
}

// stateInfo satisfies a client.StateInfo
type stateInfo struct {
	status   client.Status
	reason   string
	messages []string
}

var _ client.StateInfo = (*stateInfo)(nil)

func (si stateInfo) Status() client.Status {
	return si.status
}

func (si stateInfo) Message() string {
	return strings.Join(si.messages, ", ")
}

func (si stateInfo) Reason() string {
	return si.reason
}

// expectedStatus is a client.StateInfo which is returned when the state
// of the system is as expected.
type expectedStatus client.Status

var _ client.StateInfo = (*expectedStatus)(nil)

func (expectedStatus) Message() string {
	return ""
}

func (s expectedStatus) Status() client.Status {
	return client.Status(s)
}

func (expectedStatus) Reason() string {
	return "AsExpected"
}

func asExpected(s client.Status) *expectedStatus {
	ret := expectedStatus(s)
	return &ret
}

type runReport struct {
	degraded  client.StateInfo
	available client.StateInfo
}

var _ client.StatesReport = (*runReport)(nil)

func newRunReportForError(reason string, err error) runReport {
	return runReport{
		degraded: &stateInfo{
			status:   client.TrueStatus,
			reason:   reason,
			messages: []string{err.Error()},
		},
		available: &stateInfo{
			status:   client.FalseStatus,
			reason:   reason,
			messages: []string{err.Error()},
		},
	}
}

func (r runReport) Available() client.StateInfo {
	return r.available
}

func (r runReport) Degraded() client.StateInfo {
	return r.degraded
}
