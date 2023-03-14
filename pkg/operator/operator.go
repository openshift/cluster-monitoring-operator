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
	"fmt"
	"strings"
	"time"

	"github.com/blang/semver/v4"
	"github.com/openshift/cluster-monitoring-operator/pkg/alert"
	"github.com/openshift/cluster-monitoring-operator/pkg/rebalancer"
	cmostr "github.com/openshift/cluster-monitoring-operator/pkg/strings"
	"github.com/pkg/errors"
	certapiv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiutilerrors "k8s.io/apimachinery/pkg/util/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/csr"
	"github.com/openshift/library-go/pkg/operator/events"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/pkg/tasks"
)

// InfrastructureConfig stores information about the cluster infrastructure
// which is useful for the operator.
type InfrastructureConfig struct {
	highlyAvailableInfrastructure bool
	hostedControlPlane            bool
}

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
	maxFailCount         = 2

	// see https://github.com/kubernetes/apiserver/blob/b571c70e6e823fd78910c3f5b9be895a756f4cbb/pkg/server/options/authentication.go#L239
	apiAuthenticationConfigMap    = "kube-system/extension-apiserver-authentication"
	kubeletServingCAConfigMap     = "openshift-config-managed/kubelet-serving-ca"
	prometheusAdapterTLSSecret    = "openshift-monitoring/prometheus-adapter-tls"
	etcdClientCAConfigMap         = "openshift-config/etcd-metric-serving-ca"
	telemeterCABundleConfigMap    = "openshift-monitoring/telemeter-trusted-ca-bundle"
	alertmanagerCABundleConfigMap = "openshift-monitoring/alertmanager-trusted-ca-bundle"
	grpcTLS                       = "openshift-monitoring/grpc-tls"
	metricsClientCerts            = "openshift-monitoring/metrics-client-certs"

	// Canonical name of the cluster-wide infrastrucure resource.
	clusterResourceName = "cluster"
)

type Operator struct {
	namespace, namespaceUserWorkload string

	configMapName             string
	userWorkloadConfigMapName string
	images                    map[string]string
	telemetryMatches          []string
	remoteWrite               bool
	userWorkloadEnabled       bool

	lastKnowInfrastructureConfig *InfrastructureConfig
	lastKnowProxyConfig          *ProxyConfig
	lastKnownApiServerConfig     *manifests.APIServerConfig
	lastKnownConsoleConfig       *configv1.Console

	client *client.Client

	cmapInf              cache.SharedIndexInformer
	informers            []cache.SharedIndexInformer
	informerFactories    []informers.SharedInformerFactory
	controllersToRunFunc []func(ctx context.Context, workers int)

	queue workqueue.RateLimitingInterface

	reconcileAttempts *metrics.Counter
	reconcileStatus   *metrics.Gauge

	failedReconcileAttempts int

	assets *manifests.Assets

	rebalancer *rebalancer.Rebalancer

	ruleController    *alert.RuleController
	relabelController *alert.RelabelConfigController
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
		return nil, errors.Wrap(err, "creating kubernetes clientset client")
	}
	controllerRef, err := events.GetControllerReferenceForCurrentPod(context.TODO(), kclient, namespace, nil)
	if err != nil {
		klog.Warningf("unable to get owner reference (falling back to namespace): %v", err)
	}

	eventRecorder := events.NewKubeRecorderWithOptions(
		kclient.CoreV1().Events(namespace),
		events.RecommendedClusterSingletonCorrelatorOptions(),
		"cluster-monitoring-operator",
		controllerRef,
	)

	c, err := client.NewForConfig(config, version, namespace, namespaceUserWorkload, client.KubernetesClient(kclient), client.EventRecorder(eventRecorder))
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
		userWorkloadEnabled:       false,
		namespace:                 namespace,
		namespaceUserWorkload:     namespaceUserWorkload,
		client:                    c,
		queue:                     workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(50*time.Millisecond, 3*time.Minute), "cluster-monitoring"),
		informers:                 make([]cache.SharedIndexInformer, 0),
		assets:                    a,
		informerFactories:         make([]informers.SharedInformerFactory, 0),
		controllersToRunFunc:      make([]func(context.Context, int), 0),
		rebalancer:                rebalancer.NewRebalancer(ctx, c.KubernetesInterface()),
		ruleController:            ruleController,
		relabelController:         relabelController,
		reconcileAttempts: metrics.NewCounter(&metrics.CounterOpts{
			Name:           "cluster_monitoring_operator_reconcile_attempts_total",
			Help:           "Number of attempts to reconcile the operator configuration",
			StabilityLevel: metrics.ALPHA,
		}),
		reconcileStatus: metrics.NewGauge(&metrics.GaugeOpts{
			Name:           "cluster_monitoring_operator_last_reconciliation_successful",
			Help:           "Latest reconciliation state. Set to 1 if last reconciliation succeeded, else 0.",
			StabilityLevel: metrics.ALPHA,
		}),
	}

	legacyregistry.MustRegister(
		o.reconcileAttempts,
		o.reconcileStatus,
	)

	informer := cache.NewSharedIndexInformer(
		o.client.SecretListWatchForNamespace(namespace), &v1.Secret{}, resyncPeriod, cache.Indexers{},
	)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    o.handleEvent,
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
		DeleteFunc: o.handleEvent,
	})
	o.informers = append(o.informers, informer)

	o.cmapInf = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace(namespace), &v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	o.cmapInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    o.handleEvent,
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
		DeleteFunc: o.handleEvent,
	})

	informer = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace(namespaceUserWorkload), &v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    o.handleEvent,
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
		DeleteFunc: o.handleEvent,
	})
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace("kube-system"),
		&v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace("openshift-config-managed"),
		&v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace("openshift-config"),
		&v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.InfrastructureListWatchForResource(ctx, clusterResourceName),
		&configv1.Infrastructure{}, resyncPeriod, cache.Indexers{},
	)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ApiServersListWatchForResource(ctx, clusterResourceName),
		&configv1.APIServer{}, resyncPeriod, cache.Indexers{},
	)

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) {
			o.handleEvent(newObj)
		},
	})
	o.informers = append(o.informers, informer)

	informer = cache.NewSharedIndexInformer(
		o.client.ConsoleListWatch(ctx),
		&configv1.Console{}, resyncPeriod, cache.Indexers{},
	)

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) {
			o.handleEvent(newObj)
		},
	})
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
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: o.handleEvent,
	})
	o.informers = append(o.informers, informer)

	// Setup PVC informers to sync annotation updates.
	for _, ns := range []string{o.namespace, o.namespaceUserWorkload} {
		informer = cache.NewSharedIndexInformer(
			o.client.PersistentVolumeClaimListWatchForNamespace(ns),
			&v1.PersistentVolumeClaim{}, resyncPeriod, cache.Indexers{},
		)
		informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
		})
		o.informers = append(o.informers, informer)
	}

	kubeInformersOperatorNS := informers.NewSharedInformerFactoryWithOptions(
		c.KubernetesInterface(),
		resyncPeriod,
		informers.WithNamespace(namespace),
	)
	o.informerFactories = append(o.informerFactories, kubeInformersOperatorNS)

	csrController, err := csr.NewClientCertificateController(
		csr.ClientCertOption{
			SecretNamespace: "openshift-monitoring",
			SecretName:      "metrics-client-certs",
		},
		csr.CSROption{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "system:openshift:openshift-monitoring-",
				Labels: map[string]string{
					"metrics.openshift.io/csr.subject": "prometheus",
				},
			},
			Subject:    &pkix.Name{CommonName: "system:serviceaccount:openshift-monitoring:prometheus-k8s"},
			SignerName: certapiv1.KubeAPIServerClientSignerName,
		},
		kubeInformersOperatorNS.Certificates().V1().CertificateSigningRequests(),
		o.client.KubernetesInterface().CertificatesV1().CertificateSigningRequests(),
		kubeInformersOperatorNS.Core().V1().Secrets(),
		o.client.KubernetesInterface().CoreV1(),
		o.client.EventRecorder(),
		"OpenShiftMonitoringClientCertRequester",
	)

	if err != nil {
		return nil, errors.Wrap(err, "failed to create client certificate controller")
	}
	o.controllersToRunFunc = append(o.controllersToRunFunc, csrController.Run, o.ruleController.Run, o.relabelController.Run)

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
			errChan <- errors.Wrap(err, "communicating with server failed")
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

	if _, ok := obj.(*configv1.Infrastructure); ok {
		klog.Infof("Triggering update due to an infrastructure update")
		o.enqueue(cmoConfigMap)
		return
	}

	if _, ok := obj.(*configv1.APIServer); ok {
		klog.Infof("Triggering update due to an apiserver config update")
		o.enqueue(cmoConfigMap)
		return
	}

	if _, ok := obj.(*v1.PersistentVolumeClaim); ok {
		klog.Info("Triggering update due to a PVC update")
		o.enqueue(cmoConfigMap)
		return
	}

	if _, ok := obj.(*configv1.Console); ok {
		klog.Info("Triggering update due to a console update")
		o.enqueue(cmoConfigMap)
		return
	}

	if _, ok := obj.(*configv1.ClusterOperator); ok {
		klog.Info("Triggering update due to a cluster operator update")
		o.enqueue(cmoConfigMap)
		return
	}

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
	case prometheusAdapterTLSSecret:
	case etcdClientCAConfigMap:
	case telemeterCABundleConfigMap:
	case alertmanagerCABundleConfigMap:
	case grpcTLS:
	case metricsClientCerts:
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

	o.reconcileAttempts.Inc()
	err := o.sync(ctx, key.(string))
	if err == nil {
		o.reconcileStatus.Set(1)
		o.queue.Forget(key)
		return true
	}

	o.reconcileStatus.Set(0)
	klog.Errorf("Syncing %q failed", key)
	utilruntime.HandleError(errors.Wrapf(err, "sync %q failed", key))
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

func (o *Operator) sync(ctx context.Context, key string) error {
	// The operator may have left some nodes as unschedulable during a previous
	// sync in an attempt to rebalance workloads.
	// Ensure that the nodes are switched back to schedulable first.
	err := o.rebalancer.EnsureNodesAreUncordoned()
	if err != nil {
		return err
	}

	config, err := o.Config(ctx, key)
	if err != nil {
		o.reportFailed(ctx, newRunReportForError("InvalidConfiguration", err))
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

	factory := manifests.NewFactory(o.namespace, o.namespaceUserWorkload, config, o.loadInfrastructureConfig(ctx), proxyConfig, o.assets, apiServerConfig, consoleConfig)

	tl := tasks.NewTaskRunner(
		o.client,
		// Update prometheus-operator before anything else because it is
		// responsible for managing many other resources (e.g. Prometheus,
		// Alertmanager, Thanos Ruler, ...). The metrics scraping client CA
		// should also be created first because it is referenced by Prometheus.
		tasks.NewTaskGroup(
			[]*tasks.TaskSpec{
				tasks.NewTaskSpec("Updating metrics scraping client CA", tasks.NewMetricsClientCATask(o.client, factory, config)),
				tasks.NewTaskSpec("Updating Prometheus Operator", tasks.NewPrometheusOperatorTask(o.client, factory)),
			}),
		tasks.NewTaskGroup(
			[]*tasks.TaskSpec{
				tasks.NewTaskSpec("Updating user workload Prometheus Operator", tasks.NewPrometheusOperatorUserWorkloadTask(o.client, factory, config)),
				tasks.NewTaskSpec("Updating Cluster Monitoring Operator", tasks.NewClusterMonitoringOperatorTask(o.client, factory, config)),
				tasks.NewTaskSpec("Updating Prometheus-k8s", tasks.NewPrometheusTask(o.client, factory, config)),
				tasks.NewTaskSpec("Updating Prometheus-user-workload", tasks.NewPrometheusUserWorkloadTask(o.client, factory, config)),
				tasks.NewTaskSpec("Updating Alertmanager", tasks.NewAlertmanagerTask(o.client, factory, config)),
				tasks.NewTaskSpec("Updating Alertmanager-user-workload", tasks.NewAlertmanagerUserWorkloadTask(o.client, factory, config)),
				tasks.NewTaskSpec("Updating node-exporter", tasks.NewNodeExporterTask(o.client, factory)),
				tasks.NewTaskSpec("Updating kube-state-metrics", tasks.NewKubeStateMetricsTask(o.client, factory)),
				tasks.NewTaskSpec("Updating openshift-state-metrics", tasks.NewOpenShiftStateMetricsTask(o.client, factory)),
				tasks.NewTaskSpec("Updating prometheus-adapter", tasks.NewPrometheusAdapterTask(ctx, o.namespace, o.client, factory, config)),
				tasks.NewTaskSpec("Updating Telemeter client", tasks.NewTelemeterClientTask(o.client, factory, config)),
				tasks.NewTaskSpec("Updating Thanos Querier", tasks.NewThanosQuerierTask(o.client, factory, config)),
				tasks.NewTaskSpec("Updating User Workload Thanos Ruler", tasks.NewThanosRulerUserWorkloadTask(o.client, factory, config)),
				tasks.NewTaskSpec("Updating Control Plane components", tasks.NewControlPlaneTask(o.client, factory, config)),
			}),
		// The shared configmap depends on resources being created by the previous tasks hence run it last.
		tasks.NewTaskGroup(
			[]*tasks.TaskSpec{
				tasks.NewTaskSpec("Updating configuration sharing", tasks.NewConfigSharingTask(o.client, factory, config)),
			},
		),
	)
	klog.Info("Updating ClusterOperator status to in progress.")
	err = o.client.StatusReporter().SetRollOutInProgress(ctx)
	if err != nil {
		klog.Errorf("error occurred while setting status to in progress: %v", err)
	}

	if taskErrors := tl.RunAll(ctx); len(taskErrors) > 0 {

		report, failedTask := generateRunReportFromTaskErrors(taskErrors)
		o.reportFailed(ctx, report)
		return errors.Errorf("cluster monitoring update failed (reason: %s)", failedTask)
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

	operatorUpgradeable, upgradeableReason, upgradeableMessage, err := o.Upgradeable(ctx)
	if err != nil {
		return err
	}

	err = o.client.StatusReporter().SetUpgradeable(ctx, operatorUpgradeable, upgradeableMessage, upgradeableReason)
	if err != nil {
		klog.Errorf("error occurred while setting Upgradeable status: %v", err)
	}

	return nil
}

func (o *Operator) reportFailed(ctx context.Context, report runReport) {
	o.failedReconcileAttempts++
	klog.Infof("ClusterOperator reportFailed (attempt %d).", o.failedReconcileAttempts)

	if o.failedReconcileAttempts < maxFailCount {
		klog.Infof("ClusterOperator reconciliation %d - skipping update", o.failedReconcileAttempts)
		return
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
		klog.V(5).Infof("Cluster infrastructure: plaform=%s controlPlaneTopology=%s infrastructureTopology=%s", infrastructure.Status.Platform, infrastructure.Status.ControlPlaneTopology, infrastructure.Status.InfrastructureTopology)

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
			return nil, errors.Errorf("no last known cluster proxy configuration")
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
			return nil, errors.Errorf("no last known api server configuration")
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
		return nil, errors.Wrapf(err, "the User Workload Monitoring %q ConfigMap could not be loaded", cmKey)
	}

	const configKey = "config.yaml"
	configContent, found := userCM.Data[configKey]
	if !found {
		klog.Warningf("No %q key found in User Workload Monitoring %q ConfigMap. Using defaults.", configKey, cmKey)
		return manifests.NewDefaultUserWorkloadMonitoringConfig(), nil
	}

	uwc, err := manifests.NewUserConfigFromString(configContent)
	if err != nil {
		klog.Warningf("Error creating User Workload Configuration from %q key in the %q ConfigMap. Error: %v", configKey, cmKey, err)
		return nil, errors.Wrapf(err, "the User Workload Configuration from %q key in the %q ConfigMap could not be parsed", configKey, cmKey)
	}
	return uwc, nil
}

func (o *Operator) loadConfig(key string, tp bool) (*manifests.Config, error) {
	obj, found, err := o.cmapInf.GetStore().GetByKey(key)
	if err != nil {
		return nil, errors.Wrap(err, "an error occurred when retrieving the Cluster Monitoring ConfigMap")
	}

	if !found {
		klog.Warning("No Cluster Monitoring ConfigMap was found. Using defaults.")
		return manifests.NewDefaultConfig(), nil
	}

	cmap := obj.(*v1.ConfigMap)
	configContent, found := cmap.Data["config.yaml"]

	if !found {
		return nil, errors.New("the Cluster Monitoring ConfigMap doesn't contain a 'config.yaml' key")
	}

	cParsed, err := manifests.NewConfigFromString(configContent, tp)
	if err != nil {
		return nil, errors.Wrap(err, "the Cluster Monitoring ConfigMap could not be parsed")
	}

	return cParsed, nil
}

func (o *Operator) Config(ctx context.Context, key string) (*manifests.Config, error) {
	tp, err := o.client.TechPreviewEnabled(ctx)
	if err != nil {
		return nil, err
	}

	c, err := o.loadConfig(key, tp)
	if err != nil {
		return nil, err
	}

	// Only use User Workload Monitoring ConfigMap from user ns and populate if
	// its enabled by admin via Cluster Monitoring ConfigMap.  The above
	// loadConfig() already initializes the structs with nil values for
	// UserWorkloadConfiguration struct.
	if c.ClusterMonitoringConfiguration.UserWorkloadEnabled {
		c.UserWorkloadConfiguration, err = o.loadUserWorkloadConfig(ctx)
		if err != nil {
			return nil, err
		}
	}
	o.userWorkloadEnabled = c.ClusterMonitoringConfiguration.UserWorkloadEnabled

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

	cm, err := o.client.GetConfigmap(ctx, "openshift-config", "etcd-metric-serving-ca")
	if err != nil {
		klog.Warningf("Error loading etcd CA certificates for Prometheus. Proceeding with etcd disabled. Error: %v", err)
		return c, nil
	}

	s, err := o.client.GetSecret(ctx, "openshift-config", "etcd-metric-client")
	if err != nil {
		klog.Warningf("Error loading etcd client secrets for Prometheus. Proceeding with etcd disabled. Error: %v", err)
		return c, nil
	}

	caContent, caFound := cm.Data["ca-bundle.crt"]
	certContent, certFound := s.Data["tls.crt"]
	keyContent, keyFound := s.Data["tls.key"]

	if caFound && len(caContent) > 0 &&
		certFound && len(certContent) > 0 &&
		keyFound && len(keyContent) > 0 {

		c.ClusterMonitoringConfiguration.EtcdConfig.Enabled = true
	}

	return c, nil
}

// Upgradeable verifies whether the operator can be upgraded or not. It returns
// the ConditionStatus with optional reason and message.  To set this status, it
// will verify that in HA topology, workloads with persistent storage are
// correctly balanced across multiple nodes. If it isn't it will try to
// rebalance the workloads.
func (o *Operator) Upgradeable(ctx context.Context) (configv1.ConditionStatus, string, string, error) {
	if !o.lastKnowInfrastructureConfig.HighlyAvailableInfrastructure() {
		return configv1.ConditionTrue, "", "", nil
	}

	var (
		messages           []string
		workloadRebalanced bool
	)
	for _, workload := range o.workloadsToRebalance() {
		balanced, err := o.rebalancer.WorkloadCorrectlyBalanced(ctx, &workload)
		if err != nil {
			klog.Errorf("Couldn't figure out if workload in namespace %s, with label %q is correctly balanced, err %v.", workload.Namespace, workload.LabelSelector, err)
			return configv1.ConditionUnknown, "", "", err
		}

		if balanced {
			continue
		}

		workloadRebalanced, err := o.rebalancer.RebalanceWorkloads(ctx, &workload)
		if err != nil {
			klog.Errorf("Couldn't rebalance workload in namespace %s, with label %q, err %v.", workload.Namespace, workload.LabelSelector, err)
			return configv1.ConditionUnknown, "", "", err
		}

		if !workloadRebalanced {
			messages = append(messages, fmt.Sprintf("Highly-available workload in namespace %s, with label %q and persistent storage enabled has a single point of failure.", workload.Namespace, workload.LabelSelector))
		}
	}

	if len(messages) > 0 {
		msg := "Manual intervention is needed to upgrade to the next minor version. "
		if workloadRebalanced {
			msg += "The operator couldn't rebalance the pods automatically with the annotation. " +
				"For each highly-available workload that has a single point of failure, you will need to manually delete at least one of the PersistentVolumeClaims and Pods of this workload until at least 2 of its replicas are scheduled on different nodes."
		} else {
			msg += fmt.Sprintf("For each highly-available workload that has a single point of failure please mark at least one of their PersistentVolumeClaim for deletion by annotating them with %q.", map[string]string{rebalancer.DropPVCAnnotation: "yes"})
		}
		messages = append(messages, msg)
		return configv1.ConditionFalse, "WorkloadSinglePointOfFailure", strings.Join(messages, "\n"), nil
	}

	return configv1.ConditionTrue, "", "", nil
}

// workloadsToRebalance returns the list of workloads with persistent storage
// that might need to be rebalanced.
func (o *Operator) workloadsToRebalance() []rebalancer.Workload {
	workloads := []rebalancer.Workload{
		{
			Namespace:     o.namespace,
			LabelSelector: map[string]string{"app.kubernetes.io/name": "prometheus"},
		},
		{
			Namespace:     o.namespace,
			LabelSelector: map[string]string{"app.kubernetes.io/name": "alertmanager"},
		},
	}

	if o.userWorkloadEnabled {
		workloads = append(workloads,
			rebalancer.Workload{
				Namespace:     o.namespaceUserWorkload,
				LabelSelector: map[string]string{"app.kubernetes.io/name": "prometheus"},
			},
			rebalancer.Workload{
				Namespace:     o.namespaceUserWorkload,
				LabelSelector: map[string]string{"app.kubernetes.io/name": "thanos-ruler"},
			},
		)
	}
	return workloads
}

// storageNotConfiguredMessage returns the message to be set if a pvc has not
// been configured for Prometheus. This messages includes a link to the
// documentation on configuring monitoring stack. If the current cluster
// version can be computed, the link will point to the documentation for that
// version, else it will point to latest documentation.
func (o Operator) storageNotConfiguredMessage() string {
	const docURL = "https://docs.openshift.com/container-platform/%s/monitoring/configuring-the-monitoring-stack.html"

	latestDocMsg := client.StorageNotConfiguredMessage + fmt.Sprintf(docURL, "latest")

	// if cluster version cannot be obtained due to any failure, point to the
	// latest documentation
	cv, err := o.client.GetClusterVersion(context.Background(), "version")
	if err != nil {
		klog.Warning("failed to find the cluster version: %s", err)
		return latestDocMsg
	}

	v, err := semver.Make(cv.Status.Desired.Version)
	if err != nil {
		klog.Warning("failed to parse  cluster version: %s", err)
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

func generateRunReportFromTaskErrors(tge tasks.TaskGroupErrors) (runReport, string) {

	failedTask := cmostr.ToPascalCase(tge[0].Name) + "Failed"
	if len(tge) > 1 {
		failedTask = "MultipleTasksFailed"
	}

	degraded := &stateInfo{reason: failedTask, status: client.UnknownStatus}
	available := &stateInfo{reason: failedTask, status: client.UnknownStatus}

	for _, terr := range tge {

		// each task can return a single or multiple errors (as an Aggregate)
		// each error can be a StateError or a generic error (fmt.Errorf)

		for _, serr := range toStateErrors(terr.Err) {

			switch serr.State {
			case client.DegradedState:
				degraded.messages = append(degraded.messages, serr.Reason)
				if !serr.Unknown {
					degraded.status = client.TrueStatus
				}

			case client.UnavailableState:
				available.messages = append(available.messages, serr.Reason)
				if !serr.Unknown {
					available.status = client.FalseStatus
				}
			}
		}
	}

	rpt := runReport{}

	if len(degraded.messages) != 0 {
		rpt.degraded = degraded
	} else {
		rpt.degraded = asExpected(client.FalseStatus)
	}

	if len(available.messages) != 0 {
		rpt.available = available
	} else {
		rpt.available = asExpected(client.TrueStatus)
	}

	return rpt, failedTask
}

// stateInfo satifies a client.StateInfo
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
func (r runReport) isDegraded() bool {
	if isNilOrAsExpected(r.degraded) {
		return false
	}
	return true
}

func (r runReport) isUnavailable() bool {
	if isNilOrAsExpected(r.available) {
		return false
	}
	return true
}

func (r runReport) Available() client.StateInfo {
	return r.available
}

func (r runReport) Degraded() client.StateInfo {
	return r.degraded
}

func isNilOrAsExpected(s client.StateInfo) bool {
	if s == nil {
		return true
	}

	switch s.(type) {
	case *expectedStatus:
		return true
	default:
		return false
	}
}
