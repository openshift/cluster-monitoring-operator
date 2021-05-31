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
	"fmt"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

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
	if i.Status.Platform == configv1.IBMCloudPlatformType {
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
	resyncPeriod = 15 * time.Minute

	// see https://github.com/kubernetes/apiserver/blob/b571c70e6e823fd78910c3f5b9be895a756f4cbb/pkg/server/options/authentication.go#L239
	apiAuthenticationConfigMap    = "kube-system/extension-apiserver-authentication"
	kubeletServingCAConfigMap     = "openshift-config-managed/kubelet-serving-ca"
	prometheusAdapterTLSSecret    = "openshift-monitoring/prometheus-adapter-tls"
	etcdClientCAConfigMap         = "openshift-config/etcd-metric-serving-ca"
	telemeterCABundleConfigMap    = "openshift-monitoring/telemeter-trusted-ca-bundle"
	alertmanagerCABundleConfigMap = "openshift-monitoring/alertmanager-trusted-ca-bundle"
	grpcTLS                       = "openshift-monitoring/grpc-tls"

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

	lastKnowInfrastructureConfig *InfrastructureConfig
	lastKnowProxyConfig          *ProxyConfig

	client *client.Client

	cmapInf   cache.SharedIndexInformer
	informers []cache.SharedIndexInformer

	queue workqueue.RateLimitingInterface

	reconcileAttempts prometheus.Counter
	reconcileStatus   prometheus.Gauge

	assets *manifests.Assets
}

func New(
	config *rest.Config,
	version, namespace, namespaceUserWorkload, configMapName, userWorkloadConfigMapName string,
	remoteWrite bool,
	images map[string]string,
	telemetryMatches []string,
	a *manifests.Assets,
) (*Operator, error) {
	c, err := client.New(config, version, namespace, namespaceUserWorkload)
	if err != nil {
		return nil, err
	}

	o := &Operator{
		images:                    images,
		telemetryMatches:          telemetryMatches,
		configMapName:             configMapName,
		userWorkloadConfigMapName: userWorkloadConfigMapName,
		remoteWrite:               remoteWrite,
		namespace:                 namespace,
		namespaceUserWorkload:     namespaceUserWorkload,
		client:                    c,
		queue:                     workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cluster-monitoring"),
		informers:                 make([]cache.SharedIndexInformer, 0),
		assets:                    a,
	}

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
		o.client.InfrastructureListWatchForResource(context.TODO(), clusterResourceName),
		&configv1.Infrastructure{}, resyncPeriod, cache.Indexers{},
	)
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})
	o.informers = append(o.informers, informer)

	return o, nil
}

// RegisterMetrics registers the operator's metrics with the given registerer.
func (o *Operator) RegisterMetrics(r prometheus.Registerer) {
	o.reconcileAttempts = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cluster_monitoring_operator_reconcile_attempts_total",
		Help: "Number of attempts to reconcile the operator configuration",
	})

	o.reconcileStatus = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cluster_monitoring_operator_last_reconciliation_successful",
		Help: "Latest reconciliation state. Set to 1 if last reconciliation succeeded, else 0.",
	})

	r.MustRegister(
		o.reconcileAttempts,
		o.reconcileStatus,
	)
}

// Run the controller.
func (o *Operator) Run(stopc <-chan struct{}) error {
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

	klog.V(4).Info("Waiting for initial cache sync.")
	ok := cache.WaitForCacheSync(stopc, synced...)
	if !ok {
		return errors.New("failed to sync informers")
	}
	klog.V(4).Info("Initial cache sync done.")

	go o.worker()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	key := o.namespace + "/" + o.configMapName
	_, exists, _ := o.cmapInf.GetStore().GetByKey(key)
	if !exists {
		klog.Infof("ConfigMap to configure stack does not exist. Reconciling with default config every %s.", resyncPeriod)
		o.enqueue(key)
	}

	for {
		select {
		case <-stopc:
			return nil
		case <-ticker.C:
			_, exists, _ := o.cmapInf.GetStore().GetByKey(key)
			if !exists {
				klog.Infof("ConfigMap to configure stack does not exist. Reconciling with default config every %s.", resyncPeriod)
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

func (o *Operator) worker() {
	for o.processNextWorkItem() {
	}
}

func (o *Operator) processNextWorkItem() bool {
	key, quit := o.queue.Get()
	if quit {
		return false
	}
	defer o.queue.Done(key)

	o.reconcileAttempts.Inc()
	err := o.sync(key.(string))
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

func (o *Operator) sync(key string) error {
	config, err := o.Config(key)
	if err != nil {
		klog.Infof("Updating ClusterOperator status to failed: %v", err)
		reportErr := o.client.StatusReporter().SetFailed(err, "InvalidConfiguration")
		if reportErr != nil {
			klog.Errorf("error occurred while setting status to failed: %v", reportErr)
		}
		return err
	}
	config.SetImages(o.images)
	config.SetTelemetryMatches(o.telemetryMatches)
	config.SetRemoteWrite(o.remoteWrite)

	var proxyConfig manifests.ProxyReader
	proxyConfig, err = o.loadProxyConfig()
	if err != nil {
		klog.Warningf("using proxy config from CMO configmap: %v", err)
		proxyConfig = config
	}
	factory := manifests.NewFactory(o.namespace, o.namespaceUserWorkload, config, o.loadInfrastructureConfig(), proxyConfig, o.assets)

	tl := tasks.NewTaskRunner(
		o.client,
		[]*tasks.TaskSpec{
			tasks.NewTaskSpec("Updating Prometheus Operator", tasks.NewPrometheusOperatorTask(o.client, factory)),
			tasks.NewTaskSpec("Updating user workload Prometheus Operator", tasks.NewPrometheusOperatorUserWorkloadTask(o.client, factory, config)),
			tasks.NewTaskSpec("Updating Cluster Monitoring Operator", tasks.NewClusterMonitoringOperatorTask(o.client, factory)),
			tasks.NewTaskSpec("Updating Grafana", tasks.NewGrafanaTask(o.client, factory)),
			tasks.NewTaskSpec("Updating Prometheus-k8s", tasks.NewPrometheusTask(o.client, factory)),
			tasks.NewTaskSpec("Updating Prometheus-user-workload", tasks.NewPrometheusUserWorkloadTask(o.client, factory, config)),
			tasks.NewTaskSpec("Updating Alertmanager", tasks.NewAlertmanagerTask(o.client, factory)),
			tasks.NewTaskSpec("Updating node-exporter", tasks.NewNodeExporterTask(o.client, factory)),
			tasks.NewTaskSpec("Updating kube-state-metrics", tasks.NewKubeStateMetricsTask(o.client, factory)),
			tasks.NewTaskSpec("Updating openshift-state-metrics", tasks.NewOpenShiftStateMetricsTask(o.client, factory)),
			tasks.NewTaskSpec("Updating prometheus-adapter", tasks.NewPrometheusAdapterTaks(o.namespace, o.client, factory)),
			tasks.NewTaskSpec("Updating Telemeter client", tasks.NewTelemeterClientTask(o.client, factory, config)),
			tasks.NewTaskSpec("Updating configuration sharing", tasks.NewConfigSharingTask(o.client, factory)),
			tasks.NewTaskSpec("Updating Thanos Querier", tasks.NewThanosQuerierTask(o.client, factory, config)),
			tasks.NewTaskSpec("Updating User Workload Thanos Ruler", tasks.NewThanosRulerUserWorkloadTask(o.client, factory, config)),
			tasks.NewTaskSpec("Updating Control Plane components", tasks.NewControlPlaneTask(o.client, factory, config)),
		},
	)

	klog.Info("Updating ClusterOperator status to in progress.")
	err = o.client.StatusReporter().SetInProgress()
	if err != nil {
		klog.Errorf("error occurred while setting status to in progress: %v", err)
	}

	taskName, err := tl.RunAll()
	if err != nil {
		klog.Infof("Updating ClusterOperator status to failed. Err: %v", err)
		failedTaskReason := strings.Join(strings.Fields(taskName+"Failed"), "")
		reportErr := o.client.StatusReporter().SetFailed(err, failedTaskReason)
		if reportErr != nil {
			klog.Errorf("error occurred while setting status to failed: %v", reportErr)
		}
		return err
	}

	klog.Info("Updating ClusterOperator status to done.")
	err = o.client.StatusReporter().SetDone()
	if err != nil {
		klog.Errorf("error occurred while setting status to done: %v", err)
	}

	return nil
}

func (o *Operator) loadInfrastructureConfig() *InfrastructureConfig {
	var infrastructureConfig *InfrastructureConfig

	infrastructure, err := o.client.GetInfrastructure(clusterResourceName)
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

func (o *Operator) loadProxyConfig() (*ProxyConfig, error) {
	var proxyConfig *ProxyConfig

	proxy, err := o.client.GetProxy(clusterResourceName)
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

func (o *Operator) loadUserWorkloadConfig() (*manifests.UserWorkloadConfiguration, error) {
	cmKey := fmt.Sprintf("%s/%s", o.namespaceUserWorkload, o.userWorkloadConfigMapName)

	userCM, err := o.client.GetConfigmap(o.namespaceUserWorkload, o.userWorkloadConfigMapName)
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

func (o *Operator) loadConfig(key string) (*manifests.Config, error) {
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

	cParsed, err := manifests.NewConfigFromString(configContent)
	if err != nil {
		return nil, errors.Wrap(err, "the Cluster Monitoring ConfigMap could not be parsed")
	}

	return cParsed, nil
}

func (o *Operator) Config(key string) (*manifests.Config, error) {
	c, err := o.loadConfig(key)
	if err != nil {
		return nil, err
	}

	// Only use User Workload Monitoring ConfigMap from user ns and populate if
	// its enabled by admin via Cluster Monitoring ConfigMap.  The above
	// loadConfig() already initializes the structs with nil values for
	// UserWorkloadConfiguration struct.
	if *c.ClusterMonitoringConfiguration.UserWorkloadEnabled {
		c.UserWorkloadConfiguration, err = o.loadUserWorkloadConfig()
		if err != nil {
			return nil, err
		}
	}

	// Only fetch the token and cluster ID if they have not been specified in the config.
	if c.ClusterMonitoringConfiguration.TelemeterClientConfig.ClusterID == "" || c.ClusterMonitoringConfiguration.TelemeterClientConfig.Token == "" {
		err := c.LoadClusterID(func() (*configv1.ClusterVersion, error) {
			return o.client.GetClusterVersion("version")
		})

		if err != nil {
			klog.Warningf("Could not fetch cluster version from API. Proceeding without it: %v", err)
		}

		err = c.LoadToken(func() (*v1.Secret, error) {
			return o.client.KubernetesInterface().CoreV1().Secrets("openshift-config").Get(context.TODO(), "pull-secret", metav1.GetOptions{})
		})

		if err != nil {
			klog.Warningf("Error loading token from API. Proceeding without it: %v", err)
		}
	}

	cm, err := o.client.GetConfigmap("openshift-config", "etcd-metric-serving-ca")
	if err != nil {
		klog.Warningf("Error loading etcd CA certificates for Prometheus. Proceeding with etcd disabled. Error: %v", err)
		return c, nil
	}

	s, err := o.client.GetSecret("openshift-config", "etcd-metric-client")
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

		trueBool := true
		c.ClusterMonitoringConfiguration.EtcdConfig.Enabled = &trueBool
	}

	return c, nil
}
