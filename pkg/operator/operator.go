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
	"fmt"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/pkg/tasks"
)

const (
	resyncPeriod = 5 * time.Minute

	// see https://github.com/kubernetes/apiserver/blob/b571c70e6e823fd78910c3f5b9be895a756f4cbb/pkg/server/options/authentication.go#L239
	apiAuthenticationConfigMap    = "kube-system/extension-apiserver-authentication"
	kubeletServingCAConfigMap     = "openshift-config-managed/kubelet-serving-ca"
	prometheusAdapterTLSSecret    = "openshift-monitoring/prometheus-adapter-tls"
	etcdClientCAConfigMap         = "openshift-config/etcd-metrics-serving-ca"
	telemeterCABundleConfigMap    = "openshift-monitoring/telemeter-trusted-ca-bundle"
	alertmanagerCABundleConfigMap = "openshift-monitoring/alertmanager-trusted-ca-bundle"
	grpcTLS                       = "openshift-monitoring/grpc-tls"
)

type Operator struct {
	namespace, namespaceUserWorkload string

	configMapName    string
	images           map[string]string
	telemetryMatches []string

	client *client.Client

	cmapInf                       cache.SharedIndexInformer
	kubeSystemCmapInf             cache.SharedIndexInformer
	openshiftConfigManagedCmapInf cache.SharedIndexInformer
	openshiftConfigCmapInf        cache.SharedIndexInformer
	secretInf                     cache.SharedIndexInformer

	queue workqueue.RateLimitingInterface

	reconcileAttempts prometheus.Counter
	reconcileErrors   prometheus.Counter
}

func New(config *rest.Config, version, namespace, namespaceUserWorkload, namespaceSelector, configMapName string, images map[string]string, telemetryMatches []string) (*Operator, error) {
	c, err := client.New(config, version, namespace, namespaceSelector)
	if err != nil {
		return nil, err
	}

	o := &Operator{
		images:                images,
		telemetryMatches:      telemetryMatches,
		configMapName:         configMapName,
		namespace:             namespace,
		namespaceUserWorkload: namespaceUserWorkload,
		client:                c,
		queue:                 workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cluster-monitoring"),
	}

	o.secretInf = cache.NewSharedIndexInformer(
		o.client.SecretListWatchForNamespace(namespace), &v1.Secret{}, resyncPeriod, cache.Indexers{},
	)
	o.secretInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    o.handleEvent,
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
		DeleteFunc: o.handleEvent,
	})

	o.cmapInf = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatch(), &v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	o.cmapInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    o.handleEvent,
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
		DeleteFunc: o.handleEvent,
	})

	o.kubeSystemCmapInf = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace("kube-system"),
		&v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	o.kubeSystemCmapInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})

	o.openshiftConfigManagedCmapInf = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace("openshift-config-managed"),
		&v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	o.openshiftConfigManagedCmapInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})

	o.openshiftConfigCmapInf = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatchForNamespace("openshift-config"),
		&v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	o.openshiftConfigCmapInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(_, newObj interface{}) { o.handleEvent(newObj) },
	})

	return o, nil
}

// RegisterMetrics registers the operator's metrics with the given registerer.
func (o *Operator) RegisterMetrics(r prometheus.Registerer) {
	o.reconcileAttempts = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cluster_monitoring_operator_reconcile_attempts_total",
		Help: "Number of attempts to reconcile the operator configuration",
	})

	o.reconcileErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cluster_monitoring_operator_reconcile_errors_total",
		Help: "Number of errors that occurred while reconciling the operator configuration",
	})

	r.MustRegister(
		o.reconcileAttempts,
		o.reconcileErrors,
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
	go o.secretInf.Run(stopc)
	go o.kubeSystemCmapInf.Run(stopc)

	klog.V(4).Info("Waiting for initial cache sync.")
	ok := cache.WaitForCacheSync(stopc, o.cmapInf.HasSynced, o.kubeSystemCmapInf.HasSynced)
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
		klog.Info("ConfigMap to configure stack does not exist. Reconciling with default config every 5 minutes.")
		o.enqueue(key)
	}

	for {
		select {
		case <-stopc:
			return nil
		case <-ticker.C:
			_, exists, _ := o.cmapInf.GetStore().GetByKey(key)
			if !exists {
				klog.Info("ConfigMap to configure stack does not exist. Reconciling with default config every 5 minutes.")
				o.enqueue(key)
			}
		}
	}

	return nil
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
	key, ok := o.keyFunc(obj)
	if !ok {
		return
	}

	klog.V(5).Infof("ConfigMap or Secret updated: %s", key)

	cmoConfigMap := o.namespace + "/" + o.configMapName

	switch key {
	case cmoConfigMap:
	case apiAuthenticationConfigMap:
	case kubeletServingCAConfigMap:
	case prometheusAdapterTLSSecret:
	case etcdClientCAConfigMap:
	case telemeterCABundleConfigMap:
	case alertmanagerCABundleConfigMap:
	case grpcTLS:
	default:
		klog.V(5).Infof("ConfigMap or Secret (%s) not triggering an update.", key)
		return
	}

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
		o.queue.Forget(key)
		return true
	}

	o.reconcileErrors.Inc()
	klog.Errorf("Syncing %q failed", key)
	utilruntime.HandleError(errors.Wrap(err, fmt.Sprintf("sync %q failed", key)))
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
	config := o.Config(key)
	config.SetImages(o.images)
	config.SetTelemetryMatches(o.telemetryMatches)

	factory := manifests.NewFactory(o.namespace, o.namespaceUserWorkload, config)

	tl := tasks.NewTaskRunner(
		o.client,
		[]*tasks.TaskSpec{
			tasks.NewTaskSpec("Updating Prometheus Operator", tasks.NewPrometheusOperatorTask(o.client, factory)),
			tasks.NewTaskSpec("Updating user workload Prometheus Operator", tasks.NewPrometheusOperatorUserWorkloadTask(o.client, factory, config.UserWorkloadConfig)),
			tasks.NewTaskSpec("Updating Cluster Monitoring Operator", tasks.NewClusterMonitoringOperatorTask(o.client, factory)),
			tasks.NewTaskSpec("Updating Grafana", tasks.NewGrafanaTask(o.client, factory)),
			tasks.NewTaskSpec("Updating Prometheus-k8s", tasks.NewPrometheusTask(o.client, factory, config)),
			tasks.NewTaskSpec("Updating Prometheus-user-workload", tasks.NewPrometheusUserWorkloadTask(o.client, factory, config.UserWorkloadConfig)),
			tasks.NewTaskSpec("Updating Alertmanager", tasks.NewAlertmanagerTask(o.client, factory)),
			tasks.NewTaskSpec("Updating node-exporter", tasks.NewNodeExporterTask(o.client, factory)),
			tasks.NewTaskSpec("Updating kube-state-metrics", tasks.NewKubeStateMetricsTask(o.client, factory)),
			tasks.NewTaskSpec("Updating openshift-state-metrics", tasks.NewOpenShiftStateMetricsTask(o.client, factory)),
			tasks.NewTaskSpec("Updating prometheus-adapter", tasks.NewPrometheusAdapterTaks(o.namespace, o.client, factory)),
			tasks.NewTaskSpec("Updating Telemeter client", tasks.NewTelemeterClientTask(o.client, factory, config.TelemeterClientConfig)),
			tasks.NewTaskSpec("Updating configuration sharing", tasks.NewConfigSharingTask(o.client, factory)),
			tasks.NewTaskSpec("Updating Thanos Querier", tasks.NewThanosQuerierTask(o.client, factory, config.UserWorkloadConfig)),
		},
	)

	klog.Info("Updating ClusterOperator status to in progress.")
	err := o.client.StatusReporter().SetInProgress()
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

func (o *Operator) loadConfig(key string) *manifests.Config {
	c := manifests.NewDefaultConfig()

	obj, found, err := o.cmapInf.GetStore().GetByKey(key)
	if err != nil {
		klog.Warningf("An error occurred retrieving the Cluster Monitoring ConfigMap. Using defaults: %v", err)
		return c
	}

	if !found {
		klog.Warning("No Cluster Monitoring ConfigMap was found. Using defaults.")
		return c
	}

	cmap := obj.(*v1.ConfigMap)
	configContent, found := cmap.Data["config.yaml"]

	if !found {
		klog.Warning("Cluster Monitoring ConfigMap does not contain a config. Using defaults.")
		return c
	}

	cParsed, err := manifests.NewConfigFromString(configContent)
	if err != nil {
		klog.Warningf("Cluster Monitoring config could not be parsed. Using defaults: %v", err)
		return c
	}

	return cParsed
}

func (o *Operator) Config(key string) *manifests.Config {
	c := o.loadConfig(key)

	// Only fetch the the token and cluster ID if they have not been specified in the config.
	if c.TelemeterClientConfig.ClusterID == "" || c.TelemeterClientConfig.Token == "" {
		err := c.LoadClusterID(func() (*configv1.ClusterVersion, error) {
			return o.client.GetClusterVersion("version")
		})

		if err != nil {
			klog.Warningf("Could not fetch cluster version from API. Proceeding without it: %v", err)
		}

		err = c.LoadToken(func() (*v1.Secret, error) {
			return o.client.KubernetesInterface().CoreV1().Secrets("openshift-config").Get("pull-secret", metav1.GetOptions{})
		})

		if err != nil {
			klog.Warningf("Error loading token from API. Proceeding without it: %v", err)
		}
	}

	err := c.LoadProxy(func() (*configv1.Proxy, error) {
		return o.client.GetProxy("cluster")
	})
	if err != nil {
		klog.Warningf("Could not load proxy configuration from API. This is expected and message can be ignored when proxy configuration doesn't exist. Proceeding without it: %v", err)
	}

	cm, err := o.client.GetConfigmap("openshift-config", "etcd-metric-serving-ca")
	if err != nil {
		klog.Warningf("Error loading etcd CA certificates for Prometheus. Proceeding with etcd disabled. Error: %v", err)
	}

	s, err := o.client.GetSecret("openshift-config", "etcd-metric-client")
	if err != nil {
		klog.Warningf("Error loading etcd client secrets for Prometheus. Proceeding with etcd disabled. Error: %v", err)
	}

	if err == nil {
		caContent, caFound := cm.Data["ca-bundle.crt"]
		certContent, certFound := s.Data["tls.crt"]
		keyContent, keyFound := s.Data["tls.key"]

		if caFound && len(caContent) > 0 &&
			certFound && len(certContent) > 0 &&
			keyFound && len(keyContent) > 0 {

			trueBool := true
			c.EtcdConfig.Enabled = &trueBool
		}
	}

	return c
}
