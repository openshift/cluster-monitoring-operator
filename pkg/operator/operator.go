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
	"time"

	"github.com/golang/glog"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/pkg/tasks"
)

var (
	// This variable is intended to be overridden at build time.
	Version = "dev"
)

const (
	resyncPeriod = 5 * time.Minute

	// see https://github.com/kubernetes/apiserver/blob/b571c70e6e823fd78910c3f5b9be895a756f4cbb/pkg/server/options/authentication.go#L239
	apiAuthenticationConfigMap = "kube-system/extension-apiserver-authentication"
	kubeletServingCAConfigMap  = "openshift-config-managed/kubelet-serving-ca"
	prometheusAdapterTLSSecret = "openshift-monitoring/prometheus-adapter-tls"
)

type Operator struct {
	namespace string

	configMapName string
	images        map[string]string

	client *client.Client

	cmapInf                       cache.SharedIndexInformer
	kubeSystemCmapInf             cache.SharedIndexInformer
	openshiftConfigManagedCmapInf cache.SharedIndexInformer
	secretInf                     cache.SharedIndexInformer

	queue workqueue.RateLimitingInterface

	reconcileAttempts prometheus.Counter
	reconcileErrors   prometheus.Counter
}

func New(config *rest.Config, namespace, namespaceSelector, configMapName string, images map[string]string) (*Operator, error) {
	c, err := client.New(config, Version, namespace, namespaceSelector)
	if err != nil {
		return nil, err
	}

	o := &Operator{
		images:        images,
		configMapName: configMapName,
		namespace:     namespace,
		client:        c,
		queue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cluster-monitoring"),
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
		glog.V(4).Infof("Connection established (cluster-version: %s)", v)

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
	go o.kubeSystemCmapInf.Run(stopc)

	glog.V(4).Info("Waiting for initial cache sync.")
	ok := cache.WaitForCacheSync(stopc, o.cmapInf.HasSynced, o.kubeSystemCmapInf.HasSynced)
	if !ok {
		return errors.New("failed to sync informers")
	}
	glog.V(4).Info("Initial cache sync done.")

	go o.worker()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	key := o.namespace + "/" + o.configMapName
	_, exists, _ := o.cmapInf.GetStore().GetByKey(key)
	if !exists {
		glog.Info("ConfigMap to configure stack does not exist. Reconciling with default config every 5 minutes.")
		o.enqueue(key)
	}

	for {
		select {
		case <-stopc:
			return nil
		case <-ticker.C:
			_, exists, _ := o.cmapInf.GetStore().GetByKey(key)
			if !exists {
				glog.Info("ConfigMap to configure stack does not exist. Reconciling with default config every 5 minutes.")
				o.enqueue(key)
			}
		}
	}

	return nil
}

func (o *Operator) keyFunc(obj interface{}) (string, bool) {
	k, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		glog.Errorf("creating key failed, err: %s", err)
		return k, false
	}
	return k, true
}

func (o *Operator) handleEvent(obj interface{}) {
	key, ok := o.keyFunc(obj)
	if !ok {
		return
	}

	glog.V(5).Infof("ConfigMap updated: %s", key)

	cmoConfigMap := o.namespace + "/" + o.configMapName

	switch key {
	case cmoConfigMap:
	case apiAuthenticationConfigMap:
	case kubeletServingCAConfigMap:
	case prometheusAdapterTLSSecret:
	default:
		glog.V(5).Infof("ConfigMap (%s) not triggering an update.", key)
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
	glog.Errorf("Syncing %q failed", key)
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

	factory := manifests.NewFactory(o.namespace, config)

	tl := tasks.NewTaskRunner(
		o.client,
		[]*tasks.TaskSpec{
			tasks.NewTaskSpec("Updating Prometheus Operator", tasks.NewPrometheusOperatorTask(o.client, factory)),
			tasks.NewTaskSpec("Updating Cluster Monitoring Operator", tasks.NewClusterMonitoringOperatorTask(o.client, factory)),
			tasks.NewTaskSpec("Updating Grafana", tasks.NewGrafanaTask(o.client, factory)),
			tasks.NewTaskSpec("Updating Prometheus-k8s", tasks.NewPrometheusTask(o.client, factory, config)),
			tasks.NewTaskSpec("Updating Alertmanager", tasks.NewAlertmanagerTask(o.client, factory)),
			tasks.NewTaskSpec("Updating node-exporter", tasks.NewNodeExporterTask(o.client, factory)),
			tasks.NewTaskSpec("Updating kube-state-metrics", tasks.NewKubeStateMetricsTask(o.client, factory)),
			tasks.NewTaskSpec("Updating prometheus-adapter", tasks.NewPrometheusAdapterTaks(o.namespace, o.client, factory)),
			tasks.NewTaskSpec("Updating Telemeter client", tasks.NewTelemeterClientTask(o.client, factory, config.TelemeterClientConfig)),
			tasks.NewTaskSpec("Updating configuration sharing", tasks.NewConfigSharingTask(o.client, factory)),
		},
	)

	glog.Info("Updating ClusterOperator status to in progress.")
	err := o.client.StatusReporter().SetInProgress()
	if err != nil {
		glog.Errorf("error occurred while setting status to in progress: %v", err)
	}

	err = tl.RunAll()
	if err != nil {
		glog.Infof("Updating ClusterOperator status to failed. Err: %v", err)
		reportErr := o.client.StatusReporter().SetFailed(err)
		if reportErr != nil {
			glog.Errorf("error occurred while setting status to in progress: %v", reportErr)
		}
		return err
	}

	glog.Info("Updating ClusterOperator status to done.")
	err = o.client.StatusReporter().SetDone()
	if err != nil {
		glog.Errorf("error occurred while setting status to done: %v", err)
	}

	return nil
}

func (o *Operator) loadConfig(key string) *manifests.Config {
	c := manifests.NewDefaultConfig()

	obj, found, err := o.cmapInf.GetStore().GetByKey(key)
	if err != nil {
		glog.Warningf("An error occurred retrieving the Cluster Monitoring ConfigMap. Using defaults: %v", err)
		return c
	}

	if !found {
		glog.Warning("No Cluster Monitoring ConfigMap was found. Using defaults.")
		return c
	}

	cmap := obj.(*v1.ConfigMap)
	configContent, found := cmap.Data["config.yaml"]

	if !found {
		glog.Warning("Cluster Monitoring ConfigMap does not contain a config. Using defaults.")
		return c
	}

	cParsed, err := manifests.NewConfigFromString(configContent)
	if err != nil {
		glog.Warningf("Cluster Monitoring config could not be parsed. Using defaults: %v", err)
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
			glog.Warningf("Could not fetch cluster version from API. Proceeding without it: %v", err)
		}

		err = c.LoadToken(func() (*v1.ConfigMap, error) {
			return o.client.KubernetesInterface().CoreV1().ConfigMaps("kube-system").Get("cluster-config-v1", metav1.GetOptions{})
		})

		if err != nil {
			glog.Warningf("Error loading token from API. Proceeding without it: %v", err)
		}
	}

	err := c.LoadProxy(func() (*configv1.Proxy, error) {
		return o.client.GetProxy("cluster")
	})

	if err != nil {
		glog.Warningf("Error loading proxy from API. Proceeding without it: %v", err)
	}

	return c
}
