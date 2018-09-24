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
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
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
)

type Operator struct {
	namespace     string
	configMapName string
	tagOverrides  map[string]string

	client *client.Client

	appvInf cache.SharedIndexInformer
	cmapInf cache.SharedIndexInformer

	queue workqueue.RateLimitingInterface

	reconcileAttempts prometheus.Counter
	reconcileErrors   prometheus.Counter
}

func New(namespace string, configMapName string, tagOverrides map[string]string) (*Operator, error) {
	c, err := client.New(namespace, configMapName)
	if err != nil {
		return nil, err
	}

	o := &Operator{
		tagOverrides:  tagOverrides,
		configMapName: configMapName,
		namespace:     namespace,
		client:        c,
		queue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cluster-monitoring"),
	}

	o.cmapInf = cache.NewSharedIndexInformer(
		o.client.ConfigMapListWatch(), &v1.ConfigMap{}, resyncPeriod, cache.Indexers{},
	)
	o.cmapInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    o.handleEvent,
		UpdateFunc: o.handleConfigMapUpdate,
		DeleteFunc: o.handleEvent,
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

	go o.worker()

	go o.cmapInf.Run(stopc)

	<-stopc
	return nil
}

func (o *Operator) keyFunc(obj interface{}) (string, bool) {
	k, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		glog.V(4).Infof("creating key failed, err: %s", err)
		return k, false
	}
	return k, true
}

func (o *Operator) handleConfigMapUpdate(_, cur interface{}) {
	o.handleEvent(cur)
}

func (o *Operator) handleEvent(obj interface{}) {
	key, ok := o.keyFunc(obj)
	if !ok {
		return
	}

	glog.V(4).Infof("ConfigMap updated: %s", key)
	monitoringConfigMapKey := o.namespace + "/" + o.configMapName
	if key != monitoringConfigMapKey {
		glog.V(4).Infof("ConfigMap (%s) not triggering an update. Only changes to %s configure the cluster monitoring stack.", key, monitoringConfigMapKey)
		return
	}
	o.enqueue(key)
}

func (o *Operator) worker() {
	glog.V(4).Info("Waiting for initial cache sync.")
	waitForInformerInitialSync(o.cmapInf)
	glog.V(4).Info("Initial cache sync done.")

	for o.processNextWorkItem() {
	}
}

func waitForInformerInitialSync(i ...cache.SharedInformer) {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			allSynced := true
			for _, inf := range i {
				allSynced = allSynced && inf.HasSynced()
			}
			if allSynced {
				return
			}
		}
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
	config := o.Config()
	config.SetTagOverrides(o.tagOverrides)

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
		},
	)

	return tl.RunAll()
}

func (o *Operator) Config() *manifests.Config {
	obj, exists, err := o.cmapInf.GetStore().GetByKey(o.namespace + "/" + o.configMapName)
	if err != nil {
		glog.V(4).Infof("An error occurred retrieving the Cluster Monitoring ConfigMap. Using defaults.")
		return manifests.NewDefaultConfig()
	}
	if !exists {
		return manifests.NewDefaultConfig()
	}

	cmap := obj.(*v1.ConfigMap)
	configContent, found := cmap.Data["config.yaml"]
	if !found {
		glog.V(4).Infof("Cluster Monitoring ConfigMap does not contain a config. Using defaults.")
		return manifests.NewDefaultConfig()
	}

	c, err := manifests.NewConfigFromString(configContent)
	if err != nil {
		glog.V(4).Infof("Cluster Monitoring config could not be parsed. Using defaults.")
		return manifests.NewDefaultConfig()
	}

	return c
}
