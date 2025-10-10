// Copyright 2025 The Cluster Monitoring Operator Authors
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

package alert

import (
	"context"
	"fmt"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
)

const (
	controllerName = "cluster-monitoring"
)

// ClusterMonitoringController is a controller for ClusterMonitoring resources.
type ClusterMonitoringController struct {
	client           *client.Client
	queue            workqueue.TypedRateLimitingInterface[string]
	informer         cache.SharedIndexInformer
	triggerReconcile func()
}

// NewClusterMonitoringController returns a new ClusterMonitoringController.
func NewClusterMonitoringController(ctx context.Context, client *client.Client, version string, triggerReconcile func()) (*ClusterMonitoringController, error) {
	informer := cache.NewSharedIndexInformer(
		client.ClusterMonitoringListWatch(),
		&configv1alpha1.ClusterMonitoring{},
		resyncPeriod,
		cache.Indexers{},
	)

	queue := workqueue.NewTypedRateLimitingQueueWithConfig[string](
		workqueue.NewTypedItemExponentialFailureRateLimiter[string](queueBaseDelay, queueMaxDelay),
		workqueue.TypedRateLimitingQueueConfig[string]{Name: controllerName},
	)

	controller := &ClusterMonitoringController{
		client:           client,
		queue:            queue,
		informer:         informer,
		triggerReconcile: triggerReconcile,
	}

	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.handleAdd,
		UpdateFunc: controller.handleUpdate,
		DeleteFunc: controller.handleDelete,
	})
	if err != nil {
		return nil, err
	}

	return controller, nil
}

// Run starts the controller.
func (c *ClusterMonitoringController) Run(ctx context.Context, workers int) {
	klog.Info("Starting ClusterMonitoring controller")
	defer c.queue.ShutDown()

	go c.informer.Run(ctx.Done())

	if !cache.WaitForNamedCacheSync("ClusterMonitoring controller", ctx.Done(), c.informer.HasSynced) {
		klog.Error("Failed to sync ClusterMonitoring controller cache")
		return
	}

	for i := 0; i < workers; i++ {
		go c.worker(ctx)
	}

	klog.Info("ClusterMonitoring controller started")
	<-ctx.Done()
	klog.Info("ClusterMonitoring controller stopped")
}

func (c *ClusterMonitoringController) worker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *ClusterMonitoringController) processNextWorkItem(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	if err := c.sync(ctx, key); err != nil {
		utilruntime.HandleError(fmt.Errorf("error syncing ClusterMonitoring (%s): %w", key, err))
		c.queue.AddRateLimited(key)
		return true
	}

	klog.V(4).Infof("ClusterMonitoring successfully synced: %s", key)
	c.queue.Forget(key)
	return true
}

func (c *ClusterMonitoringController) sync(ctx context.Context, key string) error {
	klog.V(4).Infof("ClusterMonitoring controller processing: %s", key)

	if c.triggerReconcile != nil {
		c.triggerReconcile()
	}

	return nil
}

func (c *ClusterMonitoringController) handleAdd(obj interface{}) {
	key, ok := c.keyFunc(obj)
	if !ok {
		return
	}
	klog.Infof("ClusterMonitoring added: %s", key)
	c.queue.Add(key)
}

func (c *ClusterMonitoringController) handleUpdate(oldObj, newObj interface{}) {
	key, ok := c.keyFunc(newObj)
	if !ok {
		return
	}
	klog.Infof("ClusterMonitoring updated: %s", key)
	c.queue.Add(key)
}

func (c *ClusterMonitoringController) handleDelete(obj interface{}) {
	key, ok := c.keyFunc(obj)
	if !ok {
		return
	}
	klog.Infof("ClusterMonitoring deleted: %s", key)
	c.queue.Add(key)
}

func (c *ClusterMonitoringController) keyFunc(obj interface{}) (string, bool) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Creating key for ClusterMonitoring object failed: %v", err)
		return key, false
	}
	return key, true
}
