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

package alert

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	osmv1alpha1 "github.com/openshift/api/monitoring/v1alpha1"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"
)

const (
	resyncPeriod   = 15 * time.Minute
	queueBaseDelay = 50 * time.Millisecond
	queueMaxDelay  = 3 * time.Minute

	// The secret containing additional alert relabel configs.
	secretName = "alert-relabel-configs"
	secretKey  = "config.yaml"
)

// RelabelConfigController is a controller for AlertRelabelConfig resources.
type RelabelConfigController struct {
	client                *client.Client
	queue                 workqueue.RateLimitingInterface
	relabelConfigInformer cache.SharedIndexInformer
	secretInformer        cache.SharedIndexInformer
}

// NewRelabelConfigController returns a new RelabelConfigController instance.
func NewRelabelConfigController(client *client.Client) *RelabelConfigController {
	// Only AlertRelabelConfig resources in the operator namespace are watched.
	relabelConfigInformer := cache.NewSharedIndexInformer(
		client.AlertRelabelConfigListWatchForNamespace(client.Namespace()),
		&osmv1alpha1.AlertRelabelConfig{},
		resyncPeriod,
		cache.Indexers{},
	)

	// We only care about watching the single secret that is generated from
	// combining the AlertRelabelConfig resources.
	secretInformer := cache.NewSharedIndexInformer(
		client.SecretListWatchForResource(client.Namespace(), secretName),
		&corev1.Secret{},
		resyncPeriod,
		cache.Indexers{},
	)

	queue := workqueue.NewNamedRateLimitingQueue(
		workqueue.NewItemExponentialFailureRateLimiter(queueBaseDelay, queueMaxDelay),
		"alert-relabel-configs",
	)

	controller := &RelabelConfigController{
		client:                client,
		queue:                 queue,
		relabelConfigInformer: relabelConfigInformer,
		secretInformer:        secretInformer,
	}

	relabelConfigInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.handleAlertRelabelConfigAdd,
		UpdateFunc: controller.handleAlertRelabelConfigUpdate,
		DeleteFunc: controller.handleAlertRelabelConfigDelete,
	})

	secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    controller.handleSecretAdd,
		UpdateFunc: controller.handleSecretUpdate,
		DeleteFunc: controller.handleSecretDelete,
	})

	return controller
}

// Run starts the controller, and blocks until the done channel for the given
// context is closed.
func (c *RelabelConfigController) Run(ctx context.Context, workers int) {
	klog.Info("Starting alert relabel config controller")

	defer c.queue.ShutDown()

	go c.relabelConfigInformer.Run(ctx.Done())
	go c.secretInformer.Run(ctx.Done())

	cache.WaitForNamedCacheSync("AlertRelabelConfig controller", ctx.Done(),
		c.relabelConfigInformer.HasSynced,
		c.secretInformer.HasSynced,
	)

	go c.worker(ctx)

	<-ctx.Done()
}

// keyFunc derives a queue or cache key for the given object, while properly
// handling tombstone objects.
func (c *RelabelConfigController) keyFunc(obj interface{}) (string, bool) {
	k, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Creating AlertRelabelConfig key failed: %v", err)
		return k, false
	}

	return k, true
}

// enqueue adds the key for the given object to the queue.
func (c *RelabelConfigController) enqueue(obj interface{}) {
	if obj == nil {
		return
	}

	key, ok := obj.(string)
	if !ok {
		key, ok = c.keyFunc(obj)
		if !ok {
			return
		}
	}

	c.queue.Add(key)
}

// worker starts processing of the controller's work queue.
func (c *RelabelConfigController) worker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

// processNextWorkItem processes the next item on the work queue.
func (c *RelabelConfigController) processNextWorkItem(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(key)

	if err := c.sync(ctx, key.(string)); err != nil {
		utilruntime.HandleError(errors.Wrap(err,
			fmt.Sprintf("Error syncing AlertRelabelConfig (%s)", key.(string))))

		// Re-queue failed sync.
		c.queue.AddRateLimited(key)

		return true
	}

	klog.V(4).Infof("AlertRelabelConfig successfully synced: %s", key.(string))
	c.queue.Forget(key) // Reset rate-limiting.

	return true
}

// handleAlertRelabelConfigAdd handles add events for the AlertRelabelConfig informer.
func (c *RelabelConfigController) handleAlertRelabelConfigAdd(obj interface{}) {
	key, ok := c.keyFunc(obj)
	if !ok {
		return
	}

	klog.V(4).Infof("AlertRelabelConfig added: %s", key)
	c.enqueue(key)
}

// handleAlertRelabelConfigDelete handles delete events for the AlertRelabelConfig informer.
func (c *RelabelConfigController) handleAlertRelabelConfigDelete(obj interface{}) {
	key, ok := c.keyFunc(obj)
	if !ok {
		return
	}

	klog.V(4).Infof("AlertRelabelConfig deleted: %s", key)
	c.enqueue(key)
}

// handleAlertRelabelConfigUpdate handles update events for the AlertRelabelConfig informer.
func (c *RelabelConfigController) handleAlertRelabelConfigUpdate(oldObj, newObj interface{}) {
	// If the ResourceVersion hasn't changed, there's nothing to do.
	if oldObj.(*osmv1alpha1.AlertRelabelConfig).ResourceVersion == newObj.(*osmv1alpha1.AlertRelabelConfig).ResourceVersion {
		klog.V(4).Info("Skipping AlertRelabelConfig update due to identical ResourceVersion (%s)",
			newObj.(*osmv1alpha1.AlertRelabelConfig).ResourceVersion)
		return
	}

	key, ok := c.keyFunc(newObj)
	if !ok {
		return
	}

	klog.V(4).Infof("AlertRelabelConfig updated: %s", key)
	c.enqueue(key)
}

// handleSecretAdd handles add events for the Secret informer.
func (c *RelabelConfigController) handleSecretAdd(obj interface{}) {
	klog.V(4).Infof("AlertRelabelConfig %q secret added", secretName)
	c.enqueue(fmt.Sprintf("secret/%s/%s", c.client.Namespace(), secretName))
}

// handleSecretAdd handles update events for the Secret informer.
func (c *RelabelConfigController) handleSecretUpdate(oldObj, newObj interface{}) {
	klog.V(4).Infof("AlertRelabelConfig %q secret updated", secretName)
	c.enqueue(fmt.Sprintf("secret/%s/%s", c.client.Namespace(), secretName))
}

// handleSecretAdd handles delete events for the Secret informer.
func (c *RelabelConfigController) handleSecretDelete(obj interface{}) {
	klog.V(4).Infof("AlertRelabelConfig %q secret deleted", secretName)
	c.enqueue(fmt.Sprintf("secret/%s/%s", c.client.Namespace(), secretName))
}

// sync reconciles the desired state of the AlertRelabelConfig for the given key.
func (c *RelabelConfigController) sync(ctx context.Context, key string) error {
	klog.V(4).Infof("AlertRelabelConfig sync for key: %s", key)

	relabelConfigs := make(map[string]*osmv1alpha1.AlertRelabelConfig)
	relabelConfigKeys := []string{}

	// Collect all non-deleted AlertRelabelConfig objects from the store.
	for _, obj := range c.relabelConfigInformer.GetStore().List() {
		rc, ok := obj.(*osmv1alpha1.AlertRelabelConfig)
		if !ok {
			klog.V(4).Infof("AlertRelabelConfig sync skipping object with type %T", obj)
			continue
		}

		if rc.DeletionTimestamp != nil {
			klog.V(4).Infof("AlertRelabelConfig sync skipping deleted object: %s", rc.Name)
			continue
		}

		relabelConfigs[rc.Name] = rc
		relabelConfigKeys = append(relabelConfigKeys, rc.Name)
	}

	sort.Strings(relabelConfigKeys)

	var yamlConfigs []yaml.MapSlice

	// Build a slice of YAML configs in lexicographical order.
	for _, k := range relabelConfigKeys {
		klog.V(4).Infof("Marshaling AlertRelabelConfig to YAML: %s", k)

		for _, c := range relabelConfigs[k].Spec.Configs {
			yamlConfigs = append(yamlConfigs, generateRelabelConfig(&c))
		}
	}

	outBytes, err := yaml.Marshal(yamlConfigs)
	if err != nil {
		return err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: c.client.Namespace(),
		},
		StringData: map[string]string{
			secretKey: string(outBytes),
		},
	}

	return c.client.CreateOrUpdateSecret(ctx, secret)
}

// generateRelabelConfig converts an osmv1alpha1.RelabelConfig to a yaml.MapSlice.
func generateRelabelConfig(c *osmv1alpha1.RelabelConfig) yaml.MapSlice {
	relabeling := yaml.MapSlice{}

	if len(c.SourceLabels) > 0 {
		relabeling = append(relabeling, yaml.MapItem{Key: "source_labels", Value: c.SourceLabels})
	}

	if c.Separator != "" {
		relabeling = append(relabeling, yaml.MapItem{Key: "separator", Value: c.Separator})
	}

	if c.TargetLabel != "" {
		relabeling = append(relabeling, yaml.MapItem{Key: "target_label", Value: c.TargetLabel})
	}

	if c.Regex != "" {
		relabeling = append(relabeling, yaml.MapItem{Key: "regex", Value: c.Regex})
	}

	if c.Modulus != uint64(0) {
		relabeling = append(relabeling, yaml.MapItem{Key: "modulus", Value: c.Modulus})
	}

	if c.Replacement != "" {
		relabeling = append(relabeling, yaml.MapItem{Key: "replacement", Value: c.Replacement})
	}

	if c.Action != "" {
		relabeling = append(relabeling, yaml.MapItem{Key: "action", Value: c.Action})
	}

	return relabeling
}
