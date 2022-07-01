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
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pkg/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"k8s.io/utils/pointer"

	osmv1alpha1 "github.com/openshift/api/monitoring/v1alpha1"
	"github.com/openshift/cluster-monitoring-operator/pkg/client"

	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
)

const (
	resyncPeriod   = 15 * time.Minute
	queueBaseDelay = 50 * time.Millisecond
	queueMaxDelay  = 3 * time.Minute

	alertSourceLabel = "openshift_io_user_alert"
	alertSourceValue = "true"
)

// RuleController is a controller for OpenShift AlertingRule objects.
type RuleController struct {
	version          string
	client           *client.Client
	queue            workqueue.RateLimitingInterface
	promRuleInformer cache.SharedIndexInformer
	ruleInformer     cache.SharedIndexInformer
}

// NewRuleController returns a new AlertingRule controller instance.
func NewRuleController(ctx context.Context, client *client.Client, version string) (*RuleController, error) {
	tp, err := client.TechPreviewEnabled(ctx)
	if err != nil {
		return nil, err
	}

	var lw cache.ListerWatcher
	if tp {
		// AlertingRule resources are only allowed in the operator namespace.
		lw = client.AlertingRuleListWatchForNamespace(client.Namespace())
	} else {
		// Instantiate a fake lister/watcher that returns no items.
		lw = &cache.ListWatch{
			ListFunc: func(metav1.ListOptions) (runtime.Object, error) {
				return &osmv1alpha1.AlertingRuleList{
					TypeMeta: metav1.TypeMeta{
						Kind: "List",
					},
				}, nil
			},
			WatchFunc: func(metav1.ListOptions) (watch.Interface, error) {
				return watch.NewFake(), nil
			},
		}
	}

	ruleInformer := cache.NewSharedIndexInformer(
		lw,
		&osmv1alpha1.AlertingRule{},
		resyncPeriod,
		cache.Indexers{},
	)

	// All generated PrometheusRule objects go into the platform namespace as
	// well, so we only need to watch those here.
	promRuleInformer := cache.NewSharedIndexInformer(
		client.PrometheusRuleListWatchForNamespace(client.Namespace()),
		&monv1.PrometheusRule{},
		resyncPeriod,
		cache.Indexers{},
	)

	queue := workqueue.NewNamedRateLimitingQueue(
		workqueue.NewItemExponentialFailureRateLimiter(queueBaseDelay, queueMaxDelay),
		"alerting-rules",
	)

	rc := &RuleController{
		version:          version,
		client:           client,
		ruleInformer:     ruleInformer,
		promRuleInformer: promRuleInformer,
		queue:            queue,
	}

	ruleInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    rc.handleAlertingRuleAdd,
		UpdateFunc: rc.handleAlertingRuleUpdate,
		DeleteFunc: rc.handleAlertingRuleDelete,
	})

	promRuleInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    nil, // No need to handle adds.
		UpdateFunc: rc.handlePrometheusRuleUpdate,
		DeleteFunc: rc.handlePrometheusRuleDelete,
	})

	return rc, nil
}

// Run starts the controller, and blocks until the done channel for the given
// context is closed.
func (rc *RuleController) Run(ctx context.Context, workers int) {
	klog.Info("Starting alerting rules controller")

	defer rc.queue.ShutDown()

	go rc.promRuleInformer.Run(ctx.Done())
	go rc.ruleInformer.Run(ctx.Done())

	cache.WaitForNamedCacheSync("AlertingRule controller", ctx.Done(),
		rc.promRuleInformer.HasSynced,
		rc.ruleInformer.HasSynced,
	)

	go rc.worker(ctx)

	<-ctx.Done()
}

// keyFunc derives a queue or cache key for the given object, while properly
// handling tombstone objects.
func (rc *RuleController) keyFunc(obj interface{}) (string, bool) {
	k, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		klog.Errorf("Creating key of AlertingRule object failed: %v", err)
		return k, false
	}

	return k, true
}

// enqueue adds the key for the given object to the queue.
func (rc *RuleController) enqueue(obj interface{}) {
	if obj == nil {
		return
	}

	key, ok := obj.(string)
	if !ok {
		key, ok = rc.keyFunc(obj)
		if !ok {
			return
		}
	}

	rc.queue.Add(key)
}

// handleAlertingRuleAdd handles add events for the AlertingRule informer.
func (rc *RuleController) handleAlertingRuleAdd(obj interface{}) {
	key, ok := rc.keyFunc(obj)
	if !ok {
		return
	}

	klog.V(4).Infof("AlertingRule added: %s", key)
	rc.enqueue(key)
}

// handleAlertingRuleDelete handles delete events for the AlertingRule informer.
func (rc *RuleController) handleAlertingRuleDelete(obj interface{}) {
	key, ok := rc.keyFunc(obj)
	if !ok {
		return
	}

	klog.V(4).Infof("AlertingRule deleted: %s", key)
	rc.enqueue(key)
}

// handleAlertingRuleUpdate handles update events for the AlertingRule informer.
func (rc *RuleController) handleAlertingRuleUpdate(oldObj, newObj interface{}) {
	oldAR, ok := oldObj.(*osmv1alpha1.AlertingRule)
	if !ok {
		return
	}

	newAR, ok := newObj.(*osmv1alpha1.AlertingRule)
	if !ok {
		return
	}

	// If the ResourceVersion hasn't changed, there's nothing to do.
	if oldAR.ResourceVersion == newAR.ResourceVersion {
		klog.V(4).Info("Ignoring AlertingRule update due to identical ResourceVersion (%s)",
			newAR.ResourceVersion)
		return
	}

	// If the Generation hasn't changed, the spec hasn't changed. Nothing to do.
	if oldAR.Generation == newAR.Generation {
		klog.V(4).Infof("Ignoring AlertingRule update due to identical Generation (%d)",
			newAR.Generation)
		return
	}

	key, ok := rc.keyFunc(newAR)
	if !ok {
		return
	}

	klog.V(4).Infof("AlertingRule updated: %s", key)
	rc.enqueue(key)
}

// worker starts processing of the controller's work queue.
func (rc *RuleController) worker(ctx context.Context) {
	for rc.processNextWorkItem(ctx) {
	}
}

// processNextWorkItem processes the next item on the work queue.
func (rc *RuleController) processNextWorkItem(ctx context.Context) bool {
	key, quit := rc.queue.Get()
	if quit {
		return false
	}

	defer rc.queue.Done(key)

	if err := rc.sync(ctx, key.(string)); err != nil {
		utilruntime.HandleError(errors.Wrap(err,
			fmt.Sprintf("Error syncing AlertingRule (%s)", key.(string))))

		// Re-queue failed sync.
		rc.queue.AddRateLimited(key)

		return true
	}

	klog.V(4).Infof("AlertingRule successfully synced: %s", key.(string))
	rc.queue.Forget(key) // Reset rate-limiting.

	return true
}

// sync reconciles the desired state of the AlertingRule for the given key.  It
// fetches the AlertingRule from the API, then generates a new PrometheusRule
// object based on the AlertingRule.
func (rc *RuleController) sync(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}

	rule, err := rc.client.GetAlertingRule(ctx, namespace, name)
	switch {
	case apierrors.IsNotFound(err):
		// Deletion is handled automatically via the OwnerReference.
		return nil

	case err != nil:
		return err
	}

	klog.V(4).Infof("Syncing AlertingRule: %s", key)

	rule.APIVersion = osmv1alpha1.GroupVersion.String()
	rule.Kind = "AlertingRule"

	// Generate the new or updated PrometheusRule object.
	promRule := &monv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rc.promRuleName(rule.Namespace, rule.Name, rule.UID),
			Namespace: rc.client.Namespace(),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         rule.APIVersion,
					Kind:               rule.Kind,
					Name:               rule.Name,
					UID:                rule.UID,
					Controller:         pointer.Bool(true),
					BlockOwnerDeletion: pointer.Bool(true),
				},
			},
			Labels: map[string]string{
				"app.kubernetes.io/version":   rc.version,
				"app.kubernetes.io/component": "alerting-rules-controller",
				"app.kubernetes.io/name":      "cluster-monitoring-operator",
				"app.kubernetes.io/part-of":   "openshift-monitoring",
				"prometheus":                  "k8s",
				"role":                        "alerting-rules",
			},
		},
		Spec: monv1.PrometheusRuleSpec{
			Groups: rc.convertRuleGroups(rule.Spec.Groups),
		},
	}

	if err := rc.client.CreateOrUpdatePrometheusRule(ctx, promRule); err != nil {
		return err
	}

	// Update AlertingRule status with latest observed generation, and the name of
	// the generated PrometheusRule object.
	rule.Status.ObservedGeneration = rule.Generation
	rule.Status.PrometheusRule.Name = fmt.Sprintf("%s/%s", promRule.Namespace, promRule.Name)

	return rc.client.UpdateAlertingRuleStatus(ctx, rule)
}

// promRuleName returns the name of PrometheusRule to be generated for the given
// AlertingRule namespace, name, and UID.
func (rc *RuleController) promRuleName(namespace, name string, uid types.UID) string {
	data := fmt.Sprintf("%s-%s-%s", namespace, name, uid)
	hash := md5.Sum([]byte(data))
	hexString := hex.EncodeToString(hash[:])

	return fmt.Sprintf("%s-%s", name, hexString[:6])
}

// convertRuleGroups converts the given OpenShift Monitoring RuleGroups to their
// corresponding upstream prometheus-operator versions.  It ensures each rule has
// a static label identifying the rule as coming from platform-monitoring, while
// being user-defined.
func (rc *RuleController) convertRuleGroups(groups []osmv1alpha1.RuleGroup) []monv1.RuleGroup {
	monv1Groups := make([]monv1.RuleGroup, len(groups))

	for i, group := range groups {
		monv1Group := monv1.RuleGroup{Name: group.Name, Interval: group.Interval}
		monv1Group.Rules = make([]monv1.Rule, len(group.Rules))

		for j, rule := range group.Rules {
			monv1Rule := monv1.Rule{
				Alert:       rule.Alert,
				Expr:        rule.Expr,
				For:         rule.For,
				Labels:      rule.Labels,
				Annotations: rule.Annotations,
			}

			if monv1Rule.Labels == nil {
				monv1Rule.Labels = make(map[string]string)
			}

			// Set a static label indicating this rule is user-defined.
			monv1Rule.Labels[alertSourceLabel] = alertSourceValue
			monv1Group.Rules[j] = monv1Rule
		}

		monv1Groups[i] = monv1Group
	}

	return monv1Groups
}

// handlePrometheusRuleUpdate handles add events for the PrometheusRule informer.
func (rc *RuleController) handlePrometheusRuleUpdate(oldObj, newObj interface{}) {
	oldPR, ok := oldObj.(*monv1.PrometheusRule)
	if !ok {
		return
	}

	newPR, ok := newObj.(*monv1.PrometheusRule)
	if !ok {
		return
	}

	// If the ResourceVersion hasn't changed, there's nothing to do.
	if oldPR.ResourceVersion == newPR.ResourceVersion {
		klog.V(4).Info("Ignoring PrometheusRule update due to identical ResourceVersion (%s)",
			newPR.ResourceVersion)
		return
	}

	// If the Generation hasn't changed, the spec hasn't changed. Nothing to do.
	if oldPR.Generation == newPR.Generation {
		klog.V(4).Infof("Ignoring PrometheusRule update due to identical Generation (%d)",
			newPR.Generation)
		return
	}

	owner := firstAlertingRuleOwner(newPR.GetOwnerReferences())

	if owner == "" {
		klog.V(4).Infof("Ignoring PrometheusRule %q update with no AlertingRule owner")
		return
	}

	key := fmt.Sprintf("%s/%s", newPR.Namespace, owner)

	klog.V(4).Infof("PrometheusRule %q updated, queuing sync of AlertingRule: %s",
		newPR.Name, key)

	rc.enqueue(key)
}

// handlePrometheusRuleDelete handles delete events for the PrometheusRule informer.
func (rc *RuleController) handlePrometheusRuleDelete(obj interface{}) {
	var pr *monv1.PrometheusRule

	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		pr, ok = d.Obj.(*monv1.PrometheusRule)
		if !ok {
			return
		}
	} else {
		pr, ok = obj.(*monv1.PrometheusRule)
		if !ok {
			return
		}
	}

	owner := firstAlertingRuleOwner(pr.GetOwnerReferences())

	if owner == "" {
		klog.V(4).Infof("Ignoring PrometheusRule %q deletion with no AlertingRule owner")
		return
	}

	key := fmt.Sprintf("%s/%s", pr.Namespace, owner)

	klog.V(4).Infof("PrometheusRule %q deleted, queuing sync of AlertingRule: %s",
		pr.Name, key)

	rc.enqueue(key)
}

// firstAlertingRuleOwner returns the name of the first owner reference found that
// is an AlertingRule resource, or an empty string if there is none.
func firstAlertingRuleOwner(refs []metav1.OwnerReference) string {
	apiVersion, kind := osmv1alpha1.GroupVersion.String(), "AlertingRule"

	for _, ref := range refs {
		if ref.APIVersion == apiVersion && ref.Kind == kind {
			return ref.Name
		}
	}

	return ""
}
