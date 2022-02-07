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
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/openshift/cluster-monitoring-operator/pkg/namespace"

	osmv1alpha1 "github.com/openshift/api/monitoring/v1alpha1"
	osmclientset "github.com/openshift/client-go/monitoring/clientset/versioned"

	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/relabel"
)

// OverrideLabel is the label added to patched rules to identify them as
// overrides.  The original rules must not have this label, because its absence
// is used in the alert_relabel_configs to drop the original alert.
const OverrideLabel = "monitoring_openshift_io__alert_override"

const (
	alertIdxName       = "alert-name"
	overridesName      = "alert-overrides"
	prometheusRuleName = "alert-overrides"
	relabelGroupName   = "050-alert-overrides"

	resyncPeriod = 15 * time.Minute
)

// Overrider is a controller that applies user-supplied overrides to platform
// alerting rules, and creates new user-defined alerting rules.
type Overrider struct {
	ctx               context.Context
	osmclient         osmclientset.Interface
	client            *client.Client
	assets            *manifests.Assets
	nsWatcher         *namespace.Watcher
	relabeler         *Relabeler
	overridesInformer cache.SharedIndexInformer
	ruleInformer      cache.SharedIndexInformer
	ruleIndexer       cache.Indexer
}

// NewOverrider returns a new Overrider controller instance.  You must then call
// Run() to start the controller.
//
// TODO(bison): Should we take a context here or just create one?
func NewOverrider(ctx context.Context, client *client.Client, relabeler *Relabeler) *Overrider {
	// Only watching the single "alert-overrides" AlertOverrides resource.
	overridesInformer := cache.NewSharedIndexInformer(
		client.AlertOverridesListWatchForResource(
			ctx,
			client.Namespace(),
			overridesName,
		),
		&osmv1alpha1.AlertOverrides{},
		resyncPeriod,
		cache.Indexers{},
	)

	// We watch all namespaces for PrometheusRule objects, but the name-severity
	// indexer only indexes rules from platform namespaces.
	//
	// TODO(bison): Need to add event handlers to reconcile overrides when the
	// overriden alerting rules change, not just when our resource changes.
	ruleInformer := cache.NewSharedIndexInformer(
		client.PrometheusRuleListWatchForNamespace(metav1.NamespaceAll),
		&monv1.PrometheusRule{},
		resyncPeriod,
		cache.Indexers{},
	)

	// TODO(bison): Should we add event handlers to the namespace watcher? If
	// the platform-monitoring label is removed from a namespace, but the
	// PrometheusRule still exists should any override then be removed?
	nsWatcher := namespace.NewWatcher(resyncPeriod, client.PlatformNamespacesListWatch())

	overrider := &Overrider{
		ctx:               ctx,
		client:            client,
		nsWatcher:         nsWatcher,
		relabeler:         relabeler,
		overridesInformer: overridesInformer,
		ruleInformer:      ruleInformer,
		ruleIndexer:       ruleInformer.GetIndexer(),
		osmclient:         client.OpenShiftMonitoring(),
	}

	overridesInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    overrider.processOverrides,
		DeleteFunc: overrider.deleteOverrides,
		UpdateFunc: func(_, newObj interface{}) {
			overrider.processOverrides(newObj)
		},
	})

	ruleInformer.AddIndexers(cache.Indexers{
		alertIdxName: overrider.indexByAlertName,
	})

	return overrider
}

// Run starts all informers and blocks until the context is closed.
func (o *Overrider) Run(ctx context.Context, workers int) {
	klog.Info("Starting alert overrides controller")

	// TODO(bison): Should we wait for these to sync here, or provide a method
	// for the caller to wait after calling run()?
	go o.nsWatcher.Run(ctx, workers)
	go o.overridesInformer.Run(ctx.Done())
	go o.ruleInformer.Run(ctx.Done())

	<-ctx.Done()
}

// findRule takes an AlertSelector and returns the matching rule from the index,
// if and only if a unique match is found.  Otherwise and error is returned.
func (o *Overrider) findRule(selector *osmv1alpha1.AlertSelector) (*monv1.Rule, error) {
	if !o.ruleInformer.HasSynced() {
		return nil, fmt.Errorf("PrometheusRule informer has not yet synced")
	}

	// Find all PrometheusRule objects with the selected rule name.
	objs, err := o.ruleIndexer.ByIndex(alertIdxName, selector.Alert)
	if err != nil {
		return nil, err
	}

	var foundRules []*monv1.Rule

	for _, obj := range objs {
		pr, ok := obj.(*monv1.PrometheusRule)
		if !ok {
			klog.Warningf("Object in cache is %T, not PrometheusRule", obj)
			continue
		}

		if pr.GetNamespace() == o.client.Namespace() &&
			pr.GetName() == prometheusRuleName {
			// Don't return rules in the generated overrides object.
			//
			// TODO(bison): Should we just not index the overrides
			// PrometheusRule object?
			continue
		}

		matched, err := matchRules(pr.Spec.Groups, selector)
		if err != nil {
			klog.Warningf("Error matching alerting rules: %v", err)
			continue
		}

		foundRules = append(foundRules, matched...)
	}

	// TODO(bison): This error message is used in the status conditions.  It
	// should probably include more information at some point.
	if found := len(foundRules); found != 1 {
		return nil, fmt.Errorf("found %d PrometheusRule objects for alert: %s",
			found, selector.Alert)
	}

	return foundRules[0], nil
}

// patchRule attempts to find the rule targeted by the given override, and
// returns a new rule with the overrides applied.
func (o *Overrider) patchRule(override *osmv1alpha1.AlertOverride) (*monv1.Rule, error) {
	rule, err := o.findRule(&override.Selector)
	if err != nil {
		return nil, err
	}

	if override.For != nil {
		rule.For = *override.For
	}

	if override.Expr != nil {
		rule.Expr = *override.Expr
	}

	if override.Labels != nil {
		rule.Labels = labels.Merge(rule.Labels, override.Labels)
	}

	if override.Annotations != nil {
		rule.Annotations = labels.Merge(rule.Annotations, override.Annotations)
	}

	rule.Labels[OverrideLabel] = "true"

	return rule, nil
}

// alertRelabelConfigs returns a secret with the default alert relabel configs
// along with any generated for patched or dropped alerting rules.
func (o *Overrider) alertRelabelConfigs(selectors []osmv1alpha1.AlertSelector) ([]relabel.Config, error) {
	var configs []relabel.Config

	for _, s := range selectors {
		config, err := relabelConfig(s)
		if err != nil {
			klog.Errorf("Error generating relabel config: %v")
			continue
		}

		config.Action = relabel.Drop
		configs = append(configs, config)
	}

	return configs, nil
}

// deleteOverrides removes the generated alert relabel configs, and removes the
// generated PrometheusRule object containing overrides and user-defined rules.
func (o *Overrider) deleteOverrides(_ interface{}) {
	o.relabeler.DeleteGroup(relabelGroupName)

	if _, err := o.relabeler.WriteSecret(); err != nil {
		klog.Errorf("Error removing alert override relabel configs: %v", err)
	}

	err := o.client.DeletePrometheusRuleByNamespaceAndName(
		o.ctx,
		o.client.Namespace(),
		prometheusRuleName,
	)
	if err != nil {
		klog.Errorf("Error deleting alert overrides PrometheusRule: %v", err)
	}
}

// processOverrides is the main handler for changes to the AlertOverrides
// configuration.  It generates the PrometheusRule object containing patched and
// new user-defined alerting rules, and updates the alert relabel configs.
//
// TODO(bison): Should we actually be putting these into a workqueue?
func (o *Overrider) processOverrides(obj interface{}) {
	overrides, ok := obj.(*osmv1alpha1.AlertOverrides)
	if !ok {
		klog.Errorf("Overrides config has type %T, not AlertOverrides", obj)
		return
	}

	newRules := make([]monv1.Rule, 0)
	patchedRules := make([]monv1.Rule, 0)
	dropRules := make([]osmv1alpha1.AlertSelector, 0)
	conditions := make([]osmv1alpha1.AlertOverridesCondition, 0)

	for _, override := range overrides.Spec.Overrides {
		switch override.Action {

		case osmv1alpha1.PatchActionType:
			patched, err := o.patchRule(&override)
			if err != nil {
				klog.Errorf("Error patching rule: %v", err)

				// Multiple matches is currently the only case in which
				// patchRule returns an error.  If that changes, this needs to
				// be rethought.
				conditions = append(conditions, multipleMatchesCondition(err))

				continue
			}

			patchedRules = append(patchedRules, *patched)
			dropRules = append(dropRules, override.Selector)

		case osmv1alpha1.DropActionType:
			dropRules = append(dropRules, override.Selector)

		default:
			klog.Errorf("Unknown action in alert-override: %q", override.Action)
		}
	}

	// Add net-new user defined rules.
	for _, rule := range overrides.Spec.Rules {
		newRules = append(newRules, monv1.Rule{
			Alert:       rule.Alert,
			Expr:        *rule.Expr,
			For:         *rule.For,
			Labels:      rule.Labels,
			Annotations: rule.Annotations,
		})
	}

	relabelConfigs, err := o.alertRelabelConfigs(dropRules)
	if err != nil {
		// TODO(bison): Should we return early here?
		klog.Errorf("Error generating alert_relabel_configs for overrides: %v", err)
		return
	}

	promRule := &monv1.PrometheusRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      prometheusRuleName,
			Namespace: o.client.Namespace(),
		},
		Spec: monv1.PrometheusRuleSpec{
			Groups: []monv1.RuleGroup{
				{
					Name:  "overrides",
					Rules: patchedRules,
				},
				{
					Name:  "additional-rules",
					Rules: newRules,
				},
			},
		},
	}

	if err := o.client.CreateOrUpdatePrometheusRule(o.ctx, promRule); err != nil {
		// TODO(bison): Same as above, should we return early here?
		klog.Errorf("Error creating alert overrides PrometheusRule: %v", err)
	}

	o.relabeler.UpdateGroup(relabelGroupName, relabelConfigs)
	if _, err := o.relabeler.WriteSecret(); err != nil {
		// TODO(bison): Same as above, should we return early here?
		klog.Errorf("Error creating alert relabel configs secret: %v", err)
	}

	overridesClient := o.osmclient.MonitoringV1alpha1().AlertOverrides(o.client.Namespace())
	overrides.Status = osmv1alpha1.AlertOverridesStatus{Conditions: conditions}

	// TODO(bison): Need to add +kubebuilder:subresource:status in the API.
	if _, err := overridesClient.UpdateStatus(o.ctx, overrides, metav1.UpdateOptions{}); err != nil {
		klog.Errorf("Error updating AlertOverrides status: %v", err)
	}

	return
}

// indexByAlertName indexes PrometheusRule objects by alerting rule names.
func (o *Overrider) indexByAlertName(obj interface{}) ([]string, error) {
	pr, ok := obj.(*monv1.PrometheusRule)
	if !ok {
		klog.Warningf("Object in cache is %T, not PrometheusRule", obj)
		return []string{}, nil
	}

	// Don't index PrometheusRule objects in non-platform namespaces.
	if !o.nsWatcher.Has(pr.GetNamespace()) {
		klog.V(4).Infof("Not indexing PrometheusRule from non-platform namespace: %s/%s",
			pr.GetNamespace(), pr.GetName())
		return []string{}, nil
	}

	keys := []string{}

	for _, group := range pr.Spec.Groups {
		for _, rule := range group.Rules {
			if rule.Alert == "" {
				continue // This is a recording rule.
			}

			keys = append(keys, rule.Alert)
		}
	}

	return keys, nil
}

// matchRules takes a slice of RuleGroup objects and an AlertSelector, and
// returns all rules that match the selector.
//
// TODO(bison): Does this belong as a method on the AlertSelector type?
func matchRules(groups []monv1.RuleGroup, selector *osmv1alpha1.AlertSelector) ([]*monv1.Rule, error) {
	// TODO(bison): This is kind of weird.  Should our AlertSelector type just
	// embed a metav1.LabelSelector struct?
	ls := &metav1.LabelSelector{MatchLabels: selector.MatchLabels}
	s, err := metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return nil, fmt.Errorf("Error converting AlertSelector to labels.Selector: %v", err)
	}

	var foundRules []*monv1.Rule

	for _, group := range groups {
		for _, rule := range group.Rules {
			if rule.Alert != selector.Alert {
				continue // Alert name doesn't match.
			}

			if s.Matches(labels.Set(rule.Labels)) {
				foundRules = append(foundRules, rule.DeepCopy())
			}
		}
	}

	return foundRules, nil
}

// relabelConfig returns a Prometheus relabel config meant to match the original
// alert targeted by the given selector.  That is, a relabel config matching the
// alert name, the set of labels matched, and an empty override label.
func relabelConfig(selector osmv1alpha1.AlertSelector) (relabel.Config, error) {
	matchLabelKeys := sets.NewString()

	// Build a Set from the matchLabels keys, so that we can easily access the
	// keys as a stably sorted list when building the regexp string.
	for k := range selector.MatchLabels {
		matchLabelKeys.Insert(k)
	}

	reParts := []string{"", selector.Alert}
	for _, k := range matchLabelKeys.List() {
		reParts = append(reParts, selector.MatchLabels[k])
	}

	regexp, err := relabel.NewRegexp(strings.Join(reParts, ";"))
	if err != nil {
		return relabel.Config{},
			fmt.Errorf("error generating alert relabel config for %q alert: %v",
				selector.Alert, err)
	}

	sourceLabels := model.LabelNames{OverrideLabel, "alertname"}
	for _, k := range matchLabelKeys.List() {
		sourceLabels = append(sourceLabels, model.LabelName(k))
	}

	return relabel.Config{SourceLabels: sourceLabels, Regex: regexp}, nil
}

func multipleMatchesCondition(err error) osmv1alpha1.AlertOverridesCondition {
	// TODO(bison): The type and reason should probably be constants in the API.
	return osmv1alpha1.AlertOverridesCondition{
		Type:    "OverrideError",
		Status:  osmv1alpha1.ConditionTrue,
		Reason:  "MultipleMatches",
		Message: err.Error(),

		// TODO(bison): Does this need to be smarter?
		LastTransitionTime: metav1.Now(),
	}
}
