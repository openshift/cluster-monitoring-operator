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
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
)

// PlatformNamespaceWatcher watches all namespace objects and
// maintains an up-to-date set of namespaces that have opted in to
// platform monitoring.
type PlatformNamespaceWatcher struct {
	namespaces sets.String
	informer   cache.SharedIndexInformer

	sync.RWMutex
}

// NewPlatformNamespaceWatcher returns a new PlatformNamespaceWatcher.
func NewPlatformNamespaceWatcher(client *client.Client) *PlatformNamespaceWatcher {
	informer := cache.NewSharedIndexInformer(
		client.PlatformNamespacesListWatch(),
		&corev1.Namespace{},
		resyncPeriod,
		cache.Indexers{},
	)

	watcher := &PlatformNamespaceWatcher{
		informer:   informer,
		namespaces: sets.NewString(),
	}

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    watcher.add,
		DeleteFunc: watcher.remove,
	})

	return watcher
}

// Run starts the controller and blocks until the context is canceled.
func (p *PlatformNamespaceWatcher) Run(ctx context.Context, workers int) {
	p.informer.Run(ctx.Done())
}

// Namespaces returns a copy of the set of namespaces at the time the
// method is called.  The set will not be kept up-to-date.
func (p *PlatformNamespaceWatcher) Namespaces() sets.String {
	p.RLock()
	defer p.RUnlock()

	return sets.NewString(p.namespaces.UnsortedList()...)
}

// IsPlatformNamespace returns true if the given namespace is in the
// set of platform namespaces.
func (p *PlatformNamespaceWatcher) IsPlatformNamespace(ns string) bool {
	p.RLock()
	defer p.RUnlock()

	return p.namespaces.Has(ns)
}

func (p *PlatformNamespaceWatcher) add(obj interface{}) {
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		klog.Errorf("namespace watcher got non-namespace object with type %T", obj)
		return
	}

	klog.V(4).Infof("Found new platform namespace: %s", ns.GetName())

	p.Lock()
	p.namespaces.Insert(ns.GetName())
	p.Unlock()
}

func (p *PlatformNamespaceWatcher) remove(obj interface{}) {
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		klog.Errorf("namespace watcher got non-namespace object with type %T", obj)
		return
	}

	klog.V(4).Infof("Removing platform namespace: %s", ns.GetName())

	p.Lock()
	p.namespaces.Delete(ns.GetName())
	p.Unlock()
}
