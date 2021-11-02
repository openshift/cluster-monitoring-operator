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

package namespace

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// Watcher watches namespace objects and maintains an up-to-date set of
// namespace names returned by the ListerWatcher used.
type Watcher interface {
	Run(ctx context.Context, workers int)
	HasSynced() bool
	Namespaces() sets.String
	Has(ns string) bool
}

type watcher struct {
	namespaces sets.String
	informer   cache.SharedIndexInformer

	sync.RWMutex
}

// NewWatcher returns a new namespace watcher using the given ListerWatcher.
func NewWatcher(resync time.Duration, lw cache.ListerWatcher) Watcher {
	informer := cache.NewSharedIndexInformer(
		lw,
		&corev1.Namespace{},
		resync,
		cache.Indexers{},
	)

	watcher := &watcher{
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
func (w *watcher) Run(ctx context.Context, workers int) {
	w.informer.Run(ctx.Done())
}

// HasSynced returns true if the watcher's informer has synced its caches.
func (w *watcher) HasSynced() bool {
	return w.informer.HasSynced()
}

// Namespaces returns a copy of the set of namespaces at the time the
// method is called.  The set will not be kept up-to-date.
func (w *watcher) Namespaces() sets.String {
	w.RLock()
	defer w.RUnlock()

	return sets.NewString(w.namespaces.UnsortedList()...)
}

// Has returns true if the given namespace is in the set of namespaces.
func (w *watcher) Has(ns string) bool {
	w.RLock()
	defer w.RUnlock()

	return w.namespaces.Has(ns)
}

// add handles the add event on the namespace informer.
func (w *watcher) add(obj interface{}) {
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		klog.Errorf("namespace watcher got non-namespace object with type %T", obj)
		return
	}

	klog.V(4).Infof("Found new platform namespace: %s", ns.GetName())

	w.Lock()
	w.namespaces.Insert(ns.GetName())
	w.Unlock()
}

// remove handles the remove event on the namespace informer.
func (w *watcher) remove(obj interface{}) {
	ns, ok := obj.(*corev1.Namespace)
	if !ok {
		klog.Errorf("namespace watcher got non-namespace object with type %T", obj)
		return
	}

	klog.V(4).Infof("Removing platform namespace: %s", ns.GetName())

	w.Lock()
	w.namespaces.Delete(ns.GetName())
	w.Unlock()
}
