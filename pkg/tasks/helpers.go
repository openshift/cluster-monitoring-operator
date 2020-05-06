// Copyright 2020 The Cluster Monitoring Operator Authors
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

package tasks

import (
	"time"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	"github.com/pkg/errors"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

type caBundleSyncer struct {
	prefix  string
	client  *client.Client
	factory *manifests.Factory
}

func (cbs *caBundleSyncer) syncTrustedCABundle(trustedCA *v1.ConfigMap) (*v1.ConfigMap, error) {
	trustedCA, err := cbs.client.CreateIfNotExistConfigMap(trustedCA)
	if err != nil {
		return nil, errors.Wrap(err, " creating root trusted CA bundle ConfigMap failed")
	}

	var (
		lastErr error
		lastCM  *v1.ConfigMap
	)
	err = wait.PollImmediate(5*time.Second, 5*time.Minute, func() (bool, error) {
		var err error
		lastCM, err = cbs.client.GetConfigmap(trustedCA.GetNamespace(), trustedCA.GetName())

		if err != nil {
			lastErr = errors.Wrap(err, "retrieving ConfigMap object failed")
			return false, nil
		}

		v, ok := lastCM.Data[manifests.TrustedCABundleKey]
		if !ok {
			lastErr = errors.New("key missing")
			return false, nil
		}
		if v == "" {
			lastErr = errors.New("empty value")
			return false, nil
		}

		return true, nil
	})
	if err != nil {
		if err == wait.ErrWaitTimeout && lastErr != nil {
			err = errors.Errorf("%v: %v", err, lastErr)
		}
		return nil, errors.Wrapf(err, "waiting for config map key %q in %s/%s ConfigMap object failed", manifests.TrustedCABundleKey, trustedCA.GetNamespace(), trustedCA.GetName())
	}

	hashedCM, err := cbs.factory.HashTrustedCA(lastCM, cbs.prefix)
	if err != nil {
		return nil, errors.Wrap(err, "hashing trusted CA bundle failed")
	}

	err = cbs.client.CreateOrUpdateConfigMap(hashedCM)
	if err != nil {
		return nil, errors.Wrap(err, "reconciling trusted CA bundle ConfigMap failed")
	}

	err = cbs.client.DeleteHashedConfigMap(
		trustedCA.GetNamespace(),
		cbs.prefix,
		string(hashedCM.Labels["monitoring.openshift.io/hash"]),
	)
	return hashedCM, errors.Wrap(err, "deleting old trusted CA bundle configmaps failed")
}
