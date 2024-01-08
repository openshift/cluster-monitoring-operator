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
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openshift/cluster-monitoring-operator/pkg/client"
	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

type caBundleSyncer struct {
	prefix  string
	client  *client.Client
	factory *manifests.Factory
}

func (cbs *caBundleSyncer) syncTrustedCABundle(ctx context.Context, trustedCA *v1.ConfigMap) (*v1.ConfigMap, error) {
	trustedCA, err := cbs.client.CreateIfNotExistConfigMap(ctx, trustedCA)
	if err != nil {
		return nil, fmt.Errorf(" creating root trusted CA bundle ConfigMap failed: %w", err)
	}

	var (
		lastErr error
		lastCM  *v1.ConfigMap
	)
	err = wait.PollUntilContextTimeout(ctx, 5*time.Second, 5*time.Minute, true, func(ctx context.Context) (bool, error) {
		var err error
		lastCM, err = cbs.client.GetConfigmap(ctx, trustedCA.GetNamespace(), trustedCA.GetName())

		if err != nil {
			lastErr = fmt.Errorf("retrieving ConfigMap object failed: %w", err)
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
		if ctx.Err() != nil && lastErr != nil {
			err = fmt.Errorf("%v: %v", err, lastErr)
		}
		return nil, fmt.Errorf("waiting for config map key %q in %s/%s ConfigMap object failed: %w", manifests.TrustedCABundleKey, trustedCA.GetNamespace(), trustedCA.GetName(), err)
	}

	hashedCM, err := cbs.factory.HashTrustedCA(lastCM, cbs.prefix)
	if err != nil {
		return nil, fmt.Errorf("hashing trusted CA bundle failed: %w", err)
	}

	err = cbs.client.CreateOrUpdateConfigMap(ctx, hashedCM)
	if err != nil {
		return nil, fmt.Errorf("reconciling trusted CA bundle ConfigMap failed: %w", err)
	}

	err = cbs.client.DeleteHashedConfigMap(
		ctx,
		trustedCA.GetNamespace(),
		cbs.prefix,
		hashedCM.Labels["monitoring.openshift.io/hash"],
	)
	if err != nil {
		return hashedCM, fmt.Errorf("deleting old trusted CA bundle configmaps failed: %w", err)
	}
	return hashedCM, nil
}
