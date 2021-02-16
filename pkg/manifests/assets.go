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

package manifests

import (
	"bytes"
	"io"
	"io/ioutil"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"
	"k8s.io/klog/v2"
)

type Assets struct {
	mtx       sync.Mutex
	assetsDir string
	data      map[string][]byte
}

func NewAssets(assetsDir string) *Assets {
	return &Assets{
		assetsDir: assetsDir,
		data:      make(map[string][]byte),
	}
}

func (a *Assets) GetAsset(name string) ([]byte, error) {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	filePath := filepath.Join(a.assetsDir, name)

	// load manifest from memory if available
	if a, ok := a.data[filePath]; ok {
		klog.V(4).Infof("Reading manifest from memory: %s\n", name)
		return a, nil
	}

	// fallback to loading manifest from disk
	klog.V(4).Infof("Reading manifest from file: %s\n", filePath)

	f, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read asset %v", name)
	}

	a.data[filePath] = f
	return f, nil
}

func (a *Assets) MustNewAssetReader(name string) io.Reader {
	f, err := a.GetAsset(name)
	if err != nil {
		panic(err)
	}
	return bytes.NewReader(f)
}
