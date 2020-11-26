package manifests

import (
	"bytes"
	"io"
	"io/ioutil"
	"path"
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
	filePath := path.Join(a.assetsDir, name)

	// load manifest from memory if available
	if a, ok := a.data[filePath]; ok {
		klog.V(4).Infof("Reading manifest from memory: %s\n", name)
		return a, nil
	}

	// fallback to loading manifest from disk
	klog.V(4).Infof("Reading manifest from file: %s\n", filePath)

	a.mtx.Lock()
	defer a.mtx.Unlock()

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
