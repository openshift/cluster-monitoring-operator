// Derived from code originally published in
//
//	https://github.com/openshift/openshift-tests-private
//
// at commit a6a189840b006da18c8203950983c0cee5ea7354.
package util

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"embed"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	e2e "k8s.io/kubernetes/test/e2e/framework"
)

// KubeConfigPath returns the value of KUBECONFIG environment variable
func KubeConfigPath() string {
	// can't use gomega in this method since it is used outside of It()
	return os.Getenv("KUBECONFIG")
}

// WaitForServiceAccount waits until the named service account gets fully
// provisioned
func WaitForServiceAccount(c corev1client.ServiceAccountInterface, name string, checkSecret bool) error {
	countOutput := -1
	// add Logf for better debug, but it will possible generate many logs because of 100 millisecond
	// so, add countOutput so that it output log every 100 times (10s)
	waitFn := func() (bool, error) {
		countOutput++
		sc, err := c.Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			// If we can't access the service accounts, let's wait till the controller
			// create it.
			if errors.IsNotFound(err) || errors.IsForbidden(err) {
				if countOutput%100 == 0 {
					e2e.Logf("Waiting for service account %q to be available: %v (will retry) ...", name, err)
				}
				return false, nil
			}
			return false, fmt.Errorf("failed to get service account %q: %v", name, err)
		}
		secretNames := []string{}
		var hasDockercfg bool
		for _, s := range sc.Secrets {
			if strings.Contains(s.Name, "dockercfg") {
				hasDockercfg = true
			}
			secretNames = append(secretNames, s.Name)
		}
		if hasDockercfg || !checkSecret {
			return true, nil
		}
		if countOutput%100 == 0 {
			e2e.Logf("Waiting for service account %q secrets (%s) to include dockercfg ...", name, strings.Join(secretNames, ","))
		}
		return false, nil
	}
	return wait.Poll(time.Duration(100*time.Millisecond), 3*time.Minute, waitFn)
}

//go:embed testdata/**/*
var fixtureFS embed.FS

var (
	fixtureDirLock sync.Once
	fixtureDir     string
)

// FixturePath returns an absolute path to a fixture file in testdata/
// TODO: the tests will run locally now, we can just pass a relative path.
func FixturePath(dir, subdir string) string {
	fixtureDirLock.Do(func() {
		fixtureDir = filepath.Join(os.TempDir(), "fixtures")
		fs.WalkDir(fixtureFS, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, _ := fixtureFS.ReadFile(path)
			fullPath := filepath.Join(fixtureDir, path)
			os.MkdirAll(filepath.Dir(fullPath), 0755)
			return os.WriteFile(fullPath, data, 0644)
		})
	})

	fullPath := filepath.Join(fixtureDir, dir, subdir)
	if _, err := os.Stat(fullPath); err != nil {
		panic(err)
	}
	return fullPath
}
