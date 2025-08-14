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

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	runtimelog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	cmo "github.com/openshift/cluster-monitoring-operator/pkg/operator"
	"github.com/openshift/cluster-monitoring-operator/pkg/server"
)

type images map[string]string

func (i *images) String() string {
	m := *i
	slice := m.asSlice()
	return strings.Join(slice, ",")
}

func (i *images) Set(value string) error {
	m := *i
	pairs := strings.Split(value, ",")
	for _, pair := range pairs {
		splitPair := strings.Split(pair, "=")
		if len(splitPair) != 2 {
			return fmt.Errorf("pair %q is malformed; key-value pairs must be in the form of \"key=value\"; multiple pairs must be comma-separated", value)
		}
		imageName := splitPair[0]
		imageTag := splitPair[1]
		m[imageName] = imageTag
	}
	return nil
}

func (i images) asSlice() []string {
	pairs := []string{}
	for name, tag := range i {
		pairs = append(pairs, name+"="+tag)
	}
	return pairs
}

func (i images) asMap() map[string]string {
	res := make(map[string]string, len(i))
	for k, v := range i {
		res[k] = v
	}
	return res
}

func (i *images) Type() string {
	return "map[string]string"
}

type telemetryConfig struct {
	Matches []string `json:"matches"`
}

func Main() int {
	flagset := flag.CommandLine
	klog.InitFlags(flagset)
	runtimelog.SetLogger(klog.Background())
	namespace := flagset.String("namespace", "openshift-monitoring", "Namespace to deploy and manage cluster monitoring stack in.")
	namespaceUserWorkload := flagset.String("namespace-user-workload", "openshift-user-workload-monitoring", "Namespace to deploy and manage user workload monitoring stack in.")
	configMapName := flagset.String("configmap", "cluster-monitoring-config", "ConfigMap name to configure the cluster monitoring stack.")
	kubeconfigPath := flagset.String("kubeconfig", "", "The path to the kubeconfig to connect to the apiserver with.")
	apiserver := flagset.String("apiserver", "", "The address of the apiserver to talk to.")
	releaseVersion := flagset.String("release-version", "", "Currently targeted release version to be reconciled against.")
	telemetryConfigFile := flagset.String("telemetry-config", "/etc/cluster-monitoring-operator/telemetry/metrics.yaml", "Path to telemetry-config.")
	remoteWrite := flagset.Bool("enabled-remote-write", false, "Whether to use legacy telemetry write protocol or Prometheus remote write.")
	assetsPath := flagset.String("assets", "/assets", "The path to the assets directory.")
	certFile := flagset.String("cert-file", "", "The path to the server certificate")
	keyFile := flagset.String("key-file", "", "The path to the server key")
	images := images{}
	flag.Var(&images, "images", "Images to use for containers managed by the cluster-monitoring-operator.")
	flag.Parse()

	f, err := os.Open(*telemetryConfigFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not open telemetry config file: %v", err)
		return 1
	}

	telemetryConfig := telemetryConfig{}
	err = yaml.NewYAMLOrJSONDecoder(f, 100).Decode(&telemetryConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not parse telemetry config file: %v", err)
		return 1
	}
	err = f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could close telemetry config file: %v", err)
		return 1
	}

	klog.V(4).Info("Configured matches for telemetry:")
	for _, m := range telemetryConfig.Matches {
		klog.V(4).Info(m)
	}

	if _, err := os.Stat(*assetsPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Could not find assets directory: %v", err)
		return 1
	}
	assets := manifests.NewAssets(*assetsPath)

	ok := true
	if *namespace == "" {
		ok = false
		fmt.Fprint(os.Stderr, "`--namespace` flag is required, but not specified.")
	}

	if *configMapName == "" {
		ok = false
		fmt.Fprint(os.Stderr, "`--configmap` flag is required, but not specified.")
	}

	if releaseVersion == nil || *releaseVersion == "" {
		fmt.Fprint(os.Stderr, "`--release-version` flag is not set.")
	}
	if releaseVersion != nil {
		klog.V(4).Infof("Release version set to %v", *releaseVersion)
	}

	if !ok {
		return 1
	}

	config, err := clientcmd.BuildConfigFromFlags(*apiserver, *kubeconfigPath)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}

	// CMO runs many tasks in parallel and the default values for rate limiting
	// are too low. Thus, we need to align the QPS limit with what is set in
	// upstream prometheus-operator. As for the burst limit, a significant
	// increase needs to be made as in large environnements with a lot of CRDs,
	// the limit set upstream is too low.
	config.QPS = 100
	config.Burst = 200

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	userWorkloadConfigMapName := "user-workload-monitoring-config"
	o, err := cmo.New(
		ctx,
		config,
		*releaseVersion,
		*namespace,
		*namespaceUserWorkload,
		*configMapName,
		userWorkloadConfigMapName,
		*remoteWrite,
		images.asMap(),
		telemetryConfig.Matches,
		assets,
	)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}

	// Start the pprof endpoints on the loopback interface.
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	//nolint:errcheck
	go http.ListenAndServe("127.0.0.1:8080", mux)

	wg, ctx := errgroup.WithContext(ctx)

	wg.Go(func() error { return o.Run(ctx) })

	// TEMPORARY TEST: Pass nil directly to test if NewAPIServerConfig(nil) is causing the crash
	// If this fixes the crash, then the issue is in NewAPIServerConfig(nil) behavior
	srv, err := server.NewServer("cluster-monitoring-operator", config, *kubeconfigPath, *certFile, *keyFile, nil)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}
	wg.Go(func() error { return srv.Run(ctx, o.CollectionProfilesEnabled) })

	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	select {
	case <-term:
		klog.V(4).Info("Received SIGTERM, exiting gracefully...")
	case <-ctx.Done():
	}

	cancel()
	if err := wg.Wait(); err != nil {
		klog.V(4).Infof("Unhandled error received. Exiting...err: %s", err)
		return 1
	}

	return 0
}

func main() {
	os.Exit(Main())
}
