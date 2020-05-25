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
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog"

	"github.com/openshift/cluster-monitoring-operator/pkg/operator"
	cmo "github.com/openshift/cluster-monitoring-operator/pkg/operator"
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
	namespace := flagset.String("namespace", "openshift-monitoring", "Namespace to deploy and manage cluster monitoring stack in.")
	namespaceUserWorkload := flagset.String("namespace-user-workload", "openshift-user-workload-monitoring", "Namespace to deploy and manage user workload monitoring stack in.")
	namespaceSelector := flagset.String("namespace-selector", "openshift.io/cluster-monitoring=true", "Selector for namespaces to monitor.")
	configMapName := flagset.String("configmap", "cluster-monitoring-config", "ConfigMap name to configure the cluster monitoring stack.")
	kubeconfigPath := flagset.String("kubeconfig", "", "The path to the kubeconfig to connect to the apiserver with.")
	apiserver := flagset.String("apiserver", "", "The address of the apiserver to talk to.")
	releaseVersion := flagset.String("release-version", "", "Currently targeted release version to be reconciled against.")
	telemetryConfigFile := flagset.String("telemetry-config", "/etc/cluster-monitoring-operator/telemetry/metrics.yaml", "Path to telemetry-config.")
	remoteWrite := flagset.Bool("enabled-remote-write", false, "Wether to use legacy telemetry write protocol or Prometheus remote write.")
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

	r := prometheus.NewRegistry()
	r.MustRegister(
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)

	config, err := clientcmd.BuildConfigFromFlags(*apiserver, *kubeconfigPath)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}

	crc, err := operator.NewTLSRotationController(config, *namespace, "grpc", []string{"prometheus-grpc", "thanos-querier"})
	if err != nil {
		klog.V(4).Info("TLS Rotation controller couldn't be initialized")
		fmt.Fprint(os.Stderr, err)
		return 1
	}

	o, err := cmo.New(config, *releaseVersion, *namespace, *namespaceUserWorkload, *namespaceSelector, *configMapName, *remoteWrite, images.asMap(), telemetryConfig.Matches, *crc)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		return 1
	}

	o.RegisterMetrics(r)
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
	go http.ListenAndServe("127.0.0.1:8080", mux)

	ctx, cancel := context.WithCancel(context.Background())
	wg, ctx := errgroup.WithContext(ctx)

	wg.Go(func() error { return o.Run(ctx.Done()) })

	term := make(chan os.Signal)
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
