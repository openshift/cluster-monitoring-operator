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

package v1

import (
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
)

type Config struct {
	Images                               *Images `json:"-"`
	RemoteWrite                          bool    `json:"-"`
	CollectionProfilesFeatureGateEnabled bool    `json:"-"`
	BasedCRDFeatureGateEnabled           bool    `json:"-"`

	ClusterMonitoringConfiguration *ClusterMonitoringOperatorSpec `json:"-"`
	UserWorkloadConfiguration      *UserWorkloadConfiguration     `json:"-"`
}

type Images struct {
	K8sPrometheusAdapter               string
	MetricsServer                      string
	PromLabelProxy                     string
	PrometheusOperatorAdmissionWebhook string
	PrometheusOperator                 string
	PrometheusConfigReloader           string
	Prometheus                         string
	Alertmanager                       string
	NodeExporter                       string
	KubeStateMetrics                   string
	OpenShiftStateMetrics              string
	KubeRbacProxy                      string
	TelemeterClient                    string
	Thanos                             string
	MonitoringPlugin                   string
}

type HTTPConfig struct {
	HTTPProxy  string `json:"httpProxy"`
	HTTPSProxy string `json:"httpsProxy"`
	NoProxy    string `json:"noProxy"`
}

func (a AlertmanagerMainConfig) IsEnabled() bool {
	return a.Enabled == nil || *a.Enabled
}

// Audit profile configurations
type Audit struct {

	// The Profile to set for audit logs. This currently matches the various
	// audit log levels such as: "metadata, request, requestresponse, none".
	// The default audit log level is "metadata"
	//
	// see: https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-policy
	// for more information about auditing and log levels.
	Profile auditv1.Level `json:"profile"`
}
