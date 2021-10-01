---
title: "API"
description: "Generated API docs for the Cluster Monitoring Operator"
lead: ""
date: 2021-03-08T08:49:31+00:00
draft: false
images: []
menu:
  docs:
    parent: "operator"
weight: 1000
toc: true
---

This Document documents the types introduced by the Cluster Monitoring Operator to be consumed by users. It describes the Platform monitoring
and User Workload monitoring configuration.

> Note this document is generated from code comments. When contributing a change to this document please do so by changing the code comments.

## ClusterMonitoringConfiguration


### Table of Contents
* [PrometheusOperatorConfig](#prometheusoperatorconfig)
* [PrometheusK8sConfig](#prometheusk8sconfig)
* [AlertmanagerMainConfig](#alertmanagermainconfig)
* [KubeStateMetricsConfig](#kubestatemetricsconfig)
* [OpenShiftStateMetricsConfig](#openshiftstatemetricsconfig)
* [GrafanaConfig](#grafanaconfig)
* [HTTPConfig](#httpconfig)
* [TelemeterClientConfig](#telemeterclientconfig)
* [K8sPrometheusAdapter](#k8sprometheusadapter)
* [ThanosQuerierConfig](#thanosquerierconfig)
* [RemoteWriteSpec](#remotewritespec)
* [AdditionalAlertmanagerConfig](#additionalalertmanagerconfig)

### PrometheusOperatorConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| logLevel |  | string | true | GA |
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |


### PrometheusK8sConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| logLevel |  | string | false | Tech Preview |
| retention |  | string | true | GA |
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |
| resources |  | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#resourcerequirements-v1-core) | true | GA |
| externalLabels |  | map[string]string | true | GA |
| volumeClaimTemplate |  | *[v12.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#embeddedpersistentvolumeclaim) | true | GA |
| remoteWrite |  | [][RemoteWriteSpec](#remotewritespec) | true | GA |
| additionalAlertmanagerConfigs |  | [][AdditionalAlertmanagerConfig](#additionalalertmanagerconfig) | true | GA |


### AlertmanagerMainConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| enabled |  | *bool | true | GA |
| logLevel |  | string | true | GA |
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |
| resources |  | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#resourcerequirements-v1-core) | true | GA |
| volumeClaimTemplate |  | *monv1.EmbeddedPersistentVolumeClaim | true | GA |


### KubeStateMetricsConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |


### OpenShiftStateMetricsConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |


### GrafanaConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| enabled |  | *bool | true | GA |
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |


### HTTPConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| httpProxy |  | string | true | GA |
| httpsProxy |  | string | true | GA |
| noProxy |  | string | true | GA |


### TelemeterClientConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| clusterID |  | string | true | GA |
| enabled |  | *bool | true | GA |
| telemeterServerURL |  | string | true | GA |
| token |  | string | true | GA |
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |


### K8sPrometheusAdapter



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |


### ThanosQuerierConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| logLevel |  | string | true | GA |
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |
| resources |  | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#resourcerequirements-v1-core) | true | GA |


### RemoteWriteSpec

RemoteWriteSpec is almost a 1to1 copy of monv1.RemoteWriteSpec but with the BearerToken field removed. In the future other fields might be added here.


<em>appears in: [PrometheusK8sConfig](#prometheusk8sconfig), [PrometheusRestrictedConfig](#prometheusrestrictedconfig)</em>

| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| url | The URL of the endpoint to send samples to. | string | true | GA |
| name | The name of the remote write queue, must be unique if specified. The name is used in metrics and logging in order to differentiate queues. Only valid in Prometheus versions 2.15.0 and newer. | string | false | GA |
| remoteTimeout | Timeout for requests to the remote write endpoint. | string | false | GA |
| headers | Custom HTTP headers to be sent along with each remote write request. Be aware that headers that are set by Prometheus itself can't be overwritten. Only valid in Prometheus versions 2.25.0 and newer. | map[string]string | false | GA |
| writeRelabelConfigs | The list of remote write relabel configurations. | [][monv1.RelabelConfig](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#relabelconfig) | false | GA |
| basicAuth | BasicAuth for the URL. | *[monv1.BasicAuth](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#basicauth) | false | GA |
| bearerTokenFile | Bearer token for remote write. | string | false | GA |
| tlsConfig | TLS Config to use for remote write. | *[monv1.SafeTLSConfig](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#safetlsconfig) | false | GA |
| proxyUrl | Optional ProxyURL | string | false | GA |
| queueConfig | QueueConfig allows tuning of the remote write queue parameters. | *[monv1.QueueConfig](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#queueconfig) | false | GA |
| metadataConfig | MetadataConfig configures the sending of series metadata to remote storage. | *[monv1.MetadataConfig](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#metadataconfig) | false | GA |


### AdditionalAlertmanagerConfig




<em>appears in: [PrometheusK8sConfig](#prometheusk8sconfig), [PrometheusRestrictedConfig](#prometheusrestrictedconfig), [ThanosRulerConfig](#thanosrulerconfig)</em>

| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| scheme | The URL scheme to use when talking to Alertmanagers. | string | false | GA |
| pathPrefix | Path prefix to add in front of the push endpoint path. | string | false | GA |
| timeout | The timeout used when sending alerts. | *string | false | GA |
| apiVersion | The api version of Alertmanager. | string | true | GA |
| tlsConfig | TLS Config to use for alertmanager connection. | [TLSConfig](#tlsconfig) | false | GA |
| bearerToken | Bearer token to use when authenticating to Alertmanager. | *[v1.SecretKeySelector](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#secretkeyselector-v1-core) | false | GA |
| staticConfigs | List of statically configured Alertmanagers. | []string | false | GA |


## UserWorkloadConfiguration


### Table of Contents
* [PrometheusOperatorConfig](#prometheusoperatorconfig)
* [PrometheusRestrictedConfig](#prometheusrestrictedconfig)
* [ThanosRulerConfig](#thanosrulerconfig)
* [RemoteWriteSpec](#remotewritespec)
* [AdditionalAlertmanagerConfig](#additionalalertmanagerconfig)

### PrometheusOperatorConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| logLevel |  | string | true | GA |
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |


### PrometheusRestrictedConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| logLevel |  | string | true | GA |
| retention |  | string | true | GA |
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |
| resources |  | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#resourcerequirements-v1-core) | true | GA |
| externalLabels |  | map[string]string | true | GA |
| volumeClaimTemplate |  | *[v12.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#embeddedpersistentvolumeclaim) | true | GA |
| remoteWrite |  | [][RemoteWriteSpec](#remotewritespec) | true | GA |
| enforcedSampleLimit |  | *uint64 | true | GA |
| enforcedTargetLimit |  | *uint64 | true | GA |
| additionalAlertmanagerConfigs |  | [][AdditionalAlertmanagerConfig](#additionalalertmanagerconfig) | true | GA |


### ThanosRulerConfig



| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| logLevel |  | string | true | GA |
| nodeSelector |  | map[string]string | true | GA |
| tolerations |  | [][v1.Toleration](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#toleration-v1-core) | true | GA |
| resources |  | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#resourcerequirements-v1-core) | true | GA |
| volumeClaimTemplate |  | *[v12.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#embeddedpersistentvolumeclaim) | true | GA |
| additionalAlertmanagerConfigs |  | [][AdditionalAlertmanagerConfig](#additionalalertmanagerconfig) | true | GA |


### RemoteWriteSpec

RemoteWriteSpec is almost a 1to1 copy of monv1.RemoteWriteSpec but with the BearerToken field removed. In the future other fields might be added here.


<em>appears in: [PrometheusK8sConfig](#prometheusk8sconfig), [PrometheusRestrictedConfig](#prometheusrestrictedconfig)</em>

| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| url | The URL of the endpoint to send samples to. | string | true | GA |
| name | The name of the remote write queue, must be unique if specified. The name is used in metrics and logging in order to differentiate queues. Only valid in Prometheus versions 2.15.0 and newer. | string | false | GA |
| remoteTimeout | Timeout for requests to the remote write endpoint. | string | false | GA |
| headers | Custom HTTP headers to be sent along with each remote write request. Be aware that headers that are set by Prometheus itself can't be overwritten. Only valid in Prometheus versions 2.25.0 and newer. | map[string]string | false | GA |
| writeRelabelConfigs | The list of remote write relabel configurations. | [][monv1.RelabelConfig](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#relabelconfig) | false | GA |
| basicAuth | BasicAuth for the URL. | *[monv1.BasicAuth](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#basicauth) | false | GA |
| bearerTokenFile | Bearer token for remote write. | string | false | GA |
| tlsConfig | TLS Config to use for remote write. | *[monv1.SafeTLSConfig](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#safetlsconfig) | false | GA |
| proxyUrl | Optional ProxyURL | string | false | GA |
| queueConfig | QueueConfig allows tuning of the remote write queue parameters. | *[monv1.QueueConfig](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#queueconfig) | false | GA |
| metadataConfig | MetadataConfig configures the sending of series metadata to remote storage. | *[monv1.MetadataConfig](https://github.com/prometheus-operator/prometheus-operator/blob/master/Documentation/api.md#metadataconfig) | false | GA |


### AdditionalAlertmanagerConfig




<em>appears in: [PrometheusK8sConfig](#prometheusk8sconfig), [PrometheusRestrictedConfig](#prometheusrestrictedconfig), [ThanosRulerConfig](#thanosrulerconfig)</em>

| Field | Description | Scheme | Required | Status
| ----- | ----------- | ------ | -------- | --------
| scheme | The URL scheme to use when talking to Alertmanagers. | string | false | GA |
| pathPrefix | Path prefix to add in front of the push endpoint path. | string | false | GA |
| timeout | The timeout used when sending alerts. | *string | false | GA |
| apiVersion | The api version of Alertmanager. | string | true | GA |
| tlsConfig | TLS Config to use for alertmanager connection. | [TLSConfig](#tlsconfig) | false | GA |
| bearerToken | Bearer token to use when authenticating to Alertmanager. | *[v1.SecretKeySelector](https://v1-17.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.17/#secretkeyselector-v1-core) | false | GA |
| staticConfigs | List of statically configured Alertmanagers. | []string | false | GA |

