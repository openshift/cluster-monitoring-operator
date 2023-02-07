
**NOTE**: The contents of this file are **automatically generated** from source code comments. 
If you wish to make a change or an addition to the content in this document, do so by **changing the code comments**.

# Cluster Monitoring Configuration Reference

Parts of Cluster Monitoring are configurable. Depending on which part of the stack users want to configure, they should edit the following:

- Configuration of OpenShift Container Platform monitoring components lies in a ConfigMap called `cluster-monitoring-config` in the `openshift-monitoring` namespace. Defined by [ClusterMonitoringConfiguration](#clustermonitoringconfiguration).
- Configuration of components that monitor user-defined projects lies in a ConfigMap called `user-workload-monitoring-config` in the `openshift-user-workload-monitoring` namespace. Defined by [UserWorkloadConfiguration](#userworkloadconfiguration).

The configuration file itself is always defined under the `config.yaml` key within the ConfigMap's data.

Monitoring a platform such as OpenShift requires a coordination of multiple components that must work well between themselves.
However, users should be able to customize the monitoring stack in such a way that they end up with a resilient and highly available monitoring solution.
Despite this, to avoid users from misconfiguring the monitoring stack of their clusters not all configuration parameters are exposed.

Configuring Cluster Monitoring is optional. If the config does not exist or is empty or malformed, then defaults will be used.

## Table of Contents
* [AdditionalAlertmanagerConfig](#additionalalertmanagerconfig)
* [AlertmanagerMainConfig](#alertmanagermainconfig)
* [AlertmanagerUserWorkloadConfig](#alertmanageruserworkloadconfig)
* [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)
* [DedicatedServiceMonitors](#dedicatedservicemonitors)
* [K8sPrometheusAdapter](#k8sprometheusadapter)
* [KubeStateMetricsConfig](#kubestatemetricsconfig)
* [NodeExporterCollectorConfig](#nodeexportercollectorconfig)
* [NodeExporterCollectorCpufreqConfig](#nodeexportercollectorcpufreqconfig)
* [NodeExporterConfig](#nodeexporterconfig)
* [OpenShiftStateMetricsConfig](#openshiftstatemetricsconfig)
* [PrometheusK8sConfig](#prometheusk8sconfig)
* [PrometheusOperatorConfig](#prometheusoperatorconfig)
* [PrometheusRestrictedConfig](#prometheusrestrictedconfig)
* [RemoteWriteSpec](#remotewritespec)
* [TLSConfig](#tlsconfig)
* [TelemeterClientConfig](#telemeterclientconfig)
* [ThanosQuerierConfig](#thanosquerierconfig)
* [ThanosRulerConfig](#thanosrulerconfig)
* [UserWorkloadConfiguration](#userworkloadconfiguration)

## AdditionalAlertmanagerConfig

#### Description

The `AdditionalAlertmanagerConfig` resource defines settings for how a component communicates with additional Alertmanager instances.

#### Required
   - ` apiVersion `

<em>appears in: [PrometheusK8sConfig](#prometheusk8sconfig), [PrometheusRestrictedConfig](#prometheusrestrictedconfig), [ThanosRulerConfig](#thanosrulerconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| apiVersion | string | Defines the API version of Alertmanager. Possible values are `v1` or `v2`. The default is `v2`. |
| bearerToken | *[v1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#secretkeyselector-v1-core) | Defines the secret key reference containing the bearer token to use when authenticating to Alertmanager. |
| pathPrefix | string | Defines the path prefix to add in front of the push endpoint path. |
| scheme | string | Defines the URL scheme to use when communicating with Alertmanager instances. Possible values are `http` or `https`. The default value is `http`. |
| staticConfigs | []string | A list of statically configured Alertmanager endpoints in the form of `<hosts>:<port>`. |
| timeout | *string | Defines the timeout value used when sending alerts. |
| tlsConfig | [TLSConfig](#tlsconfig) | Defines the TLS settings to use for Alertmanager connections. |

[Back to TOC](#table-of-contents)

## AlertmanagerMainConfig

#### Description

The `AlertmanagerMainConfig` resource defines settings for the Alertmanager component in the `openshift-monitoring` namespace.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | *bool | A Boolean flag that enables or disables the main Alertmanager instance in the `openshift-monitoring` namespace. The default value is `true`. |
| enableUserAlertmanagerConfig | bool | A Boolean flag that enables or disables user-defined namespaces to be selected for `AlertmanagerConfig` lookups. This setting only applies if the user workload monitoring instance of Alertmanager is not enabled. The default value is `false`. |
| logLevel | string | Defines the log level setting for Alertmanager. The possible values are: `error`, `warn`, `info`, `debug`. The default value is `info`. |
| nodeSelector | map[string]string | Defines the nodes on which the Pods are scheduled. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#resourcerequirements-v1-core) | Defines resource requests and limits for the Alertmanager container. |
| secrets | []string | Defines a list of secrets that need to be mounted into the Alertmanager. The secrets must reside within the same namespace as the Alertmanager object. They will be added as volumes named secret-<secret-name> and mounted at /etc/alertmanager/secrets/<secret-name> within the 'alertmanager' container of the Alertmanager Pods. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |
| volumeClaimTemplate | *[monv1.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/v0.62.0/Documentation/api.md#embeddedpersistentvolumeclaim) | Defines persistent storage for Alertmanager. Use this setting to configure the persistent volume claim, including storage class, volume size, and name. |

[Back to TOC](#table-of-contents)

## AlertmanagerUserWorkloadConfig

#### Description

The `AlertmanagerUserWorkloadConfig` resource defines the settings for the Alertmanager instance used for user-defined projects.


<em>appears in: [UserWorkloadConfiguration](#userworkloadconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables a dedicated instance of Alertmanager for user-defined alerts in the `openshift-user-workload-monitoring` namespace. The default value is `false`. |
| enableAlertmanagerConfig | bool | A Boolean flag to enable or disable user-defined namespaces to be selected for `AlertmanagerConfig` lookup. The default value is `false`. |
| logLevel | string | Defines the log level setting for Alertmanager for user workload monitoring. The possible values are `error`, `warn`, `info`, and `debug`. The default value is `info`. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#resourcerequirements-v1-core) | Defines resource requests and limits for the Alertmanager container. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |
| volumeClaimTemplate | *[monv1.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/v0.62.0/Documentation/api.md#embeddedpersistentvolumeclaim) | Defines persistent storage for Alertmanager. Use this setting to configure the persistent volume claim, including storage class, volume size and name. |

[Back to TOC](#table-of-contents)

## ClusterMonitoringConfiguration

#### Description

The `ClusterMonitoringConfiguration` resource defines settings that customize the default platform monitoring stack through the `cluster-monitoring-config` config map in the `openshift-monitoring` namespace.

| Property | Type | Description |
| -------- | ---- | ----------- |
| alertmanagerMain | *[AlertmanagerMainConfig](#alertmanagermainconfig) | `AlertmanagerMainConfig` defines settings for the Alertmanager component in the `openshift-monitoring` namespace. |
| enableUserWorkload | *bool | `UserWorkloadEnabled` is a Boolean flag that enables monitoring for user-defined projects. |
| k8sPrometheusAdapter | *[K8sPrometheusAdapter](#k8sprometheusadapter) | `K8sPrometheusAdapter` defines settings for the Prometheus Adapter component. |
| kubeStateMetrics | *[KubeStateMetricsConfig](#kubestatemetricsconfig) | `KubeStateMetricsConfig` defines settings for the `kube-state-metrics` agent. |
| prometheusK8s | *[PrometheusK8sConfig](#prometheusk8sconfig) | `PrometheusK8sConfig` defines settings for the Prometheus component. |
| prometheusOperator | *[PrometheusOperatorConfig](#prometheusoperatorconfig) | `PrometheusOperatorConfig` defines settings for the Prometheus Operator component. |
| openshiftStateMetrics | *[OpenShiftStateMetricsConfig](#openshiftstatemetricsconfig) | `OpenShiftMetricsConfig` defines settings for the `openshift-state-metrics` agent. |
| telemeterClient | *[TelemeterClientConfig](#telemeterclientconfig) | `TelemeterClientConfig` defines settings for the Telemeter Client component. |
| thanosQuerier | *[ThanosQuerierConfig](#thanosquerierconfig) | `ThanosQuerierConfig` defines settings for the Thanos Querier component. |
| nodeExporter | [NodeExporterConfig](#nodeexporterconfig) | `NodeExporterConfig` defines settings for the `node-exporter` agent. |

[Back to TOC](#table-of-contents)

## DedicatedServiceMonitors

#### Description

You can use the `DedicatedServiceMonitors` resource to configure dedicated Service Monitors for the Prometheus Adapter


<em>appears in: [K8sPrometheusAdapter](#k8sprometheusadapter)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | When `enabled` is set to `true`, the Cluster Monitoring Operator (CMO) deploys a dedicated Service Monitor that exposes the kubelet `/metrics/resource` endpoint. This Service Monitor sets `honorTimestamps: true` and only keeps metrics that are relevant for the pod resource queries of Prometheus Adapter. Additionally, Prometheus Adapter is configured to use these dedicated metrics. Overall, this feature improves the consistency of Prometheus Adapter-based CPU usage measurements used by, for example, the `oc adm top pod` command or the Horizontal Pod Autoscaler. |

[Back to TOC](#table-of-contents)

## K8sPrometheusAdapter

#### Description

The `K8sPrometheusAdapter` resource defines settings for the Prometheus Adapter component.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| audit | *Audit | Defines the audit configuration used by the Prometheus Adapter instance. Possible profile values are: `metadata`, `request`, `requestresponse`, and `none`. The default value is `metadata`. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |
| dedicatedServiceMonitors | *[DedicatedServiceMonitors](#dedicatedservicemonitors) | Defines dedicated service monitors. |

[Back to TOC](#table-of-contents)

## KubeStateMetricsConfig

#### Description

The `KubeStateMetricsConfig` resource defines settings for the `kube-state-metrics` agent.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorConfig

#### Description

The `NodeExporterCollectorConfig` resource defines settings for individual collectors of the `node-exporter` agent.


<em>appears in: [NodeExporterConfig](#nodeexporterconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| cpufreq | [NodeExporterCollectorCpufreqConfig](#nodeexportercollectorcpufreqconfig) | Defines the configuration of the `cpufreq` collector, which collects CPU frequency statistics. Disabled by default. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorCpufreqConfig

#### Description

The `NodeExporterCollectorCpufreqConfig` resource works as an on/off switch for the `cpufreq` collector of the `node-exporter` agent. By default, the `cpufreq` collector is disabled. Under certain circumstances, enabling the cpufreq collector increases CPU usage on machines with many cores. If you enable this collector and have machines with many cores, monitor your systems closely for excessive CPU usage. Please refer to https://github.com/prometheus/node_exporter/issues/1880 for more details. A related bug: https://bugzilla.redhat.com/show_bug.cgi?id=1972076


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `cpufreq` colletor. |

[Back to TOC](#table-of-contents)

## NodeExporterConfig

#### Description

The `NodeExporterConfig` resource defines settings for the `node-exporter` agent.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| collectors | [NodeExporterCollectorConfig](#nodeexportercollectorconfig) | Defines which collectors are enabled and their additional configuration parameters. |

[Back to TOC](#table-of-contents)

## OpenShiftStateMetricsConfig

#### Description

The `OpenShiftStateMetricsConfig` resource defines settings for the `openshift-state-metrics` agent.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |

[Back to TOC](#table-of-contents)

## PrometheusK8sConfig

#### Description

The `PrometheusK8sConfig` resource defines settings for the Prometheus component.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| additionalAlertmanagerConfigs | [][AdditionalAlertmanagerConfig](#additionalalertmanagerconfig) | Configures additional Alertmanager instances that receive alerts from the Prometheus component. By default, no additional Alertmanager instances are configured. |
| enforcedBodySizeLimit | string | Enforces a body size limit for Prometheus scraped metrics. If a scraped target's body response is larger than the limit, the scrape will fail. The following values are valid: an empty value to specify no limit, a numeric value in Prometheus size format (such as `64MB`), or the string `automatic`, which indicates that the limit will be automatically calculated based on cluster capacity. The default value is empty, which indicates no limit. |
| externalLabels | map[string]string | Defines labels to be added to any time series or alerts when communicating with external systems such as federation, remote storage, and Alertmanager. By default, no labels are added. |
| logLevel | string | Defines the log level setting for Prometheus. The possible values are: `error`, `warn`, `info`, and `debug`. The default value is `info`. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| queryLogFile | string | Specifies the file to which PromQL queries are logged. This setting can be either a filename, in which case the queries are saved to an `emptyDir` volume at `/var/log/prometheus`, or a full path to a location where an `emptyDir` volume will be mounted and the queries saved. Writing to `/dev/stderr`, `/dev/stdout` or `/dev/null` is supported, but writing to any other `/dev/` path is not supported. Relative paths are also not supported. By default, PromQL queries are not logged. |
| remoteWrite | [][RemoteWriteSpec](#remotewritespec) | Defines the remote write configuration, including URL, authentication, and relabeling settings. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#resourcerequirements-v1-core) | Defines resource requests and limits for the Prometheus container. |
| retention | string | Defines the duration for which Prometheus retains data. This definition must be specified using the following regular expression pattern: `[0-9]+(ms\|s\|m\|h\|d\|w\|y)` (ms = milliseconds, s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years). The default value is `15d`. |
| retentionSize | string | Defines the maximum amount of disk space used by data blocks plus the write-ahead log (WAL). Supported values are `B`, `KB`, `KiB`, `MB`, `MiB`, `GB`, `GiB`, `TB`, `TiB`, `PB`, `PiB`, `EB`, and `EiB`. By default, no limit is defined. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines the pod's topology spread constraints. |
| volumeClaimTemplate | *[monv1.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/v0.62.0/Documentation/api.md#embeddedpersistentvolumeclaim) | Defines persistent storage for Prometheus. Use this setting to configure the persistent volume claim, including storage class, volume size and name. |

[Back to TOC](#table-of-contents)

## PrometheusOperatorConfig

#### Description

The `PrometheusOperatorConfig` resource defines settings for the Prometheus Operator component.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration), [UserWorkloadConfiguration](#userworkloadconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| logLevel | string | Defines the log level settings for Prometheus Operator. The possible values are `error`, `warn`, `info`, and `debug`. The default value is `info`. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |

[Back to TOC](#table-of-contents)

## PrometheusRestrictedConfig

#### Description

The `PrometheusRestrictedConfig` resource defines the settings for the Prometheus component that monitors user-defined projects.


<em>appears in: [UserWorkloadConfiguration](#userworkloadconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| additionalAlertmanagerConfigs | [][AdditionalAlertmanagerConfig](#additionalalertmanagerconfig) | Configures additional Alertmanager instances that receive alerts from the Prometheus component. By default, no additional Alertmanager instances are configured. |
| enforcedLabelLimit | *uint64 | Specifies a per-scrape limit on the number of labels accepted for a sample. If the number of labels exceeds this limit after metric relabeling, the entire scrape is treated as failed. The default value is `0`, which means that no limit is set. |
| enforcedLabelNameLengthLimit | *uint64 | Specifies a per-scrape limit on the length of a label name for a sample. If the length of a label name exceeds this limit after metric relabeling, the entire scrape is treated as failed. The default value is `0`, which means that no limit is set. |
| enforcedLabelValueLengthLimit | *uint64 | Specifies a per-scrape limit on the length of a label value for a sample. If the length of a label value exceeds this limit after metric relabeling, the entire scrape is treated as failed. The default value is `0`, which means that no limit is set. |
| enforcedSampleLimit | *uint64 | Specifies a global limit on the number of scraped samples that will be accepted. This setting overrides the `SampleLimit` value set in any user-defined `ServiceMonitor` or `PodMonitor` object if the value is greater than `enforcedTargetLimit`. Administrators can use this setting to keep the overall number of samples under control. The default value is `0`, which means that no limit is set. |
| enforcedTargetLimit | *uint64 | Specifies a global limit on the number of scraped targets. This setting overrides the `TargetLimit` value set in any user-defined `ServiceMonitor` or `PodMonitor` object if the value is greater than `enforcedSampleLimit`. Administrators can use this setting to keep the overall number of targets under control. The default value is `0`. |
| externalLabels | map[string]string | Defines labels to be added to any time series or alerts when communicating with external systems such as federation, remote storage, and Alertmanager. By default, no labels are added. |
| logLevel | string | Defines the log level setting for Prometheus. The possible values are `error`, `warn`, `info`, and `debug`. The default setting is `info`. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| queryLogFile | string | Specifies the file to which PromQL queries are logged. This setting can be either a filename, in which case the queries are saved to an `emptyDir` volume at `/var/log/prometheus`, or a full path to a location where an `emptyDir` volume will be mounted and the queries saved. Writing to `/dev/stderr`, `/dev/stdout` or `/dev/null` is supported, but writing to any other `/dev/` path is not supported. Relative paths are also not supported. By default, PromQL queries are not logged. |
| remoteWrite | [][RemoteWriteSpec](#remotewritespec) | Defines the remote write configuration, including URL, authentication, and relabeling settings. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#resourcerequirements-v1-core) | Defines resource requests and limits for the Prometheus container. |
| retention | string | Defines the duration for which Prometheus retains data. This definition must be specified using the following regular expression pattern: `[0-9]+(ms\|s\|m\|h\|d\|w\|y)` (ms = milliseconds, s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years). The default value is `15d`. |
| retentionSize | string | Defines the maximum amount of disk space used by data blocks plus the write-ahead log (WAL). Supported values are `B`, `KB`, `KiB`, `MB`, `MiB`, `GB`, `GiB`, `TB`, `TiB`, `PB`, `PiB`, `EB`, and `EiB`. The default value is `nil`. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |
| volumeClaimTemplate | *[monv1.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/v0.62.0/Documentation/api.md#embeddedpersistentvolumeclaim) | Defines persistent storage for Prometheus. Use this setting to configure the storage class and size of a volume. |

[Back to TOC](#table-of-contents)

## RemoteWriteSpec

#### Description

The `RemoteWriteSpec` resource defines the settings for remote write storage.

#### Required
   - ` url `

<em>appears in: [PrometheusK8sConfig](#prometheusk8sconfig), [PrometheusRestrictedConfig](#prometheusrestrictedconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| authorization | *monv1.SafeAuthorization | Defines the authorization settings for remote write storage. |
| basicAuth | *[monv1.BasicAuth](https://github.com/prometheus-operator/prometheus-operator/blob/v0.62.0/Documentation/api.md#basicauth) | Defines basic authentication settings for the remote write endpoint URL. |
| bearerTokenFile | string | Defines the file that contains the bearer token for the remote write endpoint. However, because you cannot mount secrets in a pod, in practice you can only reference the token of the service account. |
| headers | map[string]string | Specifies the custom HTTP headers to be sent along with each remote write request. Headers set by Prometheus cannot be overwritten. |
| metadataConfig | *[monv1.MetadataConfig](https://github.com/prometheus-operator/prometheus-operator/blob/v0.62.0/Documentation/api.md#metadataconfig) | Defines settings for sending series metadata to remote write storage. |
| name | string | Defines the name of the remote write queue. This name is used in metrics and logging to differentiate queues. If specified, this name must be unique. |
| oauth2 | *monv1.OAuth2 | Defines OAuth2 authentication settings for the remote write endpoint. |
| proxyUrl | string | Defines an optional proxy URL. |
| queueConfig | *[monv1.QueueConfig](https://github.com/prometheus-operator/prometheus-operator/blob/v0.62.0/Documentation/api.md#queueconfig) | Allows tuning configuration for remote write queue parameters. |
| remoteTimeout | string | Defines the timeout value for requests to the remote write endpoint. |
| sigv4 | *monv1.Sigv4 | Defines AWS Signature Version 4 authentication settings. |
| tlsConfig | *[monv1.SafeTLSConfig](https://github.com/prometheus-operator/prometheus-operator/blob/v0.62.0/Documentation/api.md#safetlsconfig) | Defines TLS authentication settings for the remote write endpoint. |
| url | string | Defines the URL of the remote write endpoint to which samples will be sent. |
| writeRelabelConfigs | [][monv1.RelabelConfig](https://github.com/prometheus-operator/prometheus-operator/blob/v0.62.0/Documentation/api.md#relabelconfig) | Defines the list of remote write relabel configurations. |

[Back to TOC](#table-of-contents)

## TLSConfig

#### Description

The `TLSConfig` resource configures the settings for TLS connections.

#### Required
   - ` insecureSkipVerify `

<em>appears in: [AdditionalAlertmanagerConfig](#additionalalertmanagerconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| ca | *[v1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#secretkeyselector-v1-core) | Defines the secret key reference containing the Certificate Authority (CA) to use for the remote host. |
| cert | *[v1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#secretkeyselector-v1-core) | Defines the secret key reference containing the public certificate to use for the remote host. |
| key | *[v1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#secretkeyselector-v1-core) | Defines the secret key reference containing the private key to use for the remote host. |
| serverName | string | Used to verify the hostname on the returned certificate. |
| insecureSkipVerify | bool | When set to `true`, disables the verification of the remote host's certificate and name. |

[Back to TOC](#table-of-contents)

## TelemeterClientConfig

#### Description

`TelemeterClientConfig` defines settings for the Telemeter Client component.

#### Required
   - ` nodeSelector `
   - ` tolerations `

<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |

[Back to TOC](#table-of-contents)

## ThanosQuerierConfig

#### Description

The `ThanosQuerierConfig` resource defines settings for the Thanos Querier component.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enableRequestLogging | bool | A Boolean flag that enables or disables request logging. The default value is `false`. |
| logLevel | string | Defines the log level setting for Thanos Querier. The possible values are `error`, `warn`, `info`, and `debug`. The default value is `info`. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#resourcerequirements-v1-core) | Defines resource requests and limits for the Thanos Querier container. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |

[Back to TOC](#table-of-contents)

## ThanosRulerConfig

#### Description

The `ThanosRulerConfig` resource defines configuration for the Thanos Ruler instance for user-defined projects.


<em>appears in: [UserWorkloadConfiguration](#userworkloadconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| additionalAlertmanagerConfigs | [][AdditionalAlertmanagerConfig](#additionalalertmanagerconfig) | Configures how the Thanos Ruler component communicates with additional Alertmanager instances. The default value is `nil`. |
| logLevel | string | Defines the log level setting for Thanos Ruler. The possible values are `error`, `warn`, `info`, and `debug`. The default value is `info`. |
| nodeSelector | map[string]string | Defines the nodes on which the Pods are scheduled. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#resourcerequirements-v1-core) | Defines resource requests and limits for the Alertmanager container. |
| retention | string | Defines the duration for which Prometheus retains data. This definition must be specified using the following regular expression pattern: `[0-9]+(ms\|s\|m\|h\|d\|w\|y)` (ms = milliseconds, s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years). The default value is `15d`. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines topology spread constraints for the pods. |
| volumeClaimTemplate | *[monv1.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/v0.62.0/Documentation/api.md#embeddedpersistentvolumeclaim) | Defines persistent storage for Thanos Ruler. Use this setting to configure the storage class and size of a volume. |

[Back to TOC](#table-of-contents)

## UserWorkloadConfiguration

#### Description

The `UserWorkloadConfiguration` resource defines the settings responsible for user-defined projects in the `user-workload-monitoring-config` config map  in the `openshift-user-workload-monitoring` namespace. You can only enable `UserWorkloadConfiguration` after you have set `enableUserWorkload` to `true` in the `cluster-monitoring-config` config map under the `openshift-monitoring` namespace.

| Property | Type | Description |
| -------- | ---- | ----------- |
| alertmanager | *[AlertmanagerUserWorkloadConfig](#alertmanageruserworkloadconfig) | Defines the settings for the Alertmanager component in user workload monitoring. |
| prometheus | *[PrometheusRestrictedConfig](#prometheusrestrictedconfig) | Defines the settings for the Prometheus component in user workload monitoring. |
| prometheusOperator | *[PrometheusOperatorConfig](#prometheusoperatorconfig) | Defines the settings for the Prometheus Operator component in user workload monitoring. |
| thanosRuler | *[ThanosRulerConfig](#thanosrulerconfig) | Defines the settings for the Thanos Ruler component in user workload monitoring. |

[Back to TOC](#table-of-contents)
