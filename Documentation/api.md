
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
* [K8sPrometheusAdapter](#k8sprometheusadapter)
* [KubeStateMetricsConfig](#kubestatemetricsconfig)
* [MetricsServerConfig](#metricsserverconfig)
* [MonitoringPluginConfig](#monitoringpluginconfig)
* [NodeExporterCollectorBuddyInfoConfig](#nodeexportercollectorbuddyinfoconfig)
* [NodeExporterCollectorConfig](#nodeexportercollectorconfig)
* [NodeExporterCollectorCpufreqConfig](#nodeexportercollectorcpufreqconfig)
* [NodeExporterCollectorKSMDConfig](#nodeexportercollectorksmdconfig)
* [NodeExporterCollectorMountStatsConfig](#nodeexportercollectormountstatsconfig)
* [NodeExporterCollectorNetClassConfig](#nodeexportercollectornetclassconfig)
* [NodeExporterCollectorNetDevConfig](#nodeexportercollectornetdevconfig)
* [NodeExporterCollectorProcessesConfig](#nodeexportercollectorprocessesconfig)
* [NodeExporterCollectorSysctlConfig](#nodeexportercollectorsysctlconfig)
* [NodeExporterCollectorSystemdConfig](#nodeexportercollectorsystemdconfig)
* [NodeExporterCollectorTcpStatConfig](#nodeexportercollectortcpstatconfig)
* [NodeExporterConfig](#nodeexporterconfig)
* [OpenShiftStateMetricsConfig](#openshiftstatemetricsconfig)
* [PrometheusK8sConfig](#prometheusk8sconfig)
* [PrometheusOperatorAdmissionWebhookConfig](#prometheusoperatoradmissionwebhookconfig)
* [PrometheusOperatorConfig](#prometheusoperatorconfig)
* [PrometheusRestrictedConfig](#prometheusrestrictedconfig)
* [RemoteWriteSpec](#remotewritespec)
* [TLSConfig](#tlsconfig)
* [TelemeterClientConfig](#telemeterclientconfig)
* [ThanosQuerierConfig](#thanosquerierconfig)
* [ThanosRulerConfig](#thanosrulerconfig)
* [UserWorkloadConfig](#userworkloadconfig)
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
| bearerToken | *[v1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#secretkeyselector-v1-core) | Defines the secret key reference containing the bearer token to use when authenticating to Alertmanager. |
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
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the Alertmanager container. |
| secrets | []string | Defines a list of secrets that need to be mounted into the Alertmanager. The secrets must reside within the same namespace as the Alertmanager object. They will be added as volumes named secret-<secret-name> and mounted at /etc/alertmanager/secrets/<secret-name> within the 'alertmanager' container of the Alertmanager Pods. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |
| volumeClaimTemplate | *[monv1.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/v0.76.0/Documentation/api.md#embeddedpersistentvolumeclaim) | Defines persistent storage for Alertmanager. Use this setting to configure the persistent volume claim, including storage class, volume size, and name. |

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
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the Alertmanager container. |
| secrets | []string | Defines a list of secrets that need to be mounted into the Alertmanager. The secrets must reside within the same namespace as the Alertmanager object. They will be added as volumes named secret-<secret-name> and mounted at /etc/alertmanager/secrets/<secret-name> within the 'alertmanager' container of the Alertmanager Pods. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |
| volumeClaimTemplate | *[monv1.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/v0.76.0/Documentation/api.md#embeddedpersistentvolumeclaim) | Defines persistent storage for Alertmanager. Use this setting to configure the persistent volume claim, including storage class, volume size and name. |

[Back to TOC](#table-of-contents)

## ClusterMonitoringConfiguration

#### Description

The `ClusterMonitoringConfiguration` resource defines settings that customize the default platform monitoring stack through the `cluster-monitoring-config` config map in the `openshift-monitoring` namespace.

| Property | Type | Description |
| -------- | ---- | ----------- |
| alertmanagerMain | *[AlertmanagerMainConfig](#alertmanagermainconfig) | `AlertmanagerMainConfig` defines settings for the Alertmanager component in the `openshift-monitoring` namespace. |
| enableUserWorkload | *bool | `UserWorkloadEnabled` is a Boolean flag that enables monitoring for user-defined projects. |
| userWorkload | *[UserWorkloadConfig](#userworkloadconfig) | `UserWorkload` defines settings for the monitoring of user-defined projects. |
| metricsServer | *[MetricsServerConfig](#metricsserverconfig) | `MetricsServer` defines settings for the MetricsServer component. |
| kubeStateMetrics | *[KubeStateMetricsConfig](#kubestatemetricsconfig) | `KubeStateMetricsConfig` defines settings for the `kube-state-metrics` agent. |
| prometheusK8s | *[PrometheusK8sConfig](#prometheusk8sconfig) | `PrometheusK8sConfig` defines settings for the Prometheus component. |
| prometheusOperator | *[PrometheusOperatorConfig](#prometheusoperatorconfig) | `PrometheusOperatorConfig` defines settings for the Prometheus Operator component. |
| prometheusOperatorAdmissionWebhook | *[PrometheusOperatorAdmissionWebhookConfig](#prometheusoperatoradmissionwebhookconfig) | `PrometheusOperatorAdmissionWebhookConfig` defines settings for the Prometheus Operator's admission webhook component. |
| openshiftStateMetrics | *[OpenShiftStateMetricsConfig](#openshiftstatemetricsconfig) | `OpenShiftMetricsConfig` defines settings for the `openshift-state-metrics` agent. |
| telemeterClient | *[TelemeterClientConfig](#telemeterclientconfig) | `TelemeterClientConfig` defines settings for the Telemeter Client component. |
| thanosQuerier | *[ThanosQuerierConfig](#thanosquerierconfig) | `ThanosQuerierConfig` defines settings for the Thanos Querier component. |
| nodeExporter | [NodeExporterConfig](#nodeexporterconfig) | `NodeExporterConfig` defines settings for the `node-exporter` agent. |
| monitoringPlugin | *[MonitoringPluginConfig](#monitoringpluginconfig) | `MonitoringPluginConfig` defines settings for the monitoring `console-plugin`. |

[Back to TOC](#table-of-contents)

## K8sPrometheusAdapter

#### Description

The `K8sPrometheusAdapter` resource defines settings for the Prometheus Adapter component. This is deprecated config, setting this has no effect and will be removed in a future version.

| Property | Type | Description |
| -------- | ---- | ----------- |
| audit | *Audit | Defines the audit configuration used by the Prometheus Adapter instance. Possible profile values are: `metadata`, `request`, `requestresponse`, and `none`. The default value is `metadata`. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the PrometheusAdapter container. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |

[Back to TOC](#table-of-contents)

## KubeStateMetricsConfig

#### Description

The `KubeStateMetricsConfig` resource defines settings for the `kube-state-metrics` agent.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the KubeStateMetrics container. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |

[Back to TOC](#table-of-contents)

## MetricsServerConfig

#### Description

The `MetricsServerConfig` resource defines settings for the Metrics Server component.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| audit | *Audit | Defines the audit configuration used by the Metrics Server instance. Possible profile values are: `metadata`, `request`, `requestresponse`, and `none`. The default value is `metadata`. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the Metrics Server container. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |

[Back to TOC](#table-of-contents)

## MonitoringPluginConfig

#### Description

The `MonitoringPluginConfig` resource defines settings for the Console Plugin component in the `openshift-monitoring` namespace.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| nodeSelector | map[string]string | Defines the nodes on which the Pods are scheduled. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the console-plugin container. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorBuddyInfoConfig

#### Description

The `NodeExporterCollectorBuddyInfoConfig` resource works as an on/off switch for the `buddyinfo` collector of the `node-exporter` agent. By default, the `buddyinfo` collector is disabled.


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `buddyinfo` collector. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorConfig

#### Description

The `NodeExporterCollectorConfig` resource defines settings for individual collectors of the `node-exporter` agent.


<em>appears in: [NodeExporterConfig](#nodeexporterconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| cpufreq | [NodeExporterCollectorCpufreqConfig](#nodeexportercollectorcpufreqconfig) | Defines the configuration of the `cpufreq` collector, which collects CPU frequency statistics. Disabled by default. |
| tcpstat | [NodeExporterCollectorTcpStatConfig](#nodeexportercollectortcpstatconfig) | Defines the configuration of the `tcpstat` collector, which collects TCP connection statistics. Disabled by default. |
| netdev | [NodeExporterCollectorNetDevConfig](#nodeexportercollectornetdevconfig) | Defines the configuration of the `netdev` collector, which collects network devices statistics. Enabled by default. |
| netclass | [NodeExporterCollectorNetClassConfig](#nodeexportercollectornetclassconfig) | Defines the configuration of the `netclass` collector, which collects information about network devices. Enabled by default. |
| buddyinfo | [NodeExporterCollectorBuddyInfoConfig](#nodeexportercollectorbuddyinfoconfig) | Defines the configuration of the `buddyinfo` collector, which collects statistics about memory fragmentation from the `node_buddyinfo_blocks` metric. This metric collects data from `/proc/buddyinfo`. Disabled by default. |
| mountstats | [NodeExporterCollectorMountStatsConfig](#nodeexportercollectormountstatsconfig) | Defines the configuration of the `mountstats` collector, which collects statistics about NFS volume I/O activities. Disabled by default. |
| ksmd | [NodeExporterCollectorKSMDConfig](#nodeexportercollectorksmdconfig) | Defines the configuration of the `ksmd` collector, which collects statistics from the kernel same-page merger daemon. Disabled by default. |
| processes | [NodeExporterCollectorProcessesConfig](#nodeexportercollectorprocessesconfig) | Defines the configuration of the `processes` collector, which collects statistics from processes and threads running in the system. Disabled by default. |
| sysctl | [NodeExporterCollectorSysctlConfig](#nodeexportercollectorsysctlconfig) | Defines the configuration of the `sysctl` collector, which collects sysctl metrics. Disabled by default. |
| systemd | [NodeExporterCollectorSystemdConfig](#nodeexportercollectorsystemdconfig) | Defines the configuration of the `systemd` collector, which collects statistics on the systemd daemon and its managed services. Disabled by default. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorCpufreqConfig

#### Description

The `NodeExporterCollectorCpufreqConfig` resource works as an on/off switch for the `cpufreq` collector of the `node-exporter` agent. By default, the `cpufreq` collector is disabled. Under certain circumstances, enabling the cpufreq collector increases CPU usage on machines with many cores. If you enable this collector and have machines with many cores, monitor your systems closely for excessive CPU usage. Please refer to https://github.com/prometheus/node_exporter/issues/1880 for more details. A related bug: https://bugzilla.redhat.com/show_bug.cgi?id=1972076


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `cpufreq` collector. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorKSMDConfig

#### Description

The `NodeExporterCollectorKSMDConfig` resource works as an on/off switch for the `ksmd` collector of the `node-exporter` agent. By default, the `ksmd` collector is disabled.


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `ksmd` collector. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorMountStatsConfig

#### Description

The `NodeExporterCollectorMountStatsConfig` resource works as an on/off switch for the `mountstats` collector of the `node-exporter` agent. By default, the `mountstats` collector is disabled. If enabled, these metrics become available:\n\n\t`node_mountstats_nfs_read_bytes_total`,\n\t`node_mountstats_nfs_write_bytes_total`,\n\t`node_mountstats_nfs_operations_requests_total`.\n\nPlease be aware that these metrics can have a high cardinality. If you enable this collector, closely monitor any increases in memory usage for the `prometheus-k8s` pods.


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `mountstats` collector. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorNetClassConfig

#### Description

The `NodeExporterCollectorNetClassConfig` resource works as an on/off switch for the `netclass` collector of the `node-exporter` agent. By default, the `netclass` collector is enabled. If disabled, these metrics become unavailable: `node_network_info`, `node_network_address_assign_type`, `node_network_carrier`, `node_network_carrier_changes_total`, `node_network_carrier_up_changes_total`, `node_network_carrier_down_changes_total`, `node_network_device_id`, `node_network_dormant`, `node_network_flags`, `node_network_iface_id`, `node_network_iface_link`, `node_network_iface_link_mode`, `node_network_mtu_bytes`, `node_network_name_assign_type`, `node_network_net_dev_group`, `node_network_speed_bytes`, `node_network_transmit_queue_length`, `node_network_protocol_type`.


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `netclass` collector. |
| useNetlink | bool | A Boolean flag that activates the `netlink` implementation of the `netclass` collector. Its default value is `true`: activating the netlink mode. This implementation improves the performance of the `netclass` collector. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorNetDevConfig

#### Description

The `NodeExporterCollectorNetDevConfig` resource works as an on/off switch for the `netdev` collector of the `node-exporter` agent. By default, the `netdev` collector is enabled. If disabled, these metrics become unavailable: `node_network_receive_bytes_total`, `node_network_receive_compressed_total`, `node_network_receive_drop_total`, `node_network_receive_errs_total`, `node_network_receive_fifo_total`, `node_network_receive_frame_total`, `node_network_receive_multicast_total`, `node_network_receive_nohandler_total`, `node_network_receive_packets_total`, `node_network_transmit_bytes_total`, `node_network_transmit_carrier_total`, `node_network_transmit_colls_total`, `node_network_transmit_compressed_total`, `node_network_transmit_drop_total`, `node_network_transmit_errs_total`, `node_network_transmit_fifo_total`, `node_network_transmit_packets_total`.


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `netdev` collector. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorProcessesConfig

#### Description

The `NodeExporterCollectorProcessesConfig` resource works as an on/off switch for the `processes` collector of the `node-exporter` agent. If enabled, these metrics become available: `node_processes_max_processes`, `node_processes_pids`, `node_processes_state`, `node_processes_threads`, `node_processes_threads_state`. The metric `node_processes_state` and `node_processes_threads_state` can have up to 5 series each, depending on the state of the processes and threads. The possible states of a process or a thread are: 'D' (UNINTERRUPTABLE_SLEEP), 'R' (RUNNING & RUNNABLE), 'S' (INTERRRUPTABLE_SLEEP), 'T' (STOPPED), 'Z' (ZOMBIE). By default, the `processes` collector is disabled.


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `processes` collector. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorSysctlConfig

#### Description

The `NodeExporterCollectorSysctlConfig` resource works as an on/off switch for the `sysctl` collector of the `node-exporter` agent. Caution! Exposing metrics like kernel.random.uuid can disrupt Prometheus, as it generates new data series with every scrape. Use this option judiciously! By default, the `sysctl` collector is disabled.


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `sysctl` collector. |
| includeSysctlMetrics | []string | A list of numeric sysctl values. Note that a sysctl can contain multiple values, for example: `net.ipv4.tcp_rmem = 4096\t131072\t6291456`. Using `includeSysctlMetrics: ['net.ipv4.tcp_rmem']` the collector will expose: `node_sysctl_net_ipv4_tcp_rmem{index=\"0\"} 4096`, `node_sysctl_net_ipv4_tcp_rmem{index=\"1\"} 131072`, `node_sysctl_net_ipv4_tcp_rmem{index=\"2\"} 6291456`. If the indexes have defined meaning like in this case, the values can be mapped to multiple metrics: `includeSysctlMetrics: ['net.ipv4.tcp_rmem:min,default,max']`. The collector will expose these metrics as such: `node_sysctl_net_ipv4_tcp_rmem_min 4096`, `node_sysctl_net_ipv4_tcp_rmem_default 131072`, `node_sysctl_net_ipv4_tcp_rmem_max 6291456`. |
| includeInfoSysctlMetrics | []string | A list of string sysctl values. For example: `includeSysctlMetrics: ['kernel.core_pattern', 'kernel.seccomp.actions_avail = kill_process kill_thread']`. The collector will expose these metrics as such: `node_sysctl_info{name=\"kernel.core_pattern\", value=\"core\"} 1`, `node_sysctl_info{name=\"kernel.seccomp.actions_avail\", index=\"0\", value=\"kill_process\"} 1`, `node_sysctl_info{name=\"kernel.seccomp.actions_avail\", index=\"1\", value=\"kill_thread\"} 1`, ... |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorSystemdConfig

#### Description

The `NodeExporterCollectorSystemdConfig` resource works as an on/off switch for the `systemd` collector of the `node-exporter` agent. By default, the `systemd` collector is disabled. If enabled, the following metrics become available: `node_systemd_system_running`, `node_systemd_units`, `node_systemd_version`. If the unit uses a socket, it also generates these 3 metrics: `node_systemd_socket_accepted_connections_total`, `node_systemd_socket_current_connections`, `node_systemd_socket_refused_connections_total`. You can use the `units` parameter to select the systemd units to be included by the `systemd` collector. The selected units are used to generate the `node_systemd_unit_state` metric, which shows the state of each systemd unit. The timer units such as `logrotate.timer` generate one more metric `node_systemd_timer_last_trigger_seconds`. However, this metric's cardinality might be high (at least 5 series per unit per node). If you enable this collector with a long list of selected units, closely monitor the `prometheus-k8s` deployment for excessive memory usage.


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `systemd` collector. |
| units | []string | A list of regular expression (regex) patterns that match systemd units to be included by the `systemd` collector. By default, the list is empty, so the collector exposes no metrics for systemd units. |

[Back to TOC](#table-of-contents)

## NodeExporterCollectorTcpStatConfig

#### Description

The `NodeExporterCollectorTcpStatConfig` resource works as an on/off switch for the `tcpstat` collector of the `node-exporter` agent. By default, the `tcpstat` collector is disabled.


<em>appears in: [NodeExporterCollectorConfig](#nodeexportercollectorconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enabled | bool | A Boolean flag that enables or disables the `tcpstat` collector. |

[Back to TOC](#table-of-contents)

## NodeExporterConfig

#### Description

The `NodeExporterConfig` resource defines settings for the `node-exporter` agent.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| collectors | [NodeExporterCollectorConfig](#nodeexportercollectorconfig) | Defines which collectors are enabled and their additional configuration parameters. |
| maxProcs | uint32 | The target number of CPUs on which the Node Exporter's process will run. Use this setting to override the default value, which is set either to `4` or to the number of CPUs on the host, whichever is smaller. The default value is computed at runtime and set via the `GOMAXPROCS` environment variable before Node Exporter is launched. If a kernel deadlock occurs or if performance degrades when reading from `sysfs` concurrently, you can change this value to `1`, which limits Node Exporter to running on one CPU. For nodes with a high CPU count, setting the limit to a low number saves resources by preventing Go routines from being scheduled to run on all CPUs. However, I/O performance degrades if the `maxProcs` value is set too low, and there are many metrics to collect. |
| ignoredNetworkDevices | *[]string | A list of network devices, as regular expressions, to be excluded from the relevant collector configuration such as `netdev` and `netclass`. When not set, the Cluster Monitoring Operator uses a predefined list of devices to be excluded to minimize the impact on memory usage. When set as an empty list, no devices are excluded. If you modify this setting, monitor the `prometheus-k8s` deployment closely for excessive memory usage. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the NodeExporter container. |

[Back to TOC](#table-of-contents)

## OpenShiftStateMetricsConfig

#### Description

The `OpenShiftStateMetricsConfig` resource defines settings for the `openshift-state-metrics` agent.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the OpenShiftStateMetrics container. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |

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
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the Prometheus container. |
| retention | string | Defines the duration for which Prometheus retains data. This definition must be specified using the following regular expression pattern: `[0-9]+(ms\|s\|m\|h\|d\|w\|y)` (ms = milliseconds, s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years). The default value is `15d`. |
| retentionSize | string | Defines the maximum amount of disk space used by data blocks plus the write-ahead log (WAL). Supported values are `B`, `KB`, `KiB`, `MB`, `MiB`, `GB`, `GiB`, `TB`, `TiB`, `PB`, `PiB`, `EB`, and `EiB`. By default, no limit is defined. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines the pod's topology spread constraints. |
| collectionProfile | CollectionProfile | Defines the metrics collection profile that Prometheus uses to collect metrics from the platform components. Supported values are `full` or `minimal`. In the `full` profile (default), Prometheus collects all metrics that are exposed by the platform components. In the `minimal` profile, Prometheus only collects metrics necessary for the default platform alerts, recording rules, telemetry and console dashboards. |
| volumeClaimTemplate | *[monv1.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/v0.76.0/Documentation/api.md#embeddedpersistentvolumeclaim) | Defines persistent storage for Prometheus. Use this setting to configure the persistent volume claim, including storage class, volume size and name. |

[Back to TOC](#table-of-contents)

## PrometheusOperatorAdmissionWebhookConfig

#### Description

The `PrometheusOperatorAdmissionWebhookConfig` resource defines settings for the Prometheus Operator's admission webhook workload.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the prometheus-operator-admission-webhook container. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |

[Back to TOC](#table-of-contents)

## PrometheusOperatorConfig

#### Description

The `PrometheusOperatorConfig` resource defines settings for the Prometheus Operator component.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration), [UserWorkloadConfiguration](#userworkloadconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| logLevel | string | Defines the log level settings for Prometheus Operator. The possible values are `error`, `warn`, `info`, and `debug`. The default value is `info`. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the PrometheusOperator container. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |

[Back to TOC](#table-of-contents)

## PrometheusRestrictedConfig

#### Description

The `PrometheusRestrictedConfig` resource defines the settings for the Prometheus component that monitors user-defined projects.


<em>appears in: [UserWorkloadConfiguration](#userworkloadconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| scrapeInterval | string | Configures the default interval between consecutive scrapes in case the `ServiceMonitor` or `PodMonitor` resource does not specify any value. The interval must be set between 5 seconds and 5 minutes. The value can be expressed in: seconds (for example `30s`.), minutes (for example `1m`.) or a mix of minutes and seconds (for example `1m30s`.). The default value is `30s`. |
| evaluationInterval | string | Configures the default interval between rule evaluations in case the `PrometheusRule` resource does not specify any value. The interval must be set between 5 seconds and 5 minutes. The value can be expressed in: seconds (for example `30s`.), minutes (for example `1m`.) or a mix of minutes and seconds (for example `1m30s`.). It only applies to `PrometheusRule` resources with the `openshift.io/prometheus-rule-evaluation-scope=\"leaf-prometheus\"` label. The default value is `30s`. |
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
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the Prometheus container. |
| retention | string | Defines the duration for which Prometheus retains data. This definition must be specified using the following regular expression pattern: `[0-9]+(ms\|s\|m\|h\|d\|w\|y)` (ms = milliseconds, s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years). The default value is `24h`. |
| retentionSize | string | Defines the maximum amount of disk space used by data blocks plus the write-ahead log (WAL). Supported values are `B`, `KB`, `KiB`, `MB`, `MiB`, `GB`, `GiB`, `TB`, `TiB`, `PB`, `PiB`, `EB`, and `EiB`. The default value is `nil`. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |
| volumeClaimTemplate | *[monv1.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/v0.76.0/Documentation/api.md#embeddedpersistentvolumeclaim) | Defines persistent storage for Prometheus. Use this setting to configure the storage class and size of a volume. |

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
| basicAuth | *[monv1.BasicAuth](https://github.com/prometheus-operator/prometheus-operator/blob/v0.76.0/Documentation/api.md#basicauth) | Defines basic authentication settings for the remote write endpoint URL. |
| bearerTokenFile | string | Defines the file that contains the bearer token for the remote write endpoint. However, because you cannot mount secrets in a pod, in practice you can only reference the token of the service account. |
| headers | map[string]string | Specifies the custom HTTP headers to be sent along with each remote write request. Headers set by Prometheus cannot be overwritten. |
| metadataConfig | *[monv1.MetadataConfig](https://github.com/prometheus-operator/prometheus-operator/blob/v0.76.0/Documentation/api.md#metadataconfig) | Defines settings for sending series metadata to remote write storage. |
| name | string | Defines the name of the remote write queue. This name is used in metrics and logging to differentiate queues. If specified, this name must be unique. |
| oauth2 | *monv1.OAuth2 | Defines OAuth2 authentication settings for the remote write endpoint. |
| proxyUrl | string | Defines an optional proxy URL. If the cluster-wide proxy is enabled, it replaces the proxyUrl setting. The cluster-wide proxy supports both HTTP and HTTPS proxies, with HTTPS taking precedence. |
| queueConfig | *[monv1.QueueConfig](https://github.com/prometheus-operator/prometheus-operator/blob/v0.76.0/Documentation/api.md#queueconfig) | Allows tuning configuration for remote write queue parameters. |
| remoteTimeout | string | Defines the timeout value for requests to the remote write endpoint. |
| sendExemplars | *bool | Enables sending exemplars via remote write. When enabled, Prometheus is configured to store a maximum of 100,000 exemplars in memory. Note that this setting only applies to user-defined monitoring. It is not applicable to default in-cluster monitoring. |
| sigv4 | *monv1.Sigv4 | Defines AWS Signature Version 4 authentication settings. |
| tlsConfig | *[monv1.SafeTLSConfig](https://github.com/prometheus-operator/prometheus-operator/blob/v0.76.0/Documentation/api.md#safetlsconfig) | Defines TLS authentication settings for the remote write endpoint. |
| url | string | Defines the URL of the remote write endpoint to which samples will be sent. |
| writeRelabelConfigs | [][monv1.RelabelConfig](https://github.com/prometheus-operator/prometheus-operator/blob/v0.76.0/Documentation/api.md#relabelconfig) | Defines the list of remote write relabel configurations. |

[Back to TOC](#table-of-contents)

## TLSConfig

#### Description

The `TLSConfig` resource configures the settings for TLS connections.

#### Required
   - ` insecureSkipVerify `

<em>appears in: [AdditionalAlertmanagerConfig](#additionalalertmanagerconfig)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| ca | *[v1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#secretkeyselector-v1-core) | Defines the secret key reference containing the Certificate Authority (CA) to use for the remote host. |
| cert | *[v1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#secretkeyselector-v1-core) | Defines the secret key reference containing the public certificate to use for the remote host. |
| key | *[v1.SecretKeySelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#secretkeyselector-v1-core) | Defines the secret key reference containing the private key to use for the remote host. |
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
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the TelemeterClient container. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |

[Back to TOC](#table-of-contents)

## ThanosQuerierConfig

#### Description

The `ThanosQuerierConfig` resource defines settings for the Thanos Querier component.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| enableRequestLogging | bool | A Boolean flag that enables or disables request logging. The default value is `false`. |
| logLevel | string | Defines the log level setting for Thanos Querier. The possible values are `error`, `warn`, `info`, and `debug`. The default value is `info`. |
| enableCORS | bool | A Boolean flag that enables setting CORS headers. The headers would allow access from any origin. The default value is `false`. |
| nodeSelector | map[string]string | Defines the nodes on which the pods are scheduled. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the Thanos Querier container. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines a pod's topology spread constraints. |

[Back to TOC](#table-of-contents)

## ThanosRulerConfig

#### Description

The `ThanosRulerConfig` resource defines configuration for the Thanos Ruler instance for user-defined projects.


<em>appears in: [UserWorkloadConfiguration](#userworkloadconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| additionalAlertmanagerConfigs | [][AdditionalAlertmanagerConfig](#additionalalertmanagerconfig) | Configures how the Thanos Ruler component communicates with additional Alertmanager instances. The default value is `nil`. |
| evaluationInterval | string | Configures the default interval between Prometheus rule evaluations in case the `PrometheusRule` resource does not specify any value. The interval must be set between 5 seconds and 5 minutes. The value can be expressed in: seconds (for example `30s`.), minutes (for example `1m`.) or a mix of minutes and seconds (for example `1m30s`.). It applies to `PrometheusRule` resources without the `openshift.io/prometheus-rule-evaluation-scope=\"leaf-prometheus\"` label. The default value is `15s`. |
| logLevel | string | Defines the log level setting for Thanos Ruler. The possible values are `error`, `warn`, `info`, and `debug`. The default value is `info`. |
| nodeSelector | map[string]string | Defines the nodes on which the Pods are scheduled. |
| resources | *[v1.ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#resourcerequirements-v1-core) | Defines resource requests and limits for the Thanos Ruler container. |
| retention | string | Defines the duration for which Prometheus retains data. This definition must be specified using the following regular expression pattern: `[0-9]+(ms\|s\|m\|h\|d\|w\|y)` (ms = milliseconds, s= seconds,m = minutes, h = hours, d = days, w = weeks, y = years). The default value is `24h`. |
| tolerations | [][v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#toleration-v1-core) | Defines tolerations for the pods. |
| topologySpreadConstraints | []v1.TopologySpreadConstraint | Defines topology spread constraints for the pods. |
| volumeClaimTemplate | *[monv1.EmbeddedPersistentVolumeClaim](https://github.com/prometheus-operator/prometheus-operator/blob/v0.76.0/Documentation/api.md#embeddedpersistentvolumeclaim) | Defines persistent storage for Thanos Ruler. Use this setting to configure the storage class and size of a volume. |

[Back to TOC](#table-of-contents)

## UserWorkloadConfig

#### Description

The `UserWorkloadConfig` resource defines settings for the monitoring of user-defined projects.


<em>appears in: [ClusterMonitoringConfiguration](#clustermonitoringconfiguration)</em>

| Property | Type | Description |
| -------- | ---- | ----------- |
| rulesWithoutLabelEnforcementAllowed | *bool | A Boolean flag that enables or disables the ability to deploy user-defined `PrometheusRules` objects for which the `namespace` label isn't enforced to the namespace of the object. Such objects should be created in a namespace configured under the `namespacesWithoutLabelEnforcement` property of the `UserWorkloadConfiguration` resource. The default value is `true`. |

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
| namespacesWithoutLabelEnforcement | []string | Defines the list of namespaces for which Prometheus and Thanos Ruler in user-defined monitoring don't enforce the `namespace` label value in `PrometheusRule` objects.\n\nIt allows to define recording and alerting rules that can query across multiple projects (not limited to user-defined projects) instead of deploying identical `PrometheusRule` objects in each user project.\n\nTo make the resulting alerts and metrics visible to project users, the query expressions should return a `namespace` label with a non-empty value. |

[Back to TOC](#table-of-contents)
