# Default alerts

Cluster Monitoring ships with the following alerts preconfigured by default.

|Alert   	|Severity   	|Description   	|
|---	|---	|---	|
|<a id="DeadMansSwitch"></a>`DeadMansSwitch`   	|`none`   	|Alert triggers continuously to ensure that the entire Alerting pipeline is functional. For more information, see [Dead Man’s Switch][dead-man] in Configuring Alertmanager.   	|
|<a id="AlertmanagerConfigInconsistent"></a>`AlertmanagerConfigInconsistent`   	|`critical`   	|The configuration of the instances of the Alertmanager cluster for a given service are out of sync.   	|
|<a id="AlertmanagerDownOrMissing"></a>`AlertmanagerDownOrMissing`   	|`warning`  	| Alertmanager down or not discovered. An unexpected number of Alertmanagers are scraped or Alertmanagers have disappeared from discovery.   	|
|<a id="APIServerErrorsHigh"></a>`APIServerErrorsHigh`   	|`warning/critical`   	|The API server responds to a lot of requests with errors.   	|
|<a id="APIServerLatencyHigh"></a>`APIServerLatencyHigh`   	|`warning/critical`   	|The response latency of the API server to clients is high.   	|
|<a id="DaemonSetRolloutStuck"></a>`DaemonSetRolloutStuck`   	|`warning`   	|A daemon set is not fully rolled out to all desired nodes.   	|
|<a id="DeploymentGenerationMismatch"></a>`DeploymentGenerationMismatch`   	|`warning`   	|The observed generation of a deployment does not match its desired generation.   	|
|<a id="DeploymentReplicasNotUpdated"></a>`DeploymentReplicasNotUpdated`   	|`warning`   	|A deployment has not been rolled out properly. Either replicas are not being updated to the most recent version, or not all replicas are ready. The alert does not fire if the deployment was paused intentionally.   	|
|<a id="FailedReload"></a>`FailedReload`   	|`warning`   	|Reloading Alertmanager's or Prometheus’ configuration has failed for a given namespace.   	|
|<a id="FdExhaustionClose"></a>`FdExhaustionClose`   	|two default alerts, with two severities: `warning` and `critical`   	|File descriptors for the given job, namespace, pod, or instance will soon be exhausted.   	|
|<a id="K8SApiServerLatency"></a>`K8SApiServerLatency`   	|`warning`   	|Kubernetes API server latency is high. More than 99th percentile latency for given requests to the kube-apiserver is above 1 second.   	|
|<a id="K8SApiserverDown"></a>`K8SApiserverDown`   	|`critical`   	|The API server is unreachable. Prometheus failed to scrape the API server(s), or all API servers have disappeared from service discovery.   	|
|<a id="K8SControllerManagerDown"></a>`K8SControllerManagerDown`   	|`critical`  	| There is no running K8S controller manager. Deployments and replication controllers are not making progress.   	|
|<a id="K8SKubeletDown"></a>`K8SKubeletDown`   	|`warning`   	|Many kubelets cannot be scraped. Prometheus failed to scrape the listed percentage of kubelets, or all kubelets have disappeared from service discovery.   	|
|<a id="K8SKubeletTooManyPods"></a>`K8SKubeletTooManyPods`   	|`warning`   	|Kubelet is close to pod limit. The given kubelet instance is running the listed number of pods, which is close to the limit of 110.   	|
|<a id="K8SManyNodesNotReady"></a>`K8SManyNodesNotReady`   	|`critical`   	|More than 10% of the listed number of Kubernetes nodes are NotReady.   	|
|<a id="K8SNodeNotReady"></a>`K8SNodeNotReady`   	|`warning`   	|The Kubelet on the listed node has not checked in with the API, or has set itself to NotReady, for more than an hour.   	|
|<a id="K8SSchedulerDown"></a>`K8SSchedulerDown`   	|`critical`   	|There is no running Kubernetes scheduler. New pods are not being assigned to nodes.   	|
|<a id="NodeExporterDown"></a>`NodeExporterDown`   	|`warning`   	|Prometheus could not scrape a node-exporter for more than 10m, or node-exporters have disappeared from discovery.   	|
|<a id="NodeDiskRunningFull"></a>`NodeDiskRunningFull`   	|`warning/critical`   	|If disks keep filling up at the current pace they will run out of free space within the next hours.   	|
|<a id="PodFrequentlyRestart"></a>`PodFrequentlyRestart`   	|`warning`   	|A pod is restarting several times an hour.   	|
|<a id="PrometheusNotConnectedToAlertmanagers"></a>`PrometheusNotConnectedToAlertmanagers`   	| `warning`   	|A monitored Prometheus instance is not connected to any Alertmanagers. Any firing alerts will not be sent anywhere.   	|
|<a id="PrometheusNotificationQueueRunningFull"></a>`PrometheusNotificationQueueRunningFull`   	|`warning`   	|Prometheus is generating more alerts than it can send to Alertmanagers in time.   	|
|<a id="PrometheusErrorSendingAlerts"></a>`PrometheusErrorSendingAlerts`   	|`warning/critical`   	|Prometheus encounters errors while trying to send alerts to Alertmanagers.   	|
|<a id="TargetDown"></a>`TargetDown`   	|`warning`  	|Targets are down. The listed percentage of job targets are down.   	|


[dead-man]: configuring-prometheus-alertmanager.md#dead-mans-switch
