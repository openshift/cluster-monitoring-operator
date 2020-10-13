# Configuring Cluster Monitoring

Parts of Cluster Monitoring are configurable. This configuration lies in a ConfigMap called `cluster-monitoring-config` in the `openshift-monitoring` namespace. The configuration file itself is defined under the `config.yaml` key within the ConfigMap's data.

Configuring Cluster Monitoring is optional. If the config does not exist, or is empty or malformed, then defaults will be used.

## Reference

The following configuration options are available for Cluster Monitoring.

### Config

The Config object represents the top level keys of the YAML configuration. Refer to the underlying configuration objects for their individual fields.

```yaml
[ prometheusOperator: <PrometheusOperatorConfig> ]
[ prometheusK8s: <PrometheusK8sConfig> ]
[ alertmanagerMain: <AlertmanagerMainConfig> ]
[ nodeExporter: <NodeExporterConfig> ]
[ kubeStateMetrics: <KubeStateMetricsConfig> ]
[ grafana: <GrafanaConfig> ]
[ thanosQuerier: <ThanosQuerierConfig> ]
[ openshiftStateMetrics: <OpenShiftMetricsConfig> ]
[ http: <HTTPConfig> ]
[ enableUserWorkload: <UserWorkloadEnabled> ]
[ telemeterClient: <TelemeterClientConfig> ]
```

### PrometheusOperatorConfig

Use PrometheusOperatorConfig to customize the base images used by the Prometheus Operator.

```yaml
logLevel: <string>
# nodeSelector defines the nodes on which PrometheusOperator instances will be scheduled.
nodeSelector: 
  [ - <labelname>: <labelvalue> ]
# tolerations allow PrometheusOperator instances to be scheduled onto nodes with matching taints
tolerations:
  - [v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#toleration-v1-core)
```

### PrometheusK8sConfig

Use PrometheusK8sConfig to customize the Prometheus instance used for cluster monitoring.

```yaml
# logLevel defines the verbosity of PrometheusK8s instance
logLevel: <string>
# retention time for samples.
retention: <string>
# nodeSelector defines the nodes on which the Prometheus server will be scheduled.
nodeSelector:
  [ - <labelname>: <labelvalue> ]
# tolerations allow Prometheus server instances to be scheduled onto nodes with matching taints
tolerations:
  - [v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#toleration-v1-core)
# resources defines the resource requests and limits for the Prometheus instance.
resources: [v1.ResourceRequirements](https://kubernetes.io/docs/api-reference/v1.6/#resourcerequirements-v1-core)
# externalLabels allows the external labels configuration of Prometheus to be
# specified by users
externalLabels:
  [ - <labelname>: <labelvalue> ]
# volumeClaimTemplate defines the template to use for persistent storage for Prometheus pods.
volumeClaimTemplate: [v1.PersistentVolumeClaim](https://kubernetes.io/docs/api-reference/v1.6/#persistentvolumeclaim-v1-core)
# remoteWrite defines the `remote_write` configuration for prometheus.
remoteWrite:
  - url: <string>
```

### AlertmanagerMainConfig

Use AlertmanagerMainConfig to customize the central Alertmanager cluster.

```yaml
# nodeSelector defines the nodes on which Alertmanager instances will be scheduled.
nodeSelector:
  [ - <labelname>: <labelvalue> ]
# tolerations allow Alertmanager instances to be scheduled onto nodes with matching taints
tolerations:
  - [v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#toleration-v1-core)
# resources defines the resource requests and limits for the Alertmanager instances.
resources: [v1.ResourceRequirements](https://kubernetes.io/docs/api-reference/v1.6/#resourcerequirements-v1-core)
# volumeClaimTemplate defines the template to use for persistent storage for Alertmanager pods.
volumeClaimTemplate: [v1.PersistentVolumeClaim](https://kubernetes.io/docs/api-reference/v1.6/#persistentvolumeclaim-v1-core)
```

### KubeStateMetricsConfig

Use KubeStateMetricsConfig to configure parameters for deployment of the `kube-state-metrics` components.

```yaml
# nodeSelector defines the nodes on which KubeStateMetrics instances will be scheduled.
nodeSelector: 
  [ - <labelname>: <labelvalue> ]
# tolerations allow KubeStateMetrics instances to be scheduled onto nodes with matching taints
tolerations:
  - [v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#toleration-v1-core)
```

### GrafanaConfig

Use GrafanaConfig to configure parameters for deployment of the `grafana` components.
```yaml
# nodeSelector defines the nodes on which Grafana instances will be scheduled.
nodeSelector: 
  [ - <labelname>: <labelvalue> ]
# tolerations allow Grafana instances to be scheduled onto nodes with matching taints
tolerations:
  - [v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#toleration-v1-core)
# resources defines the resource requests and limits for the Grafana instances.
```

### ThanosQuerierConfig

Use ThanosQuerierConfig to configure parameters for deployment of the `thanos-querier` components.

```yaml
# nodeSelector defines the nodes on which thanosQuerier instances will be scheduled.
nodeSelector: 
  [ - <labelname>: <labelvalue> ]
# tolerations allow thanosQuerier instances to be scheduled onto nodes with matching taints
tolerations:
  - [v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#toleration-v1-core)
# resources defines the resource requests and limits for the thanosQuerier instances.
resources: [v1.ResourceRequirements](https://kubernetes.io/docs/api-reference/v1.6/#resourcerequirements-v1-core)
```

### HTTPConfig

Use HTTPConfig to configure proxy parameter for the cluster monitoring components.

```yaml
httpProxy: <string>
httpsProxy: <string>
noProxy: <string>
```

### UserWorkloadEnabled

Use UserWorkloadEnabled for Monitoring own  services in addition to monitoring the openshift cluster.

```yaml
enableUserWorkload: <bool>
```

[quay]: https://quay.io/