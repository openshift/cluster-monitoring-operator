# Configuring Cluster Monitoring

Parts of Cluster Monitoring are configurable. This configuration lies in a ConfigMap called `cluster-monitoring-config` in the `openshift-monitoring` namespace. The configuration file itself is defined under the `config.yaml` key within the ConfigMap's data.

Configuring Cluster Monitoring is optional. If the config does not exist, or is empty or malformed, then defaults will be used.

## Configuring custom images

In certain environments it may be required that container images are downloaded from a custom registry rather than from the canonical container image repositories on [quay.io][quay].

This is an example configuration with all image parameters set to a custom registry:

[embedmd]:# (../../examples/user-guides/configuring-cluster-monitoring/custom-image-config.yaml)
```yaml
prometheusOperator:
  baseImage: custom-registry.com/prometheus-operator
  prometheusConfigReloaderBaseImage: custom-registry.com/prometheus-config-reloader
  configReloaderBaseImage: custom-registry.com/configmap-reload
prometheusK8s:
  baseImage: custom-registry.com/prometheus
alertmanagerMain:
  baseImage: custom-registry.com/alertmanager
auth:
  baseImage: custom-registry.com/openshift-oauth-proxy
nodeExporter:
  baseImage: custom-registry.com/node-exporter
kubeStateMetrics:
  baseImage: custom-registry.com/kube-state-metrics
  addonResizerBaseImage: custom-registry.com/addon-resizer
```

> Note: The container images coming from repositories of a custom registry are expected to mirror the canonical repositories on [quay.io][quay].

## Reference

The following configuration options are available for Cluster Monitoring.

### Config

The Config object represents the top level keys of the YAML configuration. Refer to the underlying configuration objects for their individual fields.

```yaml
[ prometheusOperator: <PrometheusOperatorConfig> ]
[ prometheusK8s: <PrometheusK8sConfig> ]
[ alertmanagerMain: <AlertmanagerMainConfig> ]
[ ingress: <IngressConfig> ]
[ auth: <AuthConfig> ]
[ nodeExporter: <NodeExporterConfig> ]
[ kubeStateMetrics: <KubeStateMetricsConfig> ]
```

### PrometheusOperatorConfig

Use PrometheusOperatorConfig to customize the base images used by the Prometheus Operator.

```yaml
# baseImage references a base container image. Defaults to "quay.io/coreos/prometheus-operator".
baseImage: <string>
# prometheusConfigReloaderBaseImage references a base container image. Defaults to "quay.io/coreos/prometheus-config-reloader".
prometheusConfigReloaderBaseImage: <string>
# configReloaderBaseImage references a base container image. Defaults to "quay.io/coreos/configmap-reload".
configReloaderBaseImage: <string>
```

### PrometheusK8sConfig

Use PrometheusK8sConfig to customize the Prometheus instance used for cluster monitoring.

```yaml
# retention time for samples.
retention: <string>
# baseImage references a base container image. Defaults to "quay.io/prometheus/prometheus".
baseImage: <string>
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
```

### AlertmanagerMainConfig

Use AlertmanagerMainConfig to customize the central Alertmanager cluster.

```yaml
# baseImage references a base container image. Defaults to "quay.io/prometheus/alertmanager".
baseImage: <string>
# nodeSelector defines the nodes on which Alertmanager instances will be scheduled.
nodeSelector:
  [ - <labelname>: <labelvalue> ]
# tolerations allow Alertmanager instances to be scheduled onto nodes with matching taints
tolerations:
  - [v1.Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.13/#toleration-v1-core)
# resources defines the resource requests and limits for the Alertmanager instances.
resources: [v1.ResourceRequirements](https://kubernetes.io/docs/api-reference/v1.6/#resourcerequirements-v1-core)
# volumeClaimTemplate defines the template to use for persistent storage for Alertmanager nodes.
volumeClaimTemplate: [v1.PersistentVolumeClaim](https://kubernetes.io/docs/api-reference/v1.6/#persistentvolumeclaim-v1-core)
```

### AuthConfig

Use AuthConfig to configure parameters for the authentication proxies of Prometheus and Alertmanager Pods.

```yaml
# baseImage is the container image repository that will be used to deploy monitoring auth service, along with the tag specified in the asset manifest. Defaults to repository listed in manifests in assets folder.
baseImage: <string>
```
### NodeExporterConfig

Use NodeExporterConfig to configure parameters for deployment of the `node-exporter` components.

```yaml
# baseImage is the container image repository that will be used to deploy the node-exporter pods
baseImage: <string>
```
### KubeStateMetricsConfig

Use KubeStateMetricsConfig to configure parameters for deployment of the `kube-state-metrics` components.

```yaml
# baseImage is the container image repository that will be used to deploy the kube-state-metrics pods
baseImage: <string>
addonResizerBaseImage: <string>
```

[quay]: https://quay.io/
