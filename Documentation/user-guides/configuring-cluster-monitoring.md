# Cluster Monitoring Configuration Reference

Parts of Cluster Monitoring are configurable. Depending on which part of the stack users want to configure, they should edit the following:

- Configuration of OpenShift Container Platform monitoring components lies in a ConfigMap called `cluster-monitoring-config` in the `openshift-monitoring` namespace.
- Configuration of components that monitor user-defined projects lies in a ConfigMap called `user-workload-monitoring-config` in the `openshift-user-workload-monitoring` namespace.

The configuration file itself is always defined under the `config.yaml` key within the ConfigMap's data.

Monitoring a platform such as OpenShift requires a coordination of multiple components that must work well between themselves.
However, users should be able to customize the monitoring stack in such a way that they end up with a resilient and highly available monitoring solution.
Despite this, to avoid users from misconfiguring the monitoring stack of their clusters not all configuration parameters are exposed.

Configuring Cluster Monitoring is optional. If the config does not exist or is empty or malformed, then defaults will be used.

## Index

- [Configuration of OpenShift Container Platform](#configuration-of-openShif-container-platform)
  - [alertmanagerMain](#alertmanagerMain)
  - [enableUserWorkload](#enableuserworkloadmonitoring)
  - [k8sPrometheusAdapter](#k8sprometheusadapter)
  - [kubeStateMetrics](#kubeStateMetrics)
  - [prometheusK8s](#prometheusK8s)
  - [prometheusOperator](#prometheusOperator)
  - [openshiftStateMetrics](#openshiftStateMetrics)
  - [thanosQuerier](#thanosQuerier)
- [Configuration of user workload monitoring](#configuration-of-user-workload-monitoring)
  - [alertmanager](#alertmanager)
  - [prometheus](#prometheus)
  - [prometheusOperator](#prometheusoperator-1)
  - [thanosRuler](#thanosruler)
- [Common data types](#common-data-types)
  - [AdditionalAlertmanagerConfig](#additionalalertmanagerconfig)
    - [TLSConfig](#tlsconfig)
  - [RemoteWriteSpec](#remotewritespec)
    - [BasicAuth](#basicauth)
    - [MetadataConfig](#metadataconfig)
    - [QueueConfig](#queueconfig)
    - [RelabelConfig](#relabelconfig)
    - [SafeTLSConfig](#safetlsconfig)

## Configuration of OpenShift Container Platform

The ConfigMap `cluster-monitoring-config` in the `openshift-monitoring` namespace is the root for all configuration of the core infrastruture monitoring. Here we can configure the following:

```yaml
# Holds configuration related with the main Alertmanager instance.
alertmanagerMain: <struct>
# Boolean flag to enable monitoring for user-defined projects.
# Default: false
enableUserWorkload: <bool>
# Holds configuration related with prometheus-adapter
k8sPrometheusAdapter: <struct>
# Holds configuration related with kube-state-metrics agent
kubeStateMetrics: <struct>
# Holds configuration related with the prometheus component that will be managed by
# the prometheus-operator
prometheusK8s: <struct>
# Holds configuration related with prometheus-operator
prometheusOperator: <struct>
# Holds configuration related with openshift-state-metrics agent
openshiftStateMetrics: <struct>
# Holds configuration related with the Thanos Querier component
thanosQuerier: <struct>
```

### alertmanagerMain

Holds configuration for all things Alertmanager

```yaml
alertmanagerMain:
  # Boolean flag to enable or disable the main Alertmanager instance under
  # openshift-monitoring
  # default: true
  enabled: <bool>
  # Boolean flag to enable or disable user-defined projects namespaces to be selected
  # for AlertmanagerConfig lookup, by default Alertmanager only looks for configuration
  # in the namespace where it was deployed to. This will only work if the UWM Alertmanager
  # instance is not enabled
  # default: false
  enableUserAlertmanagerConfig: <bool>
  # Log level for Alertmanager to be configured with.
  # Possible values are: error, warn, info, debug.
  # default: info
  logLevel: <string>
  # Define which Nodes the Pods are scheduled on.
  nodeSelector: v1.NodeSelector
  # Define resources requests and limits for single Pods.
  resources: v1.ResourceRequirements
  # Defines the Pods tolerations.
  tolerations: v1.Toleration
  # Allows configuring persistent storage for the Alertmanager Pods
  # it's possible to configure storageClass and size of volume.
  volumeClaimTemplate: v1.PersistentVolumeClaim
```

Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    alertmanagerMain:
      enabled: true
      enableUserAlertmanagerConfig: true
      logLevel: "debug"
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
      - operator: Exists
      resources:
        requests:
          cpu: 5m
          memory: 30Mi
      volumeClaimTemplate:
        spec:
          resources:
            requests:
              storage: 15Gi
```

### enableUserWorkloadMonitoring

Enables (when `true`) or disables (default) monitoring for user-defined projects.

When enabled CMO will create a new namespace called openshift-user-workload-monitoring to which it will deploy the following components:

- prometheus-operator
- prometheus
- thanos-ruler

These components will be responsible for monitoring all namespaces not monitored by the OpenShift Container Platform monitoring stack.

```yaml
# default: false
enableUserWorkload: <bool>
```

Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    enableUserWorkload: true
```

### k8sPrometheusAdapter

Holds configuration for all things Prometheus adapter.

```yaml
k8sPrometheusAdapter:
  # Audit configuration to be used by the prometheus adapter instance,
  # possible profile values are: "metadata, request, requestresponse, none".
  # default: metadata
  audit: <struct>
  # Define which Nodes the Pods are scheduled on.
  nodeSelector: v1.NodeSelector
  # Defines the Pods tolerations.
  tolerations: v1.Toleration
```

For more in-depth documentation on how to configure audit please refer to [OpenShift Docs setting audit log levels for prometheus adapter](https://docs.openshift.com/container-platform/latest/monitoring/configuring-the-monitoring-stack.html#setting-audit-log-levels-for-the-prometheus-adapter_configuring-the-monitoring-stack).

Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    k8sPrometheusAdapter:
      audit:
        profile: request
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
      - operator: Exists
```

### kubeStateMetrics

Holds configuration for all things kube-state-metrics agent.

```yaml
kubeStateMetrics:
  # Define which Nodes the Pods are scheduled on.
  nodeSelector: v1.NodeSelector
  # Defines the Pods tolerations.
  tolerations: v1.Toleration
```

Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    kubeStateMetrics:
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
      - operator: Exists
```

### prometheusK8s

Holds configuration related to the Prometheus component.

```yaml
prometheusK8s:
  # Holds configuration about how the Prometheus component should communicate with aditional
  # Alertmanager instances, from configuring the URL scheme, timeout to authentication
  # method and others.
  # default: nil
  additionalAlertmanagerConfigs: AdditionalAlertmanagerConfig
  # Enforces body size limit of Prometheus scrapes, if a scrape is bigger than
  # the limit it will fail.
  # 3 kinds of values are accepted:
  #  1. empty value: no limit
  #  2. a value in Prometheus size format, e.g. "64MB"
  #  3. string "automatic", which means the limit will be automatically calculated based on
  #     cluster capacity.
  # default: 64MB
  enforcedBodySizeLimit: <string>
  # The labels to add to any time series or alerts when communicating with external systems
  # (federation, remote storage, Alertmanager).
  # default: nil
  externalLabels: <map[string]string>
  # Log level for Prometheus to be configured with.
  # Possible values are: error, warn, info, debug.
  # default: info
  logLevel: <string>
  # Define which Nodes the Pods are scheduled on.
  nodeSelector: v1.NodeSelector
  # QueryLogFile specifies the file to which PromQL queries are logged. Suports both just a filename
  # in which case they will be saved to an emptyDir volume at /var/log/prometheus, if a full path is
  # given an emptyDir volume will be mounted at that location. Relative paths not supported,
  # also not supported writing to linux std streams.
  # default: ""
  queryLogFile: <string>
  # Holds the remote write configuration, everything from url, authorization to relabeling
  remoteWrite: RemoteWriteSpec
  # Define resources requests and limits for single Pods.
  resources: v1.ResourceRequirements
  # Time duration Prometheus shall retain data for. RetentionSize must match the regular expression
  # [0-9]+(ms|s|m|h|d|w|y) (milliseconds seconds minutes hours days weeks years).
  # default: 15d
  retention: <string>
  # Maximum amount of disk space used by blocks + WAL.
  # default: nil
  retentionSize: <string>
  # Defines the Pods tolerations.
  tolerations: v1.Toleration
  # Allows configuring persistent storage for the Prometheus Pods
  # it's possible to configure storageClass and size of volume.
  volumeClaimTemplate: v1.PersistentVolumeClaim
```

Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    prometheusK8s:
      additionalAlertmanagerConfigs:
      - apiVersion: v2
        scheme: https
        bearerToken:
          name: alertmanager1-bearer-token
          key: token
        staticConfigs:
        - alertmanager1-remote.com
      enforcedBodySizeLimit: 64MB
      externalLabels:
        datacenter: eu-west
      logLevel: debug
      nodeSelector:
        kubernetes.io/os: linux
      queryLogFile: /tmp/test.log
      retention: 10h
      resources:
        requests:
          cpu: 100m
          memory: 100Mi
      remoteWrite:
      - url: "https://test.remotewrite.com/api/write"
      retention: 24h
      retentionSize: 15GB
      tolerations:
      - operator: "Exists"
      volumeClaimTemplate:
        spec:
          resources:
            requests:
              storage: 15Gi
```

### prometheusOperator

Holds configuration related to prometheus-operator.

```yaml
prometheusOperator:
  # Log level for Prometheus Operator to be configured with.
  # Possible values are: error, warn, info, debug.
  # default: info
  logLevel: <string>
  # Define which Nodes the Pods are scheduled on.
  nodeSelector: v1.NodeSelector
  # Defines the Pods tolerations.
  tolerations: v1.Toleration
```

Example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
   prometheusOperator:
      logLevel: debug
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
      - operator: Exists
```

### openshiftStateMetrics

Holds configuration for all things openshift-state-metrics agent.

```yaml
openshiftStateMetrics:
  # Define which Nodes the Pods are scheduled on.
  nodeSelector: v1.NodeSelector
  # Defines the Pods tolerations.
  tolerations: v1.Toleration
```

Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    openshiftStateMetrics:
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
      - operator: Exists
```


### thanosQuerier

Holds configuration related to the Thanos Querier component.

```yaml
thanosQuerier:
  # Boolean flag to enable or disable request logging
  # default: false
  enableRequestLogging: <bool>
  # Log level for Thanos Querier to be configured with.
  # Possible values are: error, warn, info, debug.
  # default: info
  logLevel: <string>
  # Define which Nodes the Pods are scheduled on.
  nodeSelector: v1.NodeSelector
  # Define resources requests and limits for single Pods.
  resources: v1.ResourceRequirements
  # Defines the Pods tolerations.
  tolerations: v1.Toleration
```

Example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    thanosQuerier:
      enableRequestLogging: true
      logLevel: debug
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
      - operator: Exists
      resources:
        requests:
          cpu: 100m
          memory: 100Mi
```

## Configuration of user workload monitoring

The ConfigMap `user-workload-monitoring-config` in the `openshift-user-workload-monitoring` namespace is the root for all configuration of components that monitor user-defined projects. Here we can configure the following:

```yaml
# Holds configuration for the Alertmanager component for user-defined projects.
alertmanager: <struct>
# Holds configuration related to the Prometheus component that will be managed by
# the prometheus-operator from configuring nodeSelector to RemoteWrite
prometheus: <struct>
# Holds configuration related with prometheus-operator, nodeSelector, tolerations
# and logLevel
prometheusOperator: <struct>
# Holds configuration for the Thanos Ruler component
thanosRuler: <struct>
```

### alertmanager

Holds configuration for all things Alertmanager regarding user-defined projects.

```yaml
alertmanager:
  # Boolean flag to enable or disable a dedicated instance of Alertmanager
  # for user-defined projects
  # default: false
  enabled: <bool>
  # Boolean flag to enable or disable user-defined projects namespaces to be selected
  # for AlertmanagerConfig lookup, by default Alertmanager only looks for configuration
  # in the namespace where it was deployed to
  # default: false
  enableAlertmanagerConfig: <bool>
  # Log level for Alertmanager to be configured with.
  # Possible values are: error, warn, info, debug.
  # default: info
  logLevel: <string>
  # Define which Nodes the Pods are scheduled on.
  nodeSelector: v1.NodeSelector
  # Define resources requests and limits for single Pods.
  resources: v1.ResourceRequirements
  # Defines the Pods tolerations.
  tolerations: v1.Toleration
  # Allows configuring persistent storage for the Alertmanager Pods
  # it's possible to configure storageClass and size of volume.
  volumeClaimTemplate: v1.PersistentVolumeClaim
```

Example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: user-workload-monitoring-config
  namespace: openshift-user-workload-monitoring
data:
  config.yaml: |
    alertmanager:
      enabled: true
      enableAlertmanagerConfig: true
      logLevel: "debug"
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
      - operator: Exists
      resources:
        requests:
          cpu: 5m
          memory: 30Mi
      volumeClaimTemplate:
        spec:
          resources:
            requests:
              storage: 15Gi
```

### prometheus

Holds configuration related to the Prometheus component that will monitor user-defined projects.

```yaml
prometheus:
  # Holds configuration about how the Prometheus component should communicate with aditional
  # Alertmanager instances, from configuring the URL scheme, timeout to authentication
  # method and others.
  # default: nil
  additionalAlertmanagerConfigs: AdditionalAlertmanagerConfig
  # Per-scrape limit on the number of labels accepted for a sample. If more than this
  # number of labels are present post metric-relabeling, the entire scrape will be treated as
  # failed. 0 means no limit.
  # default: 0
  enforcedLabelLimit: <integer>
  # Per-scrape limit on the length of labels name that will be accepted for a sample. If a label name
  # is longer than this number post metric-relabeling, the entire scrape will be treated as
  # failed. 0 means no limit.
  # default: 0
  enforcedLabelNameLengthLimit: <integer>
  # Per-scrape limit on the length of labels value that will be accepted for a sample. If a label
  # value is longer than this number post metric-relabeling, the entire scrape will be treated
  # as failed. 0 means no limit.
  # default: 0
  enforcedLabelValueLengthLimit: <integer>
  # EnforcedSampleLimit defines a global limit on the number of scraped samples that will be accepted.
  # This overrides any SampleLimit set per ServiceMonitor or/and PodMonitor. It is meant to be
  # used by admins to enforce the SampleLimit to keep the overall number of samples/series under the
  # desired limit. Note that if SampleLimit is lower that value will be taken instead.
  # default: 0
  enforcedSampleLimit: <integer>
  # EnforcedTargetLimit defines a global limit on the number of scraped targets. This overrides
  # any TargetLimit set per ServiceMonitor or/and PodMonitor. It is meant to be used by admins to
  # enforce the TargetLimit to keep the overall number of targets under the desired limit. Note
  # that if TargetLimit is lower, that value will be taken instead, except if either value is
  # zero, in which case the non-zero value will be used. If both values are zero, no limit is
  # enforced.
  # default: 0
  enforcedTargetLimit: <integer>
  # The labels to add to any time series or alerts when communicating with external systems
  # (federation, remote storage, Alertmanager).
  externalLabels: <map[string]string>
  # Log level for Prometheus to be configured with.
  # Possible values are: error, warn, info, debug.
  # default: info
  logLevel: <string>
  # Define which Nodes the Pods are scheduled on.
  nodeSelector: v1.NodeSelector
  # QueryLogFile specifies the file to which PromQL queries are logged. Supports both just a filename
  # in which case they will be saved to an emptyDir volume at /var/log/prometheus, if a full path is
  # given an emptyDir volume will be mounted at that location. Relative paths not supported
  # default: ""
  queryLogFile: <string>
  # Holds the remote write configuration, everything from url, authorization to relabeling
  remoteWrite: RemoteWriteSpec
  # Define resources requests and limits for single Pods.
  resources: v1.ResourceRequirements
  # Time duration Prometheus shall retain data for. Default is '24h' if retentionSize is not set,
  # and must match the regular expression [0-9]+(ms|s|m|h|d|w|y) (milliseconds seconds minutes
  # hours days weeks years).
  retention: <string>
  # Maximum amount of disk space used by blocks.
  retentionSize: <string>
  # Defines the Pods tolerations.
  tolerations: v1.Toleration
  # Allows configuring persistent storage for the Prometheus Pods
  # it's possible to configure storageClass and size of volume.
  volumeClaimTemplate: v1.PersistentVolumeClaim
```

Example

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: user-workload-monitoring-config
  namespace: openshift-user-workload-monitoring
data:
  config.yaml: |
    prometheus:
      additionalAlertmanagerConfigs:
      - apiVersion: v2
        scheme: https
        bearerToken:
          name: alertmanager1-bearer-token
          key: token
        staticConfigs:
        - alertmanager1-remote.com
      enforcedLabelLimit: 500
      enforcedLabelNameLengthLimit: 50
      enforcedLabelValueLengthLimit: 600
      enforcedSampleLimit: 100
      enforcedTargetLimit: 10
      externalLabels:
        datacenter: eu-west
      logLevel: debug
      nodeSelector:
        kubernetes.io/os: linux
      queryLogFile: /tmp/test.log
      retention: 10h
      resources:
        requests:
          cpu: 100m
          memory: 100Mi
      remoteWrite:
      - url: "https://test.remotewrite.com/api/write"
      retention: 24h
      retentionSize: 15GB
      tolerations:
     - operator: "Exists"
      volumeClaimTemplate:
        spec:
          resources:
            requests:
              storage: 15Gi
```

### prometheusOperator

This section of the configuration is exactly equal to the one described in the [Prometheus operator section](#prometheusoperator) of Configuration of OpenShift Container Platform.

### thanosRuler

Holds configuration for all things Thanos ruler regarding user-defined projects.

```yaml
thanosRuler:
  # Holds configuration about how the Thanos ruler component should communicate with aditional
  # Alertmanager instances, from configuring the URL scheme, timeout to authentication
  # method and others.
  # default: nil
  additionalAlertmanagerConfigs: AdditionalAlertmanagerConfig
  # Log level for Alertmanager to be configured with.
  # Possible values are: error, warn, info, debug.
  # default: nil
  logLevel: <string>
  # Define which Nodes the Pods are scheduled on.
  nodeSelector: v1.NodeSelector
  # Define resources requests and limits for single Pods.
  resources: v1.ResourceRequirements
  # Time duration Prometheus shall retain data for. Default is '24h' if retentionSize is not set,
  # and must match the regular expression [0-9]+(ms|s|m|h|d|w|y) (milliseconds seconds minutes
  # hours days weeks years).
  # default: 15d
  retention: <string>
  # Defines the Pods tolerations.
  tolerations: v1.Toleration
  # Allows configuring persistent storage for the Alertmanager Pods
  # it's possible to configure storageClass and size of volume.
  volumeClaimTemplate: v1.PersistentVolumeClaim
```

Example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: user-workload-monitoring-config
  namespace: openshift-user-workload-monitoring
data:
  config.yaml: |
    thanosRuler:
      additionalAlertmanagerConfigs:
      - apiVersion: v2
        scheme: https
        bearerToken:
          name: alertmanager1-bearer-token
          key: token
        staticConfigs:
        - alertmanager1-remote.com
      logLevel: debug
      nodeSelector:
        kubernetes.io/os: linux
      resources:
        requests:
          cpu: 100m
          memory: 100Mi
      retention: 24h
      tolerations:
      - operator: "Exists"
      volumeClaimTemplate:
        spec:
          resources:
            requests:
              storage: 15Gi
```

## Common data types

This section contains a set of data types which common to both configurations.

### AdditionalAlertmanagerConfig

Holds configuration about how component should communicate with aditional Alertmanager instances, from configuring the URL scheme, timeout to authentication method and others.

```yaml
additionalAlertmanagerConfigs:
  # The api version of Alertmanager.
  apiVersion: <string>
  # Bearer token to use when authenticating to Alertmanager.
  bearerToken: v1.SecretKeySelector
  # Path prefix to add in front of the push endpoint path.
  pathPrefix: <string>
  # The URL scheme to use when talking to Alertmanagers.
  scheme: <string>
  # List of statically configured Alertmanagers.
  staticConfigs: <[]string>
  # The timeout used when sending alerts.
  timeout: <string>
  # TLS Config to use for alertmanager connection.
  tlsConfig: TLSConfig
```

#### TLSConfig

Holds configuration for TLS configuration

```yaml
tlsConfig:
  # The CA cert in the Prometheus container to use for the targets.
  ca: v1.SecretKeySelector
  # The client cert in the Prometheus container to use for the targets.
  cert: v1.SecretKeySelector
  # Disable target certificate validation.
  insecureSkipVerify: <bool>
  # The client key in the Prometheus container to use for the targets.
  key: v1.SecretKeySelector
  # Used to verify the hostname for the targets.
  serverName: <string>
```

### RemoteWriteSpec

Holds configuration for remote write

```yaml
remoteWrite:
  # The URL of the endpoint to send samples to.
  url: <string>
  # The name of the remote write queue, must be unique if specified. The
  # name is used in metrics and logging in order to differentiate queues.
  # Only valid in Prometheus versions 2.15.0 and newer.
  name: <string>
  # Timeout for requests to the remote write endpoint.
  remoteTimeout: <string>
  # Custom HTTP headers to be sent along with each remote write request.
  # Be aware that headers that are set by Prometheus itself can't be overwritten.
  # Only valid in Prometheus versions 2.25.0 and newer.
  headers: <map[string]string>
  # The list of remote write relabel configurations.
  writeRelabelConfigs: RelabelConfig
  # BasicAuth for the URL.
  basicAuth: BasicAuth
  # Bearer token for remote write.
  bearerTokenFile: <string>
  # TLS Config to use for remote write.
  tlsConfig: SafeTLSConfig
  # Optional ProxyURL
  proxyUrl: <string>
  # QueueConfig allows tuning of the remote write queue parameters.
  queueConfig: QueueConfig
  # MetadataConfig configures the sending of series metadata to remote storage.
  metadataConfig: MetadataConfig
```


#### BasicAuth

```yaml
basicAuth:
  # The secret in the service monitor namespace that contains the username
  # for authentication.
  username: v1.SecretKeySelector
  # The secret in the service monitor namespace that contains the password
  # for authentication.
  password: v1.SecretKeySelector
```

#### MetadataConfig

```yaml
metadataConfig:
  # Whether metric metadata is sent to remote storage or not.
  send: <bool>
  # How frequently metric metadata is sent to remote storage.
  sendInterval: <string>
```

#### QueueConfig

```yaml
queueConfig:
  # BatchSendDeadline is the maximum time a sample will wait in buffer.
  batchSendDeadline: <string>
  # Capacity is the number of samples to buffer per shard before we start dropping them.
  capacity: <integer>
  # MaxBackoff is the maximum retry delay.
  maxBackoff: <string>
  # MaxRetries is the maximum number of times to retry a batch on recoverable errors.
  maxRetries: <integer>
  # MaxShards is the maximum number of shards, i.e. amount of concurrency.
  maxShards: <integer>
  # MaxSamplesPerSend is the maximum number of samples per send.
  maxSamplesPerSend: <integer>
  # MinBackoff is the initial retry delay. Gets doubled for every retry.
  minBackoff: <string>
  # MinShards is the minimum number of shards, i.e. amount of concurrency.
  minShards: <integer>
  # Retry upon receiving a 429 status code from the remote-write storage.
  # This is experimental feature and might change in the future.
  retryOnRateLimit: <bool>
```

#### RelabelConfig

Holds configuration for relabeling in remote write

```yaml
relabelConfig:
  # Action to perform based on regex matching. Default is 'replace'
  action: <string>
  # Modulus to take of the hash of the source label values.
  modulus: <integer>
  # Regular expression against which the extracted value is matched. Default is '(.*)'
  regex: <string>
  # Replacement value against which a regex replace is performed if the
  # regular expression matches. Regex capture groups are available. Default is '$1'
  replacement: <string>
  # Separator placed between concatenated source label values. default is ';'.
  separator: <string>
  #The source labels select values from existing labels. Their content is concatenated
  #using the configured separator and matched against the configured regular expression
  #for the replace, keep, and drop actions.
  sourceLabels: <[]string>
  # Label to which the resulting value is written in a replace action.
  # It is mandatory for replace actions. Regex capture groups are available.
  targetLabel: <string>
```

#### SafeTLSConfig

Holds configuration for TLS configuration

```yaml
tlsConfig:
  # Struct containing the CA cert to use for the targets.
  ca: SecretOrConfigMap
  # Struct containing the client cert file for the targets.
  cert: SecretOrConfigMap
  # Disable target certificate validation.
  insecureSkipVerify: <bool>
  # Secret containing the client key file for the targets.
  keySecret: v1.SecretKeySelector
  # Used to verify the hostname for the targets.
  serverName: <string>
```