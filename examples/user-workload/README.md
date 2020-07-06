# Enable user workload monitoring

Admin has to first enable user workload monitoring via the main cluster-monitoring `ConfigMap`:

```
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    enableUserWorkload: true
```

`ConfigMap` called `user-workload-monitoring-config` in the `openshift-user-workload-monitoring` namespace can then be used to configure the user workload monitoring stack. A user who's granted the `user-workload-monitoring-config-edit` `Role` in the `openshift-user-workload-monitoring` namespace gets full permissions on this `ConfigMap`.

Configuration example is located in this directory, with the following supported configuration fields:
```
prometheusOperator:
logLevel     string
nodeSelector map[string]string
tolerations  []v1.Toleration

thanosRuler:
logLevel     string
nodeSelector map[string]string
tolerations  []v1.Toleration
resources           *v1.ResourceRequirements
volumeClaimTemplate *v1.PersistentVolumeClaim

prometheus:
logLevel     string
nodeSelector map[string]string
tolerations  []v1.Toleration
retention string
resources           *v1.ResourceRequirements
externalLabels      map[string]string
volumeClaimTemplate *v1.PersistentVolumeClaim
hostport            string
remoteWrite         []monv1.RemoteWriteSpec
```
