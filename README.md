# Cluster Monitoring Operator

The Cluster Monitoring Operator manages and updates the Prometheus-based cluster monitoring stack deployed on top of OpenShift.

It contains the following components:

* [Prometheus Operator](https://github.com/coreos/prometheus-operator)
* [Prometheus](https://github.com/prometheus/prometheus)
* [Alertmanager](https://github.com/prometheus/alertmanager) cluster for cluster and application level alerting
* [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics)
* [node_exporter](https://github.com/prometheus/node_exporter)
* [prometheus-adapter](https://github.com/DirectXMan12/k8s-prometheus-adapter)

The deployed Prometheus instance (`prometheus-k8s`) is responsible for monitoring and alerting on cluster and OpenShift components; it should not be extended to monitor user applications. Users interested in leveraging Prometheus for application monitoring on OpenShift should consider enabling [User Workload Monitoring](https://docs.openshift.com/container-platform/4.10/monitoring/enabling-monitoring-for-user-defined-projects.html) to easily setup new Prometheus instances to monitor and alert on their applications.

Alertmanager is a cluster-global component for handling alerts generated by all Prometheus instances deployed in that cluster.

## Adding new metrics to be sent via telemetry

To add new metrics to be sent via telemetry, simply add a selector that matches the time-series to be sent in [manifests/0000_50_cluster-monitoring-operator_04-config.yaml](manifests/0000_50_cluster-monitoring-operator_04-config.yaml).

Documentation on the data sent can be found in the [data collection documentation](Documentation/data-collection.md).

## Contributing
Please refer to the [CONTRIBUTING.md](./CONTRIBUTING.md) document for information.

## Release

Release checklist is available when creating new ["Release Checklist" issue](https://github.com/openshift/cluster-monitoring-operator/issues/new?template=release.md).
