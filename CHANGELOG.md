## 0.0.2 / 2018-05-16

* [ENHANCEMENT] Update Prometheus Operator to v0.19.0

## 0.0.1 / 2018-04-16

Initial release.

This release includes a fully automated monitoring stack for OpenShift. It collects metrics from:

* The OpenShift control plane (API, controllers, kubelets)
* The monitoring stack itself (Prometheus, Alertmanager)
* The kube-state-metrics Kubernetes exporter
* The Prometheus node-exporter

It also includes a set of alerting rules inherited from the Tectonic monitoring stack.
