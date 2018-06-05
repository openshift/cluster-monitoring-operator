## 0.0.5 / 2018-06-05

* [ENHANCEMENT] Update Prometheus Operator to v0.20.0

## 0.0.4 / 2018-05-25

* Set GOOS=linux to build binaries for Linux by default
* Add a default namespace selector for service monitors
* Remove securityContext by default

## 0.0.3 / 2018-05-23

* Remove resource limit defaults
* Improve SCC defaults for compatibility
* Fix config-reloader version compatibility issue

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
