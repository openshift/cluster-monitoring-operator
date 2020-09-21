module github.com/openshift/cluster-monitoring-operator

go 1.14

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/coreos/prometheus-operator v0.40.0
	github.com/ghodss/yaml v1.0.0
	github.com/gogo/protobuf v1.3.1
	github.com/openshift/api v0.0.0-20200623075207-eb651a5bb0ad
	github.com/openshift/client-go v0.0.0-20200623090625-83993cebb5ae
	github.com/openshift/library-go v0.0.0-20200421122923-c1de486c7d47
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/prometheus v1.8.2-0.20200609102542-5d7e3e970602 // v1.8.2 is misleading as Prometheus does not have v2 module. This is pointing to v2.19.0, the same as in promehteus-    operator v0.40.0
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a
	golang.org/x/sys v0.0.0-20200722175500-76b94024e4b6 // indirect
	k8s.io/api v0.19.2
	k8s.io/apiextensions-apiserver v0.18.3
	k8s.io/apimachinery v0.19.2
	k8s.io/apiserver v0.18.3
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
	k8s.io/kube-aggregator v0.18.3
	k8s.io/metrics v0.18.4
)

replace (
	k8s.io/api => k8s.io/api v0.19.2
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.2
	k8s.io/client-go => k8s.io/client-go v0.19.2
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269
)
