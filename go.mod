module github.com/openshift/cluster-monitoring-operator

go 1.14

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/coreos/prometheus-operator v0.40.0
	github.com/ghodss/yaml v1.0.0
	github.com/gogo/protobuf v1.3.1
	github.com/imdario/mergo v0.3.7
	github.com/jteeuwen/go-bindata v3.0.8-0.20151023091102-a0ff2567cfb7+incompatible // indirect
	github.com/openshift/api v0.0.0-20200722170803-0ba2c3658da6
	github.com/openshift/client-go v0.0.0-20200722173614-5a1b0aaeff15
	github.com/openshift/library-go v0.0.0-20200722204747-e3f2c82ff290
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/prometheus v1.8.2-0.20200609102542-5d7e3e970602 // v1.8.2 is misleading as Prometheus does not have v2 module. This is pointing to v2.19.0, the same as in promehteus-    operator v0.40.0
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a
	golang.org/x/sys v0.0.0-20200722175500-76b94024e4b6 // indirect
	k8s.io/api v0.19.2
	k8s.io/apiextensions-apiserver v0.19.0-rc.2
	k8s.io/apimachinery v0.19.2
	k8s.io/apiserver v0.19.2
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0 // indirect
	k8s.io/klog/v2 v2.2.0
	k8s.io/kube-aggregator v0.19.2
	k8s.io/metrics v0.18.4
)

replace (
	k8s.io/api => k8s.io/api v0.19.2
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.2
	k8s.io/client-go => k8s.io/client-go v0.19.2
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269
)
