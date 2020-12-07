module github.com/openshift/cluster-monitoring-operator

go 1.14

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/ghodss/yaml v1.0.0
	github.com/gogo/protobuf v1.3.1
	github.com/imdario/mergo v0.3.7
	github.com/openshift/api v0.0.0-20200722170803-0ba2c3658da6
	github.com/openshift/client-go v0.0.0-20200722173614-5a1b0aaeff15
	github.com/openshift/library-go v0.0.0-20200722204747-e3f2c82ff290
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator v0.44.0
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.44.0
	github.com/prometheus/client_golang v1.8.0
	github.com/prometheus/prometheus v1.8.2-0.20201015110737-0a7fdd3b7696 // v1.8.2 is misleading as Prometheus does not have v2 module. This is pointing to v2.22.0, the same as in prometheus-operator v0.44.0
	golang.org/x/sync v0.0.0-20201008141435-b3e1573b7520
	k8s.io/api v0.19.4
	k8s.io/apiextensions-apiserver v0.19.4
	k8s.io/apimachinery v0.19.4
	k8s.io/apiserver v0.19.4
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog/v2 v2.3.0
	k8s.io/kube-aggregator v0.19.4
	k8s.io/metrics v0.19.4
)

replace (
	k8s.io/api => k8s.io/api v0.19.4
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.4
	k8s.io/client-go => k8s.io/client-go v0.19.4
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269
)
