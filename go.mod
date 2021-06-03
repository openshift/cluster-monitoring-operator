module github.com/openshift/cluster-monitoring-operator

go 1.14

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/ghodss/yaml v1.0.0
	github.com/gogo/protobuf v1.3.2
	github.com/imdario/mergo v0.3.7
	github.com/openshift/api v0.0.0-20210225162315-bae60f47eed7
	github.com/openshift/client-go v0.0.0-20201214125552-e615e336eb49
	github.com/openshift/library-go v0.0.0-20210113192829-cfbb3f4c80c2
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator v0.47.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.48.1
	github.com/prometheus-operator/prometheus-operator/pkg/client v0.47.1
	github.com/prometheus/client_golang v1.10.0
	github.com/prometheus/prometheus v1.8.2-0.20210215121130-6f488061dfb4 // v1.8.2 is misleading as Prometheus does not have v2 module. This is pointing to v2.26.0, the same as in prometheus-operator v0.47.1
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	k8s.io/api v0.21.0
	k8s.io/apiextensions-apiserver v0.21.0
	k8s.io/apimachinery v0.21.0
	k8s.io/apiserver v0.21.0
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog/v2 v2.8.0
	k8s.io/kube-aggregator v0.20.0
	k8s.io/metrics v0.19.4
)

replace (
	k8s.io/api => k8s.io/api v0.21.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.21.0
	k8s.io/client-go => k8s.io/client-go v0.21.0
)
