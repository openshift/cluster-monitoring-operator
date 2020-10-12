module github.com/openshift/cluster-monitoring-operator

go 1.13

require (
	github.com/Jeffail/gabs v1.1.1
	github.com/brancz/gojsontoyaml v0.0.0-20191212081931-bf2969bbd742
	github.com/campoy/embedmd v1.0.0
	github.com/coreos/prometheus-operator v0.39.0
	github.com/gogo/protobuf v1.3.1
	github.com/imdario/mergo v0.3.7
	github.com/jsonnet-bundler/jsonnet-bundler v0.3.1
	github.com/jteeuwen/go-bindata v3.0.8-0.20151023091102-a0ff2567cfb7+incompatible
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mitchellh/hashstructure v1.0.0 // indirect
	github.com/openshift/api v0.0.0-20200326160804-ecb9283fe820
	github.com/openshift/client-go v0.0.0-20200326155132-2a6cd50aedd0
	github.com/openshift/library-go v0.0.0-20200421122923-c1de486c7d47
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v1.2.1
	github.com/prometheus/prometheus v2.9.2+incompatible
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	k8s.io/api v0.19.2
	k8s.io/apiextensions-apiserver v0.18.2
	k8s.io/apimachinery v0.19.2
	k8s.io/apiserver v0.18.2
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
	k8s.io/kube-aggregator v0.18.0
	k8s.io/metrics v0.18.6
)

replace (
	github.com/prometheus/prometheus => github.com/prometheus/prometheus v1.8.2-0.20190819201610-48b2c9c8eae2 // v1.8.2 is misleading as Prometheus does not have v2 module. This is pointing to one commit after 2.12.0.
	k8s.io/api => k8s.io/api v0.18.6
	k8s.io/apimachinery => k8s.io/apimachinery v0.18.6
	k8s.io/client-go => k8s.io/client-go v0.18.6
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20190228160746-b3a7cee44a30
)
