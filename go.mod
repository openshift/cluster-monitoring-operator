module github.com/openshift/cluster-monitoring-operator

go 1.13

require (
	github.com/Jeffail/gabs v1.1.1
	github.com/coreos/prometheus-operator v0.40.0
	github.com/ghodss/yaml v1.0.0
	github.com/gogo/protobuf v1.3.1
	github.com/imdario/mergo v0.3.6 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mitchellh/hashstructure v1.0.0 // indirect
	github.com/openshift/api v0.0.0-20200623075207-eb651a5bb0ad
	github.com/openshift/client-go v0.0.0-20200623090625-83993cebb5ae
	github.com/openshift/library-go v0.0.0-20200120084036-bb27e57e2f2b
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.6.0
	github.com/prometheus/prometheus v1.8.2-0.20200609102542-5d7e3e970602 // v1.8.2 is misleading as Prometheus does not have v2 module. This is pointing to v2.19.0, the same as in promehteus-    operator v0.40.0
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a
	k8s.io/api v0.18.4
	k8s.io/apiextensions-apiserver v0.18.3
	k8s.io/apimachinery v0.18.4
	k8s.io/apiserver v0.18.3
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v1.0.0
	k8s.io/kube-aggregator v0.18.3
	k8s.io/metrics v0.18.4
)

replace (
	k8s.io/api => k8s.io/api v0.18.3
	k8s.io/apimachinery => k8s.io/apimachinery v0.18.3
	k8s.io/client-go => k8s.io/client-go v0.18.3
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20190912054826-cd179ad6a269
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20190228160746-b3a7cee44a30
)
