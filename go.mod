module github.com/openshift/cluster-monitoring-operator

go 1.12

require (
	github.com/Jeffail/gabs v1.1.1
	github.com/ant31/crd-validation v0.0.0-20180801212718-38f6a293f140 // indirect
	github.com/coreos/prometheus-operator v0.0.0-00010101000000-000000000000
	github.com/emicklei/go-restful v2.8.0+incompatible // indirect
	github.com/imdario/mergo v0.3.6 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mitchellh/hashstructure v1.0.0 // indirect
	github.com/openshift/api v3.9.1-0.20190809235250-af7bae2945fe+incompatible
	github.com/openshift/client-go v0.0.0-20190412095722-0255926f5393
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v1.1.0
	golang.org/x/net v0.0.0-20190813141303-74dc4d7220e7 // indirect
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	k8s.io/api v0.0.0-20190813020757-36bff7324fb7
	k8s.io/apiextensions-apiserver v0.0.0-20190620085554-14e95df34f1f
	k8s.io/apimachinery v0.0.0-20190809020650-423f5d784010
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog v0.4.0
	k8s.io/kube-aggregator v0.0.0-20181004124448-331c5a816775
	k8s.io/metrics v0.0.0-20181004124939-8b490d15bb19
)

replace (
	github.com/coreos/prometheus-operator => github.com/coreos/prometheus-operator v0.33.0
	github.com/prometheus/prometheus => github.com/prometheus/prometheus v1.8.2-0.20190819201610-48b2c9c8eae2 // v1.8.2 is misleading as Prometheus does not have v2 module. This is pointing to one commit after 2.12.0.
	k8s.io/client-go => k8s.io/client-go v0.0.0-20190620085101-78d2af792bab
)
