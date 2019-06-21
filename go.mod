module github.com/openshift/cluster-monitoring-operator

go 1.12

replace (
	github.com/coreos/prometheus-operator => github.com/coreos/prometheus-operator v0.31.1-0.20190621140400-7b51b28a4853
	k8s.io/api => k8s.io/api v0.0.0-20190606204050-af9c91bd2759
	k8s.io/client-go => k8s.io/client-go v11.0.1-0.20190606204521-b8faab9c5193+incompatible
)

require (
	github.com/Jeffail/gabs v1.1.1
	github.com/ant31/crd-validation v0.0.0-20180801212718-38f6a293f140 // indirect
	github.com/coreos/prometheus-operator v0.0.0-00010101000000-000000000000
	github.com/emicklei/go-restful v2.8.0+incompatible // indirect
	github.com/go-openapi/spec v0.18.0 // indirect
	github.com/go-openapi/swag v0.18.0 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/groupcache v0.0.0-20190129154638-5b532d6fd5ef // indirect
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/imdario/mergo v0.3.6 // indirect
	github.com/json-iterator/go v1.1.5 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mitchellh/hashstructure v1.0.0 // indirect
	github.com/openshift/api v0.0.0-20190424103643-f9c19755eb3e
	github.com/openshift/client-go v0.0.0-20190412095722-0255926f5393
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.3-0.20190127221311-3c4408c8b829
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	golang.org/x/time v0.0.0-20181108054448-85acf8d2951c // indirect
	k8s.io/api v0.0.0-20190620084959-7cf5895f2711
	k8s.io/apiextensions-apiserver v0.0.0-20190620085554-14e95df34f1f
	k8s.io/apimachinery v0.0.0-20190612205821-1799e75a0719
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog v0.3.2 // indirect
	k8s.io/kube-aggregator v0.0.0-20181004124448-331c5a816775
	k8s.io/metrics v0.0.0-20181004124939-8b490d15bb19
	k8s.io/utils v0.0.0-20190529001817-6999998975a7 // indirect
)
