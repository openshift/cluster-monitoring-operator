module github.com/openshift/cluster-monitoring-operator

go 1.12

replace (
	github.com/coreos/prometheus-operator => github.com/coreos/prometheus-operator v0.30.1
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
	github.com/golang/groupcache v0.0.0-20190129154638-5b532d6fd5ef // indirect
	github.com/google/gofuzz v0.0.0-20170612174753-24818f796faf // indirect
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/imdario/mergo v0.3.6 // indirect
	github.com/json-iterator/go v1.1.5 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mitchellh/hashstructure v1.0.0 // indirect
	github.com/openshift/api v3.9.1-0.20190809235250-af7bae2945fe+incompatible
	github.com/openshift/client-go v0.0.0-20190412095722-0255926f5393
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/common v0.0.0-20190107103113-2998b132700a // indirect
	github.com/prometheus/procfs v0.0.0-20190104112138-b1a0a9a36d74 // indirect
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	golang.org/x/time v0.0.0-20181108054448-85acf8d2951c // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0-20190313235455-40a48860b5ab
	k8s.io/apiextensions-apiserver v0.0.0-20190315093550-53c4693659ed
	k8s.io/apimachinery v0.0.0-20190313205120-d7deff9243b1
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/klog v0.3.2
	k8s.io/kube-aggregator v0.0.0-20181004124448-331c5a816775
	k8s.io/metrics v0.0.0-20181004124939-8b490d15bb19
	k8s.io/utils v0.0.0-20190529001817-6999998975a7 // indirect
)
