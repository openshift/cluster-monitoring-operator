module github.com/openshift/cluster-monitoring-operator

go 1.16

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/Jeffail/gabs/v2 v2.6.1
	github.com/ghodss/yaml v1.0.0
	github.com/go-logr/logr v1.2.2 // indirect
	github.com/google/go-cmp v0.5.7 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/imdario/mergo v0.3.12
	github.com/openshift/api v0.0.0-20211217221424-8779abfbd571
	github.com/openshift/client-go v0.0.0-20220120123103-cf1275baf30c
	github.com/openshift/library-go v0.0.0-20211220195323-eca2c467c492
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator v0.53.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.53.1
	github.com/prometheus-operator/prometheus-operator/pkg/client v0.53.1
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/common v0.32.1
	github.com/prometheus/prometheus v1.8.2-0.20211214150951-52c693a63be1 // v1.8.2 is misleading as Prometheus does not have v2 module. This is pointing to v2.32.1, the same as in prometheus-operator v0.53.1
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
	golang.org/x/net v0.0.0-20220114011407-0dd24b26b47d // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.23.2
	k8s.io/apiextensions-apiserver v0.23.1
	k8s.io/apimachinery v0.23.2
	k8s.io/apiserver v0.23.1
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog/v2 v2.40.1
	k8s.io/kube-aggregator v0.23.1
	k8s.io/kubectl v0.23.1
	k8s.io/metrics v0.23.1
	sigs.k8s.io/json v0.0.0-20211208200746-9f7c6b3444d2 // indirect
)

replace k8s.io/client-go => k8s.io/client-go v0.23.1

replace github.com/openshift/api => github.com/bison/openshift-api v0.0.0-20220120114256-c63e9ac3cf9f

replace github.com/openshift/client-go => github.com/bison/openshift-client-go v0.0.0-20220126160613-aeb9712cd2b8
