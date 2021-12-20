module github.com/openshift/cluster-monitoring-operator

go 1.16

require (
	github.com/Jeffail/gabs v1.4.0
	github.com/Jeffail/gabs/v2 v2.6.1
	github.com/ghodss/yaml v1.0.0
	github.com/imdario/mergo v0.3.11
	github.com/openshift/api v0.0.0-20211217221424-8779abfbd571
	github.com/openshift/client-go v0.0.0-20211209144617-7385dd6338e3
	github.com/openshift/library-go v0.0.0-20211220195323-eca2c467c492
	github.com/pkg/errors v0.9.1
	github.com/prometheus-operator/prometheus-operator v0.52.1
	github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring v0.52.1
	github.com/prometheus-operator/prometheus-operator/pkg/client v0.52.1
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/prometheus v1.8.2-0.20211005150130-f29caccc4255 // v1.8.2 is misleading as Prometheus does not have v2 module. This is pointing to v2.26.1, the same as in prometheus-operator v0.52.1
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.23.0
	k8s.io/apiextensions-apiserver v0.23.0
	k8s.io/apimachinery v0.23.0
	k8s.io/apiserver v0.23.0
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/klog/v2 v2.30.0
	k8s.io/kube-aggregator v0.23.0
	k8s.io/kubectl v0.23.0
	k8s.io/metrics v0.23.0
)

replace k8s.io/client-go => k8s.io/client-go v0.23.0
