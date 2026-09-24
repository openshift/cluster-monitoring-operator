module github.com/openshift/cluster-monitoring-operator/hack

go 1.14

require (
	github.com/brancz/gojsontoyaml v0.1.0
	github.com/campoy/embedmd v1.0.0
	github.com/client9/misspell v0.3.4
	github.com/google/go-jsonnet v0.20.0
	github.com/jsonnet-bundler/jsonnet-bundler v0.5.1
	github.com/prometheus/prometheus v0.44.0
)

replace golang.org/x/net => github.com/openshift-sustaining/net v0.35.0-sec.4
