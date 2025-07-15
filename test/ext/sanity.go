package ext

import (
	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
)

var _ = g.Describe("[Jira:Monitoring][sig-instrumentation] sanity test", func() {
	g.It("should always pass [Suite:openshift/cluster-monitoring-operator/conformance/parallel]", func() {
		o.Expect(true).To(o.BeTrue())
	})
})
