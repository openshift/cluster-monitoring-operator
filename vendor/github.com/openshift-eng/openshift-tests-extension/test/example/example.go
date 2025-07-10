package example

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	g "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"
)

var flags struct {
	beforeAllCount  int
	beforeEachCount int
}

var _ = Describe("[sig-testing] openshift-tests-extension ordered", Ordered, func() {
	BeforeAll(func() {
		flags.beforeAllCount++
	})

	It("should run beforeAll once", func() {
		Expect(flags.beforeAllCount).To(Equal(1))
	})
})

var _ = Describe("[sig-testing] openshift-tests-extension setup", func() {
	BeforeEach(func() {
		flags.beforeEachCount++
	})

	It("should support beforeEach", func() {
		Expect(flags.beforeEachCount).To(BeNumerically(">", 0))
	})
})

var _ = Describe("[sig-testing] openshift-tests-extension", func() {
	It("should support passing tests", func() {
		Expect(true).To(BeTrue())
	})

	It("should support failing tests", func() {
		Expect(1).To(Equal(2))
	})

	It("should support panicking tests", func() {
		panic("oh no")
	})

	It("should support slow tests", g.Slow(), func() {
		time.Sleep(15 * time.Second)
		Expect(true).To(BeTrue())
	})

	It("should support test-skips via environment flags", func() {
		Expect(true).To(BeTrue()) //This doesn't need to do anything special, just exist
	})
})
