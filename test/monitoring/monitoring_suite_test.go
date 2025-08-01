package monitoring_test

import (
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMonitoring(t *testing.T) {
	RegisterFailHandler(Fail)
	suiteConfig, reporterConfig := GinkgoConfiguration()
	// Hardcoded until we find an easy way to pass it via "go test"
	suiteConfig.Timeout = 3 * time.Hour
	reporterConfig.NoColor = true
	RunSpecs(t, "Monitoring Suite", suiteConfig, reporterConfig)
}
