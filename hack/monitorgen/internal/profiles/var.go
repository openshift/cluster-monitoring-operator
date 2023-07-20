package profiles

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"gopkg.in/yaml.v2"
)

func generateProfile(sm monitoringv1.ServiceMonitor, parentSMPath, metricsFilePath, profile string, defaultMetrics map[string][]string, patchSM func(sm *monitoringv1.ServiceMonitor, metrics []string)) {
	var err error

	// Minimal set of metrics to keep based on the hard coded value in
	// minimalProfileMetrics
	metricsToKeep := defaultMetrics[sm.Name]

	// Overwrite previous value if the user specified a file path
	if metricsFilePath != "" {
		metricsToKeep, err = readFileByLine(metricsFilePath)
		if err != nil {
			log.Fatalf("failed to update metrics to keep from file: %e", err)
		}
	}

	if len(metricsToKeep) == 0 {
		return //nothing to do
	}

	newSM := sm.DeepCopy()
	newSM.Name = fmt.Sprintf("%s-%s", newSM.Name, profile)
	newSM.Labels[manifests.CollectionProfileLabel] = profile
	patchSM(newSM, metricsToKeep)
	writeServiceMonitorToFile(parentSMPath, *newSM)
}

func writeServiceMonitorToFile(fullSMPath string, sm monitoringv1.ServiceMonitor) {
	// Take a file name like metrics.yaml and add "-minimal" between
	// "." and "yaml" resulting in "metrics-minimal.yaml"
	profile := sm.Labels[manifests.CollectionProfileLabel]
	splitedName := strings.Split(fullSMPath, ".")
	newSMPath := fmt.Sprintf("./%s-%s.%s", splitedName[len(splitedName)-2], profile, splitedName[len(splitedName)-1])

	yamlData, err := yaml.Marshal(sm)
	if err != nil {
		log.Fatalf("failed marsahling monitor: %e", err)
	}

	err = os.WriteFile(newSMPath, yamlData, 0644)
	if err != nil {
		log.Fatalf("Unable to write data into the file: %e", err)
	}
}

func readFileByLine(path string) ([]string, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read metrics file: %e", err)
	}
	return strings.Split(string(f), "\n"), nil
}
