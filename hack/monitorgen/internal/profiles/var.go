package profiles

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/openshift/cluster-monitoring-operator/pkg/manifests"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"sigs.k8s.io/yaml"
)

type ProfilesGenerator interface {
	Profile() manifests.CollectionProfile
	PatchServiceMonitor(sm *monitoringv1.ServiceMonitor, metrics []string)
	DefaultMetrics() map[string][]string
	ParentSMPath() string
	MetricsFilePath() string
}

func generateProfile(pg ProfilesGenerator, sm monitoringv1.ServiceMonitor) {
	var err error

	// Minimal set of metrics to keep based on the hard coded value in
	// minimalProfileMetrics
	metrics := pg.DefaultMetrics()[sm.Name]

	// Overwrite previous value if the user specified a file path
	if pg.MetricsFilePath() != "" {
		metrics, err = readFileByLine(pg.MetricsFilePath())
		if err != nil {
			log.Fatalf("failed to update metrics to keep from file: %e", err)
		}
	}

	if len(metrics) == 0 {
		return //nothing to do
	}

	newSM := sm.DeepCopy()
	newSM.Name = fmt.Sprintf("%s-%s", newSM.Name, pg.Profile())
	newSM.Labels[manifests.CollectionProfileLabel] = string(pg.Profile())
	pg.PatchServiceMonitor(newSM, metrics)
	writeServiceMonitorToFile(pg.ParentSMPath(), newSM)
}

func writeServiceMonitorToFile(fullSMPath string, sm *monitoringv1.ServiceMonitor) {
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

// removeDrop goes through metricRelabelConfigs and
// returns a copy of metricRelabelConfigs without relabelConfigs that have the
// action "drop"
func removeDrop(metricRelabelConfigs []*monitoringv1.RelabelConfig) []*monitoringv1.RelabelConfig {
	mrc := make([]*monitoringv1.RelabelConfig, 1)
	for _, relabelConfig := range metricRelabelConfigs {
		if relabelConfig.Action == "drop" {
			continue
		}
		mrc = append(mrc, relabelConfig)
	}

	return mrc
}

// keepMetrics goes through the metrics in the slice metrics and joins
// in a string with "|", them returns a relabelConfig with action "keep" and the
// joined metrics in the regex field.
func keepMetrics(metrics []string) *monitoringv1.RelabelConfig {
	jointMetrics := metrics[0]
	for i := 1; i < len(metrics); i++ {
		jointMetrics = jointMetrics + "|" + metrics[i]
	}

	return &monitoringv1.RelabelConfig{
		Action: "keep",
		SourceLabels: []monitoringv1.LabelName{
			"__name__",
		},
		Regex: fmt.Sprintf("(%s)", jointMetrics),
	}
}
