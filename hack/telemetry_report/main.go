package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/xlab/treeprint"
	"gopkg.in/yaml.v3"
)

const (
	defaultLookback = 24 * time.Hour
	maxSampleValues = 3

	maxSelectors           = 3
	maxMetricsPerSelector  = 50
	maxTimeseriesPerMetric = 10
	maxTotalTimeseries     = 10
	maxMatchersPerSelector = 3

	// Recording rule names must follow level:metric:operations (exactly 2 colons).
	ruleNameColons = 2
	// rate()/irate() need at least 2 scrape intervals worth of data.
	minSamplesForRate = 2

	configFileURL = "https://raw.githubusercontent.com/openshift/cluster-monitoring-operator/main/manifests/0000_50_cluster-monitoring-operator_04-config.yaml"
)

// sensitiveLabels are labels whose values change across deployments or may
// contain PII / identifying information (hostnames, IPs, private registry
// URLs, usernames, etc.). Metrics forwarded to telemetry must aggregate
// these away in a recording rule.
var sensitiveLabels = []string{
	// Infrastructure identifiers, change per node/pod, leak topology.
	"instance", "node", "nodename", "hostname",
	"host_ip", "pod_ip", "address",

	// Machine / system identifiers.
	"machine_id", "system_uuid", "boot_id",
	"provider_id", "spec_provider_id", "serial",

	// Kubernetes object names, user-defined, change per deployment.
	"namespace", "pod", "container", "container_id",
	"uid", "pod_uid",
	"replicaset", "deployment", "statefulset",
	"daemonset", "cronjob",
	"service", "service_account",
	"secret", "configmap",
	"persistentvolumeclaim", "volume", "volumename",

	// Workload / owner references, user-defined names.
	"workload", "owner_name", "created_by_name",
	"targetref_name", "resource_name", "lease_holder",

	// Re-exported Kubernetes object names.
	"exported_pod", "exported_namespace",
	"exported_node", "exported_service", "ocp_namespace",

	// Image references, may contain private registry URLs.
	"image", "image_id", "image_spec",

	// Paths, may contain pod names, UUIDs, internal API structure.
	"path", "endpoint",

	// Authentication / user identity.
	"username",
}

// rateAllowedTypes are metric types that can be meaningfully passed to
// rate() / irate(). Everything else (gauge, info, stateset, gaugehistogram)
// will produce unreliable results.
var rateAllowedTypes = map[v1.MetricType]bool{
	v1.MetricTypeCounter:   true,
	v1.MetricTypeHistogram: true,
	v1.MetricTypeSummary:   true,
	v1.MetricTypeUnknown:   true,
}

// counterSafeFuncs are PromQL functions that correctly handle counter
// resets or do not depend on the absolute value of a counter.
var counterSafeFuncs = map[string]bool{
	"rate": true, "irate": true, "increase": true,
	"absent": true, "absent_over_time": true, "present_over_time": true,
	"changes": true, "resets": true, "count_over_time": true,
	"timestamp": true,
}

// counterSafeAggrs are aggregation operators that do not depend on the
// absolute value of a counter (they only count occurrences or group).
var counterSafeAggrs = map[string]bool{
	"count": true, "group": true,
}

type fullReport struct {
	Selectors []selectorReport `yaml:"selectors"`
}

type selectorReport struct {
	Selector      string         `yaml:"selector"`
	Metrics       []metricReport `yaml:"metrics"`
	FailingChecks checkList      `yaml:"failing_checks,omitempty"`

	checks []string `yaml:"-"`
}

type checkList struct {
	Count    int      `yaml:"count"`
	Messages []string `yaml:"messages,omitempty"`
}

type metricReport struct {
	Name          string      `yaml:"name"`
	PeakSeries    int         `yaml:"peak_series"`
	ValueRange    string      `yaml:"value_range"`
	RecordingRule *ruleReport `yaml:"recording_rule,omitempty"`
	Labels        []labelInfo `yaml:"labels,omitempty"`

	colons     int         `yaml:"-"` // pre-computed strings.Count(Name, ":")
	parsedExpr parser.Expr `yaml:"-"` // pre-computed ParseExpr of RecordingRule.Expr (nil if no rule or parse error)
}

type ruleReport struct {
	File string `yaml:"file"`
	Expr string `yaml:"expr"`
	Tree string `yaml:"tree,omitempty"`
}

func (r ruleReport) MarshalYAML() (interface{}, error) {
	exprNode := &yaml.Node{Kind: yaml.ScalarNode, Value: r.Expr}
	if strings.Contains(r.Expr, "\n") {
		exprNode.Style = yaml.LiteralStyle
	}
	node := &yaml.Node{Kind: yaml.MappingNode}
	node.Content = append(node.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: "file"}, &yaml.Node{Kind: yaml.ScalarNode, Value: r.File},
		&yaml.Node{Kind: yaml.ScalarNode, Value: "expr"}, exprNode,
	)
	if r.Tree != "" {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: "tree"},
			&yaml.Node{Kind: yaml.ScalarNode, Value: r.Tree, Style: yaml.LiteralStyle},
		)
	}
	return node, nil
}

type labelInfo struct {
	Name           string   `yaml:"name"`
	DistinctValues int      `yaml:"distinct_values"`
	SampleValues   []string `yaml:"sample_values,flow"`
}

type configEntry struct {
	Selector string
}

func main() {
	log.SetFlags(0)

	rangeFlag := flag.Duration("range", defaultLookback, "lookback window (e.g. 1h, 6h, 24h)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <PROM_URL> <selector> [<selector> ...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Example: %s http://localhost:9998 '{__name__=\"metric_a\"}'\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Example: %s -range 6h http://localhost:9998 '{__name__=\"metric_b\"}'\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  To access Prometheus, run: oc port-forward -n openshift-monitoring prometheus-k8s-0 9998:9090")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	lookback := *rangeFlag
	promURL := flag.Arg(0)
	selectors := flag.Args()[1:]
	parsedSelectors := make([][]*labels.Matcher, len(selectors))
	for i, s := range selectors {
		matchers, err := parser.ParseMetricSelector(s)
		if err != nil {
			log.Fatalf("invalid selector %q: %v", s, err)
		}
		parsedSelectors[i] = matchers
	}

	var configEntries []configEntry
	var configErr string
	entries, err := downloadConfigFile(configFileURL)
	if err != nil {
		configErr = fmt.Sprintf("telemetry config file: %v", err)
	} else {
		configEntries = entries
	}

	client, err := api.NewClient(api.Config{Address: promURL})
	if err != nil {
		log.Fatal(err)
	}
	prom := v1.NewAPI(client)
	ctx := context.Background()

	end := time.Now()

	recordingRules, ruleDefCounts, err := fetchRecordingRules(ctx, prom)
	if err != nil {
		log.Fatalf("fetching recording rules: %v", err)
	}

	scrapeInterval, err := fetchScrapeInterval(ctx, prom)
	if err != nil {
		log.Fatalf("fetching scrape interval: %v", err)
	}

	alertLeaves, err := fetchAlertLeafMetrics(ctx, prom, recordingRules)
	if err != nil {
		log.Fatalf("fetching alerting rules: %v", err)
	}

	fmt.Printf("# Telemetry selectors report (%s)\n", model.Duration(lookback))
	fmt.Printf("# args: %s\n", strings.Join(selectors, " "))
	if age := tsdbAge(ctx, prom, end); age > 0 && age < lookback {
		fmt.Printf("# NOTE: TSDB only has %s of data, value_range/peak_series may not be representative of the full %s window.\n", age.Round(time.Second), model.Duration(lookback))
	}
	fmt.Printf("# Results depend on the queried Prometheus instance and may differ elsewhere.\n")

	querySeries := newSeriesQuerier(ctx, prom, end)
	peakCount := newPeakCounter(ctx, prom, end, lookback)
	queryValueRange := newValueRangeQuerier(ctx, prom, end, lookback)

	var report fullReport
	totalTimeseries := 0
	for i, selector := range selectors {
		sr, err := buildReport(ctx, prom, selector, end, recordingRules, querySeries, peakCount, queryValueRange)
		if err != nil {
			log.Fatalf("selector %q: %v", selector, err)
		}
		totalTimeseries += runChecks(ctx, prom, sr, parsedSelectors[i], recordingRules, ruleDefCounts, scrapeInterval, peakCount, querySeries, queryValueRange, alertLeaves, configEntries, configErr, selectors)
		report.Selectors = append(report.Selectors, *sr)
	}

	// Append global checks to every selector.
	var globalFails []string
	if len(selectors) > maxSelectors {
		globalFails = append(globalFails,
			fmt.Sprintf("%d selectors exceed limit of %d per run, split by owner or merge related selectors",
				len(selectors), maxSelectors))
	}
	if totalTimeseries > maxTotalTimeseries && len(selectors) > 1 {
		globalFails = append(globalFails,
			fmt.Sprintf("all selectors combined produce %d timeseries (limit %d), reduce cardinality in recording rules (e.g. aggregate away high-cardinality labels)",
				totalTimeseries, maxTotalTimeseries))
	}
	if len(configEntries) > 0 {
		configNames := make(map[string]bool)
		for _, ce := range configEntries {
			for _, n := range extractSelectorMetricNames(ce.Selector, recordingRules) {
				configNames[n] = true
			}
		}
		for _, sel := range selectors {
			for _, n := range extractSelectorMetricNames(sel, recordingRules) {
				if configNames[n] {
					globalFails = append(globalFails,
						fmt.Sprintf("metric %q is already in the telemetry config file", n))
				}
			}
		}
	}
	if len(globalFails) > 0 {
		for i := range report.Selectors {
			sr := &report.Selectors[i]
			sr.FailingChecks.Messages = append(sr.FailingChecks.Messages, globalFails...)
			sr.FailingChecks.Count = len(sr.FailingChecks.Messages)
		}
	}

	hasErrors := slices.ContainsFunc(report.Selectors, func(sr selectorReport) bool {
		return sr.FailingChecks.Count > 0
	})

	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	if err := enc.Encode(&report); err != nil {
		log.Fatalf("encoding report: %v", err)
	}
	enc.Close()

	if hasErrors {
		os.Exit(1)
	}
}

func fetchRecordingRules(ctx context.Context, prom v1.API) (map[string]ruleReport, map[string]int, error) {
	result, err := prom.Rules(ctx)
	if err != nil {
		return nil, nil, err
	}
	rules := make(map[string]ruleReport)
	ruleDefCounts := make(map[string]int)
	for _, group := range result.Groups {
		for _, rule := range group.Rules {
			rec, ok := rule.(v1.RecordingRule)
			if !ok {
				continue
			}
			ruleDefCounts[rec.Name]++
			if _, exists := rules[rec.Name]; exists {
				continue
			}
			rules[rec.Name] = ruleReport{File: filepath.Base(group.File), Expr: rec.Query}
		}
	}
	return rules, ruleDefCounts, nil
}

// fetchAlertLeafMetrics returns a map from alert name to the raw scraped
// metrics it ultimately depends on (following recording rule chains).
func fetchAlertLeafMetrics(ctx context.Context, prom v1.API, rules map[string]ruleReport) (map[string]map[string]bool, error) {
	result, err := prom.Rules(ctx)
	if err != nil {
		return nil, err
	}
	alerts := make(map[string]map[string]bool)
	for _, group := range result.Groups {
		for _, rule := range group.Rules {
			ar, ok := rule.(v1.AlertingRule)
			if !ok {
				continue
			}
			if _, exists := alerts[ar.Name]; exists {
				continue
			}
			alerts[ar.Name] = sliceToSet(resolveLeafMetrics(ar.Query, rules, map[string]bool{}))
		}
	}
	return alerts, nil
}

func fetchScrapeInterval(ctx context.Context, prom v1.API) (time.Duration, error) {
	result, err := prom.Config(ctx)
	if err != nil {
		return 0, err
	}
	var cfg struct {
		Global struct {
			ScrapeInterval string `yaml:"scrape_interval"`
		} `yaml:"global"`
	}
	if err := yaml.Unmarshal([]byte(result.YAML), &cfg); err != nil {
		return 0, fmt.Errorf("parsing config YAML: %w", err)
	}
	if cfg.Global.ScrapeInterval == "" {
		return 0, fmt.Errorf("scrape_interval is empty in Prometheus config, cannot validate rate() ranges")
	}
	d, err := model.ParseDuration(cfg.Global.ScrapeInterval)
	if err != nil {
		return 0, fmt.Errorf("parsing scrape_interval %q: %w", cfg.Global.ScrapeInterval, err)
	}
	return time.Duration(d), nil
}

func tsdbAge(ctx context.Context, prom v1.API, now time.Time) time.Duration {
	result, _, err := prom.Query(ctx, "prometheus_tsdb_lowest_timestamp_seconds", now)
	if err != nil {
		return 0
	}
	vec, _ := result.(model.Vector)
	if len(vec) == 0 {
		return 0
	}
	lowestTS := time.Unix(int64(vec[0].Value), 0)
	return now.Sub(lowestTS)
}

func newSeriesQuerier(ctx context.Context, prom v1.API, ts time.Time) func(string) model.Vector {
	cache := make(map[string]model.Vector)
	return func(expr string) model.Vector {
		if v, ok := cache[expr]; ok {
			return v
		}
		result, _, err := prom.Query(ctx, expr, ts)
		if err != nil {
			cache[expr] = nil
			return nil
		}
		vec, _ := result.(model.Vector)
		cache[expr] = vec
		return vec
	}
}

// newPeakCounter returns a function that computes the highest number of
// timeseries a metric had over the lookback window.
func newPeakCounter(ctx context.Context, prom v1.API, ts time.Time, lookback time.Duration) func(string) int {
	cache := make(map[string]int)
	rangeStr := model.Duration(lookback).String()
	return func(name string) int {
		if v, ok := cache[name]; ok {
			return v
		}
		q := fmt.Sprintf("max_over_time(count(%s)[%s:])", name, rangeStr)
		result, _, err := prom.Query(ctx, q, ts)
		if err != nil {
			cache[name] = 0
			return 0
		}
		vec, _ := result.(model.Vector)
		if len(vec) == 0 {
			cache[name] = 0
			return 0
		}
		n := int(vec[0].Value)
		cache[name] = n
		return n
	}
}

// newValueRangeQuerier returns a function that computes the min and max values
// a metric had over the lookback window. Returns (NaN, NaN) when no data.
func newValueRangeQuerier(ctx context.Context, prom v1.API, ts time.Time, lookback time.Duration) func(string) (float64, float64) {
	type mm struct{ min, max float64 }
	cache := make(map[string]mm)
	rangeStr := model.Duration(lookback).String()
	queryScalar := func(q string) float64 {
		result, _, err := prom.Query(ctx, q, ts)
		if err != nil {
			return math.NaN()
		}
		vec, _ := result.(model.Vector)
		if len(vec) == 0 {
			return math.NaN()
		}
		return float64(vec[0].Value)
	}
	return func(name string) (float64, float64) {
		if v, ok := cache[name]; ok {
			return v.min, v.max
		}
		v := mm{
			min: queryScalar(fmt.Sprintf("min(min_over_time(%s[%s]))", name, rangeStr)),
			max: queryScalar(fmt.Sprintf("max(max_over_time(%s[%s]))", name, rangeStr)),
		}
		cache[name] = v
		return v.min, v.max
	}
}

func formatValueRange(min, max float64) string {
	if math.IsNaN(min) && math.IsNaN(max) {
		return "no data"
	}
	return formatVal(min) + ", " + formatVal(max)
}

func formatVal(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "NaN"
	}
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', 4, 64)
}

func discoverMetricNames(ctx context.Context, prom v1.API, selector string, ts time.Time) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	q := fmt.Sprintf("group by (__name__) (%s)", selector)
	result, _, err := prom.Query(ctx, q, ts)
	if err != nil {
		return nil, fmt.Errorf("discovering metric names: %w", err)
	}
	vec, _ := result.(model.Vector)
	if len(vec) > maxMetricsPerSelector {
		return nil, fmt.Errorf("selector matches %d metrics (limit %d), add a __name__ matcher to narrow it down", len(vec), maxMetricsPerSelector)
	}
	var names []string
	for _, s := range vec {
		if name := string(s.Metric[model.MetricNameLabel]); name != "" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

func buildReport(ctx context.Context, prom v1.API, selector string, end time.Time, recordingRules map[string]ruleReport, querySeries func(string) model.Vector, peakCount func(string) int, queryValueRange func(string) (float64, float64)) (*selectorReport, error) {
	liveNames, err := discoverMetricNames(ctx, prom, selector, end)
	if err != nil {
		return nil, err
	}

	buildTree := func(name string, rule ruleReport) *ruleReport {
		exprStr := prettyExpr(rule.Expr)
		r := ruleReport{
			File: rule.File,
			Expr: exprStr,
		}
		tree := treeprint.NewWithRoot("")
		buildDepTree(rule.Expr, recordingRules, map[string]bool{name: true}, map[string]bool{}, tree, querySeries, peakCount, queryValueRange, true)
		r.Tree = treeToBlock(tree)
		return &r
	}

	report := &selectorReport{Selector: selector}

	allNames := sliceToSet(liveNames)
	// Also include explicit names from the selector so checks still run
	// even when a metric has 0 series.
	var extraMatchers string
	if matchers, err := parser.ParseMetricSelector(selector); err == nil {
		var parts []string
		for _, m := range matchers {
			if m.Name != labels.MetricName {
				parts = append(parts, m.String())
				continue
			}
			switch m.Type {
			case labels.MatchEqual:
				allNames[m.Value] = true
			case labels.MatchRegexp:
				for _, name := range m.SetMatches() {
					allNames[name] = true
				}
			}
		}
		if len(parts) > 0 {
			extraMatchers = "{" + strings.Join(parts, ",") + "}"
		}
	}

	for _, name := range slices.Sorted(maps.Keys(allNames)) {
		qualifiedName := name + extraMatchers
		mn, mx := queryValueRange(qualifiedName)
		metric := metricReport{
			Name:       name,
			PeakSeries: peakCount(qualifiedName),
			ValueRange: formatValueRange(mn, mx),
			colons:     strings.Count(name, ":"),
		}

		if rule, ok := recordingRules[name]; ok {
			metric.RecordingRule = buildTree(name, rule)
			metric.parsedExpr, _ = parser.ParseExpr(rule.Expr)
		}

		vec := querySeries(qualifiedName)
		byLabel := make(map[string]map[string]bool)
		for _, sample := range vec {
			for k, v := range sample.Metric {
				if k == model.MetricNameLabel {
					continue
				}
				labelName := string(k)
				if byLabel[labelName] == nil {
					byLabel[labelName] = make(map[string]bool)
				}
				byLabel[labelName][string(v)] = true
			}
		}
		for _, labelName := range slices.Sorted(maps.Keys(byLabel)) {
			vals := slices.Sorted(maps.Keys(byLabel[labelName]))
			metric.Labels = append(metric.Labels, labelInfo{
				Name:           labelName,
				DistinctValues: len(vals),
				SampleValues:   vals[:min(maxSampleValues, len(vals))],
			})
		}
		slices.SortFunc(metric.Labels, func(a, b labelInfo) int {
			if a.DistinctValues != b.DistinctValues {
				return b.DistinctValues - a.DistinctValues
			}
			return strings.Compare(a.Name, b.Name)
		})
		report.Metrics = append(report.Metrics, metric)
	}
	return report, nil
}

func runChecks(ctx context.Context, prom v1.API, report *selectorReport, matchers []*labels.Matcher, rules map[string]ruleReport, ruleDefCounts map[string]int, scrapeInterval time.Duration, peakCount func(string) int, querySeries func(string) model.Vector, queryValueRange func(string) (float64, float64), alertLeaves map[string]map[string]bool, configEntries []configEntry, configErr string, passedSelectors []string) int {
	totalTimeseries := 0
	for _, m := range report.Metrics {
		totalTimeseries += m.PeakSeries
	}

	metadataCache := make(map[string][]v1.Metadata)
	lookupMetadata := func(metric string) []v1.Metadata {
		if entries, ok := metadataCache[metric]; ok {
			return entries
		}
		result, err := prom.Metadata(ctx, metric, "")
		if err != nil {
			metadataCache[metric] = nil
			return nil
		}
		metadataCache[metric] = result[metric]
		return result[metric]
	}

	checkLiveness(report)
	checkRules(report, rules, lookupMetadata)
	checkMultipleDefinitions(report, ruleDefCounts)
	checkSuffixMismatch(report)
	checkSumOverMax(report, rules, peakCount, lookupMetadata)
	checkRateUsage(report, rules, scrapeInterval, lookupMetadata)
	checkCounterUsage(report, rules, lookupMetadata)
	checkDeadDeps(report, rules, peakCount)
	checkAlertOverlap(report, rules, alertLeaves)
	checkMatchers(report, matchers)
	checkLabels(report, matchers)
	checkLabelCasing(report, rules, querySeries)
	checkCardinalityLimits(report, totalTimeseries)
	checkMetadataConflicts(report, rules, lookupMetadata)
	if configErr != "" {
		report.checks = append(report.checks, configErr)
	} else if len(configEntries) == 0 {
		report.checks = append(report.checks, "telemetry config file has no selectors")
	} else {
		checkLeafOverlap(report, rules, configEntries, passedSelectors)
	}

	report.FailingChecks = checkList{Count: len(report.checks), Messages: report.checks}
	return totalTimeseries
}

// checkLiveness verifies the selector matched at least one metric and
// each metric has at least one timeseries.
func checkLiveness(report *selectorReport) {
	if len(report.Metrics) == 0 {
		report.checks = append(report.checks,
			"selector matched 0 metrics, verify the selector is correct and the metrics exist")
		return
	}
	for _, metric := range report.Metrics {
		if metric.PeakSeries != 0 {
			continue
		}
		detail := "target may not be scraped or feature not enabled"
		if metric.RecordingRule != nil {
			detail = "source metrics may not exist or rule dependencies are not met"
		}
		report.checks = append(report.checks,
			fmt.Sprintf("metric %q has 0 timeseries, %s", metric.Name, detail))
	}
}

// checkRules validates that each metric is a recording rule with a proper
// level:metric:operations name. Also flags CMO-defined rules, irate(), and
// _total suffix misuse.
func checkRules(report *selectorReport, rules map[string]ruleReport, lookupMetadata func(string) []v1.Metadata) {
	for _, metric := range report.Metrics {
		if metric.RecordingRule == nil {
			if metric.colons >= ruleNameColons {
				report.checks = append(report.checks,
					fmt.Sprintf("metric %q looks like a recording rule (has %d colons) but was not found among this instance's rules, ensure it is loaded", metric.Name, metric.colons))
			} else {
				report.checks = append(report.checks,
					fmt.Sprintf("metric %q is not a recording rule, consider using one to control cardinality and drop potentially sensitive labels", metric.Name))
			}
			if strings.HasSuffix(metric.Name, "_total") {
				entries := lookupMetadata(metric.Name)
				isCounter := slices.ContainsFunc(entries, func(md v1.Metadata) bool {
					return md.Type == "counter"
				})
				if len(entries) > 0 && !isCounter {
					report.checks = append(report.checks,
						fmt.Sprintf("metric %q ends with _total but is not a counter, verify the metric type", metric.Name))
				}
			}
			continue
		}

		if metric.colons != ruleNameColons {
			report.checks = append(report.checks,
				fmt.Sprintf("recording rule %q name needs exactly %d colons for level:metric:operations (has %d)",
					metric.Name, ruleNameColons, metric.colons))
		}

		if strings.HasSuffix(metric.Name, ":total") {
			report.checks = append(report.checks,
				fmt.Sprintf("recording rule %q ends with :total (reserved for raw counters)", metric.Name))
		}

		if lastColon := strings.LastIndex(metric.Name, ":"); lastColon >= 0 && strings.HasSuffix(metric.Name[lastColon+1:], "_total") {
			report.checks = append(report.checks,
				fmt.Sprintf("recording rule %q has operations suffix _total (reserved for raw counters, consider :sum or similar)", metric.Name))
		}

		if strings.HasPrefix(metric.RecordingRule.File, "openshift-monitoring-") {
			report.checks = append(report.checks,
				fmt.Sprintf("recording rule %q is defined in CMO, it should probably live in the owning component operator",
					metric.Name))
		}

		if metric.parsedExpr != nil {
			hasIrate := false
			parser.Inspect(metric.parsedExpr, func(node parser.Node, _ []parser.Node) error {
				if call, ok := node.(*parser.Call); ok && call.Func.Name == "irate" {
					hasIrate = true
				}
				return nil
			})
			if hasIrate {
				report.checks = append(report.checks,
					fmt.Sprintf("recording rule %q uses irate() which is not appropriate for telemetry, consider rate() instead",
						metric.Name))
			}
		}
	}
}

// checkMultipleDefinitions flags recording rules with more than one
// definition in Prometheus. The report only shows one, so stats may be
// incomplete.
func checkMultipleDefinitions(report *selectorReport, ruleDefCounts map[string]int) {
	for _, metric := range report.Metrics {
		if metric.RecordingRule == nil {
			continue
		}
		if n := ruleDefCounts[metric.Name]; n > 1 {
			report.checks = append(report.checks,
				fmt.Sprintf("recording rule %q has %d definitions in Prometheus, the report only shows one, the dependency tree, checks, and stats may be incorrect",
					metric.Name, n))
		}
	}
}

// checkSuffixMismatch flags rules whose name suffix doesn't match the
// expression (e.g. a rule named ":sum" whose expr uses max()).
// The outermost operation is always accepted. For sum(inner), the inner
// operation is also accepted since sum can be omitted per
// https://prometheus.io/docs/practices/rules/.
func checkSuffixMismatch(report *selectorReport) {
	for _, metric := range report.Metrics {
		if metric.parsedExpr == nil || metric.colons < 1 {
			continue
		}
		lastColon := strings.LastIndex(metric.Name, ":")
		actualSuffix := metric.Name[lastColon+1:]

		accepted := acceptedSuffixes(metric.parsedExpr)
		if len(accepted) == 0 {
			continue
		}
		ok := false
		for _, a := range accepted {
			if strings.HasPrefix(actualSuffix, a) {
				ok = true
				break
			}
		}
		if ok {
			continue
		}

		expected := ":" + strings.Join(accepted, " or :")
		report.checks = append(report.checks,
			fmt.Sprintf("recording rule %q has suffix :%s, expected %s based on the expression",
				metric.Name, actualSuffix, expected))
	}
}

// checkSumOverMax flags sum() over expressions whose values are only 0 or 1,
// where max(), min(), or group() may be more appropriate. Skips counters, histograms,
// and rate()-wrapped expressions.
func checkSumOverMax(report *selectorReport, rules map[string]ruleReport, peakCount func(string) int, lookupMetadata func(string) []v1.Metadata) {
	for _, metric := range report.Metrics {
		if metric.parsedExpr == nil {
			continue
		}

		seen := make(map[string]bool)
		for _, aggr := range findTopLevelSums(metric.parsedExpr) {
			hasRateOrCounter := false
			var innerName string
			parser.Inspect(aggr.Expr, func(node parser.Node, _ []parser.Node) error {
				switch n := node.(type) {
				case *parser.Call:
					switch n.Func.Name {
					case "rate", "irate", "increase":
						hasRateOrCounter = true
					}
				case *parser.VectorSelector:
					name := vectorSelectorName(n)
					if innerName == "" {
						innerName = name
					}
					for _, md := range lookupMetadata(name) {
						switch md.Type {
						case "counter", "histogram", "summary":
							hasRateOrCounter = true
						}
					}
				}
				return nil
			})
			if hasRateOrCounter {
				continue
			}

			innerStr := aggr.Expr.String()
			if seen[innerStr] {
				continue
			}
			seen[innerStr] = true

			if peakCount(innerStr) <= 1 {
				continue
			}
			if peakCount(fmt.Sprintf("(%s != 0) and (%s != 1)", innerStr, innerStr)) > 0 {
				continue
			}

			if innerName == "" {
				innerName = innerStr
			}
			report.checks = append(report.checks,
				fmt.Sprintf("recording rule %q uses sum() on %q which currently only has values 0 and 1, if this is a boolean/presence metric, max(), min(), or group() may be more appropriate",
					metric.Name, innerName))
		}
	}
}

// findTopLevelSums returns sum() aggregations at the top level.
// Recurses through arithmetic binary ops and parens but stops at other
// aggregations and comparison operators. sum(x) == N is a counting pattern
// (not a cardinality problem), so comparisons are excluded.
func findTopLevelSums(expr parser.Expr) []*parser.AggregateExpr {
	switch n := expr.(type) {
	case *parser.AggregateExpr:
		if n.Op == parser.SUM {
			return []*parser.AggregateExpr{n}
		}
	case *parser.BinaryExpr:
		if n.Op.IsComparisonOperator() {
			return nil
		}
		return append(findTopLevelSums(n.LHS), findTopLevelSums(n.RHS)...)
	case *parser.ParenExpr:
		return findTopLevelSums(n.Expr)
	}
	return nil
}

// checkAlertOverlap flags recording rules whose leaf metrics exactly match
// an existing alert. ALERTS is already forwarded, so the rule may be
// redundant. See also checkLeafOverlap which does the same comparison
// against existing telemetry config selectors.
func checkAlertOverlap(report *selectorReport, rules map[string]ruleReport, alertLeaves map[string]map[string]bool) {
	sortedAlerts := slices.Sorted(maps.Keys(alertLeaves))
	for _, metric := range report.Metrics {
		rule, ok := rules[metric.Name]
		if !ok {
			continue
		}
		leafSet := sliceToSet(resolveLeafMetrics(rule.Expr, rules, map[string]bool{}))
		if len(leafSet) == 0 {
			continue
		}
		for _, alertName := range sortedAlerts {
			alertSet := alertLeaves[alertName]
			if len(alertSet) != len(leafSet) {
				continue
			}
			if maps.Equal(leafSet, alertSet) {
				report.checks = append(report.checks,
					fmt.Sprintf("recording rule %q uses the same source metrics as alert %q, ALERTS is already forwarded to telemetry so this metric may be redundant",
						metric.Name, alertName))
				break
			}
		}
	}
}

// checkMatchers validates selector matchers for common issues (duplicates,
// negative matches, unnecessary regexes, unsorted alternations, etc.).
func checkMatchers(report *selectorReport, matchers []*labels.Matcher) {
	hasName := false
	for _, m := range matchers {
		if m.Name == labels.MetricName {
			hasName = true
			break
		}
	}
	if !hasName {
		report.checks = append(report.checks,
			"selector has no __name__ matcher, every selector must specify metric names")
	}

	if len(matchers) > maxMatchersPerSelector {
		report.checks = append(report.checks,
			fmt.Sprintf("selector has %d matchers (limit %d), consider moving filtering into the recording rule",
				len(matchers), maxMatchersPerSelector))
	}

	seenLabels := make(map[string]bool, len(matchers))
	for _, m := range matchers {
		if seenLabels[m.Name] {
			report.checks = append(report.checks,
				fmt.Sprintf("label %q has multiple matchers, consider combining into one", m.Name))
		}
		seenLabels[m.Name] = true

		switch m.Type {
		case labels.MatchEqual:
			if m.Value == "" && m.Name != labels.MetricName {
				report.checks = append(report.checks,
					fmt.Sprintf("matcher %s matches empty or missing values, use a positive match instead%s",
						m, suggestFix(m.Name)))
			}
			continue
		case labels.MatchNotEqual:
			report.checks = append(report.checks,
				fmt.Sprintf("matcher %s is a negative match, consider enumerating allowed values instead%s",
					m, suggestFix(m.Name)))
		case labels.MatchNotRegexp:
			report.checks = append(report.checks,
				fmt.Sprintf("matcher %s is a negative regex, consider enumerating allowed values instead%s",
					m, suggestFix(m.Name)))
		case labels.MatchRegexp:
			if strings.HasPrefix(m.Value, "^") || strings.HasSuffix(m.Value, "$") {
				suggested := strings.TrimPrefix(m.Value, "^")
				suggested = strings.TrimSuffix(suggested, "$")
				report.checks = append(report.checks,
					fmt.Sprintf("matcher %s has redundant anchors (Prometheus auto-anchors), use %s=~\"%s\"",
						m, m.Name, suggested))
			}
			values := m.SetMatches()
			if len(values) == 0 {
				report.checks = append(report.checks,
					fmt.Sprintf("matcher %s is open-ended, consider using bounded values%s",
						m, suggestFix(m.Name)))
				continue
			}
			if len(values) < 2 {
				report.checks = append(report.checks,
					fmt.Sprintf("matcher %s uses unnecessary regexp, use %s=\"%s\" instead",
						m, m.Name, values[0]))
				continue
			}

			seen := make(map[string]bool, len(values))
			for _, v := range values {
				if seen[v] {
					report.checks = append(report.checks,
						fmt.Sprintf("matcher %s has duplicate values in alternation, consider removing duplicates", m))
					break
				}
				seen[v] = true
			}
			if !slices.IsSorted(values) {
				sorted := slices.Sorted(maps.Keys(seen))
				report.checks = append(report.checks,
					fmt.Sprintf("matcher %s alternation is unsorted, consider using %s=~\"%s\"",
						m, m.Name, strings.Join(sorted, "|")))
			}
		}
	}
}

// checkLabels flags labels without a matcher (cardinality risk) and
// sensitive labels (PII, hostnames, etc.) that should be aggregated away.
func checkLabels(report *selectorReport, matchers []*labels.Matcher) {
	controlled := make(map[string]bool, len(matchers))
	for _, m := range matchers {
		controlled[m.Name] = true
	}

	for _, metric := range report.Metrics {
		for _, label := range metric.Labels {
			if !controlled[label.Name] {
				if label.DistinctValues == 1 {
					report.checks = append(report.checks,
						fmt.Sprintf("metric %q label %q has 1 value (%s), consider pinning it with %s=%q or dropping it in the recording rule",
							metric.Name, label.Name, label.SampleValues[0], label.Name, label.SampleValues[0]))
				} else {
					report.checks = append(report.checks,
						fmt.Sprintf("metric %q label %q has no matcher, consider adding one to bound cardinality%s",
							metric.Name, label.Name, suggestFix(label.Name)))
				}
			}
			if slices.Contains(sensitiveLabels, label.Name) {
				report.checks = append(report.checks,
					fmt.Sprintf("metric %q label %q may be sensitive (PII risk), consider aggregating it away in the recording rule",
						metric.Name, label.Name))
			}
		}
	}
}

// checkLabelCasing flags labels that have values differing only in
// capitalization (e.g. "Production" vs "production" for the same label).
// Checks the recording rule and the metrics it references.
func checkLabelCasing(report *selectorReport, rules map[string]ruleReport, querySeries func(string) model.Vector) {
	for _, metric := range report.Metrics {
		if metric.parsedExpr == nil {
			continue
		}
		valuesByLabel := make(map[string]map[string]bool)
		addLabelValues(querySeries(metric.Name), valuesByLabel)
		collectDirectLabelValues(metric.parsedExpr, querySeries, valuesByLabel)

		for _, labelName := range slices.Sorted(maps.Keys(valuesByLabel)) {
			byLower := make(map[string][]string)
			for v := range valuesByLabel[labelName] {
				key := strings.ToLower(v)
				byLower[key] = append(byLower[key], v)
			}
			var groups []string
			for _, key := range slices.Sorted(maps.Keys(byLower)) {
				variants := byLower[key]
				if len(variants) <= 1 {
					continue
				}
				slices.Sort(variants)
				groups = append(groups, strings.Join(variants, "/"))
			}
			if len(groups) > 0 {
				report.checks = append(report.checks,
					fmt.Sprintf("label %q has mixed-case values in %q: %s; consider label_replace() to normalize",
						labelName, metric.Name, strings.Join(groups, ", ")))
			}
		}
	}
}

// collectDirectLabelValues queries each metric in the expression and collects
// its label values (does not follow recording rule chains).
func collectDirectLabelValues(expr parser.Expr, querySeries func(string) model.Vector, result map[string]map[string]bool) {
	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		vs, ok := node.(*parser.VectorSelector)
		if !ok {
			return nil
		}
		addLabelValues(querySeries(vs.String()), result)
		return nil
	})
}

// addLabelValues merges label values from a query result into dst.
func addLabelValues(vec model.Vector, dst map[string]map[string]bool) {
	for _, s := range vec {
		for k, v := range s.Metric {
			if k == model.MetricNameLabel {
				continue
			}
			lbl := string(k)
			if dst[lbl] == nil {
				dst[lbl] = make(map[string]bool)
			}
			dst[lbl][string(v)] = true
		}
	}
}

// checkCardinalityLimits flags metrics exceeding timeseries limits.
// When there is only 1 metric, the per-selector total is identical to the
// per-metric message and is skipped to avoid redundancy.
func checkCardinalityLimits(report *selectorReport, totalTimeseries int) {
	for _, metric := range report.Metrics {
		if metric.PeakSeries <= maxTimeseriesPerMetric {
			continue
		}
		report.checks = append(report.checks,
			fmt.Sprintf("metric %q has %d timeseries (limit %d), consider aggregating away high-cardinality labels in the recording rule",
				metric.Name, metric.PeakSeries, maxTimeseriesPerMetric))
	}
	if totalTimeseries > maxTotalTimeseries && len(report.Metrics) > 1 {
		report.checks = append(report.checks,
			fmt.Sprintf("selector totals %d timeseries across %d metrics (limit %d), reduce cardinality in recording rules (e.g. aggregate away high-cardinality labels)",
				totalTimeseries, len(report.Metrics), maxTotalTimeseries))
	}
}

// checkMetadataConflicts flags leaf metrics that have conflicting type metadata
// (e.g. reported as "counter" by one source and "gauge" by another).
func checkMetadataConflicts(report *selectorReport, rules map[string]ruleReport, lookupMetadata func(string) []v1.Metadata) {
	seen := make(map[string]bool)
	for _, metric := range report.Metrics {
		leaves := leafMetricSet(metric.Name, rules)
		for leaf := range leaves {
			if seen[leaf] {
				continue
			}
			seen[leaf] = true
			entries := lookupMetadata(leaf)
			if len(entries) <= 1 {
				continue
			}
			typeSet := make(map[string]bool)
			for _, m := range entries {
				typeSet[string(m.Type)] = true
			}
			if len(typeSet) > 1 {
				types := slices.Sorted(maps.Keys(typeSet))
				report.checks = append(report.checks,
					fmt.Sprintf("leaf metric %q has conflicting type metadata: %s",
						leaf, strings.Join(types, ", ")))
			}
		}
	}
}

// checkDeadDeps warns about dependency-chain metrics with 0 series over the
// lookback window. Skips optional positions (RHS of "unless"/"or", absent()).
func checkDeadDeps(report *selectorReport, rules map[string]ruleReport, peakCount func(string) int) {
	for _, metric := range report.Metrics {
		if metric.RecordingRule == nil {
			continue
		}
		visited := map[string]bool{metric.Name: true}
		seen := make(map[string]bool)
		dead := findRequiredDeadDeps(metric.RecordingRule.Expr, rules, visited, seen, peakCount)
		for _, dep := range dead {
			report.checks = append(report.checks,
				fmt.Sprintf("recording rule %q depends on %q which has 0 series, ensure it is exercised within the observation window", metric.Name, dep))
		}
	}
}

// findRequiredDeadDeps walks an expression and returns metrics with 0 series.
// Skips optional positions: RHS of "unless"/"or", inside absent().
func findRequiredDeadDeps(expression string, rules map[string]ruleReport, visited, seen map[string]bool, peakCount func(string) int) []string {
	expr, err := parser.ParseExpr(expression)
	if err != nil {
		return nil
	}

	var dead []string
	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		vs, ok := node.(*parser.VectorSelector)
		if !ok || isOptionalNode(node, path) || isBinaryRHS(node, path, parser.LOR) {
			return nil
		}

		selector := vs.String()
		if seen[selector] {
			return nil
		}
		if peakCount(selector) == 0 {
			dead = append(dead, selector)
			seen[selector] = true
		}

		name := vectorSelectorName(vs)
		rule, ok := rules[name]
		if name != "" && !visited[name] && ok {
			visited[name] = true
			dead = append(dead, findRequiredDeadDeps(rule.Expr, rules, visited, seen, peakCount)...)
		}
		return nil
	})
	return dead
}

// isBinaryRHS returns true when node is on the right side of a binary
// operator (e.g. the B in "A unless B") somewhere above it in the AST.
func isBinaryRHS(node parser.Node, path []parser.Node, op parser.ItemType) bool {
	for i, p := range path {
		be, ok := p.(*parser.BinaryExpr)
		if !ok || be.Op != op {
			continue
		}
		var child parser.Node
		if i+1 < len(path) {
			child = path[i+1]
		} else {
			child = node
		}
		if child == be.RHS {
			return true
		}
	}
	return false
}

// isOptionalNode returns true if the metric is in a position where 0 series
// is fine: RHS of "unless", or inside absent()/absent_over_time().
func isOptionalNode(node parser.Node, path []parser.Node) bool {
	if isBinaryRHS(node, path, parser.LUNLESS) {
		return true
	}
	for _, p := range path {
		call, ok := p.(*parser.Call)
		if ok && (call.Func.Name == "absent" || call.Func.Name == "absent_over_time") {
			return true
		}
	}
	return false
}

// checkRateUsage validates rate()/irate(): metric must be a counter, must not
// wrap an aggregation (rate(sum()) => sum(rate())), range >= 2x scrape_interval.
func checkRateUsage(report *selectorReport, rules map[string]ruleReport, scrapeInterval time.Duration, lookupMetadata func(string) []v1.Metadata) {
	for _, metric := range report.Metrics {
		if metric.parsedExpr == nil {
			continue
		}

		parser.Inspect(metric.parsedExpr, func(node parser.Node, path []parser.Node) error {
			call, ok := node.(*parser.Call)
			if !ok || (call.Func.Name != "rate" && call.Func.Name != "irate") {
				return nil
			}

			for _, arg := range call.Args {
				ms, ok := arg.(*parser.MatrixSelector)
				if !ok {
					continue
				}
				vs, ok := ms.VectorSelector.(*parser.VectorSelector)
				if !ok {
					continue
				}

				innerName := vectorSelectorName(vs)
				if innerName == "" {
					continue
				}

				leafMetrics := []string{innerName}
				if rule, ok := rules[innerName]; ok {
					leafMetrics = resolveLeafMetrics(rule.Expr, rules, map[string]bool{innerName: true})
					if innerExpr, err := parser.ParseExpr(rule.Expr); err == nil {
						if aggrName := outermostAggregation(innerExpr); aggrName != "" {
							report.checks = append(report.checks,
								fmt.Sprintf("recording rule %q applies %s() over %q which uses %s(), consider reversing the order: %s(%s(...)) instead of %s(%s(...))",
									metric.Name, call.Func.Name, innerName, aggrName,
									aggrName, call.Func.Name, call.Func.Name, aggrName))
						}
					}
				}

				for _, leaf := range leafMetrics {
					entries := lookupMetadata(leaf)
					if len(entries) == 0 {
						continue
					}

					var types []string
					hasDisallowed := false
					for _, m := range entries {
						types = append(types, string(m.Type))
						if !rateAllowedTypes[m.Type] {
							hasDisallowed = true
						}
					}
					if !hasDisallowed {
						continue
					}

					if len(entries) > 1 {
						report.checks = append(report.checks,
							fmt.Sprintf("recording rule %q uses %s() on %q which has conflicting types: %s",
								metric.Name, call.Func.Name, leaf, strings.Join(types, ", ")))
					} else {
						report.checks = append(report.checks,
							fmt.Sprintf("recording rule %q uses %s() on %q which is a %s, not a counter",
								metric.Name, call.Func.Name, leaf, entries[0].Type))
					}
				}

				minRange := minSamplesForRate * scrapeInterval
				if ms.Range < minRange {
					report.checks = append(report.checks,
						fmt.Sprintf("recording rule %q uses %s() with range %s, need at least %s (>= %dx scrape_interval %s)",
							metric.Name, call.Func.Name,
							model.Duration(ms.Range),
							model.Duration(minRange),
							minSamplesForRate,
							model.Duration(scrapeInterval)))
				}
			}
			return nil
		})
	}
}

// checkCounterUsage detects counters used without rate()/irate()/increase().
func checkCounterUsage(report *selectorReport, rules map[string]ruleReport, lookupMetadata func(string) []v1.Metadata) {
	for _, metric := range report.Metrics {
		if metric.parsedExpr == nil {
			continue
		}

		flagged := make(map[string]bool)
		parser.Inspect(metric.parsedExpr, func(node parser.Node, path []parser.Node) error {
			vs, ok := node.(*parser.VectorSelector)
			if !ok {
				return nil
			}
			name := vectorSelectorName(vs)
			if name == "" || flagged[name] {
				return nil
			}

			if _, ok := rules[name]; ok {
				return nil
			}

			if isOptionalNode(node, path) {
				return nil
			}
			// Walk from innermost parent outward. The first aggregation or
			// function we encounter determines safety: rate()/count()/group()
			// etc. make the counter safe, but if we hit a non-safe aggregation
			// (like sum/max) first, the counter is used raw.
			counterSafe := false
			for i := len(path) - 1; i >= 0; i-- {
				parent := path[i]
				if call, ok := parent.(*parser.Call); ok {
					counterSafe = counterSafeFuncs[call.Func.Name]
					break
				}
				if aggr, ok := parent.(*parser.AggregateExpr); ok {
					counterSafe = counterSafeAggrs[aggr.Op.String()]
					break
				}
			}
			if counterSafe {
				return nil
			}

			entries := lookupMetadata(name)
			if len(entries) == 0 {
				return nil
			}

			var types []string
			hasCounter, allCounter := false, true
			for _, m := range entries {
				types = append(types, string(m.Type))
				if m.Type == v1.MetricTypeCounter {
					hasCounter = true
				} else {
					allCounter = false
				}
			}
			if !hasCounter {
				return nil
			}

			if allCounter {
				report.checks = append(report.checks,
					fmt.Sprintf("recording rule %q uses counter %q without rate()/increase(), raw counter values reset on restart and grow unbounded, making them meaningless as-is",
						metric.Name, name))
			} else {
				report.checks = append(report.checks,
					fmt.Sprintf("recording rule %q uses %q (conflicting types: %s) without rate(), consider rate() if it is a counter",
						metric.Name, name, strings.Join(types, ", ")))
			}
			flagged[name] = true
			return nil
		})
	}
}

func vectorSelectorName(vs *parser.VectorSelector) string {
	if vs.Name != "" {
		return vs.Name
	}
	for _, m := range vs.LabelMatchers {
		if m.Name == labels.MetricName && m.Type == labels.MatchEqual {
			return m.Value
		}
	}
	return ""
}

// outermostAggregation returns the outermost aggregation in expr (e.g.
// "sum" for sum(rate(...))), or "" if the expression isn't an aggregation.
func outermostAggregation(expr parser.Expr) string {
	switch n := expr.(type) {
	case *parser.AggregateExpr:
		return n.Op.String()
	case *parser.ParenExpr:
		return outermostAggregation(n.Expr)
	default:
		return ""
	}
}

// acceptedSuffixes returns the operations that are valid as a name suffix.
// The outermost operation is always first. For sum(rate/irate/increase),
// the inner rate-like op is also accepted since sum can be omitted per
// https://prometheus.io/docs/practices/rules/.
// Returns nil when no known suffix applies.
func acceptedSuffixes(expr parser.Expr) []string {
	outer := outermostOp(expr)
	if outer == "" {
		return nil
	}
	if aggr, ok := unwrapParens(expr).(*parser.AggregateExpr); ok && aggr.Op == parser.SUM {
		if inner := innerRateLikeOp(aggr.Expr); inner != "" {
			return []string{outer, inner}
		}
	}
	return []string{outer}
}

func unwrapParens(expr parser.Expr) parser.Expr {
	if p, ok := expr.(*parser.ParenExpr); ok {
		return unwrapParens(p.Expr)
	}
	return expr
}

// outermostOp returns the outermost known operation name, or "".
func outermostOp(expr parser.Expr) string {
	switch n := expr.(type) {
	case *parser.AggregateExpr:
		return n.Op.String()
	case *parser.Call:
		switch n.Func.Name {
		case "rate", "irate", "increase", "histogram_quantile":
			return n.Func.Name
		}
	case *parser.BinaryExpr:
		if n.Op == parser.DIV {
			return "ratio"
		}
	case *parser.ParenExpr:
		return outermostOp(n.Expr)
	}
	return ""
}

// innerRateLikeOp returns rate/irate/increase if the expression directly
// contains one of those, or "" otherwise. Only these qualify for the
// "sum can be omitted" convention.
func innerRateLikeOp(expr parser.Expr) string {
	switch n := expr.(type) {
	case *parser.Call:
		switch n.Func.Name {
		case "rate", "irate", "increase":
			return n.Func.Name
		}
	case *parser.ParenExpr:
		return innerRateLikeOp(n.Expr)
	}
	return ""
}

// resolveLeafMetrics follows recording rule chains and returns the raw
// scraped metrics the expression depends on. Skips absent() guards.
func resolveLeafMetrics(expression string, rules map[string]ruleReport, visited map[string]bool) []string {
	expr, err := parser.ParseExpr(expression)
	if err != nil {
		return nil
	}

	var leaves []string
	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		vs, ok := node.(*parser.VectorSelector)
		if !ok {
			return nil
		}
		if isOptionalNode(node, path) {
			return nil
		}
		name := vectorSelectorName(vs)
		if name == "" || visited[name] {
			return nil
		}
		visited[name] = true
		if rule, ok := rules[name]; ok {
			leaves = append(leaves, resolveLeafMetrics(rule.Expr, rules, visited)...)
		} else {
			leaves = append(leaves, name)
		}
		return nil
	})
	return leaves
}

// buildDepTree builds a visual dependency tree for a recording rule.
func buildDepTree(expression string, rules map[string]ruleReport, visited, seen map[string]bool, branch treeprint.Tree, querySeries func(string) model.Vector, peakCount func(string) int, queryValueRange func(string) (float64, float64), includeValueRange bool) {
	expr, err := parser.ParseExpr(expression)
	if err != nil {
		return
	}

	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		vs, ok := node.(*parser.VectorSelector)
		if !ok {
			return nil
		}
		name := vectorSelectorName(vs)
		rule, isRule := rules[name]
		if name != "" && isRule {
			selector := vs.String()
			var valueRangeStr string
			if includeValueRange {
				mn, mx := queryValueRange(selector)
				valueRangeStr = formatValueRange(mn, mx)
			}
			label := prettyRuleLabel(selector, rule.Expr, peakCount(selector), rule.File, valueRangeStr)
			child := branch.AddBranch(label)
			if !visited[name] {
				visited[name] = true
				buildDepTree(rule.Expr, rules, visited, seen, child, querySeries, peakCount, queryValueRange, false)
			}
			return nil
		}

		selector := vs.String()
		if seen[selector] {
			return nil
		}
		seen[selector] = true
		vec := querySeries(selector)
		var lsets []model.LabelSet
		for _, s := range vec {
			lsets = append(lsets, model.LabelSet(s.Metric))
		}
		var valueRangeStr string
		if includeValueRange {
			mn, mx := queryValueRange(selector)
			valueRangeStr = formatValueRange(mn, mx)
		}
		branch.AddNode(rawMetricTreeLabel(selector, lsets, peakCount(selector), valueRangeStr))
		return nil
	})
}

func treeToBlock(tree treeprint.Tree) string {
	_, body, _ := strings.Cut(strings.TrimRight(tree.String(), "\n"), "\n")
	return body
}

func prettyRuleLabel(name, expression string, peakSeries int, file string, valueRange string) string {
	pretty := strings.ReplaceAll(prettyExpr(expression), "\n", "\n    ")
	if valueRange != "" {
		return fmt.Sprintf("%s\n  <expr: %s>\n  <value_range: %s> <peak_series: %d> <file: %s>", name, pretty, valueRange, peakSeries, file)
	}
	return fmt.Sprintf("%s\n  <expr: %s>\n  <peak_series: %d> <file: %s>", name, pretty, peakSeries, file)
}

// prettyExpr returns a nicely formatted PromQL expression. Pretty(0) may
// add leading spaces, so we strip and de-indent uniformly.
func prettyExpr(expr string) string {
	parsed, err := parser.ParseExpr(expr)
	if err != nil {
		return strings.Join(strings.Fields(expr), " ")
	}
	s := parsed.Pretty(0)
	indent := s[:len(s)-len(strings.TrimLeft(s, " "))]
	if indent == "" {
		return s
	}
	return strings.ReplaceAll(strings.TrimPrefix(s, indent), "\n"+indent, "\n")
}

func rawMetricTreeLabel(name string, series []model.LabelSet, peakSeries int, valueRange string) string {
	jobs := make(map[string]bool)
	for _, ls := range series {
		if j, ok := ls["job"]; ok {
			jobs[string(j)] = true
		}
	}
	var parts []string
	jobStr := strings.Join(slices.Sorted(maps.Keys(jobs)), ", ")
	if jobStr != "" {
		parts = append(parts, fmt.Sprintf("<job: %s>", jobStr))
	}
	if valueRange != "" {
		parts = append(parts, fmt.Sprintf("<value_range: %s>", valueRange))
	}
	parts = append(parts, fmt.Sprintf("<peak_series: %d>", peakSeries))
	return fmt.Sprintf("%s\n  %s", name, strings.Join(parts, " "))
}

func sliceToSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

// suggestFix returns a short example showing how to restrict a label.
func suggestFix(labelName string) string {
	if labelName == labels.MetricName {
		return ", split into one selector per metric"
	}
	return fmt.Sprintf(", e.g. %s=~\"val1|val2\"", labelName)
}

func downloadConfigFile(url string) ([]configEntry, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseConfigData(data)
}

func parseConfigData(data []byte) ([]configEntry, error) {
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(data, &cm); err != nil {
		return nil, fmt.Errorf("parsing configmap: %w", err)
	}

	metricsYAML, ok := cm.Data["metrics.yaml"]
	if !ok {
		return nil, fmt.Errorf("no metrics.yaml key in configmap data")
	}

	return parseConfigEntries(metricsYAML)
}

func parseConfigEntries(metricsYAML string) ([]configEntry, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(metricsYAML), &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("unexpected YAML structure")
	}

	mapping := doc.Content[0]
	var seq *yaml.Node
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "matches" {
			seq = mapping.Content[i+1]
			break
		}
	}
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("no matches sequence found")
	}

	var entries []configEntry
	for _, item := range seq.Content {
		entries = append(entries, configEntry{Selector: item.Value})
	}

	return entries, nil
}

// extractSelectorMetricNames returns the metric names matched by a selector.
// Uses SetMatches() for bounded regexes, falls back to scanning all rules.
func extractSelectorMetricNames(selector string, rules map[string]ruleReport) []string {
	matchers, err := parser.ParseMetricSelector(selector)
	if err != nil {
		return nil
	}
	var nameMatcher *labels.Matcher
	for _, m := range matchers {
		if m.Name == labels.MetricName {
			nameMatcher = m
			break
		}
	}
	if nameMatcher == nil {
		return nil
	}

	switch nameMatcher.Type {
	case labels.MatchEqual:
		return []string{nameMatcher.Value}
	case labels.MatchRegexp:
		if sm := nameMatcher.SetMatches(); len(sm) > 0 {
			return sm
		}
		var names []string
		for name := range rules {
			if nameMatcher.Matches(name) {
				names = append(names, name)
			}
		}
		return names
	default:
		return nil
	}
}

// leafMetricSet returns the raw scraped metrics a metric depends on.
func leafMetricSet(metricName string, rules map[string]ruleReport) map[string]bool {
	if rule, ok := rules[metricName]; ok {
		return sliceToSet(resolveLeafMetrics(rule.Expr, rules, map[string]bool{metricName: true}))
	}
	return map[string]bool{metricName: true}
}

// checkLeafOverlap flags metrics whose leaf dependencies exactly match another
// metric already in the telemetry config (excluding the passed selectors).
// See also checkAlertOverlap which does the same comparison against alerts.
func checkLeafOverlap(report *selectorReport, rules map[string]ruleReport, configEntries []configEntry, passedSelectors []string) {
	passedSet := sliceToSet(passedSelectors)

	type existingMetric struct {
		name     string
		selector string
		leaves   map[string]bool
	}
	var existing []existingMetric

	for _, ce := range configEntries {
		if passedSet[ce.Selector] {
			continue
		}
		for _, name := range extractSelectorMetricNames(ce.Selector, rules) {
			leaves := leafMetricSet(name, rules)
			if len(leaves) == 0 {
				continue
			}
			existing = append(existing, existingMetric{
				name:     name,
				selector: ce.Selector,
				leaves:   leaves,
			})
		}
	}

	for _, metric := range report.Metrics {
		newLeaves := leafMetricSet(metric.Name, rules)
		if len(newLeaves) == 0 {
			continue
		}

		for _, em := range existing {
			if em.name == metric.Name {
				continue
			}
			if maps.Equal(newLeaves, em.leaves) {
				sortedLeaves := slices.Sorted(maps.Keys(newLeaves))
				report.checks = append(report.checks,
					fmt.Sprintf("metric %q shares the same leaf metrics (%s) as existing selector %s, consider whether this is redundant",
						metric.Name, strings.Join(sortedLeaves, ", "), em.selector))
			}
		}
	}
}
