// Copyright 2024 The Cluster Monitoring Operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

var testdataDir = filepath.Join("..", "..", "hack", "telemetry_report", "testdata")

func TestTelemetryReport(t *testing.T) {
	ctx := context.Background()

	data, err := os.ReadFile(filepath.Join(testdataDir, "prometheusrule.yaml"))
	require.NoError(t, err)
	var rule monitoringv1.PrometheusRule
	require.NoError(t, yaml.Unmarshal(data, &rule))

	require.NoError(t, f.OperatorClient.CreateOrUpdatePrometheusRule(ctx, &rule))
	t.Cleanup(func() {
		require.NoError(t, f.OperatorClient.DeletePrometheusRuleByNamespaceAndName(ctx, rule.Namespace, rule.Name))
	})

	binary := buildTelemetryReport(t)

	host, cleanup, err := f.ForwardPodPort(t, f.Ns, "prometheus-k8s-0", 9090)
	require.NoError(t, err)
	t.Cleanup(cleanup)
	promURL := fmt.Sprintf("http://%s", host)

	// Wait for recording rules to produce data: a trivial one and a
	// rate()-based one that needs multiple scrape cycles. The extra sleep
	// gives the remaining rules time to evaluate through their chains.
	waitForQuery(t, promURL, "e2etelemetry:const_one:gauge", 5*time.Minute)
	waitForQuery(t, promURL, "e2etelemetry:etcd_wal_fsync:deep_rate", 5*time.Minute)
	time.Sleep(30 * time.Second)

	tests := map[string]string{
		"selector_issues":         `{__name__=~"e2etelemetry:etcd_has_leader:max|e2etelemetry:etcd:total|e2etelemetry:etcd_has_leader:max", extra!="gone", extra!~"prod", extra2=~"foo", extra3="", extra4=~"val.+"}`,
		"suffix_mismatch":         `{__name__=~"e2etelemetry:etcd_has_leader:wrong_sum|e2etelemetry:etcd_wal_fsync:wrong_ratio|e2etelemetry:process_cpu:sum_total|e2etelemetry:suffix_ok:rate|e2etelemetry:suffix_ok:sum|e2etelemetry:suffix_ok:rate5m|e2etelemetry:etcd_wal_fsync:wrong_max|e2etelemetry:suffix_max_rate:rate5m|e2etelemetry:suffix_sum_increase:increase1h|e2etelemetry:suffix_div:sum"}`,
		"deep_chain":              `{__name__="e2etelemetry:chain_top:max"}`,
		"rate_issues":             `{__name__=~"e2etelemetry:etcd_has_leader:rate_gauge|e2etelemetry:etcd_wal_fsync:deep_rate|e2etelemetry:etcd_wal_fsync:rate_short|e2etelemetry:etcd_wal_fsync_sum:rate|e2etelemetry:process_cpu_seconds:max"}`,
		"edge_cases":              `{__name__=~"e2etelemetry:cycle_a:sum|e2etelemetry:self_ref:sum|e2etelemetry:regex_inner:sum|e2etelemetry:no_metrics:gauge|e2etelemetry:counter_mixed:sum|e2etelemetry:process_cpu_seconds_total:max|e2etelemetry:chained_unless:max|e2etelemetry:dead_lhs_and:test"}`,
		"peak_series_consistency": `{__name__=~"e2etelemetry:const_one:gauge|e2etelemetry:const_zero:gauge|e2etelemetry:const_multi:gauge|e2etelemetry:const_dead:sum"}`,
		"matcher_aware":           `{__name__=~"e2etelemetry:etcd_job_exists:max|e2etelemetry:etcd_job_ghost:max|e2etelemetry:etcd_job_mixed:sum"}`,
		"multi_definition":        `{__name__="e2etelemetry:etcd_multi_def:max"}`,
		"sum_over_bool":           `{__name__=~"e2etelemetry:sum_allone:sum|e2etelemetry:sum_mixed:sum|e2etelemetry:max_allone:max|e2etelemetry:sum_bool_eq:gauge"}`,
	}

	for name, selector := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out, err := exec.Command(binary, promURL, selector).CombinedOutput()
			require.Error(t, err, string(out))

			golden, err := os.ReadFile(filepath.Join(testdataDir, name+".txt"))
			require.NoError(t, err)
			matchGolden(t, string(out), string(golden))
		})
	}

	// Rule with 3 colons must trigger the colon-count naming check.
	t.Run("max_colons", func(t *testing.T) {
		t.Parallel()
		out, _ := exec.Command(binary, promURL, `{__name__="e2etelemetry:etcd:too:many_colons"}`).CombinedOutput()
		outStr := string(out)
		require.Contains(t, outStr, "needs exactly 2 colons for level:metric:operations")
	})

	// Leaf overlap message must list leaf metrics inline and suggest redundancy.
	t.Run("leaf_overlap_message_format", func(t *testing.T) {
		t.Parallel()
		out, _ := exec.Command(binary, promURL, `{__name__="e2etelemetry:config_overlap:sum"}`).CombinedOutput()
		outStr := string(out)
		require.Contains(t, outStr, "shares the same leaf metrics (up) as existing selector")
		require.Contains(t, outStr, "consider whether this is redundant")
	})

	// Leaf with conflicting type metadata (counter vs gauge) must be flagged.
	t.Run("metadata_conflicts_detected", func(t *testing.T) {
		t.Parallel()
		out, _ := exec.Command(binary, promURL, `{__name__="e2etelemetry:memstats_alloc:max"}`).CombinedOutput()
		outStr := string(out)
		require.Contains(t, outStr, `leaf metric "go_memstats_alloc_bytes" has conflicting type metadata:`)
	})

	// Report header must echo back all selectors on the same line.
	t.Run("config_args_header", func(t *testing.T) {
		t.Parallel()
		s1 := `{__name__="cluster_feature_set"}`
		s2 := `{__name__="e2etelemetry:etcd_has_leader:max"}`
		out, _ := exec.Command(binary, promURL, s1, s2).CombinedOutput()
		require.Contains(t, string(out), fmt.Sprintf("# args: %s %s", s1, s2))
	})

	// Metric sharing the same leaf set as a config selector must be flagged.
	t.Run("config_duplicate_detected", func(t *testing.T) {
		t.Parallel()
		out, _ := exec.Command(binary, promURL, `{__name__="e2etelemetry:config_overlap:sum"}`).CombinedOutput()
		require.Contains(t, string(out), "shares the same leaf metrics (up) as existing selector")
	})

	// Tested selector sharing a __name__ with the config must be flagged,
	// even when using alternation and extra matchers.
	t.Run("metric_already_in_config", func(t *testing.T) {
		t.Parallel()
		out, _ := exec.Command(binary, promURL, `{__name__=~"count:up0|e2etelemetry:nonexistent", extra="filter"}`).CombinedOutput()
		outStr := string(out)
		require.Contains(t, outStr, `metric "count:up0" is already in the telemetry config file`)
		require.NotContains(t, outStr, `metric "e2etelemetry:nonexistent" is already in the telemetry config file`)
	})

	// absent() in an "or" fallback must not be treated as a shared leaf.
	t.Run("absent_not_flagged_as_duplicate", func(t *testing.T) {
		t.Parallel()
		out, _ := exec.Command(binary, promURL, `{__name__="e2etelemetry:absent_fallback:ratio"}`).CombinedOutput()
		require.NotContains(t, string(out), "shares the same leaf metrics")
	})

	// Passing more selectors than the limit must produce a warning.
	t.Run("multi_selector_limits", func(t *testing.T) {
		t.Parallel()
		sels := []string{
			`{__name__="e2etelemetry:etcd_has_leader:max"}`,
			`{__name__="e2etelemetry:chain_top:max"}`,
			`{__name__="e2etelemetry:etcd_has_leader:wrong_sum"}`,
			`{__name__="e2etelemetry:process_cpu:sum_total"}`,
		}
		args := append([]string{promURL}, sels...)
		out, err := exec.Command(binary, args...).CombinedOutput()
		outStr := string(out)
		require.Error(t, err, outStr)
		require.Contains(t, outStr, fmt.Sprintf("# args: %s %s %s %s", sels[0], sels[1], sels[2], sels[3]))
		require.Contains(t, outStr, "4 selectors exceed limit of 3 per run, split by owner or merge related selectors")
	})
}

// matchGolden compares tool output against a golden file after normalizing
// the few fields that vary between environments: rule file UIDs (random
// suffix per apply), peak_series/value_range (depend on data age), and the
// TSDB-age note. Everything else (messages, counts, labels) is compared
// exactly.
func matchGolden(t *testing.T, got, golden string) {
	t.Helper()
	normalize := func(s string) string {
		s = regexp.MustCompile(`(file: )\S+\.yaml`).ReplaceAllString(s, "${1}RULEFILE")
		s = regexp.MustCompile(`peak_series: \d+`).ReplaceAllString(s, "peak_series: N")
		s = regexp.MustCompile(`value_range: [^\n>]+`).ReplaceAllString(s, "value_range: V")
		s = regexp.MustCompile(`(?m)^# NOTE: TSDB.*\n`).ReplaceAllString(s, "")
		return s
	}
	if n := normalize(got); n != normalize(golden) {
		t.Fatalf("output doesn't match golden file.\n\nnormalized got:\n%s", n)
	}
}

func buildTelemetryReport(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "telemetry_report")
	srcDir := filepath.Join("..", "..", "hack", "telemetry_report")
	out, err := exec.Command("go", "build", "-C", srcDir, "-mod=mod", "-o", binary, ".").CombinedOutput()
	require.NoError(t, err, "go build failed:\n%s", out)
	return binary
}

// waitForQuery polls Prometheus until the given instant query returns data.
func waitForQuery(t *testing.T, promURL, query string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	endpoint := promURL + "/api/v1/query?query=" + url.QueryEscape(query)
	for {
		resp, err := http.Get(endpoint)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 && !strings.Contains(string(body), `"result":[]`) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %q", timeout, query)
		}
		time.Sleep(5 * time.Second)
	}
}
