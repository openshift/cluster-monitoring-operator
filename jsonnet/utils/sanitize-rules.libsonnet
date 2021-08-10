local k8sMixinUtils = import 'github.com/kubernetes-monitoring/kubernetes-mixin/lib/utils.libsonnet';

local excludedRuleGroups = [
  'kube-apiserver-availability.rules',
  // rules managed by openshift/cluster-kube-controller-manager-operator.
  'kubernetes-system-controller-manager',
  // rules managed by openshift/cluster-kube-scheduler-operator.
  'kubernetes-system-scheduler',
  // rules managed by openshift/cluster-kube-apiserver-operator.
  'kube-apiserver-slos',
  'kube-apiserver.rules',
  'kube-apiserver-burnrate.rules',
];

local excludedRules = [
  {
    name: 'alertmanager.rules',
    rules: [
      { alert: 'AlertmanagerClusterCrashlooping' },
    ],
  },
  {
    name: 'general.rules',
    rules: [
      { alert: 'TargetDown' },
    ],
  },
  {
    name: 'kubernetes-system',
    rules: [
      { alert: 'KubeVersionMismatch' },
    ],
  },
  {
    name: 'kubernetes-resources',
    rules: [
      // Removing CPUThrottlingHigh alert as per https://bugzilla.redhat.com/show_bug.cgi?id=1843346
      { alert: 'CPUThrottlingHigh' },
    ],
  },
  {
    name: 'kubernetes-system-apiserver',
    rules: [
      // KubeClientCertificateExpiration alert isn't
      // actionable because the cluster admin has no way to
      // prevent a client from using an expird certificate.
      { alert: 'KubeClientCertificateExpiration' },
    ],
  },
  {
    name: 'kubernetes-system-kubelet',
    rules: [
      // Kubelet*CertificateExpiration alerts are based on absolute thresholds which
      // make them prone to failures (e.g. if the lifetime of the certificate is
      // decreased, the alert might fire while everything is fine).
      // In addition we have alerts to detect that a Kubelet
      // can't renew its certificates which makes it redundant
      // to alert on certificates being almost expired.
      // See https://coreos.slack.com/archives/CB48XQ4KZ/p1603712568136500.
      { alert: 'KubeletClientCertificateExpiration' },
      { alert: 'KubeletServerCertificateExpiration' },
    ],
  },
  {
    name: 'kubernetes-apps',
    rules: [
      { alert: 'KubeDeploymentReplicasMismatch' },
    ],
  },
  {
    name: 'prometheus',
    rules: [
      { alert: 'PrometheusErrorSendingAlertsToAnyAlertmanager' },
    ],
  },
  {
    name: 'thanos-query',
    rules: [
      { alert: 'ThanosQueryInstantLatencyHigh' },
      { alert: 'ThanosQueryRangeLatencyHigh' },
    ],
  },
];

local patchedRules = [
  {
    name: 'alertmanager.rules',
    rules: [
      {
        alert: 'AlertmanagerMembersInconsistent',
        labels: {
          severity: 'warning',
        },
      },
      {
        alert: 'AlertmanagerClusterFailedToSendAlerts',
        labels: {
          severity: 'warning',
        },
      },
      {
        alert: 'AlertmanagerConfigInconsistent',
        labels: {
          severity: 'warning',
        },
      },
      {
        alert: 'AlertmanagerClusterDown',
        labels: {
          severity: 'warning',
        },
      },
    ],
  },
  {
    name: 'kubernetes-apps',
    rules: [
      // Stop-gap fix for https://bugzilla.redhat.com/show_bug.cgi?id=1943667
      {
        alert: 'KubeDaemonSetRolloutStuck',
        annotations: {
          description: 'DaemonSet {{ $labels.namespace }}/{{ $labels.daemonset }} has not finished or progressed for at least 30 minutes.',
        },
        'for': '30m',
      },
    ],
  },
  {
    name: 'kube-state-metrics',
    rules: [
      {
        alert: 'KubeStateMetricsListErrors',
        labels: {
          severity: 'warning',
        },
      },
      {
        alert: 'KubeStateMetricsWatchErrors',
        labels: {
          severity: 'warning',
        },
      },
    ],
  },
  {
    name: 'kubernetes-storage',
    local kubernetesStorageConfig = { prefixedNamespaceSelector: 'namespace=~"(openshift-.*|kube-.*|default)",', kubeletSelector: 'job="kubelet", metrics_path="/metrics"' },
    rules: [
      {
        alert: 'KubePersistentVolumeErrors',
        labels: {
          severity: 'warning',
        },
      },
      {
        alert: 'KubePersistentVolumeFillingUp',
        expr: |||
          (
            kubelet_volume_stats_available_bytes{%(prefixedNamespaceSelector)s%(kubeletSelector)s}
              /
            kubelet_volume_stats_capacity_bytes{%(prefixedNamespaceSelector)s%(kubeletSelector)s}
          ) < 0.03
          and
          kubelet_volume_stats_used_bytes{%(prefixedNamespaceSelector)s%(kubeletSelector)s} > 0
        ||| % kubernetesStorageConfig,
        'for': '5m',
        labels: {
          severity: 'critical',
        },
      },
      {
        alert: 'KubePersistentVolumeFillingUp',
        labels: {
          severity: 'warning',
        },
      },
    ],
  },
  {
    name: 'node-exporter',
    local nodeExporterConfig = { nodeExporterSelector: 'job="node-exporter"', fsSelector: 'fstype!=""', fsSpaceFillingUpCriticalThreshold: 15 },
    rules: [
      {
        alert: 'NodeFilesystemSpaceFillingUp',
        expr: |||
          (
            node_filesystem_avail_bytes{%(nodeExporterSelector)s,%(fsSelector)s} / node_filesystem_size_bytes{%(nodeExporterSelector)s,%(fsSelector)s} * 100 < %(fsSpaceFillingUpCriticalThreshold)d
          and
            predict_linear(node_filesystem_avail_bytes{%(nodeExporterSelector)s,%(fsSelector)s}[6h], 2*60*60) < 0
          and
            node_filesystem_readonly{%(nodeExporterSelector)s,%(fsSelector)s} == 0
          )
        ||| % nodeExporterConfig,
        'for': '1h',
        labels: {
          severity: 'critical',
        },
      },
      {
        alert: 'NodeFilesystemSpaceFillingUp',
        labels: {
          severity: 'warning',
        },
      },
      {
        alert: 'NodeFilesystemFilesFillingUp',
        expr: |||
          (
            node_filesystem_files_free{%(nodeExporterSelector)s,%(fsSelector)s} / node_filesystem_files{%(nodeExporterSelector)s,%(fsSelector)s} * 100 < 20
          and
            predict_linear(node_filesystem_files_free{%(nodeExporterSelector)s,%(fsSelector)s}[6h], 2*60*60) < 0
          and
            node_filesystem_readonly{%(nodeExporterSelector)s,%(fsSelector)s} == 0
          )
        ||| % nodeExporterConfig,
        'for': '1h',
        labels: {
          severity: 'critical',
        },
      },
      {
        alert: 'NodeFilesystemFilesFillingUp',
        labels: {
          severity: 'warning',
        },
      },
    ],
  },
  {
    name: 'prometheus',
    rules: [
      {
        alert: 'PrometheusDuplicateTimestamps',
        'for': '1h',
      },
      {
        alert: 'PrometheusOutOfOrderTimestamps',
        'for': '1h',
      },
      {
        alert: 'PrometheusBadConfig',
        labels: {
          severity: 'warning',
        },
      },
      {
        alert: 'PrometheusRemoteStorageFailures',
        expr: |||
          (
            (rate(prometheus_remote_storage_failed_samples_total{%(prometheusSelector)s}[5m]) or rate(prometheus_remote_storage_samples_failed_total{%(prometheusSelector)s}[5m]))
          /
            (
              (rate(prometheus_remote_storage_failed_samples_total{%(prometheusSelector)s}[5m]) or rate(prometheus_remote_storage_samples_failed_total{%(prometheusSelector)s}[5m]))
            +
              (rate(prometheus_remote_storage_succeeded_samples_total{%(prometheusSelector)s}[5m]) or rate(prometheus_remote_storage_samples_total{%(prometheusSelector)s}[5m]))
            )
          )
          * 100
          > 10
        ||| % { prometheusSelector: 'job=~"prometheus-k8s|prometheus-user-workload"' },
        'for': '15m',
        labels: {
          severity: 'warning',
        },

      },
      {
        alert: 'PrometheusRuleFailures',
        labels: {
          severity: 'warning',
        },
      },
      {
        alert: 'PrometheusRemoteWriteBehind',
        labels: {
          severity: 'info',
        },
      },
    ],
  },
  {
    name: 'thanos-rule',
    rules: [
      {
        alert: 'ThanosNoRuleEvaluations',
        labels: {
          severity: 'warning',
        },
      },
      {
        alert: 'ThanosRuleHighRuleEvaluationFailures',
        labels: {
          severity: 'warning',
        },
      },
      {
        alert: 'ThanosRuleSenderIsFailingAlerts',
        labels: {
          severity: 'warning',
        },
      },
    ],
  },
  {
    name: 'thanos-sidecar',
    rules: [
      {
        alert: '',
        'for': '1h',
        labels: {
          severity: 'warning',
        },
      },
    ],
  },
  {
    name: 'thanos-query',
    rules: [
      {
        alert: '',
        'for': '1h',
        labels: {
          severity: 'warning',
        },
      },
    ],
  },
];

// TODO(paulfantom): ideally all alerts have runbooks and this list could be converted into excludeRunbooks
local includeRunbooks = [
  'HighlyAvailableWorkloadIncorrectlySpread',
];

local removeRunbookUrl(rule) = rule {
  [if 'alert' in rule && ('runbook_url' in rule.annotations) && !std.member(includeRunbooks, rule.alert) then 'annotations']+: {
    runbook_url:: null,
  },
};

local patchOrExcludeRule(rule, ruleSet, operation) =
  if std.length(ruleSet) == 0 then
    [rule]
  else if ('alert' in rule) then
    // empty alert name is matching-all
    local matchedRules = std.filter(function(ruleItem) ('alert' in ruleItem) && ((ruleItem.alert == rule.alert) || (ruleItem.alert == '')), ruleSet);
    local matchedRulesSeverity = std.filter(function(ruleItem) if ('labels' in ruleItem) && ('severity' in ruleItem.labels) then ruleItem.labels.severity == rule.labels.severity else false, matchedRules);

    if std.length(matchedRules) > 1 && std.length(matchedRulesSeverity) >= 1 then
      local targetRule = matchedRulesSeverity[0];
      if operation == 'patch' then
        local patch = {
          [k]: targetRule[k]
          for k in std.objectFields(targetRule)
          if k != 'alert' && k != 'record'
        };
        [std.mergePatch(rule, patch)]
      else if operation == 'exclude' then
        []
      else
        assert false : 'operation not support ' + operation;
        []

    else if std.length(matchedRules) > 1 && std.length(matchedRulesSeverity) == 0 then
      assert false : 'Duplicated patch rules without matching severity for rule: ' + std.toString(rule);
      []
    else if std.length(matchedRules) == 1 && std.length(matchedRulesSeverity) <= 1 then
      local targetRule = matchedRules[0];
      if operation == 'patch' then
        local patch = {
          [k]: targetRule[k]
          for k in std.objectFields(targetRule)
          if k != 'alert' && k != 'record'
        };
        [std.mergePatch(rule, patch)]
      else if operation == 'exclude' then
        []
      else
        assert false : 'operation not support ' + operation;
        []

    else
      [rule]
  else if ('record' in rule) then
    // empty record name is matching-all
    local matchedRules = std.filter(function(ruleItem) ('record' in ruleItem) && ((ruleItem.record == rule.record) || (ruleItem.record == '')), ruleSet);

    if std.length(matchedRules) == 1 then
      local targetRule = matchedRules[0];
      if operation == 'patch' then
        local patch = {
          [k]: targetRule[k]
          for k in std.objectFields(targetRule)
          if k != 'alert' && k != 'record'
        };
        [std.mergePatch(rule, patch)]
      else
        []
    else if std.length(matchedRules) > 1 then
      assert false : 'Duplicated patch for record rules: ' + std.toString(rule) + ' matching patches: ' + std.toString(matchedRules);
      []
    else
      [rule]

  else
    // neither alert nor record rule, leave it as is
    [rule];


local patchOrExcludeRuleGroup(group, groupSet, operation) =
  if std.length(groupSet) == 0 then
    [group.rules]
  else if (group.name == groupSet[0].name) then
    [patchOrExcludeRule(rule, groupSet[0].rules, operation) for rule in group.rules]
  else
    [] + patchOrExcludeRuleGroup(group, groupSet[1:], operation);

{
  excludeRule(o): o {
    [if (o.kind == 'PrometheusRule') then 'spec']+: {
      groups: std.filterMap(
        function(group) !std.member(excludedRuleGroups, group.name),
        function(group)
          group {
            rules: std.flattenArrays(
              patchOrExcludeRuleGroup(group, excludedRules, 'exclude')
            ),
          },
        super.groups,
      ),
    },
  },

  patchRule(o): o {
    [if (o.kind == 'PrometheusRule') then 'spec']+: {
      groups: std.map(
        function(group)
          group {
            rules: std.flattenArrays(
              patchOrExcludeRuleGroup(group, patchedRules, 'patch')
            ),
          },
        super.groups,
      ),
    },
  },

  removeRunbookUrls(o): o {
    [if (o.kind == 'PrometheusRule') then 'spec']+: k8sMixinUtils.mapRuleGroups(removeRunbookUrl),
  },

  // excludedRules removes upstream rules that we don't want to carry in CMO.
  // It can remove specific rules from a rules group (see excludedRules) or a
  // whole rules group (see excludedRuleGroups).
  excludeRules(o): {
    [k]: $.excludeRule(o[k])
    for k in std.objectFields(o)
  },

  // patchRules adapts upstream rules to comply with OpenShift requirements
  // (such as extending the for duration, changing alert severity, and so on).
  // The patches are defined in the patchedRules array where each item contains
  // the name of the affected group and the list of patches keyed by their
  // 'alert' or 'record' identifier. The function will apply the patch to every
  // alerting/recording rule in the group whose name starts by the identifier.
  patchRules(o): {
    [k]: $.patchRule(o[k])
    for k in std.objectFields(o)
  },

  // shorthand for rule patching, rule excluding, and runbook_url removal
  sanitizeAlertRules(o): {
    [k]: $.removeRunbookUrls($.patchRule($.excludeRule(o[k])))
    for k in std.objectFields(o)
  },
}
