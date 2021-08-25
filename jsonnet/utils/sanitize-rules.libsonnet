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
    name: 'general.rules',
    rules: [
      {
        alert: 'Watchdog',
        labels: {
          // All OpenShift alerts should include a namespace label.
          // See: https://issues.redhat.com/browse/MON-939
          namespace: 'openshift-monitoring',
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
    name: 'kubernetes-resources',
    rules: [
      // The expression for these alerts are cross-namespace, but all OpenShift
      // alerts should include a namespace label for routing purposes, so we set
      // one statically here.
      //
      // See: https://issues.redhat.com/browse/MON-939
      {
        alert: 'KubeCPUOvercommit',
        labels: {
          namespace: 'kube-system',
        },
      },
      {
        alert: 'KubeMemoryOvercommit',
        labels: {
          namespace: 'kube-system',
        },
      },
    ],
  },
  {
    name: 'kubernetes-system-kubelet',
    rules: [
      // Similar to above, the expression for this alert uses 'absent()' and
      // doesn't include a namespace label, so we set one statically.
      //
      // See: https://issues.redhat.com/browse/MON-939
      {
        alert: 'KubeletDown',
        labels: {
          namespace: 'kube-system',
        },
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
  else if (('alert' in rule && 'alert' in ruleSet[0]) && std.startsWith(rule.alert, ruleSet[0].alert)) ||
          (('record' in rule && 'record' in ruleSet[0]) && std.startsWith(rule.record, ruleSet[0].record)) then
    if operation == 'patch' then
      local patch = {
        [k]: ruleSet[0][k]
        for k in std.objectFields(ruleSet[0])
        if k != 'alert' && k != 'record'
      };
      [std.mergePatch(rule, patch)]
    else
      []
  else
    [] + patchOrExcludeRule(rule, ruleSet[1:], operation);

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
