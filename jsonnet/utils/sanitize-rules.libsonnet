local k8sMixinUtils = import 'github.com/kubernetes-monitoring/kubernetes-mixin/lib/utils.libsonnet';

// List of rule groups which are dropped from the final manifests.
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
  'kube-apiserver-histogram.rules',
  // Availability of kube-proxy depends on the selected CNO plugin hence the
  // rules should be managed by CNO directly.
  'kubernetes-system-kube-proxy',
];

// List of rules which are dropped from the final manifests.
local excludedRules = [
  {
    name: 'alertmanager.rules',
    rules: [
      // Already covered by the KubePodCrashLooping alerting rules.
      { alert: 'AlertmanagerClusterCrashlooping' },
      //
      { alert: 'AlertmanagerClusterFailedToSendAlerts', severity: 'warning' },
    ],
  },
  {
    name: 'general.rules',
    rules: [
      // CMO ships a modified TargetDown alerting rule which is less noisy than upstream.
      { alert: 'TargetDown' },
      // We decided not to ship the InfoInhibitor alerting rule for now.
      { alert: 'InfoInhibitor' },
    ],
  },
  {
    name: 'kube-state-metrics',
    rules: [
      // We do not configure sharding for kube-state-metrics.
      { alert: 'KubeStateMetricsShardingMismatch' },
      { alert: 'KubeStateMetricsShardsMissing' },
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
      // Removing Kube*QuotaOvercommit alerts since quotas should not be defined
      // for system namespaces. Refer OCPBUGS-10699 for more details.
      { alert: 'KubeCPUQuotaOvercommit' },
      { alert: 'KubeMemoryQuotaOvercommit' },
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
      //
      // See https://coreos.slack.com/archives/CB48XQ4KZ/p1603712568136500.
      { alert: 'KubeletClientCertificateExpiration' },
      { alert: 'KubeletServerCertificateExpiration' },
    ],
  },
  {
    name: 'kubernetes-apps',
    rules: [
      // We ship a modified KubeDeploymentReplicasMismatch alerting rule which
      // takes into account the availability of the control plane nodes.
      { alert: 'KubeDeploymentReplicasMismatch' },
    ],
  },
  {
    name: 'prometheus',
    rules: [
      // PrometheusErrorSendingAlertsToAnyAlertmanager has a critical severity but it
      // can be noisy and we prefer to rely on the Watchdog alerting rule to detect
      // broken communication between Prometheus and Alertmanager.  We keep the
      // PrometheusErrorSendingAlertsToSomeAlertmanagers alerting rule with the
      // warning severity to help with root cause.
      //
      // Refer to https://bugzilla.redhat.com/show_bug.cgi?id=1986981 for details.
      { alert: 'PrometheusErrorSendingAlertsToAnyAlertmanager' },
    ],
  },
  // The following recording rules are removed due to lack of usefulness
  // Refer to https://bugzilla.redhat.com/show_bug.cgi?id=1996785 for details.
  {
    name: 'kube-prometheus-node-recording.rules',
    rules: [
      { record: 'instance:node_cpu:ratio' },
    ],
  },
  {
    name: 'node.rules',
    rules: [
      { record: 'node:node_num_cpu:sum' },
    ],
  },
  {
    name: 'openshift-kubernetes.rules',
    rules: [
      { record: 'namespace:container_spec_cpu_shares:sum' },
      { record: 'pod:container_memory_usage_bytes:sum' },
      { record: 'pod:container_spec_cpu_shares:sum' },
    ],
  },
  {
    name: 'thanos-query',
    rules: [
      // We have no SLO on the Thanos querier API service.
      { alert: 'ThanosQueryInstantLatencyHigh' },
      { alert: 'ThanosQueryRangeLatencyHigh' },
    ],
  },
  {
    name: 'node-exporter',
    rules: [
      // NodeCPUHighUsage, NodeMemoryHighUtilization and NodeDiskIOSaturation
      // are removed because they are irrelevant for environments where it is
      // fine to have over/fully utilized nodes.
      { alert: 'NodeCPUHighUsage' },
      { alert: 'NodeMemoryHighUtilization' },
      { alert: 'NodeDiskIOSaturation' },
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
    name: 'node-exporter',
    rules: [
      {
        // When the PTP operator is installed, it provides a more reliable and accurate
        // alerting rule to detect unsynchronized clocks. The NodeClockNotSynchronising
        // alerting rule is patched to never become active in this case.
        // See https://issues.redhat.com/browse/MON-3544
        alert: 'NodeClockNotSynchronising',
        expr: function(o)
          std.format('(\n%(expr)s) and on() absent(up{job="ptp-monitor-service"})', o)
        ,
        labels: {
          severity: 'critical',
        },
      },
      {
        // See previous item.
        alert: 'NodeClockSkewDetected',
        expr: function(o)
          std.format('(\n%(expr)s) and on() absent(up{job="ptp-monitor-service"})', o),
      },
      {
        // Extend the upstream for duration to reduce alert noise.
        alert: 'NodeSystemdServiceFailed',
        'for': '15m',
      },
    ],
  },
  {
    name: 'kubernetes-apps',
    rules: [
      // On clusters with few nodes, the number of daemonset instances being
      // unavailable may not change during more than 15 minutes while the
      // rollout is making progress.
      // See https://bugzilla.redhat.com/show_bug.cgi?id=1943667
      {
        alert: 'KubeDaemonSetRolloutStuck',
        annotations: {
          description: 'DaemonSet {{ $labels.namespace }}/{{ $labels.daemonset }} has not finished or progressed for at least 30 minutes.',
        },
        'for': '30m',
      },
      // This patches the alert KubePodNotReady to exclude pods with 'Failed' phase.
      // This should be removed after the resolution of the bug TRT-589:
      // https://issues.redhat.com/browse/TRT-589
      {
        alert: 'KubePodNotReady',
        expr: |||
          sum by (namespace, pod, cluster) (
            max by(namespace, pod, cluster) (
              kube_pod_status_phase{%(prefixedNamespaceSelector)s, %(kubeStateMetricsSelector)s, phase=~"Pending|Unknown"}
              unless ignoring(phase) (kube_pod_status_unschedulable{%(kubeStateMetricsSelector)s} == 1)
            ) * on(namespace, pod, cluster) group_left(owner_kind) topk by(namespace, pod, cluster) (
              1, max by(namespace, pod, owner_kind, cluster) (kube_pod_owner{owner_kind!="Job"})
            )
          ) > 0
        ||| % {
          prefixedNamespaceSelector: 'namespace=~"(openshift-.*|kube-.*|default)"',
          kubeStateMetricsSelector: 'job="kube-state-metrics"',
        },
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
      // All OpenShift alerts should include a namespace label.
      //
      // See https://issues.redhat.com/browse/OCPBUGS-17191
      {
        alert: 'KubeletTooManyPods',
        labels: {
          namespace: 'kube-system',
        },
      },
      {
        alert: 'KubeletPlegDurationHigh',
        labels: {
          namespace: 'kube-system',
        },
      },
      {
        alert: 'KubeletPodStartUpLatencyHigh',
        labels: {
          namespace: 'kube-system',
        },
      },
      {
        alert: 'KubeNodeReadinessFlapping',
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
          // All OpenShift alerts should include a namespace label.
          //
          // See https://issues.redhat.com/browse/OCPBUGS-17191
          namespace: 'openshift-monitoring',
        },
      },
      {
        alert: 'KubeStateMetricsWatchErrors',
        labels: {
          severity: 'warning',
          // All OpenShift alerts should include a namespace label.
          //
          // See https://issues.redhat.com/browse/OCPBUGS-17191
          namespace: 'openshift-monitoring',
        },
      },
    ],
  },
  {
    name: 'kubernetes-storage',
    local kubernetesStorageConfig = { prefixedNamespaceSelector: 'namespace=~"(openshift-.*|kube-.*|default)",', kubeletSelector: 'job="kubelet", metrics_path="/metrics"' },
    rules: [
      {
        // Refer to https://bugzilla.redhat.com/show_bug.cgi?id=1986981 for details.
        alert: 'KubePersistentVolumeErrors',
        labels: {
          severity: 'warning',
        },
      },
    ],
  },
  {
    name: 'kubernetes-system-apiserver',
    rules: [
      {
        alert: 'KubeAggregatedAPIDown',
        'for': '15m',
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
        // Refer to https://bugzilla.redhat.com/show_bug.cgi?id=1986981 for details.
        alert: 'PrometheusBadConfig',
        labels: {
          severity: 'warning',
        },
      },
      {
        // Refer to https://bugzilla.redhat.com/show_bug.cgi?id=1986981 for details.
        alert: 'PrometheusRemoteStorageFailures',
        labels: {
          severity: 'warning',
        },

      },
      {
        // Refer to https://bugzilla.redhat.com/show_bug.cgi?id=1986981 for details.
        alert: 'PrometheusRuleFailures',
        labels: {
          severity: 'warning',
        },
      },
      {
        // Refer to https://bugzilla.redhat.com/show_bug.cgi?id=1986981 for details.
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
        // Refer to https://bugzilla.redhat.com/show_bug.cgi?id=1986981 for details.
        alert: 'ThanosNoRuleEvaluations',
        labels: {
          severity: 'warning',
        },
      },
      {
        // Refer to https://bugzilla.redhat.com/show_bug.cgi?id=1986981 for details.
        alert: 'ThanosRuleHighRuleEvaluationFailures',
        labels: {
          severity: 'warning',
        },
      },
      {
        // Refer to https://bugzilla.redhat.com/show_bug.cgi?id=1986981 for details.
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

local openShiftRunbook(runbook) =
  'https://github.com/openshift/runbooks/blob/master/' + runbook;

local openShiftRunbookCMO(runbook) =
  openShiftRunbook('alerts/cluster-monitoring-operator/' + runbook);

local includeRunbooks = {
  AlertmanagerClusterFailedToSendAlerts: openShiftRunbookCMO('AlertmanagerClusterFailedToSendAlerts.md'),
  AlertmanagerFailedReload: openShiftRunbookCMO('AlertmanagerFailedReload.md'),
  AlertmanagerFailedToSendAlerts: openShiftRunbookCMO('AlertmanagerFailedToSendAlerts.md'),
  ClusterOperatorDegraded: openShiftRunbookCMO('ClusterOperatorDegraded.md'),
  ClusterOperatorDown: openShiftRunbookCMO('ClusterOperatorDown.md'),
  KubeAPIDown: openShiftRunbookCMO('KubeAPIDown.md'),
  KubeDeploymentReplicasMismatch: openShiftRunbookCMO('KubeDeploymentReplicasMismatch.md'),
  KubeJobFailed: openShiftRunbookCMO('KubeJobFailed.md'),
  KubeNodeNotReady: openShiftRunbookCMO('KubeNodeNotReady.md'),
  KubePersistentVolumeFillingUp: openShiftRunbookCMO('KubePersistentVolumeFillingUp.md'),
  KubePersistentVolumeInodesFillingUp: openShiftRunbookCMO('KubePersistentVolumeInodesFillingUp.md'),
  KubePodNotReady: openShiftRunbookCMO('KubePodNotReady.md'),
  KubeletDown: openShiftRunbookCMO('KubeletDown.md'),
  NodeFileDescriptorLimit: openShiftRunbookCMO('NodeFileDescriptorLimit.md'),
  NodeFilesystemAlmostOutOfFiles: openShiftRunbookCMO('NodeFilesystemAlmostOutOfFiles.md'),
  NodeFilesystemAlmostOutOfSpace: openShiftRunbookCMO('NodeFilesystemAlmostOutOfSpace.md'),
  NodeFilesystemFilesFillingUp: openShiftRunbookCMO('NodeFilesystemFilesFillingUp.md'),
  NodeFilesystemSpaceFillingUp: openShiftRunbookCMO('NodeFilesystemSpaceFillingUp.md'),
  NodeRAIDDegraded: openShiftRunbookCMO('NodeRAIDDegraded.md'),
  NodeClockNotSynchronising: openShiftRunbookCMO('NodeClockNotSynchronising.md'),
  PrometheusOperatorRejectedResources: openShiftRunbookCMO('PrometheusOperatorRejectedResources.md'),
  PrometheusRuleFailures: openShiftRunbookCMO('PrometheusRuleFailures.md'),
  PrometheusRemoteStorageFailures: openShiftRunbookCMO('PrometheusRemoteStorageFailures.md'),
  PrometheusScrapeBodySizeLimitHit: openShiftRunbookCMO('PrometheusScrapeBodySizeLimitHit.md'),
  PrometheusTargetSyncFailure: openShiftRunbookCMO('PrometheusTargetSyncFailure.md'),
  TelemeterClientFailures: openShiftRunbookCMO('TelemeterClientFailures.md'),
  ThanosRuleQueueIsDroppingAlerts: openShiftRunbookCMO('ThanosRuleQueueIsDroppingAlerts.md'),
  ThanosRuleRuleEvaluationLatencyHigh: openShiftRunbookCMO('ThanosRuleRuleEvaluationLatencyHigh.md'),
};

local addRunbookUrl(rule) = rule {
  [if 'alert' in rule && std.objectHas(includeRunbooks, rule.alert) then 'annotations']+: {
    runbook_url: includeRunbooks[rule.alert],
  },
};

local removeRunbookUrl(rule) = rule {
  [if 'alert' in rule && ('runbook_url' in rule.annotations) && !std.objectHas(includeRunbooks, rule.alert) then 'annotations']+: {
    runbook_url:: null,
  },
};

local patchOrExcludeRule(rule, ruleSet, operation) =
  if std.length(ruleSet) == 0 then
    [rule]
  else if ('severity' in ruleSet[0] && !std.startsWith(rule.labels.severity, ruleSet[0].severity)) then
    // If the 'severity' field is set then it means "drop any alerting rule
    // matching this name + severity label".
    [] + patchOrExcludeRule(rule, ruleSet[1:], operation)
  else if (('alert' in rule && 'alert' in ruleSet[0]) && std.startsWith(rule.alert, ruleSet[0].alert)) ||
          (('record' in rule && 'record' in ruleSet[0]) && std.startsWith(rule.record, ruleSet[0].record)) then
    if operation == 'patch' then
      local patch = {
        [k]: if (std.isFunction(ruleSet[0][k])) then
          ruleSet[0][k](rule[k])
        else
          ruleSet[0][k]
        for k in std.objectFields(ruleSet[0])
        if k != 'alert' && k != 'record'
      };
      [std.mergePatch(rule, patch)]
    else
      // action is 'exclude'.
      []
  else
    // Evaluate the next override.
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

  addRunbookUrls(o): o {
    [if (o.kind == 'PrometheusRule') then 'spec']+: k8sMixinUtils.mapRuleGroups(addRunbookUrl),
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
    [k]: $.addRunbookUrls($.removeRunbookUrls($.patchRule($.excludeRule(o[k]))))
    for k in std.objectFields(o)
  },
}
