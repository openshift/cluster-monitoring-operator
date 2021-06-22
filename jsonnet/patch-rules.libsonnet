local excludedRuleGroups = [
  'kube-apiserver-availability.rules',
  // rules managed by openshift/cluster-kube-controller-manager-operator.
  'kubernetes-system-controller-manager',
  // rules managed by openshift/cluster-kube-scheduler-operator.
  'kubernetes-system-scheduler',
  // rules managed by openshift/cluster-kube-apiserver-operator.
  'kube-apiserver-slos',
  'kube-apiserver.rules',
];

local excludedRules = [
  {
    name: 'etcd',
    rules: [
      { alert: 'etcdHighNumberOfFailedGRPCRequests' },
      { alert: 'etcdInsufficientMembers' },
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
    name: 'thanos-query',
    rules: [
      { alert: 'ThanosQueryInstantLatencyHigh' },
      { alert: 'ThanosQueryRangeLatencyHigh' },
    ],
  },
];

local patchedRules = [
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
  // excludedRules removes upstream rules that we don't want to carry in CMO.
  // It can remove specific rules from a rules group (see excludedRules) or a
  // whole rules group (see excludedRuleGroups).
  excludeRules(o): {
    local exclude(o) = o {
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
    [k]: exclude(o[k])
    for k in std.objectFields(o)
  },

  // patchRules adapts upstream rules to comply with OpenShift requirements
  // (such as extending the for duration, changing alert severity, and so on).
  // The patches are defined in the patchedRules array where each item contains
  // the name of the affected group and the list of patches keyed by their
  // 'alert' or 'record' identifier. The function will apply the patch to every
  // alerting/recording rule in the group whose name starts by the identifier.
  patchRules(o): {
    local patch(o) = o {
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
    [k]: patch(o[k])
    for k in std.objectFields(o)
  },
}
