local excludedRuleGroups = [
  'kube-apiserver-availability.rules',
];

local excludedRules = [
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
];

local patchedRules = [
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
];

local patchOrExcludeRule(rule, ruleSet, operation) =
  if std.length(ruleSet) == 0 then
    [rule]
  else if (('alert' in rule && 'alert' in ruleSet[0]) && std.startsWith(rule.alert, ruleSet[0].alert)) ||
          (('record' in rule && 'record' in ruleSet[0]) && std.startsWith(rule.record, ruleSet[0].record)) then
    if operation == 'patch' then
      [std.mergePatch(rule, ruleSet[0])]
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
    [k]: if std.isObject(o[k]) then exclude(o[k]) else o[k]
    for k in std.objectFields(o)
  },

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
    [k]: if std.isObject(o[k]) then patch(o[k]) else o[k]
    for k in std.objectFields(o)
  },
}
