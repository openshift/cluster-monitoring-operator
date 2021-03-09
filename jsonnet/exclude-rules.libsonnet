local excludeRule(rule, excludedRules) =
  if std.length(excludedRules) == 0 then
    [rule]
  else if (('alert' in rule && 'alert' in excludedRules[0]) && rule.alert == excludedRules[0].alert) ||
          (('record' in rule && 'record' in excludedRules[0]) && rule.record == excludedRules[0].record) then
    []
  else
    [] + excludeRule(rule, excludedRules[1:]);

local excludeRuleGroup(group, excludedGroups) =
  if std.length(excludedGroups) == 0 then
    [group.rules]
  else if (group.name == excludedGroups[0].name) then
    [excludeRule(rule, excludedGroups[0].rules) for rule in group.rules]
  else
    [] + excludeRuleGroup(group, excludedGroups[1:]);

{
  excludeRules(o): {
    local exclude(o) = o {
      [if (o.kind == 'PrometheusRule') then 'spec']+: {
        groups: std.filterMap(
          function(group) !std.member(excludedRuleGroups, group.name),
          function(group)
            group {
              rules: std.flattenArrays(
                excludeRuleGroup(group, excludedRules)
              ),
            },
          super.groups,
        ),
      },
    },
    [k]: exclude(o[k])
    for k in std.objectFields(o)
  },

  local excludedRuleGroups = [
    'kube-apiserver-availability.rules',
  ],

  local excludedRules = [
    {
      name: 'etcd',
      rules: [
        { alert: 'etcdHighNumberOfFailedGRPCRequests' },
        { alert: 'etcdInsufficientMembers' },
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
  ],
}
