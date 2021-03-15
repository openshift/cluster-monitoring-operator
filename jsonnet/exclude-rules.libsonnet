{
  excludeRules(o): {
    local filterRule(o) = o {
      [if (o.kind == 'PrometheusRule') then 'spec']+: {
        groups: std.filter(
          function(group) !(group.name == 'kube-apiserver-availability.rules'),
          std.map(
            function(ruleGroup)
              if ruleGroup.name == 'etcd' then
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && (rule.alert == 'etcdHighNumberOfFailedGRPCRequests' || rule.alert == 'etcdInsufficientMembers')), ruleGroup.rules) }
              else if ruleGroup.name == 'kubernetes-system' then
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && rule.alert == 'KubeVersionMismatch'), ruleGroup.rules) }
              // Removing CPUThrottlingHigh alert as per https://bugzilla.redhat.com/show_bug.cgi?id=1843346
              else if ruleGroup.name == 'kubernetes-resources' then
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && rule.alert == 'CPUThrottlingHigh'), ruleGroup.rules) }
              else if ruleGroup.name == 'kubernetes-system-apiserver' then
                // KubeClientCertificateExpiration alert isn't
                // actionable because the cluster admin has no way to
                // prevent a client from using an expird certificate.
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && (rule.alert == 'KubeClientCertificateExpiration')), ruleGroup.rules) }
              else if ruleGroup.name == 'kubernetes-system-kubelet' then
                // Kubelet*CertificateExpiration alerts are based on absolute thresholds which
                // make them prone to failures (e.g. if the lifetime of the certificate is
                // decreased, the alert might fire while everything is fine).
                // In addition we have alerts to detect that a Kubelet
                // can't renew its certificates which makes it redundant
                // to alert on certificates being almost expired.
                // See https://coreos.slack.com/archives/CB48XQ4KZ/p1603712568136500.
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && (rule.alert == 'KubeletClientCertificateExpiration' || rule.alert == 'KubeletServerCertificateExpiration')), ruleGroup.rules) }
              else if ruleGroup.name == 'kubernetes-apps' then
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && rule.alert == 'KubeDeploymentReplicasMismatch'), ruleGroup.rules) }
              else if ruleGroup.name == 'prometheus' then
                ruleGroup {
                  rules:
                    std.map(
                      function(rule)
                        if 'alert' in rule && (rule.alert == 'PrometheusDuplicateTimestamps' || rule.alert == 'PrometheusOutOfOrderTimestamps') then
                          rule { 'for': '1h' }
                        else
                          rule,
                      ruleGroup.rules,
                    ),
                }
              else if ruleGroup.name == 'general.rules' then
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && (rule.alert == 'TargetDown')), ruleGroup.rules) }
              else
                ruleGroup,
            super.groups,
          ),
        ),
      },
    },
    [k]: filterRule(o[k])
    for k in std.objectFields(o)
  },
}
