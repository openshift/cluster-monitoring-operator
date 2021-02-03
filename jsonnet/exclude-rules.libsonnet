{
  excludeRules(o): {
    local filterRule(o) = o {
      [if (o.kind == 'PrometheusRule') then 'spec']+: {
        groups:
          std.map(
            function(ruleGroup)
              if ruleGroup.name == 'etcd' then
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && rule.alert == 'etcdHighNumberOfFailedGRPCRequests'), ruleGroup.rules) }
              else if ruleGroup.name == 'kubernetes-system' then
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && rule.alert == 'KubeVersionMismatch'), ruleGroup.rules) }
              // Removing CPUThrottlingHigh alert as per https://bugzilla.redhat.com/show_bug.cgi?id=1843346
              else if ruleGroup.name == 'kubernetes-resources' then
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && rule.alert == 'CPUThrottlingHigh'), ruleGroup.rules) }
              else if ruleGroup.name == 'kubernetes-system-kubelet' then
                ruleGroup { rules: std.filter(function(rule) !('alert' in rule && (rule.alert == 'KubeletClientCertificateExpiration' || rule.alert == 'KubeletServerCertificateExpiration')), ruleGroup.rules) }
              else if ruleGroup.name == 'kube-apiserver-availability.rules' then
                ruleGroup { rules: std.filter(function(rule) !('record' in rule && rule.record == 'apiserver_request:availability30d'), ruleGroup.rules) }
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
              else
                ruleGroup,
            super.groups,
          ),
      },
    },
    [k]: filterRule(o[k])
    for k in std.objectFields(o)
  },
}