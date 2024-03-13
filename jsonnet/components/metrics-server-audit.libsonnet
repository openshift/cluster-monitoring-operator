local profile(level) = {
  apiVersion: 'audit.k8s.io/v1',
  kind: 'Policy',
  metadata: {
    name: level,
  },
  // omit stage RequestReceived to avoid duplication of logs for both stages
  // RequestReceived and ResponseComplete
  omitStages: ['RequestReceived'],
  rules: [{ level: level }],
};


{
  values+:: {
    audit_profiles_name: 'metrics-server-audit-profiles',
  },
  metricsServer+: {
    deployment+: {
      spec+: {
        template+: {
          spec+: {
            containers:
              std.map(
                function(c)
                  if c.name == 'metrics-server' then
                    c {
                      volumeMounts+: [{
                        mountPath: '/etc/audit',
                        name: $.values.audit_profiles_name,
                        readOnly: true,
                      }, {
                        mountPath: '/var/log/metrics-server',
                        name: 'audit-log',
                        readOnly: false,
                      }],
                    }
                  else
                    c,
                super.containers,
              ),

            volumes+: [{
              name: 'audit-log',
              emptyDir: {},
            }, {
              name: $.values.audit_profiles_name,
              configMap: {
                name: $.values.audit_profiles_name,
              },
            }],
          },
        },
      },
    },

    configmapAuditProfiles: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: $.values.audit_profiles_name,
        namespace: $.values.common.namespace,
      },
      data: {
        [std.asciiLower(x) + '-profile.yaml']: std.manifestYamlDoc(profile(x))
        for x in ['None', 'Metadata', 'Request', 'RequestResponse']
      },
    },
  },
}
