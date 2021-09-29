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
    profiles_name: 'prometheus-adapter-audit-profiles',
  },
  prometheusAdapter+: {
    deployment+: {
      spec+: {
        template+: {
          spec+: {
            containers:
              std.map(
                function(c)
                  if c.name == 'prometheus-adapter' then
                    c {
                      volumeMounts+: [{
                        mountPath: '/etc/audit',
                        name: $.values.profiles_name,
                        readOnly: true,
                      }, {
                        mountPath: '/var/log/adapter',
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
              name: $.values.profiles_name,
              configMap: {
                name: $.values.profiles_name,
              },
            }],
          },  // spec
        },  // template
      },  // spec
    },  // deployment

    configmapAuditProfiles: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: $.values.profiles_name,
        namespace: $.values.common.namespace,
      },
      data: {
        // TODO(sthaha): use quote_keys=false when version > 0.17 is released
        // generate <level>-profile.yaml for all log levels
        [std.asciiLower(x) + '-profile.yaml']: std.manifestYamlDoc(profile(x))
        for x in ['None', 'Metadata', 'Request', 'RequestResponse']
      },
    },
  },  // pa
}
