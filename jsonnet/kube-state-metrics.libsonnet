local tmpVolumeName = 'volume-directive-shadow';
local tlsVolumeName = 'kube-state-metrics-tls';

local kubeStateMetrics = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/kube-state-metrics.libsonnet';

function(params)
  local cfg = params;

  kubeStateMetrics(cfg) + {
    // Adding the serving certs annotation causes the serving certs controller
    // to generate a valid and signed serving certificate and put it in the
    // specified secret.
    service+: {
      metadata+: {
        annotations+: {
          'service.beta.openshift.io/serving-cert-secret-name': 'kube-state-metrics-tls',
        },
      },
    },

    // This changes kube-state-metrics to be scraped with validating TLS.

    serviceMonitor+: {
      spec+: {
        endpoints: [
          {
            bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            honorLabels: true,
            interval: '1m',
            scrapeTimeout: '1m',
            port: 'https-main',
            scheme: 'https',
            tlsConfig: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              serverName: 'server-name-replaced-at-runtime',
            },
            // Drop the "instance" and "pod" labels since we're runinng only
            // one instance of kube-state-metrics. The "instance" label must be
            // dropped at the metrics relabeling stage (instead of the service
            // discovery stage) because otherwise Prometheus will default its
            // value to the address being scraped.
            // The net result is to avoid excessive series churn when
            // kube-state-metrics is redeployed because of node reboot, pod
            // rescheduling or cluster upgrade.
            metricRelabelings: [
              {
                action: 'labeldrop',
                regex: 'instance',
              },
            ],
            relabelings: [
              {
                action: 'labeldrop',
                regex: 'pod',
              },
            ],
          },
          {
            bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            interval: '1m',
            scrapeTimeout: '1m',
            port: 'https-self',
            scheme: 'https',
            tlsConfig: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              serverName: 'server-name-replaced-at-runtime',
            },
          },
        ],
      },
    },

    // This removes the upstream addon-resizer and all resource requests and
    // limits. Additionally configures the kube-rbac-proxies to use the serving
    // cert configured on the `Service` above.
    //
    // The upstream kube-state-metrics Dockerfile defines a `VOLUME` directive
    // in `/tmp`. Although this is unused it will take some time for it to get
    // released, which is why it is shadowed here for the time being.

    deployment+: {
      spec+: {
        template+: {
          spec+: {
            containers:
              std.filterMap(
                function(c) c.name != 'addon-resizer',
                function(c)
                  if std.startsWith(c.name, 'kube-rbac-proxy') then
                    c {
                      args+: [
                        '--tls-cert-file=/etc/tls/private/tls.crt',
                        '--tls-private-key-file=/etc/tls/private/tls.key',
                      ],
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts: [{
                        mountPath: '/etc/tls/private',
                        name: tlsVolumeName,
                        readOnly: false,
                      }],
                      securityContext: {},
                      resources: {
                        requests: {
                          memory: '15Mi',
                          cpu: '1m',
                        },
                      },
                    }
                  else
                    c {
                      args+: [
                        '--metric-denylist=kube_secret_labels',
                        '--metric-labels-allowlist=pods=[*],node=[*]',
                      ],
                      securityContext: {},
                      resources: {
                        requests: {
                          memory: '80Mi',
                          cpu: '2m',
                        },
                      },
                      volumeMounts: [{
                        mountPath: '/tmp',
                        name: tmpVolumeName,
                        readOnly: false,
                      }],
                    },
                super.containers,
              ),
            volumes+: [
              {
                emptyDir: {},
                name: tmpVolumeName,
              },
              {
                name: tlsVolumeName,
                secret: {
                  secretName: 'kube-state-metrics-tls',
                },
              },
            ],
            securityContext: {},
            priorityClassName: 'system-cluster-critical',
          },
        },
      },
    },
  }
