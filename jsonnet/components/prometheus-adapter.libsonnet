local tmpVolumeName = 'volume-directive-shadow';
local tlsVolumeName = 'kube-state-metrics-tls';

local tlsVolumeName = 'prometheus-adapter-tls';

local prometheusAdapterPrometheusConfig = 'prometheus-adapter-prometheus-config';
local prometheusAdapterPrometheusConfigPath = '/etc/prometheus-config';

local servingCertsCABundle = 'serving-certs-ca-bundle';
local servingCertsCABundleDirectory = 'ssl/certs';
local servingCertsCABundleFileName = 'service-ca.crt';
local servingCertsCABundleMountPath = '/etc/%s' % servingCertsCABundleDirectory;

local generateCertInjection = import '../utils/generate-certificate-injection.libsonnet';
local generateServiceMonitor = import '../utils/generate-service-monitors.libsonnet';

local prometheusAdapter = (import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus-adapter.libsonnet');

function(params)
  local cfg = params;
  local pa = prometheusAdapter(cfg);

  pa {
    // This role is moved to cluster-monitoring-operator.libsonnet
    // Hence hiding it in prometheus-adapter.
    clusterRoleAggregatedMetricsReader:: null,

    apiService+:
      {
        metadata+: {
          annotations+: {
            'service.beta.openshift.io/inject-cabundle': 'true',
          },
        },
        spec+: {
          insecureSkipTLSVerify: false,
          service+: {
            port: 443,
          },
        },
      },

    service+:
      {
        metadata+: {
          annotations+: {
            'service.beta.openshift.io/serving-cert-secret-name': tlsVolumeName,
          },
        },
        spec+: {
          type: 'ClusterIP',
        },
      },

    serviceMonitor+: {
      metadata+: {
        labels+: {
          'monitoring.openshift.io/collection-profile': 'full',
        },
      },
    },

    minimalServiceMonitor: generateServiceMonitor.minimal(
      self.serviceMonitor, std.join('|',
                                    [
                                      'apiserver_audit_event_total',
                                      'apiserver_current_inflight_requests',
                                      'apiserver_request_duration_seconds_bucket',
                                      'apiserver_request_duration_seconds_count',
                                      'apiserver_request_total',
                                      'process_start_time_seconds',
                                    ])
    ),

    deployment+:
      {
        metadata+: {
          labels+: {
            'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
          },
        },
        spec+: {
          replicas: 2,
          strategy+: {
            // Apply HA conventions
            rollingUpdate: {
              maxUnavailable: 1,
            },
          },
          template+: {
            metadata+: {
              labels+: {
                'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
              },
            },
            spec+: {
              containers:
                std.map(
                  function(c)
                    if c.name == 'prometheus-adapter' then
                      c
                      {
                        args: [
                          // Keeping until decided how to move on: https://github.com/DirectXMan12/k8s-prometheus-adapter/issues/144
                          // '--prometheus-ca-file=%s/%s' % [servingCertsCABundleMountPath, servingCertsCABundleFileName],
                          // '--prometheus-token-file=/var/run/secrets/kubernetes.io/serviceaccount/token',
                          '--prometheus-auth-config=%s/%s' % [prometheusAdapterPrometheusConfigPath, 'prometheus-config.yaml'],
                          '--config=/etc/adapter/config.yaml',
                          '--metrics-relist-interval=1m',
                          '--prometheus-url=' + cfg.prometheusURL,
                          '--secure-port=6443',
                          '--tls-cipher-suites=' + cfg.tlsCipherSuites,
                          '--disable-http2',
                        ],
                        volumeMounts: [
                          {
                            mountPath: '/tmp',
                            name: 'tmpfs',
                            readOnly: false,
                          },
                          {
                            mountPath: '/etc/adapter',
                            name: 'config',
                            readOnly: false,
                          },
                          {
                            mountPath: prometheusAdapterPrometheusConfigPath,
                            name: prometheusAdapterPrometheusConfig,
                            readOnly: false,
                          },
                          {
                            mountPath: servingCertsCABundleMountPath,
                            name: servingCertsCABundle,
                            readOnly: false,
                          },
                        ],
                        resources: {
                          requests: {
                            memory: '40Mi',
                            cpu: '1m',
                          },
                        },
                      }
                    else
                      c,
                  super.containers,
                ),

              volumes: [
                {
                  name: 'tmpfs',
                  emptyDir: {},
                },
                {
                  name: 'config',
                  configMap: {
                    name: 'adapter-config',
                  },
                },
                {
                  name: prometheusAdapterPrometheusConfig,
                  configMap: {
                    name: prometheusAdapterPrometheusConfig,
                  },
                },
                generateCertInjection.SCOCaBundleVolume(servingCertsCABundle),
              ],
              securityContext: {},
              priorityClassName: 'system-cluster-critical',
            },
          },
        },
      },

    clusterRoleBindingView: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: 'ClusterRoleBinding',
      metadata: {
        name: 'prometheus-adapter-view',
      },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'ClusterRole',
        name: 'cluster-monitoring-view',
      },
      subjects: [{
        kind: 'ServiceAccount',
        name: 'prometheus-adapter',
        namespace: cfg.namespace,
      }],
    },

    configmapPrometheus: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: {
        name: prometheusAdapterPrometheusConfig,
        namespace: cfg.namespace,
      },
      data: {
        'prometheus-config.yaml': |||
          apiVersion: v1
          clusters:
          - cluster:
              certificate-authority: %s
              server: %s
            name: prometheus-k8s
          contexts:
          - context:
              cluster: prometheus-k8s
              user: prometheus-k8s
            name: prometheus-k8s
          current-context: prometheus-k8s
          kind: Config
          preferences: {}
          users:
          - name: prometheus-k8s
            user:
              tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
        ||| % [
          servingCertsCABundleMountPath + '/' + servingCertsCABundleFileName,
          cfg.prometheusURL,
        ],
      },
    },
  }
