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

local prometheusAdapter = (import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/prometheus-adapter.libsonnet');

function(params)
  local cfg = params;
  local pa = prometheusAdapter(cfg);

  local config = {
    resourceRuleConfig:: {
      kubelet: '4m',
      nodeExporter: '4m',
      windowsExporter: '4m',
      metricPrefix: cfg.prometheusAdapterMetricPrefix,
    },

    resourceRules: {
      cpu: {
        containerQuery: |||
          sum by (<<.GroupBy>>) (
            irate (
                %(metricPrefix)scontainer_cpu_usage_seconds_total{<<.LabelMatchers>>,container!="",pod!=""}[%(kubelet)s]
            )
          )
        ||| % $.resourceRuleConfig,
        nodeQuery: |||
          sum by (<<.GroupBy>>) (
            1 - irate(
              node_cpu_seconds_total{mode="idle"}[%(nodeExporter)s]
            )
            * on(namespace, pod) group_left(node) (
              node_namespace_pod:kube_pod_info:{<<.LabelMatchers>>}
            )
          )
          or sum by (<<.GroupBy>>) (
            1 - irate(
              windows_cpu_time_total{mode="idle",
              job="windows-exporter",<<.LabelMatchers>>}[%(windowsExporter)s]
            )
          )
        ||| % $.resourceRuleConfig,
        resources: {
          overrides: {
            node: { resource: 'node' },
            namespace: { resource: 'namespace' },
            pod: { resource: 'pod' },
          },
        },
        containerLabel: 'container',
      },
      memory: {
        containerQuery: |||
          sum by (<<.GroupBy>>) (
            %(metricPrefix)scontainer_memory_working_set_bytes{<<.LabelMatchers>>,container!="",pod!=""}
          )
        ||| % $.resourceRuleConfig,
        nodeQuery: |||
          sum by (<<.GroupBy>>) (
            node_memory_MemTotal_bytes{job="node-exporter",<<.LabelMatchers>>}
            -
            node_memory_MemAvailable_bytes{job="node-exporter",<<.LabelMatchers>>}
          )
          or sum by (<<.GroupBy>>) (
            windows_cs_physical_memory_bytes{job="windows-exporter",<<.LabelMatchers>>}
            -
            windows_memory_available_bytes{job="windows-exporter",<<.LabelMatchers>>}
          )
        ||| % $.resourceRuleConfig,
        resources: {
          overrides: {
            instance: { resource: 'node' },
            namespace: { resource: 'namespace' },
            pod: { resource: 'pod' },
          },
        },
        containerLabel: 'container',
      },
      window: '5m',
    },
  };

  pa {
    configMapDedicatedServiceMonitors: {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: pa._metadata {
        name: 'adapter-config-dedicated-sm',
      },
      data: { 'config.yaml': std.manifestYamlDoc(config) },
    },

    clusterRoleAggregatedMetricsReader+:
      {
        metadata+: {
          labels+: {
            'rbac.authorization.k8s.io/aggregate-to-cluster-reader': 'true',
          },
        },
      },

    apiService+:
      {
        metadata+: {
          annotations+: {
            'service.beta.openshift.io/inject-cabundle': 'true',
          },
        },
        spec+: {
          insecureSkipTLSVerify: false,
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
      spec+: {
        endpoints: std.map(
          function(e) e {
            tlsConfig+: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              serverName: 'server-name-replaced-at-runtime',
              certFile: '/etc/prometheus/secrets/metrics-client-certs/tls.crt',
              keyFile: '/etc/prometheus/secrets/metrics-client-certs/tls.key',
              insecureSkipVerify: false,
              // TODO: prometheus-adapter currently is a stock upstream aggregated api server.
              // It does not support static authorization.
            },
          },
          super.endpoints
        ),
      },
    },

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
                          '--logtostderr=true',
                          '--metrics-relist-interval=1m',
                          '--prometheus-url=' + cfg.prometheusURL,
                          '--secure-port=6443',
                          '--tls-cipher-suites=' + cfg.tlsCipherSuites,
                        ],
                        terminationMessagePolicy: 'FallbackToLogsOnError',
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
    // TODO: remove podDisruptionBudget once https://github.com/prometheus-operator/kube-prometheus/pull/1156 is merged
    podDisruptionBudget+: {
      apiVersion: 'policy/v1',
    },
  }
