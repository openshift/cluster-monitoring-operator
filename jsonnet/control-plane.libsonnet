local controlPlane = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/k8s-control-plane.libsonnet';

function(params)
  local cfg = params;

  controlPlane(cfg) + {

    etcdMixin:: (import 'github.com/etcd-io/etcd/contrib/mixin/mixin.libsonnet') + {
      _config+:: cfg.mixin._config,
    },

    etcdPrometheusRule: {
      apiVersion: 'monitoring.coreos.com/v1',
      kind: 'PrometheusRule',
      metadata: {
        labels: cfg.commonLabels + cfg.mixin.ruleLabels,
        name: 'etcd-prometheus-rules',
        namespace: cfg.namespace,
      },
      spec: {
        local r = if std.objectHasAll($.etcdMixin, 'prometheusRules') then $.etcdMixin.prometheusRules.groups else [],
        local a = if std.objectHasAll($.etcdMixin, 'prometheusAlerts') then $.etcdMixin.prometheusAlerts.groups else [],
        groups: a + r,
      },
    },

    serviceMonitorEtcd: {
      apiVersion: 'monitoring.coreos.com/v1',
      kind: 'ServiceMonitor',
      metadata: {
        name: 'etcd',
        namespace: cfg.namespace,
        labels: {
          'app.kubernetes.io/name': 'etcd',
          'k8s-app': 'etcd',
        },
      },
      spec: {
        jobLabel: 'k8s-app',
        endpoints: [
          {
            port: 'etcd-metrics',
            interval: '30s',
            scheme: 'https',
            // Prometheus Operator (and Prometheus) allow us to specify a tlsConfig. This is required as most likely your etcd metrics end points is secure.
            tlsConfig: {
              caFile: '/etc/prometheus/secrets/kube-etcd-client-certs/etcd-client-ca.crt',
              keyFile: '/etc/prometheus/secrets/kube-etcd-client-certs/etcd-client.key',
              certFile: '/etc/prometheus/secrets/kube-etcd-client-certs/etcd-client.crt',
            },
          },
        ],
        selector: {
          matchLabels: {
            'k8s-app': 'etcd',
          },
        },
        namespaceSelector: {
          matchNames: ['openshift-etcd'],
        },
      },
    },

    // This changes the kubelet's certificates to be validated when
    // scraping.
    serviceMonitorKubelet+: {
      metadata+: {
        labels+: {
          'k8s-app': 'kubelet',
        },
      },
      spec+: {
        jobLabel: 'k8s-app',
        selector: {
          matchLabels: {
            'k8s-app': 'kubelet',
          },
        },
        endpoints:
          std.map(
            function(e)
              e {
                tlsConfig+: {
                  caFile: '/etc/prometheus/configmaps/kubelet-serving-ca-bundle/ca-bundle.crt',
                  insecureSkipVerify: false,
                },
              } +
              {
                // Increase the scrape timeout to match the scrape interval
                // because the kubelet metric endpoints might take more than the default
                // 10 seconds to reply.
                scrapeTimeout: '30s',
              }
              +
              if 'path' in e && e.path == '/metrics/cadvisor' then
                // Drop cAdvisor metrics with excessive cardinality.
                {
                  metricRelabelings+: [
                    {
                      sourceLabels: ['__name__'],
                      action: 'drop',
                      regex: 'container_memory_failures_total',
                    },
                  ],
                }
              else
                {}
            ,
            super.endpoints,
          ) +
          // Collect metrics from CRI-O.
          [{
            interval: '30s',
            port: 'https-metrics',
            relabelings: [
              {
                sourceLabels: ['__address__'],
                action: 'replace',
                targetLabel: '__address__',
                regex: '(.+)(?::\\d+)',
                replacement: '$1:9537',
              },
              {
                sourceLabels: ['endpoint'],
                action: 'replace',
                targetLabel: 'endpoint',
                replacement: 'crio',
              },
              {
                action: 'replace',
                targetLabel: 'job',
                replacement: 'crio',
              },
            ],
            // Drop metrics with excessive label cardinality.
            metricRelabelings: [
              {
                sourceLabels: ['__name__'],
                regex: 'container_runtime_crio_image_layer_reuse|container_runtime_crio_image_pulls_.+',
                action: 'drop',
              },
            ],
          }],
      },
    },

    // This avoids creating service monitors which are already managed by the respective operators.
    serviceMonitorApiserver:: {},
    serviceMonitorKubeScheduler:: {},
    serviceMonitorKubeControllerManager:: {},
    serviceMonitorCoreDNS:: {},

  }
