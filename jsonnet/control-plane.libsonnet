local controlPlane = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/components/k8s-control-plane.libsonnet';

function(params)
  local cfg = params;

  controlPlane(cfg) + {

    // etcMixin is required to generate the etcd dashboards.
    etcdMixin:: (import 'github.com/etcd-io/etcd/contrib/mixin/mixin.libsonnet') + {
      _config+:: cfg.mixin._config,
    },

    // Hide etcd alerting and recording rules because they are handled by the
    // etcd operator.
    etcdPrometheusRule:: null,

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
              },
            super.endpoints,
          ) +
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
          }],
      },
    },

    // This avoids creating service monitors which are already managed by the respective operators.
    serviceMonitorApiserver:: {},
    serviceMonitorKubeScheduler:: {},
    serviceMonitorKubeControllerManager:: {},
    serviceMonitorCoreDNS:: {},

  }
