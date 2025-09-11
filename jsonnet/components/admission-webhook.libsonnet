local tlsVolumeName = 'prometheus-operator-admission-webhook-tls';
local admissionWebhook = import 'github.com/prometheus-operator/prometheus-operator/jsonnet/prometheus-operator/admission-webhook.libsonnet';
local antiAffinity = import 'github.com/prometheus-operator/kube-prometheus/jsonnet/kube-prometheus/addons/anti-affinity.libsonnet';
local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;

function(params)
  local aw = admissionWebhook(params);

  aw {
    deployment+: {
      metadata+: {
        labels+: {
          'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
        },
      },
      spec+: {
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
            annotations+: {
              'openshift.io/required-scc': 'restricted-v2',
            },
          },
          spec+: {
            // TODO(simonpasquier): configure client certificate authority to
            // enforce client authentication.
            securityContext: {},
            priorityClassName: 'system-cluster-critical',
            containers:
              std.map(
                function(c)
                  if c.name == 'prometheus-operator-admission-webhook' then
                    c {
                      args+: [
                        '--web.tls-cipher-suites=' + params.tlsCipherSuites,
                        '--web.tls-min-version=VersionTLS12',
                      ],
                      livenessProbe: {
                        httpGet: {
                          path: '/healthz',
                          port: 'https',
                          scheme: 'HTTPS',
                        },
                      },
                      readinessProbe: {
                        httpGet: {
                          path: '/healthz',
                          port: 'https',
                          scheme: 'HTTPS',
                        },
                      },
                      securityContext: {},
                    }
                  else
                    c,
                super.containers,
              ),
          } + antiAffinity.antiaffinity(
            aw.deployment.spec.selector.matchLabels,
            aw._config.namespace,
            'hard',
            'kubernetes.io/hostname',
          ),
        },
      },
    },

    service+: {
      metadata+: {
        annotations+: {
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-operator-admission-webhook-tls',
        } + withDescription('Expose the admission webhook service which validates `PrometheusRules` and `AlertmanagerConfig` custom resources on port ' + $.service.spec.ports[0].port + '.'),
      },
    },

    // We collect no metrics from the admission webhook service.
    // The availability of the service is measured at the Kubernetes API
    // level using the apiserver_admission_webhook_* metrics available from
    // the API server.
    serviceMonitor:: {},

    prometheusRuleValidatingWebhook: {
      apiVersion: 'admissionregistration.k8s.io/v1',
      kind: 'ValidatingWebhookConfiguration',
      metadata: {
        name: 'prometheusrules.openshift.io',
        labels: {
          'app.kubernetes.io/component': 'controller',
          'app.kubernetes.io/name': 'prometheus-operator',
        },
        annotations: {
          'service.beta.openshift.io/inject-cabundle': 'true',
        },
      },
      webhooks: [
        {
          name: 'prometheusrules.openshift.io',
          rules: [
            {
              apiGroups: ['monitoring.coreos.com'],
              apiVersions: ['v1'],
              operations: ['CREATE', 'UPDATE'],
              resources: ['prometheusrules'],
              scope: 'Namespaced',
            },
          ],
          clientConfig: {
            service: {
              namespace: 'openshift-monitoring',
              name: 'prometheus-operator-admission-webhook',
              port: 8443,
              path: '/admission-prometheusrules/validate',
            },
          },
          admissionReviewVersions: ['v1'],
          sideEffects: 'None',
          timeoutSeconds: 5,
          failurePolicy: 'Ignore',
        },
      ],
    },

    alertmanagerConfigValidatingWebhook: {
      apiVersion: 'admissionregistration.k8s.io/v1',
      kind: 'ValidatingWebhookConfiguration',
      metadata: {
        name: 'alertmanagerconfigs.openshift.io',
        labels: {
          'app.kubernetes.io/component': 'controller',
          'app.kubernetes.io/name': 'prometheus-operator',
        },
        annotations: {
          'service.beta.openshift.io/inject-cabundle': 'true',
        },
      },
      webhooks: [
        {
          name: 'alertmanagerconfigs.openshift.io',
          rules: [
            {
              apiGroups: ['monitoring.coreos.com'],
              apiVersions: ['v1alpha1'],
              operations: ['CREATE', 'UPDATE'],
              resources: ['alertmanagerconfigs'],
              scope: 'Namespaced',
            },
          ],
          clientConfig: {
            service: {
              namespace: 'openshift-monitoring',
              name: 'prometheus-operator-admission-webhook',
              port: 8443,
              path: '/admission-alertmanagerconfigs/validate',
            },
          },
          admissionReviewVersions: ['v1'],
          sideEffects: 'None',
          timeoutSeconds: 5,
          failurePolicy: 'Ignore',
        },
      ],
    },
    networkPolicy: {
      apiVersion: 'networking.k8s.io/v1',
      kind: 'NetworkPolicy',
      metadata: {
        annotations: {
          'include.release.openshift.io/hypershift': 'true',
          'include.release.openshift.io/ibm-cloud-managed': 'true',
          'include.release.openshift.io/self-managed-high-availability': 'true',
          'include.release.openshift.io/single-node-developer': 'true',
        },
        name: 'prometheus-operator-access',
        namespace: cfg.namespace,
      },
      spec: {
        podSelector: {
          matchLabels: {
            'app.kubernetes.io/name': 'prometheus-operator',
          },
        },
        policyTypes: [
          'Ingress',
          'Egress',
        ],
        ingress: [
          {
            ports: [
              {
                port: '8443',
                protocol: 'TCP',
              },
            ],
          },
        ],
        egress: [
          {},
        ],
      },
    },
  }
