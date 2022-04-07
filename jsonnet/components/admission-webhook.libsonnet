local tlsVolumeName = 'prometheus-operator-admission-webhook-tls';
local admissionWebhook = import 'github.com/prometheus-operator/prometheus-operator/jsonnet/prometheus-operator/admission-webhook.libsonnet';

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
        template+: {
          metadata+: {
            labels+: {
              'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
            },
          },
          spec+: {
            // TODO(simonpasquier): configure client certificate authority to
            // enforce client authentication.
            affinity+: {
              podAntiAffinity: {
                requiredDuringSchedulingIgnoredDuringExecution: [
                  {
                    labelSelector: {
                      matchLabels: aw.deployment.spec.selector.matchLabels,
                    },
                    topologyKey: 'kubernetes.io/hostname',
                  },
                ],
              },
            },
            securityContext: {},
            priorityClassName: 'system-cluster-critical',
            containers:
              std.map(
                function(c)
                  if c.name == 'prometheus-operator-admission-webhook' then
                    c {
                      args+: [
                        '--web.enable-tls=true',
                        '--web.tls-cipher-suites=' + params.tlsCipherSuites,
                        '--web.tls-min-version=VersionTLS12',
                        '--web.cert-file=/etc/tls/private/tls.crt',
                        '--web.key-file=/etc/tls/private/tls.key',
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
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts+: [
                        {
                          mountPath: '/etc/tls/private',
                          name: 'tls-certificates',
                          readOnly: true,
                        },
                      ],
                    }
                  else
                    c,
                super.containers,
              ),
            volumes+: [
              {
                name: 'tls-certificates',
                secret: {
                  secretName: 'prometheus-operator-admission-webhook-tls',
                  items: [
                    {
                      key: 'tls.crt',
                      path: 'tls.crt',
                    },
                    {
                      key: 'tls.key',
                      path: 'tls.key',
                    },
                  ],
                },
              },
            ],
          },
        },
      },
    },

    service+: {
      metadata+: {
        annotations+: {
          'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-operator-admission-webhook-tls',
        },
      },
    },

    // We collect no metrics from the admission webhook service.
    // The availability of the service is measured at the Kubernetes API
    // level using the apiserver_admission_webhook_* metrics available from
    // the API server.
    serviceMonitor:: {},

    podDisruptionBudget: {
      apiVersion: 'policy/v1',
      kind: 'PodDisruptionBudget',
      metadata: {
        name: aw._config.name,
        namespace: aw._config.namespace,
        labels: aw._config.commonLabels,
      },
      spec: {
        minAvailable: 1,
        selector: {
          matchLabels: aw._config.selectorLabels,
        },

      },
    },

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
  }
