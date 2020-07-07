local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local service = k.core.v1.service;
local deployment = k.apps.v1beta2.deployment;
local container = deployment.mixin.spec.template.spec.containersType;
local volume = deployment.mixin.spec.template.spec.volumesType;
local containerVolumeMount = container.volumeMountsType;
local tlsVolumeName = 'prometheus-operator-tls';
local certsCAVolumeName = 'operator-certs-ca-bundle';

{
  clusterPrometheusOperator+:: $.prometheusOperator {
    deployment+: {
        spec+: {
          template+: {
            spec+: {
              nodeSelector+: {
                'node-role.kubernetes.io/master': '',
              },
              tolerations: [
                {
                  key: 'node-role.kubernetes.io/master',
                  operator: 'Exists',
                  effect: 'NoSchedule',
                },
              ],
              securityContext: {},
              priorityClassName: 'system-cluster-critical',
              containers:
                std.map(
                  function(c)
                    if c.name == 'prometheus-operator' then
                      c {
                        args+: [
                          '--namespaces=' + $._config.namespace,
                          '--prometheus-instance-namespaces=' + $._config.namespace,
                          '--thanos-ruler-instance-namespaces=' + $._config.namespace,
                          '--alertmanager-instance-namespaces=' + $._config.namespace,
                          '--config-reloader-cpu=0',
                          '--config-reloader-memory=0',
                          '--web.enable-tls=true',
                          '--web.tls-cipher-suites=' + std.join(',', $._config.tlsCipherSuites),
                          '--web.tls-min-version=VersionTLS12',
                        ],
                        securityContext: {},
                        resources: {
                          requests: {
                            memory: '60Mi',
                            cpu: '5m',
                          },
                        },
                        terminationMessagePolicy: 'FallbackToLogsOnError',
                        volumeMounts+: [
                          containerVolumeMount.new(tlsVolumeName, '/etc/tls/private'),
                        ],
                      }
                    else if c.name == 'kube-rbac-proxy' then
                      c {
                        args: [
                          '--logtostderr',
                          '--secure-listen-address=:8443',
                          '--tls-cipher-suites=' + std.join(',', $._config.tlsCipherSuites),
                          '--upstream=https://prometheus-operator.openshift-monitoring.svc:8080/',
                          '--tls-cert-file=/etc/tls/private/tls.crt',
                          '--tls-private-key-file=/etc/tls/private/tls.key',
                          '--upstream-ca-file=/etc/configmaps/operator-cert-ca-bundle/service-ca.crt',
                        ],
                        terminationMessagePolicy: 'FallbackToLogsOnError',
                        volumeMounts: [
                          containerVolumeMount.new(tlsVolumeName, '/etc/tls/private'),
                          containerVolumeMount.new(certsCAVolumeName, '/etc/configmaps/operator-cert-ca-bundle'),
                        ],
                        securityContext: {},
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
              volumes+: [
                volume.fromSecret(tlsVolumeName, 'prometheus-operator-tls'),
                {
                  name: certsCAVolumeName,
                  configMap: {
                    name: certsCAVolumeName,
                  },
                },
              ],
            },
          },
        },
      },

    service+:
      service.mixin.metadata.withAnnotations({
        'service.beta.openshift.io/serving-cert-secret-name': "prometheus-operator-tls",
      }) +
      service.mixin.spec.withPortsMixin([{name: 'web', port: 8080, targetPort: 8080,}]),

    serviceMonitor+: {
      spec+: {
        endpoints: [
          {
            honorLabels: true,
            bearerTokenFile: '/var/run/secrets/kubernetes.io/serviceaccount/token',
            port: 'https',
            scheme: 'https',
            tlsConfig: {
              caFile: '/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt',
              serverName: 'server-name-replaced-at-runtime',
            },
          },
        ],
      },
    },

    operatorCertsCaBundle: {
      apiVersion: "v1",
      kind: "ConfigMap",
      metadata: {
        annotations: {
          "service.alpha.openshift.io/inject-cabundle": "true",
        },
        name: certsCAVolumeName,
        namespace: $._config.namespace,
      },
      data: {
        "service-ca.crt": ""
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
          'app.kubernetes.io/version': $._config.versions.prometheusOperator,
        },
        annotations: {
          "service.beta.openshift.io/inject-cabundle": true
        },
      },
      webhooks: [
        {
          name: 'prometheusrules.openshift.io',
          rules: [
            {
              apiGroups: ['monitoring.coreos.com'],
              apiVersions: ['v1'],
              operations:  ['CREATE', 'UPDATE'],
              resources:   ['prometheusrules'],
              scope:       'Namespaced',
            },
          ],
          clientConfig: {
            service: {
              namespace: 'openshift-monitoring',
              name: 'prometheus-operator',
              port: 8080,
              path: '/admission-prometheusrules/validate'
            },
          },
          admissionReviewVersions: ['v1beta1'],
          sideEffects: 'None',
          timeoutSeconds: 5,
        },
      ],
    },
  },
}
