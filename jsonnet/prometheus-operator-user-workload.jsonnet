local k = import 'ksonnet/ksonnet.beta.3/k.libsonnet';
local service = k.core.v1.service;
local deployment = k.apps.v1beta2.deployment;
local container = deployment.mixin.spec.template.spec.containersType;
local volume = deployment.mixin.spec.template.spec.volumesType;
local containerVolumeMount = container.volumeMountsType;
local tlsVolumeName = 'prometheus-operator-user-workload-tls';

{
  prometheusOperatorUserWorkload:: $.prometheusOperator {
    namespace:: $._config.namespaceUserWorkload,

    '0alertmanagerCustomResourceDefinition':: {},
    '0prometheusCustomResourceDefinition':: {},
    '0servicemonitorCustomResourceDefinition':: {},
    '0podmonitorCustomResourceDefinition':: {},
    '0prometheusruleCustomResourceDefinition':: {},
    '0thanosrulerCustomResourceDefinition':: {},
    // TODO: remove after 0.40 prometheus-operator is merged.
    clusterRole+: {
     rules+:
      [
	  {
	    "apiGroups": [
	      "apiextensions.k8s.io"
	    ],
	    "resources": [
	      "customresourcedefinitions"
	    ],
	    "verbs": [
	      "create"
	    ]
	  },
	  {
	    "apiGroups": [
	      "apiextensions.k8s.io"
	    ],
	    "resourceNames": [
	      "alertmanagers.monitoring.coreos.com",
	      "podmonitors.monitoring.coreos.com",
	      "prometheuses.monitoring.coreos.com",
	      "prometheusrules.monitoring.coreos.com",
	      "servicemonitors.monitoring.coreos.com",
	      "thanosrulers.monitoring.coreos.com"
	    ],
	    "resources": [
	      "customresourcedefinitions"
	    ],
	    "verbs": [
	      "get",
	      "update"
	    ]
	  }
	],
      metadata+: {
        name: 'prometheus-user-workload-operator',
      },
    },

    clusterRoleBinding+: {
      metadata+: {
        name: 'prometheus-user-workload-operator',
      },
      roleRef+: {
        name: 'prometheus-user-workload-operator',
      },
    },

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
                      args: std.filter(
                        function(arg) !std.startsWith(arg, '--kubelet-service'),
                        super.args,
                      ) + [
                        '--deny-namespaces=' + $._config.namespace,
                        '--prometheus-instance-namespaces=' + $._config.namespaceUserWorkload,
                        '--alertmanager-instance-namespaces=' + $._config.namespaceUserWorkload,
                        '--thanos-ruler-instance-namespaces=' + $._config.namespaceUserWorkload,
                        '--config-reloader-cpu=0',
                      ],
                      securityContext: {},
                      resources: {
                        requests: {
                          memory: '17Mi',
                          cpu: '1m',
                        },
                      },
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                    }
                  else if c.name == 'kube-rbac-proxy' then
                    c {
                      args+: [
                        '--tls-cert-file=/etc/tls/private/tls.crt',
                        '--tls-private-key-file=/etc/tls/private/tls.key',
                      ],
                      terminationMessagePolicy: 'FallbackToLogsOnError',
                      volumeMounts: [
                        containerVolumeMount.new(tlsVolumeName, '/etc/tls/private'),
                      ],
                      securityContext: {},
                      resources: {
                        requests: {
                          memory: '10Mi',
                          cpu: '1m',
                        },
                      },
                    }
                  else
                    c,
                super.containers,
              ),
            volumes+: [
              volume.fromSecret(tlsVolumeName, 'prometheus-operator-user-workload-tls'),
            ],
          },
        },
      },
    },
    service+:
      service.mixin.metadata.withAnnotations({
        'service.beta.openshift.io/serving-cert-secret-name': 'prometheus-operator-user-workload-tls',
      }),
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
  },
}
