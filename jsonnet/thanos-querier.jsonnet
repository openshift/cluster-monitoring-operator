local k = import 'ksonnet/ksonnet.beta.4/k.libsonnet';
local service = k.core.v1.service;
local deployment = k.apps.v1.deployment;
local container = deployment.mixin.spec.template.spec.containersType;
local servicePort = service.spec.portsType;

{
  local config = super._config,

  thanos+:: {
    variables+:: {
      image: config.imageRepos.openshiftThanos + ':' + config.versions.openshiftThanos,
    },

    querier+: {
      service+:
        service.mixin.metadata.withNamespace(config.namespace) +
        // The ClusterIP is explicitly set, as it signifies the
        // cluster-monitoring-operator, that when reconciling this service the
        // cluster IP needs to be retained.
        service.mixin.spec.withType('ClusterIP'),

      deployment+:
        deployment.mixin.metadata.withNamespace(config.namespace) +
        {
          spec+: {
            template+: {
              spec+: {
                securityContext: {},
                priorityClassName: 'system-cluster-critical',
                tolerations: [
                  {
                    key: "node-role.kubernetes.io/master",
                    operator: "Exists",
                    effect: "NoSchedule",
                  },
                ],
                containers: [
                    super.containers[0] +
                    container.withArgsMixin([
                      '--store=dnssrv+_grpc._tcp.%s.%s.svc.cluster.local' % [
                          'prometheus-k8s',
                          'openshift-monitoring',
                      ],
                      '--store=dnssrv+_grpc._tcp.%s.%s.svc.cluster.local' % [
                          'prometheus-user-workload',
                          'openshift-user-workload-monitoring',
                      ],
                    ]) + {
                      resources: {
                        requests: {
                          memory: '12Mi',
                          cpu: '10m',
                      },
                    },
                  },
                ],
              },
            },
          },
        },
    },
  },
}
