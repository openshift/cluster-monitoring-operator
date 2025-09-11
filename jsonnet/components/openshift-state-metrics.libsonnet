local generateSecret = import '../utils/generate-secret.libsonnet';
local withDescription = (import '../utils/add-annotations.libsonnet').withDescription;

function(params) {
  local cfg = params,
  local osm = (import 'github.com/openshift/openshift-state-metrics/jsonnet/openshift-state-metrics.libsonnet') + {
    _config+:: {
      namespace: cfg.namespace,
      versions: {
        openshiftStateMetrics: 'latest',
        kubeRbacProxy: 'latest',
      },
      openshiftStateMetrics+:: {
        baseMemory: '32Mi',
      },
    },
  },

  // Remapping everything as this is the only way I could think of without refactoring imported library
  // This shouldn't make much difference as openshift-state-metrics project is scheduled for deprecation
  clusterRoleBinding: osm.openshiftStateMetrics.clusterRoleBinding,
  clusterRole: osm.openshiftStateMetrics.clusterRole,
  deployment: osm.openshiftStateMetrics.deployment {
    metadata+: {
      labels+: {
        'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
      } + cfg.commonLabels + osm._config.commonLabels,
    },
    spec+: {
      template+: {
        metadata+: {
          labels+: {
            'app.kubernetes.io/managed-by': 'cluster-monitoring-operator',
          } + cfg.commonLabels,
          annotations+: {
            'openshift.io/required-scc': 'restricted-v2',
          },
        },
        spec+: {
          containers:
            std.map(
              function(c)
                if c.name == 'kube-rbac-proxy-main' || c.name == 'kube-rbac-proxy-self' then
                  c {
                    image: cfg.kubeRbacProxyImage,
                    args+: [
                      '--config-file=/etc/kube-rbac-policy/config.yaml',
                      '--client-ca-file=/etc/tls/client/client-ca.crt',
                    ],
                    volumeMounts+: [
                      {
                        mountPath: '/etc/kube-rbac-policy',
                        name: 'openshift-state-metrics-kube-rbac-proxy-config',
                        readOnly: true,
                      },
                      {
                        mountPath: '/etc/tls/client',
                        name: 'metrics-client-ca',
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
              name: 'openshift-state-metrics-kube-rbac-proxy-config',
              secret: {
                secretName: 'openshift-state-metrics-kube-rbac-proxy-config',
              },
            },
            {
              name: 'metrics-client-ca',
              configMap: {
                name: 'metrics-client-ca',
              },
            },
          ],
        },
      },
    },
  },
  kubeRbacProxySecret: generateSecret.staticAuthSecret(cfg.namespace, cfg.commonLabels, 'openshift-state-metrics-kube-rbac-proxy-config'),
  serviceAccount: osm.openshiftStateMetrics.serviceAccount,
  service: osm.openshiftStateMetrics.service {
    metadata+: {
      annotations+: withDescription(
        |||
          Expose openshift-state-metrics `/metrics` endpoints within the cluster on the following ports:
          * Port %d provides access to the OpenShift resource metrics. This port is for internal use, and no other usage is guaranteed.
          * Port %d provides access to the internal `openshift-state-metrics` metrics. This port is for internal use, and no other usage is guaranteed.
        ||| % [$.service.spec.ports[0].port, $.service.spec.ports[1].port],
      ),
    },
  },
  serviceMonitor: osm.openshiftStateMetrics.serviceMonitor,
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
      name: 'openshift-state-metrics-access',
      namespace: cfg.namespace,
    },
    spec: {
      podSelector: {
        matchLabels: {
          'app.kubernetes.io/name': 'openshift-state-metrics',
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
            {
              port: '9443',
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
