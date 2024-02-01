{
  // Returns a Secret holding the kube-rbac-proxy's configuration for the 'web'
  // endpoint which exposes all the endpoints of the Prometheus/Thanos web
  // server.
  //
  // To be allowed, the client needs permissions on the 'prometheuses/api'
  // (virtual) subresource of the 'openshift-monitoring/k8s' Prometheus
  // object. It can be granted via a role binding to the
  // 'cluster-monitoring-metrics-api' Role.
  //
  // Before OCP 4.16, the function was implemented by the OpenShift's
  // oauth-proxy and the access was gated on the permission to 'get' any
  // 'namespaces' resource (or `cluster-monitoring-view` ClusterRole)..
  kubeRBACSecretForMonitoringAPI(name, labels, additionalConfig={}):: {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name: name,
      namespace: 'openshift-monitoring',
      labels: labels,
    },
    type: 'Opaque',
    data: {},
    stringData: {
      'config.yaml': std.manifestYamlDoc({
        authorization: {
          resourceAttributes: {
            apiGroup: 'monitoring.coreos.com',
            resource: 'prometheuses',
            subresource: 'api',
            namespace: 'openshift-monitoring',
            name: 'k8s',
          },
        },
      } + additionalConfig),
    },
  },

  // Returns a Secret holding the kube-rbac-proxy's configuration which allows
  // the Prometheus service account to scrape the /metrics endpoint.
  staticAuthSecret(namespace, labels, name, additionalConfig={}):: {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: {
      name: name,
      namespace: namespace,
      labels: labels,
    },
    type: 'Opaque',
    data: {},
    stringData: {
      'config.yaml': std.manifestYamlDoc({
        authorization: {
          static: [
            {
              user: {
                name: 'system:serviceaccount:openshift-monitoring:prometheus-k8s',
              },
              verb: 'get',
              path: '/metrics',
              resourceRequest: false,
            },
          ],
        },
      } + additionalConfig),
    },
  },
}
