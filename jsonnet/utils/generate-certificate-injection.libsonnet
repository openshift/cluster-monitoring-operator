{
  // this ca bundle is injected by the cluster-network-operator
  trustedCNOCaBundleCM(cfgNamespace, cfgName):: {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: cfgName,
      namespace: cfgNamespace,
      labels: {
        'config.openshift.io/inject-trusted-cabundle': 'true',
      },
    },
    data: {},
  },
}
