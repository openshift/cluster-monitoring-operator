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
  // this ca bundle is injected by the service-ca-operator
  SCOCaBundleCM(cfgNamespace, cfgName):: {
    apiVersion: 'v1',
    kind: 'ConfigMap',
    metadata: {
      name: cfgName,
      namespace: cfgNamespace,
      annotations: {
        'service.beta.openshift.io/inject-cabundle': 'true',
      },
    },
    data: {},
  },
  SCOCaBundleVolume(volName):: {
    name: volName,
    configmap: {
      name: volName,
      items: [
        {
          key: 'service-ca.crt',
          path: 'service-ca.crt',
        },
      ],
    },
  },
}
