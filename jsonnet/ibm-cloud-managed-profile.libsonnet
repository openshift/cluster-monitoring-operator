{
  // Generates manifests specific to the ibm-cloud-managed profile for use
  // in ROKS clusters.
  // Specifically, it generates a new cluster monitoring operator deployment by
  // modifiying the original deployment manifest:
  // - adds the ibm-cloud-managed profile annotation
  // - removes the master node selector
  // Contact: cewong@redhat.com

  local removeMasterNodeSelector(sel) = {
    [if x != 'node-role.kubernetes.io/master' then x]: sel[x]
    for x in std.objectFields(sel)
  },

  local setProfileAnnotation(metadata, profile) =
    local annotations = if 'annotations' in metadata then metadata.annotations else {};
    {
      [if !std.startsWith(x, 'include.release.openshift.io/') then x]: annotations[x]
      for x in std.objectFields(annotations)
    } +
    {
      ['include.release.openshift.io/' + profile]: 'true',
    },


  manifests+:: {
    local operatorDeployment = import 'manifests/0000_50_cluster-monitoring-operator_05-deployment.json',
    '0000_50_cluster-monitoring-operator_05-deployment-ibm-cloud-managed': operatorDeployment {
      local originalMetadata = super.metadata,
      metadata+: {
        annotations: setProfileAnnotation(originalMetadata, 'ibm-cloud-managed'),
      },
      spec+: {
        template+: {
          spec+: {
            nodeSelector: removeMasterNodeSelector(super.nodeSelector),
          },
        },
      },
    },
  },
}
