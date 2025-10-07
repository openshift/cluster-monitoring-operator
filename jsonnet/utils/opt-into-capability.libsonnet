{
  local addAnnotationToChild(parent, annotationKeyCapability, annotationValueOptionalMonitoringCapability) =
    parent {
      metadata+: {
        annotations+: {
          [annotationKeyCapability]: annotationValueOptionalMonitoringCapability,
        },
      },
    },
  local addAnnotationToChildren(parent, annotationKeyCapability, annotationValueOptionalMonitoringCapability) =
    local listKinds = std.set(['RoleList', 'RoleBindingList']);
    parent {
      [k]:
        if std.objectHas(parent[k], 'kind') && std.setMember(parent[k].kind, listKinds) && std.objectHas(parent[k], 'items')
        then
          parent[k] {
            items: [addAnnotationToChild(item, annotationKeyCapability, annotationValueOptionalMonitoringCapability) for item in parent[k].items],
          }
        else
          addAnnotationToChild(parent[k], annotationKeyCapability, annotationValueOptionalMonitoringCapability)
      for k in std.objectFields(parent)
    },

  local annotationKeyCapability = 'capability.openshift.io/name',
  local annotationValueConsoleCapability = 'Console',
  local annotationValueOptionalMonitoringCapability = 'OptionalMonitoring',
  consoleForObject(o): addAnnotationToChild(o, annotationKeyCapability, annotationValueConsoleCapability),
  consoleForObjectWithWalk(o): addAnnotationToChildren(o, annotationKeyCapability, annotationValueConsoleCapability),
  optionalMonitoringForObject(o): addAnnotationToChild(o, annotationKeyCapability, annotationValueOptionalMonitoringCapability),
  optionalMonitoringForObjectWithWalk(o): addAnnotationToChildren(o, annotationKeyCapability, annotationValueOptionalMonitoringCapability),
}
