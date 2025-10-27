{
  local addAnnotationToChild(o, key, value) =
    o {
      metadata+: {
        annotations+: {
          [key]: value,
        },
      },
    },
  local addAnnotationToChildren(o, key, value) =
    local listKinds = std.set(['RoleList', 'RoleBindingList']);
    o {
      [k]:
        if std.objectHas(o[k], 'kind') && std.setMember(o[k].kind, listKinds) && std.objectHas(o[k], 'items')
        then
          o[k] {
            items: [addAnnotationToChild(item, key, value) for item in o[k].items],
          }
        else
          addAnnotationToChild(o[k], key, value)
      for k in std.objectFields(o)
    },

  local annotationKeyCapability = 'capability.openshift.io/name',
  local annotationValueConsoleCapability = 'Console',
  local annotationValueOptionalMonitoringCapability = 'OptionalMonitoring',

  // consoleForObject adds the Console capability annotation to a single object.
  consoleForObject(o): addAnnotationToChild(o, annotationKeyCapability, annotationValueConsoleCapability),

  // consoleForObjectWithWalk adds the Console capability annotation to all objects in the given parent object, iteratively.
  consoleForObjectWithWalk(o): addAnnotationToChildren(o, annotationKeyCapability, annotationValueConsoleCapability),

  // optionalMonitoringForObject adds the OptionalMonitoring capability annotation to a single object.
  optionalMonitoringForObject(o): addAnnotationToChild(o, annotationKeyCapability, annotationValueOptionalMonitoringCapability),

  // optionalMonitoringForObjectWithWalk adds the OptionalMonitoring capability annotation to all objects in the given parent object, iteratively.
  optionalMonitoringForObjectWithWalk(o): addAnnotationToChildren(o, annotationKeyCapability, annotationValueOptionalMonitoringCapability),
}
