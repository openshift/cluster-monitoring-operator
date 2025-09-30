{
  local addAnnotationToChild(parent, annotationKey, annotationValue) =
    parent {
      metadata+: {
        annotations+: {
          [annotationKey]: annotationValue,
        },
      },
    },
  local addAnnotationToChildren(parent, annotationKey, annotationValue) =
    local listKinds = std.set(['RoleList', 'RoleBindingList']);
    parent {
      [k]:
        if std.objectHas(parent[k], 'kind') && std.setMember(parent[k].kind, listKinds) && std.objectHas(parent[k], 'items')
        then
          parent[k] {
            items: [addAnnotationToChild(item, annotationKey, annotationValue) for item in parent[k].items],
          }
        else
          addAnnotationToChild(parent[k], annotationKey, annotationValue)
      for k in std.objectFields(parent)
    },
  local annotationKey = 'capability.openshift.io/name',
  local annotationValue = 'OptionalMonitoring',
  forObject(o): addAnnotationToChild(o, annotationKey, annotationValue),
  forObjectWithWalk(o): addAnnotationToChildren(o, annotationKey, annotationValue),
}
