{
  addLabels(o, labels): {
    [k]: o[k] +
         if !std.setMember(o[k].kind, ['ConfigMapList']) then
           { metadata+: { labels+: labels } }
         else
           {}
    for k in std.objectFields(o)
  },
}
