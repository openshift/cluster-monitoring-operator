{
  removeNetworkPolicy(o): {
    [k]: o[k]
    for k in std.objectFieldsAll(o)
    if !std.endsWith(k, 'networkPolicy')
  },
}
