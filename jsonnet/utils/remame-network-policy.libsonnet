{
  // rename object oldKey to newKey
  renameKey(o, oldKey, newKey): {
    [if k == oldKey then newKey else k]: o[k]
    for k in std.objectFields(o)
  },
}
