{
  removeRulesByResourcePrefix(o, apiGroup, prefix): o {
    rules: std.map(
      function(r)
        r + if std.member(r.apiGroups, apiGroup) then
          {
            resources: std.filter(
              function(rsc)
                !std.startsWith(rsc, prefix),
              r.resources,
            ),
          }
        else
          {}
      ,
      o.rules,
    ),
  },
}
