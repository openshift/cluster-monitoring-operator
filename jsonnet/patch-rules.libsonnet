local patchRule(rule, patchedRules) =
  if std.length(patchedRules) == 0 then
    [rule]
  else if (('alert' in rule && 'alert' in patchedRules[0]) && rule.alert == patchedRules[0].alert) ||
          (('record' in rule && 'record' in patchedRules[0]) && rule.record == patchedRules[0].record) then
    [std.mergePatch(rule, patchedRules[0])]
  else
    [] + patchRule(rule, patchedRules[1:]);

local patchRuleGroup(group, patchedGroups) =
  if std.length(patchedGroups) == 0 then
    [group.rules]
  else if (group.name == patchedGroups[0].name) then
    [patchRule(rule, patchedGroups[0].rules) for rule in group.rules]
  else
    [] + patchRuleGroup(group, patchedGroups[1:]);

{
  patchRules(o): {
    local exclude(o) = o {
      [if (o.kind == 'PrometheusRule') then 'spec']+: {
        groups: std.map(
          function(group)
            group {
              rules: std.flattenArrays(
                patchRuleGroup(group, patchedRules)
              ),
            },
          super.groups,
        ),
      },
    },
    [k]: exclude(o[k])
    for k in std.objectFields(o)
  },

  local patchedRules = [
    {
      name: 'prometheus',
      rules: [
        {
          alert: 'PrometheusDuplicateTimestamps',
          'for': '1h',
        },
        {
          alert: 'PrometheusOutOfOrderTimestamps',
          'for': '1h',
        },
      ],
    },
  ],
}
