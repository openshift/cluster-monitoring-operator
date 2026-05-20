{
  // overrideFlag removes any container arg starting with flagPrefix and appends
  // flagPrefix+value. flagPrefix must include '=' for flags like '--foo='.
  overrideFlag(flagPrefix, value, args)::
    std.filter(function(a) !std.startsWith(a, flagPrefix), args) + [flagPrefix + value],
}
