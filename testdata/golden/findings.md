## detlint report

**1 error**, 1 warning, 1 info across 2 rule files.

| Severity | Check | Location | Rule | Finding |
|---|---|---|---|---|
| WARN | `metadata` | `rules/one.yml:1:1` | One | rule has no level _(Set level.)_ |
| ERROR | `typos` | `rules/two.yml:5:5` | Two | unknown field "ComandLine" in selection "selection" (schema "windows_security"); did you mean "CommandLine"? _(Did you mean "CommandLine"?)_ |
| INFO | `wildcard` | `rules/two.yml:14:3` | Two | info only |
