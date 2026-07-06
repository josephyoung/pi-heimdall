# Fail closed when Protected Configuration cannot be hidden

Heimdall treats its own configuration as Protected Configuration, so agent-visible tool activity must not read or modify it. If bash cannot run inside an active sandbox, Heimdall blocks bash instead of trying to parse shell commands, because command string filtering cannot reliably hide files from arbitrary shell programs.
