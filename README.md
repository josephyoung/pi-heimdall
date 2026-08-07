# @josephyoung/pi-heimdall

Security controls for [`@earendil-works/pi-coding-agent`](https://www.npmjs.com/package/@earendil-works/pi-coding-agent).
Heimdall puts policy checks around shell and file tools before their input or
output reaches the model.

## Fork notice

This repository is a maintained fork of
[`casualjim/pi-heimdall`](https://github.com/casualjim/pi-heimdall). It retains
the original project's security goal and MIT attribution, while this fork is
published as `@josephyoung/pi-heimdall` and has evolved into a single-entry
package with sandbox, policy, and protected-configuration controls.

## Install

```bash
# All projects
pi install @josephyoung/pi-heimdall

# Current project only
pi install -l @josephyoung/pi-heimdall

# One-off run
pi -e @josephyoung/pi-heimdall
```

GitHub fallback:

```bash
pi install git:github.com/josephyoung/pi-heimdall
```

## Security controls

One extension entry point registers six independent guards:

| Guard | Scope |
|---|---|
| `sandbox-guard` | Applies filesystem, environment, and network policy to bash and file tools; protects Heimdall config |
| `secret-guard` | Blocks secret-variable references and redacts known secret values from bash output |
| `env-protect` | Denies real dotenv files while allowing examples and templates |
| `kubectl-secret-guard` | Denies Kubernetes commands that expose secrets, pod environments, or protected finalizers |
| `sops-secret-guard` | Denies SOPS operations that decrypt or reveal content |
| `command-policy-guard` | Enforces repository-specific blocked command prefixes |

`sandbox-guard` is always registered. The other guards can be disabled without
sharing runtime state or weakening each other.

## Configuration

Heimdall reads and deep-merges these files at session start:

1. `~/.pi/agent/heimdall.json`
2. `<cwd>/.pi/heimdall.json`

Project values win for scalars and objects; arrays are concatenated.

```json
{
  "disabled": ["sops-secret-guard"],
  "sandbox": {
    "enabled": true,
    "network": "host",
    "paths": {
      ".": { "mode": "write" },
      "~/shared": {},
      "~/.ssh": { "mode": "deny" }
    },
    "env": {
      "allow": null,
      "deny": ["*_TOKEN", "*_SECRET", "*_PASSWORD", "*_KEY"],
      "set": { "NO_COLOR": "1" }
    }
  },
  "commandPolicies": []
}
```

Valid `disabled` values are `secret-guard`, `command-policy-guard`,
`env-protect`, `kubectl-secret-guard`, and `sops-secret-guard`.

### Sandbox rules

The bash sandbox requires Linux and `bubblewrap`. Paths default to read-only;
use `mode: "write"` for writable paths and `mode: "deny"` for exclusions. The
most specific matching path wins. `~`, `$VAR`, and `${VAR}` are expanded.

Common system paths and `$HOME` are read-only by default, while the project and
`/tmp` are writable. Credential stores, cloud configs, editor configs, and AI
tool configs under the home directory are denied by default. Add explicit rules
for any additional private paths in your environment.

Environment handling is ordered as follows:

1. `allow: null` inherits the process environment; `allow: []` starts empty.
2. `deny` removes exact names or `*` glob matches.
3. `set` overrides values; `null` removes a variable.

`network` accepts `"host"` (default) or `"none"`. The `/sandbox` TUI command
shows active policy. `pi --no-sandbox` disables isolation for the session, but
bash remains blocked as described below.

Container deployments may set:

- `HEIMDALL_BWRAP_BIND_KERNEL_FS=1` to bind host `/dev` and `/proc`.
- `HEIMDALL_BWRAP_BIND_PROC=0` to omit `/proc` when an outer container would
  expose same-UID process roots through it.
- `HEIMDALL_BWRAP_BIND_ROOT=/absolute/path` to promote an allowed workspace
  root to the actual writable bind mount.
- `HEIMDALL_PROTECT_CONFIG_OVERLAY=0` to disable the synthetic config overlay
  when rootless container mounts reject it.

### Protected Configuration

Both Heimdall config files are operator-owned Protected Configuration:

- Direct file-tool reads and writes are blocked, including symlink aliases.
- Broad `grep`, `find`, and `ls` results omit the files and their contents.
- Sandboxed bash receives synthetic empty files at those paths.

This boundary fails closed. If Linux/bubblewrap isolation is unavailable or the
sandbox is disabled, Heimdall blocks bash instead of exposing its policy file.
Edit the config outside Pi.

### Command policies

Policies match tokenized command prefixes in every shell segment:

```json
{
  "commandPolicies": [
    {
      "name": "project-test-entrypoint",
      "blocked": ["npm", "test"],
      "message": "Use `mise test` for this repository."
    }
  ]
}
```

Matching handles environment prefixes, common wrappers, shell groups, shell
`-c`, path-qualified executables, quoting, escapes, and heredocs. It is a policy
guard, not a complete shell interpreter; indirect execution through containers,
SSH, or embedded languages is outside its scope.

### Secret values

Create `<cwd>/.env.json` with the names to protect. JSON values are ignored;
actual values are captured from the Pi process environment.

```json
{
  "GITHUB_TOKEN": "",
  "OPENAI_API_KEY": ""
}
```

Commands that name those variables are blocked. Matching output is redacted in
plain, base64, ROT13, reversed, hex, and hexdump-derived forms. Generic
`SECRET`, `KEY`, `TOKEN`, `PASSWORD`, `PASS`, `APIKEY`, `CREDENTIAL`, and
`PRIVATE` assignments are masked even without `.env.json`.

## Package compatibility

Heimdall replaces Pi's built-in `bash` tool. Another package cannot register a
second replacement with the same name. For `oh-pi`, disable only
`pi-package/extensions/bg-process.ts` in `pi config`; its other extensions,
skills, prompts, and themes can remain enabled.

## Development

There is no build step; Pi loads the TypeScript sources directly.

```bash
npm install
npm run typecheck
npm test
npm run check:pack
```

CI runs install, typecheck, and package-content checks. Guard changes should
also include a blocked case and a nearby allowed case in the local test suite.

## License

MIT. Original work © casualjim; fork maintenance by Joseph Young.
