# pi-heimdall

Guardian extensions for [pi](https://github.com/badlogic/pi-mono) that protect
against accidental secret exposure through tool calls.

Named after Heimdall, watcher of the Bifröst — the one who sees everything
coming and slams the gate shut when it shouldn't pass.

Ported from the equivalent [opencode](https://opencode.ai) plugins.

## What it does

pi-heimdall ships a single extension entry point (`heimdall.ts`) with six
independent guards. Each one intercepts tool calls before they run (and, in one
case, after they return) and blocks or redacts anything that would leak secrets
to the LLM context.

| Guard | Type | Tool | Blocks / redacts |
|---|---|---|---|
| `sandbox-guard` | always-on | `bash`, `read`, `write`, `edit`, `grep`, `find`, `ls` | OS-level filesystem isolation via bubblewrap — only configured paths + system binaries visible, synthetic `/etc`, env var filtering, `$HOME` read-only by default |
| `env-protect` | opt-out | `read` | Reading `.env`, `.env.*`, `.envrc`, `*.env` — except `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.defaults` |
| `kubectl-secret-guard` | opt-out | `bash` | `kubectl get secrets`, `kubectl patch ... finalizers`, `kubectl exec` into a pod that dumps env / `/var/run/secrets` / `app.ini` |
| `sops-secret-guard` | opt-out | `bash` | Any `sops` invocation that would decrypt content: `sops decrypt`, `sops -d`, `sops --decrypt`, `sops exec-env`, `sops exec-file`, `sops edit`, and bare `sops <file>` |
| `command-policy-guard` | opt-out | `bash` | Commands that violate repo policy as defined in `.pi/heimdall.json` (e.g. blocking `cargo test` in favour of `mise test`) |
| `secret-guard` | opt-out | `bash` | Commands that reference secret env var names from a project `.env.json`, and redacts their values from bash output (plaintext, base64, rot13, reversed, hex, and hexdump-decoded) |

`sandbox-guard` is always-on when enabled in config. The other five are opt-out
via the `disabled` array (see below).

## Install

### Global (all projects)

```bash
pi install @josephyoung/pi-heimdall
```

### Project-local

```bash
pi install -l @josephyoung/pi-heimdall
```

Project-local installs land in `.pi/settings.json` and are picked up
automatically for every run in that directory.

### From GitHub

```bash
pi install git:github.com/josephyoung/pi-heimdall
```

### From a local clone

```bash
git clone https://github.com/josephyoung/pi-heimdall ~/src/pi-heimdall
pi install ~/src/pi-heimdall
```

### Try without installing

```bash
pi -e @josephyoung/pi-heimdall
```

## Troubleshooting

### oh-pi conflicts

When Heimdall is installed alongside `oh-pi`, pi may fail at startup with a
conflict similar to:

```text
Tool "bash" conflicts with .../oh-pi/pi-package/extensions/bg-process.ts
```

This happens because Heimdall's `sandbox-guard` wraps pi's built-in `bash` tool
so commands can run through the sandbox policy, while `oh-pi`'s `bg-process.ts`
also overrides `bash` to auto-background long-running commands. Pi allows an
extension to override a built-in tool, but two installed packages cannot both
register a custom tool with the same name.

To use Heimdall and `oh-pi` together, disable only `oh-pi`'s `bg-process.ts`
extension while keeping the rest of `oh-pi` enabled:

```bash
pi config
```

Then uncheck:

```text
npm:oh-pi → Extensions → bg-process.ts
```

Or edit `~/.pi/agent/settings.json` manually:

```json
{
  "packages": [
    {
      "source": "npm:oh-pi",
      "extensions": ["-pi-package/extensions/bg-process.ts"]
    },
    "npm:@josephyoung/pi-heimdall"
  ]
}
```

Omitted resource types still load normally, so this keeps `oh-pi` skills,
prompts, themes, and other extensions enabled. The only disabled piece is the
`bg-process.ts` extension and the `bg_status` tool it registers.

## Configuration

Config is loaded from two locations and deep-merged (project overrides user):

- **User-level**: `~/.pi/agent/heimdall.json`
- **Project-level**: `<cwd>/.pi/heimdall.json`

All guards are enabled by default. Disable individual opt-out guards via the
`disabled` array:

```json
{
  "disabled": ["env-protect", "kubectl-secret-guard"],
  "sandbox": { "enabled": true },
  "commandPolicies": []
}
```

## Configuring `sandbox-guard`

`sandbox-guard` provides filesystem isolation for agent tools. Bash commands
run inside a bubblewrap (bwrap) namespace, and built-in file tools (`read`,
`write`, `edit`, `grep`, `find`, `ls`) are checked against the same path policy
before execution. The agent cannot read default private home paths such as
`~/Private`, `~/.ssh`, `~/.kube`, `~/.aws`, `~/.config`, AI tool configs
(Claude, Codex, Cursor, Windsurf, Antigravity, Kiro, Augment, Zed, Aider, Gemini,
Continue, Codeium, OpenAI, Anthropic), editor configs (VS Code, JetBrains,
Neovim, Vim), cloud/credential directories, and more — unless users explicitly opt
them in. Other files under
`$HOME` are mounted read-only by default so users can reference non-sensitive
home config files.

**Requirements:** Linux with `bubblewrap` installed (`apt install bubblewrap`,
`dnf install bubblewrap`, etc.). With host networking, Heimdall also preserves
DNS on systems where `/etc/resolv.conf` is a symlink (for example,
`systemd-resolved`) by bind-mounting only the symlink's real target, not all of
`/run`.

### Minimal config

```json
{
  "sandbox": {
    "enabled": true
  }
}
```

### Full config

```json
{
  "sandbox": {
    "enabled": true,
    "network": "host",
    "paths": {
      ".": { "mode": "write" },
      "~/.pi": { "mode": "write" },
      "/etc": [
        { "path": "/etc/resolv.conf" },
        { "path": "/etc/hosts" },
        { "path": "/etc/ssl" },
        {
          "path": "/etc/passwd",
          "content": "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n"
        }
      ]
    },
    "env": {
      "allow": null,
      "deny": ["*_TOKEN", "*_SECRET", "*_PASSWORD", "AWS_*", "GITHUB_TOKEN"],
      "set": {
        "PATH": "/usr/bin:/bin",
        "NO_COLOR": "1",
        "AWS_PROFILE": null
      }
    }
  }
}
```

### Path rules

- `paths` keys are prefixes. Keys support `~` (home directory) and `$VAR`/`${VAR}`
  expansion (e.g. `"~/.config"`, `"$HOME/projects"`).
- A value can be one entry or an array of entries.
- An entry without `path` applies to the whole prefix.
- An entry with `path` applies to that specific file/path under the prefix.
- `mode` defaults to `"read"`; write access requires `"mode": "write"`.
- `mode: "deny"` explicitly blocks a subpath of an otherwise allowed prefix.
  The most specific match wins, so `"~/.ssh": { "mode": "deny" }` blocks
  `~/.ssh` even when `$HOME` is read-only.
- `content` creates a synthetic file at `path` for sandboxed bash commands.
  Direct host `read` of synthetic paths is blocked so it cannot expose the real
  host file.

Deny example:

```json
{
  "sandbox": {
    "paths": {
      "$HOME": {},
      "~/.ssh": { "mode": "deny" },
      "~/.aws": { "mode": "deny" },
      "~/.config/gh": { "mode": "deny" }
    }
  }
}
```

### Default path visibility

| Path | Access | Notes |
|---|---|---|
| `.` (project dir) | read-write | |
| `/tmp` | read-write | |
| `~/.pi` | read-write | User's pi config directory. Uses `~` expansion to `$HOME/.pi`. |
| `~/Private` | denied | User-private files. Exact user/project rules can override. |
| `~/.ssh`, `~/.gnupg`, `~/.netrc` | denied | Auth keys and credential files. |
| `~/.aws`, `~/.azure`, `~/.gcloud`, `~/.oci`, `~/.kube` | denied | Cloud and Kubernetes credentials/config. |
| `~/.docker`, `~/.terraform.d`, `~/.vault-token` | denied | Infrastructure credentials/config. |
| `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials`, `~/.cargo/credentials.toml` | denied | Package registry credentials. |
| `~/.sops`, `~/.age`, `~/.password-store` | denied | Secret stores and encryption keys. |
| `~/.claude`, `~/.codex`, `~/.forge`, `~/.cursor`, `~/.windsurf`, `~/.antigravity`, `~/.kiro`, `~/.augment`, `~/.zed`, `~/.aider`, `~/.gemini`, `~/.continue`, `~/.codeium`, `~/.openai`, `~/.anthropic` | denied | AI coding tools (CLI agents, AI-native IDEs) — API keys commonly stored here. This list is not exhaustive; users should extend it in `.pi/heimdall.json`. |
| `~/.vscode`, `~/.vscode-server`, `~/.code` | denied | VS Code, VS Code Insiders/OSS editor configs (may contain auth tokens). |
| `~/.config/JetBrains`, `~/.local/share/JetBrains` | denied | JetBrains IDE configs (modern XDG paths). |
| `~/.config/nvim`, `~/.local/share/nvim`, `~/.vim`, `~/.viminfo` | denied | Neovim and Vim configs. |
| `$HOME` | read-only | Added automatically. User/project config can override. |
| `/usr` | read-only | System binaries |
| `/opt` | read-only | |
| `/srv` | read-only | |
| `/etc` | read-only | Configure specific files via `paths` |
| `/nix/store` | read-only | NixOS compatibility |
| `/run/current-system/sw` | read-only | NixOS compatibility |
| `/bin`, `/sbin`, `/lib`, `/lib64` | read-only | Legacy non-usr-merged compatibility. Skipped on modern distros. |

### Environment rules

- `env.allow` omitted or `null` — **inherits the current environment** (default).
- `env.allow: []` — starts with no environment variables.
- `env.deny` removes matching variables and overrides `allow`.
- `env.set` is applied last. String values set/override variables; `null` unsets them.
- Exact names and `*` globs are supported for `allow` and `deny`.
- Default deny patterns: `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_KEY`.

### Network

- `"host"` (default) — shared with host. Agent can reach Docker, internet.
- `"none"` — isolated network namespace.

### Container bwrap compatibility

For rootless or non-root containers where bubblewrap cannot mount nested kernel
filesystems or remount a workspace subdirectory, these environment variables
adjust only the bwrap mount arguments:

- `HEIMDALL_BWRAP_BIND_KERNEL_FS=1` uses `--dev-bind /dev /dev` and
  `--ro-bind /proc /proc` instead of mounting fresh `/dev` and `/proc`.
- `HEIMDALL_BWRAP_BIND_ROOT=/absolute/path` promotes writable mounts below that
  root to `--bind /absolute/path /absolute/path`. The value must be an absolute
  path below `/`; `/` and relative paths are rejected.

`HEIMDALL_BWRAP_BIND_ROOT` does not change the sandbox path policy checks, but it
does make the specified root the actual writable bwrap mount. Use a root that
contains only data the sandboxed command may write.

### Session controls

- **Disable for a session:** `pi --no-sandbox`
- **Check status:** `/sandbox` command in the TUI

## Configuring `command-policy-guard`

`command-policy-guard` reads repo-specific command policies from
`.pi/heimdall.json` at the project root. If the `commandPolicies` array is
missing or empty, the guard does nothing.

Example:

```json
{
  "commandPolicies": [
    {
      "name": "no-cargo-test",
      "blocked": ["cargo", "test"],
      "message": "Use `mise test` or `mise run test` instead of `cargo test`."
    },
    {
      "name": "no-cargo-nextest",
      "blocked": ["cargo", "nextest"],
      "message": "Use `mise test` or `mise run --force test` instead of `cargo nextest`."
    }
  ]
}
```

Each policy has three fields:

- **`name`** — a human-readable identifier used in block messages.
- **`blocked`** — an array of tokens that must appear at the start of a command.
  Prefix matching is used, so `["cargo", "test"]` blocks `cargo test`,
  `cargo test --lib`, `cargo test foo::bar`, etc.
- **`message`** — the explanation shown to the model when a command is blocked.

The command line is properly tokenized (respecting single quotes, double quotes,
and backslash escapes) and each shell segment (commands separated by `;`, `|`,
`&&`, `||`, or newlines) is checked independently.

### Bypass hardening

The guard handles several patterns a motivated LLM might try:

- **Env prefixes**: `CARGO_TARGET_DIR=/tmp cargo test` — `KEY=value` tokens
  before the command are skipped.
- **Wrapper commands**: `sudo cargo test`, `env cargo test`, `eval cargo test` —
  known wrappers are skipped before matching.
- **Shell groups**: `{ cargo test; }`, `( cargo test )` — `{` and `(` prefix
  tokens are skipped.
- **Shell `-c` recursion**: `bash -c 'cargo test'` — the `-c` argument is
  recursively parsed through the full pipeline (segments, heredocs, policies).
- **Path-qualified commands**: `/usr/bin/cargo test`, `~/.cargo/bin/cargo test` —
  basename matching resolves `cargo` from any path.
- **Backslash escapes**: `car\go test` — escapes are consumed during
  tokenization so the result matches `cargo`.
- **Quote splicing**: `ca''rgo test`, `ca""rgo test` — empty quotes are
  stripped during tokenization.
- **Heredocs**: `cat <<EOF\ncargo test\nEOF` — heredoc bodies are excluded
  from matching to avoid false positives.

### Known acceptable gaps

Some patterns cannot be caught without a full shell interpreter:

- `timeout 60 cargo test` — wrappers that take arguments before the command
- `docker run cargo test`, `ssh host cargo test` — indirect execution
- `python3 -c "os.system('cargo test')"` — embedded language execution
- `nix develop -c cargo test` — tool-specific wrappers

## Configuring `secret-guard`

`secret-guard` needs a `.env.json` at your project root listing the environment
variables that should be treated as secrets. **Values in the JSON are ignored —
only the keys matter.** The actual secret values are captured from `process.env`
when pi starts.

```json
{
  "GITHUB_TOKEN": "",
  "OPENAI_API_KEY": "",
  "STRIPE_SECRET_KEY": "",
  "AWS_SECRET_ACCESS_KEY": ""
}
```

With this in place:

- Any bash command that mentions `GITHUB_TOKEN` as a whole word is blocked.
- Any bash output containing the actual value of `GITHUB_TOKEN` (in plaintext,
  base64, rot13, reversed, raw hex, or hexdump form) is replaced with
  `[REDACTED]`.

Even without `.env.json`, `secret-guard` still applies a generic
trailing-pattern redaction: anything matching `*(SECRET|KEY|TOKEN|PASSWORD|PASS|APIKEY|CREDENTIAL|PRIVATE)=...`
in bash output gets its value masked.

### A `sops` key is ignored

If your `.env.json` uses the key `sops` (for example, it's a sops-encrypted
file with a `sops` metadata section), that key is skipped so pi-heimdall
doesn't try to match literal metadata as a secret name.

## How the guards communicate with the LLM

When a guard blocks a tool call it returns a `reason` string that is delivered
back to the model as the tool result. Every reason includes an explicit
instruction such as:

> *Ask the user to run this command directly in their terminal if needed.
> Never attempt to bypass this protection or ask the user to disable it.*

This keeps the model from going into "creative workaround" mode and trying a
different command to accomplish the same leak.

If a pi TUI is attached, a warning notification is also shown so you can see
the block in real time.

## Layout

```
extensions/
└── heimdall.ts          # entry point — loads config, registers all guards

guards/
├── command-policy-guard.ts
├── env-protect.ts
├── kubectl-secret-guard.ts
├── sandbox-guard.ts
├── secret-guard.ts
├── sops-secret-guard.ts
└── types.ts
```

Each guard is a standalone module. There is no shared runtime state between
them — you can delete any guard file (except `sandbox-guard.ts` and `types.ts`)
and the others will keep working.

## Development

```bash
npm install           # optional: only for editor tooling / type checks
npm run typecheck     # type-check the extensions
npm run check:pack    # verify the package tarball contents
```

GitHub Actions runs the same checks on pushes and pull requests to `main`.

Pi loads `.ts` files directly via [jiti](https://github.com/unjs/jiti), so no
build step is required at runtime.

## License

MIT © casualjim
