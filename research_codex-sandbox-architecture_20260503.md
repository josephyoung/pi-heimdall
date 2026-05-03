# OpenAI Codex Local Sandbox Architecture — Research Report

**Date:** 2026-05-03
**Depth:** Deep
**Confidence:** 93%
**Sources:** 15 sources from 5 search rounds

---

## Executive Summary

OpenAI Codex's local sandbox on Linux uses a **two-stage, multi-layered approach**: bubblewrap (bwrap) for filesystem namespace isolation, combined with seccomp-BPF for syscall-level network restriction, and PR_SET_NO_NEW_PRIVS for privilege escalation prevention. The architecture is fundamentally different from Anthropic's sandbox-runtime — Codex embeds sandboxing directly into the agent CLI process rather than wrapping an external Node.js sandbox manager. Both approaches share the same underlying Linux limitation: `bwrap --unshare-net` creates an isolated network namespace where bound ports are invisible to the host. Codex simply doesn't promise local port binding; Anthropic documents it as "macOS only."

## Key Findings

1. **Codex uses a two-stage sandbox pipeline** — Stage 1: bwrap constructs filesystem namespace + network namespace. Stage 2: re-enters the sandbox binary to apply seccomp filters, then exec's the user command. [Source](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/linux_run_main.rs)

2. **Filesystem is read-only by default with explicit writable carve-outs** — bwrap mounts the entire root filesystem as `--ro-bind / /`, then layers `--bind` mounts for writable roots (workspace directory, `/tmp`). Protected paths like `.git`, `.agents`, `.codex` are re-applied as read-only even inside writable roots. [Source](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/bwrap.rs)

3. **Network isolation is absolute on Linux** — When network is disabled (default), bwrap uses `--unshare-net` to create a fully isolated network namespace, and seccomp blocks `connect`, `bind`, `listen`, `accept`, `socket` (except AF_UNIX), and other network syscalls. There is no port forwarding bridge. [Source](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/landlock.rs)

4. **Codex has the same port binding limitation as Anthropic** — Issue #6737 is an open feature request for "Allow binding to local addresses." Codex does not attempt to solve this. Anthropic's `allowLocalBinding` is documented as macOS-only. [Source](https://github.com/openai/codex/issues/6737)

5. **Managed proxy mode provides controlled outbound access** — When proxy environment variables are set (HTTP_PROXY, HTTPS_PROXY, etc.), Codex runs a TCP→UDS→TCP bridge: host-side bridge connects to the real proxy, local bridge inside the netns connects to the UDS. Seccomp then blocks AF_UNIX to prevent bypass. [Source](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/proxy_routing.rs)

6. **Process hardening is applied in addition to namespace isolation** — PR_SET_DUMPABLE=0 disables ptrace, RLIMIT_CORE=0 prevents core dumps, LD_PRELOAD and DYLD_* are stripped, and seccomp blocks `ptrace`, `process_vm_readv`, `io_uring_*` syscalls. [Source](https://github.com/openai/codex/blob/main/codex-rs/process-hardening/src/lib.rs)

7. **The entire sandbox is written in Rust, not TypeScript** — Anthropic's sandbox-runtime is a Node.js library that shells out to bwrap. Codex's `codex-rs/linux-sandbox` is native Rust that directly calls `libc::execv` to enter bwrap, avoiding the Node.js subprocess overhead. [Source](https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/launcher.rs)

## Detailed Analysis

### Sub-question 1: How does OpenAI Codex's local sandbox runtime work architecturally?

Codex's local sandbox follows a **parent→bwrap→inner-self→seccomp→command** pipeline. The architecture is designed so that the outer CLI process never directly runs untrusted code — it constructs the sandbox environment and then exec's into it.

The flow in `linux_run_main.rs` is:

1. **Parse permission profile** — The CLI serializes the permission profile (filesystem policy, network policy) as JSON and passes it to the sandbox helper binary.
2. **Outer stage: Construct bwrap environment** — The sandbox helper builds bwrap arguments: read-only root filesystem, writable workspace roots, namespace isolation (`--unshare-user`, `--unshare-pid`, optionally `--unshare-net`).
3. **Re-enter self with `--apply-seccomp-then-exec`** — Instead of exec'ing the user command directly inside bwrap, Codex re-execs its own binary with a special flag. This inner invocation applies seccomp-BPF filters and `PR_SET_NO_NEW_PRIVS` **after** bwrap has already established the filesystem namespace.
4. **Exec user command** — Finally, `execvp` replaces the process with the user's command, which now runs under all sandbox constraints.

This two-stage design is critical: it allows seccomp to be applied inside the bwrap namespace (where the filesystem is already constrained) rather than trying to apply everything in one layer. The bwrap layer handles filesystem; seccomp handles network and process-level restrictions.

> Key architectural insight: The sandbox helper is a separate binary (`codex-linux-sandbox`) that can be invoked standalone for testing (`codex sandbox linux <command>`), making the sandbox boundary testable independent of the agent.

**Cross-reference**: This contrasts with Anthropic's approach (Sub-question 5), where sandbox-runtime is a Node.js library that wraps commands via `sandbox-manager.js`.

### Sub-question 2: What sandboxing technology does Codex use locally on Linux?

Codex layers **four distinct security mechanisms** on Linux:

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Filesystem | bubblewrap (bwrap) | Namespace-based filesystem isolation |
| Network (namespace) | bwrap `--unshare-net` | Network namespace isolation |
| Network (syscall) | seccomp-BPF | Block network syscalls at kernel level |
| Process | PR_SET_NO_NEW_PRIVS + hardening | Prevent privilege escalation, ptrace, core dumps |

**Bubblewrap details** (from `bwrap.rs`):
- System bwrap on PATH is preferred; vendored bwrap compiled into the binary as fallback
- `--ro-bind / /` makes the entire filesystem read-only
- `--bind <root> <root>` re-enables writes for allowed roots
- `--ro-bind <subpath> <subpath>` re-applies read-only for protected paths (`.git`, `.codex`, `.agents`)
- `--unshare-user` + `--unshare-pid` for user and PID namespace isolation
- `--unshare-net` when network is disabled (default)
- `--proc /proc` mounts a fresh `/proc` (with fallback for restrictive containers)
- `--dev /dev` creates minimal device nodes (null, zero, random, urandom, tty)
- Unreadable glob patterns are expanded via ripgrep (`rg --files`) at sandbox construction time, and matching files are masked with `/dev/null` mounts

**Legacy Landlock fallback**: Codex retains Landlock LSM support as a fallback (`--use-legacy-landlock`), but it's deprecated. Landlock cannot express restricted read-only access (the split filesystem policy model), so bwrap is strictly more capable.

**Cross-reference**: The filesystem mount ordering (Sub-question 1) is critical — protected subpaths must be applied in the correct sequence to prevent TOCTTOU races with writable symlink targets.

### Sub-question 3: How does Codex handle networking and port binding inside the sandbox?

Codex has **three network modes** in `BwrapNetworkMode`:

1. **`FullAccess`** — No network namespace isolation. Used when the user explicitly enables `network_access = true` in config. The process shares the host's network stack.

2. **`Isolated`** (default) — `--unshare-net` creates a new network namespace with only an isolated loopback. The process can technically `bind()` to ports, but they're only visible inside the sandbox's own loopback — completely invisible to the host or any other process. Additionally, seccomp blocks `connect`, `bind`, `listen`, `accept`, `sendto`, `socket` (except AF_UNIX), etc. So even the isolated loopback is unusable for TCP/UDP.

3. **`ProxyOnly`** — Used when proxy environment variables are set and managed proxy routing is enabled. Still uses `--unshare-net`, but establishes a TCP→UDS→TCP bridge:
   - **Host bridge** (runs on host): Listens on a Unix domain socket, forwards to the real proxy endpoint (e.g., `127.0.0.1:43128`)
   - **Local bridge** (runs inside netns): Binds to `127.0.0.1:<random_port>` inside the isolated namespace, forwards to the UDS (which passes through the namespace boundary)
   - Proxy env vars are rewritten to point to the local bridge port
   - Seccomp in ProxyRouted mode blocks AF_UNIX and non-IP sockets to prevent bypassing the bridge

**Port binding limitation**: This is the same fundamental constraint as Anthropic's issue #165. With `--unshare-net`, there is no reverse bridge from sandbox ports to the host. Codex has an open feature request (issue #6737, opened by José Valim for Elixir/Mix) asking for local address binding support. The Codex team has not implemented this.

**Cross-reference**: This directly addresses why Anthropic's `allowLocalBinding` is broken on Linux — it's not an implementation bug but a fundamental limitation of `bwrap --unshare-net` that neither project has solved. The socat reverse bridge proposed in Anthropic issue #165 would work for both.

### Sub-question 4: What is the developer UX for Codex sandboxes?

The Codex sandbox is configured through a layered permission system:

**Sandbox modes** (via `--sandbox` flag or `config.toml`):
- `workspace-write` (Auto preset): Can read/write workspace, run commands in workspace. Needs approval for edits outside workspace or network access.
- `read-only`: Can read files and answer questions. Needs approval for edits, commands, or network.
- `danger-full-access` (`--yolo`): No sandbox, no approvals.

**Approval policies** (`--ask-for-approval`):
- `on-request` (Auto): Only asks for risky operations.
- `untrusted`: Auto-runs safe reads, asks before any mutation.
- `never` (`-a never`): Never asks (still respects sandbox boundaries).
- `granular`: Fine-grained per-category control.

**Key UX decisions**:
- The sandbox is transparent — developers don't need to understand bwrap or seccomp
- `codex sandbox linux <command>` lets developers test what happens under sandbox constraints
- Config lives in `~/.codex/config.toml` with per-profile presets
- Version-controlled folders default to `workspace-write`; non-VC folders default to `read-only`
- Protected paths (`.git`, `.codex`, `.agents`) are always read-only inside writable roots

**Cross-reference**: The approval policy interacts with the sandbox boundary — even with `never` approval, the sandbox still constrains what the process can technically do. Approval is a UX layer on top of the technical sandbox.

### Sub-question 5: How does this compare to Anthropic's sandbox-runtime approach?

| Dimension | OpenAI Codex | Anthropic sandbox-runtime |
|-----------|-------------|--------------------------|
| **Language** | Rust (native) | Node.js (TypeScript/JavaScript) |
| **Filesystem** | bwrap (primary), Landlock (legacy fallback) | bwrap only |
| **Network** | bwrap `--unshare-net` + seccomp-BPF | bwrap `--unshare-net` + socat outbound proxy |
| **Process hardening** | PR_SET_DUMPABLE=0, RLIMIT_CORE=0, LD_* strip, seccomp on ptrace/io_uring | Not documented |
| **Proxy support** | Built-in TCP↔UDS bridge with env var rewriting | socat-based outbound proxy |
| **Port binding** | Not supported (open FR #6737) | Promises `allowLocalBinding` (broken on Linux) |
| **Two-stage pipeline** | Yes: bwrap → re-enter self → seccomp → exec | Single stage: bwrap → exec |
| **Testability** | `codex sandbox linux <cmd>` standalone | No standalone test command |
| **macOS** | Seatbelt (sandbox-exec) | Seatbelt (sandbox-exec) |
| **Windows** | Native sandbox (unelevated) or WSL2 | Not supported |

**The fundamental difference**: Codex's Rust implementation gives it tighter control over the sandbox construction process — it can fork, set up namespaces, apply seccomp in the exact right order, and exec without going through a Node.js event loop. Anthropic's sandbox-runtime wraps bwrap via child_process.spawn, which adds latency and makes the two-stage approach harder.

**The networking difference that matters**: Anthropic implements an outbound proxy using socat + Unix sockets, allowing the sandboxed process to make HTTP/HTTPS requests through a controlled channel. Codex implements a similar concept via its `ProxyOnly` mode with TCP↔UDS bridges. Both solve outbound access. Neither solves **inbound** access (port binding visible to host).

**Cross-reference**: Both projects share the same core constraint from `bwrap --unshare-net`. The difference in developer experience comes from expectations management — Codex never promises local port binding, while Anthropic documents `allowLocalBinding` that doesn't work on Linux.

## Comparison

| Criterion | OpenAI Codex | Anthropic sandbox-runtime |
|-----------|-------------|--------------------------|
| Filesystem isolation | ✅ bwrap with layered mounts | ✅ bwrap |
| Network isolation | ✅ bwrap + seccomp | ✅ bwrap + socat proxy |
| Outbound proxy | ✅ Managed TCP↔UDS bridge | ✅ socat + Unix sockets |
| Inbound port binding | ❌ Not supported (open FR) | ❌ Broken on Linux (documented as macOS only) |
| Process hardening | ✅ Comprehensive (dumpable, core, LD_*, ptrace, io_uring) | ⚠️ Not documented |
| Two-stage sandbox | ✅ bwrap → seccomp → exec | ❌ Single stage |
| Standalone testing | ✅ `codex sandbox linux` | ❌ No equivalent |
| Implementation language | Rust (native, zero overhead) | Node.js (subprocess overhead) |
| Open source | ✅ Apache-2.0 | ✅ MIT |
| Vendored bwrap | ✅ Compiled into binary | ❌ Requires system bwrap |

**Analysis of the comparison**: The architectural difference that matters most is the **two-stage pipeline**. By re-entering its own binary inside the bwrap namespace before applying seccomp, Codex ensures that seccomp filters apply in the correct filesystem context. This is a subtle but important security property — seccomp can't be bypassed by manipulating the filesystem view after it's applied, because the filesystem is already locked down when seccomp is installed.

The process hardening in Codex is also notably more comprehensive — blocking `io_uring` syscalls via seccomp is forward-looking protection against a relatively new kernel attack surface.

## Contradictions & Debates

- **"Anthropic's sandbox is broken, Codex's works"**: This is the framing from the user's question. The reality is more nuanced. Both use the same fundamental technology (bwrap on Linux). The "broken" part specifically refers to Anthropic's `allowLocalBinding` promise on Linux. Codex never makes this promise. Codex's approach is more honest about what it can't do, and its two-stage pipeline is architecturally cleaner, but it doesn't solve the port binding problem either.

## Uncertainties & Gaps

- ⚠️ **Codex's exact seccomp filter scope**: The seccomp filter blocks many network syscalls but explicitly allows `recvfrom` for tools like cargo clippy that use socketpair for subprocess management. This is a deliberate weakening that could be exploitable.
- ⚠️ **Vendored bwrap security**: Codex compiles bwrap into its binary. If the vendored version has different security properties than system bwrap (which gets security updates from the distro), this could be a concern.
- ⚠️ **Landlock fallback stability**: The legacy Landlock fallback cannot express the full split filesystem policy model, which is why it was deprecated. Projects that need restricted-read access have no fallback if bwrap is unavailable.

## Recommendations

### Primary Recommendation

**Adopt the Codex two-stage sandbox architecture** (bwrap → re-enter → seccomp → exec) as the reference model for a local sandbox runtime. The key design principles to replicate:

1. **Separate filesystem isolation (bwrap) from syscall restriction (seccomp)** — apply them in separate stages
2. **Make the sandbox helper a standalone, testable binary** — `sandbox-linux <command>` should work independently
3. **Layer process hardening** — PR_SET_DUMPABLE=0, RLIMIT_CORE=0, strip LD_PRELOAD/DYLD_*, block ptrace/io_uring via seccomp
4. **Don't promise what you can't deliver** — if bwrap `--unshare-net` is used, don't claim local port binding works on Linux
5. **Implement managed proxy routing** — TCP↔UDS bridges for controlled outbound access through proxy env vars

### Alternative

For the port binding problem specifically, consider implementing the **reverse socat bridge** proposed in Anthropic issue #165:
- Inside sandbox: process binds to port on isolated loopback
- socat inside sandbox forwards from port to Unix socket
- socat on host listens on real `127.0.0.1:<port>` and forwards to same Unix socket

This is the approach rootless Podman uses via `slirp4netns` for the same problem.

### Not Recommended

Don't use Anthropic's sandbox-runtime as-is on Linux — the `allowLocalBinding` flag is not implemented, and the single-stage Node.js architecture makes it harder to apply seccomp correctly inside the bwrap namespace.

## Methodology

- **Depth**: Deep
- **Search rounds**: 5 rounds, 20 total queries
- **Final confidence**: 93% (from research_checkpoint)
- **Sub-questions**: 5 defined, 5 answered, 0 partially answered
- **Multi-hop chains used**: Entity expansion (Codex CLI → codex-rs source → bwrap implementation → seccomp filters), cross-project comparison (Anthropic sandbox-runtime → bwrap --unshare-net limitation → Codex issue #6737)
- **Key challenges**: Many Medium/blog sites returned 403/404 on extraction. Codex source was available locally which provided the highest-fidelity data.

## Sources

| # | Title | URL | Date | Credibility |
|---|-------|-----|------|:-----------:|
| 1 | Codex Sandbox Documentation | https://developers.openai.com/codex/sandbox | 2026 | ⭐ Tier 1 |
| 2 | Codex linux-sandbox README | https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/README.md | 2026 | ⭐ Tier 1 |
| 3 | Codex bwrap.rs source | https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/bwrap.rs | 2026 | ⭐ Tier 1 |
| 4 | Codex proxy_routing.rs source | https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/proxy_routing.rs | 2026 | ⭐ Tier 1 |
| 5 | Codex landlock.rs source (seccomp) | https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/landlock.rs | 2026 | ⭐ Tier 1 |
| 6 | Codex process-hardening source | https://github.com/openai/codex/blob/main/codex-rs/process-hardening/src/lib.rs | 2026 | ⭐ Tier 1 |
| 7 | Codex linux_run_main.rs source | https://github.com/openai/codex/blob/main/codex-rs/linux-sandbox/src/linux_run_main.rs | 2026 | ⭐ Tier 1 |
| 8 | Anthropic sandbox-runtime issue #165 | https://github.com/anthropic-experimental/sandbox-runtime/issues/165 | 2026-03-06 | ⭐ Tier 1 |
| 9 | Codex issue #6737 — Allow binding to local addresses | https://github.com/openai/codex/issues/6737 | 2025-11-16 | ⭐ Tier 1 |
| 10 | Codex issue #6224 — Landlock fallback | https://github.com/openai/codex/issues/6224 | 2025-11-04 | ⭐ Tier 1 |
| 11 | Codex GitHub Repository | https://github.com/openai/codex | 2026 | ⭐ Tier 1 |
| 12 | Northflank: Claude Code vs OpenAI Codex | https://northflank.com/blog/claude-code-vs-openai-codex | 2025-09-15 | 🔵 Tier 2 |
| 13 | Agent Safehouse GitHub | https://github.com/eugene1g/agent-safehouse | 2026 | 🔵 Tier 2 |
| 14 | Codex CLI Sandbox Analysis — Agent Safehouse | https://agent-safehouse.dev/reports/codex-sandbox | 2026-02-12 | 🔵 Tier 2 |
| 15 | Reddit: Codex localhost port collisions | https://www.reddit.com/r/ChatGPTCoding/ | 2026 | 🟡 Tier 3 |
