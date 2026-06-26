# Heimdall

Heimdall is the project context for a pi package that guards agent tool use. The
language here describes the product concepts, not implementation details.

## Language

**Heimdall**:
The package that watches pi agent activity and prevents accidental secret
exposure or unsafe policy violations.
_Avoid_: plugin, wrapper

**Guard**:
A protection rule that observes a pi interaction and can block it, redact it, or
report its status.
_Avoid_: checker, filter

**Sandbox Guard**:
The guard that limits what filesystem, environment, and network surface a shell
command can access during a session.
_Avoid_: jail, container

**Opt-out Guard**:
A guard that runs by default but can be disabled by configuration.
_Avoid_: optional guard, plugin flag

**Tool Call**:
A requested action from the agent to a pi tool before the action has run.
_Avoid_: command, request

**Tool Result**:
The output returned by a pi tool after the action has run.
_Avoid_: response, command output

**Block Reason**:
The explanation returned to the agent when Heimdall prevents a tool call.
_Avoid_: error, warning

**Redaction**:
Replacement of sensitive output with a neutral marker before it reaches model
context.
_Avoid_: masking, hiding

**Secret Key**:
The environment variable name that identifies a value as sensitive.
_Avoid_: credential name, token name

**Secret Value**:
The sensitive runtime value associated with a secret key.
_Avoid_: credential, token

**Dotenv File**:
A local environment file whose contents are treated as sensitive unless it is an
example or template variant.
_Avoid_: env file

**Command Policy**:
A repository rule that blocks a family of shell commands and supplies the
preferred alternative.
_Avoid_: lint rule, command ban

**Path Policy**:
The configured access model that decides whether a path is readable, writable,
or denied during guarded execution.
_Avoid_: mount config, filesystem config

**Synthetic File**:
A configured file whose sandbox-visible contents are supplied by Heimdall rather
than read from the host.
_Avoid_: fake file, generated file

**Session**:
A single pi run in which Heimdall loads configuration and applies guards.
_Avoid_: process, invocation

**Operator**:
The human running pi who may adjust configuration or run protected commands
directly when needed.
_Avoid_: user, developer
