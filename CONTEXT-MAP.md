# Context Map

## Contexts

- [Heimdall](./CONTEXT.md) - pi package context for guarding agent tool calls
  against secret exposure and unsafe policy violations.

## Relationships

- **Heimdall -> pi**: Heimdall participates in pi sessions by registering guards
  around tool calls and tool results.
- **Heimdall -> project policy**: Heimdall reads configured policy and sandbox
  rules, then applies them during a session.
- **Heimdall -> operator**: Heimdall reports blocked actions and active sandbox
  status through pi UI notifications.

No separate bounded contexts are split out yet.
