# AGENTS.md

## Project

`@casualjim/pi-heimdall` is a pi package that registers one extension entry point
and several independent security guards. Its job is to block or redact tool
activity that could expose secrets or bypass a repository policy.

Runtime TypeScript is loaded directly by pi. There is no build step.

## Layout

- `extensions/heimdall.ts` loads user/project config, merges it, reports active
  guards, and registers every guard.
- `guards/types.ts` owns shared config types only.
- `guards/sandbox-guard.ts` wraps bash with bubblewrap and enforces the same path
  policy for pi file tools.
- `guards/secret-guard.ts` blocks secret key references and redacts secret values
  from bash output.
- `guards/env-protect.ts` blocks reads of real dotenv files while allowing example
  variants.
- `guards/kubectl-secret-guard.ts` blocks risky Kubernetes secret/finalizer/env
  commands.
- `guards/sops-secret-guard.ts` blocks sops decrypting commands.
- `guards/command-policy-guard.ts` enforces `.pi/heimdall.json` command policies.
- `.pi/heimdall.json` is this repository's sample/local policy config.

## Commands

- Install dependencies: `npm install`
- Typecheck package code: `npm run typecheck`
- Run Vitest suite: `npm test`
- Check published contents: `npm run check:pack`
- Do not run `npm run build`; this package has no build script.

CI and publish workflows run `npm ci`, `npm run typecheck`, and
`npm run check:pack`. `npm test` is available locally but is not currently in
CI.

## Guard Rules

- Keep guards independent. Do not add cross-guard runtime state unless the user
  asks for a broader design change.
- Keep shared code boring and local. Put shared types in `guards/types.ts`; avoid
  new helper modules until at least two guards need the same logic.
- Security changes should fail closed at trust boundaries. A blocked tool call
  needs a clear reason and must not suggest bypassing Heimdall.
- Preserve the opt-out model: `sandbox-guard` is always registered and follows
  sandbox config; the other guards can be disabled through `disabled`.
- Preserve config loading semantics: user config and project config are
  deep-merged, project config wins for scalars/objects, arrays concatenate.
- For command parsing, prefer the existing tokenized path in
  `command-policy-guard.ts` over ad hoc string splitting.
- For regex-based guards, update both blocked and allowed examples. False
  positives are product bugs here, not harmless noise.
- For sandbox changes, keep synthetic files from exposing host files through
  direct read tools.

## Testing Notes

- `vitest.config.ts` excludes `tests/command-policy-guard.test.ts`; do not assume
  `npm test` covers command-policy parser behavior.
- When changing a guard, add or update at least one test that proves the intended
  block and one test that proves a nearby allowed command still passes.
- When changing package metadata or published files, run `npm run check:pack`.

## Release Notes

Publishing is handled by `.github/workflows/release.yml` on `main`. It publishes
the current `package.json` version if it is not already on npm, then bumps the
next version with `[skip ci]`.
