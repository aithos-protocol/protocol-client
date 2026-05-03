# Changelog

All notable changes to `@aithos/protocol-client` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.8] — 2026-05-03

### Added
- **Compute proxy client** (`src/compute.ts`) — single-shot Bedrock invocation
  through `compute.aithos.be/v1/invoke`. Builds a signed envelope with the
  user's public-sphere key, posts JSON-RPC with `mandate_id` and `app_did`,
  parses the proxy's response (content + usage + billing metadata).
  - Public surface: `invokeBedrock`, `ComputeError`, `DEFAULT_COMPUTE_ENDPOINT`,
    types `ComputeMessage`, `InvokeBedrockArgs`, `InvokeBedrockResult`,
    `StopReason`.
  - Errors are surfaced as `ComputeError` with stable `code` tags so callers
    can branch on `network` / `http` / `empty` / JSON-RPC error codes.
  - Multi-turn agentic loops with native tool calling are deferred to a
    follow-up release; for now apps drive the loop client-side by calling
    `invokeBedrock` per turn.
- 9 unit tests for the compute client (mocked `fetch`, asserts envelope
  structure, params shape, error mapping, abort signal propagation).

### Documentation
- Bumped `VERSION` constant in `src/index.ts`.

## [0.1.0-alpha.7] — 2026-05-01

### Fixed
- `package.json` `repository.url` and `bugs.url` now point at
  `github.com/aithos-protocol/protocol-client` (the canonical org-level
  repo). Previous releases lingered on `github.com/Math1987/protocol-client`
  from a transient stage of the move into the `aithos-protocol` org.

### Documentation
- README "Status" section: clarified that during the alpha phase the npm
  `latest` tag tracks the most recent alpha so the package page reflects
  current code (license, deps, README). Once `0.1.0` stable ships, `latest`
  moves to the stable line and pre-releases remain available under `@alpha`.

## [0.1.0-alpha.6] — 2026-04-30

### License
- Switched from **BUSL-1.1** to **Apache License 2.0**. The reference
  implementation is now under a permissive OSI-approved license, immediately
  and irrevocably for the `0.x` line. Rationale: at zero traction, BUSL costs
  more in adoption friction (excluded from distros, OSI-only enterprise
  policies, community pushback) than it protects. For a protocol client
  meant to be embedded everywhere, adoption *is* value. This aligns with the
  same decision taken in `aithos-protocol` (see ADR-0007 there).
- `LICENSE` file replaced with the canonical Apache-2.0 text.
- `package.json` `"license"` field switched to `"Apache-2.0"`.
- All source files (`src/`, `test/`) now carry an
  `// SPDX-License-Identifier: Apache-2.0` header.
- Versions `0.1.0-alpha.1` through `0.1.0-alpha.5` (published under BUSL-1.1)
  remain under BUSL-1.1 for anyone who already obtained them.

### Dependencies
- Bumped **`@aithos/protocol-core`** from `^0.3.0` to `^0.5.0` — picks up the
  pluggable storage backend, signed envelopes (`signEnvelope` /
  `verifyEnvelope`), and the matching Apache-2.0 release of the protocol
  primitives.

## [0.1.0-alpha.5] — 2026-04-25

### Fixed
- `fetchActiveDelegateRecipients` now applies `impliedRead` (write.X implies
  read.X), matching the behavior of the synchronous helpers.

## [0.1.0-alpha.3] — 2026-04-24

### Added
- `parseConnectRequest` and `signAndPublishMandate` helpers for the connect
  flow.

## [0.1.0-alpha.1] — 2026-04-24

### Added
- Initial extraction from the `innoesate` monorepo (19 files, ~3.9k LOC):
  Ed25519/X25519 crypto primitives, identity model, ethos edition builder,
  delegate-mandate workflow, JSON-RPC client for `api.aithos.be`.
