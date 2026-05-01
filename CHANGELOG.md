# Changelog

All notable changes to `@aithos/protocol-client` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
