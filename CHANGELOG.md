# Changelog

All notable changes to `@aithos/protocol-client` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.23] — 2026-06-08

### Changed

- **`runOnboarding` now mints a v0.3 first edition.** It previously built a v0.2
  monolithic edition via `buildSignedFirstEdition`, which `loadEthosV03` then
  rejected — so a freshly-onboarded ethos was unreadable through the v0.3
  transport. It now authors a v0.3 per-section edition (`authorBundleV03`, public
  zone) after `publish_identity`, posting per-section blobs. Same did-hash
  convention, so the server accepts it unchanged.

### Added

- `loadEthosV03` tags its "not a v0.3 edition" error with
  `data: { legacy: true, aithos }`, so a caller (the SDK) can detect a legacy
  v0.2 ethos and migrate it.

## [0.1.0-alpha.22] — 2026-06-08

### Added

- **Delegate authoring wired through the v0.3 editor.**
  `publishEthosEditionV03Delegate` (`editor-v03.ts`) mirrors the owner publish
  but patches ONLY the delegate's `actorSphere` via `patchEditionV03Delegate`
  (carrying every other zone forward verbatim) and signs the §11 envelope with
  the delegate key + mandate (bare-multibase `verificationMethod`). Subject
  identity (did/handle/display name) comes from the predecessor manifest — a
  delegate never mints a first edition. Completes the per-section delegate write
  path the SDK `EthosClient` rides on (#52).

## [0.1.0-alpha.21] — 2026-06-07

### Added

- **Per-section delegate recipients in the v0.3 owner author (§3.5.7′).**
  `authorBundleV03` now accepts `delegateGrants` and seals each section's DEK to
  the subject **plus every delegate whose read-bearing verb-scopes cover that
  specific section** — a whole-zone read grant matches every section, a
  section-scoped grant only its own (carry-forward re-encrypts only the sections
  whose recipient set changed). New `fetchActiveDelegateGrants` (list/get-mandate
  + scopes) feeds it from `publishEthosEditionV03Owner`, and a browser-safe
  `crypto/ethos-scope.ts` (`parseEthosScope` / `coversRead`) does the matching.
  Closes per-section READ scoping in the SDK/app owner-publish path.

### Changed

- **Ethos verb-scopes (draft `bundle-v0.3-section-verb-scopes.md`).** Client-side
  mint brought into lockstep with protocol-core 0.9.0:
  - `crypto/mandate.ts`: `MANDATE_VERSION_CURRENT` 0.3.0 → **0.5.0**;
    `validateScopesAgainstSphere` generalised to the verb grammar
    (`ethos.<verb>.<zone>[#…]`) — a mutating verb (write/edit/append/delete)
    requires the matching actor sphere, the public sphere allows any
    `ethos.*.public` / `ethos.read.all` (+ `gamma.read`, `compute.invoke`,
    `data.*`), and a circle mandate may carry no `self`-zone ethos scope.
  - `delegate-recipients.ts`: wrap-list membership now recognises every
    read-bearing verb (read/edit/append/write, with or without a selector) on a
    zone, so delegates granted the new verbs are still sealed for (zone-level
    wrap model unchanged; per-section narrowing in the owner-author path is
    tracked separately).
- Peer/dep `@aithos/protocol-core` → `^0.9.0`.

## [0.1.0-alpha.20] — 2026-06-06

### Added

- **v0.3 per-section bundle support.** `crypto/bundle-v03.ts` (read: manifest
  types, `decryptSection` / `decryptSectionTitle`, `readZoneIndex`, `readSection`,
  owner/delegate `SectionReader`) and `crypto/bundle-v03-write.ts` (author: owner
  `authorBundleV03` with byte-identical carry-forward, `patchEditionV03Delegate`
  for section-scoped delegate authoring, v0.3 manifest signing). AADs are
  byte-identical with `@aithos/protocol-core` (cross-impl tested).
- **v0.3 editor (`editor-v03.ts`):** `loadEthosV03` (manifest + per-zone index +
  per-section decrypt over `get_ethos_manifest` / `get_ethos_section`) and
  `publishEthosEditionV03Owner` (author + signed §11 publish, carry-forward).
- **Public endpoint config:** `configureEndpoints` / `resetEndpoints` (promote the
  former internal `_setEndpoints`) so consumers (the SDK) can point api/cdn at a
  dev account.

### Changed

- Requires `@aithos/protocol-core` `^0.8.0` (per-section v0.3 default).

## [0.1.0-alpha.19] — 2026-06-01

### Added

- **Optional dedicated `#data` sphere** in the browser identity path
  (spec/data/02-key-hierarchy.md §2.2). `createBrowserIdentity` is now eager —
  new identities carry a `#data` keypair; `signedDidDocument` appends a `#data`
  verificationMethod + a `#data-kex` keyAgreement entry **after** the three Ethos
  spheres (root-signed, canonical order matching `@aithos/protocol-core`). The
  recovery/vault blob (`blob-format.ts`) and the keystore types serialize an
  optional `data` seed; `browserIdentityFromStored` rehydrates it when present.

  Purpose: owner data/asset PDS envelopes can sign under `#data` so the root key
  stays cold (the data sub-protocol's intended convention).

  **Backward compatible**: `#data` is optional everywhere — legacy identities,
  vaults, and recovery files (root/public/circle/self only) still load and
  operate under `#root`. No wire-format change; 81 existing + 5 new `#data`
  tests pass.

## [0.1.0-alpha.18] — 2026-06-01

### Changed

- Raise the `@aithos/protocol-core` dependency floor from `^0.6.3` to `^0.6.5`.
  0.6.5 makes the envelope/mandate verify path browser-bundleable (no `node:`
  built-ins) and `Buffer`-free at runtime. Since this client imports
  `@aithos/protocol-core/envelope` into browser apps, pinning the floor
  guarantees consumers can't resolve a 0.6.3/0.6.4 that throws
  `Buffer is not defined` in the browser. No code change.

## [0.1.0-alpha.17] — 2026-05-31

> ⚠️ **Coordinated release.** The envelope-signing change below switches the
> client to the "with-proof" convention. It MUST NOT be deployed/consumed until
> the Aithos servers run the dual-verify EXPAND step
> (`platform/shared`, accept with-proof OR without-proof) in production. See
> `PLAN-ENVELOPE-PROOF-CONVERGENCE.md`.

### Changed

- **Canonicalization unified onto `@aithos/protocol-core`.** `src/crypto/
  canonical.ts` now re-exports core's `canonicalize` instead of a hand-ported
  copy — the exact function the Aithos servers (`platform/shared`) already use,
  removing any client/server drift on the bytes that envelope signatures,
  mandate signatures and ethos edition hashes commit to. Byte-identity over a
  representative corpus is proven by `test/canonical-core-conformance.test.ts`.
  (Stricter on one edge: an `undefined` object value now throws per RFC 8785
  rather than being silently skipped — Aithos payloads never carry undefined.)
- **`buildSignedEnvelope` signs in the "with-proof" convention** (spec §5.1.1 /
  Ed25519Signature2020), delegating to core's `signEnvelope` /
  `signEnvelopeWithMandate`. Replaces the former "without-proof" ported signer.
  The function stays synchronous; call sites are unchanged. This aligns the
  client with the data-PDS and with how mandates/revocations are already signed.

### Dependencies

- `@aithos/protocol-core` `^0.5.0` → `^0.6.3` (now a real runtime dependency,
  not vestigial — the client imports core's `canonicalize` and envelope signers).

## [0.1.0-alpha.16] — 2026-05-30

### Added

- **`signMandate` accepts the lateral `data.<collection>.append` scope.**
  Append is insert-only and grants no read (mirrors protocol-core). Like
  write/compute mandates, an append mandate now requires `grantee.pubkey`
  (the depositor signs each insert envelope) but needs no `kex_pubkey` — the
  depositor seals each DEK to the owner's public key
  (`@aithos/data-crypto` `encryptRecordForRecipient`) and keeps no read
  capability. `mintDelegateBundle` already supplies the grantee key, so
  minting an append bundle works end-to-end. Kept in lockstep with
  `@aithos/protocol-core`.

## [0.1.0-alpha.15] — 2026-05-30

### Added

- **`validateScopesAgainstSphere` permits `data.*` scopes under the public
  sphere.** Data access scopes (`data.<collection>.<action>`) are
  sphere-neutral — the data access axis is the collection, and the
  cryptographic binding is the grantee key + CMK wrap, not the sphere
  (`aithos-protocol` `spec/data/04-mandates.md` §4.4). They are now accepted
  under every `actor_sphere`, including `public`. This unblocks combined
  mandates such as `ethos.read.public` + `data.<col>.read`. Mirrors
  `@aithos/protocol-core` `validateScopesAgainstSphere` — kept in lockstep.

## [0.1.0-alpha.14] — 2026-05-28

### Added

- **`buildSignedFirstEditionFromSections` accepts encrypted-zone sections
  at height=1.** New optional args:
  - `circleSections?: readonly Section[]`
  - `selfSections?: readonly Section[]`
  - `delegateRecipientsCircle?: readonly EncryptRecipient[]`
  - `delegateRecipientsSelf?: readonly EncryptRecipient[]`

  When passed, each non-empty private zone is sealed via the same
  `sealPrivateZone` helper used by `buildSignedNextEdition` (fresh DEK +
  HKDF wrap for the owner + any delegate recipients, XChaCha20-Poly1305-IETF
  ciphertext). The resulting manifest is verifiable by the existing
  reader path with no special-casing of height=1.

- `BuildFirstEditionResult` gains optional `circleBytes?: Uint8Array`
  and `selfBytes?: Uint8Array` — the sealed ciphertext bytes to upload
  alongside the manifest as `zones.circle.bytes_base64` /
  `zones.self.bytes_base64` in `aithos.publish_ethos_edition`.

### Unchanged

- `buildSignedFirstEdition` (the single-section wrapper used by
  `runOnboarding`) is byte-for-byte unchanged. It continues to emit a
  public-only first edition.
- An existing call site that only passes `publicSections` produces the
  exact same manifest as before — all new args are optional and
  non-breaking.
- `publicSections` remains required and non-empty. Callers that only
  have circle/self content to land at height=1 should pass a sentinel
  public section (e.g. `aithos-init`) alongside; the protocol spec
  would allow a missing public zone, but every resolution flow (handle
  lookup, did.json discovery, public crawl) assumes one exists.

### Migration

None required. Existing call sites continue to work. New capability is
opt-in via the new args.

## [0.1.0-alpha.13] — 2026-05-10

### Fixed

- **`mintDelegateBundle` and `signAndPublishMandate` now sign mandates
  with `not_before = now - 30s` by default**, so a server whose clock
  runs slightly behind the client doesn't reject the freshly-minted
  mandate as `Mandate not yet valid`. Previously the underlying
  `signMandate` accepted a `notBefore` arg but it wasn't threaded
  through the higher-level mint chain — every mint used `Date.now()`,
  which caused intermittent `-32040` rejections in production whenever
  client/Lambda clock skew exceeded a few hundred ms.

### Added

- `notBefore?: Date` field on `MintArgs` (mintDelegateBundle) and
  `SignAndPublishMandateArgs`. Caller can override the default offset
  for advanced flows (delayed-activation mandates, deterministic tests,
  etc.).
- `MANDATE_NOTBEFORE_OFFSET_SECONDS_DEFAULT` exported constant (= 30,
  matches the verifier's `MANDATE_CLOCK_SKEW_SECONDS_DEFAULT` in
  `@aithos/protocol-core@>=0.5.2` so client and server are aligned).

## [0.1.0-alpha.12] — 2026-05-10

### Added

- **`buildSignedFirstEditionFromSections({identity, signedDidDoc, publicSections})`**
  — multi-section variant of `buildSignedFirstEdition`. Accepts an arbitrary
  list of `Section[]` for the public zone of the first edition (height=1,
  prev_hash=null), instead of forcing a single seed section via the
  `publicTitle`/`publicBody` pair. Used by `@aithos/sdk@>=0.1.0-alpha.7`'s
  first-`publish()` path so a user who staged N additions before their first
  publish lands them all in one edition rather than getting forced to publish
  twice.

  `publicSections` MUST be non-empty (a manifest must declare at least one
  zone). Encrypted-zone (circle / self) first editions remain unsupported by
  this helper — publish them as a subsequent edition via
  `buildSignedNextEdition`.

### Changed

- `buildSignedFirstEdition` is now a thin wrapper around
  `buildSignedFirstEditionFromSections`. Public API and on-wire output are
  unchanged: same byte-for-byte rendered markdown, same manifest shape,
  same signature.

## [0.1.0-alpha.10] — 2026-05-05

### Removed (BREAKING for direct callers; mitigated by `@aithos/sdk`)
- **`src/compute.ts` and all its public exports** — `invokeBedrock`,
  `ComputeError`, `DEFAULT_COMPUTE_ENDPOINT`, types `ComputeMessage`,
  `InvokeBedrockArgs`, `InvokeBedrockResult`, `StopReason`.
- The `computeInvokeEndpoint()` helper from `src/endpoints.ts` is also
  removed — it was only used by the deleted `compute.ts`.
- Test file `test/compute.test.ts` removed.

### Why
`compute.ts` was a temporary lodging place for the Bedrock proxy client.
Its proper home is `@aithos/sdk` (which now ships its own implementation
in `0.1.0-alpha.1+`). Keeping a duplicate in protocol-client invited
divergence; this release retires it cleanly.

### Migration
Apps invoking Bedrock should switch to `@aithos/sdk`:

```diff
- import { invokeBedrock } from "@aithos/protocol-client";
- const out = await invokeBedrock({ identity, appDid, mandateId, … });

+ import { AithosSDK } from "@aithos/sdk";
+ const sdk = new AithosSDK({ identity, appDid });
+ const out = await sdk.compute.invokeBedrock({ mandateId, … });
```

The two are wire-compatible (both POST a §11 signed envelope to
`compute.aithos.be/v1/invoke`); only the package surface and the SDK's
namespaced ergonomics differ.

### Note on alpha.8 / alpha.9
Both versions exist as commits in this repo's git history but were never
published to npm. alpha.7 (the latest published) does not contain
`compute.ts`, so for npm users this is a clean continuation —
`alpha.7 → alpha.10` with no deprecation cycle to navigate.

## [0.1.0-alpha.9] — 2026-05-03 (unpublished)

### Changed (internal — no public API change)
- **Centralized endpoint configuration** in `src/endpoints.ts`. The lib's
  HTTP targets (`api`, `cdn`, `compute`, `auth`) now live in a single mutable
  table, with public read-only access via `getEndpoints()` /
  `DEFAULT_ENDPOINTS` and internal-only overrides via `_setEndpoints` /
  `_resetEndpoints` (NOT re-exported from the package barrel).
- All consumers refactored to use the centralized table via URL builder
  helpers (`readEndpoint`, `writeEndpoint`, `converseEndpoint`,
  `computeInvokeEndpoint`):
  - `api.ts` — `getEndpoints().api` resolved per-call
  - `onboarding.ts`, `editor.ts`, `mandate-mint.ts` — `writeEndpoint()`
  - `compute.ts` — `computeInvokeEndpoint()` (default) with per-call
    `endpoint` override preserved
- `DEFAULT_COMPUTE_ENDPOINT` (alpha.8 export) now aliases
  `DEFAULT_ENDPOINTS.compute` for consistency. Stable.

### Why
Posture set in PLATFORM-COMPUTE-DESIGN.md §"Posture open-source et contrat
de stabilité": the lib is open-source, by default plugged on Aithos. The
endpoint table lives in a separable module so a future public configuration
API for self-hosting is a non-breaking addition. **No public configurability
is exposed yet** — that decision is reserved.

### Tests
- 8 new tests for `endpoints.ts` (defaults, URL builders, overrides,
  immutability of `DEFAULT_ENDPOINTS`).
- All existing tests still pass (49 total).

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
