// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// @aithos/protocol-client — public API surface.
//
// Alpha phase: we re-export the full module surface to let consumers
// iterate fast. Names will be curated / narrowed before 0.1.0 stable.
//
// Import shape:
//   import { readRpc, buildSignedEnvelope, createBrowserIdentity } from "@aithos/protocol-client";
//
// Four naming collisions inherited from the monorepo are resolved here by
// picking a canonical source per name:
//   - `SealedZone`       → delegate-recipients (the zone enum "circle" | "self").
//                          crypto/encrypt's local `SealedZone` result object
//                          stays internal — use `encryptZone()` directly.
//   - `DidDocument`      → types.ts (the wire-format shape). crypto/identity's
//                          authoring shape stays internal to that module.
//   - `ZoneCipher`       → crypto/decrypt (the canonical shape).
//   - `Manifest`         → types.ts (wire-format). crypto/manifest's authoring
//                          structure stays internal; its builders are exported.

// ⚠️ Keep in sync with package.json "version" on every release (the exported
// VERSION had drifted to alpha.14 while the package moved on — consumers
// branching on it got stale info). A release script should bump both.
export const VERSION = "0.1.0-alpha.41";

// --- API client (JSON-RPC 2.0 to api.aithos.be) ---
export * from "./api.js";

// --- Bounded-concurrency mapper (per-section RPC fan-out) ---
export * from "./concurrency.js";

// --- Opt-in perf caches (identity doc + delegate grants) ---
export * from "./perf-cache.js";

// --- Connect handshake parser + sphere inference ---
export * from "./connect-request.js";

// --- DID helpers ---
export * from "./did.js";

// --- Wire-format types (canonical for DidDocument, Manifest) ---
export * from "./types.js";

// --- Endpoints (api / cdn / compute / auth resolution) ---
//
// Only the read-only surface is exposed: type, defaults, getter, URL
// builders. The `_setEndpoints` / `_resetEndpoints` overrides remain
// internal — see the comment in src/endpoints.ts about the future public
// self-hosting configuration API.
export {
  type AithosEndpoints,
  DEFAULT_ENDPOINTS,
  getEndpoints,
  configureEndpoints,
  resetEndpoints,
  readEndpoint,
  writeEndpoint,
} from "./endpoints.js";

// --- Storage contracts (what a keystore impl must produce/consume) ---
export * from "./storage-types.js";

// --- Zone parser (markdown → sections) ---
export * from "./zone-parser.js";

// --- Ethos edition editor (high-level: load, modify, publish) ---
export * from "./editor.js";

// --- v0.3 per-section editor (read + owner publish over the v0.3 RPCs) ---
export * from "./editor-v03.js";
export * from "./editor-v04.js";
export { manifestHashHexV04Pc } from "./crypto/bundle-v04.js";
export {
  openZoneKey as openZoneKeyV04Pc,
  sealZoneKeyTo as sealZoneKeyToV04Pc,
  type KeyRingV04Pc,
  type ExtraWrapsV04Pc,
} from "./crypto/bundle-v04.js";

// --- Delegate recipients resolution (canonical for SealedZone) ---
export * from "./delegate-recipients.js";

// --- Mandate mint (build + sign a delegate bundle) ---
export * from "./mandate-mint.js";

// --- Revocation epoch (one-write "revoke all mandates") ---
export * from "./mandate-epoch.js";

// --- Onboarding (create identity, publish first edition) ---
export * from "./onboarding.js";

// NOTE: Bedrock compute proxy client lives in `@aithos/sdk` since
// alpha.10. This package keeps its scope strictly to crypto, identity,
// mandates, and ethos editions; consult the SDK for `invokeBedrock`.

// --- Cryptography primitives ---
export * from "./crypto/canonical.js";
export * from "./crypto/ed25519.js";
export * from "./crypto/encoding.js";

// Argon2id KDF + AES-GCM blob primitives — used by @aithos/sdk's
// password-based auth helpers (signIn, signUp). Apps that don't touch
// the auth surface can ignore these.
export {
  DEFAULT_KDF,
  ARGON2_KEY_BYTES,
  ARGON2_SALT_BYTES,
  argon2idKey,
  deriveAuthAndEncKeys,
  randomSalt,
  zeroize,
  type KdfParams,
} from "./crypto/argon2id.js";

export {
  BLOB_KEY_BYTES,
  BLOB_NONCE_BYTES,
  encryptBlob,
  decryptBlob,
  randomNonce,
} from "./crypto/blob.js";

export {
  BLOB_VERSION,
  BlobFormatError,
  buildBlobPlaintext,
  hexToSeed,
  parseBlob,
  serializeBlob,
  type BlobIdentity,
  type BlobPlaintext,
  type BlobSeeds,
} from "./crypto/blob-format.js";

// crypto/encrypt — exclude local SealedZone (canonical is from delegate-recipients).
export {
  encryptZone,
  type EncryptRecipient,
  type SealedWrap,
} from "./crypto/encrypt.js";

// crypto/decrypt — canonical for ZoneCipher.
export * from "./crypto/decrypt.js";

// crypto/bundle-v03 — v0.3 per-section READ (manifest, index, per-section decrypt).
export {
  type SectionCipher,
  type SectionTitle,
  type TitleCipher,
  type SectionDescriptor,
  type BundleZoneV2,
  type ManifestV03,
  type SphereName,
  type SectionReader,
  type IndexRow,
  type SectionReadResult,
  isV03Manifest,
  ownerSectionReader,
  delegateSectionReader,
  decryptSection,
  decryptSectionTitle,
  parseSectionMarkdown,
  readZoneIndex,
  readSection,
  locateSection,
} from "./crypto/bundle-v03.js";

// crypto/bundle-v03-write — v0.3 per-section WRITE (author an edition).
export {
  type SectionRecipient,
  type WriteSectionCtx,
  type WrittenSection,
  type AuthorV03Args,
  type AuthoredV03,
  type DelegateAuthorV03,
  type DelegatePatchArgs,
  type DelegateReadGrant,
  type OwnerPatchArgs,
  subjectRecipient,
  renderSectionMarkdown,
  encryptSection,
  encryptSectionTitle,
  writeSection,
  signManifestV03,
  signManifestV03Delegate,
  canonicalManifestV03HashHex,
  authorBundleV03,
  delegateZoneRecipients,
  ownerZoneKexPubkey,
  patchEditionV03Delegate,
  patchEditionV03Owner,
} from "./crypto/bundle-v03-write.js";

export * from "./crypto/envelope.js";

// crypto/identity — exclude local DidDocument (canonical is types.ts).
export {
  type BrowserIdentity,
  type DidDocumentProof,
  type KeyAgreementMethod,
  SPHERES,
  type Sphere,
  type VerificationMethod,
  browserIdentityFromStored,
  createBrowserIdentity,
  signedDidDocument,
  sphereDidUrl,
} from "./crypto/identity.js";

export * from "./crypto/kex.js";
export * from "./crypto/mandate.js";

// crypto/manifest — exclude ZoneCipher (→ decrypt) and Manifest (→ types).
export {
  type BuildDelegatePrivateEditionArgs,
  type BuildDelegatePrivateEditionResult,
  type BuildDelegatePublicEditionArgs,
  type BuildDelegatePublicEditionResult,
  type BuildFirstEditionArgs,
  type BuildFirstEditionFromSectionsArgs,
  type BuildFirstEditionResult,
  type BuildNextEditionArgs,
  type BuildNextEditionResult,
  type DelegatePublicSigner,
  type ManifestSignature,
  type Section,
  type ZoneDoc,
  type ZoneManifest,
  type ZoneSignature,
  type ZoneWrap,
  buildSignedFirstEdition,
  buildSignedFirstEditionFromSections,
  buildSignedNextEdition,
  buildSignedNextEditionAsDelegatePrivate,
  buildSignedNextEditionAsDelegatePublic,
  canonicalManifestHashHex,
} from "./crypto/manifest.js";