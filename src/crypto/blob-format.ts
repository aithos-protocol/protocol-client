// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Vault blob format — what gets AES-GCM-encrypted with `enc_key`.
//
// Shape and canonicalization rules are documented in `aithos/auth/CRYPTO.md`.
// The serializer here is the single source of truth ; both the opt-in
// register path and the login restore path go through `serializeBlob` /
// `parseBlob`.
//
// Canonical JSON : object keys sorted lexicographically, no extra
// whitespace, UTF-8. Strict canonicalization isn't required for AES-GCM
// correctness (the auth tag only cares about bytes), but it makes the
// format deterministic for tests and for any future server-side audit.

import type { StoredDelegate } from "../storage-types.js";

export const BLOB_VERSION = 1 as const;

/** Identity metadata mirrored inside the blob. The DID is also visible
 *  in the JWT, so this duplication is just for convenience when the
 *  client decrypts the blob to hydrate its keystore. */
export interface BlobIdentity {
  readonly did: string;
  readonly handle: string;
  readonly displayName: string;
}

/** All four seeds as 64-char lowercase hex (32 bytes each). */
export interface BlobSeeds {
  readonly root: string;
  readonly public: string;
  readonly circle: string;
  readonly self: string;
}

export interface BlobPlaintext {
  readonly version: typeof BLOB_VERSION;
  readonly seeds: BlobSeeds;
  readonly identity: BlobIdentity;
  readonly delegates: readonly StoredDelegate[];
}

export class BlobFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BlobFormatError";
  }
}

/* -------------------------------------------------------------------------- */
/*  Canonical JSON                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Stable JSON encoding with sorted object keys.
 *
 * `JSON.stringify` already preserves array order ; we only need to sort
 * object keys. We do this recursively because a nested mandate object
 * carrying `{ scopes: [...], not_after: "..." }` would otherwise depend
 * on insertion order. Two different machines that produce the same
 * `BlobPlaintext` MUST yield the same bytes.
 */
function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) {
    out[k] = canonicalize(obj[k]);
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/*  Validation                                                                */
/* -------------------------------------------------------------------------- */

const HEX_64 = /^[0-9a-f]{64}$/;

function assertHex32(seed: unknown, name: string): asserts seed is string {
  if (typeof seed !== "string" || !HEX_64.test(seed)) {
    throw new BlobFormatError(`${name}: expected 32-byte hex string (64 chars, lowercase)`);
  }
}

function assertNonEmpty(s: unknown, name: string): asserts s is string {
  if (typeof s !== "string" || s.length === 0) {
    throw new BlobFormatError(`${name}: expected non-empty string`);
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Validates the runtime shape of a `BlobPlaintext` candidate. */
function validate(p: unknown): asserts p is BlobPlaintext {
  if (!isPlainObject(p)) throw new BlobFormatError("not an object");
  if (p["version"] !== BLOB_VERSION) {
    throw new BlobFormatError(`unsupported blob version: ${String(p["version"])}`);
  }
  const seeds = p["seeds"];
  if (!isPlainObject(seeds)) throw new BlobFormatError("seeds: not an object");
  assertHex32(seeds["root"], "seeds.root");
  assertHex32(seeds["public"], "seeds.public");
  assertHex32(seeds["circle"], "seeds.circle");
  assertHex32(seeds["self"], "seeds.self");

  const identity = p["identity"];
  if (!isPlainObject(identity)) throw new BlobFormatError("identity: not an object");
  assertNonEmpty(identity["did"], "identity.did");
  assertNonEmpty(identity["handle"], "identity.handle");
  // displayName may be empty string but must be a string.
  if (typeof identity["displayName"] !== "string") {
    throw new BlobFormatError("identity.displayName: expected string");
  }

  const delegates = p["delegates"];
  if (!Array.isArray(delegates)) {
    throw new BlobFormatError("delegates: expected array");
  }
  for (const d of delegates) {
    if (!isPlainObject(d)) throw new BlobFormatError("delegates[*]: not an object");
    // We trust the underlying StoredDelegate type here. The vault is
    // round-tripping bundles produced and consumed by the same app, so
    // detailed structural validation lives where the bundles are
    // accepted from the network.
  }
}

/* -------------------------------------------------------------------------- */
/*  Public API                                                                */
/* -------------------------------------------------------------------------- */

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Serialize a blob plaintext to canonical UTF-8 bytes ready for
 * `encryptBlob(enc_key, nonce, …)`.
 *
 * Throws `BlobFormatError` on malformed input — caller must have already
 * built a well-formed object via {@link buildBlobPlaintext}.
 */
export function serializeBlob(plaintext: BlobPlaintext): Uint8Array {
  validate(plaintext);
  const json = JSON.stringify(canonicalize(plaintext));
  return encoder.encode(json);
}

/**
 * Inverse of {@link serializeBlob}. Throws `BlobFormatError` if bytes
 * don't decode to a valid v1 blob — typically caused by a wrong password
 * (decryption yielded random-looking bytes that don't parse as JSON).
 */
export function parseBlob(bytes: Uint8Array): BlobPlaintext {
  let text: string;
  try {
    text = decoder.decode(bytes);
  } catch {
    throw new BlobFormatError("decoded bytes are not valid UTF-8");
  }
  let obj: unknown;
  try {
    obj = JSON.parse(text);
  } catch (e) {
    throw new BlobFormatError(`invalid JSON: ${(e as Error).message}`);
  }
  validate(obj);
  return obj;
}

/**
 * Convenience for the register path : build a `BlobPlaintext` from the
 * raw pieces produced by `runOnboarding()`. The seeds are expected as
 * 32-byte Uint8Arrays ; we hex-encode here so the canonical form stays
 * JSON-friendly.
 */
export function buildBlobPlaintext(input: {
  readonly identity: BlobIdentity;
  readonly seeds: {
    readonly root: Uint8Array;
    readonly public: Uint8Array;
    readonly circle: Uint8Array;
    readonly self: Uint8Array;
  };
  readonly delegates?: readonly StoredDelegate[];
}): BlobPlaintext {
  return {
    version: BLOB_VERSION,
    identity: input.identity,
    seeds: {
      root: bytesToHex(input.seeds.root),
      public: bytesToHex(input.seeds.public),
      circle: bytesToHex(input.seeds.circle),
      self: bytesToHex(input.seeds.self),
    },
    delegates: input.delegates ?? [],
  };
}

/* -------------------------------------------------------------------------- */
/*  Hex utility                                                               */
/* -------------------------------------------------------------------------- */

function bytesToHex(b: Uint8Array): string {
  if (b.length !== 32) {
    throw new BlobFormatError("seed: expected 32 bytes");
  }
  let out = "";
  for (let i = 0; i < b.length; i++) out += b[i]!.toString(16).padStart(2, "0");
  return out;
}

export function hexToSeed(hex: string): Uint8Array {
  if (!HEX_64.test(hex)) throw new BlobFormatError("expected 64-char hex string");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
