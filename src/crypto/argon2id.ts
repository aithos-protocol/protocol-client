// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Argon2id key derivation for the Aithos password-based vault.
//
// Two entry points :
//
//   - `argon2idKey(password, salt, kdf?)`            single derivation
//   - `deriveAuthAndEncKeys(password, authSalt, encSalt, kdf?)`
//                                                    pair derivation
//
// The cryptographic invariants live in `aithos/auth/CRYPTO.md`. The short
// version : Argon2id with OWASP-recommended parameters (m=65536, t=3, p=1)
// in 32-byte mode, AES-256-GCM with a fresh 12-byte nonce on every
// encryption (cf. ./blob.ts).
//
// `auth_key` is sent to the auth server (which hashes it again with
// Argon2id before checking against the stored hash) as a login proof.
// `enc_key` never leaves the browser; it encrypts the JSON blob containing
// the user's seeds and received delegate bundles.

import { argon2id as argon2idHashWasm } from "hash-wasm";

/* -------------------------------------------------------------------------- */
/*  Constants                                                                 */
/* -------------------------------------------------------------------------- */

/** Default KDF parameters — OWASP 2024 recommendation for password-only auth. */
export const DEFAULT_KDF: KdfParams = Object.freeze({
  m: 65536, // memory cost in KiB (64 MiB)
  t: 3, // time cost / iterations
  p: 1, // parallelism (single-threaded WASM)
});

export interface KdfParams {
  /** Memory cost in KiB. */
  readonly m: number;
  /** Time cost / iterations. */
  readonly t: number;
  /** Parallelism (typically 1 in browsers — hash-wasm is single-threaded). */
  readonly p: number;
}

/** Salt size in bytes. 16 bytes = 128 bits, more than enough domain separation. */
export const ARGON2_SALT_BYTES = 16;

/** Derived key length in bytes — 256 bits, fits AES-256 and a login proof. */
export const ARGON2_KEY_BYTES = 32;

/* -------------------------------------------------------------------------- */
/*  Random helpers                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Throws if no Web Crypto getRandomValues is available. Every modern
 * browser has it, and Node 19+ exposes it on `globalThis.crypto`. We
 * keep the explicit check so a misconfigured environment fails loudly
 * rather than silently using `Math.random`.
 */
function getRandom(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  const c =
    typeof globalThis !== "undefined"
      ? (globalThis as { crypto?: Crypto }).crypto
      : undefined;
  if (!c || typeof c.getRandomValues !== "function") {
    throw new Error("crypto.getRandomValues unavailable; refusing to derive keys");
  }
  c.getRandomValues(buf);
  return buf;
}

/** Generate a fresh 16-byte salt. */
export function randomSalt(): Uint8Array {
  return getRandom(ARGON2_SALT_BYTES);
}

/* -------------------------------------------------------------------------- */
/*  Key derivation                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Derive a single 32-byte key from `password` and `salt` using Argon2id.
 *
 * The hash-wasm API returns hex by default; we ask for raw bytes so we
 * can hand them straight to AES-GCM and base64 helpers.
 *
 * Throws on inputs that would silently produce a useless derivation
 * (empty password, wrong salt size, non-integer KDF parameters).
 */
export async function argon2idKey(
  password: string,
  salt: Uint8Array,
  kdf: KdfParams = DEFAULT_KDF,
): Promise<Uint8Array> {
  if (!password || typeof password !== "string") {
    throw new Error("argon2idKey: password must be a non-empty string");
  }
  if (!(salt instanceof Uint8Array) || salt.length !== ARGON2_SALT_BYTES) {
    throw new Error(`argon2idKey: salt must be ${ARGON2_SALT_BYTES} bytes`);
  }
  if (!Number.isInteger(kdf.m) || !Number.isInteger(kdf.t) || !Number.isInteger(kdf.p)) {
    throw new Error("argon2idKey: kdf must be all integers");
  }
  const out = await argon2idHashWasm({
    password,
    salt,
    parallelism: kdf.p,
    iterations: kdf.t,
    memorySize: kdf.m,
    hashLength: ARGON2_KEY_BYTES,
    outputType: "binary",
  });
  return out as Uint8Array;
}

/**
 * Derive both `auth_key` and `enc_key` from the user's password.
 *
 * The two keys are independent (different salts) so a server-side leak
 * of `auth_key`'s hash gives an attacker no foothold on the blob's
 * encryption key. Convention :
 *
 *   - `auth_key` → sent to the server as login proof
 *   - `enc_key`  → kept in the browser, never leaves
 *
 * `kdf` defaults to {@link DEFAULT_KDF}; callers should reuse the params
 * the server returned via `/auth/login/challenge` for sign-in (the
 * server may rotate to stronger parameters over time).
 */
export async function deriveAuthAndEncKeys(
  password: string,
  authSalt: Uint8Array,
  encSalt: Uint8Array,
  kdf: KdfParams = DEFAULT_KDF,
): Promise<{ readonly authKey: Uint8Array; readonly encKey: Uint8Array }> {
  // hash-wasm reuses a single worker; the await pair doesn't introduce
  // real parallelism but keeps the calling code linear if a JS scheduler
  // gets clever about microtask ordering.
  const [authKey, encKey] = await Promise.all([
    argon2idKey(password, authSalt, kdf),
    argon2idKey(password, encSalt, kdf),
  ]);
  return { authKey, encKey };
}

/**
 * Best-effort zeroization of a sensitive byte buffer. JavaScript doesn't
 * promise the underlying memory wasn't paged out or copied by the
 * garbage collector — call this anyway, both as defense-in-depth and
 * as documentation that the buffer should no longer be used.
 */
export function zeroize(b: Uint8Array): void {
  b.fill(0);
}
