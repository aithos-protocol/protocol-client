// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// AES-256-GCM helpers for the Aithos password-encrypted vault blob.
//
// These primitives are deliberately separate from `./encrypt.ts` (which
// handles per-recipient zone sealing). The vault blob is a single
// `enc_key`-encrypted payload, with no key-agreement step — the symmetric
// key is the one derived from the user's password via Argon2id.
//
// `enc_key` size : 32 bytes (AES-256).
// Nonce size     : 12 bytes (GCM standard, the only safe choice with
//                  @noble/ciphers' API).

import { gcm } from "@noble/ciphers/aes";

/** AES-GCM nonce size in bytes (96 bits). */
export const BLOB_NONCE_BYTES = 12;

/** Symmetric key size in bytes (AES-256). */
export const BLOB_KEY_BYTES = 32;

/**
 * Throws if no Web Crypto getRandomValues is available. Mirrors the same
 * guard used in `./argon2id.ts` so the failure mode is consistent across
 * the crypto surface.
 */
function getRandom(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  const c =
    typeof globalThis !== "undefined"
      ? (globalThis as { crypto?: Crypto }).crypto
      : undefined;
  if (!c || typeof c.getRandomValues !== "function") {
    throw new Error("crypto.getRandomValues unavailable; refusing to encrypt");
  }
  c.getRandomValues(buf);
  return buf;
}

/** Generate a fresh 12-byte nonce for AES-GCM. */
export function randomNonce(): Uint8Array {
  return getRandom(BLOB_NONCE_BYTES);
}

/**
 * AES-256-GCM encrypt with the caller-provided nonce. Returns the
 * ciphertext with the 16-byte GCM auth tag appended (the @noble/ciphers
 * convention).
 *
 * The caller MUST persist `nonce` alongside the ciphertext; without it,
 * decryption is impossible. The nonce isn't secret — only the key is.
 *
 * Pattern :
 *
 *   const nonce = randomNonce();
 *   const cipher = encryptBlob(encKey, nonce, plaintext);
 *   // store { cipher, nonce } together
 */
export function encryptBlob(
  encKey: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  if (encKey.length !== BLOB_KEY_BYTES) {
    throw new Error(`encryptBlob: enc_key must be ${BLOB_KEY_BYTES} bytes`);
  }
  if (nonce.length !== BLOB_NONCE_BYTES) {
    throw new Error(`encryptBlob: nonce must be ${BLOB_NONCE_BYTES} bytes`);
  }
  return gcm(encKey, nonce).encrypt(plaintext);
}

/**
 * AES-256-GCM decrypt. Throws if the GCM auth tag check fails — typically
 * because :
 *
 *   - the password was wrong (so `enc_key` was wrong),
 *   - the ciphertext was tampered with,
 *   - the wrong nonce was paired with the ciphertext.
 *
 * Callers should surface these as a single user-facing error
 * ("wrong password or corrupted vault") rather than distinguishing,
 * because the underlying GCM error doesn't tell you which.
 */
export function decryptBlob(
  encKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  if (encKey.length !== BLOB_KEY_BYTES) {
    throw new Error(`decryptBlob: enc_key must be ${BLOB_KEY_BYTES} bytes`);
  }
  if (nonce.length !== BLOB_NONCE_BYTES) {
    throw new Error(`decryptBlob: nonce must be ${BLOB_NONCE_BYTES} bytes`);
  }
  return gcm(encKey, nonce).decrypt(ciphertext);
}
