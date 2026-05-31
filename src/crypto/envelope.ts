// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Signed envelope §11.2 — browser side.
//
// ⚠️ CONVENTION CHANGE (PLAN-ENVELOPE-PROOF-CONVERGENCE.md, étape 2b):
// `buildSignedEnvelope` now delegates to `@aithos/protocol-core` and signs in
// the "with-proof" convention (canonicalize the full envelope with
// proof.proofValue=""), exactly like the data-PDS, mandates and revocations.
// This replaces protocol-client's former "without-proof" ported signer.
//
// DO NOT PUBLISH this until the server dual-verify (étape 1 EXPAND) is deployed
// to ALL without-proof surfaces (api/compute/extract/builder/primitives) and
// confirmed live — otherwise with-proof envelopes are rejected by servers that
// only accept without-proof.
//
// The function stays SYNCHRONOUS (core's signEnvelope / signEnvelopeWithMandate
// are sync, seed-based), so call sites (editor.ts, onboarding.ts,
// mandate-mint.ts) are unchanged.
//
// Two signing paths:
//   - Owner path: `verificationMethod = "{iss}#{sphere}"`; `mandate` omitted.
//   - Delegate path: `verificationMethod = <multibase Ed25519 pubkey>`;
//     `mandate` REQUIRED (carries the full §4.2 Mandate).

import {
  signEnvelope,
  signEnvelopeWithMandate,
} from "@aithos/protocol-core/envelope";
import type { Mandate as CoreMandate } from "@aithos/protocol-core/mandate";

import type { KeyPair } from "./ed25519.js";
import type { SignedMandate } from "./mandate.js";

export interface EnvelopeProof {
  readonly type: "Ed25519Signature2020";
  readonly verificationMethod: string;
  readonly created: string;
  readonly proofValue: string;
}

export interface SignedEnvelope {
  readonly "aithos-envelope": "0.1.0";
  readonly iss: string;
  readonly aud: string;
  readonly method: string;
  readonly iat: number;
  readonly exp: number;
  readonly nonce: string;
  readonly params_hash: string;
  /**
   * Full signed mandate — ONLY present when the caller is a delegate
   * signing under that mandate. Server rejects a multibase-keyed
   * envelope without this field.
   */
  readonly mandate?: SignedMandate;
  readonly proof: EnvelopeProof;
}

export interface BuildEnvelopeArgs {
  /** Issuer DID — root DID of the subject, not the delegate's ID. */
  readonly iss: string;
  /** Full URL of the write endpoint, matches what CloudFront routes to the Lambda. */
  readonly aud: string;
  /** Fully-qualified JSON-RPC method, e.g. `aithos.publish_identity`. */
  readonly method: string;
  /**
   * Verification method the server should resolve to a pubkey. Two shapes:
   *   - `{iss}#{sphere}` (DID URL) — owner direct signing.
   *   - a bare multibase Ed25519 pubkey — delegate signing. MUST be paired
   *     with `mandate`.
   */
  readonly verificationMethod: string;
  /** Params object EXCLUDING `_envelope` (that's what params_hash commits to). */
  readonly params: unknown;
  /** Signing keypair (matches `verificationMethod`). */
  readonly signer: KeyPair;
  /** Lifetime in seconds; default 120. The server caps at 300. */
  readonly ttlSeconds?: number;
  /**
   * Full signed mandate; REQUIRED when `verificationMethod` is a bare
   * multibase key. Omit for owner-path envelopes.
   */
  readonly mandate?: SignedMandate;
}

export function buildSignedEnvelope(args: BuildEnvelopeArgs): SignedEnvelope {
  const ttlSeconds = args.ttlSeconds ?? 120;

  // Delegate path: bare-multibase verificationMethod + attached mandate.
  // Owner path: did#sphere verificationMethod, no mandate.
  const env = args.mandate
    ? signEnvelopeWithMandate({
        iss: args.iss,
        aud: args.aud,
        method: args.method,
        params: args.params,
        delegateKey: {
          seed: args.signer.seed,
          pubkeyMultibase: args.verificationMethod,
        },
        mandate: args.mandate as unknown as CoreMandate,
        ttlSeconds,
      })
    : signEnvelope({
        iss: args.iss,
        aud: args.aud,
        method: args.method,
        params: args.params,
        sphereKey: {
          seed: args.signer.seed,
          verificationMethod: args.verificationMethod,
        },
        ttlSeconds,
      });

  // core's SignedEnvelope is structurally identical to protocol-client's
  // (same §11.2 wire shape); the cast bridges the two nominal types.
  return env as unknown as SignedEnvelope;
}
