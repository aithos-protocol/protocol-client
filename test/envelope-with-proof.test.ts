// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Locks the étape-2b convention switch (PLAN-ENVELOPE-PROOF-CONVERGENCE.md):
 * `buildSignedEnvelope` must now sign in the "with-proof" convention — i.e. the
 * signature is over canonicalize(full envelope, proof.proofValue="") — matching
 * @aithos/protocol-core, the data-PDS, and how mandates/revocations are signed.
 *
 * The server's dual-verify (étape 1) accepts both during the migration, but the
 * CLIENT must emit with-proof. This asserts exactly that, and that it no longer
 * emits the legacy without-proof bytes.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { canonicalize } from "../src/crypto/canonical.js";
import { generateKeyPair, verify } from "../src/crypto/ed25519.js";
import { buildSignedEnvelope, type SignedEnvelope } from "../src/crypto/envelope.js";

const ISS = "did:aithos:z6MkWithProofConventionTestSubject";
const AUD = "https://api.aithos.be/mcp/primitives/write";
const METHOD = "aithos.publish_identity";

function withProofBytes(env: SignedEnvelope): Uint8Array {
  return new TextEncoder().encode(
    canonicalize({ ...env, proof: { ...env.proof, proofValue: "" } }),
  );
}

function withoutProofBytes(env: SignedEnvelope): Uint8Array {
  const { proof: _omit, ...rest } = env;
  void _omit;
  return new TextEncoder().encode(canonicalize(rest));
}

describe("buildSignedEnvelope — with-proof convention (étape 2b)", () => {
  it("signs over the with-proof payload (verifies; data-PDS-compatible)", () => {
    const kp = generateKeyPair();
    const env = buildSignedEnvelope({
      iss: ISS,
      aud: AUD,
      method: METHOD,
      verificationMethod: `${ISS}#public`,
      params: { b: 2, a: 1, nested: { y: [3, 1, 2] } },
      signer: kp,
    });
    const sig = new Uint8Array(Buffer.from(env.proof.proofValue, "base64url"));
    assert.equal(verify(sig, withProofBytes(env), kp.publicKey), true);
  });

  it("no longer verifies under the legacy without-proof payload", () => {
    const kp = generateKeyPair();
    const env = buildSignedEnvelope({
      iss: ISS,
      aud: AUD,
      method: METHOD,
      verificationMethod: `${ISS}#public`,
      params: { hello: "world" },
      signer: kp,
    });
    const sig = new Uint8Array(Buffer.from(env.proof.proofValue, "base64url"));
    assert.equal(verify(sig, withoutProofBytes(env), kp.publicKey), false);
  });

  it("carries a well-formed proof block (§11.2)", () => {
    const kp = generateKeyPair();
    const env = buildSignedEnvelope({
      iss: ISS,
      aud: AUD,
      method: METHOD,
      verificationMethod: `${ISS}#public`,
      params: { hello: "world" },
      signer: kp,
    });
    assert.equal(env["aithos-envelope"], "0.1.0");
    assert.equal(env.proof.type, "Ed25519Signature2020");
    assert.equal(env.proof.verificationMethod, `${ISS}#public`);
    assert.equal(env.proof.proofValue.length, 86); // 64-byte sig, base64url, no padding
  });
});
