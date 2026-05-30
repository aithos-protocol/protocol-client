// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// signMandate guard for the lateral `data.<collection>.append` scope:
// an append mandate must bind to a grantee.pubkey (the depositor signs each
// insert envelope). Mirrors protocol-core. The guard runs before any signing,
// so a minimal issuer stub is enough to exercise the throw path.

import { test } from "node:test";
import assert from "node:assert/strict";
import { signMandate } from "../src/index.js";

// Minimal stub: the pubkey guard throws before the issuer keys are touched.
const ISSUER_STUB = { did: "did:aithos:owner" } as unknown as Parameters<
  typeof signMandate
>[0]["issuer"];

test("append mandate without grantee.pubkey is rejected", () => {
  assert.throws(
    () =>
      signMandate({
        issuer: ISSUER_STUB,
        actorSphere: "self",
        grantee: { id: "urn:aithos:patient:bob" }, // no pubkey
        scopes: ["data.mandats_patients.append"],
        ttlSeconds: 600,
      }),
    /append mandate.*grantee\.pubkey/,
  );
});

test("append scope is not rejected as a forbidden/public-sphere scope", () => {
  // With a pubkey present, the append guard passes; the call proceeds past
  // scope validation and only then fails trying to sign with the stub issuer.
  // We assert the failure is NOT a scope/pubkey rejection.
  assert.throws(
    () =>
      signMandate({
        issuer: ISSUER_STUB,
        actorSphere: "public",
        grantee: {
          id: "urn:aithos:patient:bob",
          pubkey: "z6MkokbQF9g3wr65GEWSRQ98s4oR2qgSfnmL499pySGuLc24",
        },
        scopes: ["data.mandats_patients.append"],
        ttlSeconds: 600,
      }),
    (e: unknown) => {
      const msg = (e as Error).message;
      return (
        !/grantee\.pubkey/.test(msg) &&
        !/not permitted for the public sphere/.test(msg)
      );
    },
  );
});
