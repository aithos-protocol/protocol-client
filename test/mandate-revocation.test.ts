// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Conformance: the browser client SIGNS a §4.3 Revocation (signRevocation), and
// @aithos/protocol-core (the reference) verifies it via verifyRevocation. Proves
// the client's revocation is byte-valid — same canonicalization, signed under the
// SAME sphere key that issued the mandate (#public / #circle / #self), resolvable
// in the subject's DID document.

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { createBrowserIdentity, signMandate, signRevocation } from "../src/index.js";
import { signedDidDocument } from "../src/crypto/identity.js";

const core = await import("@aithos/protocol-core");

describe("signRevocation — conformance vs protocol-core verifyRevocation", () => {
  test("a public-sphere mandate's revocation verifies (signed with #public)", () => {
    const id = createBrowserIdentity("alice", "Alice");
    const didDoc = signedDidDocument(id);
    const mandate = signMandate({
      issuer: id,
      actorSphere: "public",
      grantee: { id: "urn:aithos:agent:demo" },
      scopes: ["ethos.read.public"],
      ttlSeconds: 3600,
    });

    const rev = signRevocation({ issuer: id, mandate, reason: "test" });
    assert.equal(rev["aithos-revocation"], "0.1.0");
    assert.equal(rev.mandate_id, mandate.id);
    assert.equal(rev.issuer, mandate.issuer);
    assert.equal(rev.issued_by_key, mandate.issued_by_key);
    assert.match(rev.issued_by_key, /#public$/);

    const res = core.verifyRevocation(rev as never, didDoc as never);
    assert.ok(res.ok, `verifyRevocation failed: ${res.errors.join("; ")}`);
  });

  test("a circle-sphere mandate's revocation is signed with #circle and verifies", () => {
    const id = createBrowserIdentity("bob", "Bob");
    const didDoc = signedDidDocument(id);
    const mandate = signMandate({
      issuer: id,
      actorSphere: "circle",
      grantee: { id: "urn:aithos:agent:demo" },
      scopes: ["ethos.read.circle"],
      ttlSeconds: 3600,
    });
    assert.match(mandate.issued_by_key, /#circle$/);

    const rev = signRevocation({ issuer: id, mandate });
    assert.equal(rev.signature.key, mandate.issued_by_key); // #circle, NOT #public
    const res = core.verifyRevocation(rev as never, didDoc as never);
    assert.ok(res.ok, `verifyRevocation failed: ${res.errors.join("; ")}`);
  });

  test("tampering with the revocation breaks verification", () => {
    const id = createBrowserIdentity("carol", "Carol");
    const didDoc = signedDidDocument(id);
    const mandate = signMandate({
      issuer: id,
      actorSphere: "public",
      grantee: { id: "urn:aithos:agent:demo" },
      scopes: ["ethos.read.public"],
      ttlSeconds: 3600,
    });
    const rev = signRevocation({ issuer: id, mandate, reason: "orig" });

    const tampered = { ...rev, reason: "changed" };
    const res = core.verifyRevocation(tampered as never, didDoc as never);
    assert.equal(res.ok, false, "a mutated reason must fail signature verification");
  });
});
