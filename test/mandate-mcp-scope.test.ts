// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// `mcp.<server>.<…>` connector scopes are sphere-neutral (like `data.*`), so
// signMandate accepts them under the public sphere. Keeps lockstep with
// protocol-core. Lets a consent bundle carry a connector grant in its single
// #public mandate.

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";

import { createBrowserIdentity } from "../src/crypto/identity.js";
import { generateKeyPair } from "../src/crypto/ed25519.js";
import { ed25519PublicKeyToMultibase } from "../src/crypto/encoding.js";
import { signMandate } from "../src/crypto/mandate.js";

describe("signMandate — mcp.* scopes under the public sphere", () => {
  const mintPublic = (scopes: string[]) => {
    const id = createBrowserIdentity("mcp-alice", "MCP Alice");
    const agent = generateKeyPair();
    return signMandate({
      issuer: id,
      actorSphere: "public",
      grantee: { id: "agent:x", pubkey: ed25519PublicKeyToMultibase(agent.publicKey) },
      scopes,
      ttlSeconds: 3600,
    });
  };

  test("mcp.<server> is accepted under public and carried in the mandate", () => {
    const m = mintPublic(["ethos.read.public", "mcp.github", "data.notes.read"]);
    assert.equal(m.actor_sphere, "public");
    assert.ok(m.scopes.includes("mcp.github"), "carries mcp.github");
    assert.ok(m.scopes.includes("data.notes.read"), "still carries data scopes");
  });

  test("a non-allowed scope under public still throws", () => {
    assert.throws(() => mintPublic(["ethos.read.self"]), /not permitted for the public sphere/);
  });
});
