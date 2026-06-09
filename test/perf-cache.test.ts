// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Opt-in perf caches: default-off passthrough, TTL memoization,
// single-flight coalescing, invalidation, and failure eviction.
// Plus mandateToGrant — the in-hand-mandate projection that lets a publish
// seal a freshly-minted mandate without waiting for list_mandates to settle.

import { strict as assert } from "node:assert";
import { afterEach, describe, it } from "node:test";

import {
  _resetPerfCaches,
  cachedDelegateGrants,
  cachedIdentityDoc,
  configurePerfCaches,
  invalidateDelegateGrantsCache,
  invalidateIdentityCache,
} from "../src/perf-cache.js";
import { mandateToGrant } from "../src/delegate-recipients.js";
import { createBrowserIdentity, ed25519PublicKeyToMultibase, signMandate } from "../src/index.js";

afterEach(() => _resetPerfCaches());

describe("perf caches", () => {
  it("are passthrough (no memoization) by default", async () => {
    let calls = 0;
    const load = () => Promise.resolve(++calls);
    assert.equal(await cachedIdentityDoc("did:a", load), 1);
    assert.equal(await cachedIdentityDoc("did:a", load), 2);
    assert.equal(await cachedDelegateGrants("did:a", load), 3);
    assert.equal(await cachedDelegateGrants("did:a", load), 4);
  });

  it("memoize within TTL once configured, per key", async () => {
    configurePerfCaches({ identityTtlMs: 60_000, delegateGrantsTtlMs: 60_000 });
    let calls = 0;
    const load = () => Promise.resolve(++calls);
    assert.equal(await cachedIdentityDoc("did:a", load), 1);
    assert.equal(await cachedIdentityDoc("did:a", load), 1); // hit
    assert.equal(await cachedIdentityDoc("did:b", load), 2); // other key
    assert.equal(await cachedDelegateGrants("did:a", load), 3); // separate cache
    assert.equal(await cachedDelegateGrants("did:a", load), 3); // hit
  });

  it("coalesce concurrent loads into one in-flight promise (single-flight)", async () => {
    configurePerfCaches({ delegateGrantsTtlMs: 60_000 });
    let calls = 0;
    const slow = () =>
      new Promise<number>((r) => setTimeout(() => r(++calls), 10));
    const [a, b, c] = await Promise.all([
      cachedDelegateGrants("did:a", slow),
      cachedDelegateGrants("did:a", slow),
      cachedDelegateGrants("did:a", slow),
    ]);
    assert.deepEqual([a, b, c], [1, 1, 1]);
    assert.equal(calls, 1);
  });

  it("invalidate by key and globally", async () => {
    configurePerfCaches({ identityTtlMs: 60_000, delegateGrantsTtlMs: 60_000 });
    let calls = 0;
    const load = () => Promise.resolve(++calls);
    await cachedIdentityDoc("did:a", load); // 1
    invalidateIdentityCache("did:a");
    assert.equal(await cachedIdentityDoc("did:a", load), 2);
    await cachedDelegateGrants("did:a", load); // 3
    invalidateDelegateGrantsCache(); // global
    assert.equal(await cachedDelegateGrants("did:a", load), 4);
  });

  it("never serve a rejected load from cache", async () => {
    configurePerfCaches({ identityTtlMs: 60_000 });
    let calls = 0;
    const flaky = () =>
      ++calls === 1 ? Promise.reject(new Error("transient")) : Promise.resolve(calls);
    await assert.rejects(cachedIdentityDoc("did:a", flaky), /transient/);
    assert.equal(await cachedIdentityDoc("did:a", flaky), 2); // retried, then cached
    assert.equal(await cachedIdentityDoc("did:a", flaky), 2);
  });

  it("expire entries after the TTL", async () => {
    configurePerfCaches({ identityTtlMs: 20 });
    let calls = 0;
    const load = () => Promise.resolve(++calls);
    assert.equal(await cachedIdentityDoc("did:a", load), 1);
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(await cachedIdentityDoc("did:a", load), 2);
  });
});

describe("mandateToGrant", () => {
  function mintReadMandate(scopes: readonly string[]) {
    const owner = createBrowserIdentity("perf-owner", "Perf Owner");
    const grantee = createBrowserIdentity("perf-agent", "Perf Agent");
    const granteePubkey = ed25519PublicKeyToMultibase(grantee.public.publicKey);
    return signMandate({
      issuer: owner,
      actorSphere: "self",
      grantee: { id: "agent:test", pubkey: granteePubkey },
      scopes,
      ttlSeconds: 3600,
    });
  }

  it("projects a circle+self read mandate into both zones with its scopes", () => {
    const mandate = mintReadMandate(["ethos.read.circle", "ethos.read.self"]);
    const g = mandateToGrant(mandate);
    assert.ok(g.circle, "expected a circle grant");
    assert.ok(g.self, "expected a self grant");
    assert.deepEqual(g.self!.scopes, ["ethos.read.circle", "ethos.read.self"]);
    assert.ok(g.self!.recipient.didUrl.startsWith("agent:test#"));
    assert.equal(g.self!.recipient.x25519PublicKey.length, 32);
  });

  it("covers only the zones the scopes read-bear", () => {
    const g = mandateToGrant(mintReadMandate(["ethos.read.circle"]));
    assert.ok(g.circle);
    assert.equal(g.self, undefined);
  });

  it("returns {} for an expired mandate or a missing grantee pubkey", () => {
    const mandate = mintReadMandate(["ethos.read.self"]);
    const past = new Date(Date.parse(mandate.not_after) + 1000);
    assert.deepEqual(mandateToGrant(mandate, past), {});
    const noPk = { ...mandate, grantee: { id: "agent:test" } };
    assert.deepEqual(mandateToGrant(noPk), {});
  });
});
