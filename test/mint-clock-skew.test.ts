// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Verify that mintDelegateBundle / signAndPublishMandate sign mandates
// with not_before in the past by default (clock-skew defense), and that
// the caller can override via the new `notBefore` field.

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  MANDATE_NOTBEFORE_OFFSET_SECONDS_DEFAULT,
  signMandate,
  mintDelegateBundle,
  signAndPublishMandate,
  createBrowserIdentity,
  type SignedMandate,
} from "../src/index.js";

function storedFromBrowser(id: ReturnType<typeof createBrowserIdentity>) {
  // Mirror the StoredIdentity shape mintDelegateBundle expects.
  const seedHex = (b: Uint8Array) =>
    Array.from(b)
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");
  return {
    version: "0.1.0" as const,
    did: id.did,
    handle: id.handle,
    displayName: id.displayName,
    seeds: {
      root: seedHex(id.root.seed),
      public: seedHex(id.public.seed),
      circle: seedHex(id.circle.seed),
      self: seedHex(id.self.seed),
    },
    savedAt: new Date().toISOString(),
  };
}

describe("mint clock-skew defense", () => {
  test("default offset is 30 seconds", () => {
    assert.equal(MANDATE_NOTBEFORE_OFFSET_SECONDS_DEFAULT, 30);
  });

  test("signAndPublishMandate signs with not_before in the past by default", async () => {
    const id = createBrowserIdentity("alice", "Alice");
    const stored = storedFromBrowser(id);
    const beforeMint = Date.now();

    let capturedRequestBody: any = null;
    const fakeFetch = (async (_url: any, init: any) => {
      capturedRequestBody = JSON.parse(init.body as string);
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: "x", result: { ok: true } }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    const savedFetch = globalThis.fetch;
    globalThis.fetch = fakeFetch;
    try {
      await signAndPublishMandate({
        owner: stored,
        grantee: { id: "urn:aithos:agent:test", pubkey: "z6MkTest" },
        actorSphere: "public",
        scopes: ["ethos.read.public"],
        ttlSeconds: 600,
        writeEndpoint: "https://api.test/mcp/primitives/write",
      });
    } finally {
      globalThis.fetch = savedFetch;
    }

    const mandate = capturedRequestBody?.params?.mandate as SignedMandate;
    assert.ok(mandate, "mandate must have been published");
    const nbMs = new Date(mandate.not_before).getTime();
    const offsetMs = beforeMint - nbMs;
    // Offset should be roughly MANDATE_NOTBEFORE_OFFSET_SECONDS_DEFAULT * 1000,
    // give or take ~50ms for execution time.
    assert.ok(
      offsetMs > 25_000 && offsetMs < 35_000,
      `expected not_before to be ~30s in the past, but offset was ${offsetMs}ms`,
    );
  });

  test("explicit notBefore overrides the default offset", async () => {
    const id = createBrowserIdentity("alice", "Alice");
    const stored = storedFromBrowser(id);

    const explicitNotBefore = new Date("2026-01-01T00:00:00.000Z");
    let capturedRequestBody: any = null;
    const fakeFetch = (async (_url: any, init: any) => {
      capturedRequestBody = JSON.parse(init.body as string);
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: "x", result: { ok: true } }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    const savedFetch = globalThis.fetch;
    globalThis.fetch = fakeFetch;
    try {
      await signAndPublishMandate({
        owner: stored,
        grantee: { id: "urn:aithos:agent:test", pubkey: "z6MkTest" },
        actorSphere: "public",
        scopes: ["ethos.read.public"],
        ttlSeconds: 600,
        writeEndpoint: "https://api.test/mcp/primitives/write",
        notBefore: explicitNotBefore,
      });
    } finally {
      globalThis.fetch = savedFetch;
    }

    const mandate = capturedRequestBody?.params?.mandate as SignedMandate;
    assert.equal(mandate.not_before, explicitNotBefore.toISOString());
  });

  test("mintDelegateBundle threads notBefore through to the underlying signer", async () => {
    const id = createBrowserIdentity("alice", "Alice");
    const stored = storedFromBrowser(id);

    const explicitNotBefore = new Date("2026-02-02T00:00:00.000Z");
    let capturedRequestBody: any = null;
    const fakeFetch = (async (_url: any, init: any) => {
      capturedRequestBody = JSON.parse(init.body as string);
      return new Response(
        JSON.stringify({ jsonrpc: "2.0", id: "x", result: { ok: true } }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    const savedFetch = globalThis.fetch;
    globalThis.fetch = fakeFetch;
    try {
      const r = await mintDelegateBundle({
        owner: stored,
        granteeId: "urn:aithos:agent:test",
        actorSphere: "public",
        scopes: ["ethos.read.public"],
        ttlSeconds: 600,
        notBefore: explicitNotBefore,
      });
      assert.equal(r.mandate.not_before, explicitNotBefore.toISOString());
    } finally {
      globalThis.fetch = savedFetch;
    }
  });
});
