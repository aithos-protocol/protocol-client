// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// runOnboarding must mint a v0.3 (per-section) first edition — previously it
// built a v0.2 monolithic edition via buildSignedFirstEdition, which then made
// loadEthosV03 reject the freshly-created ethos. fetch is mocked so no network.

import { test, describe, afterEach } from "node:test";
import { strict as assert } from "node:assert";

import { runOnboarding } from "../src/onboarding.js";
import { _setEndpoints, _resetEndpoints } from "../src/endpoints.js";

let savedFetch: typeof fetch | undefined;

function installMock(captureEdition: (body: any) => void) {
  savedFetch = globalThis.fetch;
  _setEndpoints({ api: "https://api.test.local" });
  globalThis.fetch = (async (_url: unknown, init?: { body?: string }) => {
    const body = init?.body ? JSON.parse(init.body) : {};
    if (body.method === "aithos.publish_ethos_edition") captureEdition(body);
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: body.method, result: { ok: true } }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as unknown as typeof fetch;
}

describe("runOnboarding — v0.3 first edition", () => {
  afterEach(() => {
    if (savedFetch) {
      globalThis.fetch = savedFetch;
      savedFetch = undefined;
    }
    _resetEndpoints();
  });

  test("publishes an aithos:0.3.0 manifest with per-section blobs", async () => {
    let edition: any = null;
    installMock((b) => (edition = b));

    const r = await runOnboarding({
      handle: "alice",
      displayName: "Alice",
      publicTitle: "Hi",
      publicBody: "Hello from onboarding.",
      tags: ["demo"],
    });

    // Returned manifest is v0.3.
    assert.equal(r.manifest.aithos, "0.3.0");

    // The posted edition is v0.3, height 1, with per-section blobs (not the
    // legacy per-zone `zones` payload).
    assert.ok(edition, "publish_ethos_edition was called");
    assert.equal(edition.params.manifest.aithos, "0.3.0");
    assert.equal(edition.params.manifest.edition.height, 1);
    assert.equal(edition.params.manifest.edition.prev_hash, null);
    assert.ok(edition.params.blobs, "per-section blobs present");
    assert.equal(edition.params.zones, undefined, "no legacy per-zone payload");
    assert.deepEqual(
      edition.params.manifest.zones.public.sections.map((s: any) => s.title),
      ["Hi"],
    );
    // Owner first edition is signed under #public.
    assert.match(edition.params._envelope.proof.verificationMethod, /#public$/);
  });
});
