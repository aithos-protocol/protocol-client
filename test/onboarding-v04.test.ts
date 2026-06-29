// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// runOnboarding mints a v0.4 (per-section, content-addressed) FIRST edition at
// height=1 directly — brand-new accounts are born v0.4, never via the v0.3→v0.4
// migration path. fetch is mocked so no network.

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

describe("runOnboarding — v0.4 first edition", () => {
  afterEach(() => {
    if (savedFetch) {
      globalThis.fetch = savedFetch;
      savedFetch = undefined;
    }
    _resetEndpoints();
  });

  test("publishes an aithos:0.4.0 height=1 edition with content-addressed objects", async () => {
    let edition: any = null;
    installMock((b) => (edition = b));

    const r = await runOnboarding({
      handle: "alice",
      displayName: "Alice",
      publicTitle: "Hi",
      publicBody: "Hello from onboarding.",
      tags: ["demo"],
    });

    // Returned manifest is v0.4.
    assert.equal(r.manifest.aithos, "0.4.0");

    // The posted edition is a v0.4 first edition: height 1, no predecessor.
    assert.ok(edition, "publish_ethos_edition was called");
    const m = edition.params.manifest;
    assert.equal(m.aithos, "0.4.0");
    assert.equal(m.edition.height, 1);
    assert.equal(m.edition.prev_hash, null);
    assert.equal(m.edition.supersedes, null);

    // v0.4 uploads content-addressed objects (shards) + section blobs; there is
    // no legacy per-zone `zones.<z>.sections` payload — the public zone is a ref.
    assert.ok(edition.params.objects, "content-addressed objects present");
    assert.ok(edition.params.blobs, "section blobs present");
    assert.ok(m.zones.public.shard_shas?.length > 0, "public zone is a v0.4 ref");
    assert.equal(m.zones.public.sections, undefined, "no legacy per-zone payload");

    // Owner first edition is signed under #public.
    assert.match(edition.params._envelope.proof.verificationMethod, /#public$/);
  });
});
