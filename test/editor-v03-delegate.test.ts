// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Transport wiring for DELEGATE authoring: publishEthosEditionV03Delegate.
//
// The crypto core (patchEditionV03Delegate: per-section recipients, carry-forward,
// authorized_by) is covered byte-for-byte against protocol-core in
// bundle-v03-delegate.test.ts. THIS test exercises the thin network wrapper —
// the glue the SDK delegate path will ride on:
//   get_identity → ownerZoneKexPubkey → pre-fetch prior blobs (carry-forward)
//   → patchEditionV03Delegate → DELEGATE envelope (bare-multibase + mandate)
//   → POST publish_ethos_edition.
// `fetch` is mocked so no server is needed.

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";

import { createBrowserIdentity, signedDidDocument } from "../src/crypto/identity.js";
import { generateKeyPair } from "../src/crypto/ed25519.js";
import { ed25519PublicKeyToMultibase } from "../src/crypto/encoding.js";
import { signMandate } from "../src/crypto/mandate.js";
import { authorBundleV03, type DelegateReadGrant } from "../src/crypto/bundle-v03-write.js";
import { edPubToX25519Pub } from "../src/crypto/kex.js";
import { loadEthosV03, publishEthosEditionV03Delegate } from "../src/editor-v03.js";
import { _setEndpoints, _resetEndpoints } from "../src/endpoints.js";
import type { ManifestV03 } from "../src/crypto/bundle-v03.js";
import type { Section } from "../src/crypto/manifest.js";

const sec = (id: string, title: string, body: string): Section => ({
  id,
  title,
  body,
  gamma_ref: "gamma_" + id,
});

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    statusText: "OK",
    json: async () => body,
  } as unknown as Response;
}

describe("publishEthosEditionV03Delegate — transport wiring", () => {
  test("delegate appends a self section: posts a delegate-signed v0.3 edition + carry-forward", async () => {
    const id = createBrowserIdentity("alice", "Alice");
    const didDoc = signedDidDocument(id);
    const subjectDid = id.did;
    // Same byte-shape the wrapper recomputes from get_identity.
    const didJson = new TextEncoder().encode(JSON.stringify(didDoc, null, 2) + "\n");

    // Owner edition 1 — the predecessor the delegate patches. One self section
    // the delegate is NOT sealed into, so it must carry forward verbatim.
    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "alice",
      displayName: "Alice",
      didJson,
      zones: { self: [sec("sec_routine", "Routine", "Up at six.")] },
      now: new Date("2026-06-06T10:00:00Z"),
    });

    // A delegate (agent key) holding a self write mandate.
    const agent = generateKeyPair();
    const pubkeyMultibase = ed25519PublicKeyToMultibase(agent.publicKey);
    const mandate = signMandate({
      issuer: id,
      actorSphere: "self",
      grantee: { id: "agent:gmail", pubkey: pubkeyMultibase },
      scopes: ["ethos.write.self"],
      ttlSeconds: 3600,
    });

    // Mock the platform: two reads (get_identity, get_ethos_section) + one write.
    const reads: string[] = [];
    const writes: Array<Record<string, any>> = [];
    const realFetch = globalThis.fetch;
    _setEndpoints({ api: "https://api.test.local" });
    globalThis.fetch = (async (url: unknown, init?: { body?: string }) => {
      const u = String(url);
      const reqBody = init?.body ? JSON.parse(init.body) : {};
      if (u.endsWith("/mcp/primitives/read")) {
        reads.push(reqBody.method);
        if (reqBody.method === "aithos.get_identity") {
          return jsonResponse({ result: { object: didDoc } });
        }
        if (reqBody.method === "aithos.get_ethos_section") {
          const desc = ed1.manifest.zones.self!.sections.find(
            (s) => s.section_id === reqBody.params.section_id,
          )!;
          return jsonResponse({
            result: { object: { bytes_base64: bytesToBase64(ed1.blobs.get(desc.file)!) } },
          });
        }
        throw new Error("unexpected read method " + reqBody.method);
      }
      if (u.endsWith("/mcp/primitives/write")) {
        writes.push(reqBody);
        return jsonResponse({ result: { ok: true } });
      }
      throw new Error("unexpected url " + u);
    }) as unknown as typeof fetch;

    try {
      const { manifest } = await publishEthosEditionV03Delegate({
        delegate: {
          granteeId: "agent:gmail",
          pubkeyMultibase,
          seed: agent.seed,
          mandateId: mandate.id,
          actorSphere: "self",
        },
        mandate,
        prevManifest: ed1.manifest as ManifestV03,
        patch: { upserts: [sec("sec_inbox", "Inbox triage", "3 unread.")] },
      });

      // Returned manifest: edition 2, delegate-signed with authorized_by.
      assert.equal(manifest.edition.height, 2);
      assert.equal(manifest.edition.supersedes, ed1.manifest.bundle_id);
      const sig = manifest.integrity.manifest_signature as {
        key: string;
        authorized_by?: string;
      };
      assert.equal(sig.key, pubkeyMultibase, "manifest signed with the delegate key");
      assert.equal(sig.authorized_by, mandate.id);

      // It fetched the DID doc and carried forward by fetching the prior blob.
      assert.ok(reads.includes("aithos.get_identity"), "fetched identity");
      assert.ok(reads.includes("aithos.get_ethos_section"), "fetched prior blob for carry-forward");

      // Exactly one publish POST, on the delegate path.
      assert.equal(writes.length, 1);
      const posted = writes[0]!;
      assert.equal(posted.method, "aithos.publish_ethos_edition");
      const env = posted.params._envelope;
      assert.equal(
        env.proof.verificationMethod,
        pubkeyMultibase,
        "envelope signed with the bare delegate multibase (delegate path)",
      );
      assert.ok(env.mandate, "mandate attached to the envelope");
      assert.equal(env.mandate.id, mandate.id);

      // Posted manifest carries the delegate signature + both sections.
      const pm = posted.params.manifest as ManifestV03;
      assert.equal((pm.integrity.manifest_signature as any).authorized_by, mandate.id);
      assert.deepEqual(
        pm.zones.self!.sections.map((s) => s.section_id).sort(),
        ["sec_inbox", "sec_routine"],
      );

      // Carry-forward: the owner's prior blob is reposted byte-identical.
      const routineDesc = pm.zones.self!.sections.find((s) => s.section_id === "sec_routine")!;
      assert.equal(
        posted.params.blobs[routineDesc.file].bytes_base64,
        bytesToBase64(ed1.blobs.get(routineDesc.file)!),
        "prior section carried forward verbatim",
      );
    } finally {
      globalThis.fetch = realFetch;
      _resetEndpoints();
    }
  });

  test("rejects a non-v0.3 predecessor", async () => {
    const agent = generateKeyPair();
    const pubkeyMultibase = ed25519PublicKeyToMultibase(agent.publicKey);
    await assert.rejects(
      () =>
        publishEthosEditionV03Delegate({
          delegate: {
            granteeId: "agent:x",
            pubkeyMultibase,
            seed: agent.seed,
            mandateId: "mandate_x",
            actorSphere: "self",
          },
          mandate: {} as any,
          prevManifest: { aithos: "0.2.0" } as unknown as ManifestV03,
          patch: { upserts: [] },
        }),
      /v0\.3 predecessor required/,
    );
  });
});

describe("loadEthosV03 — delegate reader path", () => {
  test("a delegate decrypts ONLY the sections sealed to it; the rest stays opaque", async () => {
    const id = createBrowserIdentity("carol", "Carol");
    const didDoc = signedDidDocument(id);
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(didDoc, null, 2) + "\n");

    // A delegate sealed into ONLY sec_a (read scope narrowed by #id=).
    const agent = generateKeyPair();
    const pubkeyMultibase = ed25519PublicKeyToMultibase(agent.publicKey);
    const grant: DelegateReadGrant = {
      recipient: {
        didUrl: `agent:gmail#${pubkeyMultibase}`,
        x25519PublicKey: edPubToX25519Pub(agent.publicKey),
      },
      scopes: ["ethos.read.self#id=sec_a"],
    };
    const ed = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "carol",
      displayName: "Carol",
      didJson,
      zones: { self: [sec("sec_a", "A", "alpha"), sec("sec_b", "B", "beta")] },
      delegateGrants: { self: [grant] },
      now: new Date("2026-06-07T10:00:00Z"),
    });

    const realFetch = globalThis.fetch;
    _setEndpoints({ api: "https://api.test.local" });
    globalThis.fetch = (async (url: unknown, init?: { body?: string }) => {
      const u = String(url);
      const b = init?.body ? JSON.parse(init.body) : {};
      if (u.endsWith("/mcp/primitives/read")) {
        if (b.method === "aithos.get_ethos_manifest") {
          return jsonResponse({ result: { object: ed.manifest } });
        }
        if (b.method === "aithos.get_ethos_section") {
          const desc = ed.manifest.zones.self!.sections.find(
            (s) => s.section_id === b.params.section_id,
          )!;
          return jsonResponse({
            result: { object: { bytes_base64: bytesToBase64(ed.blobs.get(desc.file)!) } },
          });
        }
      }
      throw new Error("unexpected read " + u);
    }) as unknown as typeof fetch;

    try {
      const snap = await loadEthosV03(subjectDid, undefined, {
        granteeId: "agent:gmail",
        pubkeyMultibase,
        seed: agent.seed,
      });

      // Sections: only sec_a is decryptable for this delegate.
      assert.deepEqual(snap.sections!.self.map((s) => s.id), ["sec_a"]);
      assert.equal(snap.sections!.self[0]!.body, "alpha");

      // Index: both descriptors are present, but only sec_a's title is readable.
      assert.deepEqual(snap.index.self.map((r) => r.section_id).sort(), ["sec_a", "sec_b"]);
      assert.deepEqual(
        snap.index.self.filter((r) => !r.title_hidden).map((r) => r.title),
        ["A"],
      );
    } finally {
      globalThis.fetch = realFetch;
      _resetEndpoints();
    }
  });
});
