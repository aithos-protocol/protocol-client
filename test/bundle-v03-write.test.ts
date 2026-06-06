// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Cross-implementation conformance: the browser client AUTHORS a v0.3 per-section
// edition, and @aithos/protocol-core (the reference) verifies + decrypts it. This
// proves the write mirror produces byte-valid bundles the CLI / API accept:
// per-section AEAD, the encrypted self index, the signed v0.3 manifest, and the
// carry-forward cost property across editions.

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { createBrowserIdentity, signedDidDocument } from "../src/crypto/identity.js";
import { edSeedToX25519Secret } from "../src/crypto/kex.js";
import { authorBundleV03, type AuthoredV03 } from "../src/crypto/bundle-v03-write.js";
import {
  readZoneIndex,
  ownerSectionReader,
  type ManifestV03,
} from "../src/crypto/bundle-v03.js";
import type { Section } from "../src/crypto/manifest.js";

const core = await import("@aithos/protocol-core");

function writeBundle(authored: AuthoredV03, didJson: Uint8Array): string {
  const dir = mkdtempSync(join(tmpdir(), "pc-v03-out-"));
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(authored.manifest));
  writeFileSync(join(dir, "did.json"), didJson);
  for (const [file, bytes] of authored.blobs) {
    const abs = join(dir, file);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, bytes);
  }
  return dir;
}

const sec = (id: string, title: string, body: string, tags?: string[]): Section => ({
  id,
  title,
  body,
  ...(tags ? { tags } : {}),
  gamma_ref: "gamma_" + id,
});

describe("v0.3 write mirror — conformance vs protocol-core", () => {
  test("client authors a v0.3 edition that protocol-core verifies + decrypts", () => {
    const id = createBrowserIdentity("alice", "Alice");
    const didDoc = signedDidDocument(id);
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(didDoc));

    const authored = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "alice",
      displayName: "Alice",
      didJson,
      zones: {
        public: [sec("sec_bio", "Bio", "Public bio.")],
        circle: [sec("sec_rate", "Rate", "1200/day.", ["pricing"])],
        self: [sec("sec_routine", "Routine", "Up at six."), sec("sec_goals", "Goals", "Ship v0.3.")],
      },
    });

    assert.equal(authored.manifest.aithos, "0.3.0");
    assert.equal(authored.manifest.edition.height, 1);
    assert.equal(authored.manifest.zones.self!.index_encrypted, true);

    const dir = writeBundle(authored, didJson);
    try {
      // Reference verifier (with owner readers) runs §3.8′ incl. the per-section
      // decrypt + plaintext-hash checks — so OK proves the client's ciphertext
      // is byte-valid AND opens under protocol-core.
      const reader = (z: "circle" | "self") => ({
        didUrl: `${subjectDid}#${z}-kex`,
        x25519Secret: edSeedToX25519Secret(id[z].seed),
      });
      // verifyBundleV03Dir with owner readers runs the per-section decrypt +
      // plaintext-hash checks (§3.8′ #7 / B11) — OK proves the client's
      // ciphertext is byte-valid AND opens under protocol-core.
      const res = core.verifyBundleV03Dir(dir, { readers: [reader("circle"), reader("self")] });
      assert.ok(res.ok, `protocol-core verify failed: ${res.errors.join("; ")}`);
      assert.deepEqual([...res.zonesSkipped].sort(), [], "no zone skipped — all decrypted");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("carry-forward: an unchanged section's blob is reused byte-identical across editions", () => {
    const id = createBrowserIdentity("bob", "Bob");
    const didDoc = signedDidDocument(id);
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(didDoc));

    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "bob",
      displayName: "Bob",
      didJson,
      zones: { self: [sec("sec_routine", "Routine", "Up at six."), sec("sec_goals", "Goals", "v1")] },
      now: new Date("2026-06-06T10:00:00Z"),
    });

    // Edition 2: change Goals, keep Routine identical.
    const ed2 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "bob",
      displayName: "Bob",
      didJson,
      zones: { self: [sec("sec_routine", "Routine", "Up at six."), sec("sec_goals", "Goals", "v2")] },
      prev: { manifest: ed1.manifest, getBlob: (f) => ed1.blobs.get(f)! },
      now: new Date("2026-06-07T10:00:00Z"),
    });

    assert.equal(ed2.manifest.edition.height, 2);
    assert.equal(ed2.manifest.edition.supersedes, ed1.manifest.bundle_id);

    const routineFile = "self/sec_routine.enc";
    const goalsFile = "self/sec_goals.enc";
    // Routine carried forward byte-identical; Goals re-encrypted (differs).
    assert.deepEqual([...ed2.blobs.get(routineFile)!], [...ed1.blobs.get(routineFile)!]);
    assert.notDeepEqual([...ed2.blobs.get(goalsFile)!], [...ed1.blobs.get(goalsFile)!]);

    // The client can read its own ed2 self index (owner key).
    const selfReader = ownerSectionReader(subjectDid, "self", id.self.seed);
    const idx = readZoneIndex((ed2.manifest as ManifestV03).zones.self!, subjectDid, selfReader);
    assert.deepEqual(idx.map((r) => r.title).sort(), ["Goals", "Routine"]);
  });
});
