// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Cross-implementation conformance: the browser client reads a v0.3 per-section
// bundle AUTHORED by @aithos/protocol-core (the reference). This proves the
// mirror in src/crypto/bundle-v03.ts is byte-compatible with the CLI/API:
// per-section decrypt, the encrypted self index, and the host (no-key) view.

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  readZoneIndex,
  readSection,
  locateSection,
  ownerSectionReader,
  isV03Manifest,
  type ManifestV03,
  type SectionReader,
} from "../src/crypto/bundle-v03.js";

// Author a reference bundle with protocol-core (Node, filesystem).
const HOME = mkdtempSync(join(tmpdir(), "pc-v03-home-"));
process.env.AITHOS_HOME = HOME;
const core = await import("@aithos/protocol-core");

function blob(dir: string, file: string): Uint8Array {
  return new Uint8Array(readFileSync(join(dir, file)));
}

describe("v0.3 read mirror — conformance vs protocol-core", () => {
  test("reads index + sections from a protocol-core bundle; host view hides self titles", () => {
    const outDir = mkdtempSync(join(tmpdir(), "pc-v03-bundle-"));
    try {
      const id = core.createIdentity("alice", "Alice");
      core.writeIdentityToDisk(id);

      const sec = (idn: string, title: string, body: string, tags?: string[]) => ({
        id: idn,
        title,
        body,
        ...(tags ? { tags } : {}),
        gamma_ref: core.newGammaId(),
      });

      core.authorBundleV03({
        identity: id,
        outDir,
        zones: {
          public: [sec("sec_bio", "Bio", "Public bio.")],
          circle: [sec("sec_rate", "Rate", "1200/day.", ["pricing"])],
          self: [sec("sec_routine", "Routine", "Up at six."), sec("sec_goals", "Goals", "Ship v0.3.")],
        },
      });

      const manifest = JSON.parse(readFileSync(join(outDir, "manifest.json"), "utf8")) as ManifestV03;
      assert.ok(isV03Manifest(manifest), "authored bundle is v0.3");
      const subjectDid = manifest.subject_did;

      // Owner reader for the encrypted self/circle zones (from the Ed25519 seed).
      const selfReader: SectionReader = ownerSectionReader(subjectDid, "self", id.self.seed);
      const circleReader: SectionReader = ownerSectionReader(subjectDid, "circle", id.circle.seed);

      // --- index: public + circle are clear; self is encrypted ---------------
      const pubIdx = readZoneIndex(manifest.zones.public!, subjectDid);
      assert.deepEqual(pubIdx.map((r) => r.title), ["Bio"]);

      const circleIdx = readZoneIndex(manifest.zones.circle!, subjectDid, circleReader);
      assert.deepEqual(circleIdx.map((r) => r.title), ["Rate"]);

      // Owner decrypts the self index titles.
      const selfIdxOwner = readZoneIndex(manifest.zones.self!, subjectDid, selfReader);
      assert.deepEqual(selfIdxOwner.map((r) => r.title).sort(), ["Goals", "Routine"]);
      assert.ok(selfIdxOwner.every((r) => !r.title_hidden));

      // Host (no key) sees the self ids but NOT the titles.
      const selfIdxHost = readZoneIndex(manifest.zones.self!, subjectDid);
      assert.ok(selfIdxHost.every((r) => r.title_hidden && r.title === undefined));
      assert.equal(selfIdxHost.length, 2);

      // --- section bodies: locate + fetch blob + decode ----------------------
      const readById = (sectionId: string, reader?: SectionReader) => {
        const zoneName = locateSection(manifest, sectionId)!;
        const zm = manifest.zones[zoneName]!;
        const desc = zm.sections.find((s) => s.section_id === sectionId)!;
        return readSection(zm, desc, blob(outDir, desc.file), subjectDid, reader);
      };

      const bio = readById("sec_bio");
      assert.ok(bio.accessible && bio.section!.body === "Public bio.");

      const rate = readById("sec_rate", circleReader);
      assert.ok(rate.accessible && rate.section!.body === "1200/day.");
      assert.deepEqual([...(rate.section!.tags ?? [])], ["pricing"]);

      const routine = readById("sec_routine", selfReader);
      assert.ok(routine.accessible && routine.section!.title === "Routine" && routine.section!.body === "Up at six.");

      // Host trying a self section → inaccessible (not a recipient / no key).
      const routineHost = readById("sec_routine");
      assert.equal(routineHost.accessible, false);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });
});
