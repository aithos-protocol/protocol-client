// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Conformance for the OWNER DELTA author (patchEditionV03Owner): authoring a new
// edition from a per-zone patch (only the changed sections) instead of the full
// content. Proves the three properties the lazy-publish SDK depends on:
//   1. Equivalence — for a deterministic (public) edit, the patch author yields a
//      byte-identical manifest + blob set to the full re-author (authorBundleV03).
//   2. Delta — a single-section edit carries every other section forward by
//      descriptor (its blob omitted) and uploads exactly one blob; protocol-core
//      still verifies the reconstructed self-contained bundle.
//   3. Reseal safety net — a delegate grant added/changed since the predecessor
//      re-encrypts ONLY the sections whose recipient set changed, pulling their
//      plaintext on demand via fetchBody; untouched sections (and the common
//      no-grant-change edit) never call fetchBody at all.

import { test, describe } from "node:test";
import { strict as assert } from "node:assert";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { createBrowserIdentity, signedDidDocument } from "../src/crypto/identity.js";
import { generateKeyPair } from "../src/crypto/ed25519.js";
import { edSeedToX25519Secret, edPubToX25519Pub } from "../src/crypto/kex.js";
import { ed25519PublicKeyToMultibase } from "../src/crypto/encoding.js";
import {
  authorBundleV03,
  patchEditionV03Owner,
  type AuthoredV03,
  type DelegateReadGrant,
} from "../src/crypto/bundle-v03-write.js";
import {
  readSection,
  ownerSectionReader,
  delegateSectionReader,
  type ManifestV03,
} from "../src/crypto/bundle-v03.js";
import type { Section } from "../src/crypto/manifest.js";

const core = await import("@aithos/protocol-core");

function blobFor(
  desc: { blob_sha?: string; file: string },
  ...maps: Array<ReadonlyMap<string, Uint8Array>>
): Uint8Array {
  for (const m of maps) {
    const b = m.get(desc.blob_sha!);
    if (b) return b;
  }
  throw new Error(`no blob for ${desc.file} (sha ${desc.blob_sha})`);
}

// Reconstruct a self-contained bundle dir (delta blobs + the prior edition's) so
// protocol-core can verify a delta edition end-to-end.
function writeBundle(authored: AuthoredV03, didJson: Uint8Array, prior?: ReadonlyMap<string, Uint8Array>): string {
  const dir = mkdtempSync(join(tmpdir(), "pc-v03-owner-patch-"));
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(authored.manifest));
  writeFileSync(join(dir, "did.json"), didJson);
  for (const zone of Object.values(authored.manifest.zones)) {
    for (const desc of zone?.sections ?? []) {
      const abs = join(dir, desc.file);
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, blobFor(desc, authored.blobs, ...(prior ? [prior] : [])));
    }
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

const find = (m: ManifestV03, zone: "public" | "circle" | "self", id: string) =>
  m.zones[zone]!.sections.find((s) => s.section_id === id)!;

const T1 = new Date("2026-06-06T10:00:00Z");
const T2 = new Date("2026-06-07T10:00:00Z");

describe("v0.3 owner delta author (patchEditionV03Owner)", () => {
  test("equivalence: a public edit yields the SAME manifest + blobs as a full re-author", async () => {
    const id = createBrowserIdentity("alice", "Alice");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));

    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "alice",
      displayName: "Alice",
      didJson,
      zones: {
        public: [sec("sec_bio", "Bio", "Public bio."), sec("sec_links", "Links", "site.example")],
        circle: [sec("sec_rate", "Rate", "1200/day.", ["pricing"])],
        self: [sec("sec_routine", "Routine", "Up at six."), sec("sec_goals", "Goals", "Ship v0.3.")],
      },
      now: T1,
    });
    const prev = { manifest: ed1.manifest, getBlob: (f: string) => ed1.blobs.get(f)! };

    // Edit one public section; keep its gamma_ref fixed so both authors see the
    // exact same input (the SDK rotates gamma per edit, but equivalence is about
    // identical inputs → identical outputs).
    const editedBio = sec("sec_bio", "Bio", "Public bio — UPDATED.");

    const full = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "alice",
      displayName: "Alice",
      didJson,
      zones: {
        public: [editedBio, sec("sec_links", "Links", "site.example")],
        circle: [sec("sec_rate", "Rate", "1200/day.", ["pricing"])],
        self: [sec("sec_routine", "Routine", "Up at six."), sec("sec_goals", "Goals", "Ship v0.3.")],
      },
      prev,
      now: T2,
    });

    const patched = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "alice",
      displayName: "Alice",
      didJson,
      prev,
      patch: { public: { upserts: [editedBio] } },
      now: T2,
    });

    // Byte-identical manifest (public is deterministic; circle/self carry
    // forward verbatim in BOTH paths).
    assert.deepEqual(patched.manifest, full.manifest, "patch manifest == full re-author manifest");

    // Same delta: exactly the edited public blob, nothing else.
    assert.deepEqual([...patched.blobs.keys()].sort(), [...full.blobs.keys()].sort());
    assert.equal(patched.blobs.size, 1, "one blob uploaded");
    const bio2 = find(patched.manifest as ManifestV03, "public", "sec_bio");
    assert.ok(patched.blobs.has(bio2.blob_sha!), "the edited public blob is present");

    // Untouched sections carried byte-identical to ed1.
    assert.deepEqual(
      find(patched.manifest as ManifestV03, "public", "sec_links"),
      find(ed1.manifest as ManifestV03, "public", "sec_links"),
    );
    assert.deepEqual(
      find(patched.manifest as ManifestV03, "circle", "sec_rate"),
      find(ed1.manifest as ManifestV03, "circle", "sec_rate"),
    );
    assert.deepEqual(
      find(patched.manifest as ManifestV03, "self", "sec_routine"),
      find(ed1.manifest as ManifestV03, "self", "sec_routine"),
    );
  });

  test("delta: a self edit carries the rest forward and protocol-core verifies the result", async () => {
    const id = createBrowserIdentity("bob", "Bob");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));

    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "bob",
      displayName: "Bob",
      didJson,
      zones: {
        public: [sec("sec_bio", "Bio", "hi")],
        self: [sec("sec_routine", "Routine", "Up at six."), sec("sec_goals", "Goals", "v1")],
      },
      now: T1,
    });
    const prev = { manifest: ed1.manifest, getBlob: (f: string) => ed1.blobs.get(f)! };

    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "bob",
      displayName: "Bob",
      didJson,
      prev,
      patch: { self: { upserts: [sec("sec_goals", "Goals", "v2")] } },
      now: T2,
    });

    assert.equal(ed2.manifest.edition.height, 2);
    assert.equal(ed2.manifest.edition.supersedes, ed1.manifest.bundle_id);

    const r1 = find(ed1.manifest as ManifestV03, "self", "sec_routine");
    const r2 = find(ed2.manifest as ManifestV03, "self", "sec_routine");
    const g1 = find(ed1.manifest as ManifestV03, "self", "sec_goals");
    const g2 = find(ed2.manifest as ManifestV03, "self", "sec_goals");
    assert.equal(r2.blob_sha, r1.blob_sha, "Routine carried → same blob_sha");
    assert.equal(ed2.blobs.has(r2.blob_sha!), false, "carried blob omitted from delta");
    assert.notEqual(g2.blob_sha, g1.blob_sha, "Goals changed → new blob_sha");
    assert.equal(ed2.blobs.size, 1, "only the edited section uploaded");

    const dir = writeBundle(ed2, didJson, ed1.blobs);
    try {
      const reader = (z: "circle" | "self") => ({
        didUrl: `${subjectDid}#${z}-kex`,
        x25519Secret: edSeedToX25519Secret(id[z].seed),
      });
      const res = core.verifyBundleV03Dir(dir, { readers: [reader("circle"), reader("self")] });
      assert.ok(res.ok, `protocol-core verify failed: ${res.errors.join("; ")}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("reseal: a grant added since the predecessor re-encrypts ONLY the covered section", async () => {
    const id = createBrowserIdentity("carol", "Carol");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));

    // ed1: owner-only, two circle sections, no grants.
    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "carol",
      displayName: "Carol",
      didJson,
      zones: { circle: [sec("sec_x", "X", "x-body"), sec("sec_y", "Y", "y-body")] },
      now: T1,
    });
    const prev = { manifest: ed1.manifest, getBlob: (f: string) => ed1.blobs.get(f)! };

    // A section-scoped grant covering sec_x only, added after ed1.
    const agent = generateKeyPair();
    const pubkeyMultibase = ed25519PublicKeyToMultibase(agent.publicKey);
    const grant: DelegateReadGrant = {
      recipient: { didUrl: `agent:scoped#${pubkeyMultibase}`, x25519PublicKey: edPubToX25519Pub(agent.publicKey) },
      scopes: ["ethos.read.circle#id=sec_x"],
    };

    const bodies = new Map<string, Section>([
      ["sec_x", sec("sec_x", "X", "x-body")],
      ["sec_y", sec("sec_y", "Y", "y-body")],
    ]);
    const fetched: string[] = [];
    const fetchBody = async (_zone: "public" | "circle" | "self", sectionId: string): Promise<Section> => {
      fetched.push(sectionId);
      const s = bodies.get(sectionId);
      if (!s) throw new Error(`no body ${sectionId}`);
      return s;
    };

    // EMPTY content patch — the only change is the new grant.
    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "carol",
      displayName: "Carol",
      didJson,
      delegateGrants: { circle: [grant] },
      prev,
      patch: {},
      fetchBody,
      now: T2,
    });

    assert.deepEqual(fetched, ["sec_x"], "fetchBody pulled ONLY the resealed section");

    const x1 = find(ed1.manifest as ManifestV03, "circle", "sec_x");
    const x2 = find(ed2.manifest as ManifestV03, "circle", "sec_x");
    const y1 = find(ed1.manifest as ManifestV03, "circle", "sec_y");
    const y2 = find(ed2.manifest as ManifestV03, "circle", "sec_y");

    assert.notEqual(x2.blob_sha, x1.blob_sha, "covered section re-encrypted → new blob_sha");
    assert.ok(ed2.blobs.has(x2.blob_sha!), "resealed blob present in delta");
    assert.deepEqual(y2, y1, "uncovered section carried byte-identical");
    assert.equal(ed2.blobs.has(y2.blob_sha!), false, "uncovered blob omitted");
    assert.equal(ed2.blobs.size, 1, "exactly one section resealed");

    // The grantee can now decrypt sec_x in ed2 (and still cannot read sec_y).
    const zm = (ed2.manifest as ManifestV03).zones.circle!;
    const delReader = delegateSectionReader("agent:scoped", pubkeyMultibase, agent.seed);
    assert.equal(
      readSection(zm, x2, blobFor(x2, ed2.blobs, ed1.blobs), subjectDid, delReader).accessible,
      true,
      "delegate reads the freshly resealed section",
    );
    assert.equal(
      readSection(zm, y2, blobFor(y2, ed2.blobs, ed1.blobs), subjectDid, delReader).accessible,
      false,
      "delegate still cannot read the uncovered section",
    );
    // Owner still reads both.
    const ownerReader = ownerSectionReader(subjectDid, "circle", id.circle.seed);
    assert.equal(readSection(zm, x2, blobFor(x2, ed2.blobs, ed1.blobs), subjectDid, ownerReader).accessible, true);
    assert.equal(readSection(zm, y2, blobFor(y2, ed2.blobs, ed1.blobs), subjectDid, ownerReader).accessible, true);
  });

  test("no reseal: an ordinary edit with unchanged grants never calls fetchBody", async () => {
    const id = createBrowserIdentity("dave", "Dave");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));

    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "dave",
      displayName: "Dave",
      didJson,
      zones: { self: [sec("sec_a", "A", "alpha"), sec("sec_b", "B", "beta")] },
      now: T1,
    });
    const prev = { manifest: ed1.manifest, getBlob: (f: string) => ed1.blobs.get(f)! };

    const fetchBody = async (): Promise<Section> => {
      throw new Error("fetchBody must not be called for an unchanged-grant edit");
    };

    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "dave",
      displayName: "Dave",
      didJson,
      prev,
      patch: { self: { upserts: [sec("sec_a", "A", "alpha-2")] } },
      // self tags supplied for the carried section (none here), proving the path
      // is exercised without forcing a reseal.
      carriedSelfTags: new Map([["sec_b", []]]),
      fetchBody,
      now: T2,
    });

    assert.equal(ed2.blobs.size, 1, "only the edited section uploaded");
    const b1 = find(ed1.manifest as ManifestV03, "self", "sec_b");
    const b2 = find(ed2.manifest as ManifestV03, "self", "sec_b");
    assert.deepEqual(b2, b1, "untouched section carried byte-identical (no reseal)");
  });

  test("reseal on self uses carriedSelfTags to evaluate a #tag= grant", async () => {
    const id = createBrowserIdentity("erin", "Erin");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));

    // self tags are sealed in title_cipher, so the owner supplies them from the
    // already-decrypted index via carriedSelfTags.
    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "erin",
      displayName: "Erin",
      didJson,
      zones: { self: [sec("sec_p", "P", "priced", ["pricing"]), sec("sec_q", "Q", "quiet")] },
      now: T1,
    });
    const prev = { manifest: ed1.manifest, getBlob: (f: string) => ed1.blobs.get(f)! };

    const agent = generateKeyPair();
    const pubkeyMultibase = ed25519PublicKeyToMultibase(agent.publicKey);
    const grant: DelegateReadGrant = {
      recipient: { didUrl: `agent:tagged#${pubkeyMultibase}`, x25519PublicKey: edPubToX25519Pub(agent.publicKey) },
      scopes: ["ethos.read.self#tag=pricing"],
    };

    const fetched: string[] = [];
    const fetchBody = async (_zone: "public" | "circle" | "self", sectionId: string): Promise<Section> => {
      fetched.push(sectionId);
      return sectionId === "sec_p" ? sec("sec_p", "P", "priced", ["pricing"]) : sec("sec_q", "Q", "quiet");
    };

    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "erin",
      displayName: "Erin",
      didJson,
      delegateGrants: { self: [grant] },
      prev,
      patch: {},
      carriedSelfTags: new Map([
        ["sec_p", ["pricing"]],
        ["sec_q", []],
      ]),
      fetchBody,
      now: T2,
    });

    assert.deepEqual(fetched, ["sec_p"], "only the #tag=pricing section resealed");
    const p2 = find(ed2.manifest as ManifestV03, "self", "sec_p");
    const q1 = find(ed1.manifest as ManifestV03, "self", "sec_q");
    const q2 = find(ed2.manifest as ManifestV03, "self", "sec_q");
    assert.ok(ed2.blobs.has(p2.blob_sha!), "tagged section resealed into the delta");
    assert.deepEqual(q2, q1, "untagged self section carried byte-identical");

    const zm = (ed2.manifest as ManifestV03).zones.self!;
    const delReader = delegateSectionReader("agent:tagged", pubkeyMultibase, agent.seed);
    assert.equal(
      readSection(zm, p2, blobFor(p2, ed2.blobs, ed1.blobs), subjectDid, delReader).accessible,
      true,
      "delegate reads the resealed #tag=pricing section",
    );
  });
});
