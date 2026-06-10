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

  test("reseal: a grant re-wraps ONLY the covered section (no re-encryption)", async () => {
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

    assert.deepEqual(fetched, [], "a pure grant re-wraps — fetchBody never called");

    const x1 = find(ed1.manifest as ManifestV03, "circle", "sec_x");
    const x2 = find(ed2.manifest as ManifestV03, "circle", "sec_x");
    const y1 = find(ed1.manifest as ManifestV03, "circle", "sec_y");
    const y2 = find(ed2.manifest as ManifestV03, "circle", "sec_y");

    assert.equal(x2.blob_sha, x1.blob_sha, "covered section re-wrapped → blob_sha unchanged");
    assert.ok(
      x2.cipher!.wraps.map((w) => w.recipient).includes(`agent:scoped#${pubkeyMultibase}`),
      "delegate added to the covered section's wraps",
    );
    assert.deepEqual(y2, y1, "uncovered section carried byte-identical");
    assert.equal(ed2.blobs.size, 0, "a pure grant uploads zero blobs (re-wrap, not re-encrypt)");

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

    assert.deepEqual(fetched, [], "a #tag= grant re-wraps — fetchBody never called");
    const p1 = find(ed1.manifest as ManifestV03, "self", "sec_p");
    const p2 = find(ed2.manifest as ManifestV03, "self", "sec_p");
    const q1 = find(ed1.manifest as ManifestV03, "self", "sec_q");
    const q2 = find(ed2.manifest as ManifestV03, "self", "sec_q");
    assert.equal(p2.blob_sha, p1.blob_sha, "tagged section re-wrapped → blob_sha unchanged");
    assert.equal(ed2.blobs.size, 0, "zero upload (re-wrap, not re-encrypt)");
    assert.ok(
      p2.title_cipher!.wraps.map((w) => w.recipient).includes(`agent:tagged#${pubkeyMultibase}`),
      "delegate added to the encrypted title's wraps",
    );
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

describe("v0.3 owner delta author — cheap re-wrap on grant (no re-encryption)", () => {
  test("granting on circle re-wraps the DEK: blob_sha unchanged, zero upload, delegate decrypts", async () => {
    const id = createBrowserIdentity("frank", "Frank");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));

    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "frank",
      displayName: "Frank",
      didJson,
      zones: { circle: [sec("sec_x", "X", "x-body")] },
      now: T1,
    });
    const prev = { manifest: ed1.manifest, getBlob: (f: string) => ed1.blobs.get(f)! };
    const x1 = find(ed1.manifest as ManifestV03, "circle", "sec_x");

    const agent = generateKeyPair();
    const pub = ed25519PublicKeyToMultibase(agent.publicKey);
    const grant: DelegateReadGrant = {
      recipient: { didUrl: `agent:reader#${pub}`, x25519PublicKey: edPubToX25519Pub(agent.publicKey) },
      scopes: ["ethos.read.circle#id=sec_x"],
    };
    // The re-wrap must NOT need the plaintext.
    const fetchBody = async (): Promise<Section> => {
      throw new Error("re-wrap must not call fetchBody");
    };

    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "frank",
      displayName: "Frank",
      didJson,
      delegateGrants: { circle: [grant] },
      prev,
      patch: {},
      fetchBody,
      now: T2,
    });

    const x2 = find(ed2.manifest as ManifestV03, "circle", "sec_x");
    assert.equal(x2.blob_sha, x1.blob_sha, "body untouched → same blob_sha");
    assert.equal(ed2.blobs.size, 0, "a pure grant uploads zero blobs");
    const recips = x2.cipher!.wraps.map((w) => w.recipient);
    assert.ok(recips.includes(`${subjectDid}#circle-kex`), "subject still wrapped");
    assert.ok(recips.includes(`agent:reader#${pub}`), "delegate now wrapped");

    // Delegate decrypts the carried-forward body; owner still can too.
    const zm = (ed2.manifest as ManifestV03).zones.circle!;
    const delReader = delegateSectionReader("agent:reader", pub, agent.seed);
    const r = readSection(zm, x2, blobFor(x2, ed2.blobs, ed1.blobs), subjectDid, delReader);
    assert.ok(r.accessible && r.section, "delegate opens the re-wrapped section");
    assert.equal(r.section!.body, "x-body");
    const ownerReader = ownerSectionReader(subjectDid, "circle", id.circle.seed);
    assert.equal(
      readSection(zm, x2, blobFor(x2, ed2.blobs, ed1.blobs), subjectDid, ownerReader).accessible,
      true,
      "owner still reads it",
    );
  });

  test("granting on self re-wraps the encrypted title too (delegate gets title + body), blob unchanged", async () => {
    const id = createBrowserIdentity("gina", "Gina");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));

    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "gina",
      displayName: "Gina",
      didJson,
      zones: { self: [sec("sec_p", "P", "priced", ["pricing"])] },
      now: T1,
    });
    const prev = { manifest: ed1.manifest, getBlob: (f: string) => ed1.blobs.get(f)! };
    const p1 = find(ed1.manifest as ManifestV03, "self", "sec_p");

    const agent = generateKeyPair();
    const pub = ed25519PublicKeyToMultibase(agent.publicKey);
    const grant: DelegateReadGrant = {
      recipient: { didUrl: `agent:tagged#${pub}`, x25519PublicKey: edPubToX25519Pub(agent.publicKey) },
      scopes: ["ethos.read.self#tag=pricing"],
    };
    const fetchBody = async (): Promise<Section> => {
      throw new Error("re-wrap must not call fetchBody");
    };

    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "gina",
      displayName: "Gina",
      didJson,
      delegateGrants: { self: [grant] },
      prev,
      patch: {},
      carriedSelfTags: new Map([["sec_p", ["pricing"]]]),
      fetchBody,
      now: T2,
    });

    const p2 = find(ed2.manifest as ManifestV03, "self", "sec_p");
    assert.equal(p2.blob_sha, p1.blob_sha, "self body untouched → same blob_sha");
    assert.equal(ed2.blobs.size, 0, "zero upload");
    assert.ok(
      p2.title_cipher!.wraps.map((w) => w.recipient).includes(`agent:tagged#${pub}`),
      "delegate added to the encrypted title's wraps",
    );

    const zm = (ed2.manifest as ManifestV03).zones.self!;
    const delReader = delegateSectionReader("agent:tagged", pub, agent.seed);
    const r = readSection(zm, p2, blobFor(p2, ed2.blobs, ed1.blobs), subjectDid, delReader);
    assert.ok(r.accessible && r.section, "delegate opens the re-wrapped self section");
    assert.equal(r.section!.title, "P", "title recovered from re-wrapped title_cipher");
    assert.equal(r.section!.body, "priced");
    assert.deepEqual(r.section!.tags, ["pricing"]);
  });

  test("ROTATE mode: revoking a delegate rotates the DEK (re-encrypt, new blob_sha, old key locked out)", async () => {
    const id = createBrowserIdentity("hank", "Hank");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));

    const agent = generateKeyPair();
    const pub = ed25519PublicKeyToMultibase(agent.publicKey);
    const grant: DelegateReadGrant = {
      recipient: { didUrl: `agent:reader#${pub}`, x25519PublicKey: edPubToX25519Pub(agent.publicKey) },
      scopes: ["ethos.read.circle#id=sec_x"],
    };

    // ed1 already sealed to owner + delegate.
    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "hank",
      displayName: "Hank",
      didJson,
      zones: { circle: [sec("sec_x", "X", "x-body")] },
      delegateGrants: { circle: [grant] },
      now: T1,
    });
    const x1 = find(ed1.manifest as ManifestV03, "circle", "sec_x");
    assert.ok(
      x1.cipher!.wraps.map((w) => w.recipient).includes(`agent:reader#${pub}`),
      "delegate sealed in ed1",
    );
    const prev = { manifest: ed1.manifest, getBlob: (f: string) => ed1.blobs.get(f)! };

    // ed2: grants now empty (revoked) → recipients shrink → must re-encrypt.
    const fetched: string[] = [];
    const fetchBody = async (_z: "public" | "circle" | "self", sid: string): Promise<Section> => {
      fetched.push(sid);
      return sec("sec_x", "X", "x-body");
    };
    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "hank",
      displayName: "Hank",
      didJson,
      delegateGrants: { circle: [] },
      prev,
      patch: {},
      fetchBody,
      resealMode: "rotate", // the explicit hard-cut — additive (default) never removes
      now: T2,
    });

    const x2 = find(ed2.manifest as ManifestV03, "circle", "sec_x");
    assert.deepEqual(fetched, ["sec_x"], "revocation re-encrypts (fetched the body)");
    assert.notEqual(x2.blob_sha, x1.blob_sha, "DEK rotated → new blob_sha");
    assert.ok(ed2.blobs.has(x2.blob_sha!), "re-encrypted blob uploaded");
    assert.ok(
      !x2.cipher!.wraps.map((w) => w.recipient).includes(`agent:reader#${pub}`),
      "revoked delegate dropped from wraps",
    );
    const zm = (ed2.manifest as ManifestV03).zones.circle!;
    const delReader = delegateSectionReader("agent:reader", pub, agent.seed);
    assert.equal(
      readSection(zm, x2, blobFor(x2, ed2.blobs, ed1.blobs), subjectDid, delReader).accessible,
      false,
      "revoked delegate cannot read the rotated section",
    );
  });
});

describe("v0.3 owner delta author — ADDITIVE reseal (default, P0)", () => {
  /** ed1 sealed to owner + delegate A on one circle section. */
  function sealedToA() {
    const id = createBrowserIdentity("iris", "Iris");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));
    const agentA = generateKeyPair();
    const pubA = ed25519PublicKeyToMultibase(agentA.publicKey);
    const grantA: DelegateReadGrant = {
      recipient: { didUrl: `agent:a#${pubA}`, x25519PublicKey: edPubToX25519Pub(agentA.publicKey) },
      scopes: ["ethos.read.circle"],
    };
    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "iris",
      displayName: "Iris",
      didJson,
      zones: { circle: [sec("sec_x", "X", "x-body")] },
      delegateGrants: { circle: [grantA] },
      now: T1,
    });
    const prev = { manifest: ed1.manifest, getBlob: (f: string) => ed1.blobs.get(f)! };
    const neverFetch = async (): Promise<Section> => {
      throw new Error("additive publish must NEVER call fetchBody");
    };
    return { id, subjectDid, didJson, agentA, pubA, ed1, prev, neverFetch };
  }

  test("a revoked delegate's wrap is KEPT: no re-encryption, no fetchBody, zero upload", async () => {
    const { id, subjectDid, didJson, pubA, ed1, prev, neverFetch } = sealedToA();
    // Grants now empty (A revoked) — the pure-shrink case that used to jam.
    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "iris",
      displayName: "Iris",
      didJson,
      delegateGrants: { circle: [] },
      prev,
      patch: {},
      fetchBody: neverFetch,
      now: T2,
    });
    const x1 = find(ed1.manifest as ManifestV03, "circle", "sec_x");
    const x2 = find(ed2.manifest as ManifestV03, "circle", "sec_x");
    assert.equal(x2.blob_sha, x1.blob_sha, "body untouched");
    assert.equal(ed2.blobs.size, 0, "zero upload");
    assert.ok(
      x2.cipher!.wraps.map((w) => w.recipient).includes(`agent:a#${pubA}`),
      "revoked residue kept verbatim (server gates its reads)",
    );
    // And the publish ACTUALLY produced a new edition (height bumped) — the
    // P0 symptom was precisely that no edition could be published anymore.
    assert.equal(ed2.manifest.edition.height, ed1.manifest.edition.height + 1);
  });

  test("P0 scenario: grant B while revoked A lingers → B appended, A kept, blob unchanged, B decrypts", async () => {
    const { id, subjectDid, didJson, pubA, ed1, prev, neverFetch } = sealedToA();
    const agentB = generateKeyPair();
    const pubB = ed25519PublicKeyToMultibase(agentB.publicKey);
    const grantB: DelegateReadGrant = {
      recipient: { didUrl: `agent:b#${pubB}`, x25519PublicKey: edPubToX25519Pub(agentB.publicKey) },
      scopes: ["ethos.read.circle"],
    };
    // Active grants = [B] only (A revoked) — used to force a re-encrypt + jam.
    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "iris",
      displayName: "Iris",
      didJson,
      delegateGrants: { circle: [grantB] },
      prev,
      patch: {},
      fetchBody: neverFetch,
      now: T2,
    });
    const x1 = find(ed1.manifest as ManifestV03, "circle", "sec_x");
    const x2 = find(ed2.manifest as ManifestV03, "circle", "sec_x");
    assert.equal(x2.blob_sha, x1.blob_sha, "append is a re-wrap: body/blob untouched");
    assert.equal(ed2.blobs.size, 0, "zero upload");
    const recips = x2.cipher!.wraps.map((w) => w.recipient);
    assert.ok(recips.includes(`${subjectDid}#circle-kex`), "owner still wrapped");
    assert.ok(recips.includes(`agent:a#${pubA}`), "revoked residue untouched");
    assert.ok(recips.includes(`agent:b#${pubB}`), "fresh grant appended");

    const zm = (ed2.manifest as ManifestV03).zones.circle!;
    const bReader = delegateSectionReader("agent:b", pubB, agentB.seed);
    const r = readSection(zm, x2, blobFor(x2, ed2.blobs, ed1.blobs), subjectDid, bReader);
    assert.ok(r.accessible && r.section, "B opens the appended wrap");
    assert.equal(r.section!.body, "x-body");
    const ownerReader = ownerSectionReader(subjectDid, "circle", id.circle.seed);
    assert.equal(
      readSection(zm, x2, blobFor(x2, ed2.blobs, ed1.blobs), subjectDid, ownerReader).accessible,
      true,
      "owner still reads it",
    );
  });

  test("an EDITED section resyncs its recipients (drops the revoked, adds the covered) — both modes", async () => {
    const { id, subjectDid, didJson, pubA, ed1, prev } = sealedToA();
    const agentB = generateKeyPair();
    const pubB = ed25519PublicKeyToMultibase(agentB.publicKey);
    const grantB: DelegateReadGrant = {
      recipient: { didUrl: `agent:b#${pubB}`, x25519PublicKey: edPubToX25519Pub(agentB.publicKey) },
      scopes: ["ethos.read.circle"],
    };
    // Content edit of sec_x with active grants = [B]: re-encryption is forced by
    // the edit itself, so the recipient list is rebuilt from the active grants —
    // the "free cleanup": A (revoked) is gone AND the new DEK is unknown to it.
    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "iris",
      displayName: "Iris",
      didJson,
      delegateGrants: { circle: [grantB] },
      prev,
      patch: { circle: { upserts: [sec("sec_x", "X", "x-body v2")] } },
      now: T2,
    });
    const x1 = find(ed1.manifest as ManifestV03, "circle", "sec_x");
    const x2 = find(ed2.manifest as ManifestV03, "circle", "sec_x");
    assert.notEqual(x2.blob_sha, x1.blob_sha, "content edit → new DEK + new blob");
    const recips = x2.cipher!.wraps.map((w) => w.recipient);
    assert.ok(!recips.includes(`agent:a#${pubA}`), "revoked A dropped on edit (cleanup)");
    assert.ok(recips.includes(`agent:b#${pubB}`), "covered B sealed on edit");
  });

  test("additive on self extends the sealed title too; protocol-core verifies the edition", async () => {
    const id = createBrowserIdentity("jane", "Jane");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));
    const agentA = generateKeyPair();
    const pubA = ed25519PublicKeyToMultibase(agentA.publicKey);
    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "jane",
      displayName: "Jane",
      didJson,
      zones: { self: [sec("sec_s", "S", "s-body", ["plans"])] },
      delegateGrants: {
        self: [{
          recipient: { didUrl: `agent:a#${pubA}`, x25519PublicKey: edPubToX25519Pub(agentA.publicKey) },
          scopes: ["ethos.read.self"],
        }],
      },
      now: T1,
    });
    const prev = { manifest: ed1.manifest, getBlob: (f: string) => ed1.blobs.get(f)! };
    const agentB = generateKeyPair();
    const pubB = ed25519PublicKeyToMultibase(agentB.publicKey);
    const ed2 = await patchEditionV03Owner({
      identity: id,
      subjectDid,
      subjectHandle: "jane",
      displayName: "Jane",
      didJson,
      delegateGrants: {
        self: [{
          recipient: { didUrl: `agent:b#${pubB}`, x25519PublicKey: edPubToX25519Pub(agentB.publicKey) },
          scopes: ["ethos.read.self"],
        }],
      },
      prev,
      patch: {},
      carriedSelfTags: new Map([["sec_s", ["plans"]]]),
      now: T2,
    });
    const s2 = find(ed2.manifest as ManifestV03, "self", "sec_s");
    assert.equal(ed2.blobs.size, 0, "zero upload");
    const titleRecips = s2.title_cipher!.wraps.map((w) => w.recipient);
    assert.ok(titleRecips.includes(`agent:a#${pubA}`), "residue kept on title wraps");
    assert.ok(titleRecips.includes(`agent:b#${pubB}`), "B appended on title wraps");
    const bReader = delegateSectionReader("agent:b", pubB, agentB.seed);
    const zm = (ed2.manifest as ManifestV03).zones.self!;
    const r = readSection(zm, s2, blobFor(s2, ed2.blobs, ed1.blobs), subjectDid, bReader);
    assert.ok(r.accessible && r.section, "B opens body via appended wrap");
    assert.equal(r.section!.title, "S", "B opens the sealed title via appended wrap");

    // The additive edition still verifies end-to-end under protocol-core,
    // including the self reader (same harness as the delta test above).
    const dir = writeBundle(ed2, didJson, ed1.blobs);
    try {
      const res = core.verifyBundleV03Dir(dir, {
        readers: [
          { didUrl: `${subjectDid}#self-kex`, x25519Secret: edSeedToX25519Secret(id.self.seed) },
        ],
      });
      assert.ok(res.ok, `protocol-core verify failed: ${res.errors.join("; ")}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
