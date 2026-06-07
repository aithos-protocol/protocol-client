// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Cross-implementation conformance: the browser client authors a v0.3 edition AS
// A DELEGATE (section-scoped), and @aithos/protocol-core verifies it with a
// delegate resolver. Proves: per-section recipients (owner + delegate), the
// delegate-signed manifest (authorized_by), carry-forward of sections the
// delegate can't read, and owner-readability of the delegate's own section.

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
  patchEditionV03Delegate,
  ownerZoneKexPubkey,
  type AuthoredV03,
  type DelegateAuthorV03,
  type DelegateReadGrant,
} from "../src/crypto/bundle-v03-write.js";
import {
  readSection,
  ownerSectionReader,
  delegateSectionReader,
  readZoneIndex,
  type ManifestV03,
} from "../src/crypto/bundle-v03.js";
import type { Section } from "../src/crypto/manifest.js";

const core = await import("@aithos/protocol-core");

function writeBundle(authored: AuthoredV03, didJson: Uint8Array): string {
  const dir = mkdtempSync(join(tmpdir(), "pc-v03-del-"));
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(authored.manifest));
  writeFileSync(join(dir, "did.json"), didJson);
  for (const [file, bytes] of authored.blobs) {
    const abs = join(dir, file);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, bytes);
  }
  return dir;
}

const sec = (id: string, title: string, body: string): Section => ({ id, title, body, gamma_ref: "gamma_" + id });

describe("v0.3 delegate authoring — conformance vs protocol-core", () => {
  test("a section-scoped delegate appends to self; owner reads it; the rest carries forward", () => {
    const id = createBrowserIdentity("alice", "Alice");
    const didDoc = signedDidDocument(id);
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(didDoc));

    // Owner edition 1: one self section the delegate cannot read.
    const ed1 = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "alice",
      displayName: "Alice",
      didJson,
      zones: { self: [sec("sec_routine", "Routine", "Up at six.")] },
      now: new Date("2026-06-06T10:00:00Z"),
    });

    // A delegate (agent key) scoped to self.
    const agent = generateKeyPair();
    const pubkeyMultibase = ed25519PublicKeyToMultibase(agent.publicKey);
    const delegate: DelegateAuthorV03 = {
      granteeId: "agent:gmail",
      pubkeyMultibase,
      seed: agent.seed,
      mandateId: "mandate_test01",
      actorSphere: "self",
    };
    const ownerZonePubkey = ownerZoneKexPubkey(didDoc, subjectDid, "self");

    // Edition 2: the delegate appends its own self section.
    const ed2 = patchEditionV03Delegate({
      delegate,
      subjectDid,
      subjectHandle: "alice",
      displayName: "Alice",
      didJson,
      ownerZonePubkey,
      prev: { manifest: ed1.manifest, getBlob: (f) => ed1.blobs.get(f)! },
      patch: { upserts: [sec("sec_inbox", "Inbox triage", "3 unread.")] },
      now: new Date("2026-06-07T10:00:00Z"),
    });

    // Edition shape + delegate signature.
    assert.equal(ed2.manifest.edition.height, 2);
    assert.equal(ed2.manifest.edition.supersedes, ed1.manifest.bundle_id);
    const sig = (ed2.manifest as ManifestV03).integrity.manifest_signature as {
      key: string;
      authorized_by?: string;
    };
    assert.equal(sig.key, pubkeyMultibase, "manifest signed with the delegate key");
    assert.equal(sig.authorized_by, "mandate_test01");

    // The owner's prior section carried forward byte-identical.
    assert.deepEqual([...ed2.blobs.get("self/sec_routine.enc")!], [...ed1.blobs.get("self/sec_routine.enc")!]);

    // Owner can read BOTH (its own + the delegate's); delegate reads ONLY its own.
    const zm = (ed2.manifest as ManifestV03).zones.self!;
    const inboxDesc = zm.sections.find((s) => s.section_id === "sec_inbox")!;
    const routineDesc = zm.sections.find((s) => s.section_id === "sec_routine")!;

    const ownerReader = ownerSectionReader(subjectDid, "self", id.self.seed);
    const delReader = delegateSectionReader("agent:gmail", pubkeyMultibase, agent.seed);

    const ownerInbox = readSection(zm, inboxDesc, ed2.blobs.get(inboxDesc.file)!, subjectDid, ownerReader);
    assert.ok(ownerInbox.accessible && ownerInbox.section!.body === "3 unread.");

    const delInbox = readSection(zm, inboxDesc, ed2.blobs.get(inboxDesc.file)!, subjectDid, delReader);
    assert.ok(delInbox.accessible && delInbox.section!.body === "3 unread.");

    const delRoutine = readSection(zm, routineDesc, ed2.blobs.get(routineDesc.file)!, subjectDid, delReader);
    assert.equal(delRoutine.accessible, false, "delegate is NOT a recipient of the owner's section");

    // Self index: owner sees both titles; delegate sees only its own.
    const ownerIdx = readZoneIndex(zm, subjectDid, ownerReader);
    assert.deepEqual(ownerIdx.map((r) => r.title).sort(), ["Inbox triage", "Routine"]);
    const delIdx = readZoneIndex(zm, subjectDid, delReader);
    assert.deepEqual(
      delIdx.filter((r) => !r.title_hidden).map((r) => r.title),
      ["Inbox triage"],
    );

    // protocol-core verifies the delegate-signed edition (resolver returns the
    // delegate pubkey) + decrypts every section with the owner readers.
    const dir = writeBundle(ed2, didJson);
    try {
      const reader = (z: "circle" | "self") => ({
        didUrl: `${subjectDid}#${z}-kex`,
        x25519Secret: edSeedToX25519Secret(id[z].seed),
      });
      const res = core.verifyBundleV03Dir(dir, {
        readers: [reader("circle"), reader("self")],
        resolveDelegatePubkey: () => agent.publicKey,
      });
      assert.ok(res.ok, `protocol-core verify failed: ${res.errors.join("; ")}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("v0.3 owner author — per-section delegate recipients (§3.5.7′)", () => {
  function setup(scopes: readonly string[]) {
    const id = createBrowserIdentity("carol", "Carol");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));
    const agent = generateKeyPair();
    const pubkeyMultibase = ed25519PublicKeyToMultibase(agent.publicKey);
    const grant: DelegateReadGrant = {
      recipient: {
        didUrl: `agent:scoped#${pubkeyMultibase}`,
        x25519PublicKey: edPubToX25519Pub(agent.publicKey),
      },
      scopes,
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
    const zm = (ed.manifest as ManifestV03).zones.self!;
    const aDesc = zm.sections.find((s) => s.section_id === "sec_a")!;
    const bDesc = zm.sections.find((s) => s.section_id === "sec_b")!;
    const delReader = delegateSectionReader("agent:scoped", pubkeyMultibase, agent.seed);
    const ownerReader = ownerSectionReader(subjectDid, "self", id.self.seed);
    const canRead = (desc: typeof aDesc, reader: typeof delReader) =>
      readSection(zm, desc, ed.blobs.get(desc.file)!, subjectDid, reader).accessible;
    return { aDesc, bDesc, delReader, ownerReader, canRead };
  }

  test("a section-scoped grant (#id=) seals the delegate into ONLY its section", () => {
    const { aDesc, bDesc, delReader, ownerReader, canRead } = setup([
      "ethos.edit.self#id=sec_a",
    ]);
    assert.equal(canRead(aDesc, delReader), true, "delegate reads its scoped section");
    assert.equal(canRead(bDesc, delReader), false, "delegate cannot read the out-of-scope section");
    // Owner always reads everything.
    assert.equal(canRead(aDesc, ownerReader), true);
    assert.equal(canRead(bDesc, ownerReader), true);
  });

  test("a whole-zone read grant seals the delegate into every section", () => {
    const { aDesc, bDesc, delReader, canRead } = setup(["ethos.read.self"]);
    assert.equal(canRead(aDesc, delReader), true);
    assert.equal(canRead(bDesc, delReader), true);
  });

  test("a prefix grant seals only matching ids; an append verb still bears read", () => {
    const id = createBrowserIdentity("dave", "Dave");
    const subjectDid = id.did;
    const didJson = new TextEncoder().encode(JSON.stringify(signedDidDocument(id)));
    const agent = generateKeyPair();
    const pubkeyMultibase = ed25519PublicKeyToMultibase(agent.publicKey);
    const grant: DelegateReadGrant = {
      recipient: {
        didUrl: `agent:gmail#${pubkeyMultibase}`,
        x25519PublicKey: edPubToX25519Pub(agent.publicKey),
      },
      scopes: ["ethos.append.self#prefix=gmail:"],
    };
    const ed = authorBundleV03({
      identity: id,
      subjectDid,
      subjectHandle: "dave",
      displayName: "Dave",
      didJson,
      zones: { self: [sec("gmail:1", "Mail", "hi"), sec("note:1", "Note", "secret")] },
      delegateGrants: { self: [grant] },
      now: new Date("2026-06-07T10:00:00Z"),
    });
    const zm = (ed.manifest as ManifestV03).zones.self!;
    const gDesc = zm.sections.find((s) => s.section_id === "gmail:1")!;
    const nDesc = zm.sections.find((s) => s.section_id === "note:1")!;
    const delReader = delegateSectionReader("agent:gmail", pubkeyMultibase, agent.seed);
    assert.equal(
      readSection(zm, gDesc, ed.blobs.get(gDesc.file)!, subjectDid, delReader).accessible,
      true,
      "append delegate reads its gmail:* section",
    );
    assert.equal(
      readSection(zm, nDesc, ed.blobs.get(nDesc.file)!, subjectDid, delReader).accessible,
      false,
      "append delegate cannot read note:1",
    );
  });
});
