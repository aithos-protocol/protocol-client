// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Tests for buildSignedFirstEditionFromSections — the multi-section
// first-edition builder used by the SDK to publish height=1 with the
// user's staged additions in one shot, instead of forcing a single seed
// section like buildSignedFirstEdition.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildSignedFirstEdition,
  buildSignedFirstEditionFromSections,
  createBrowserIdentity,
  signedDidDocument,
  type Section,
} from "../src/index.js";

function fakeSection(title: string, body: string, idSuffix: string): Section {
  return {
    id: `sec_${idSuffix}`,
    title,
    body,
    gamma_ref: `gamma_none_${idSuffix.padEnd(24, "0")}`,
  };
}

test("buildSignedFirstEditionFromSections — accepts N public sections", () => {
  const id = createBrowserIdentity("alice", "Alice");
  const signedDoc = signedDidDocument(id);
  const sections: Section[] = [
    fakeSection("First", "Body of first.", "aaaaaaaaaaaa"),
    fakeSection("Second", "Body of second.", "bbbbbbbbbbbb"),
    fakeSection("Third", "Body of third.", "cccccccccccc"),
  ];

  const r = buildSignedFirstEditionFromSections({
    identity: id,
    signedDidDoc: signedDoc,
    publicSections: sections,
  });

  assert.equal(r.manifest.edition.height, 1);
  assert.equal(r.manifest.edition.prev_hash, null);
  assert.equal(r.manifest.edition.supersedes, null);
  assert.equal(r.manifest.subject_did, id.did);
  assert.deepEqual(r.manifest.zones.public?.section_titles, [
    "First",
    "Second",
    "Third",
  ]);
  assert.ok(r.publicMarkdownBytes.length > 0);
  // Rendered markdown must contain the three section titles in order.
  const rendered = new TextDecoder().decode(r.publicMarkdownBytes);
  assert.match(rendered, /# First /);
  assert.match(rendered, /# Second /);
  assert.match(rendered, /# Third /);
  assert.ok(
    rendered.indexOf("# First") < rendered.indexOf("# Second"),
    "section ordering must be preserved in rendering",
  );
});

test("buildSignedFirstEditionFromSections — rejects empty section list", () => {
  const id = createBrowserIdentity("alice", "Alice");
  const signedDoc = signedDidDocument(id);
  assert.throws(
    () =>
      buildSignedFirstEditionFromSections({
        identity: id,
        signedDidDoc: signedDoc,
        publicSections: [],
      }),
    /at least one section/,
  );
});

test("buildSignedFirstEdition — back-compat wrapper produces a valid 1-section first edition", () => {
  const id = createBrowserIdentity("alice", "Alice");
  const signedDoc = signedDidDocument(id);

  const r = buildSignedFirstEdition({
    identity: id,
    signedDidDoc: signedDoc,
    publicTitle: "Hello",
    publicBody: "World",
  });

  assert.equal(r.manifest.edition.height, 1);
  assert.deepEqual(r.manifest.zones.public?.section_titles, ["Hello"]);
  assert.match(
    new TextDecoder().decode(r.publicMarkdownBytes),
    /# Hello /,
  );
});

test("buildSignedFirstEditionFromSections — manifest signature is valid (round-trip via verify path)", () => {
  // Sanity: the manifest_signature value must be present and base64url-ish.
  // A full server-side verify roundtrip is exercised by the editor test
  // suite; here we just guard against a missing signature regression.
  const id = createBrowserIdentity("alice", "Alice");
  const signedDoc = signedDidDocument(id);
  const r = buildSignedFirstEditionFromSections({
    identity: id,
    signedDidDoc: signedDoc,
    publicSections: [fakeSection("Solo", "Body.", "ddddddddd001")],
  });
  assert.equal(r.manifest.integrity.manifest_signature.alg, "ed25519");
  assert.equal(
    r.manifest.integrity.manifest_signature.key,
    `${id.did}#public`,
  );
  assert.match(
    r.manifest.integrity.manifest_signature.value,
    /^[A-Za-z0-9_-]+$/,
    "must be base64url",
  );
});

/* -------------------------------------------------------------------------- */
/*  Encrypted-zone first editions (added in 0.1.0-alpha.14)                   */
/* -------------------------------------------------------------------------- */

test("buildSignedFirstEditionFromSections — accepts circle sections in addition to public", () => {
  const id = createBrowserIdentity("alice", "Alice");
  const signedDoc = signedDidDocument(id);

  const r = buildSignedFirstEditionFromSections({
    identity: id,
    signedDidDoc: signedDoc,
    publicSections: [fakeSection("Sentinel", "Initialized.", "aaaaaaaaaaaa")],
    circleSections: [
      fakeSection("Private", "Circle body.", "cccccccccccc"),
    ],
  });

  // Manifest declares both zones.
  assert.equal(r.manifest.edition.height, 1);
  assert.equal(r.manifest.edition.prev_hash, null);
  assert.ok(r.manifest.zones.public, "public zone must be present");
  assert.ok(r.manifest.zones.circle, "circle zone must be present");

  // Public zone — unencrypted, plaintext markdown bytes returned.
  assert.equal(r.manifest.zones.public!.encrypted, false);
  assert.deepEqual(r.manifest.zones.public!.section_titles, ["Sentinel"]);

  // Circle zone — sealed: encrypted=true, cipher present, signature
  // under #circle.
  assert.equal(r.manifest.zones.circle!.encrypted, true);
  assert.equal(r.manifest.zones.circle!.file, "circle.md.enc");
  assert.deepEqual(r.manifest.zones.circle!.section_titles, ["Private"]);
  assert.equal(r.manifest.zones.circle!.signature.key, `${id.did}#circle`);
  assert.ok(r.manifest.zones.circle!.cipher, "circle cipher must be present");
  assert.equal(
    r.manifest.zones.circle!.cipher!.alg,
    "xchacha20poly1305-ietf",
  );
  assert.ok(
    r.manifest.zones.circle!.cipher!.wraps.length >= 1,
    "must have at least one wrap (owner)",
  );

  // Ciphertext bytes returned for upload.
  assert.ok(r.circleBytes, "circleBytes must be returned");
  assert.ok(r.circleBytes!.length > 0, "circleBytes must be non-empty");
  assert.equal(r.selfBytes, undefined, "selfBytes absent when no self");

  // Manifest still signed by #public.
  assert.equal(
    r.manifest.integrity.manifest_signature.key,
    `${id.did}#public`,
  );
});

test("buildSignedFirstEditionFromSections — accepts self sections in addition to public", () => {
  const id = createBrowserIdentity("alice", "Alice");
  const signedDoc = signedDidDocument(id);

  const r = buildSignedFirstEditionFromSections({
    identity: id,
    signedDidDoc: signedDoc,
    publicSections: [fakeSection("Sentinel", "Initialized.", "aaaaaaaaaaaa")],
    selfSections: [fakeSection("Journal", "Self body.", "sssssssssss1")],
  });

  assert.ok(r.manifest.zones.self, "self zone must be present");
  assert.equal(r.manifest.zones.self!.encrypted, true);
  assert.equal(r.manifest.zones.self!.file, "self.md.enc");
  assert.deepEqual(r.manifest.zones.self!.section_titles, ["Journal"]);
  assert.equal(r.manifest.zones.self!.signature.key, `${id.did}#self`);

  assert.ok(r.selfBytes, "selfBytes must be returned");
  assert.equal(r.circleBytes, undefined, "circleBytes absent when no circle");
});

test("buildSignedFirstEditionFromSections — accepts public + circle + self in a single first edition", () => {
  const id = createBrowserIdentity("alice", "Alice");
  const signedDoc = signedDidDocument(id);

  const r = buildSignedFirstEditionFromSections({
    identity: id,
    signedDidDoc: signedDoc,
    publicSections: [fakeSection("Public", "Pub body.", "pppppppppppp")],
    circleSections: [fakeSection("Circle", "Circ body.", "cccccccccccc")],
    selfSections: [fakeSection("Self", "Self body.", "sssssssssss1")],
  });

  assert.equal(r.manifest.edition.height, 1);
  assert.ok(r.manifest.zones.public);
  assert.ok(r.manifest.zones.circle);
  assert.ok(r.manifest.zones.self);

  // Three distinct sphere signatures.
  assert.equal(r.manifest.zones.public!.signature.key, `${id.did}#public`);
  assert.equal(r.manifest.zones.circle!.signature.key, `${id.did}#circle`);
  assert.equal(r.manifest.zones.self!.signature.key, `${id.did}#self`);

  // Three distinct ciphers (DEKs are independent).
  assert.equal(r.manifest.zones.public!.encrypted, false);
  assert.equal(r.manifest.zones.circle!.encrypted, true);
  assert.equal(r.manifest.zones.self!.encrypted, true);
  assert.ok(r.manifest.zones.circle!.cipher);
  assert.ok(r.manifest.zones.self!.cipher);
  assert.notEqual(
    r.manifest.zones.circle!.cipher!.nonce,
    r.manifest.zones.self!.cipher!.nonce,
    "circle and self nonces must be independent",
  );

  // All three zones produce bytes for upload.
  assert.ok(r.publicMarkdownBytes.length > 0);
  assert.ok(r.circleBytes && r.circleBytes.length > 0);
  assert.ok(r.selfBytes && r.selfBytes.length > 0);
});

test("buildSignedFirstEditionFromSections — back-compat: omitting circle/self yields byte-identical output to pre-alpha.14 behavior", () => {
  // Regression guard: the simple public-only call site (used today by
  // runOnboarding and by `#publishFirstEditionOwner` when the user only
  // stages public adds) must produce a manifest that doesn't have
  // `circle` or `self` keys in `zones`, and the result must not carry
  // `circleBytes` / `selfBytes` fields.
  const id = createBrowserIdentity("alice", "Alice");
  const signedDoc = signedDidDocument(id);

  const r = buildSignedFirstEditionFromSections({
    identity: id,
    signedDidDoc: signedDoc,
    publicSections: [fakeSection("Only", "Body.", "oooooooooooo")],
  });

  assert.deepEqual(Object.keys(r.manifest.zones), ["public"]);
  assert.equal(
    r.circleBytes,
    undefined,
    "circleBytes must be absent when no circleSections",
  );
  assert.equal(
    r.selfBytes,
    undefined,
    "selfBytes must be absent when no selfSections",
  );
});

test("buildSignedFirstEditionFromSections — empty circleSections array is treated as 'no circle zone'", () => {
  // Edge case: `circleSections: []` should not produce a zones.circle
  // entry. Otherwise we'd publish an empty encrypted zone with no
  // sections, which is a footgun.
  const id = createBrowserIdentity("alice", "Alice");
  const signedDoc = signedDidDocument(id);

  const r = buildSignedFirstEditionFromSections({
    identity: id,
    signedDidDoc: signedDoc,
    publicSections: [fakeSection("Pub", "Body.", "pppppppppppp")],
    circleSections: [],
  });

  assert.equal(
    r.manifest.zones.circle,
    undefined,
    "empty circleSections must not produce a circle zone entry",
  );
  assert.equal(r.circleBytes, undefined);
});
