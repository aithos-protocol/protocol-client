// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Tests for the optional dedicated #data sphere
// (spec/data/02-key-hierarchy.md §2.2) in the browser identity path. Mirrors
// the protocol-core data-sphere tests.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  createBrowserIdentity,
  signedDidDocument,
  browserIdentityFromStored,
  buildBlobPlaintext,
  serializeBlob,
  parseBlob,
} from "../src/index.js";

test("createBrowserIdentity is eager — carries a #data sphere", () => {
  const id = createBrowserIdentity("alice", "Alice");
  assert.ok(id.data, "identity.data should be present");
  assert.equal(id.data.seed.length, 32);
  assert.notDeepEqual(id.data.seed, id.root.seed);
});

test("signedDidDocument exposes #data + #data-kex and stays root-signed", () => {
  const id = createBrowserIdentity("bob", "Bob");
  const doc = signedDidDocument(id);
  const vmIds = doc.verificationMethod.map((vm) => vm.id);
  const kexIds = (doc.keyAgreement ?? []).map((vm) => vm.id);

  for (const s of ["public", "circle", "self"]) {
    assert.ok(vmIds.includes(`${doc.id}#${s}`), `missing #${s}`);
  }
  assert.ok(vmIds.includes(`${doc.id}#data`), "missing #data VM");
  assert.ok(kexIds.includes(`${doc.id}#data-kex`), "missing #data-kex");
  // #data appended AFTER the 3 Ethos spheres (canonical order).
  assert.equal(vmIds[vmIds.length - 1], `${doc.id}#data`);
  assert.equal(doc.proof.verificationMethod, `${doc.id}#root`);
});

test("legacy identity without #data → 3-sphere doc, no #data", () => {
  const id = createBrowserIdentity("dave", "Dave");
  const legacy = { ...id, data: undefined };
  const doc = signedDidDocument(legacy);
  assert.ok(!doc.verificationMethod.some((vm) => vm.id === `${doc.id}#data`));
  assert.equal(doc.verificationMethod.length, 3);
});

test("recovery/vault blob round-trips the #data seed", () => {
  const id = createBrowserIdentity("carol", "Carol");
  const blob = buildBlobPlaintext({
    identity: { handle: id.handle, displayName: id.displayName, did: id.did },
    seeds: {
      root: id.root.seed,
      public: id.public.seed,
      circle: id.circle.seed,
      self: id.self.seed,
      data: id.data!.seed,
    },
  });
  const parsed = parseBlob(serializeBlob(blob));
  assert.ok(parsed.seeds.data, "parsed blob should carry seeds.data");
  assert.equal(parsed.seeds.data, blob.seeds.data);

  // Rehydrate → identity carries #data again.
  const rehydrated = browserIdentityFromStored({
    handle: id.handle,
    displayName: id.displayName,
    did: id.did,
    seeds: parsed.seeds,
  });
  assert.ok(rehydrated.data);
  assert.deepEqual(rehydrated.data.seed, id.data!.seed);
});

test("legacy blob without #data still parses (backward compat)", () => {
  const id = createBrowserIdentity("erin", "Erin");
  const blob = buildBlobPlaintext({
    identity: { handle: id.handle, displayName: id.displayName, did: id.did },
    seeds: {
      root: id.root.seed,
      public: id.public.seed,
      circle: id.circle.seed,
      self: id.self.seed,
      // no data
    },
  });
  const parsed = parseBlob(serializeBlob(blob));
  assert.equal(parsed.seeds.data, undefined);
  const rehydrated = browserIdentityFromStored({
    handle: id.handle,
    displayName: id.displayName,
    did: id.did,
    seeds: parsed.seeds,
  });
  assert.equal(rehydrated.data, undefined);
});
