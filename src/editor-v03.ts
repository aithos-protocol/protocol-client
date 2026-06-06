// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// v0.3 (per-section) editor — the transport wiring for the per-section bundle.
//
// Reads: get_ethos_manifest (v0.3 manifest) + get_ethos_section (one blob by id)
// — the client decrypts locally with the owner sphere keys. Writes: author a new
// v0.3 edition locally (authorBundleV03), then POST publish_ethos_edition with
// the per-section blobs inside a signed §11 envelope.
//
// Scope: OWNER authoring (the app's own ethos). Carry-forward reuses the prior
// edition's blobs byte-identical, so only changed sections are re-encrypted; the
// prior blobs are pre-fetched (authorBundleV03 takes a synchronous getBlob).
//
// Delegate authoring exists at the crypto layer (patchEditionV03Delegate) and is
// wired through the editor in a follow-up.

import type { StoredIdentity } from "./storage-types.js";
import { browserIdentityFromStored } from "./crypto/identity.js";
import type { DidDocument } from "./crypto/identity.js";
import type { Section } from "./crypto/manifest.js";
import { buildSignedEnvelope } from "./crypto/envelope.js";
import { readRpc } from "./api.js";
import { writeEndpoint } from "./endpoints.js";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "./crypto/encoding.js";
import {
  isV03Manifest,
  ownerSectionReader,
  readSection,
  readZoneIndex,
  type IndexRow,
  type ManifestV03,
  type SphereName,
} from "./crypto/bundle-v03.js";
import { authorBundleV03 } from "./crypto/bundle-v03-write.js";

export class EditV03Error extends Error {
  readonly step: string;
  readonly data?: Record<string, unknown>;
  constructor(step: string, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "EditV03Error";
    this.step = step;
    this.data = data;
  }
}

const SPHERES: readonly SphereName[] = ["public", "circle", "self"];

/* -------------------------------------------------------------------------- */
/*  Read                                                                      */
/* -------------------------------------------------------------------------- */

export interface EthosV03Snapshot {
  readonly manifest: ManifestV03;
  /** Section index per zone (id + title; self titles need the owner key). */
  readonly index: Record<SphereName, IndexRow[]>;
  /** Decrypted sections per zone (only when the owner identity is supplied). */
  readonly sections?: Record<SphereName, Section[]>;
}

/** Fetch one section blob by id (base64 → bytes) via get_ethos_section. */
async function fetchSectionBlob(did: string, sectionId: string): Promise<Uint8Array> {
  const signed = await readRpc<{ object: { bytes_base64: string } }>(
    "aithos.get_ethos_section",
    { did, section_id: sectionId },
  );
  return bytesFromBase64(signed.object.bytes_base64);
}

/**
 * Load a v0.3 ethos: the manifest + per-zone index, and — when the owner
 * identity is supplied — the decrypted sections (fetched per-section, then
 * decrypted locally). Throws if the subject's current edition is not v0.3.
 */
export async function loadEthosV03(did: string, identity?: StoredIdentity): Promise<EthosV03Snapshot> {
  const signed = await readRpc<{ object: ManifestV03 }>("aithos.get_ethos_manifest", { did });
  const manifest = signed.object;
  if (!isV03Manifest(manifest)) {
    throw new EditV03Error("manifest", `subject ${did} is not on a v0.3 edition (aithos=${(manifest as { aithos?: string }).aithos})`);
  }
  const subjectDid = manifest.subject_did;
  const owner = identity && identity.did === did ? identity : undefined;

  const index = {} as Record<SphereName, IndexRow[]>;
  const sections = owner ? ({} as Record<SphereName, Section[]>) : undefined;

  for (const zone of SPHERES) {
    const zm = manifest.zones[zone];
    if (!zm) {
      index[zone] = [];
      if (sections) sections[zone] = [];
      continue;
    }
    const reader =
      zone !== "public" && owner
        ? ownerSectionReader(subjectDid, zone, hexToBytes(owner.seeds[zone]))
        : undefined;
    index[zone] = readZoneIndex(zm, subjectDid, reader);

    if (sections) {
      const list: Section[] = [];
      for (const desc of zm.sections) {
        const blob = await fetchSectionBlob(did, desc.section_id);
        const res = readSection(zm, desc, blob, subjectDid, reader);
        if (res.accessible && res.section) list.push(res.section);
      }
      sections[zone] = list;
    }
  }

  return { manifest, index, ...(sections ? { sections } : {}) };
}

/* -------------------------------------------------------------------------- */
/*  Publish (owner)                                                           */
/* -------------------------------------------------------------------------- */

export interface PublishV03OwnerArgs {
  readonly identity: StoredIdentity;
  /** The current v0.3 manifest (from loadEthosV03). Omit for the first edition. */
  readonly prevManifest?: ManifestV03;
  /** Full new section lists per zone (replaces the zone's content). */
  readonly publicSections?: readonly Section[];
  readonly circleSections?: readonly Section[];
  readonly selfSections?: readonly Section[];
  /** subject_handle / display_name — defaults from prevManifest when present. */
  readonly handle?: string;
  readonly displayName?: string;
}

export interface PublishV03Result {
  readonly manifest: ManifestV03;
}

/**
 * Author + publish a new v0.3 edition as the owner. Unchanged sections carry
 * forward (their prior blobs are pre-fetched and reused byte-identical); only
 * changed/new sections are re-encrypted. The new edition is posted inside a
 * signed §11 envelope.
 */
export async function publishEthosEditionV03Owner(args: PublishV03OwnerArgs): Promise<PublishV03Result> {
  const browserId = browserIdentityFromStored(args.identity);
  const did = browserId.did;

  // did.json (exact server byte-shape) → its sha256 anchors the manifest.
  const idResp = await readRpc<{ object: DidDocument }>("aithos.get_identity", { did });
  const didJson = new TextEncoder().encode(JSON.stringify(idResp.object, null, 2) + "\n");

  const handle = args.handle ?? args.prevManifest?.subject_handle;
  const displayName = args.displayName ?? args.prevManifest?.display_name ?? handle;
  if (!handle) {
    throw new EditV03Error("handle", "subject_handle required (pass `handle` or a prevManifest)");
  }

  const zones: Partial<Record<SphereName, readonly Section[]>> = {
    ...(args.publicSections ? { public: args.publicSections } : {}),
    ...(args.circleSections ? { circle: args.circleSections } : {}),
    ...(args.selfSections ? { self: args.selfSections } : {}),
  };

  // Carry-forward needs the prior blobs (authorBundleV03 takes a SYNC getBlob),
  // so pre-fetch every prior section blob into a map first.
  let prev: { manifest: ManifestV03; getBlob: (file: string) => Uint8Array } | undefined;
  if (args.prevManifest && isV03Manifest(args.prevManifest)) {
    const blobMap = new Map<string, Uint8Array>();
    for (const zone of SPHERES) {
      for (const desc of args.prevManifest.zones[zone]?.sections ?? []) {
        blobMap.set(desc.file, await fetchSectionBlob(did, desc.section_id));
      }
    }
    prev = {
      manifest: args.prevManifest,
      getBlob: (file) => {
        const b = blobMap.get(file);
        if (!b) throw new EditV03Error("carry-forward", `prior blob not pre-fetched: ${file}`);
        return b;
      },
    };
  }

  const { manifest, blobs } = authorBundleV03({
    identity: browserId,
    subjectDid: did,
    subjectHandle: handle,
    displayName: displayName ?? handle,
    didJson,
    zones,
    ...(prev ? { prev } : {}),
  });

  // Per-section blobs → the publish input shape.
  const blobsParam: Record<string, { bytes_base64: string }> = {};
  for (const [file, bytes] of blobs) {
    blobsParam[file] = { bytes_base64: bytesToBase64(bytes) };
  }

  const params = { manifest, blobs: blobsParam };
  const envelope = buildSignedEnvelope({
    iss: did,
    aud: writeEndpoint(),
    method: "aithos.publish_ethos_edition",
    verificationMethod: `${did}#public`,
    params,
    signer: browserId.public,
  });

  const res = await fetch(writeEndpoint(), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "aithos.publish_ethos_edition",
      method: "aithos.publish_ethos_edition",
      params: { ...params, _envelope: envelope },
    }),
  });
  const body = (await res.json()) as {
    result?: unknown;
    error?: { code: number; message: string; data?: Record<string, unknown> };
  };
  if (body.error) {
    throw new EditV03Error("publish_ethos_edition", body.error.message, {
      code: body.error.code,
      ...body.error.data,
    });
  }

  return { manifest };
}

/* -------------------------------------------------------------------------- */
/*  internals                                                                 */
/* -------------------------------------------------------------------------- */

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex must be even-length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function bytesFromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}
