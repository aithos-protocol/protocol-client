// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// v0.3 (per-section) editor — the transport wiring for the per-section bundle.
//
// Reads: get_ethos_manifest (v0.3 manifest) + get_ethos_section (one blob by id)
// — the client decrypts locally with the owner sphere keys. Writes: author a new
// v0.3 edition locally (authorBundleV03), then POST publish_ethos_edition with
// the per-section blobs inside a signed §11 envelope.
//
// Scope: OWNER + DELEGATE authoring. Carry-forward reuses the prior edition's
// blobs byte-identical, so only changed sections are re-encrypted; the prior
// blobs are pre-fetched (the author fns take a synchronous getBlob).
//
// Delegate authoring (publishEthosEditionV03Delegate) patches only the
// delegate's actor sphere via patchEditionV03Delegate and signs the §11 envelope
// with the delegate key + mandate (bare-multibase verificationMethod).

import type { StoredIdentity } from "./storage-types.js";
import { browserIdentityFromStored } from "./crypto/identity.js";
import type { DidDocument } from "./crypto/identity.js";
import type { Section } from "./crypto/manifest.js";
import { buildSignedEnvelope } from "./crypto/envelope.js";
import type { SignedMandate } from "./crypto/mandate.js";
import { readRpc } from "./api.js";
import { writeEndpoint } from "./endpoints.js";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, multibaseToEd25519PublicKey } from "./crypto/encoding.js";
import {
  delegateSectionReader,
  isV03Manifest,
  ownerSectionReader,
  readSection,
  readZoneIndex,
  type IndexRow,
  type ManifestV03,
  type SphereName,
} from "./crypto/bundle-v03.js";
import {
  authorBundleV03,
  ownerZoneKexPubkey,
  patchEditionV03Delegate,
  type DelegateAuthorV03,
} from "./crypto/bundle-v03-write.js";
import { fetchActiveDelegateGrants } from "./delegate-recipients.js";

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
  /** Decrypted sections per zone, for whatever this reader can open (public is
   *  always present; circle/self only for owner/recipient delegate). Always set
   *  by {@link loadEthosV03}; a zone may be an empty array when unreadable. */
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

/** A delegate reader's key material — decrypts only the sections (and index
 *  titles) it is a recipient of. The owner path takes `identity` instead. */
export interface DelegateReaderArgs {
  /** Grantee id from the mandate (e.g. `agent:gmail`). */
  readonly granteeId: string;
  /** The delegate's Ed25519 public key, multibase — the wrap recipient suffix. */
  readonly pubkeyMultibase: string;
  /** The delegate's Ed25519 seed (32 bytes). */
  readonly seed: Uint8Array;
}

/**
 * Load a v0.3 ethos: the manifest + per-zone index, and the decrypted sections
 * for whoever can read them — the OWNER (`identity`, reads every encrypted zone
 * with the sphere seeds) or a DELEGATE (`delegate`, reads only the sections
 * sealed to its key per §3.5.7′). Pass neither for an anonymous read — `public`
 * sections (plaintext) are still returned; `circle`/`self` come back empty with
 * their titles hidden. Sections are fetched per-section and decrypted locally;
 * non-decryptable sections are silently skipped, so a zone with descriptors but
 * an empty `sections[zone]` means "present but not readable for this reader".
 * Throws if the subject's edition is not v0.3.
 */
export async function loadEthosV03(
  did: string,
  identity?: StoredIdentity,
  delegate?: DelegateReaderArgs,
): Promise<EthosV03Snapshot> {
  const signed = await readRpc<{ object: ManifestV03 }>("aithos.get_ethos_manifest", { did });
  const manifest = signed.object;
  if (!isV03Manifest(manifest)) {
    const ver = (manifest as { aithos?: string }).aithos;
    throw new EditV03Error(
      "manifest",
      `subject ${did} is not on a v0.3 edition (aithos=${ver})`,
      { legacy: true, aithos: ver },
    );
  }
  const subjectDid = manifest.subject_did;
  const owner = identity && identity.did === did ? identity : undefined;

  const index = {} as Record<SphereName, IndexRow[]>;
  // Decrypted sections are built for every caller: public is plaintext (anyone),
  // circle/self need a reader (owner = all sections, delegate = only its sealed
  // ones, anonymous = none).
  const sections = {} as Record<SphereName, Section[]>;

  for (const zone of SPHERES) {
    const zm = manifest.zones[zone];
    if (!zm) {
      index[zone] = [];
      sections[zone] = [];
      continue;
    }
    // Public is plaintext (no reader). For circle/self pick the owner reader
    // (every section) or the delegate reader (only its sealed sections).
    const reader =
      zone === "public"
        ? undefined
        : owner
          ? ownerSectionReader(subjectDid, zone, hexToBytes(owner.seeds[zone]))
          : delegate
            ? delegateSectionReader(delegate.granteeId, delegate.pubkeyMultibase, delegate.seed)
            : undefined;
    index[zone] = readZoneIndex(zm, subjectDid, reader);

    // Only fetch+decrypt blobs we have a chance of reading: public is always
    // plaintext; circle/self need a reader (anonymous skips them entirely).
    const list: Section[] = [];
    if (zone === "public" || reader) {
      for (const desc of zm.sections) {
        const blob = await fetchSectionBlob(did, desc.section_id);
        const res = readSection(zm, desc, blob, subjectDid, reader);
        if (res.accessible && res.section) list.push(res.section);
      }
    }
    sections[zone] = list;
  }

  return { manifest, index, sections };
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
  //
  // Accept ANY prevManifest, not just v0.3: a v0.2 (monolithic) manifest is a
  // valid predecessor for the owner migration (§1) — it carries bundle_id and
  // edition.height, so the new edition links at height+1 with the correct
  // prev_hash. Its v1 zones have no per-section `.sections`, so `?.sections ?? []`
  // yields an empty prefetch (nothing to carry forward → every section is
  // re-encrypted fresh, which is exactly what a migration wants).
  let prev: { manifest: ManifestV03; getBlob: (file: string) => Uint8Array } | undefined;
  if (args.prevManifest) {
    const blobMap = new Map<string, Uint8Array>();
    for (const zone of SPHERES) {
      for (const desc of args.prevManifest.zones[zone]?.sections ?? []) {
        // Content-addressed sections are carried forward by sha (omitted) or
        // re-encrypted fresh — either way their prior blob is never re-uploaded,
        // so skip the pre-fetch. Only legacy (no blob_sha) predecessors need it.
        if (desc.blob_sha) continue;
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

  // Active delegate grants → per-section recipients (§3.5.7′): each section is
  // sealed to the subject plus every delegate whose read-bearing scopes cover
  // it. Best-effort: a grant we can't resolve is skipped (surfaced in errors),
  // never blocking the owner's own publish.
  const grants = await fetchActiveDelegateGrants(did);
  const { manifest, blobs } = authorBundleV03({
    identity: browserId,
    subjectDid: did,
    subjectHandle: handle,
    displayName: displayName ?? handle,
    didJson,
    zones,
    delegateGrants: { circle: grants.circle, self: grants.self },
    ...(prev ? { prev } : {}),
  });

  // Per-section blobs → the publish input shape. `blobs` is keyed by blob_sha
  // (delta upload): one entry per CHANGED/new section; carried-forward sections
  // are omitted and reused server-side from blobs/{blob_sha}.
  const blobsParam: Record<string, { bytes_base64: string }> = {};
  for (const [sha, bytes] of blobs) {
    blobsParam[sha] = { bytes_base64: bytesToBase64(bytes) };
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
/*  Publish (delegate, section-scoped)                                        */
/* -------------------------------------------------------------------------- */

export interface PublishV03DelegateArgs {
  /** The delegate authoring this edition (agent key + mandate id + actor sphere). */
  readonly delegate: DelegateAuthorV03;
  /** The full signed mandate authorising the write — attached to the §11 envelope. */
  readonly mandate: SignedMandate;
  /** Predecessor edition: a delegate always patches an existing v0.3 edition. */
  readonly prevManifest: ManifestV03;
  /** Changes to the delegate's actor sphere (upserts provide full sections). */
  readonly patch: { readonly upserts?: readonly Section[]; readonly deletes?: readonly string[] };
}

/**
 * Author + publish a new v0.3 edition AS A DELEGATE. Mirrors
 * {@link publishEthosEditionV03Owner}, but: (1) patches ONLY the delegate's
 * `actorSphere` and carries every other zone forward verbatim (the delegate
 * isn't entitled to read them), and (2) signs the §11 envelope with the delegate
 * key + mandate (bare-multibase `verificationMethod`) instead of an owner sphere.
 *
 * Subject identity (did/handle/display name) comes from `prevManifest` — a
 * delegate never mints a first edition.
 */
export async function publishEthosEditionV03Delegate(
  args: PublishV03DelegateArgs,
): Promise<PublishV03Result> {
  const { delegate, prevManifest } = args;
  if (!isV03Manifest(prevManifest)) {
    throw new EditV03Error("manifest", "v0.3 predecessor required for delegate authoring");
  }
  const did = prevManifest.subject_did;
  const handle = prevManifest.subject_handle;
  const displayName = prevManifest.display_name ?? handle;

  // did.json (exact server byte-shape) anchors the manifest; the DID document
  // also yields the subject's `#${zone}-kex` pubkey the delegate seals into.
  const idResp = await readRpc<{ object: DidDocument }>("aithos.get_identity", { did });
  const didDoc = idResp.object;
  const didJson = new TextEncoder().encode(JSON.stringify(didDoc, null, 2) + "\n");
  const ownerZonePubkey = ownerZoneKexPubkey(didDoc, did, delegate.actorSphere);

  // Carry-forward: patchEditionV03Delegate copies every zone the delegate can't
  // read VERBATIM. With content-addressing it carries those by blob_sha (the
  // server reuses the stored object), so the delegate no longer needs to
  // pre-download opaque blobs of sections it can't read — only legacy (no
  // blob_sha) predecessors still require a pre-fetch.
  const blobMap = new Map<string, Uint8Array>();
  for (const zone of SPHERES) {
    for (const desc of prevManifest.zones[zone]?.sections ?? []) {
      if (desc.blob_sha) continue;
      blobMap.set(desc.file, await fetchSectionBlob(did, desc.section_id));
    }
  }

  const { manifest, blobs } = patchEditionV03Delegate({
    delegate,
    subjectDid: did,
    subjectHandle: handle,
    displayName: displayName ?? handle,
    didJson,
    ownerZonePubkey,
    prev: {
      manifest: prevManifest,
      getBlob: (file) => {
        const b = blobMap.get(file);
        if (!b) throw new EditV03Error("carry-forward", `prior blob not pre-fetched: ${file}`);
        return b;
      },
    },
    patch: args.patch,
  });

  // Per-section blobs → the publish input shape. `blobs` is keyed by blob_sha
  // (delta upload): one entry per CHANGED/new section; carried-forward sections
  // are omitted and reused server-side from blobs/{blob_sha}.
  const blobsParam: Record<string, { bytes_base64: string }> = {};
  for (const [sha, bytes] of blobs) {
    blobsParam[sha] = { bytes_base64: bytesToBase64(bytes) };
  }

  const params = { manifest, blobs: blobsParam };
  const envelope = buildSignedEnvelope({
    iss: did,
    aud: writeEndpoint(),
    method: "aithos.publish_ethos_edition",
    // Bare multibase verificationMethod + attached mandate = the delegate path.
    verificationMethod: delegate.pubkeyMultibase,
    signer: {
      seed: delegate.seed,
      publicKey: multibaseToEd25519PublicKey(delegate.pubkeyMultibase),
    },
    mandate: args.mandate,
    params,
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
