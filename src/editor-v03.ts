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
import { buildSignedEnvelope, type SignedEnvelope } from "./crypto/envelope.js";
import type { SignedMandate } from "./crypto/mandate.js";
import { readRpc } from "./api.js";
import { readEndpoint, writeEndpoint } from "./endpoints.js";
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
  patchEditionV03Owner,
  type DelegateAuthorV03,
} from "./crypto/bundle-v03-write.js";
import {
  fetchActiveDelegateGrants,
  mandateToGrant,
  type DelegateGrantWithScopes,
} from "./delegate-recipients.js";
import { DEFAULT_RPC_CONCURRENCY, mapLimit } from "./concurrency.js";
import { cachedIdentityDoc } from "./perf-cache.js";

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

/** Fetch one section blob by id (base64 → bytes) via get_ethos_section. When
 *  `auth` is provided (encrypted zones), the request carries a signed §11
 *  envelope so the server can authorize + revocation-check the read; public
 *  reads pass no auth and stay anonymous. */
async function fetchSectionBlob(
  did: string,
  sectionId: string,
  auth?: ReadAuth,
): Promise<Uint8Array> {
  const params = { did, section_id: sectionId };
  const signed = await readRpc<{ object: { bytes_base64: string } }>(
    "aithos.get_ethos_section",
    auth ? { ...params, _envelope: auth("aithos.get_ethos_section", params) } : params,
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
  /** The signed mandate, attached to the §11 read envelope so the server can
   *  authorize + revocation-check the delegate's encrypted-zone reads. Without
   *  it, encrypted reads fall back to anonymous (public-only). */
  readonly mandate?: SignedMandate;
}

/** A read-envelope signer: builds a signed §11 envelope for an encrypted-zone
 *  read RPC. Public reads pass no auth and stay anonymous. */
export type ReadAuth = (method: string, params: unknown) => SignedEnvelope;

/** Owner read-auth: signs with the subject's `#public` sphere key, which
 *  authorizes reading ANY of the subject's own zones (the server only checks
 *  iss === subject for a non-delegate envelope). */
function ownerReadAuth(
  subjectDid: string,
  browserId: ReturnType<typeof browserIdentityFromStored>,
): ReadAuth {
  return (method, params) =>
    buildSignedEnvelope({
      iss: subjectDid,
      aud: readEndpoint(),
      method,
      verificationMethod: `${subjectDid}#public`,
      params,
      signer: browserId.public,
    });
}

/** Delegate read-auth: signs with the delegate key and attaches its mandate; the
 *  server scope-checks the mandate per section and rejects it if revoked. */
function delegateReadAuth(
  subjectDid: string,
  seed: Uint8Array,
  pubkeyMultibase: string,
  mandate: SignedMandate,
): ReadAuth {
  const signer = { seed, publicKey: multibaseToEd25519PublicKey(pubkeyMultibase) };
  return (method, params) =>
    buildSignedEnvelope({
      iss: subjectDid,
      aud: readEndpoint(),
      method,
      verificationMethod: pubkeyMultibase,
      signer,
      mandate,
      params,
    });
}

/** Pick the read-auth for the current reader: owner (sphere key) or delegate
 *  (mandate). Returns undefined for an anonymous reader → encrypted reads stay
 *  public-only. */
function readAuthFor(
  subjectDid: string,
  owner: StoredIdentity | undefined,
  delegate: DelegateReaderArgs | undefined,
): ReadAuth | undefined {
  if (owner) return ownerReadAuth(subjectDid, browserIdentityFromStored(owner));
  if (delegate?.mandate) {
    return delegateReadAuth(subjectDid, delegate.seed, delegate.pubkeyMultibase, delegate.mandate);
  }
  return undefined;
}

/** The section reader for a zone: `public` → none (plaintext); `circle`/`self`
 *  → the owner's sphere reader (every section) or the delegate's reader (only
 *  the sections sealed to it). Shared by the index, section, and full loaders. */
function sectionReaderForZone(
  zone: SphereName,
  subjectDid: string,
  owner: StoredIdentity | undefined,
  delegate: DelegateReaderArgs | undefined,
): Parameters<typeof readSection>[4] {
  if (zone === "public") return undefined;
  if (owner) return ownerSectionReader(subjectDid, zone, hexToBytes(owner.seeds[zone]));
  if (delegate) return delegateSectionReader(delegate.granteeId, delegate.pubkeyMultibase, delegate.seed);
  return undefined;
}

/** Fetch the subject's did.json (`get_identity`). Memoized through the opt-in
 *  perf cache (TTL configured by the host; passthrough by default) — the doc
 *  changes only on key rotation / sphere augmentation, yet every publish needs
 *  its exact byte-shape to anchor `sha256_of_did_json`. */
function fetchIdentityDocV03(did: string): Promise<DidDocument> {
  return cachedIdentityDoc(did, async () => {
    const idResp = await readRpc<{ object: DidDocument }>("aithos.get_identity", { did });
    return idResp.object;
  });
}

/**
 * Pre-fetch the prior blobs a carry-forward needs (the author fns take a SYNC
 * getBlob). Only LEGACY descriptors (no `blob_sha`) require it — content-
 * addressed sections are carried by sha (omitted) or re-encrypted fresh, so
 * their prior blob is never re-uploaded. Fetches run with bounded concurrency
 * instead of one-by-one: a first publish over a large pre-content-addressed
 * ethos was previously M sequential round-trips.
 */
async function prefetchLegacyBlobs(
  did: string,
  prevManifest: ManifestV03,
  readAuth: ReadAuth | undefined,
): Promise<Map<string, Uint8Array>> {
  const targets: { file: string; sectionId: string; zone: SphereName }[] = [];
  for (const zone of SPHERES) {
    for (const desc of prevManifest.zones[zone]?.sections ?? []) {
      if (desc.blob_sha) continue;
      targets.push({ file: desc.file, sectionId: desc.section_id, zone });
    }
  }
  const blobMap = new Map<string, Uint8Array>();
  const bytes = await mapLimit(targets, DEFAULT_RPC_CONCURRENCY, (t) =>
    fetchSectionBlob(did, t.sectionId, t.zone === "public" ? undefined : readAuth),
  );
  targets.forEach((t, i) => blobMap.set(t.file, bytes[i]!));
  return blobMap;
}

/** Merge in-hand mandates (freshly minted, not yet visible in `list_mandates`)
 *  into fetched grants — deduped by wrap recipient, extras win. */
function mergeExtraGrants(
  grants: { circle: readonly DelegateGrantWithScopes[]; self: readonly DelegateGrantWithScopes[] },
  extras: readonly SignedMandate[] | undefined,
): { circle: readonly DelegateGrantWithScopes[]; self: readonly DelegateGrantWithScopes[] } {
  if (!extras || extras.length === 0) return grants;
  const out = { circle: [...grants.circle], self: [...grants.self] };
  for (const mandate of extras) {
    const g = mandateToGrant(mandate);
    for (const zone of ["circle", "self"] as const) {
      const grant = g[zone];
      if (!grant) continue;
      const i = out[zone].findIndex((x) => x.recipient.didUrl === grant.recipient.didUrl);
      if (i >= 0) out[zone][i] = grant;
      else out[zone].push(grant);
    }
  }
  return out;
}

/** Fetch the v0.3 manifest, throwing the legacy-v0.2 signal when the subject's
 *  current edition isn't v0.3 (same error {@link loadEthosV03} raises). */
async function fetchManifestV03(did: string): Promise<ManifestV03> {
  const signed = await readRpc<{ object: ManifestV03 }>("aithos.get_ethos_manifest", { did });
  const manifest = signed.object;
  if (!isV03Manifest(manifest)) {
    const ver = (manifest as { aithos?: string }).aithos;
    throw new EditV03Error("manifest", `subject ${did} is not on a v0.3 edition (aithos=${ver})`, {
      legacy: true,
      aithos: ver,
    });
  }
  return manifest;
}

/**
 * Load ONLY the manifest + per-zone index (section titles + capability flags) —
 * the lightweight half of {@link loadEthosV03}. NO section bodies are fetched or
 * decrypted, so the cost is one network round-trip regardless of how many
 * sections the zones hold. Pair with {@link loadSectionV03} to read bodies on
 * demand (the point of content-addressing: never load everything up front).
 */
export async function loadEthosIndexV03(
  did: string,
  identity?: StoredIdentity,
  delegate?: DelegateReaderArgs,
): Promise<{ manifest: ManifestV03; index: Record<SphereName, IndexRow[]> }> {
  const manifest = await fetchManifestV03(did);
  return { manifest, index: zoneIndexFromManifest(manifest, identity, delegate) };
}

/**
 * Build the per-zone index (section titles + flags) from an IN-HAND manifest —
 * the pure, zero-network half of {@link loadEthosIndexV03}. Local crypto only
 * (self titles are unsealed with the owner/delegate key when available). Lets a
 * caller that just PUBLISHED an edition reconstruct the fresh index from the
 * manifest it authored instead of re-fetching it.
 */
export function zoneIndexFromManifest(
  manifest: ManifestV03,
  identity?: StoredIdentity,
  delegate?: DelegateReaderArgs,
): Record<SphereName, IndexRow[]> {
  const subjectDid = manifest.subject_did;
  const owner = identity && identity.did === subjectDid ? identity : undefined;
  const index = {} as Record<SphereName, IndexRow[]>;
  for (const zone of SPHERES) {
    const zm = manifest.zones[zone];
    index[zone] = zm
      ? readZoneIndex(zm, subjectDid, sectionReaderForZone(zone, subjectDid, owner, delegate))
      : [];
  }
  return index;
}

/**
 * Read + decrypt ONE section on demand, using a manifest already obtained from
 * {@link loadEthosIndexV03} (so no manifest refetch). Returns `null` when the
 * section is absent from the manifest or this reader can't decrypt it (`public`
 * is always returned). One `get_ethos_section` round-trip; the server resolves
 * the descriptor's `blob_sha` to the deduplicated blob.
 */
export async function loadSectionV03(
  manifest: ManifestV03,
  zone: SphereName,
  sectionId: string,
  identity?: StoredIdentity,
  delegate?: DelegateReaderArgs,
): Promise<Section | null> {
  const zm = manifest.zones[zone];
  const desc = zm?.sections.find((s) => s.section_id === sectionId);
  if (!zm || !desc) return null;
  const subjectDid = manifest.subject_did;
  const owner = identity && identity.did === subjectDid ? identity : undefined;
  const reader = sectionReaderForZone(zone, subjectDid, owner, delegate);
  if (zone !== "public" && !reader) return null;
  const auth = zone === "public" ? undefined : readAuthFor(subjectDid, owner, delegate);
  const blob = await fetchSectionBlob(subjectDid, sectionId, auth);
  const res = readSection(zm, desc, blob, subjectDid, reader);
  return res.accessible && res.section ? res.section : null;
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
 *
 * Eager: fetches+decrypts every readable section. For a lazy UI, prefer
 * {@link loadEthosIndexV03} + {@link loadSectionV03}.
 */
export async function loadEthosV03(
  did: string,
  identity?: StoredIdentity,
  delegate?: DelegateReaderArgs,
): Promise<EthosV03Snapshot> {
  const { manifest, index } = await loadEthosIndexV03(did, identity, delegate);
  const subjectDid = manifest.subject_did;
  const owner = identity && identity.did === did ? identity : undefined;
  const sections = {} as Record<SphereName, Section[]>;
  const readAuth = readAuthFor(subjectDid, owner, delegate);

  // Fan the per-section fetches out with bounded concurrency instead of one
  // sequential await per section (the old N+1: 1 + N round-trips). Zones run
  // in parallel too; document order is preserved because results are mapped
  // back by index. Decryption stays local + sequential (cheap).
  await Promise.all(
    SPHERES.map(async (zone) => {
      const zm = manifest.zones[zone];
      const reader = zm ? sectionReaderForZone(zone, subjectDid, owner, delegate) : undefined;
      const list: Section[] = [];
      if (zm && (zone === "public" || reader)) {
        const auth = zone === "public" ? undefined : readAuth;
        const blobs = await mapLimit(zm.sections, DEFAULT_RPC_CONCURRENCY, (desc) =>
          fetchSectionBlob(did, desc.section_id, auth),
        );
        zm.sections.forEach((desc, i) => {
          const res = readSection(zm, desc, blobs[i]!, subjectDid, reader);
          if (res.accessible && res.section) list.push(res.section);
        });
      }
      sections[zone] = list;
    }),
  );
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
  /**
   * DELTA path (preferred for edits): a per-zone patch of only the changed
   * sections. When present together with `prevManifest`, the edition is authored
   * via {@link patchEditionV03Owner} — untouched sections carry forward by
   * descriptor without ever being read or decrypted, so a single-section edit
   * uploads one blob AND reads ~no other sections. Mutually exclusive in spirit
   * with the `*Sections` fields (those drive the full re-author used for the
   * first edition and v0.2 migration).
   */
  readonly patch?: Partial<
    Record<SphereName, { readonly upserts?: readonly Section[]; readonly deletes?: readonly string[] }>
  >;
  /** Decrypted tags for carried `self` sections, so the author can evaluate
   *  `#tag=` grants when deciding whether a carried section needs a reseal. */
  readonly carriedSelfTags?: ReadonlyMap<string, readonly string[]>;
  /** Pulls a carried section's plaintext on demand — invoked by the delta author
   *  ONLY for a section whose recipient set changed and must be re-encrypted. */
  readonly fetchBody?: (zone: SphereName, sectionId: string) => Promise<Section>;
  /** subject_handle / display_name — defaults from prevManifest when present. */
  readonly handle?: string;
  readonly displayName?: string;
  /**
   * In-hand mandates to seal IN ADDITION to the server-listed active grants —
   * typically the mandate minted milliseconds ago, which `list_mandates`
   * (eventually-consistent index) may not surface yet. Merged over the fetched
   * grants (deduped by wrap recipient), which makes "mint → immediately
   * reseal" deterministic instead of racing the index settle.
   */
  readonly extraGrantMandates?: readonly SignedMandate[];
  /**
   * Recipient policy for CARRIED sections (see OwnerPatchArgs.resealMode):
   * `"additive"` (default) never removes a recipient — revoked residue stays,
   * new grants are appended cheaply; `"rotate"` re-encrypts shrunken sections
   * (the explicit "Rotate keys" hard-cut, requires `fetchBody`).
   */
  readonly resealMode?: "additive" | "rotate";
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

  // The three pre-publish lookups are independent — run them CONCURRENTLY
  // instead of one after the other (each was a full round-trip):
  //
  //   1. did.json (exact server byte-shape) → its sha256 anchors the manifest.
  //      Memoized via the opt-in identity cache.
  //   2. Legacy-blob pre-fetch for carry-forward (authorBundleV03 takes a SYNC
  //      getBlob). Accept ANY prevManifest, not just v0.3: a v0.2 (monolithic)
  //      manifest is a valid predecessor for the owner migration (§1) — it
  //      carries bundle_id and edition.height, so the new edition links at
  //      height+1 with the correct prev_hash. Its v1 zones have no per-section
  //      `.sections`, so the prefetch is empty (nothing to carry forward →
  //      every section is re-encrypted fresh, exactly what a migration wants).
  //   3. Active delegate grants → per-section recipients (§3.5.7′): each
  //      section is sealed to the subject plus every delegate whose
  //      read-bearing scopes cover it. Best-effort: a grant we can't resolve
  //      is skipped (surfaced in errors), never blocking the owner's publish.
  const [didDoc, blobMap, fetchedGrants] = await Promise.all([
    fetchIdentityDocV03(did),
    args.prevManifest
      ? prefetchLegacyBlobs(did, args.prevManifest, ownerReadAuth(did, browserId))
      : Promise.resolve(new Map<string, Uint8Array>()),
    fetchActiveDelegateGrants(did),
  ]);
  const didJson = new TextEncoder().encode(JSON.stringify(didDoc, null, 2) + "\n");

  let prev: { manifest: ManifestV03; getBlob: (file: string) => Uint8Array } | undefined;
  if (args.prevManifest) {
    prev = {
      manifest: args.prevManifest,
      getBlob: (file) => {
        const b = blobMap.get(file);
        if (!b) throw new EditV03Error("carry-forward", `prior blob not pre-fetched: ${file}`);
        return b;
      },
    };
  }

  // Freshly-minted mandates the index may not list yet seal in deterministically.
  const grants = mergeExtraGrants(
    { circle: fetchedGrants.circle, self: fetchedGrants.self },
    args.extraGrantMandates,
  );
  const { manifest, blobs } =
    args.patch && prev
      ? // DELTA: author from the patch, carrying untouched sections forward by
        // descriptor (no plaintext) and resealing only what the grants changed.
        await patchEditionV03Owner({
          identity: browserId,
          subjectDid: did,
          subjectHandle: handle,
          displayName: displayName ?? handle,
          didJson,
          delegateGrants: { circle: grants.circle, self: grants.self },
          prev,
          patch: args.patch,
          ...(args.carriedSelfTags ? { carriedSelfTags: args.carriedSelfTags } : {}),
          ...(args.fetchBody ? { fetchBody: args.fetchBody } : {}),
          ...(args.resealMode ? { resealMode: args.resealMode } : {}),
        })
      : // FULL: re-author every zone from the supplied section lists (first
        // edition, v0.2 migration, or an explicit whole-bundle replace).
        authorBundleV03({
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

  // Two independent pre-publish lookups, run CONCURRENTLY:
  //
  //   1. did.json (exact server byte-shape) anchors the manifest; the DID
  //      document also yields the subject's `#${zone}-kex` pubkey the delegate
  //      seals into. Memoized via the opt-in identity cache.
  //   2. Carry-forward: patchEditionV03Delegate copies every zone the delegate
  //      can't read VERBATIM. With content-addressing it carries those by
  //      blob_sha (the server reuses the stored object), so the delegate no
  //      longer pre-downloads opaque blobs of sections it can't read — only
  //      legacy (no blob_sha) predecessors still require a (bounded-parallel)
  //      pre-fetch.
  const readAuth = delegateReadAuth(did, delegate.seed, delegate.pubkeyMultibase, args.mandate);
  const [didDoc, blobMap] = await Promise.all([
    fetchIdentityDocV03(did),
    prefetchLegacyBlobs(did, prevManifest, readAuth),
  ]);
  const didJson = new TextEncoder().encode(JSON.stringify(didDoc, null, 2) + "\n");
  const ownerZonePubkey = ownerZoneKexPubkey(didDoc, did, delegate.actorSphere);

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
