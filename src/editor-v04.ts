// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// v0.4 incremental editor — read / owner write / migration / delegate write.
// Spec: Aithos-protocol/spec/drafts/bundle-v0.4-incremental-manifest-and-zone-keys.md
// (Partie II). Transport mirrors editor-v03: signed §11 envelopes, batch object
// reads (aithos.get_ethos_objects), per-section blob reads (unchanged RPC),
// ONE publish POST carrying { manifest, objects, blobs } — objects/blobs are
// the CHANGED ones only (everything else carries by sha, server-validated).

import { randomBytes } from "@noble/ciphers/webcrypto";

import {
  buildManifestV04,
  shardIndexForSection,
  type ManifestV04,
  type ShardEntryV04,
  type ZoneRefV04,
  type ZoneShardV04,
} from "@aithos/protocol-core/bundle-v04";

import type { StoredIdentity } from "./storage-types.js";
import { browserIdentityFromStored } from "./crypto/identity.js";
import type { DidDocument } from "./crypto/identity.js";
import { buildSignedEnvelope } from "./crypto/envelope.js";
import type { SignedMandate } from "./crypto/mandate.js";
import { readRpc } from "./api.js";
import { readEndpoint, writeEndpoint } from "./endpoints.js";
import { bytesToHex, bytesToB64, b64ToBytes, multibaseToEd25519PublicKey } from "./crypto/encoding.js";
import { edPubToX25519Pub, edSeedToX25519Secret } from "./crypto/kex.js";
import {
  parseSectionMarkdown,
  titleAad,
  type ManifestV03,
  type SphereName,
} from "./crypto/bundle-v03.js";
import {
  canonicalManifestV03HashHex,
  ownerZoneKexPubkey,
  renderSectionMarkdown,
} from "./crypto/bundle-v03-write.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";
import {
  readAuthFor,
  fetchSectionBlob,
  type DelegateReaderArgs,
  type ReadAuth,
  EditV03Error,
} from "./editor-v03.js";
import type { Section } from "./crypto/manifest.js";
import {
  buildShards,
  decryptBodyV04,
  decryptTitleV2pc,
  encryptBodyV04,
  encryptTitleV2pc,
  entriesFromShards,
  generateZoneKey,
  manifestHashHexV04Pc,
  objectBytes,
  objectSha,
  openDekUnderZoneKey,
  openZoneKey,
  ownerKexLabel,
  ownerKexSecret,
  sealDekUnderZoneKey,
  sealZoneKeyTo,
  signManifestV04Pc,
  type ExtraWrapsV04Pc,
  type KeyRingV04Pc,
  type ZoneKeyPc,
} from "./crypto/bundle-v04.js";
import { sha256 } from "@noble/hashes/sha2";
import type { WrapEntry } from "./crypto/decrypt.js";
import { unwrapDek, } from "./crypto/decrypt.js";
import { wrapDek } from "./crypto/encrypt.js";

const SPHERES: readonly SphereName[] = ["public", "circle", "self"];
const ENC_ZONES = ["circle", "self"] as const;

export function isV04Manifest(m: unknown): m is ManifestV04 {
  return !!m && (m as { aithos?: string }).aithos === "0.4.0";
}

/** Fetch the subject's did.json (uncached — tiny, and the fence path that
 *  needs it is rare). */
export async function fetchDidDocAny(did: string): Promise<DidDocument> {
  const res = await readRpc<{ object: DidDocument }>("aithos.get_identity", { did });
  return res.object;
}

/** Fetch the subject's CURRENT manifest, whatever its format — the version
 *  probe every dual-format client needs before picking a loader. */
export async function fetchManifestAny(
  did: string,
): Promise<{ aithos?: string } & Record<string, unknown>> {
  const res = await readRpc<{ object: { aithos?: string } & Record<string, unknown> }>(
    "aithos.get_ethos_manifest",
    { did },
  );
  return res.object;
}

/* -------------------------------------------------------------------------- */
/*  Object fetch (batch ≤64)                                                  */
/* -------------------------------------------------------------------------- */

async function fetchObjects(
  did: string,
  shas: readonly string[],
  auth?: ReadAuth,
): Promise<Map<string, unknown>> {
  const out = new Map<string, unknown>();
  for (let i = 0; i < shas.length; i += 64) {
    const chunk = shas.slice(i, i + 64);
    const params = { did, shas: chunk };
    const res = await readRpc<{ objects: Array<{ sha: string; bytes_base64: string }>; missing: string[] }>(
      "aithos.get_ethos_objects",
      auth ? { ...params, _envelope: auth("aithos.get_ethos_objects", params) } : params,
    );
    for (const o of res.objects) {
      out.set(o.sha, JSON.parse(new TextDecoder().decode(b64ToBytes(o.bytes_base64))));
    }
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/*  Snapshot + index                                                          */
/* -------------------------------------------------------------------------- */

export interface IndexRowV04 {
  readonly section_id: string;
  readonly title?: string;
  readonly tags?: string[];
  readonly title_hidden: boolean;
  readonly gamma_ref: string;
  readonly readable: boolean;
  readonly approx_size_bytes?: number;
}

export interface EthosV04Snapshot {
  readonly manifest: ManifestV04;
  readonly shards: Record<SphereName, ZoneShardV04[]>;
  readonly keyrings: Partial<Record<SphereName, KeyRingV04Pc>>;
  readonly extrawraps: Partial<Record<SphereName, ExtraWrapsV04Pc>>;
  /** Zone keys this reader could open (owner: all; delegate: granted zones). */
  readonly zoneKeys: Partial<Record<SphereName, ZoneKeyPc>>;
  readonly index: Record<SphereName, IndexRowV04[]>;
}

function readerLabel(owner: StoredIdentity | undefined, delegate: DelegateReaderArgs | undefined, did: string, zone: SphereName): string | null {
  if (owner) return ownerKexLabel(did, zone);
  if (delegate) return `${delegate.granteeId}#${delegate.pubkeyMultibase}`;
  return null;
}

function readerKexSecret(owner: StoredIdentity | undefined, delegate: DelegateReaderArgs | undefined, zone: "circle" | "self"): Uint8Array | null {
  if (owner) return ownerKexSecret(owner, zone);
  if (delegate) return edSeedToX25519Secret(delegate.seed);
  return null;
}

/** Load manifest objects + open what this reader can. ONE object batch. */
export async function loadEthosIndexV04(
  did: string,
  manifest: ManifestV04,
  owner?: StoredIdentity,
  delegate?: DelegateReaderArgs,
): Promise<EthosV04Snapshot> {
  const auth = readAuthFor(did, owner, delegate);
  const shas: string[] = [];
  for (const z of SPHERES) {
    const ref = manifest.zones[z];
    if (!ref) continue;
    shas.push(...ref.shard_shas);
    if (auth && ref.keyring_sha) shas.push(ref.keyring_sha);
    if (auth && ref.extrawraps_sha) shas.push(ref.extrawraps_sha);
  }
  const objs = await fetchObjects(did, shas, auth);

  const shards = { public: [], circle: [], self: [] } as Record<SphereName, ZoneShardV04[]>;
  const keyrings: Partial<Record<SphereName, KeyRingV04Pc>> = {};
  const extrawraps: Partial<Record<SphereName, ExtraWrapsV04Pc>> = {};
  const zoneKeys: Partial<Record<SphereName, ZoneKeyPc>> = {};

  for (const z of SPHERES) {
    const ref = manifest.zones[z];
    if (!ref) continue;
    shards[z] = ref.shard_shas.map((sha) => (objs.get(sha) ?? { object: "zone_shard", v: 1, zone: z, entries: [] }) as ZoneShardV04);
    if (ref.keyring_sha && objs.has(ref.keyring_sha)) keyrings[z] = objs.get(ref.keyring_sha) as KeyRingV04Pc;
    if (ref.extrawraps_sha && objs.has(ref.extrawraps_sha)) extrawraps[z] = objs.get(ref.extrawraps_sha) as ExtraWrapsV04Pc;
  }

  for (const z of ENC_ZONES) {
    const kr = keyrings[z];
    const label = readerLabel(owner, delegate, did, z);
    const sk = readerKexSecret(owner, delegate, z);
    if (!kr || !label || !sk) continue;
    const entry = kr.wraps.find((w) => w.recipient === label);
    if (!entry) continue;
    try {
      zoneKeys[z] = openZoneKey(entry, sk);
    } catch {
      /* wrong key material — treated as no zone access */
    }
  }

  const index = { public: [], circle: [], self: [] } as Record<SphereName, IndexRowV04[]>;
  for (const z of SPHERES) {
    const ew = extrawraps[z];
    const myLabel = readerLabel(owner, delegate, did, z);
    for (const sh of shards[z]) {
      for (const e of sh.entries) {
        const viaZoneKey = z !== "public" && !!zoneKeys[z] && !!e.enc_dek;
        const viaExtra = !!ew && !!myLabel && !!ew.entries.find((x) => x.section_id === e.section_id)?.wraps.some((w) => w.recipient === myLabel);
        const readable = z === "public" || !!owner ? true : viaZoneKey || viaExtra;
        let title = e.title;
        let tags = e.tags;
        let hidden = z === "self";
        if (z === "self" && e.title_cipher && readable) {
          try {
            const dek = sectionDek(did, z, e, zoneKeys[z], ew, myLabel, owner, delegate);
            if (dek) {
              const t = decryptTitleV2pc(dek, did, e.section_id, e.title_cipher);
              title = t.title;
              tags = t.tags;
              hidden = false;
            }
          } catch {
            /* keep hidden */
          }
        }
        index[z].push({
          section_id: e.section_id,
          ...(title !== undefined ? { title } : {}),
          ...(tags ? { tags } : {}),
          title_hidden: hidden,
          gamma_ref: e.gamma_ref,
          readable,
          ...(e.approx_size_bytes !== undefined ? { approx_size_bytes: e.approx_size_bytes } : {}),
        });
      }
    }
    index[z].sort((a, b) => (a.section_id < b.section_id ? -1 : 1));
  }

  return { manifest, shards, keyrings, extrawraps, zoneKeys, index };
}

/** Resolve a section's DEK for this reader, or null. */
function sectionDek(
  did: string,
  zone: SphereName,
  e: ShardEntryV04,
  zk: ZoneKeyPc | undefined,
  ew: ExtraWrapsV04Pc | undefined,
  myLabel: string | null,
  owner?: StoredIdentity,
  delegate?: DelegateReaderArgs,
): Uint8Array | null {
  if (zone === "public") return null;
  if (zk && e.enc_dek && e.enc_dek.kid === zk.kid) {
    try {
      return openDekUnderZoneKey(zk.key, e.enc_dek, did, zone, e.section_id);
    } catch {
      /* fall through to extrawraps */
    }
  }
  if (ew && myLabel) {
    const wrap = ew.entries.find((x) => x.section_id === e.section_id)?.wraps.find((w) => w.recipient === myLabel);
    const sk = readerKexSecret(owner, delegate, zone as "circle" | "self");
    if (wrap && sk) {
      try {
        return unwrapDek(wrap.wrap, sk);
      } catch {
        return null;
      }
    }
  }
  return null;
}

/** Read + decrypt ONE section from a loaded snapshot (blob fetched on demand). */
export async function loadSectionV04(
  did: string,
  snap: EthosV04Snapshot,
  zone: SphereName,
  sectionId: string,
  owner?: StoredIdentity,
  delegate?: DelegateReaderArgs,
): Promise<Section | null> {
  const e = entriesFromShards(snap.shards[zone]).get(sectionId);
  if (!e) return null;
  const auth = readAuthFor(did, owner, delegate);
  if (zone === "public") {
    const blob = await fetchSectionBlob(did, sectionId, auth);
    const parsed = parseSectionMarkdown(new TextDecoder().decode(blob));
    return { id: sectionId, gamma_ref: e.gamma_ref, ...parsed };
  }
  const myLabel = readerLabel(owner, delegate, did, zone);
  const dek = sectionDek(did, zone, e, snap.zoneKeys[zone], snap.extrawraps[zone], myLabel, owner, delegate);
  if (!dek || !e.n) return null;
  const blob = await fetchSectionBlob(did, sectionId, auth);
  const md = new TextDecoder().decode(decryptBodyV04(dek, e.n, did, sectionId, blob));
  const parsed = parseSectionMarkdown(md);
  return { id: sectionId, gamma_ref: e.gamma_ref, ...parsed };
}

/* -------------------------------------------------------------------------- */
/*  Publish plumbing (shared)                                                 */
/* -------------------------------------------------------------------------- */

interface UploadSet {
  objects: Map<string, Uint8Array>; // sha -> canonical bytes
  blobs: Map<string, Uint8Array>; // sha -> ciphertext/plaintext bytes
}

function addObject(up: UploadSet, obj: unknown): string {
  const bytes = objectBytes(obj);
  const sha = bytesToHex(sha256(bytes));
  up.objects.set(sha, bytes);
  return sha;
}

async function postPublishV04(
  did: string,
  manifest: ManifestV04,
  up: UploadSet,
  signer:
    | { kind: "owner"; owner: StoredIdentity }
    | { kind: "delegate"; seed: Uint8Array; pubkeyMultibase: string; mandate: SignedMandate },
): Promise<{ height: number }> {
  const objectsParam: Record<string, { bytes_base64: string }> = {};
  for (const [sha, bytes] of up.objects) objectsParam[sha] = { bytes_base64: bytesToB64(bytes) };
  const blobsParam: Record<string, { bytes_base64: string }> = {};
  for (const [sha, bytes] of up.blobs) blobsParam[sha] = { bytes_base64: bytesToB64(bytes) };

  const params = { manifest, objects: objectsParam, blobs: blobsParam };
  const envelope =
    signer.kind === "owner"
      ? buildSignedEnvelope({
          iss: did,
          aud: writeEndpoint(),
          method: "aithos.publish_ethos_edition",
          verificationMethod: `${did}#public`,
          params,
          signer: browserIdentityFromStored(signer.owner).public,
        })
      : buildSignedEnvelope({
          iss: did,
          aud: writeEndpoint(),
          method: "aithos.publish_ethos_edition",
          verificationMethod: signer.pubkeyMultibase,
          signer: { seed: signer.seed, publicKey: multibaseToEd25519PublicKey(signer.pubkeyMultibase) },
          mandate: signer.mandate,
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
    result?: { height: number };
    error?: { code: number; message: string; data?: Record<string, unknown> };
  };
  if (body.error) {
    throw new EditV03Error("publish_ethos_edition", body.error.message, {
      code: body.error.code,
      ...body.error.data,
    });
  }
  return { height: manifest.edition.height };
}

function zoneRefOf(
  shardShas: string[],
  shardCount: number,
  n: number,
  keyringSha?: string,
  extrawrapsSha?: string,
): ZoneRefV04 {
  return {
    n,
    shard_count: shardCount,
    shard_shas: shardShas,
    ...(keyringSha ? { keyring_sha: keyringSha } : {}),
    ...(extrawrapsSha ? { extrawraps_sha: extrawrapsSha } : {}),
  };
}

/** Diff new shards against prev refs: upload only the changed ones. */
function uploadChangedShards(up: UploadSet, shards: ZoneShardV04[], prevShas: ReadonlySet<string>): string[] {
  return shards.map((sh) => {
    const bytes = objectBytes(sh);
    const sha = bytesToHex(sha256(bytes));
    if (!prevShas.has(sha)) up.objects.set(sha, bytes);
    return sha;
  });
}

/* -------------------------------------------------------------------------- */
/*  Owner write (edit/add/delete + sealGrant/prune/rotate modes)              */
/* -------------------------------------------------------------------------- */

export interface ZoneGrantTarget {
  /** Wrap recipient label: `granteeId#pubkeyMultibase`. */
  readonly recipient: string;
  /** The grantee's X25519 public key (derived from its Ed25519 pubkey). */
  readonly x25519PublicKey: Uint8Array;
}

export interface SectionGrantTarget extends ZoneGrantTarget {
  readonly section_id: string;
}

export interface PatchV04OwnerArgs {
  readonly did: string;
  readonly owner: StoredIdentity;
  readonly prev: EthosV04Snapshot;
  readonly patches?: Partial<Record<SphereName, { upserts?: readonly Section[]; deletes?: readonly string[] }>>;
  /** sealGrant (zone scope): add these recipients to the zone keyring — O(1). */
  readonly addZoneGrants?: Partial<Record<"circle" | "self", readonly ZoneGrantTarget[]>>;
  /** sealGrant (per-section): add DEK wraps in ExtraWraps. */
  readonly addSectionGrants?: Partial<Record<"circle" | "self", readonly SectionGrantTarget[]>>;
  /** pruneWraps: drop these recipient labels from keyring + extrawraps. */
  readonly pruneLabels?: ReadonlySet<string>;
  /** rotate = new zone key, enc_dek rewrap, keyring rebuilt to keepRecipients.
   *  rotate-deep additionally re-encrypts every body (new DEKs + blobs). */
  readonly rotate?: { mode: "rotate" | "rotate-deep"; zones: readonly ("circle" | "self")[]; keepRecipients: Partial<Record<"circle" | "self", readonly ZoneGrantTarget[]>> };
}

export async function patchEditionV04Owner(args: PatchV04OwnerArgs): Promise<{ manifest: ManifestV04; height: number }> {
  const { did, owner, prev } = args;
  const up: UploadSet = { objects: new Map(), blobs: new Map() };
  const prevManifest = prev.manifest;
  const prevObjShas = new Set<string>();
  for (const z of SPHERES) {
    const r = prevManifest.zones[z];
    if (!r) continue;
    for (const s of r.shard_shas) prevObjShas.add(s);
    if (r.keyring_sha) prevObjShas.add(r.keyring_sha);
    if (r.extrawraps_sha) prevObjShas.add(r.extrawraps_sha);
  }

  const zones = {} as Record<SphereName, ZoneRefV04>;

  for (const z of SPHERES) {
    const entries = entriesFromShards(prev.shards[z]);
    const patch = args.patches?.[z];
    const isEnc = z !== "public";
    let zk = isEnc ? prev.zoneKeys[z] : undefined;
    let keyring = isEnc ? prev.keyrings[z] : undefined;
    let extrawraps = prev.extrawraps[z];
    let keyringDirty = false;
    let extraDirty = false;

    if (isEnc && !zk) throw new EditV03Error("v04_owner_zone_key", `owner could not open the ${z} zone key`);

    /* ---- rotate ---- */
    const rot = args.rotate && (args.rotate.zones as readonly string[]).includes(z) ? args.rotate : undefined;
    if (rot && isEnc && zk) {
      const fresh = generateZoneKey();
      const keep = rot.keepRecipients[z as "circle" | "self"] ?? [];
      const wraps = [
        sealZoneKeyTo(fresh, ownerKexLabel(did, z), x25519.getPublicKey(ownerKexSecret(owner, z as "circle" | "self"))),
        ...keep.map((g) => sealZoneKeyTo(fresh, g.recipient, g.x25519PublicKey)),
      ].sort((a, b) => (a.recipient < b.recipient ? -1 : 1));
      keyring = { object: "keyring", v: 1, zone: z, kid: fresh.kid, wraps };
      keyringDirty = true;
      // rewrap every enc_dek (symmetric; bodies untouched unless rotate-deep)
      for (const [id, e] of entries) {
        if (!e.enc_dek) continue;
        const dek = openDekUnderZoneKey(zk.key, e.enc_dek, did, z, id);
        if (rot.mode === "rotate-deep") {
          // new DEK + re-encrypted body — fetch, re-encrypt, re-upload
          const auth = readAuthFor(did, owner, undefined)!;
          const blob = await fetchSectionBlob(did, id, auth);
          const md = decryptBodyV04(dek, e.n!, did, id, blob);
          const newDek = new Uint8Array(randomBytes(32));
          const encd = encryptBodyV04(newDek, did, id, md);
          const blobSha = bytesToHex(sha256(encd.blob));
          up.blobs.set(blobSha, encd.blob);
          const tc = e.title_cipher
            ? encryptTitleV2pc(newDek, did, id, decryptTitleV2pc(dek, did, id, e.title_cipher))
            : undefined;
          entries.set(id, {
            ...e,
            blob_sha: blobSha,
            n: encd.n,
            approx_size_bytes: encd.blob.length,
            ...(tc ? { title_cipher: tc } : {}),
            enc_dek: sealDekUnderZoneKey(fresh, newDek, did, z, id),
          });
        } else {
          entries.set(id, { ...e, enc_dek: sealDekUnderZoneKey(fresh, dek, did, z, id) });
        }
      }
      zk = fresh;
    }

    /* ---- prune ---- */
    if (args.pruneLabels && isEnc) {
      if (keyring && keyring.wraps.some((w) => args.pruneLabels!.has(w.recipient))) {
        keyring = { ...keyring, wraps: keyring.wraps.filter((w) => !args.pruneLabels!.has(w.recipient)) };
        keyringDirty = true;
      }
      if (extrawraps) {
        const pruned = extrawraps.entries
          .map((en) => ({ ...en, wraps: en.wraps.filter((w) => !args.pruneLabels!.has(w.recipient)) }))
          .filter((en) => en.wraps.length > 0);
        if (pruned.length !== extrawraps.entries.length || pruned.some((en, i) => en.wraps.length !== extrawraps!.entries[i]?.wraps.length)) {
          extrawraps = { ...extrawraps, entries: pruned };
          extraDirty = true;
        }
      }
    }

    /* ---- sealGrant: zone scope (O(1)) ---- */
    const zoneGrants = isEnc ? args.addZoneGrants?.[z as "circle" | "self"] : undefined;
    if (zoneGrants && zoneGrants.length > 0 && keyring && zk) {
      const have = new Set(keyring.wraps.map((w) => w.recipient));
      const added = zoneGrants.filter((g) => !have.has(g.recipient)).map((g) => sealZoneKeyTo(zk!, g.recipient, g.x25519PublicKey));
      if (added.length > 0) {
        keyring = { ...keyring, wraps: [...keyring.wraps, ...added].sort((a, b) => (a.recipient < b.recipient ? -1 : 1)) };
        keyringDirty = true;
      }
    }

    /* ---- sealGrant: per-section ---- */
    const secGrants = isEnc ? args.addSectionGrants?.[z as "circle" | "self"] : undefined;
    if (secGrants && secGrants.length > 0 && zk) {
      const map = new Map((extrawraps?.entries ?? []).map((en) => [en.section_id, { ...en, wraps: [...en.wraps] }]));
      for (const g of secGrants) {
        const e = entries.get(g.section_id);
        if (!e?.enc_dek) continue;
        const dek = openDekUnderZoneKey(zk.key, e.enc_dek, did, z, g.section_id);
        const en = map.get(g.section_id) ?? { section_id: g.section_id, wraps: [] };
        if (!en.wraps.some((w) => w.recipient === g.recipient)) {
          en.wraps.push({ recipient: g.recipient, wrap: wrapDek(dek, g.recipient, g.x25519PublicKey) });
          en.wraps.sort((a, b) => (a.recipient < b.recipient ? -1 : 1));
          map.set(g.section_id, en);
          extraDirty = true;
        }
      }
      if (extraDirty) {
        extrawraps = {
          object: "extra_wraps",
          v: 1,
          zone: z,
          entries: [...map.values()].sort((a, b) => (a.section_id < b.section_id ? -1 : 1)),
        };
      }
    }

    /* ---- content patches ---- */
    for (const id of patch?.deletes ?? []) entries.delete(id);
    for (const s of patch?.upserts ?? []) {
      if (z === "public") {
        const md = new TextEncoder().encode(renderSectionMarkdown(s));
        const blobSha = bytesToHex(sha256(md));
        up.blobs.set(blobSha, md);
        entries.set(s.id, {
          section_id: s.id,
          title: s.title,
          ...(s.tags ? { tags: [...s.tags] } : {}),
          blob_sha: blobSha,
          sha256_of_plaintext: blobSha,
          gamma_ref: s.gamma_ref,
          approx_size_bytes: md.length,
        });
      } else {
        const dek = new Uint8Array(randomBytes(32));
        const md = new TextEncoder().encode(renderSectionMarkdown(s));
        const plainSha = bytesToHex(sha256(md));
        const encd = encryptBodyV04(dek, did, s.id, md);
        const blobSha = bytesToHex(sha256(encd.blob));
        up.blobs.set(blobSha, encd.blob);
        const prevE = entries.get(s.id);
        entries.set(s.id, {
          section_id: s.id,
          ...(z === "circle" ? { title: s.title, ...(s.tags ? { tags: [...s.tags] } : {}) } : {}),
          ...(z === "self" ? { title_cipher: encryptTitleV2pc(dek, did, s.id, { title: s.title, ...(s.tags ? { tags: [...s.tags] } : {}) }) } : {}),
          blob_sha: blobSha,
          sha256_of_plaintext: plainSha,
          gamma_ref: s.gamma_ref,
          n: encd.n,
          approx_size_bytes: encd.blob.length,
          enc_dek: sealDekUnderZoneKey(zk!, dek, did, z, s.id),
        });
        // self-cleaning: an owner edit resyncs THIS section — drop dead extra wraps
        if (prevE && extrawraps && args.pruneLabels) {
          /* already handled by prune pass */
        }
      }
    }

    /* ---- assemble the zone ---- */
    const list = [...entries.values()];
    const { shards, shardShas, shardCount } = buildShards(z, list);
    const shasUploaded = uploadChangedShards(up, shards, prevObjShas);
    const keyringSha = isEnc && keyring ? (keyringDirty ? addObject(up, keyring) : prevManifest.zones[z]?.keyring_sha) : undefined;
    const extraSha = extrawraps && extrawraps.entries.length > 0 ? (extraDirty ? addObject(up, extrawraps) : prevManifest.zones[z]?.extrawraps_sha) : undefined;
    zones[z] = zoneRefOf(shasUploaded, shardCount, list.length, keyringSha, extraSha);
  }

  const manifest = signManifestV04Pc(
    buildManifestV04({
      subjectDid: did,
      handle: prevManifest.subject_handle,
      displayName: prevManifest.display_name,
      bundleId: "bundle_" + bytesToHex(randomBytes(8)),
      editionVersion: prevManifest.edition.version,
      createdAt: new Date().toISOString(),
      supersedes: prevManifest.bundle_id,
      prevHash: "sha256:" + manifestHashHexV04Pc(prevManifest),
      height: prevManifest.edition.height + 1,
      zones,
      sha256OfDidJson: prevManifest.integrity.sha256_of_did_json,
      ...(prevManifest.gamma ? { gamma: prevManifest.gamma } : {}),
    }),
    { kind: "owner", subjectDid: did, publicSphereSeed: hexSeed(owner, "public") },
  );
  await postPublishV04(did, manifest, up, { kind: "owner", owner });
  return { manifest, height: manifest.edition.height };
}

/* -------------------------------------------------------------------------- */
/*  Migration v0.3 → v0.4 (owner, one edition; N10)                           */
/* -------------------------------------------------------------------------- */

export interface MigrateArgs {
  readonly did: string;
  readonly owner: StoredIdentity;
  readonly prevV03: ManifestV03;
  /** Active grants to carry: zone-scoped → keyring, narrowed → extrawraps. */
  readonly zoneGrants?: Partial<Record<"circle" | "self", readonly ZoneGrantTarget[]>>;
}

export async function migrateV03ToV04(args: MigrateArgs): Promise<{ manifest: ManifestV04; height: number }> {
  const { did, owner, prevV03 } = args;
  const up: UploadSet = { objects: new Map(), blobs: new Map() };
  const zones = {} as Record<SphereName, ZoneRefV04>;

  for (const z of SPHERES) {
    const descs = prevV03.zones[z]?.sections ?? [];
    const isEnc = z !== "public";
    const zk = isEnc ? generateZoneKey() : undefined;
    const entries: ShardEntryV04[] = [];
    const extraEntries: ExtraWrapsV04Pc["entries"] = [];

    for (const d of descs) {
      const base = {
        section_id: d.section_id,
        blob_sha: d.blob_sha!,
        sha256_of_plaintext: d.sha256_of_plaintext,
        gamma_ref: d.gamma_ref,
      };
      if (!isEnc) {
        entries.push({
          ...base,
          ...(d.title !== undefined ? { title: d.title } : {}),
          ...(d.tags ? { tags: [...d.tags] } : {}),
        } as ShardEntryV04);
        continue;
      }
      // owner unwraps its own v0.3 wrap → DEK (local, no body read)
      const ownerLabel = ownerKexLabel(did, z);
      const wrap = (d.cipher?.wraps ?? []).find((w) => w.recipient === ownerLabel) as WrapEntry | undefined;
      if (!wrap) throw new EditV03Error("v04_migrate", `no owner wrap on ${z}/${d.section_id}`);
      const dek = unwrapDek(wrap, ownerKexSecret(owner, z as "circle" | "self"));
      // carry foreign ACTIVE wraps for non-zone grantees? narrowed grants only:
      // zone-scoped grants go to the keyring; everything else is re-derived by
      // sealGrant later. The migration carries NO per-section wraps by default
      // (dead ones get pruned for free); section-scoped active grants are rare
      // and re-sealed by the SDK right after migration (one publish).
      const tc = z === "self" ? encryptTitleV2pc(dek, did, d.section_id, openV03SelfTitle(did, z, d, owner)) : undefined;
      entries.push({
        ...base,
        ...(z === "circle" && d.title !== undefined ? { title: d.title, ...(d.tags ? { tags: [...d.tags] } : {}) } : {}),
        ...(tc ? { title_cipher: tc } : {}),
        n: d.cipher!.nonce,
        enc_dek: sealDekUnderZoneKey(zk!, dek, did, z, d.section_id),
      } as ShardEntryV04);
    }

    const { shards, shardCount } = buildShards(z, entries);
    const shardShas = shards.map((sh) => addObject(up, sh));
    let keyringSha: string | undefined;
    if (isEnc && zk) {
      const wraps = [
        sealZoneKeyTo(zk, ownerKexLabel(did, z), x25519.getPublicKey(ownerKexSecret(owner, z as "circle" | "self"))),
        ...(args.zoneGrants?.[z as "circle" | "self"] ?? []).map((g) => sealZoneKeyTo(zk, g.recipient, g.x25519PublicKey)),
      ].sort((a, b) => (a.recipient < b.recipient ? -1 : 1));
      keyringSha = addObject(up, { object: "keyring", v: 1, zone: z, kid: zk.kid, wraps } satisfies KeyRingV04Pc);
    }
    const extraSha = extraEntries.length > 0 ? addObject(up, { object: "extra_wraps", v: 1, zone: z, entries: extraEntries } satisfies ExtraWrapsV04Pc) : undefined;
    zones[z] = zoneRefOf(shardShas, shardCount, entries.length, keyringSha, extraSha);
  }

  const manifest = signManifestV04Pc(
    buildManifestV04({
      subjectDid: did,
      handle: prevV03.subject_handle,
      displayName: prevV03.display_name,
      bundleId: "bundle_" + bytesToHex(randomBytes(8)),
      editionVersion: prevV03.edition.version,
      createdAt: new Date().toISOString(),
      supersedes: prevV03.bundle_id,
      prevHash: "sha256:" + canonicalManifestV03HashHex(prevV03),
      height: prevV03.edition.height + 1,
      zones,
      sha256OfDidJson: prevV03.integrity.sha256_of_did_json,
      ...(prevV03.gamma ? { gamma: prevV03.gamma as never } : {}),
    }),
    { kind: "owner", subjectDid: did, publicSphereSeed: hexSeed(owner, "public") },
  );
  await postPublishV04(did, manifest, up, { kind: "owner", owner });
  return { manifest, height: manifest.edition.height };
}

/* -------------------------------------------------------------------------- */
/*  Delegate write                                                            */
/* -------------------------------------------------------------------------- */

export interface PatchV04DelegateArgs {
  readonly did: string;
  readonly delegate: { granteeId: string; pubkeyMultibase: string; seed: Uint8Array; mandate: SignedMandate; mandateId: string };
  readonly prev: EthosV04Snapshot;
  readonly zone: SphereName;
  readonly upserts?: readonly Section[];
  readonly deletes?: readonly string[];
  /** did.json — needed on the fence path to wrap the DEK to the owner. */
  readonly didDoc?: DidDocument;
}

export async function patchEditionV04Delegate(args: PatchV04DelegateArgs): Promise<{ manifest: ManifestV04; height: number }> {
  const { did, delegate, prev, zone } = args;
  const up: UploadSet = { objects: new Map(), blobs: new Map() };
  const prevManifest = prev.manifest;
  const prevObjShas = new Set<string>();
  for (const z of SPHERES) {
    const r = prevManifest.zones[z];
    if (!r) continue;
    for (const s of r.shard_shas) prevObjShas.add(s);
    if (r.keyring_sha) prevObjShas.add(r.keyring_sha);
    if (r.extrawraps_sha) prevObjShas.add(r.extrawraps_sha);
  }

  const entries = entriesFromShards(prev.shards[zone]);
  const isEnc = zone !== "public";
  const zk = isEnc ? prev.zoneKeys[zone] : undefined;
  const myLabel = `${delegate.granteeId}#${delegate.pubkeyMultibase}`;
  let extrawraps = prev.extrawraps[zone];
  let extraDirty = false;

  for (const id of args.deletes ?? []) entries.delete(id);
  for (const s of args.upserts ?? []) {
    const md = new TextEncoder().encode(renderSectionMarkdown(s));
    const plainSha = bytesToHex(sha256(md));
    if (!isEnc) {
      up.blobs.set(plainSha, md);
      entries.set(s.id, {
        section_id: s.id,
        title: s.title,
        ...(s.tags ? { tags: [...s.tags] } : {}),
        blob_sha: plainSha,
        sha256_of_plaintext: plainSha,
        gamma_ref: s.gamma_ref,
        approx_size_bytes: md.length,
      });
      continue;
    }
    const dek = new Uint8Array(randomBytes(32));
    const encd = encryptBodyV04(dek, did, s.id, md);
    const blobSha = bytesToHex(sha256(encd.blob));
    up.blobs.set(blobSha, encd.blob);
    const common = {
      section_id: s.id,
      ...(zone === "circle" ? { title: s.title, ...(s.tags ? { tags: [...s.tags] } : {}) } : {}),
      ...(zone === "self" ? { title_cipher: encryptTitleV2pc(dek, did, s.id, { title: s.title, ...(s.tags ? { tags: [...s.tags] } : {}) }) } : {}),
      blob_sha: blobSha,
      sha256_of_plaintext: plainSha,
      gamma_ref: s.gamma_ref,
      n: encd.n,
      approx_size_bytes: encd.blob.length,
    };
    if (zk) {
      entries.set(s.id, { ...common, enc_dek: sealDekUnderZoneKey(zk, dek, did, zone, s.id) } as ShardEntryV04);
    } else {
      // fence path (N9.3): no zone key — entry without enc_dek; DEK wrapped to
      // author + owner in ExtraWraps. Owner kex pk comes from did.json.
      if (!args.didDoc) throw new EditV03Error("v04_delegate_fence", "didDoc required to wrap the DEK to the owner");
      const ownerPk = ownerZoneKexPubkey(args.didDoc, did, zone as "circle" | "self");
      const authorPk = edPubToX25519Pub(multibaseToEd25519PublicKey(delegate.pubkeyMultibase));
      entries.set(s.id, common as ShardEntryV04);
      const map = new Map((extrawraps?.entries ?? []).map((en) => [en.section_id, { ...en, wraps: [...en.wraps] }]));
      const en = map.get(s.id) ?? { section_id: s.id, wraps: [] };
      en.wraps = [
        { recipient: ownerKexLabel(did, zone), wrap: wrapDek(dek, ownerKexLabel(did, zone), ownerPk) },
        { recipient: myLabel, wrap: wrapDek(dek, myLabel, authorPk) },
      ].sort((a, b) => (a.recipient < b.recipient ? -1 : 1));
      map.set(s.id, en);
      extrawraps = {
        object: "extra_wraps",
        v: 1,
        zone,
        entries: [...map.values()].sort((a, b) => (a.section_id < b.section_id ? -1 : 1)),
      };
      extraDirty = true;
    }
  }

  const list = [...entries.values()];
  const { shards, shardCount } = buildShards(zone, list);
  const shardShas = uploadChangedShards(up, shards, prevObjShas);
  const zones = { ...prevManifest.zones } as Record<SphereName, ZoneRefV04>;
  zones[zone] = zoneRefOf(
    shardShas,
    shardCount,
    list.length,
    prevManifest.zones[zone]?.keyring_sha,
    extrawraps && extrawraps.entries.length > 0 ? (extraDirty ? addObject(up, extrawraps) : prevManifest.zones[zone]?.extrawraps_sha) : undefined,
  );

  const manifest = signManifestV04Pc(
    buildManifestV04({
      subjectDid: did,
      handle: prevManifest.subject_handle,
      displayName: prevManifest.display_name,
      bundleId: "bundle_" + bytesToHex(randomBytes(8)),
      editionVersion: prevManifest.edition.version,
      createdAt: new Date().toISOString(),
      supersedes: prevManifest.bundle_id,
      prevHash: "sha256:" + manifestHashHexV04Pc(prevManifest),
      height: prevManifest.edition.height + 1,
      zones,
      sha256OfDidJson: prevManifest.integrity.sha256_of_did_json,
      ...(prevManifest.gamma ? { gamma: prevManifest.gamma } : {}),
    }),
    { kind: "delegate", pubkeyMultibase: delegate.pubkeyMultibase, seed: delegate.seed, mandateId: delegate.mandateId },
  );
  await postPublishV04(did, manifest, up, {
    kind: "delegate",
    seed: delegate.seed,
    pubkeyMultibase: delegate.pubkeyMultibase,
    mandate: delegate.mandate,
  });
  return { manifest, height: manifest.edition.height };
}

/* -------------------------------------------------------------------------- */
/*  small helpers                                                             */
/* -------------------------------------------------------------------------- */

function hexSeed(owner: StoredIdentity, zone: "public" | "circle" | "self"): Uint8Array {
  const hex = owner.seeds[zone];
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Open a v0.3 self title_cipher with the OWNER's kex (migration only). */
function openV03SelfTitle(
  did: string,
  zone: "circle" | "self",
  d: { section_id: string; title_cipher?: { nonce: string; wraps: readonly WrapEntry[]; ct: string } },
  owner: StoredIdentity,
): { title: string; tags?: string[] } {
  const tc = d.title_cipher;
  if (!tc) return { title: d.section_id };
  const label = ownerKexLabel(did, zone);
  const wrap = tc.wraps.find((w) => w.recipient === label);
  if (!wrap) return { title: d.section_id };
  const dek = unwrapDek(wrap, ownerKexSecret(owner, zone));
  const pt = xchacha20poly1305(dek, b64ToBytes(tc.nonce), titleAad(did, d.section_id)).decrypt(b64ToBytes(tc.ct));
  return JSON.parse(new TextDecoder().decode(pt)) as { title: string; tags?: string[] };
}
