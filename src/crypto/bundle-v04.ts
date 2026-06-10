// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// v0.4 incremental bundle — crypto + object layer (browser mirror of
// @aithos/protocol-core's bundle-v04.ts; spec Partie II N1-N5). Pure +
// transport-agnostic, byte-identical constructions with the reference:
// the §3.6 wrap (pc's WrapEntry wire shape), the enc_dek and title-v2 AEADs
// (AADs pinned by core's dekAadV04 / titleAadV2), the JCS object shas, and
// the deterministic sharding (imported straight from core — one source of
// truth for slot math).

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { sha256 } from "@noble/hashes/sha2";

import {
  dekAadV04,
  titleAadV2,
  shardCountForN,
  shardIndexForSection,
  type EncDekV04,
  type ManifestV04,
  type ShardEntryV04,
  type TitleCipherV2,
  type ZoneRefV04,
  type ZoneShardV04,
} from "@aithos/protocol-core";

import { base64url, base64urlDecode, bytesToHex } from "./encoding.js";
import { canonicalize } from "./canonical.js";
import { sign } from "./ed25519.js";
import { edSeedToX25519Secret } from "./kex.js";
import { wrapDek } from "./encrypt.js";
import { unwrapDek, type WrapEntry } from "./decrypt.js";
import { sectionAad, type SphereName } from "./bundle-v03.js";
import type { StoredIdentity } from "../storage-types.js";

export type { EncDekV04, ManifestV04, ShardEntryV04, TitleCipherV2, ZoneRefV04, ZoneShardV04 };

/* -------------------------------------------------------------------------- */
/*  Wire types kept pc-local (wraps use pc's WrapEntry shape — same wire as   */
/*  core's ZoneWrap, proven interoperable by every v0.3 bundle)               */
/* -------------------------------------------------------------------------- */

export interface KeyRingV04Pc {
  object: "keyring";
  v: 1;
  zone: SphereName;
  kid: string;
  wraps: { recipient: string; wrap: WrapEntry }[];
}

export interface ExtraWrapsV04Pc {
  object: "extra_wraps";
  v: 1;
  zone: SphereName;
  entries: { section_id: string; wraps: { recipient: string; wrap: WrapEntry }[] }[];
}

export interface ZoneKeyPc {
  kid: string;
  key: Uint8Array;
}

/* -------------------------------------------------------------------------- */
/*  Objects — canonical bytes + shas (N1)                                     */
/* -------------------------------------------------------------------------- */

export function objectBytes(obj: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(obj));
}

export function objectSha(obj: unknown): string {
  return bytesToHex(sha256(objectBytes(obj)));
}

/** Partition + sort entries into shard objects; returns shards in slot order. */
export function buildShards(
  zone: SphereName,
  entries: readonly ShardEntryV04[],
): { shards: ZoneShardV04[]; shardShas: string[]; shardCount: number } {
  const shardCount = shardCountForN(entries.length);
  const buckets: ShardEntryV04[][] = Array.from({ length: shardCount }, () => []);
  for (const e of entries) buckets[shardIndexForSection(e.section_id, shardCount)]!.push(e);
  const shards = buckets.map((list) => ({
    object: "zone_shard" as const,
    v: 1 as const,
    zone: zone as ZoneShardV04["zone"],
    entries: [...list].sort((a, b) =>
      a.section_id < b.section_id ? -1 : a.section_id > b.section_id ? 1 : 0,
    ),
  }));
  return { shards, shardShas: shards.map(objectSha), shardCount };
}

export function entriesFromShards(shards: readonly ZoneShardV04[]): Map<string, ShardEntryV04> {
  const out = new Map<string, ShardEntryV04>();
  for (const sh of shards) for (const e of sh.entries) out.set(e.section_id, e);
  return out;
}

/* -------------------------------------------------------------------------- */
/*  Zone master keys (N3/N4)                                                  */
/* -------------------------------------------------------------------------- */

export function generateZoneKey(): ZoneKeyPc {
  return { kid: "zk" + bytesToHex(randomBytes(8)), key: new Uint8Array(randomBytes(32)) };
}

/** Owner kex label — the keyring recipient the subject always holds. */
export function ownerKexLabel(subjectDid: string, zone: SphereName): string {
  return `${subjectDid}#${zone}-kex`;
}

/** The subject's X25519 kex secret for a zone, from its stored sphere seed. */
export function ownerKexSecret(owner: StoredIdentity, zone: "circle" | "self"): Uint8Array {
  return edSeedToX25519Secret(hexToBytes(owner.seeds[zone]));
}

/** Seal the zone key to one recipient — §3.6 wrap over jcs({kid, zone_key}). */
export function sealZoneKeyTo(
  zk: ZoneKeyPc,
  recipientLabel: string,
  recipientX25519Pk: Uint8Array,
): { recipient: string; wrap: WrapEntry } {
  const payload = new TextEncoder().encode(
    canonicalize({ kid: zk.kid, zone_key: base64url(zk.key) }),
  );
  return { recipient: recipientLabel, wrap: wrapDek(payload, recipientLabel, recipientX25519Pk) };
}

export function openZoneKey(
  entry: { recipient: string; wrap: WrapEntry },
  myX25519Sk: Uint8Array,
): ZoneKeyPc {
  const payload = unwrapDek(entry.wrap, myX25519Sk);
  const parsed = JSON.parse(new TextDecoder().decode(payload)) as {
    kid?: unknown;
    zone_key?: unknown;
  };
  if (typeof parsed.kid !== "string" || typeof parsed.zone_key !== "string") {
    throw new Error("keyring wrap payload malformed (expected {kid, zone_key})");
  }
  return { kid: parsed.kid, key: base64urlDecode(parsed.zone_key) };
}

/* -------------------------------------------------------------------------- */
/*  enc_dek + body + title (N2/N3)                                            */
/* -------------------------------------------------------------------------- */

export function sealDekUnderZoneKey(
  zk: ZoneKeyPc,
  dek: Uint8Array,
  subjectDid: string,
  zone: SphereName,
  sectionId: string,
): EncDekV04 {
  const n = new Uint8Array(randomBytes(24));
  const c = xchacha20poly1305(zk.key, n, dekAadV04(subjectDid, zone as never, sectionId, zk.kid)).encrypt(dek);
  return { kid: zk.kid, n: base64url(n), c: base64url(c) };
}

export function openDekUnderZoneKey(
  zoneKey: Uint8Array,
  encDek: EncDekV04,
  subjectDid: string,
  zone: SphereName,
  sectionId: string,
): Uint8Array {
  return xchacha20poly1305(
    zoneKey,
    base64urlDecode(encDek.n),
    dekAadV04(subjectDid, zone as never, sectionId, encDek.kid),
  ).decrypt(base64urlDecode(encDek.c));
}

/** Encrypt a section body (markdown bytes) under a caller-supplied DEK; the
 *  nonce goes to the shard entry (`n`), the blob stays raw ciphertext —
 *  byte-compatible with v0.3 stored blobs (§3.4′ AAD unchanged). */
export function encryptBodyV04(
  dek: Uint8Array,
  subjectDid: string,
  sectionId: string,
  markdownBytes: Uint8Array,
): { blob: Uint8Array; n: string } {
  const nonce = new Uint8Array(randomBytes(24));
  const blob = xchacha20poly1305(dek, nonce, sectionAad(subjectDid, sectionId)).encrypt(markdownBytes);
  return { blob, n: base64url(nonce) };
}

export function decryptBodyV04(
  dek: Uint8Array,
  n: string,
  subjectDid: string,
  sectionId: string,
  blob: Uint8Array,
): Uint8Array {
  return xchacha20poly1305(dek, base64urlDecode(n), sectionAad(subjectDid, sectionId)).decrypt(blob);
}

export function encryptTitleV2pc(
  dek: Uint8Array,
  subjectDid: string,
  sectionId: string,
  title: { title: string; tags?: string[] },
): TitleCipherV2 {
  const n = new Uint8Array(randomBytes(24));
  const ct = xchacha20poly1305(dek, n, titleAadV2(subjectDid, sectionId)).encrypt(
    new TextEncoder().encode(canonicalize(title)),
  );
  return { n: base64url(n), ct: base64url(ct) };
}

export function decryptTitleV2pc(
  dek: Uint8Array,
  subjectDid: string,
  sectionId: string,
  tc: TitleCipherV2,
): { title: string; tags?: string[] } {
  const pt = xchacha20poly1305(dek, base64urlDecode(tc.n), titleAadV2(subjectDid, sectionId)).decrypt(
    base64urlDecode(tc.ct),
  );
  return JSON.parse(new TextDecoder().decode(pt)) as { title: string; tags?: string[] };
}

/* -------------------------------------------------------------------------- */
/*  Manifest signing (mirror of core's signManifestV04, pc signer)            */
/* -------------------------------------------------------------------------- */

export type V04Signer =
  | { kind: "owner"; subjectDid: string; publicSphereSeed: Uint8Array }
  | { kind: "delegate"; pubkeyMultibase: string; seed: Uint8Array; mandateId: string };

export function signManifestV04Pc(m: ManifestV04, signer: V04Signer): ManifestV04 {
  const baseSig =
    signer.kind === "owner"
      ? { alg: "ed25519" as const, key: `${signer.subjectDid}#public`, value: "" }
      : {
          alg: "ed25519" as const,
          key: signer.pubkeyMultibase,
          value: "",
          authorized_by: signer.mandateId,
        };
  const base: ManifestV04 = { ...m, integrity: { ...m.integrity, manifest_signature: baseSig } };
  const bytes = new TextEncoder().encode(canonicalize(base));
  const seed = signer.kind === "owner" ? signer.publicSphereSeed : signer.seed;
  const value = base64url(sign(bytes, seed));
  return { ...base, integrity: { ...base.integrity, manifest_signature: { ...baseSig, value } } };
}

/** sha256 hex of the canonical (blank-sig) v0.4 manifest — prev_hash anchor. */
export function manifestHashHexV04Pc(m: ManifestV04): string {
  const blanked: ManifestV04 = {
    ...m,
    integrity: {
      ...m.integrity,
      manifest_signature: { ...m.integrity.manifest_signature, value: "" },
    },
  };
  return bytesToHex(sha256(new TextEncoder().encode(canonicalize(blanked))));
}

/* -------------------------------------------------------------------------- */

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex must be even-length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
