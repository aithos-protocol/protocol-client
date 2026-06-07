// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// v0.3 per-section bundle — WRITE half (browser mirror of @aithos/protocol-core's
// `bundle-v03.ts` author path). Pure + transport-agnostic: produces an in-memory
// { manifest, blobs } that the caller (editor.ts) POSTs to the API. Every
// constant — section/title AAD, the section markdown form, the DEK wrap, the
// manifest signing input — is kept byte-identical with the reference so a bundle
// authored here verifies and decrypts under the CLI / protocol-core.
//
// Owner authoring with the subject's own sphere as the recipient. Carry-forward
// (the v0.3 cost property): a section whose plaintext hash + gamma_ref +
// recipient set are unchanged from `prev` has its prior blob reused verbatim, so
// only genuinely-changed sections pay the re-encryption cost.

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";

import { base64url, bytesToHex, multibaseToX25519PublicKey } from "./encoding.js";
import { canonicalize } from "./canonical.js";
import { sign } from "./ed25519.js";
import { edSeedToX25519Secret } from "./kex.js";
import { wrapDek } from "./encrypt.js";
import { sphereDidUrl, type BrowserIdentity } from "./identity.js";
import type { Section } from "./manifest.js";
import { coversRead } from "./ethos-scope.js";
import {
  sectionAad,
  titleAad,
  type BundleZoneV2,
  type ManifestV03,
  type SectionCipher,
  type SectionDescriptor,
  type SectionTitle,
  type SphereName,
  type TitleCipher,
} from "./bundle-v03.js";

/** Per-section recipient: who can open the section DEK (and its title cipher). */
export interface SectionRecipient {
  readonly didUrl: string;
  readonly x25519PublicKey: Uint8Array;
}

/** Which zones seal their index titles (self only). Mirrors protocol-core. */
const ZONE_INDEX_ENCRYPTED: Record<SphereName, boolean> = {
  public: false,
  circle: false,
  self: true,
};

/* -------------------------------------------------------------------------- */
/*  Recipients                                                                 */
/* -------------------------------------------------------------------------- */

/** The subject's own sphere recipient: `${did}#${zone}-kex` + its X25519 pubkey. */
export function subjectRecipient(
  identity: BrowserIdentity,
  subjectDid: string,
  zone: "circle" | "self",
): SectionRecipient {
  const sk = edSeedToX25519Secret(identity[zone].seed);
  const pk = x25519.getPublicKey(sk);
  sk.fill(0);
  return { didUrl: `${subjectDid}#${zone}-kex`, x25519PublicKey: pk };
}

/* -------------------------------------------------------------------------- */
/*  Section markdown + per-section AEAD                                        */
/* -------------------------------------------------------------------------- */

/** Render one section to its canonical markdown form (§3.4.5′). */
export function renderSectionMarkdown(section: { title: string; body: string; tags?: readonly string[] }): string {
  const parts: string[] = [`# ${section.title}`];
  if (section.tags && section.tags.length > 0) {
    parts.push(`<!-- tags: ${JSON.stringify(section.tags)} -->`);
  }
  parts.push("");
  parts.push(section.body);
  return parts.join("\n").replace(/\s+$/, "") + "\n";
}

function sha256hex(s: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(s)));
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** Encrypt one section body under a fresh per-section DEK (§3.4.1′). */
export function encryptSection(
  plaintext: string,
  subjectDid: string,
  sectionId: string,
  recipients: readonly SectionRecipient[],
): { ciphertext: Uint8Array; cipher: SectionCipher } {
  const dek = randomBytes(32);
  const nonce = randomBytes(24);
  try {
    const aead = xchacha20poly1305(dek, nonce, sectionAad(subjectDid, sectionId));
    const ciphertext = aead.encrypt(new TextEncoder().encode(plaintext));
    const wraps = recipients.map((r) => wrapDek(dek, r.didUrl, r.x25519PublicKey));
    return { ciphertext, cipher: { alg: "xchacha20poly1305-ietf", nonce: base64url(nonce), wraps } };
  } finally {
    dek.fill(0);
  }
}

/** Seal a section's title/tags to the same recipients as its body (self index). */
export function encryptSectionTitle(
  meta: SectionTitle,
  subjectDid: string,
  sectionId: string,
  recipients: readonly SectionRecipient[],
): TitleCipher {
  const dek = randomBytes(32);
  const nonce = randomBytes(24);
  try {
    const aead = xchacha20poly1305(dek, nonce, titleAad(subjectDid, sectionId));
    const ct = aead.encrypt(new TextEncoder().encode(canonicalize(meta)));
    const wraps = recipients.map((r) => wrapDek(dek, r.didUrl, r.x25519PublicKey));
    return { alg: "xchacha20poly1305-ietf", nonce: base64url(nonce), wraps, ct: base64url(ct) };
  } finally {
    dek.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  Write one section -> descriptor + blob bytes                              */
/* -------------------------------------------------------------------------- */

export interface WriteSectionCtx {
  readonly zone: SphereName;
  readonly encrypted: boolean;
  readonly indexEncrypted: boolean;
  readonly subjectDid: string;
  readonly recipients: readonly SectionRecipient[];
}

export interface WrittenSection {
  readonly descriptor: SectionDescriptor;
  readonly file: string;
  readonly blob: Uint8Array;
}

/** Produce one section's manifest descriptor + the bytes to store at its path. */
export function writeSection(ctx: WriteSectionCtx, section: Section): WrittenSection {
  const plaintext = renderSectionMarkdown(section);
  const sha = sha256hex(plaintext);
  const ext = ctx.encrypted ? "enc" : "md";
  const file = `${ctx.zone}/${section.id}.${ext}`;

  const desc: {
    section_id: string;
    file: string;
    sha256_of_plaintext: string;
    gamma_ref: string;
    title?: string;
    tags?: readonly string[];
    cipher?: SectionCipher;
    title_cipher?: TitleCipher;
  } = { section_id: section.id, file, sha256_of_plaintext: sha, gamma_ref: section.gamma_ref };

  if (ctx.indexEncrypted) {
    desc.title_cipher = encryptSectionTitle(
      { title: section.title, ...(section.tags && section.tags.length > 0 ? { tags: section.tags } : {}) },
      ctx.subjectDid,
      section.id,
      ctx.recipients,
    );
  } else {
    desc.title = section.title;
    if (section.tags && section.tags.length > 0) desc.tags = section.tags;
  }

  let blob: Uint8Array;
  if (!ctx.encrypted) {
    blob = new TextEncoder().encode(plaintext);
  } else {
    const enc = encryptSection(plaintext, ctx.subjectDid, section.id, ctx.recipients);
    desc.cipher = enc.cipher;
    blob = enc.ciphertext;
  }
  return { descriptor: desc as SectionDescriptor, file, blob };
}

/* -------------------------------------------------------------------------- */
/*  Manifest assembly + signing                                               */
/* -------------------------------------------------------------------------- */

function blankSig(m: ManifestV03): ManifestV03 {
  return {
    ...m,
    integrity: {
      ...m.integrity,
      manifest_signature: { ...(m.integrity.manifest_signature as object), value: "" } as unknown,
    },
  } as ManifestV03;
}

/** Hex SHA-256 of the canonical (blank-signature) manifest — the `prev_hash` anchor. */
export function canonicalManifestV03HashHex(m: ManifestV03): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonicalize(blankSig(m)))));
}

/** Sign a v0.3 manifest with the subject's `#public` sphere key (owner path). */
export function signManifestV03(identity: BrowserIdentity, manifest: ManifestV03): ManifestV03 {
  const key = sphereDidUrl(identity, "public");
  const base: ManifestV03 = {
    ...manifest,
    integrity: { ...manifest.integrity, manifest_signature: { alg: "ed25519", key, value: "" } },
  } as ManifestV03;
  const bytes = new TextEncoder().encode(canonicalize(base));
  const raw = sign(bytes, identity.public.seed);
  return {
    ...base,
    integrity: {
      ...base.integrity,
      manifest_signature: { alg: "ed25519", key, value: base64url(raw) },
    },
  } as ManifestV03;
}

function allocEditionVersion(now: Date, prevVersion: string | undefined): string {
  const day = now.toISOString().slice(0, 10).replace(/-/g, ".");
  if (prevVersion) {
    const m = prevVersion.match(/^(\d{4}\.\d{2}\.\d{2})-(\d+)$/);
    if (m && m[1] === day) return `${day}-${parseInt(m[2] ?? "0", 10) + 1}`;
  }
  return `${day}-1`;
}

/* -------------------------------------------------------------------------- */
/*  Author a complete v0.3 edition                                            */
/* -------------------------------------------------------------------------- */

/**
 * A delegate that may READ part of an encrypted zone, projected for the owner
 * author's per-section recipient derivation (§3.5.7′). `recipient` is the
 * delegate's wrap entry; `scopes` are the mandate's scopes, evaluated per
 * section via {@link coversRead} so the delegate is sealed into ONLY the
 * sections its read-bearing verb-scopes match.
 */
export interface DelegateReadGrant {
  readonly recipient: SectionRecipient;
  readonly scopes: readonly string[];
}

export interface AuthorV03Args {
  readonly identity: BrowserIdentity;
  readonly subjectDid: string;
  readonly subjectHandle: string;
  readonly displayName: string;
  /** The exact bytes of the published did.json (hashed into the manifest). */
  readonly didJson: Uint8Array;
  /** Sections per zone, in display order. */
  readonly zones: Partial<Record<SphereName, readonly Section[]>>;
  /**
   * Active delegate read-grants for the encrypted zones. Each section's DEK is
   * wrapped to the subject PLUS every delegate here whose scopes cover reading
   * that specific section. Omit (or empty) for a subject-only bundle.
   */
  readonly delegateGrants?: Partial<Record<"circle" | "self", readonly DelegateReadGrant[]>>;
  /** Previous edition for the chain + carry-forward. `getBlob` fetches a prior blob by file path. */
  readonly prev?: { readonly manifest: ManifestV03; readonly getBlob: (file: string) => Uint8Array };
  readonly now?: Date;
}

export interface AuthoredV03 {
  readonly manifest: ManifestV03;
  /** file path -> bytes, for every section blob in the new edition. */
  readonly blobs: ReadonlyMap<string, Uint8Array>;
}

const SPHERES: readonly SphereName[] = ["public", "circle", "self"];

function recipientLabelsEqual(cipher: SectionCipher | undefined, recipients: readonly SectionRecipient[]): boolean {
  const a = new Set((cipher?.wraps ?? []).map((w) => w.recipient));
  if (a.size !== recipients.length) return false;
  for (const r of recipients) if (!a.has(r.didUrl)) return false;
  return true;
}

/**
 * Author a complete v0.3 edition (owner path) into an in-memory { manifest, blobs }.
 * Unchanged sections carry forward byte-identical from `prev` (cost property);
 * genuinely-changed/new sections are freshly encrypted.
 */
export function authorBundleV03(args: AuthorV03Args): AuthoredV03 {
  const now = args.now ?? new Date();
  const createdAt = now.toISOString();
  const blobs = new Map<string, Uint8Array>();

  // Edition chain.
  let supersedes: string | null = null;
  let prevHash: string | null = null;
  let height = 1;
  let prevVersion: string | undefined;
  if (args.prev) {
    supersedes = args.prev.manifest.bundle_id;
    prevHash = "sha256:" + canonicalManifestV03HashHex(args.prev.manifest);
    height = args.prev.manifest.edition.height + 1;
    prevVersion = args.prev.manifest.edition.version;
  }
  const editionVersion = allocEditionVersion(now, prevVersion);
  const bundleId = `urn:aithos:${args.subjectHandle}:${editionVersion}`;

  const zoneEntries: Partial<Record<SphereName, BundleZoneV2>> = {};
  for (const zone of SPHERES) {
    const encrypted = zone !== "public";
    const indexEncrypted = ZONE_INDEX_ENCRYPTED[zone];
    const subjectRec = encrypted
      ? subjectRecipient(args.identity, args.subjectDid, zone as "circle" | "self")
      : null;
    const grantsForZone = encrypted
      ? args.delegateGrants?.[zone as "circle" | "self"] ?? []
      : [];
    const prevZone = args.prev?.manifest.zones[zone];
    const descriptors: SectionDescriptor[] = [];

    for (const section of args.zones[zone] ?? []) {
      // Per-section recipients (§3.5.7′): the subject always, plus every
      // delegate whose read-bearing verb-scopes cover THIS section. A whole-zone
      // read grant matches every section; a section-scoped grant only its own.
      // Public is plaintext → no recipients.
      const recipients: SectionRecipient[] = encrypted
        ? [
            subjectRec!,
            ...grantsForZone
              .filter((g) =>
                coversRead(g.scopes, zone as "circle" | "self", {
                  id: section.id,
                  ...(section.tags ? { tags: section.tags } : {}),
                }),
              )
              .map((g) => g.recipient),
          ]
        : [];

      const plaintext = renderSectionMarkdown(section);
      const sha = sha256hex(plaintext);
      const prevDesc = prevZone?.sections.find((s) => s.section_id === section.id);
      // Carry-forward compares THIS section's recipient set, so granting or
      // revoking a section-scoped delegate re-encrypts only the sections whose
      // recipients actually changed (§3.5.6′).
      const canCarry =
        !!args.prev &&
        !!prevDesc &&
        prevDesc.sha256_of_plaintext === sha &&
        prevDesc.gamma_ref === section.gamma_ref &&
        (!encrypted || recipientLabelsEqual(prevDesc.cipher, recipients));

      if (canCarry && args.prev && prevDesc) {
        // Reuse the prior blob + descriptor verbatim.
        blobs.set(prevDesc.file, args.prev.getBlob(prevDesc.file));
        descriptors.push(prevDesc);
      } else {
        const w = writeSection({ zone, encrypted, indexEncrypted, subjectDid: args.subjectDid, recipients }, section);
        blobs.set(w.file, w.blob);
        descriptors.push(w.descriptor);
      }
    }

    zoneEntries[zone] = {
      format_version: "v2",
      encrypted,
      ...(indexEncrypted ? { index_encrypted: true } : {}),
      sections: descriptors,
    };
  }

  const didHashHex = bytesToHex(sha256(args.didJson));
  const unsigned: ManifestV03 = {
    aithos: "0.3.0",
    bundle_id: bundleId,
    subject_did: args.subjectDid,
    subject_handle: args.subjectHandle,
    display_name: args.displayName,
    edition: { version: editionVersion, created_at: createdAt, supersedes, prev_hash: prevHash, height },
    zones: zoneEntries as ManifestV03["zones"],
    integrity: {
      sha256_of_did_json: didHashHex,
      manifest_signature: { alg: "ed25519", key: `${args.subjectDid}#public`, value: "" },
    },
  };

  return { manifest: signManifestV03(args.identity, unsigned), blobs };
}

/* -------------------------------------------------------------------------- */
/*  Delegate (section-scoped) authoring — patch one zone, carry the rest      */
/* -------------------------------------------------------------------------- */

/** A section-scoped delegate authoring from the browser (the agent key + mandate). */
export interface DelegateAuthorV03 {
  /** Grantee id from the mandate (e.g. `agent:gmail`). */
  readonly granteeId: string;
  /** The delegate's Ed25519 public key, multibase — the wrap recipient suffix. */
  readonly pubkeyMultibase: string;
  /** The delegate's Ed25519 seed (32 bytes). */
  readonly seed: Uint8Array;
  /** The mandate authorising this write — recorded as `authorized_by`. */
  readonly mandateId: string;
  /** The mandate's actor sphere — the only zone the delegate may (re)author. */
  readonly actorSphere: "circle" | "self";
}

/** Recipients for a delegate-authored section: the owner sphere + the delegate itself (§3.5.2′). */
export function delegateZoneRecipients(
  ownerZonePubkey: Uint8Array,
  subjectDid: string,
  zone: "circle" | "self",
  delegate: DelegateAuthorV03,
): SectionRecipient[] {
  const dsk = edSeedToX25519Secret(delegate.seed);
  const dpk = x25519.getPublicKey(dsk);
  dsk.fill(0);
  return [
    { didUrl: `${subjectDid}#${zone}-kex`, x25519PublicKey: ownerZonePubkey },
    { didUrl: `${delegate.granteeId}#${delegate.pubkeyMultibase}`, x25519PublicKey: dpk },
  ];
}

/** Extract the subject's `#${zone}-kex` X25519 public key from a DID document. */
export function ownerZoneKexPubkey(
  didDoc: { keyAgreement?: ReadonlyArray<{ id: string; publicKeyMultibase: string }> },
  subjectDid: string,
  zone: "circle" | "self",
): Uint8Array {
  const id = `${subjectDid}#${zone}-kex`;
  const vm = (didDoc.keyAgreement ?? []).find((k) => k.id === id);
  if (!vm) throw new Error(`DID document has no keyAgreement entry ${id}`);
  return multibaseToX25519PublicKey(vm.publicKeyMultibase);
}

/** Sign a v0.3 manifest with the delegate Ed25519 key + `authorized_by` (§3.8′ #5). */
export function signManifestV03Delegate(manifest: ManifestV03, delegate: DelegateAuthorV03): ManifestV03 {
  const baseSig = { alg: "ed25519", key: delegate.pubkeyMultibase, value: "", authorized_by: delegate.mandateId };
  const base: ManifestV03 = {
    ...manifest,
    integrity: { ...manifest.integrity, manifest_signature: baseSig },
  } as ManifestV03;
  const bytes = new TextEncoder().encode(canonicalize(base));
  const raw = sign(bytes, delegate.seed);
  return {
    ...base,
    integrity: { ...base.integrity, manifest_signature: { ...baseSig, value: base64url(raw) } },
  } as ManifestV03;
}

export interface DelegatePatchArgs {
  readonly delegate: DelegateAuthorV03;
  readonly subjectDid: string;
  readonly subjectHandle: string;
  readonly displayName: string;
  readonly didJson: Uint8Array;
  /** The subject's `#${actorSphere}-kex` X25519 pubkey (from {@link ownerZoneKexPubkey}). */
  readonly ownerZonePubkey: Uint8Array;
  /** Predecessor edition + a blob fetcher (carry-forward source). */
  readonly prev: { readonly manifest: ManifestV03; readonly getBlob: (file: string) => Uint8Array };
  /** Changes to the delegate's actor sphere (upserts provide full sections). */
  readonly patch: { readonly upserts?: readonly Section[]; readonly deletes?: readonly string[] };
  readonly now?: Date;
}

/**
 * Author a new edition AS A DELEGATE: patch only the delegate's `actorSphere`
 * (its scoped sections are sealed to owner + delegate), carry every other
 * section and zone forward VERBATIM (blob + descriptor copied — no decryption,
 * since the delegate isn't entitled to read them), and sign the manifest with
 * the delegate key + `authorized_by`. Mirrors protocol-core `patchEditionV03`.
 */
export function patchEditionV03Delegate(args: DelegatePatchArgs): AuthoredV03 {
  const now = args.now ?? new Date();
  const createdAt = now.toISOString();
  const prev = args.prev.manifest;
  const zone = args.delegate.actorSphere;
  const blobs = new Map<string, Uint8Array>();

  const editionVersion = allocEditionVersion(now, prev.edition.version);
  const bundleId = `urn:aithos:${args.subjectHandle}:${editionVersion}`;
  const recipients = delegateZoneRecipients(args.ownerZonePubkey, args.subjectDid, zone, args.delegate);
  const indexEncrypted = ZONE_INDEX_ENCRYPTED[zone];

  const zoneEntries: Partial<Record<SphereName, BundleZoneV2>> = {};
  for (const z of SPHERES) {
    const prevZone = prev.zones[z];
    if (z !== zone) {
      // Carry the whole zone forward verbatim (copy blobs + reuse the entry).
      if (prevZone) {
        for (const d of prevZone.sections) blobs.set(d.file, args.prev.getBlob(d.file));
        zoneEntries[z] = prevZone;
      }
      continue;
    }

    // The authored zone: apply the patch.
    const deletes = new Set(args.patch.deletes ?? []);
    const upserts = new Map((args.patch.upserts ?? []).map((s) => [s.id, s]));
    const descriptors: SectionDescriptor[] = [];

    // Existing sections in their prior order: drop deletes, re-encrypt upserts,
    // otherwise carry forward verbatim.
    for (const d of prevZone?.sections ?? []) {
      if (deletes.has(d.section_id)) continue;
      const up = upserts.get(d.section_id);
      if (up) {
        const w = writeSection({ zone, encrypted: true, indexEncrypted, subjectDid: args.subjectDid, recipients }, up);
        blobs.set(w.file, w.blob);
        descriptors.push(w.descriptor);
        upserts.delete(d.section_id);
      } else {
        blobs.set(d.file, args.prev.getBlob(d.file));
        descriptors.push(d);
      }
    }
    // New sections (upserts not present in prev), in input order.
    for (const s of args.patch.upserts ?? []) {
      if (!upserts.has(s.id)) continue; // already applied above
      const w = writeSection({ zone, encrypted: true, indexEncrypted, subjectDid: args.subjectDid, recipients }, s);
      blobs.set(w.file, w.blob);
      descriptors.push(w.descriptor);
    }

    zoneEntries[z] = {
      format_version: "v2",
      encrypted: true,
      ...(indexEncrypted ? { index_encrypted: true } : {}),
      sections: descriptors,
    };
  }

  const didHashHex = bytesToHex(sha256(args.didJson));
  const unsigned: ManifestV03 = {
    aithos: "0.3.0",
    bundle_id: bundleId,
    subject_did: args.subjectDid,
    subject_handle: args.subjectHandle,
    display_name: args.displayName,
    edition: {
      version: editionVersion,
      created_at: createdAt,
      supersedes: prev.bundle_id,
      prev_hash: "sha256:" + canonicalManifestV03HashHex(prev),
      height: prev.edition.height + 1,
    },
    zones: zoneEntries as ManifestV03["zones"],
    integrity: {
      sha256_of_did_json: didHashHex,
      manifest_signature: { alg: "ed25519", key: args.delegate.pubkeyMultibase, value: "" },
    },
  };

  return { manifest: signManifestV03Delegate(unsigned, args.delegate), blobs };
}
