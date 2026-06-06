// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// v0.3 per-section bundle — READ half (browser mirror of @aithos/protocol-core's
// `bundle-v03.ts`). Every constant (AAD prefixes, wrap construction, markdown
// form) is kept byte-identical with the reference so a section sealed by the CLI
// / API opens here exactly.
//
// These functions are PURE and transport-agnostic: the caller fetches the
// manifest and the per-section blob bytes (from the API/CDN) and passes them in.
// The index needs only the manifest (the self title lives in `title_cipher`,
// whose ciphertext is embedded); a section body additionally needs its blob.
//
// Layout recap (spec §3, v0.3):
//   manifest.json            aithos: "0.3.0", zones[z].sections[] descriptors
//   public/<id>.md           plaintext section markdown
//   circle|self/<id>.enc     XChaCha20-Poly1305 ciphertext of the markdown
//
// Section AEAD AAD = "aithos-section-v1\0" ‖ subject_did ‖ "\0" ‖ section_id
// Title  AEAD AAD = "aithos-title-v1\0"   ‖ subject_did ‖ "\0" ‖ section_id
// DEK wrap = identical to the v0.2 zone wrap (x25519-hkdf-sha256-aead).

import { xchacha20poly1305 } from "@noble/ciphers/chacha";

import { base64urlDecode } from "./encoding.js";
import { edSeedToX25519Secret } from "./kex.js";
import { unwrapDek, type WrapEntry } from "./decrypt.js";
import type { Section } from "./manifest.js";

const SECTION_AAD_PREFIX = new TextEncoder().encode("aithos-section-v1\0");
const TITLE_AAD_PREFIX = new TextEncoder().encode("aithos-title-v1\0");
const NUL = new Uint8Array([0]);

/* -------------------------------------------------------------------------- */
/*  v0.3 manifest types                                                       */
/* -------------------------------------------------------------------------- */

export interface SectionCipher {
  readonly alg: "xchacha20poly1305-ietf";
  readonly nonce: string; // base64url
  readonly wraps: readonly WrapEntry[];
}

export interface SectionTitle {
  readonly title: string;
  readonly tags?: readonly string[];
}

export interface TitleCipher {
  readonly alg: "xchacha20poly1305-ietf";
  readonly nonce: string; // base64url
  readonly wraps: readonly WrapEntry[];
  readonly ct: string; // base64url — the sealed jcs({title, tags?})
}

export interface SectionDescriptor {
  readonly section_id: string;
  /** Relative path of the blob: `public/<id>.md` or `circle|self/<id>.enc`. */
  readonly file: string;
  readonly sha256_of_plaintext: string;
  readonly gamma_ref: string;
  /** Clear title (public / circle). Absent on the encrypted self index. */
  readonly title?: string;
  readonly tags?: readonly string[];
  /** Present on encrypted-zone sections (circle / self). */
  readonly cipher?: SectionCipher;
  /** Present only on the encrypted self index — the sealed title/tags. */
  readonly title_cipher?: TitleCipher;
}

export interface BundleZoneV2 {
  readonly format_version: "v2";
  readonly encrypted: boolean;
  /** True for the `self` index: titles are sealed in `title_cipher`. */
  readonly index_encrypted?: boolean;
  readonly sections: readonly SectionDescriptor[];
}

export interface ManifestV03 {
  readonly aithos: "0.3.0";
  readonly bundle_id: string;
  readonly subject_did: string;
  readonly subject_handle: string;
  readonly display_name: string;
  readonly edition: {
    readonly version: string;
    readonly created_at: string;
    readonly supersedes: string | null;
    readonly prev_hash: string | null;
    readonly height: number;
  };
  readonly zones: {
    readonly public?: BundleZoneV2;
    readonly circle?: BundleZoneV2;
    readonly self?: BundleZoneV2;
  };
  readonly gamma?: unknown;
  readonly integrity: {
    readonly sha256_of_did_json: string;
    readonly manifest_signature: unknown;
  };
}

export type SphereName = "public" | "circle" | "self";

/** True when a parsed manifest is the v0.3 per-section format. */
export function isV03Manifest(m: { aithos?: unknown } | null | undefined): m is ManifestV03 {
  return !!m && (m as { aithos?: unknown }).aithos === "0.3.0";
}

/* -------------------------------------------------------------------------- */
/*  Reader credentials                                                        */
/* -------------------------------------------------------------------------- */

export interface SectionReader {
  /** DID URL the reader claims (the wrap `recipient`). */
  readonly didUrl: string;
  /** X25519 secret (clamped), e.g. via {@link edSeedToX25519Secret}. */
  readonly x25519Secret: Uint8Array;
}

/** Owner reader for an encrypted zone: `${subject_did}#${sphere}-kex`. */
export function ownerSectionReader(
  subjectDid: string,
  sphere: "circle" | "self",
  sphereSeed: Uint8Array,
): SectionReader {
  return { didUrl: `${subjectDid}#${sphere}-kex`, x25519Secret: edSeedToX25519Secret(sphereSeed) };
}

/** Delegate reader: the wrap recipient id is `${granteeId}#${pubkeyMultibase}`. */
export function delegateSectionReader(
  granteeId: string,
  granteePubkeyMultibase: string,
  delegateSeed: Uint8Array,
): SectionReader {
  return {
    didUrl: `${granteeId}#${granteePubkeyMultibase}`,
    x25519Secret: edSeedToX25519Secret(delegateSeed),
  };
}

/* -------------------------------------------------------------------------- */
/*  AEAD: section body + title                                                */
/* -------------------------------------------------------------------------- */

function sectionAad(subjectDid: string, sectionId: string): Uint8Array {
  const enc = new TextEncoder();
  return concatBytes(SECTION_AAD_PREFIX, enc.encode(subjectDid), NUL, enc.encode(sectionId));
}

function titleAad(subjectDid: string, sectionId: string): Uint8Array {
  const enc = new TextEncoder();
  return concatBytes(TITLE_AAD_PREFIX, enc.encode(subjectDid), NUL, enc.encode(sectionId));
}

/** Decrypt one section's body ciphertext to its markdown form. Throws on no-wrap / tamper. */
export function decryptSection(
  ciphertext: Uint8Array,
  cipher: SectionCipher,
  subjectDid: string,
  sectionId: string,
  reader: SectionReader,
): string {
  const wrap = cipher.wraps.find((w) => w.recipient === reader.didUrl);
  if (!wrap) throw new Error(`no wrap entry for ${reader.didUrl} on section ${sectionId}`);
  const dek = unwrapDek(wrap, reader.x25519Secret);
  try {
    const aad = sectionAad(subjectDid, sectionId);
    const aead = xchacha20poly1305(dek, base64urlDecode(cipher.nonce), aad);
    return new TextDecoder().decode(aead.decrypt(ciphertext));
  } finally {
    dek.fill(0);
  }
}

/** Decrypt a section's sealed title/tags ({@link TitleCipher}). Throws on no-wrap / tamper. */
export function decryptSectionTitle(
  title: TitleCipher,
  subjectDid: string,
  sectionId: string,
  reader: SectionReader,
): SectionTitle {
  const wrap = title.wraps.find((w) => w.recipient === reader.didUrl);
  if (!wrap) throw new Error(`no title wrap for ${reader.didUrl} on section ${sectionId}`);
  const dek = unwrapDek(wrap, reader.x25519Secret);
  try {
    const aad = titleAad(subjectDid, sectionId);
    const aead = xchacha20poly1305(dek, base64urlDecode(title.nonce), aad);
    const pt = aead.decrypt(base64urlDecode(title.ct));
    return JSON.parse(new TextDecoder().decode(pt)) as SectionTitle;
  } finally {
    dek.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  Section markdown <-> structured                                           */
/* -------------------------------------------------------------------------- */

/** Inverse of protocol-core's `renderSectionMarkdown` (§3.4.5′). */
export function parseSectionMarkdown(md: string): { title: string; body: string; tags?: string[] } {
  const header = md.match(/^# (.+?)\s*\n/);
  if (!header) throw new Error("section markdown missing '# <title>' heading");
  const title = (header[1] ?? "").trim();
  let rest = md.slice(header[0].length);
  let tags: string[] | undefined;
  const tagsMatch = rest.match(/^<!-- tags:\s*(\[.*?\])\s*-->\s*\n/);
  if (tagsMatch) {
    try {
      tags = JSON.parse(tagsMatch[1] ?? "[]") as string[];
    } catch {
      /* ignore malformed tags */
    }
    rest = rest.slice(tagsMatch[0].length);
  }
  const body = rest.replace(/^\n+/, "").replace(/\s+$/, "");
  return { title, body, ...(tags ? { tags } : {}) };
}

/* -------------------------------------------------------------------------- */
/*  Zone index (id + title + provenance, no body)                             */
/* -------------------------------------------------------------------------- */

export interface IndexRow {
  readonly section_id: string;
  readonly title?: string;
  readonly tags?: readonly string[];
  /** True when the title is sealed and this reader can't open it (host view). */
  readonly title_hidden: boolean;
  readonly gamma_ref: string;
}

/**
 * Resolve a zone's section index for display. Clear-index zones (public, circle)
 * return titles directly. For the encrypted self index, each title is decrypted
 * from its own `title_cipher` when `reader` is one of its recipients — so a
 * section-scoped delegate sees exactly the titles it can read, a host sees none.
 */
export function readZoneIndex(
  zone: BundleZoneV2,
  subjectDid: string,
  reader?: SectionReader,
): IndexRow[] {
  if (!zone.index_encrypted) {
    return zone.sections.map((s) => ({
      section_id: s.section_id,
      ...(s.title !== undefined ? { title: s.title } : {}),
      ...(s.tags ? { tags: s.tags } : {}),
      title_hidden: false,
      gamma_ref: s.gamma_ref,
    }));
  }
  return zone.sections.map((s) => {
    if (reader && s.title_cipher) {
      try {
        const meta = decryptSectionTitle(s.title_cipher, subjectDid, s.section_id, reader);
        return {
          section_id: s.section_id,
          title: meta.title,
          ...(meta.tags ? { tags: meta.tags } : {}),
          title_hidden: false,
          gamma_ref: s.gamma_ref,
        };
      } catch {
        /* not a recipient of this section → hidden */
      }
    }
    return { section_id: s.section_id, title_hidden: true, gamma_ref: s.gamma_ref };
  });
}

/* -------------------------------------------------------------------------- */
/*  Read one section (descriptor + fetched blob bytes)                        */
/* -------------------------------------------------------------------------- */

export interface SectionReadResult {
  readonly accessible: boolean;
  readonly section?: Section;
  readonly reason?: string;
}

/**
 * Decode one section from its manifest descriptor + the fetched blob bytes.
 * `blob` is the plaintext markdown for `public`, or the `.enc` ciphertext for
 * `circle` / `self` (decrypted with `reader`). Returns `accessible:false` with a
 * `reason` when the reader is not a recipient or the bytes don't authenticate.
 */
export function readSection(
  zone: BundleZoneV2,
  descriptor: SectionDescriptor,
  blob: Uint8Array,
  subjectDid: string,
  reader?: SectionReader,
): SectionReadResult {
  try {
    let md: string;
    if (!zone.encrypted) {
      md = new TextDecoder().decode(blob);
    } else {
      if (!descriptor.cipher) return { accessible: false, reason: "encrypted section has no cipher block" };
      if (!reader) return { accessible: false, reason: "no reader key for an encrypted section" };
      if (!descriptor.cipher.wraps.some((w) => w.recipient === reader.didUrl)) {
        return { accessible: false, reason: "reader is not a recipient of this section" };
      }
      md = decryptSection(blob, descriptor.cipher, subjectDid, descriptor.section_id, reader);
    }
    const parsed = parseSectionMarkdown(md);
    return {
      accessible: true,
      section: {
        id: descriptor.section_id,
        title: parsed.title,
        body: parsed.body,
        ...(parsed.tags ? { tags: parsed.tags } : {}),
        gamma_ref: descriptor.gamma_ref,
      },
    };
  } catch (e) {
    return { accessible: false, reason: (e as Error).message };
  }
}

/** Locate which zone a section id lives in (manifest-only). */
export function locateSection(manifest: ManifestV03, sectionId: string): SphereName | null {
  for (const z of ["public", "circle", "self"] as const) {
    if (manifest.zones[z]?.sections.some((s) => s.section_id === sectionId)) return z;
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/*  internals                                                                 */
/* -------------------------------------------------------------------------- */

function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
