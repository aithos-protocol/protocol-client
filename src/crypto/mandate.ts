// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Client-side mandate signing.
//
// Mirrors protocol-core's `createMandate` in a browser-safe form: no
// node:crypto, no node:fs, no `ulid` dep. A signed mandate produced here
// is byte-identical to one produced by the reference CLI as far as the
// server-side `verifyMandate` is concerned (same canonicalization, same
// Ed25519 signature scheme, same verification method URL convention).
//
// Spec: §4.2 "Mandate envelope".

import { canonicalize } from "./canonical.js";
import { sign } from "./ed25519.js";
import { base64url } from "./encoding.js";
import type { BrowserIdentity, Sphere } from "./identity.js";
import { sphereDidUrl } from "./identity.js";

export const MANDATE_VERSION_CURRENT = "0.5.0" as const;

/**
 * Scopes a mandate may NEVER carry. Mirrors protocol-core's
 * `FORBIDDEN_SCOPES`. Surfaced here so the mint UI can block the user
 * BEFORE we call signMandate, which would otherwise reject them server
 * side.
 */
export const FORBIDDEN_SCOPES: ReadonlySet<string> = new Set([
  "mandate.issue",
  "mandate.revoke",
  "identity.rotate-keys",
  "identity.destroy",
]);

/**
 * Scopes implying a write operation. A mandate carrying any of these
 * MUST bind to a specific delegate key (grantee.pubkey), per §4.5.4.
 */
const WRITE_SCOPE_PREFIX = "ethos.write.";
function hasWriteScope(scopes: readonly string[]): boolean {
  return scopes.some((s) => s.startsWith(WRITE_SCOPE_PREFIX));
}

/**
 * Whether the scope set carries any `data.<collection>.append` scope.
 *
 * `append` is a lateral data capability (insert-only, no read) — mirrors
 * protocol-core `hasDataAppendScope`. Like write/compute mandates, an append
 * mandate MUST bind to a `grantee.pubkey`: the depositor signs every insert
 * envelope under it. Unlike read/write data mandates it needs no `kex_pubkey`
 * — the depositor seals each DEK to the owner's public key and keeps no read
 * capability.
 */
function hasDataAppendScope(scopes: readonly string[]): boolean {
  return scopes.some((s) => /^data\.[^.]+\.append$/.test(s));
}

export interface Grantee {
  readonly id: string;
  readonly label?: string;
  /** Ed25519 pubkey multibase (z…) — required for sealed-zone delegates. */
  readonly pubkey?: string;
}

export interface MandateConstraints {
  readonly domains?: readonly string[];
  readonly rate_limit?: Readonly<Record<string, number>>;
  readonly require_counter_sign?: readonly string[];
}

export interface SignedMandate {
  readonly "aithos-mandate": typeof MANDATE_VERSION_CURRENT;
  readonly id: string;
  readonly issuer: string;
  readonly issued_by_key: string;
  readonly grantee: Grantee;
  readonly actor_sphere: Sphere;
  readonly scopes: readonly string[];
  readonly constraints?: MandateConstraints;
  readonly not_before: string;
  readonly not_after: string;
  readonly issued_at: string;
  readonly nonce: string;
  readonly signature: {
    readonly alg: "ed25519";
    readonly key: string;
    readonly value: string;
  };
}

export interface SignMandateArgs {
  readonly issuer: BrowserIdentity;
  readonly actorSphere: Sphere;
  readonly grantee: Grantee;
  readonly scopes: readonly string[];
  readonly ttlSeconds: number;
  readonly constraints?: MandateConstraints;
  readonly notBefore?: Date;
}

/**
 * Build + sign a mandate in one pass. Throws if the caller passes
 * forbidden scopes or a write scope without grantee.pubkey.
 */
export function signMandate(args: SignMandateArgs): SignedMandate {
  for (const scope of args.scopes) {
    if (FORBIDDEN_SCOPES.has(scope)) {
      throw new Error(
        `scope "${scope}" can never be delegated (forbidden by §11.7)`,
      );
    }
  }
  if (hasWriteScope(args.scopes) && !args.grantee.pubkey) {
    throw new Error(
      `write mandate requires grantee.pubkey so the delegate signer can be bound (§4.5.4)`,
    );
  }
  if (hasDataAppendScope(args.scopes) && !args.grantee.pubkey) {
    throw new Error(
      `append mandate (data.<collection>.append) requires grantee.pubkey so the depositor's insert signer can be bound`,
    );
  }
  validateScopesAgainstSphere(args.scopes, args.actorSphere);

  const now = args.notBefore ?? new Date();
  const notAfter = new Date(now.getTime() + args.ttlSeconds * 1000);
  const nonceBytes = new Uint8Array(9); // 72 bits of entropy
  crypto.getRandomValues(nonceBytes);
  const nonce = base64url(nonceBytes);

  const keyUrl = sphereDidUrl(args.issuer, args.actorSphere);
  const unsigned = {
    "aithos-mandate": MANDATE_VERSION_CURRENT,
    id: `mandate_${generateUlid()}`,
    issuer: args.issuer.did,
    issued_by_key: keyUrl,
    grantee: args.grantee,
    actor_sphere: args.actorSphere,
    scopes: [...args.scopes],
    ...(args.constraints ? { constraints: args.constraints } : {}),
    not_before: now.toISOString(),
    not_after: notAfter.toISOString(),
    issued_at: new Date().toISOString(),
    nonce,
    signature: {
      alg: "ed25519" as const,
      key: keyUrl,
      value: "",
    },
  };

  const sigBytes = sign(
    new TextEncoder().encode(canonicalize(unsigned)),
    args.issuer[args.actorSphere].seed,
  );
  return {
    ...unsigned,
    signature: { ...unsigned.signature, value: base64url(sigBytes) },
  } as SignedMandate;
}

/** A §4.3 signed Revocation — references the mandate being revoked. */
export interface Revocation {
  readonly "aithos-revocation": "0.1.0";
  readonly mandate_id: string;
  readonly issuer: string;
  readonly issued_by_key: string;
  readonly revoked_at: string;
  readonly reason: string;
  readonly signature: {
    readonly alg: "ed25519";
    readonly key: string;
    readonly value: string;
  };
}

export interface SignRevocationArgs {
  readonly issuer: BrowserIdentity;
  /** The mandate being revoked — its `issuer` + `issued_by_key` drive the signature. */
  readonly mandate: Pick<SignedMandate, "id" | "issuer" | "issued_by_key">;
  /** Free-text reason; signed into the document (defaults to ""). */
  readonly reason?: string;
  readonly revokedAt?: Date;
}

/**
 * Build + sign a §4.3 Revocation — browser-safe mirror of protocol-core's
 * `createRevocation`. The signature MUST come from the SAME sphere key that
 * issued the mandate (`mandate.issued_by_key`), so the server resolves it in the
 * subject's DID document and `verifyRevocation` accepts it. `mandate_kind` is
 * omitted for the default `"action"` case (matching the reference), so the
 * canonical form is byte-identical.
 */
export function signRevocation(args: SignRevocationArgs): Revocation {
  const issuedBy = args.mandate.issued_by_key;
  const m = issuedBy.match(/#(public|circle|self)$/);
  if (!m) throw new Error(`cannot determine sphere from issued_by_key: ${issuedBy}`);
  const sphere = m[1] as Sphere;
  const unsigned = {
    "aithos-revocation": "0.1.0" as const,
    mandate_id: args.mandate.id,
    issuer: args.mandate.issuer,
    issued_by_key: issuedBy,
    revoked_at: (args.revokedAt ?? new Date()).toISOString(),
    reason: args.reason ?? "",
    signature: { alg: "ed25519" as const, key: issuedBy, value: "" },
  };
  const sigBytes = sign(
    new TextEncoder().encode(canonicalize(unsigned)),
    args.issuer[sphere].seed,
  );
  return { ...unsigned, signature: { ...unsigned.signature, value: base64url(sigBytes) } };
}

/**
 * Validate the scope → actor_sphere relationship. Mirrors protocol-core's
 * `validateScopesAgainstSphere` byte-for-byte so we fail client-side with
 * the same errors the server would emit. If we get any of this wrong,
 * `publish_mandate` will still reject the envelope — this is for UX.
 *
 * Rules:
 *   - Each `ethos.write.X` scope requires `actor_sphere === X` exactly
 *     (a self-sphere mandate cannot bundle a circle write, because the
 *     signing key must match the target zone).
 *   - The `public` sphere is heavily restricted: only
 *     `ethos.read.public`, `ethos.read.all`, `ethos.write.public`, and
 *     `gamma.read`. Any other scope is rejected.
 *   - For circle/self sphere, read scopes and gamma.read are unconstrained.
 */
/**
 * Minimal ethos-scope parse — `ethos.<verb>.<zone>[#selector]`. Returns null
 * for any non-ethos or malformed scope (fail-closed). A browser-safe subset of
 * protocol-core's `parseEthosScope`, kept inline so this mint path stays
 * dependency-free (see file header).
 */
function parseEthosVerbZone(s: string): { verb: string; zone: string } | null {
  if (!s.startsWith("ethos.")) return null;
  const hash = s.indexOf("#");
  const head = hash === -1 ? s : s.slice(0, hash);
  const parts = head.split(".");
  if (parts.length !== 3) return null;
  const verb = parts[1]!;
  const zone = parts[2]!;
  const verbs = new Set(["read", "edit", "append", "delete", "write"]);
  const zones = new Set(["public", "circle", "self", "all"]);
  if (!verbs.has(verb) || !zones.has(zone)) return null;
  if (zone === "all" && verb !== "read") return null;
  return { verb, zone };
}

const MUTATING_ETHOS_VERBS: ReadonlySet<string> = new Set([
  "edit",
  "append",
  "delete",
  "write",
]);

/**
 * Validate the scope → actor_sphere relationship. Mirrors protocol-core's
 * `validateScopesAgainstSphere` (v0.5 verb-scopes) so we fail client-side with
 * the same errors the server would emit. UX only — the server re-checks.
 *
 * Rules (§4.8′):
 *   - A mutating ethos verb (write/edit/append/delete) on zone Z requires
 *     `actor_sphere === Z` (the signing key must match the target zone).
 *   - The `public` sphere allows only `ethos.<verb>.public` / `ethos.read.all`,
 *     `gamma.read`, `compute.invoke`, and `data.*` scopes.
 *   - A circle mandate cannot carry any ethos scope on the `self` zone.
 */
function validateScopesAgainstSphere(
  scopes: readonly string[],
  sphere: Sphere,
): void {
  for (const s of scopes) {
    const p = parseEthosVerbZone(s);
    if (p && p.zone !== "all" && MUTATING_ETHOS_VERBS.has(p.verb) && sphere !== p.zone) {
      throw new Error(`scope ${s} requires actor_sphere=${p.zone} (got ${sphere})`);
    }
  }
  if (sphere === "public") {
    for (const s of scopes) {
      const p = parseEthosVerbZone(s);
      const ok =
        (p !== null && (p.zone === "public" || p.zone === "all")) ||
        s === "gamma.read" ||
        s === "compute.invoke" ||
        // Data scopes (`data.<collection>.<action>`) are sphere-neutral and
        // permitted under every sphere — keep in lockstep with protocol-core.
        s.startsWith("data.") ||
        // Connector scopes (`mcp.<server>.<…>`) are likewise sphere-neutral: the
        // access axis is the connector (gated at the gateway), not an ethos zone.
        s.startsWith("mcp.");
      if (!ok) {
        throw new Error(`scope ${s} is not permitted for the public sphere`);
      }
    }
  }
  if (sphere === "circle") {
    for (const s of scopes) {
      const p = parseEthosVerbZone(s);
      if (p && p.zone === "self") {
        throw new Error(`scope ${s} (zone self) cannot be granted on a circle mandate`);
      }
    }
  }
}

/* -------------------------------------------------------------------------- */
/*  ULID (monotonic-ish, browser-safe)                                        */
/* -------------------------------------------------------------------------- */

// Crockford base32 alphabet — matches the ULID spec.
const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Generate a 26-char ULID.
 *
 * 48-bit timestamp (10 chars) + 80-bit randomness (16 chars). We don't
 * bother with per-process monotonic guarantees — mandate ids have enough
 * randomness to never collide across a browser session.
 */
export function generateUlid(): string {
  const ts = Date.now();
  const timeChars = new Array<string>(10);
  let t = ts;
  for (let i = 9; i >= 0; i--) {
    timeChars[i] = ULID_ALPHABET[t & 0x1f]!;
    t = Math.floor(t / 32);
  }
  const rnd = new Uint8Array(10);
  crypto.getRandomValues(rnd);
  const rndChars = new Array<string>(16);
  // 10 bytes = 80 bits. Encode as 16 base32 chars (5 bits each).
  let bitBuf = 0;
  let bitLen = 0;
  let outIdx = 0;
  for (let i = 0; i < rnd.length; i++) {
    bitBuf = (bitBuf << 8) | rnd[i]!;
    bitLen += 8;
    while (bitLen >= 5) {
      bitLen -= 5;
      const v = (bitBuf >> bitLen) & 0x1f;
      rndChars[outIdx++] = ULID_ALPHABET[v]!;
    }
  }
  return timeChars.join("") + rndChars.join("");
}