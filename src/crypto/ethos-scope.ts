// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Ethos verb-scope grammar — browser-safe mirror of @aithos/protocol-core's
// `ethos-authz.ts` (the bits the client author needs). Kept inline here, like
// the rest of `crypto/*`, so the write/author path stays dependency-free and
// byte-faithful to the reference. Grammar (spec §4.8′):
//
//   ethos.<verb>.<zone>[#id=<id> | #prefix=<p> | #tag=<t>]
//   verb := read | edit | append | delete | write
//   zone := public | circle | self   (plus the legacy read-all: `all`)

export type EthosVerb = "read" | "edit" | "append" | "delete" | "write";

export interface ParsedEthosScope {
  readonly verb: EthosVerb;
  readonly zone: "public" | "circle" | "self" | "all";
  readonly selector:
    | { readonly kind: "all" }
    | { readonly kind: "id"; readonly id: string }
    | { readonly kind: "prefix"; readonly prefix: string }
    | { readonly kind: "tag"; readonly tag: string };
}

const VERBS: ReadonlySet<string> = new Set([
  "read",
  "edit",
  "append",
  "delete",
  "write",
]);
const ZONES: ReadonlySet<string> = new Set(["public", "circle", "self", "all"]);

/** Parse `ethos.<verb>.<zone>[#selector]`; null (fail-closed) if malformed. */
export function parseEthosScope(scope: string): ParsedEthosScope | null {
  if (!scope.startsWith("ethos.")) return null;
  const hash = scope.indexOf("#");
  const head = hash === -1 ? scope : scope.slice(0, hash);
  const parts = head.split(".");
  if (parts.length !== 3) return null;
  const verb = parts[1]!;
  const zone = parts[2]!;
  if (!VERBS.has(verb) || !ZONES.has(zone)) return null;
  if (zone === "all" && verb !== "read") return null;

  let selector: ParsedEthosScope["selector"];
  if (hash === -1) {
    selector = { kind: "all" };
  } else {
    const sel = scope.slice(hash + 1);
    if (sel === "" || zone === "all") return null;
    const eq = sel.indexOf("=");
    if (eq <= 0) return null;
    const k = sel.slice(0, eq);
    const v = sel.slice(eq + 1);
    if (v === "") return null;
    if (k === "id") selector = { kind: "id", id: v };
    else if (k === "prefix") selector = { kind: "prefix", prefix: v };
    else if (k === "tag") selector = { kind: "tag", tag: v };
    else return null;
  }
  return { verb: verb as EthosVerb, zone: zone as ParsedEthosScope["zone"], selector };
}

export interface SectionRef {
  readonly id: string;
  readonly tags?: readonly string[];
}

function matchSelector(section: SectionRef, sel: ParsedEthosScope["selector"]): boolean {
  switch (sel.kind) {
    case "all":
      return true;
    case "id":
      return section.id === sel.id;
    case "prefix":
      return section.id.startsWith(sel.prefix);
    case "tag":
      return !!section.tags && section.tags.includes(sel.tag);
  }
}

/**
 * §3.5.7′ — is the holder a recipient of `section` of `zone`? True iff it holds
 * a read-bearing verb (read/edit/append/write — `delete` does not bear read)
 * on `zone` whose selector matches the section.
 */
export function coversRead(
  scopes: readonly string[],
  zone: "public" | "circle" | "self",
  section: SectionRef,
): boolean {
  for (const s of scopes) {
    const p = parseEthosScope(s);
    if (!p) continue;
    if (p.verb === "delete") continue;
    if (p.zone !== "all" && p.zone !== zone) continue;
    if (matchSelector(section, p.selector)) return true;
  }
  return false;
}
