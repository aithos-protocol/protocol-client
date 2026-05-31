// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

/**
 * Safety gate for unifying canonicalization onto @aithos/protocol-core.
 *
 * protocol-client's `src/crypto/canonical.ts` used to carry a hand-ported JCS
 * implementation; it now re-exports core's `canonicalize`. Because this function
 * computes the bytes that envelope signatures, mandate signatures and ethos
 * edition hashes commit to, the swap MUST be byte-identical for the inputs the
 * client actually produces. This test proves that against a representative
 * corpus.
 *
 * Accepted, documented divergence: an `undefined` object VALUE. core throws
 * (RFC 8785 §3.2.2 rejects undefined); the old ported copy silently skipped the
 * key. Aithos payloads are well-formed JSON and never carry undefined values,
 * so the corpus excludes that case by design.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { canonicalize } from "../src/crypto/canonical.js"; // now re-exports core

/** Verbatim copy of the FORMER ported implementation (pre-unification ref). */
function portedCanonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonicalize: non-finite numbers are not JSON-representable");
    }
    return String(value);
  }
  if (typeof value === "string") return serializeString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(portedCanonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      if (obj[k] === undefined) continue;
      parts.push(serializeString(k) + ":" + portedCanonicalize(obj[k]));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`canonicalize: unsupported type ${typeof value}`);
}

function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x09) out += "\\t";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0d) out += "\\r";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += s[i];
  }
  return out + '"';
}

const corpus: unknown[] = [
  null,
  true,
  false,
  0,
  -1,
  42,
  Number.MAX_SAFE_INTEGER,
  "",
  "hello",
  'with "quotes" and \\ backslash',
  "tab\tnewline\nreturn\rbackspace\bform\f",
  "accented éàùçö and emoji 😀🚀 and 漢字",
  "slash / at @ pipe |",
  [],
  [1, 2, 3],
  ["z", "a", "m"],
  [{ b: 1, a: 2 }, [3, [4, 5]]],
  {},
  { b: 2, a: 1, c: 3 },
  { z: { y: { x: [1, "two", false, null] } } },
  { "key with spaces": 1, "weird:char": 2, "": "empty key" },
  { émoji: "😀", "漢字": 1, A: 0, a: 0 },
  // A mandate-shaped object (what mint canonicalizes for signing).
  {
    "aithos-mandate": "0.3.0",
    issuer: "did:aithos:z6MkExample",
    scopes: ["ethos.read.public", "data.col.read"],
    not_before: "2026-01-01T00:00:00.000Z",
    not_after: "2026-12-31T23:59:59.000Z",
    grantee: { pubkey: "z6MkDelegateKey" },
    signature: { alg: "ed25519", key: "did:aithos:z6MkExample#public", value: "" },
  },
];

describe("canonicalize conformance — core re-export vs former ported copy", () => {
  for (const [i, value] of corpus.entries()) {
    it(`corpus[${i}] is byte-identical`, () => {
      assert.equal(canonicalize(value), portedCanonicalize(value));
    });
  }
});
