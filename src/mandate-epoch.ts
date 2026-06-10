// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Revocation EPOCH — the owner's one-write "revoke ALL mandates".
//
// Bumping `aithos.mandates_void_before` on the did.json voids every mandate
// whose `issued_at` predates it (protocol-core `verifyMandate` enforces it on
// both the read and write paths server-side). Unlike per-mandate revocations
// this needs no enumeration, scales O(1) with the number of outstanding
// mandates, and makes garbage-collecting individual revocation objects safe —
// the epoch subsumes them.
//
// The updated did.json is re-signed with the ROOT key (same proof shape the
// identity was born with: Ed25519 over the JCS-canonicalized doc with
// `proofValue: ""`), and POSTed via `aithos.set_mandates_epoch` inside a
// root-signed §11 envelope. The server enforces: root envelope, doc proof,
// keys/rotation history byte-identical to the stored doc, and epoch
// monotonicity.

import { readRpc } from "./api.js";
import { writeEndpoint } from "./endpoints.js";
import { buildSignedEnvelope } from "./crypto/envelope.js";
import { canonicalize } from "./crypto/canonical.js";
import { sign } from "./crypto/ed25519.js";
import { base64url } from "./crypto/encoding.js";
import { browserIdentityFromStored } from "./crypto/identity.js";
import { invalidateDelegateGrantsCache, invalidateIdentityCache } from "./perf-cache.js";
import type { StoredIdentity } from "./storage-types.js";

export class MandateEpochError extends Error {
  readonly step: string;
  readonly data?: Record<string, unknown>;
  constructor(step: string, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "MandateEpochError";
    this.step = step;
    this.data = data;
  }
}

/** The wire did.json shape we touch — everything else is carried verbatim. */
interface WireDidDocument {
  readonly id: string;
  readonly aithos?: { readonly mandates_void_before?: string } & Record<string, unknown>;
  readonly proof?: Record<string, unknown>;
  readonly [k: string]: unknown;
}

export interface SetMandatesEpochArgs {
  readonly identity: StoredIdentity;
  /** The epoch instant — defaults to now. Must be after any stored epoch. */
  readonly epoch?: Date;
}

export interface SetMandatesEpochResult {
  readonly did: string;
  /** ISO-8601 epoch now live on the did.json. */
  readonly mandatesVoidBefore: string;
}

/**
 * Void every mandate issued before `epoch` (default: now) in ONE root-signed
 * did.json write. Invalidates the local identity + delegate-grants caches on
 * success. Per-mandate revocation objects issued before the epoch become
 * redundant (safe to GC server-side).
 */
export async function setMandatesEpoch(
  args: SetMandatesEpochArgs,
): Promise<SetMandatesEpochResult> {
  const browserId = browserIdentityFromStored(args.identity);
  const did = browserId.did;

  // Fresh fetch on purpose (never through the perf cache): we must re-sign the
  // EXACT currently-stored doc, byte-shape included.
  const cur = await readRpc<{ object: WireDidDocument }>("aithos.get_identity", { did });
  const doc = cur.object;
  if (doc.id !== did) {
    throw new MandateEpochError("identity", `did.json id mismatch (${doc.id} != ${did})`);
  }

  const epochIso = (args.epoch ?? new Date()).toISOString();
  const stored = doc.aithos?.mandates_void_before;
  if (stored && Date.parse(epochIso) <= Date.parse(stored)) {
    throw new MandateEpochError(
      "epoch",
      `epoch must be after the stored one (stored=${stored}, requested=${epochIso})`,
      { stored, requested: epochIso },
    );
  }

  // Update the epoch, re-sign the proof with the ROOT key.
  const unsigned = {
    ...doc,
    aithos: { ...(doc.aithos ?? {}), mandates_void_before: epochIso },
    proof: { ...(doc.proof ?? {}), created: epochIso, proofValue: "" },
  };
  const sig = sign(new TextEncoder().encode(canonicalize(unsigned)), browserId.root.seed);
  const newDoc = { ...unsigned, proof: { ...unsigned.proof, proofValue: base64url(sig) } };

  const params = { new_did_document: newDoc };
  const envelope = buildSignedEnvelope({
    iss: did,
    aud: writeEndpoint(),
    method: "aithos.set_mandates_epoch",
    verificationMethod: `${did}#root`,
    params,
    signer: browserId.root,
  });

  const res = await fetch(writeEndpoint(), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "aithos.set_mandates_epoch",
      method: "aithos.set_mandates_epoch",
      params: { ...params, _envelope: envelope },
    }),
  });
  const body = (await res.json()) as {
    result?: unknown;
    error?: { code: number; message: string; data?: Record<string, unknown> };
  };
  if (body.error) {
    throw new MandateEpochError("set_mandates_epoch", body.error.message, {
      code: body.error.code,
      ...body.error.data,
    });
  }

  // The did.json and the active-grant set both changed.
  invalidateIdentityCache(did);
  invalidateDelegateGrantsCache(did);
  return { did, mandatesVoidBefore: epochIso };
}
