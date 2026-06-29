// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Onboarding orchestration — browser-side.
//
// Given a handle, display name, and first public section body, this module:
//   1. generates a fresh identity (4 Ed25519 keypairs in memory)
//   2. signs the did.json
//   3. posts `aithos.publish_identity` with a root-signed envelope
//   4. builds + signs the first v0.3 edition (per-section, public zone)
//   5. posts `aithos.publish_ethos_edition` with a public-sphere-signed envelope
//   6. returns the identity + metadata so the UI can render a success page and
//      offer a recovery-file download

import {
  createBrowserIdentity,
  signedDidDocument,
  type BrowserIdentity,
  type DidDocument,
} from "./crypto/identity.js";
import { addSectionToList } from "./editor.js";
import { createEditionV04Owner } from "./editor-v04.js";
import type { StoredIdentity } from "./storage-types.js";
import type { ManifestV04 } from "@aithos/protocol-core";
import { buildSignedEnvelope } from "./crypto/envelope.js";
import { writeEndpoint } from "./endpoints.js";

export interface OnboardArgs {
  readonly handle: string;
  readonly displayName: string;
  readonly publicTitle: string;
  readonly publicBody: string;
  readonly tags?: readonly string[];
}

export interface OnboardResult {
  readonly identity: BrowserIdentity;
  readonly didDocument: DidDocument;
  readonly manifest: ManifestV04;
  readonly recoveryBlob: Blob;
}

export class OnboardError extends Error {
  readonly step: "publish_identity" | "publish_ethos_edition" | "network" | "validation";
  readonly data: Record<string, unknown> | undefined;

  constructor(step: OnboardError["step"], message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "OnboardError";
    this.step = step;
    this.data = data;
  }
}

/**
 * Run the full onboarding flow. Returns the new identity + signed docs.
 * Throws {@link OnboardError} with a `step` tag if any stage fails.
 */
export async function runOnboarding(args: OnboardArgs): Promise<OnboardResult> {
  if (!/^[a-z0-9][a-z0-9_-]{0,62}$/i.test(args.handle)) {
    throw new OnboardError(
      "validation",
      "handle must be 1-63 chars, alphanumerics + '-' / '_' only",
    );
  }
  if (!args.publicTitle.trim()) {
    throw new OnboardError("validation", "public title cannot be empty");
  }

  /* ---- 1. fresh identity ---- */
  const identity = createBrowserIdentity(args.handle, args.displayName);

  /* ---- 2. signed did.json ---- */
  const signedDoc = signedDidDocument(identity);

  /* ---- 3. POST publish_identity ---- */
  const publishIdentityParams = {
    did_document: signedDoc,
    handle: identity.handle,
    display_name: identity.displayName,
  };
  const identityEnv = buildSignedEnvelope({
    iss: identity.did,
    aud: writeEndpoint(),
    method: "aithos.publish_identity",
    verificationMethod: `${identity.did}#root`,
    params: publishIdentityParams,
    signer: identity.root,
  });
  await callWrite(
    "aithos.publish_identity",
    { ...publishIdentityParams, _envelope: identityEnv },
    "publish_identity",
  );

  /* ---- 4+5. first edition (v0.4 per-section, content-addressed) + publish ---- */
  // v0.4 is the latest Ethos format and the platform default — author the very
  // first edition directly in v0.4 (height=1, no predecessor), so brand-new
  // accounts are born v0.4 without ever touching the v0.3→v0.4 migration path.
  // Same did-hash convention the server enforces: JSON.stringify(doc, null, 2)+"\n".
  const didJson = new TextEncoder().encode(JSON.stringify(signedDoc, null, 2) + "\n");
  const publicSections = addSectionToList([], {
    title: args.publicTitle,
    body: args.publicBody,
    ...(args.tags && args.tags.length > 0 ? { tags: args.tags } : {}),
  });
  const owner: StoredIdentity = {
    version: "0.1.0",
    handle: identity.handle,
    displayName: identity.displayName,
    did: identity.did,
    seeds: {
      root: bytesToHexLocal(identity.root.seed),
      public: bytesToHexLocal(identity.public.seed),
      circle: bytesToHexLocal(identity.circle.seed),
      self: bytesToHexLocal(identity.self.seed),
      ...(identity.data ? { data: bytesToHexLocal(identity.data.seed) } : {}),
    },
    savedAt: new Date().toISOString(),
  };
  let manifest: ManifestV04;
  try {
    const res = await createEditionV04Owner({
      did: identity.did,
      owner,
      handle: identity.handle,
      displayName: identity.displayName,
      sections: { public: publicSections },
      didJson,
    });
    manifest = res.manifest;
  } catch (e) {
    const err = e as { message?: string; code?: number; data?: Record<string, unknown> };
    throw new OnboardError(
      "publish_ethos_edition",
      err.message ?? "publish_ethos_edition failed",
      err.code !== undefined ? { code: err.code, ...(err.data ?? {}) } : err.data,
    );
  }

  /* ---- 6. recovery blob (plaintext v1; encrypted in a follow-up) ---- */
  const recovery = {
    aithos_recovery_version: "0.1.0-plaintext",
    warning:
      "THIS FILE CONTAINS YOUR PRIVATE KEYS IN PLAINTEXT. Store it offline, never email or upload.",
    handle: identity.handle,
    display_name: identity.displayName,
    did: identity.did,
    created_at: new Date().toISOString(),
    seeds_hex: {
      root: bytesToHexLocal(identity.root.seed),
      public: bytesToHexLocal(identity.public.seed),
      circle: bytesToHexLocal(identity.circle.seed),
      self: bytesToHexLocal(identity.self.seed),
      ...(identity.data
        ? { data: bytesToHexLocal(identity.data.seed) }
        : {}),
    },
    public_keys_multibase: {
      // Informational, redundant with did.json but useful for quick reconnects
      // without re-deriving via @noble/ed25519 offline.
    },
  };
  const recoveryBlob = new Blob([JSON.stringify(recovery, null, 2) + "\n"], {
    type: "application/json",
  });

  return { identity, didDocument: signedDoc, manifest, recoveryBlob };
}

/* -------------------------------------------------------------------------- */
/*  internals                                                                 */
/* -------------------------------------------------------------------------- */

async function callWrite(
  method: string,
  params: unknown,
  step: OnboardError["step"],
): Promise<void> {
  let res: Response;
  try {
    res = await fetch(writeEndpoint(), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: method,
        method,
        params,
      }),
    });
  } catch (e) {
    throw new OnboardError("network", (e as Error).message);
  }
  const body = (await res.json()) as {
    result?: unknown;
    error?: { code: number; message: string; data?: Record<string, unknown> };
  };
  if (body.error) {
    throw new OnboardError(step, `${method} failed: ${body.error.message}`, {
      code: body.error.code,
      ...body.error.data,
    });
  }
  if (body.result === undefined) {
    throw new OnboardError(step, `${method} returned no result`);
  }
}

/** Standard base64 with `=` padding — matches `Buffer.from(x).toString("base64")`. */
function bytesToBase64Std(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

function bytesToHexLocal(b: Uint8Array): string {
  let out = "";
  for (let i = 0; i < b.length; i++) out += b[i]!.toString(16).padStart(2, "0");
  return out;
}