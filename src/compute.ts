// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Bedrock compute proxy client — browser side.
//
// The compute proxy at compute.aithos.be is the sole holder of
// `bedrock:InvokeModel` in the Aithos infrastructure. Apps invoke it through
// signed envelopes whose signing key is the user's public-sphere key, with a
// `mandateId` referencing the user's consent for this app to spend their
// wallet.
//
// MVP scope: single-shot Bedrock invocation. Multi-turn agentic loops with
// native tool calling will land in a follow-up release once the proxy
// supports them server-side. For now, multi-turn conversations are managed
// client-side by the app: append assistant response to messages, call
// `invokeBedrock` again.

import { buildSignedEnvelope } from "./crypto/envelope.js";
import type { BrowserIdentity } from "./crypto/identity.js";

/** Default base URL for the Aithos compute proxy. */
export const DEFAULT_COMPUTE_ENDPOINT = "https://compute.aithos.be";

export interface ComputeMessage {
  readonly role: "user" | "assistant";
  readonly content: string;
}

export interface InvokeBedrockArgs {
  /** User identity. The lib signs the envelope with `identity.public`. */
  readonly identity: BrowserIdentity;
  /** DID of the app making the call (declared in the mandate). */
  readonly appDid: string;
  /** Mandate ID granting this app the right to spend the user's wallet. */
  readonly mandateId: string;
  /** Bedrock model id, e.g. `"anthropic.claude-3-5-sonnet"`. */
  readonly model: string;
  /** Conversation messages (user / assistant turns). */
  readonly messages: readonly ComputeMessage[];
  /** Optional system prompt (Bedrock convention — sent as a separate field). */
  readonly system?: string;
  /** Hard cap on output tokens for this call. Server will further cap by mandate. */
  readonly maxTokens?: number;
  /** Sampling temperature. Default model-dependent. */
  readonly temperature?: number;
  /** Idempotency key for retries. The lib generates one if omitted. */
  readonly idempotencyKey?: string;
  /**
   * Override the default `https://compute.aithos.be` base URL. Reserved for
   * test injection at this stage; the public API does not yet support
   * pluggable endpoints (see PLATFORM-COMPUTE-DESIGN.md §"Posture
   * open-source et contrat de stabilité").
   */
  readonly endpoint?: string;
  /** Abort signal to cancel the request. */
  readonly signal?: AbortSignal;
}

export type StopReason = "end_turn" | "max_tokens" | "stop_sequence";

export interface InvokeBedrockResult {
  /** Plain text response from the model. */
  readonly content: string;
  /** Why the model stopped generating. */
  readonly stopReason: StopReason;
  /** Token accounting from the model. */
  readonly usage: {
    readonly inputTokens: number;
    readonly outputTokens: number;
  };
  /** Microcredits debited from the user wallet for this call. */
  readonly creditsCharged: number;
  /** New wallet balance (microcredits) after debit. */
  readonly walletBalance: number;
  /** Audit log id for traceability. */
  readonly auditId: string;
}

export class ComputeError extends Error {
  readonly code: string;
  readonly data: Record<string, unknown> | undefined;

  constructor(code: string, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "ComputeError";
    this.code = code;
    this.data = data;
  }
}

/**
 * Invoke a Bedrock model through the Aithos compute proxy.
 *
 * Builds a signed envelope (signed by the user's public-sphere key) carrying
 * the request, posts it to `${endpoint}/v1/invoke`, and returns the model's
 * response along with billing metadata.
 *
 * Server-side, the proxy:
 *   - Verifies the envelope signature against the user's `did.json`.
 *   - Verifies the mandate at `mandateId` authorizes `appDid` for this model.
 *   - Checks wallet balance and quota (per-call, daily, total).
 *   - Calls Bedrock `InvokeModel`.
 *   - Debits the wallet (atomic conditional update).
 *   - Splits the markup 90/10 between dev wallet and Aithos revenue.
 *   - Returns the model's response + billing metadata.
 *
 * Throws {@link ComputeError} with a `code` tag on protocol errors so callers
 * can branch on (e.g.) `quota_exceeded` vs `mandate_revoked` vs `network`.
 */
export async function invokeBedrock(
  args: InvokeBedrockArgs,
): Promise<InvokeBedrockResult> {
  const baseUrl = args.endpoint ?? DEFAULT_COMPUTE_ENDPOINT;
  const fullUrl = `${baseUrl}/v1/invoke`;
  const idempotencyKey = args.idempotencyKey ?? generateIdempotencyKey();

  // Params that `params_hash` commits to. Optional fields are conditionally
  // included so the canonicalization is stable across calls that omit them.
  const params: Record<string, unknown> = {
    app_did: args.appDid,
    mandate_id: args.mandateId,
    model: args.model,
    messages: args.messages,
    idempotency_key: idempotencyKey,
  };
  if (args.system !== undefined) params.system = args.system;
  if (args.maxTokens !== undefined) params.max_tokens = args.maxTokens;
  if (args.temperature !== undefined) params.temperature = args.temperature;

  // Sign with the user's public-sphere key — `compute:bedrock` is conceptually
  // a public-zone-side action (the model output is what gets written, when it
  // gets written, into a public-sphere section). Consistent with the §11 spec.
  const envelope = buildSignedEnvelope({
    iss: args.identity.did,
    aud: fullUrl,
    method: "aithos.compute_invoke",
    verificationMethod: `${args.identity.did}#public`,
    params,
    signer: args.identity.public,
  });

  let res: Response;
  try {
    res = await fetch(fullUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "aithos.compute_invoke",
        method: "aithos.compute_invoke",
        params: { ...params, _envelope: envelope },
      }),
      ...(args.signal ? { signal: args.signal } : {}),
    });
  } catch (e) {
    throw new ComputeError("network", (e as Error).message);
  }

  if (!res.ok) {
    throw new ComputeError("http", `HTTP ${res.status} ${res.statusText}`);
  }

  const body = (await res.json()) as {
    result?: InvokeBedrockResult;
    error?: { code: number; message: string; data?: Record<string, unknown> };
  };

  if (body.error) {
    throw new ComputeError(
      String(body.error.code),
      body.error.message,
      body.error.data,
    );
  }

  if (!body.result) {
    throw new ComputeError("empty", "empty result from compute proxy");
  }

  return body.result;
}

function generateIdempotencyKey(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}
