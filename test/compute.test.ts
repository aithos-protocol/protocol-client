// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Tests for the compute proxy client (`src/compute.ts`).
//
// We don't hit the real `compute.aithos.be` here. Instead we mock
// `globalThis.fetch` to capture the request the lib makes, assert on its
// shape (signed envelope, JSON-RPC wrapping, params), and inject canned
// responses to exercise the success/error branches.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ComputeError,
  DEFAULT_COMPUTE_ENDPOINT,
  invokeBedrock,
  type InvokeBedrockResult,
} from "../src/compute.js";
import { createBrowserIdentity } from "../src/crypto/identity.js";

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

function makeIdentity() {
  return createBrowserIdentity("alice", "Alice Anonymous");
}

function makeOkResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function captureFetch(handler: (url: string, init: RequestInit) => Response) {
  const calls: { url: string; init: RequestInit }[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const initFinal = init ?? {};
    calls.push({ url, init: initFinal });
    return handler(url, initFinal);
  }) as typeof globalThis.fetch;
  return {
    calls,
    restore() {
      globalThis.fetch = originalFetch;
    },
  };
}

const SAMPLE_RESULT: InvokeBedrockResult = {
  content: "Hello Mathieu, this is a test response.",
  stopReason: "end_turn",
  usage: { inputTokens: 12, outputTokens: 18 },
  creditsCharged: 1200,
  walletBalance: 98_800,
  auditId: "audit:test:abc123",
};

/* -------------------------------------------------------------------------- */
/*  Happy path                                                                */
/* -------------------------------------------------------------------------- */

test("invokeBedrock — posts a JSON-RPC request to /v1/invoke with a signed envelope", async () => {
  const identity = makeIdentity();
  const captured = captureFetch(() =>
    makeOkResponse({ jsonrpc: "2.0", id: "x", result: SAMPLE_RESULT }),
  );

  try {
    const result = await invokeBedrock({
      identity,
      appDid: "did:aithos:app-test",
      mandateId: "mnd:test:001",
      model: "anthropic.claude-3-5-sonnet",
      messages: [{ role: "user", content: "Bonjour." }],
      system: "Tu es un agent de test.",
      maxTokens: 200,
      idempotencyKey: "fixed-key-for-determinism",
    });

    // Result is parsed correctly.
    assert.deepEqual(result, SAMPLE_RESULT);
  } finally {
    captured.restore();
  }

  // Exactly one HTTP call.
  assert.equal(captured.calls.length, 1);

  const call = captured.calls[0]!;
  assert.equal(call.url, `${DEFAULT_COMPUTE_ENDPOINT}/v1/invoke`);
  assert.equal(call.init.method, "POST");
  assert.equal(
    (call.init.headers as Record<string, string>)["content-type"],
    "application/json",
  );

  const body = JSON.parse(String(call.init.body)) as {
    jsonrpc: string;
    method: string;
    params: {
      app_did: string;
      mandate_id: string;
      model: string;
      messages: { role: string; content: string }[];
      system?: string;
      max_tokens?: number;
      idempotency_key: string;
      _envelope: {
        iss: string;
        aud: string;
        method: string;
        params_hash: string;
        proof: { verificationMethod: string; proofValue: string };
      };
    };
  };

  // JSON-RPC wrapper.
  assert.equal(body.jsonrpc, "2.0");
  assert.equal(body.method, "aithos.compute_invoke");

  // Params shape.
  assert.equal(body.params.app_did, "did:aithos:app-test");
  assert.equal(body.params.mandate_id, "mnd:test:001");
  assert.equal(body.params.model, "anthropic.claude-3-5-sonnet");
  assert.deepEqual(body.params.messages, [
    { role: "user", content: "Bonjour." },
  ]);
  assert.equal(body.params.system, "Tu es un agent de test.");
  assert.equal(body.params.max_tokens, 200);
  assert.equal(body.params.idempotency_key, "fixed-key-for-determinism");

  // Envelope: signed by user's public-sphere key.
  const env = body.params._envelope;
  assert.equal(env.iss, identity.did);
  assert.equal(env.aud, `${DEFAULT_COMPUTE_ENDPOINT}/v1/invoke`);
  assert.equal(env.method, "aithos.compute_invoke");
  assert.equal(env.proof.verificationMethod, `${identity.did}#public`);
  assert.match(env.params_hash, /^sha256-[0-9a-f]+$/);
  assert.ok(env.proof.proofValue.length > 0);
});

test("invokeBedrock — omits optional fields when not provided", async () => {
  const identity = makeIdentity();
  const captured = captureFetch(() =>
    makeOkResponse({ jsonrpc: "2.0", id: "x", result: SAMPLE_RESULT }),
  );

  try {
    await invokeBedrock({
      identity,
      appDid: "did:aithos:app-test",
      mandateId: "mnd:test:001",
      model: "anthropic.claude-3-5-sonnet",
      messages: [{ role: "user", content: "Hi." }],
      idempotencyKey: "fixed-key",
    });
  } finally {
    captured.restore();
  }

  const body = JSON.parse(String(captured.calls[0]!.init.body)) as {
    params: Record<string, unknown>;
  };

  assert.equal(body.params.system, undefined, "system should not be present");
  assert.equal(
    body.params.max_tokens,
    undefined,
    "max_tokens should not be present",
  );
  assert.equal(
    body.params.temperature,
    undefined,
    "temperature should not be present",
  );
});

test("invokeBedrock — generates an idempotency key when not provided", async () => {
  const identity = makeIdentity();
  const captured = captureFetch(() =>
    makeOkResponse({ jsonrpc: "2.0", id: "x", result: SAMPLE_RESULT }),
  );

  try {
    await invokeBedrock({
      identity,
      appDid: "did:aithos:app-test",
      mandateId: "mnd:test:001",
      model: "anthropic.claude-3-5-sonnet",
      messages: [{ role: "user", content: "Hi." }],
    });
  } finally {
    captured.restore();
  }

  const body = JSON.parse(String(captured.calls[0]!.init.body)) as {
    params: { idempotency_key: string };
  };

  // 16 random bytes → 32 hex chars.
  assert.match(body.params.idempotency_key, /^[0-9a-f]{32}$/);
});

test("invokeBedrock — endpoint override is honored (test injection)", async () => {
  const identity = makeIdentity();
  const captured = captureFetch(() =>
    makeOkResponse({ jsonrpc: "2.0", id: "x", result: SAMPLE_RESULT }),
  );

  try {
    await invokeBedrock({
      identity,
      appDid: "did:aithos:app-test",
      mandateId: "mnd:test:001",
      model: "anthropic.claude-3-5-sonnet",
      messages: [{ role: "user", content: "Hi." }],
      endpoint: "https://compute-staging.example.com",
    });
  } finally {
    captured.restore();
  }

  assert.equal(
    captured.calls[0]!.url,
    "https://compute-staging.example.com/v1/invoke",
  );
});

/* -------------------------------------------------------------------------- */
/*  Error paths                                                               */
/* -------------------------------------------------------------------------- */

test("invokeBedrock — surfaces JSON-RPC error as ComputeError with code", async () => {
  const identity = makeIdentity();
  const captured = captureFetch(() =>
    makeOkResponse({
      jsonrpc: "2.0",
      id: "x",
      error: {
        code: -32050,
        message: "wallet balance insufficient",
        data: { required_microcredits: 1200, available_microcredits: 800 },
      },
    }),
  );

  try {
    await assert.rejects(
      () =>
        invokeBedrock({
          identity,
          appDid: "did:aithos:app-test",
          mandateId: "mnd:test:001",
          model: "anthropic.claude-3-5-sonnet",
          messages: [{ role: "user", content: "Hi." }],
        }),
      (err: unknown) => {
        assert.ok(err instanceof ComputeError);
        assert.equal((err as ComputeError).code, "-32050");
        assert.match((err as ComputeError).message, /wallet balance/);
        assert.deepEqual((err as ComputeError).data, {
          required_microcredits: 1200,
          available_microcredits: 800,
        });
        return true;
      },
    );
  } finally {
    captured.restore();
  }
});

test("invokeBedrock — surfaces non-2xx HTTP as ComputeError 'http'", async () => {
  const identity = makeIdentity();
  const captured = captureFetch(
    () =>
      new Response("Internal Server Error", {
        status: 503,
        statusText: "Service Unavailable",
      }),
  );

  try {
    await assert.rejects(
      () =>
        invokeBedrock({
          identity,
          appDid: "did:aithos:app-test",
          mandateId: "mnd:test:001",
          model: "anthropic.claude-3-5-sonnet",
          messages: [{ role: "user", content: "Hi." }],
        }),
      (err: unknown) => {
        assert.ok(err instanceof ComputeError);
        assert.equal((err as ComputeError).code, "http");
        assert.match((err as ComputeError).message, /503/);
        return true;
      },
    );
  } finally {
    captured.restore();
  }
});

test("invokeBedrock — surfaces network failures as ComputeError 'network'", async () => {
  const identity = makeIdentity();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    throw new TypeError("fetch failed: connection refused");
  }) as typeof globalThis.fetch;

  try {
    await assert.rejects(
      () =>
        invokeBedrock({
          identity,
          appDid: "did:aithos:app-test",
          mandateId: "mnd:test:001",
          model: "anthropic.claude-3-5-sonnet",
          messages: [{ role: "user", content: "Hi." }],
        }),
      (err: unknown) => {
        assert.ok(err instanceof ComputeError);
        assert.equal((err as ComputeError).code, "network");
        assert.match((err as ComputeError).message, /connection refused/);
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("invokeBedrock — surfaces missing result as ComputeError 'empty'", async () => {
  const identity = makeIdentity();
  const captured = captureFetch(() =>
    makeOkResponse({ jsonrpc: "2.0", id: "x" }),
  );

  try {
    await assert.rejects(
      () =>
        invokeBedrock({
          identity,
          appDid: "did:aithos:app-test",
          mandateId: "mnd:test:001",
          model: "anthropic.claude-3-5-sonnet",
          messages: [{ role: "user", content: "Hi." }],
        }),
      (err: unknown) => {
        assert.ok(err instanceof ComputeError);
        assert.equal((err as ComputeError).code, "empty");
        return true;
      },
    );
  } finally {
    captured.restore();
  }
});

/* -------------------------------------------------------------------------- */
/*  Cancellation                                                              */
/* -------------------------------------------------------------------------- */

test("invokeBedrock — propagates AbortSignal to fetch", async () => {
  const identity = makeIdentity();
  const controller = new AbortController();

  let receivedSignal: AbortSignal | undefined;
  const captured = captureFetch((_url, init) => {
    receivedSignal = init.signal as AbortSignal | undefined;
    return makeOkResponse({ jsonrpc: "2.0", id: "x", result: SAMPLE_RESULT });
  });

  try {
    await invokeBedrock({
      identity,
      appDid: "did:aithos:app-test",
      mandateId: "mnd:test:001",
      model: "anthropic.claude-3-5-sonnet",
      messages: [{ role: "user", content: "Hi." }],
      signal: controller.signal,
    });
  } finally {
    captured.restore();
  }

  assert.ok(receivedSignal, "fetch should have received the abort signal");
  assert.equal(receivedSignal, controller.signal);
});
