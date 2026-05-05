// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Centralized endpoint configuration.
//
// All HTTP endpoints the lib talks to are resolved through this module. The
// production defaults point at Aithos infrastructure (`api.aithos.be`,
// `cdn.aithos.be`, `compute.aithos.be`, `auth.aithos.be`).
//
// Posture: the lib is open-source, by default plugged on Aithos. This is the
// shortest path for builders. The endpoint table is held in a mutable module
// state so that tests (and, eventually, a public configuration API for
// self-hosting) can override it. The override mechanism is INTERNAL today —
// `_setEndpoints` and `_resetEndpoints` are not re-exported from the package
// barrel. Public API stays "talks to Aithos, period". When the time comes to
// expose configurability, we add the public surface here without changing
// any consumer.
//
// See PLATFORM-COMPUTE-DESIGN.md §"Posture open-source et contrat de
// stabilité".

export interface AithosEndpoints {
  /** Protocol primitives (`/mcp/primitives/{read,write}`, `/mcp/converse`). */
  readonly api: string;
  /** CDN for signed ethos editions and DID documents (immutable bundles). */
  readonly cdn: string;
  /** Compute proxy for Bedrock invocation. */
  readonly compute: string;
  /** OAuth bridge / token vending machine for Gmail, MS Graph, Slack, etc. */
  readonly auth: string;
}

/** Default endpoints — production Aithos infrastructure. */
export const DEFAULT_ENDPOINTS: AithosEndpoints = {
  api: "https://api.aithos.be",
  cdn: "https://cdn.aithos.be",
  compute: "https://compute.aithos.be",
  auth: "https://auth.aithos.be",
};

// Mutable state. Module-scoped so callers within the lib see a single
// resolved configuration; not exposed in the public API surface yet.
let _activeEndpoints: AithosEndpoints = { ...DEFAULT_ENDPOINTS };

/**
 * Resolve the currently-active endpoint set. Used internally by the lib to
 * compute target URLs at the moment of each request.
 */
export function getEndpoints(): AithosEndpoints {
  return _activeEndpoints;
}

/**
 * Override one or more endpoints. Internal — not re-exported from the
 * package barrel. Used by tests and reserved for the future self-hosting
 * public configuration API.
 *
 * @internal
 */
export function _setEndpoints(overrides: Partial<AithosEndpoints>): void {
  _activeEndpoints = { ..._activeEndpoints, ...overrides };
}

/**
 * Reset endpoint configuration to the production defaults.
 *
 * @internal
 */
export function _resetEndpoints(): void {
  _activeEndpoints = { ...DEFAULT_ENDPOINTS };
}

/* -------------------------------------------------------------------------- */
/*  URL builders                                                              */
/*                                                                             */
/*  Compose the well-known sub-paths each consumer needs. Centralizing the    */
/*  paths here means a future protocol path change (very rare) is a one-liner */
/*  in this file rather than scattered string concatenation across the lib.   */
/* -------------------------------------------------------------------------- */

/** Read primitives endpoint: `${api}/mcp/primitives/read`. */
export function readEndpoint(): string {
  return `${getEndpoints().api}/mcp/primitives/read`;
}

/** Write primitives endpoint: `${api}/mcp/primitives/write`. */
export function writeEndpoint(): string {
  return `${getEndpoints().api}/mcp/primitives/write`;
}

/** Converse endpoint (zero-inference MCP): `${api}/mcp/converse`. */
export function converseEndpoint(): string {
  return `${getEndpoints().api}/mcp/converse`;
}

// NOTE: `computeInvokeEndpoint()` was removed in alpha.10 alongside
// `src/compute.ts`. The compute proxy URL composition now lives in
// `@aithos/sdk`. The `compute` field on `AithosEndpoints` is preserved
// here as read-only diagnostic surface (and for callers who configure
// the SDK by reading `getEndpoints().compute`).
