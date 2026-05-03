// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Tests for the centralized endpoint configuration (`src/endpoints.ts`).
//
// `_setEndpoints` and `_resetEndpoints` are internal — they're not exported
// from the package barrel. They're imported directly here from `../src/...`
// for testing. Production consumers must not depend on them; that contract is
// documented in PLATFORM-COMPUTE-DESIGN.md §"Posture open-source et contrat
// de stabilité".

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  DEFAULT_ENDPOINTS,
  _resetEndpoints,
  _setEndpoints,
  computeInvokeEndpoint,
  converseEndpoint,
  getEndpoints,
  readEndpoint,
  writeEndpoint,
} from "../src/endpoints.js";

/* -------------------------------------------------------------------------- */
/*  Defaults                                                                  */
/* -------------------------------------------------------------------------- */

test("DEFAULT_ENDPOINTS points at production Aithos infra", () => {
  assert.equal(DEFAULT_ENDPOINTS.api, "https://api.aithos.be");
  assert.equal(DEFAULT_ENDPOINTS.cdn, "https://cdn.aithos.be");
  assert.equal(DEFAULT_ENDPOINTS.compute, "https://compute.aithos.be");
  assert.equal(DEFAULT_ENDPOINTS.auth, "https://auth.aithos.be");
});

test("getEndpoints returns the production defaults out of the box", () => {
  _resetEndpoints();
  const ep = getEndpoints();
  assert.deepEqual(ep, DEFAULT_ENDPOINTS);
});

/* -------------------------------------------------------------------------- */
/*  URL builders                                                              */
/* -------------------------------------------------------------------------- */

test("URL builders compose the correct paths against defaults", () => {
  _resetEndpoints();
  assert.equal(readEndpoint(), "https://api.aithos.be/mcp/primitives/read");
  assert.equal(writeEndpoint(), "https://api.aithos.be/mcp/primitives/write");
  assert.equal(converseEndpoint(), "https://api.aithos.be/mcp/converse");
  assert.equal(computeInvokeEndpoint(), "https://compute.aithos.be/v1/invoke");
});

/* -------------------------------------------------------------------------- */
/*  Internal override                                                          */
/* -------------------------------------------------------------------------- */

test("_setEndpoints overrides individual endpoints (api only)", () => {
  _resetEndpoints();
  _setEndpoints({ api: "https://api-staging.example.com" });

  // Overridden.
  assert.equal(getEndpoints().api, "https://api-staging.example.com");
  assert.equal(
    readEndpoint(),
    "https://api-staging.example.com/mcp/primitives/read",
  );

  // Untouched.
  assert.equal(getEndpoints().compute, DEFAULT_ENDPOINTS.compute);
  assert.equal(computeInvokeEndpoint(), "https://compute.aithos.be/v1/invoke");

  _resetEndpoints();
});

test("_setEndpoints can override compute alone", () => {
  _resetEndpoints();
  _setEndpoints({ compute: "https://compute-staging.example.com" });

  assert.equal(getEndpoints().compute, "https://compute-staging.example.com");
  assert.equal(
    computeInvokeEndpoint(),
    "https://compute-staging.example.com/v1/invoke",
  );
  assert.equal(getEndpoints().api, DEFAULT_ENDPOINTS.api);

  _resetEndpoints();
});

test("_setEndpoints can override several endpoints at once", () => {
  _resetEndpoints();
  _setEndpoints({
    api: "https://api.example.com",
    compute: "https://compute.example.com",
    auth: "https://auth.example.com",
  });

  assert.equal(getEndpoints().api, "https://api.example.com");
  assert.equal(getEndpoints().compute, "https://compute.example.com");
  assert.equal(getEndpoints().auth, "https://auth.example.com");
  // CDN was NOT overridden — falls back to default.
  assert.equal(getEndpoints().cdn, DEFAULT_ENDPOINTS.cdn);

  _resetEndpoints();
});

test("_resetEndpoints restores the production defaults", () => {
  _setEndpoints({
    api: "https://api.example.com",
    compute: "https://compute.example.com",
  });
  _resetEndpoints();

  assert.deepEqual(getEndpoints(), DEFAULT_ENDPOINTS);
});

/* -------------------------------------------------------------------------- */
/*  Immutability of DEFAULT_ENDPOINTS                                         */
/* -------------------------------------------------------------------------- */

test("DEFAULT_ENDPOINTS object is not mutated by overrides", () => {
  _resetEndpoints();
  const before = { ...DEFAULT_ENDPOINTS };
  _setEndpoints({ api: "https://other.example.com" });

  // The constant itself is unchanged — only the active config holds the
  // override. This guarantees consumers reading DEFAULT_ENDPOINTS for
  // diagnostics see truth.
  assert.deepEqual(DEFAULT_ENDPOINTS, before);
  _resetEndpoints();
});
