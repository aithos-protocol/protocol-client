#!/usr/bin/env node
// Debug — compare canonicalize output from protocol-client local vs @aithos/protocol-core.

import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));

// Both implementations
const { canonicalize: localCanon } = await import(
  resolve(here, "../dist/src/crypto/canonical.js")
);
const { canonicalize: coreCanon } = await import("@aithos/protocol-core");

// Reproduce the exact params shape protocol-client sends for compute_invoke
const params = {
  app_did: "did:aithos:test-app-interview-smoke",
  mandate_id: "smoke-test",
  model: "claude-haiku-4-5",
  messages: [
    { role: "user", content: "Réponds en 3 mots maximum à : bonjour, ça va ?" },
  ],
  idempotency_key: "abc123def456",
  max_tokens: 50,
};

const local = localCanon(params);
const core = coreCanon(params);

console.log("=== local (protocol-client) ===");
console.log(local);
console.log("\n=== core (protocol-core) ===");
console.log(core);
console.log("\n=== match? ===");
console.log(local === core ? "YES — same bytes" : "NO — DIVERGENCE");

if (local !== core) {
  for (let i = 0; i < Math.min(local.length, core.length); i++) {
    if (local[i] !== core[i]) {
      console.log(
        `First diff at char ${i}: local=${JSON.stringify(local[i])} core=${JSON.stringify(core[i])}`,
      );
      console.log(`  context local: ${JSON.stringify(local.slice(Math.max(0, i - 20), i + 20))}`);
      console.log(`  context core:  ${JSON.stringify(core.slice(Math.max(0, i - 20), i + 20))}`);
      break;
    }
  }
  if (local.length !== core.length) {
    console.log(`Length diff: local=${local.length} core=${core.length}`);
  }
}

console.log("\n=== sha256 ===");
const h = (s) => createHash("sha256").update(s, "utf8").digest("hex");
console.log("local: sha256-" + h(local));
console.log("core:  sha256-" + h(core));
