// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// RFC 8785 JSON Canonicalization Scheme (JCS) — single source of truth.
//
// Re-exported from @aithos/protocol-core. protocol-client previously carried a
// hand-ported copy "kept in lockstep" with core; it now IS the same function
// the Aithos servers use (platform/shared also imports core's `canonicalize`),
// removing any possibility of client/server drift on the bytes that signatures
// and content hashes commit to (envelopes, mandates, ethos editions).
//
// Behavior note vs the former ported copy: core THROWS on an `undefined` object
// VALUE (RFC 8785 §3.2.2 rejects undefined), whereas the old copy silently
// skipped such keys. Aithos payloads are well-formed JSON and never carry
// undefined values, so this is a stricter-but-equivalent change — proven
// byte-identical over a representative corpus by
// test/canonical-core-conformance.test.ts.
export { canonicalize } from "@aithos/protocol-core/canonical";
