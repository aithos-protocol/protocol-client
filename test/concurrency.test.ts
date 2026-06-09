// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// mapLimit — bounded fan-out used by the per-section read/prefetch paths.

import { strict as assert } from "node:assert";
import { describe, it } from "node:test";

import { mapLimit } from "../src/concurrency.js";

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

describe("mapLimit", () => {
  it("preserves input order regardless of completion order", async () => {
    const out = await mapLimit([30, 5, 15, 1], 4, async (ms, i) => {
      await sleep(ms);
      return `r${i}:${ms}`;
    });
    assert.deepEqual(out, ["r0:30", "r1:5", "r2:15", "r3:1"]);
  });

  it("never exceeds the concurrency limit", async () => {
    let inFlight = 0;
    let peak = 0;
    await mapLimit(Array.from({ length: 20 }, (_, i) => i), 3, async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await sleep(5);
      inFlight--;
    });
    assert.ok(peak <= 3, `peak in-flight was ${peak}, expected <= 3`);
    assert.ok(peak >= 2, `peak in-flight was ${peak}, expected some parallelism`);
  });

  it("handles empty input and limit larger than input", async () => {
    assert.deepEqual(await mapLimit([], 8, async () => 1), []);
    assert.deepEqual(await mapLimit([7], 100, async (x) => x * 2), [14]);
  });

  it("rejects with the first error and stops scheduling new work", async () => {
    let started = 0;
    await assert.rejects(
      mapLimit(Array.from({ length: 50 }, (_, i) => i), 2, async (i) => {
        started++;
        await sleep(2);
        if (i === 1) throw new Error("boom");
        return i;
      }),
      /boom/,
    );
    // With limit 2 and a failure on the 2nd item, far fewer than 50 ran.
    assert.ok(started < 10, `started ${started} tasks after failure, expected scheduling to stop`);
  });
});
