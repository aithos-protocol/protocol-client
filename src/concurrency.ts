// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Bounded-concurrency mapper for network fan-out.
//
// The v0.3 per-section transport turns "read a zone" into N independent
// `get_ethos_section` RPCs. Issuing them strictly sequentially costs
// N × RTT (the dominant latency of every eager read and of legacy-blob
// pre-fetches); issuing them ALL at once can exhaust the browser's
// per-host connection budget and hammer the provider. `mapLimit` is the
// middle ground: a small worker pool that preserves input order in the
// result array.

/** Default fan-out for per-section RPCs. Browsers multiplex these over a
 *  single HTTP/2 connection to the provider's CloudFront distribution, so a
 *  small pool captures ~all of the latency win without burst-flooding the
 *  origin Lambda. */
export const DEFAULT_RPC_CONCURRENCY = 8;

/**
 * Map `items` through an async `fn` with at most `limit` calls in flight.
 * Results come back in INPUT order (index-addressed), regardless of
 * completion order. The first rejection aborts scheduling of new work and
 * rejects the whole call (in-flight siblings settle silently) — same
 * fail-fast contract as `Promise.all`.
 */
export async function mapLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) return [];
  const n = Math.max(1, Math.min(Math.floor(limit) || 1, items.length));
  const out = new Array<R>(items.length);
  let next = 0;
  let failed: unknown = undefined;
  let hasFailed = false;

  async function worker(): Promise<void> {
    while (!hasFailed) {
      const i = next++;
      if (i >= items.length) return;
      try {
        out[i] = await fn(items[i]!, i);
      } catch (e) {
        if (!hasFailed) {
          hasFailed = true;
          failed = e;
        }
        return;
      }
    }
  }

  await Promise.all(Array.from({ length: n }, () => worker()));
  if (hasFailed) throw failed;
  return out;
}
