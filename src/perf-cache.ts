// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Mathieu Colla

// Opt-in, short-TTL memo caches for the two read-side lookups that every
// publish repeats verbatim:
//
//   1. `aithos.get_identity` (the subject's did.json) — changes only on key
//      rotation / sphere augmentation, yet the publish paths re-fetch it on
//      every edition to anchor `sha256_of_did_json`.
//   2. The active-delegate-grants resolution (`list_mandates` + N ×
//      `get_mandate`) — re-crawled on every owner publish so new/revoked
//      mandates seal in, even when nothing changed since the publish 3
//      seconds ago.
//
// Both caches are DISABLED by default (TTL 0) so protocol-client keeps its
// current always-fresh semantics for existing callers and tests. A host (the
// SDK) opts in via {@link configurePerfCaches}; it is then responsible for
// calling {@link invalidateDelegateGrantsCache} when IT mutates mandates
// (mint / revoke) and {@link invalidateIdentityCache} on key rotation. The
// TTL bounds staleness from OTHER devices: a mandate issued elsewhere can be
// missed for at most `delegateGrantsTtlMs` before a publish picks it up —
// the same freshness window a human page-reload gives today.
//
// Entries store the in-flight PROMISE, so concurrent callers coalesce into
// one network crawl (single-flight) even with caching disabled-after-resolve
// semantics on failure: a rejected promise is evicted immediately and never
// poisons the next call.

export interface PerfCacheConfig {
  /** TTL for the did.json (`get_identity`) cache. 0 (default) = disabled. */
  readonly identityTtlMs: number;
  /** TTL for the active-delegate-grants cache. 0 (default) = disabled. */
  readonly delegateGrantsTtlMs: number;
}

let config: PerfCacheConfig = { identityTtlMs: 0, delegateGrantsTtlMs: 0 };

/** Opt in / reconfigure (partial — omitted fields keep their value). */
export function configurePerfCaches(next: Partial<PerfCacheConfig>): void {
  config = {
    identityTtlMs: next.identityTtlMs ?? config.identityTtlMs,
    delegateGrantsTtlMs: next.delegateGrantsTtlMs ?? config.delegateGrantsTtlMs,
  };
}

export function getPerfCacheConfig(): PerfCacheConfig {
  return config;
}

interface Entry<V> {
  readonly value: Promise<V>;
  readonly expiresAt: number;
}

/** Single-flight TTL map. Not exported — the two domain caches wrap it. */
class TtlCache<V> {
  readonly #map = new Map<string, Entry<V>>();

  get(key: string, ttlMs: number, loader: () => Promise<V>): Promise<V> {
    if (ttlMs <= 0) return loader(); // disabled → passthrough, no storage
    const now = Date.now();
    const hit = this.#map.get(key);
    if (hit && hit.expiresAt > now) return hit.value;
    const value = loader();
    this.#map.set(key, { value, expiresAt: now + ttlMs });
    // A failed load must not be served from cache: evict on rejection.
    value.catch(() => {
      const cur = this.#map.get(key);
      if (cur && cur.value === value) this.#map.delete(key);
    });
    return value;
  }

  invalidate(key?: string): void {
    if (key === undefined) this.#map.clear();
    else this.#map.delete(key);
  }
}

/* -------------------------------------------------------------------------- */
/*  Domain caches                                                             */
/* -------------------------------------------------------------------------- */

// Values are intentionally `unknown`-shaped here; the call sites own the types
// (editor-v03's DidDocument, delegate-recipients' DelegateGrantsByZone). This
// module stays dependency-free so anything can import it without cycles.

const identityCache = new TtlCache<unknown>();
const grantsCache = new TtlCache<unknown>();

/** Memoized loader for the subject's did.json. Passthrough when disabled. */
export function cachedIdentityDoc<V>(did: string, loader: () => Promise<V>): Promise<V> {
  return identityCache.get(did, config.identityTtlMs, loader) as Promise<V>;
}

/** Memoized loader for the owner's active delegate grants. Passthrough when disabled. */
export function cachedDelegateGrants<V>(ownerDid: string, loader: () => Promise<V>): Promise<V> {
  return grantsCache.get(ownerDid, config.delegateGrantsTtlMs, loader) as Promise<V>;
}

/** Drop the cached did.json for `did` (or every subject when omitted). Call on
 *  key rotation / identity augmentation. */
export function invalidateIdentityCache(did?: string): void {
  identityCache.invalidate(did);
}

/** Drop the cached delegate grants for `ownerDid` (or every owner when
 *  omitted). Call after minting or revoking a mandate so the next publish
 *  re-crawls and seals the change in. */
export function invalidateDelegateGrantsCache(ownerDid?: string): void {
  grantsCache.invalidate(ownerDid);
}

/** Test hook: reset config + drop everything. */
export function _resetPerfCaches(): void {
  config = { identityTtlMs: 0, delegateGrantsTtlMs: 0 };
  identityCache.invalidate();
  grantsCache.invalidate();
}
