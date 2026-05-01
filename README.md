# @aithos/protocol-client

Env-agnostic TypeScript client for the [Aithos protocol](https://github.com/aithos-protocol/aithos-protocol).
Lets you build, sign, and verify DIDs, mandates, and ethos editions from any
JavaScript environment — browser, Node, or anywhere `crypto.subtle` is
available.

This package is a thin client that depends on [`@aithos/protocol-core`](https://www.npmjs.com/package/@aithos/protocol-core)
for the wire-format primitives and adds the convenience layer: key
management, manifest building, zone encryption, signed envelopes, delegate
mandates, and a JSON-RPC client for `api.aithos.be`.

## Status

**Alpha** — API surface likely to shift until 0.1.0 stable. Use at your own
risk for production. During the alpha phase, the npm `latest` tag tracks the
most recent alpha release so the package page reflects the current code; once
`0.1.0` ships, `latest` will move to the stable line and pre-releases will
remain available under `@alpha`.

## Install

```sh
npm install @aithos/protocol-client@alpha
```

## Quick start

```ts
// (Full quick start lands when the API surface stabilizes around 0.1.0.)
// For now, see the src/index.ts barrel exports for what's available.
```

## What's in here

The package is organized around four concerns:

- **Crypto primitives** — Ed25519 signing, X25519 key exchange, HPKE-based
  zone encryption, Argon2id-based recovery files. Built on the audited
  `@noble/*` family.
- **Identity model** — DID document construction, key rotation, sphere-key
  derivation.
- **Ethos editions** — manifest building, zone packing, delegate re-sealing.
- **Platform access** — JSON-RPC 2.0 client for the Aithos platform read
  and write endpoints.

## Related packages

| Package                                                                                          | Scope                                                            |
| ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| [`@aithos/protocol-core`](https://www.npmjs.com/package/@aithos/protocol-core)                   | Wire-format primitives, types, canonicalization.                 |
| **`@aithos/protocol-client`** (this)                                                             | Env-agnostic client: signing, building, API access.              |
| [`@aithos/extension-kit`](https://www.npmjs.com/package/@aithos/extension-kit) *(coming soon)*   | Chrome MV3 extension helpers on top of this package.             |

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0). See [LICENSE](./LICENSE).

The Aithos protocol specification (in the [`aithos-protocol`](https://github.com/aithos-protocol/aithos-protocol)
repo) is under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

This package was previously released under BUSL-1.1 (versions `0.1.0-alpha.1`
through `0.1.0-alpha.5`). Those versions remain under BUSL-1.1 for anyone who
already obtained them; from `0.1.0-alpha.6` onward, all releases are
Apache-2.0 — irrevocably for the `0.x` line.

## Contributing

Issues and pull requests are welcome. Before opening a PR that changes
public API surface, please open an issue to discuss.

## Provenance

This package was extracted from the `innoesate` monorepo
(`aithos/app/src/lib/`) on 2026-04-24, as part of the foundation sprint
defined in ADR-0003. The extraction decision is tracked in
[`aithos/ARCHITECTURE-DECISIONS.md`](https://aithos.be/architecture-decisions)
in the innoestate repo.
