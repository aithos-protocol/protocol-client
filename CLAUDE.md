# Notes Claude — `protocol-client`

## ⚠️ Mount FUSE Math17 — workflow git contraint

Ce dépôt vit sur le drive Math17 dont le filesystem **interdit `unlink(2)`
depuis le sandbox Cowork**. Concrètement : un `git commit` direct depuis le
mount laisse un `.git/index.lock` résiduel qui bloque toute opération git
suivante.

→ **Lire impérativement `../CLAUDE.md`** (= `/Volumes/Math17/aithos/code/CLAUDE.md`)
avant tout commit. Le workflow autonome y est documenté.

**TL;DR** : commits depuis un `git clone --shared` dans `/tmp/<repo>-work`,
push vers `claude/<topic>` côté origin si la branche cible est checked out
côté Math17.

## 🔁 Crypto data — duplication temporaire avec `aithos-sdk`

Le sous-protocole `aithos.data.v0.1` (PDS, RFC dans
`Aithos-protocol/spec/data/`) a un module crypto autonome qui vit
aujourd'hui dans **deux endroits distincts** :

1. `Aithos-protocol/packages/data-crypto/` — POC standalone, non publié,
   suite de tests `node:test` validant la construction CMK + DEK + wraps.
2. `aithos-sdk/src/data.ts` — copie inline des mêmes primitives,
   browser-compatible (`globalThis.crypto.getRandomValues`, `btoa`/`atob`
   au lieu de `node:crypto` / `Buffer`). C'est ce qui tourne dans la
   prod du SDK depuis `@aithos/sdk@0.1.0-alpha.26`.

**Ce que `protocol-client` n'a PAS** : aucune trace de cette crypto data.

**Pourquoi cette duplication** : la session de cut du PDS visait à livrer
end-to-end (spec + backend + SDK + demo switchia) sans toucher au
package `protocol-client` déjà publié et stable en alpha.13. Plutôt
que de risquer une régression sur le client Ethos en y greffant du
neuf, on a inliné les primitives data dans le SDK.

**La dette à payer un jour** : déplacer les helpers vers
`protocol-client/src/data-crypto/` (analogue de `src/crypto/` pour les
zones Ethos), puis :
- supprimer la duplication de `aithos-sdk/src/data.ts`
- éventuellement publier `@aithos/data-crypto` comme paquet standalone
  pour les implémenteurs tiers de clients PDS

**Quand le faire** : pas urgent. À grouper avec un autre cut de
`protocol-client` (par exemple quand on ajoutera le `did:aithos:…`
resolver côté PDS qui pourrait réutiliser des helpers de DID resolution
déjà ici).

**Test de non-régression** : si on duplique correctement les AAD
bindings (`aithos-data-cmk-v1`, `aithos-data-dek-v1`,
`aithos-data-record-v1`) et les sels HKDF, l'unwrap des records écrits
par le SDK actuel doit rester possible depuis le futur module
unifié. Garder en tête.
