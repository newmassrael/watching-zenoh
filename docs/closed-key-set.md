# Closed key set

Status: design; phase 1 (the pure table, the generator and the model test) is built and no host reads
it yet. Written 2026-10-26 so that what a deployment asks of "every key is known at build time" is
decided once, against what the host session already does, and not rebuilt beside it.

## What it is

Today every key the session handles is text. A subscription stores its pattern as a bounded string and
every received key is matched against each pattern by the glob matcher; a peer's keyexpr alias is a
(wire id, text) pair; a repeat of a key is made cheap by a small memo that is valid for one subscription
epoch. That is the right model for an open deployment, where any peer may use any key.

A deployment that knows its keys when it is built can ask for more. It declares the whole set of keys
once, and the build derives, from that declaration, the answers the receive path would otherwise
compute from text:

- **a key id** for every key: a dense number, so a key is named by a number inside the session;
- **a selection** for every key and every role: the entities (subscriptions, queryables, tokens) that
  a message on that key reaches, computed at build time, wildcards expanded over the declared keys;
- **a refusal** for every key that is not in the set: a declaration, a publish or a received message
  on a key outside it is refused by a typed result and counted, never matched.

The mode is a policy of the image, not of the call: `key-set` is `open` (the default, upstream's
behaviour) or `closed`. Both modes are built from one source and both stay tested.

## What the host session has today

Read from the tree on 2026-10-26; nothing here is inferred.

- **Patterns are text, matched per row.** `crates/wz-session-core/src/pubsub.rs`: a `Subscriber` holds
  `pattern: BoundedString<MAX_KEYEXPR_BYTES>`; one matcher (`scan_subscribers`) walks the rows and calls
  `keyexpr_pattern_matches` (`keyexpr_match.rs`). The cost of a received key is the number of rows times
  the length of the key.
- **A memo shortens repeats, not first sight.** `MatchMemo` holds `MATCH_MEMO_SLOTS` (8; 0 leaves it
  out) recently matched keys, valid for one epoch. A key that has not arrived lately is matched in full;
  the heap profile only.
- **A peer's naming is text.** `PeerNaming` keeps the peer's keyexpr aliases, bounded by
  `MAX_PEER_KEYEXPR_ALIASES`; each row carries the key as text.
- **Access control is text, and its adapter is AP only.** The policy engine is the crate
  `wz-access-control`; `crates/wz-runtime-tokio/src/interceptor/access_control.rs` is the adapter that
  mirrors upstream's enforcers: rules by subject, key expression and flow, matched as text, fail-closed.
  The fixed-memory profile has no interceptor, so the allowance this adapter gives is not there.
- **There is no key id anywhere in the tree.** A search of `crates/wz-session-core/src` for a key index,
  a key table or a declared key set finds nothing; this is built from nothing.

So the part that is already there (a per-peer allow rule) exists only as an AP interceptor over text, and
the part that is new is the build-time table, the id, the precomputed selections and the refusal of
everything outside the set.

## Decisions

**D1. The set is declared per image, next to the session pool, and the generator owns the table.**
Each key carries its roles: published, subscribed (a concrete key or a wildcard selector), queried,
served, token. The generator sorts the keys, assigns ids in that order, and emits a read-only table.
Rejected: a registration call at start-up (the table would be built at run time, so the refusal of an
unlisted key could not be a build-time fact and the table would need RAM). Rejected: ids assigned by
the order of declaration in source (adding one key would renumber every id and every peer's rows).

**D2. The catalogue is pure and allocation-free.** A `KeyCatalogue` in `wz-session-core` holds the
sorted key text and, per role, the offsets and entity numbers of the selections (a compressed sparse row
table). Operations: `find_exact(text) -> Option<KeyId>`, `text(KeyId)`, `selection(KeyId, role)`. It
counts and indexes only; the host owns every buffer, as in the delivery lane.

**D3. The oracle is the glob matcher.** For every key in the set and every role, the precomputed
selection must equal what `scan_subscribers` returns for that key over the same subscriptions. A model
test enumerates the set and compares; a generator that expands a wildcard wrongly fails it. This is the
test that makes the table safe to trust and it comes before any host uses the table.

**D4. A wildcard subscription reaches only the keys that are in the set.** A subscriber on a wildcard
selector is expanded over the declared concrete keys at build time. A message whose key is not declared
is refused even if it would match the selector. Reason: admitting "a key that matches an allowed
selector" would need a text row at run time, which is the open mode returning through a side door, and
the bound on memory and on time per message would no longer be a build-time fact. Open question for the
owner below.

**D5. Resolution happens once, at the edge.** A peer's resource declaration binds its wire id to a key id
(an exact key, or a declared prefix plus a suffix looked up in the catalogue). After that a received
message names a wire id and reaches a selection by two array reads. A wire id that resolves to nothing,
and a key the peer is not allowed, are refused by one typed result and counted by reason. The alias row
shrinks from a bounded string to a number; the saving is measured, not claimed.

**D6. Per-peer allowance is a set of key ids per peer class.** The generator emits, for each peer class
the image knows, the key ids that class may publish, subscribe to, query and serve. This overlaps
upstream's access control, which stays the AP's answer for open deployments; the closed set is the
fixed-memory profile's answer and may be generated from the same rules later. Whether the two share a
declaration is a decision for the owner below.

**D7. In the closed mode the table replaces the memo.** The selection is the exact answer a memo
approximates, so `MATCH_MEMO_SLOTS` does nothing in a closed image and the memo is not built.

## Phases

1. **Pure catalogue, generator and oracle.** `KeyCatalogue`, the declaration and its validation (a
   duplicate key, a wildcard that expands to nothing, a role the key cannot have, a table past its
   bound), the generated table, and the model test of D3. No host uses it.
2. **The policy and the refusal at declare time.** `key-set` in the declaration; the tokio host refuses
   a declaration, publish or query on a key outside the set under `closed`, by a typed result. Open
   keeps today's path unchanged, tested.
3. **Receive through the id.** The peer's alias row holds a key id; the received message reaches its
   selection by index; refusals counted by reason. Measured against open with the memo on one machine and
   condition: allocations and time per sample, alias row bytes, ROM and RAM of the table.
4. **Per-peer allowance** (D6).
5. **The cooperative engine, the slot node and the C ABIs** (sessions 11 and ef own the first two; a C
   ABI door is the third), once phase 3 shows the receive path.

## Phase 1, as built

- **The table.** `crates/wz-session-core/src/key_catalogue.rs`: `KeyCatalogue` over five static arrays
  (key text, key ends, selection offsets, selection members, entity rows), `no_std`, no allocation, no
  `unsafe`. `KeyCatalogue::new` is a `const fn` that checks every property of the table (sorted unique
  non-empty keys that end on a character, offsets that cover the members, a selection that holds one
  kind's entities once each in order), so a table the generator wrote wrongly stops the build.
- **The selection is per entity kind.** A key's row has one cell for each of publisher, subscriber,
  queryable, querier and token: the entities of that kind whose pattern intersects the key. The caller
  picks the cell its message needs (a put reads the subscriber cell, a query the queryable cell).
- **A pattern is a key of the table.** The keys are the distinct texts of the declared entities,
  wildcards included, because a declaration of a subscriber on `a/**` has to resolve by its own text.
  Under D4 a wildcard is still expanded only over the other declared keys: `a/b`, undeclared, is not
  found even though `a/**` covers it, and it is refused.
- **The declaration** has the shape of a node's entities (`kind` and `key`), so the key set of a node
  is what the node already declares. `scripts/lib/wz_key_set.py` refuses a key that is not a key, a
  publisher or a token on a wildcard, the same entity twice, a wildcard no concrete key meets, and a
  set past what `u16` numbers. Entities are numbered by kind and then key, and keys by bytes, so the
  order of declaration changes nothing.
- **The oracle is two-sided, because the generator holds a port of the matcher.** Python has no
  matcher, so the generator ports `keyexpr_intersects_text`. `wz_key_set.py --write` also writes every
  pair of 399 keys over `a b @v * ** a$* $*b` up to three chunks deep with the port's answer, and
  `crates/wz-session-core/tests/key_catalogue_model.rs` compares each with the real matcher in both
  orders, compares every selection of the fixture (18 keys, 21 entities, every kind) with the matcher,
  and compares the subscriber cells with what the real `SubscriberTable` delivers to a local publish
  on each key. The test was run against a port with the rule that `**` does not cross an `@` chunk
  removed, and three of its five tests failed; with the rule back it passes.
- **Not done in phase 1.** No host, node image or generated `declared.rs` carries a catalogue, there is
  no `key-set` policy, and nothing is measured. The table's ROM size for a real node is a phase 3
  question, with the alias row.

## What is not decided

- **D4 for the owner.** Does a closed image admit a message whose key is undeclared but matches a
  declared wildcard selector? The design above refuses it. The alternative admits it as a bounded text
  row under an allowed selector, at the price of a run-time matcher and a run-time bound.
- **D6 for the owner.** One declaration for open access control and the closed allowance, or two.
- **Publisher wildcards.** A publisher on a wildcard key is not expressible in a table of concrete
  keys. The design lists the concrete keys a publisher uses; whether a wildcard publisher is needed at
  all is a question for the deployments that have one.
- **Resource ids declared by the sender** could also be fixed in the table (each key id gets a wire id
  at build time, so no declaration is sent). Left for after phase 3, when the receive side is measured.

## What this does not claim

Nothing here is measured. That the table is faster than the memo, that the alias row is smaller, and
that the closed mode removes the matcher from the receive path are the questions phase 3 answers.
