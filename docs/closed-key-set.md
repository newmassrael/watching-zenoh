# Closed key set

Status: design; phases 1 to 3b (the pure table, the generator, the model test, the gate, the policy, the
refusal of a peer's data key and delivery by the selection of a key) are built in the subscriber table;
no image supplies a table yet. Written 2026-10-26 so that what a deployment asks of "every key is known at build time" is
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
the bound on memory and on time per message would no longer be a build-time fact. This is about a data
key; a selector is another thing (see "Data keys and selectors"). Open question for the owner below.

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

## Data keys and selectors

D4 says a key outside the set is refused. That is right for a **data key** and wrong for a
**selector**, and the receive path has both:

- A data key is a concrete key a message is on: the key of a Put or a Delete, of a Reply. It is looked
  up in the table, and outside the set it is refused.
- A selector is a pattern a peer asks with: a query's, an interest's, a liveliness get's, and the
  pattern of a subscription or a queryable the peer declares. It is not a key of the set and cannot be
  looked up: any pattern may arrive, and refusing one breaks what every zenoh node answers (a `get` on
  `lab/doc/*` of a node that declares `lab/doc/small`, or the interest a zenoh-pico publisher waits
  on before it puts at all). What a closed image answers to a selector is what it selects among the
  entities it declares, and a selector that intersects none is answered with nothing, not refused.
  That is the matcher over the image's own entities, a bounded number known at build time; it is not
  the open mode's matcher over whatever a peer declared.

So the refusal of D4 applies to data keys only, and a selector is the one place a closed image still
runs the matcher, over a set fixed at build time. Where a peer's declared pattern matters (which of our
publishes it receives) is the per-peer allowance, phase 4.

## Phases

1. **Pure catalogue, generator and oracle.** `KeyCatalogue`, the declaration and its validation (a
   duplicate key, a wildcard that expands to nothing, a role the key cannot have, a table past its
   bound), the generated table, and the model test of D3. No host uses it.
2. **The gate.** `KeyGate`, open or closed, admits a key of the set or a key the image declares in the
   role asked, and counts each refusal by reason. Pure, tested over the fixture, called by no host.
   This replaces "the policy and the refusal at declare time" of the first cut of this note: see
   "Phase 2, as built" for why.
3. **The policy and the receive path**, in two steps.
   - **3a. The policy and the refusal of a peer's data key.** `key-set` (`open` is the default) lands
     with the subscriber table acting on it: a message from a peer on a key outside the set is dropped
     before a subscriber is looked up and counted. Open keeps today's path unchanged, tested.
   - **3b. Receive through the id (built).** The key a message arrives on is looked up once and the message
     reaches its subscribers by the selection of that key, by number; the subscriber rows hold the
     entity they were declared as. Measured against open with the memo on one machine and condition:
     allocations and time per sample, alias row bytes, ROM and RAM of the table.
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

## Phase 2, as built

- **The gate.** `crates/wz-session-core/src/key_gate.rs`: `KeyGate::open()` admits every key and looks
  at none; `KeyGate::closed(&catalogue)` has two questions. `admit_key(text)` is for a key that is one
  of the set (a message's key, a resource a peer declares); `admit_declared(text, kind)` is for a local
  declaration and also needs an entity of that kind declared on the key. Both answer with the `KeyId`,
  and a refusal is `OutsideSet` or `RoleNotDeclared(kind)`, counted by reason and saturating.
- **The catalogue gained `find_entity(kind, key)`**, a binary search that is sound because the table
  now checks, in a `const`, that entities ascend strictly by kind and then key (the generator already
  wrote them so, and `--selftest` holds it), which also means an entity is declared once.
- **Why the first cut of this phase changed.** Reading the tokio host before writing the refusal showed
  that `declare_subscriber`, `declare_queryable`, `declare_publisher` and `declare_querier` return a
  handle and not a `Result`, and that there are over a dozen entry points once the aliased, buffered,
  offloaded and shm forms are counted. A refusal there is either a change of the public API or a hole
  in some of the forms. It is also the wrong place: an image built from a declaration declares exactly
  its entities, so a local refusal is true by construction there, and what a closed image has to refuse
  at run time is what a peer sends. That is the receive path, which phase 3 builds, and the host that
  refuses there is where the policy belongs.
- **No policy yet.** A `key-set` switch that no host acts on would tell a deployer that a build is
  closed when nothing is, so it is declared with the first host that refuses on it.
- **Tested** by the unit tests of the gate (open admits everything and counts nothing, closed numbers
  what it admits, a pattern-covered key is outside the set, a role is admitted or refused, counters
  saturate) and by `tests/key_catalogue_model.rs` over the fixture: every declared role is admitted,
  every other (key, kind) pair is refused by role and counted, a key a declared pattern covers is
  outside the set.

## Phase 3a, as built

- **The policy.** `key-set` is `open` (default, upstream's behaviour) or `closed`, declared in
  `deploy/wz-config.toml` with its generated Kconfig and typed `SessionPolicy::key_set`. A build that
  states `closed` has a gate that refuses every key until a host gives it its table
  (`KeyGate::of_build`), so a closed image that forgot its table takes nothing and not everything.
- **The place.** `SubscriberTable` holds a `KeyGate` and applies it in the two functions every
  delivery goes through (`fire_to_subscribers` and `fire_plain_to_subscribers`), to a message that
  came from a peer. A local publish is the application's own and is not gated. A refused message
  reaches no subscriber, as a message that matched none, and is counted by reason
  (`SubscriberTable::key_gate_refused`). `set_key_gate` replaces the gate, which is how an image gives
  its table and how a test names the mode.
- **Tested.** Over the fixture, an open table delivers a peer's message on a key a pattern covers and
  counts nothing; a closed one drops it, counts it, delivers a declared key to exactly the subscribers
  its selection names, and does not gate a local publish. All 739 unit tests of the crate pass on an
  open build, and the gate and policy tests pass on a build whose environment states `closed`.
- **Not done.** Nothing calls `set_key_gate` with a real table yet: the generated `declared.rs` of a
  node does not carry one. The selector side is as it was. A reply's key is not gated. No time or
  allocation is measured: the added work on an open build is one flag test and one `Option` test per
  message from a peer.

## Phase 3b, as built

- **The row holds its entity.** A subscriber row of a table with a closed gate holds the entity the
  image declares on its pattern. `register_sink` asks the gate: a pattern the image does not declare
  as a subscriber is refused with `RegisterError::KeyNotInSet` (and counted by the gate), and an open
  table registers as before.
- **Delivery is by the selection.** A peer's message on a key of the set reaches the subscribers its
  key's selection names: the rows are walked in registration order, which every delivery promises, and
  each is asked whether its entity is in the selection, an integer search. No pattern is matched. A row
  made before the table was given, and not declared by it, is matched by its pattern, so a
  subscription the application declared is never left without its messages; `set_key_gate` numbers the
  rows it can.
- **The gate remembers the key it just admitted.** A first measurement showed the table alone losing to
  the match memory on one repeated key (below), because every message searched the table. One
  comparison with the last key's text answers a stream's next message.
- **Tested.** Over the fixture, for every key of the set, the closed table fires exactly the
  subscribers, in exactly the order, that an open table's scan fires; a subscription on an undeclared
  pattern is refused and one on a key declared only as a publisher is refused; a subscription made
  before the gate is set is still delivered to.
- **Measured** (`tests/key_set_cost.rs`, release build, the shared build machine with one free core
  and two or three other jobs, six runs; times swing by up to a factor of two between runs there, so
  they are ranges, and the allocations are exact). The fixture has 18 keys and 8 subscribers; the
  memory has 8 slots.

  | traffic, gate | ns a message | allocations a message |
  |---|---|---|
  | rotate over every key, open, memory on | 229 to 384 | 3.06 |
  | rotate over every key, closed | 25 to 45 | 0 |
  | one key repeated, open, memory on | 13 to 29 | 0 |
  | one key repeated, closed | 18 to 39 (before the last-key check, 41 to 45) | 0 |
  | rotate over every key, open, memory left out | 229 to 232 | 1 |
  | one key repeated, open, memory left out | 237 to 240 | 1 |
  | rotate or repeat, closed (the memory is not read) | 19 to 25 | 0 |

  What it says: where the open table's memory misses, which is every message of a node that hears many
  keys and the first of each key, the closed table is about five to eleven times faster and allocates
  nothing, where the open one allocates one to three times a message (the memory's writes, and the key
  split). On one repeated key the memory is at least as fast as the closed table, and the closed table
  is between level with it and about one and a half times slower; it is not faster there. The claim of
  D7, that the table replaces the memory, holds for the first case and not the second, on the figures
  above. Not measured: more subscribers than 8, a real link under the drive loop, ROM and RAM of a
  table, an image on a target.
- **Not done.** The alias row is still text and not a number (D5): resolution at the edge is what a
  peer's declared resource needs, and a resource is a prefix that a selector may be built on, so it is
  not simply a key id. A declared key must be written in the canonical form the table stores a
  pattern in, which the generator does not check yet (a pattern with a `$*` chunk the canonical form
  would rewrite is registered in its canonical form and then is not the declared text). A reply's key
  is not gated. No image supplies a table, and the match memory is still built in a closed image.

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
