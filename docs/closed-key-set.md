# Closed key set

Status: design; phases 1 to 3b (the pure table, the generator, the model test, the gate, the policy, the
refusal of a peer's data key and delivery by the selection of a key) are built in the subscriber table,
a node's declaration carries its table, and phase 4 (what each declared peer may publish) is built up
to the gate; no node's code calls `set_key_gate` with its table yet. Written 2026-10-26 so that what a deployment asks of "every key is known at build time" is
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
  out) recently matched keys, valid for one epoch. A key that has not arrived lately is matched in full.
  Measured on 2026-10-26 it was built on the heap profile only; it is now written once over both storage
  policies. A fixed table holds its slots in RAM, so it reads its own `MATCH_MEMO_FIXED_SLOTS` (default
  0: a build that does not ask pays nothing) and remembers a key of at most `MATCH_MEMO_KEY_BYTES` (64);
  a longer key is matched on every arrival.
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
upstream's access control, which stays the AP's answer for open deployments. Read against the tree,
the two are not one thing declared twice: `wz-access-control` is std and AP only, its rules are JSON5
over a subject of five axes, and a fixed-memory node declaration has no place for them. The closed
allowance is therefore one table with two possible sources (a direct declaration in the node file,
and, for an AP image that is closed, a compilation of its access-control rules), and the part that
must agree is what each says for the same peer and key. See "Phase 4, as built".

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
4. **Per-peer allowance** (D6), built up to the gate: see "Phase 4, as built".
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
- **The place.** `SubscriberTable` holds a `KeyGate` and applies it to a message that came from a peer,
  in `fire_to_subscribers`, `fire_plain_to_subscribers` and, added later, `fire_lent` (see "Phase 4, as
  built" for why the third was missing: the first cut of this phase claimed that the first two were
  every delivery, from a search of `pubsub.rs` alone, and the in-place receive path, which a
  fixed-memory image takes, is in the child module `pubsub/in_place.rs` and called the matcher
  directly). A local publish is the application's own and is not gated. A refused message
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
  not simply a key id. A reply's key is not gated. No node's code calls `set_key_gate` with its table
  yet (see "The node's table, as built"), and the match memory is still built in a closed image.
- **Canonical form, built after the first cut of this phase.** The subscriber table registers a pattern
  in canonical form, so a declared key spelled otherwise (`a/**/*`, a chunk of only `$*`, `a*b`) would
  never be the text the table holds and its subscription would be refused. The generator now refuses
  such a key, by `is_key_expression`, a port of `keyexpr_canon::validate_keyexpr`. The port is held to
  the validator as the matcher is: the corpus carries its verdict on every text of up to six
  characters over `a / * $ ?` (19,530 texts, 108 accepted), and the model test compares each with the
  validator and checks that every text the validator accepts is its own canonical form. The test was
  run with the rule that a `$` may not follow a `$*` taken out of the port, and it failed; with the rule
  back it passes.

## The node's table, as built

- **A node that states `[policy] key-set = "closed"` carries its table.** `scripts/lib/wz_node.py` takes
  the node's entities, each a kind and a key, as its key set, holds them to what the table can carry
  (canonical keys, concrete publishers and tokens, no wildcard that nothing concrete meets, no entity
  twice; a refusal says `key set:`), and writes the table into the node's generated `declared.rs` as
  a module `key_set` with `CATALOGUE` and `CLOSED`. A node that states nothing, or `open`, has the
  module with `CLOSED = None` and is held to nothing new, so the seven registered nodes keep their
  declarations and gain five lines each.
- **One name for both.** A node's code reads `declared::key_set::CLOSED`: `Some(table)` for a closed
  node and `None` for any other. The adoption is the three lines `if let Some(table) = CLOSED {
  subscribers.set_key_gate(KeyGate::closed(table)); }` before the first subscription is made, which is
  the part of the slot node and the cooperative engine that sessions ef and 11 own and which is not
  made here. `CLOSED` is the node's own declaration, so the node needs no second read of the policy.
- **The table is a module that names nothing of its includer's.** It carries its own `use` and inner
  attribute and refers to the crate by name, because a node's file already has a `MEMBERS` of its own
  and is `include!`d. The model test includes the generated fixture the same way, which compiles the
  form; the type-check of `declared-node` against a regenerated node file passes on pc2.
- **The matcher and verdict ports moved to `scripts/lib/wz_keyexpr.py`**, with `key_problem` and
  `rust_string`, so that `wz_node.py` uses them without importing the generator that imports it.

## Phase 4, as built

- **A correction first.** The gate of phases 3a and 3b did not cover the in-place receive path:
  `deliver_lent` in `pubsub/in_place.rs` called `fire_into`, the matcher, directly, so a closed table
  neither refused a key outside its set nor delivered by selection there. That is the path of the
  fixed-memory slot images, the profile the closed set is for. It is now `fire_lent`, which the lent
  path calls, with the gate and the selection, and the plain-Put path of the same module passes the
  peer's class. Two tests in `in_place.rs` hold the lent path to the owned path for a key outside the
  set and for a peer's class; with the gate bypassed again in `fire_lent` the first fails. These two
  tests need the `storage-profile` feature, which is why a run of the default features did not show
  them: the first run of them in the default build matched none, and they were run with the feature on.
- **The table.** `crates/wz-session-core/src/key_allowance.rs`: `PeerAllowance`, one row of bits for each
  declared peer and operation, one bit for each key of the set. `class_of(zid)` finds a peer's row once,
  from the sixteen bytes of its zid (the form `PEER_NODES` holds), and `allows(class, op, key)` is one
  bit test. A peer that is not declared has no row. `PeerAllowance::new` is a `const fn` that checks the
  shape (the zids' order and uniqueness, the size of the bit array, the spare bits zero). Only one
  operation, `Publish` (a peer's Put or Delete on a key, received here), is decided so far.
- **The gate.** `KeyGate::with_allowance` and `admit_key_from(class, op, text)`: the key must be of the
  set first (so a key outside it is refused as that, whoever sent it), then the peer must be one the
  image declares and its row must allow the key. A closed gate that declares no peers asks nothing of
  the peer. Refusals are counted: `peer_unknown` and `peer_not_allowed` beside the others.
- **The peer's class.** `SubscriberPeer` holds the class (`set_class`, forgotten with the peer), and
  every delivery of a peer's message passes it. A caller with no peer to give, `dispatch_borrowed`,
  passes none, which an image that declares its peers refuses, so a closed image that declares peers
  must call `dispatch_borrowed_from`. Nothing in the tree calls `set_class` yet: the session that
  learns a peer's zid does.
- **The source, direct.** A node that states a closed key set may declare `[[allow]]` tables: a `peer`
  (a zid the node declares as a peer endpoint), `ops` and `keys`. The generator refuses a peer the node
  does not declare, an operation outside the vocabulary, a key that is not canonical, and a pattern no
  concrete key of the set meets (it would allow nothing), and an `[[allow]]` in a node that states no
  closed key set. A key is allowed to a peer for an operation when it is concrete and some pattern
  listed for that peer and operation intersects it. For a concrete key that is the directional
  inclusion access control uses (the pattern covers the key) and the symmetric intersection of the
  matcher alike, which is why the existing port of the matcher is enough and nothing new was ported.
  The table is written into the node's `declared.rs` as `key_set::ALLOWED_PEERS`, `Some` when the node
  declares allowances and `None` otherwise.
- **Tested.** The model test compares every bit of the fixture's allowance (three peers, 18 keys) with the
  real matcher over what was declared, including that `**` does not allow a verbatim key and that no
  key that is itself a pattern is allowed; the generator, with the rule that a pattern key is not
  allowed removed, fails it. A gate over the fixture's tables refuses a key outside the set, a peer not
  declared and a key a declared peer's row does not allow, each counted once.
- **Not built.** The second source (compiling access-control rules), the other operations (a peer's
  query, its declarations, what this node sends it), and a node's code that reads `ALLOWED_PEERS` and
  `set_class`, which is the slot node's and the cooperative engine's.

## A reply's key, as built

- **The seam.** Every delivery of a reply, from the wire (owned, lent in place and borrowed) and from the
  loopback, reaches `ReplyRegistry::fire_replies_for`, where the reply-keyexpr acceptance already ran.
  Searched this time in the child module too (`reply/in_place.rs` calls it at one place). The gate sits
  there: `ReplyRegistry` holds a `KeyGate`, starting as the build's `key-set` policy and replaced with
  `set_key_gate`, and a reply a peer sent on a key outside the set is dropped before any pending
  query is asked, counted as `outside_set`.
- **What is not gated.** An error reply, which names no key, and the application's own loopback reply
  (`deliver_local_reply`), which is not a peer's, as a local publish is not on the subscriber side.
  The allowance is not asked for a reply: it decides what a peer may publish, and a reply is an
  answer to a query this node asked.
- **Tested** by a unit test of the registry (a key of the set, a key outside it as a Put and as a Del,
  an error reply, a loopback reply, an open registry; the pending query stays), which fails with the
  gate disabled. It needs the features `codec-response` and `codec-response-final`, which the default
  build does not have, so it was run with them on.
- **Not done.** No image calls `set_key_gate` on its reply registry yet; a node adopting its table
  gives the same gate to both registries.

## The closed set is a build feature, as built

The closed mode first shipped in every build, open or closed, and the open ones paid for it: hosted
pico-client text grew from 1,828,525 to 1,833,173 bytes over the rounds of phases 3 to 4, and the
session slot of the two admin node images grew 8 bytes (a number on every subscriber row and a class on
every peer). A mode a build does not use should cost it nothing, so the closed set is now under the
cargo feature `key-set-closed` of `wz-session-core`.

- **What the feature adds.** `key_catalogue`, `key_allowance` and the closed `key_gate`. It is additive
  and implies nothing: with it and an open policy a build starts with an open gate and may be handed a
  closed one (the tests of the closed mode run so).
- **What a build without it has.** The same path `key_gate` with the open gate only
  (`key_gate_open.rs`): `KeyGate` has no field, and `KeyId`, `EntityId`, `ClassId` and `Refusal` are
  enums with no value, so `Option<EntityId>` on every subscriber row and `Option<ClassId>` on every peer
  are zero-sized, and the arm that delivers by a key's number cannot be taken and is not generated. The
  calling code is written once, with no `cfg` at its call sites beyond the one function that reads a
  selection. A test holds the sizes at zero.
- **The policy and the feature agree or the build stops.** `key-set = closed` in a build without the
  feature fails a const assertion that names the feature, so a build cannot ask for a mode it lacks and
  silently run open. The closed value of the policy and the feature are two spellings of one fact, and
  an image that states the first enables the second.
- **A node declaration carries its table only when it is closed.** The generator no longer emits an
  empty `key_set` module for an open node: it would name a module the open build does not have. Seven
  generated files lost it.
- **Measured** on 2026-10-26, same machine and compiler, before and after: the session slot of
  `mcu-admin-node` 36,808 to 36,800 bytes and of `zephyr-admin-node` 36,800 to 36,792 (the allowance's
  8 bytes, gone); pico-client text 1,793,878 to 1,790,934 bytes locally. The hosted reading is the
  one the budgets hold and is read after the push.
- **Tested** with the feature on (the whole crate under `--all-features`, and the two integration tests
  `key_catalogue_model` and `key_set_cost`, which need it) and off (the crate's lib tests, which
  include the zero-size test).

## What is not decided

- **D4 for the owner.** Does a closed image admit a message whose key is undeclared but matches a
  declared wildcard selector? The design above refuses it. The alternative admits it as a bounded text
  row under an allowed selector, at the price of a run-time matcher and a run-time bound.
- **D6, narrowed.** Whether an AP image that is closed and already has access-control rules should
  have its allowance compiled from them (the second source of "Phase 4, as built") is the open part;
  the fixed-memory node does not need it.
- **Publisher wildcards.** A publisher on a wildcard key is not expressible in a table of concrete
  keys. The design lists the concrete keys a publisher uses; whether a wildcard publisher is needed at
  all is a question for the deployments that have one.
- **Resource ids declared by the sender** could also be fixed in the table (each key id gets a wire id
  at build time, so no declaration is sent). Left for after phase 3, when the receive side is measured.

## What this does not claim

Nothing here is measured. That the table is faster than the memo, that the alias row is smaller, and
that the closed mode removes the matcher from the receive path are the questions phase 3 answers.
