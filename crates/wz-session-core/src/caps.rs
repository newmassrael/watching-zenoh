// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Deploy-declared capacity constants — the SSOT for the bounded
//! backing sizes (`N`) the application-layer registries and the
//! owned-output value modules pin onto [`crate::bounded::BoundedVec`]
//! / [`crate::bounded::BoundedString`].
//!
//! # Why a const module rather than a type parameter
//!
//! ARCHITECTURE.md §2.4 mandates `static-first, dynamic-opt-in`. The
//! capacities here are **deploy facts**: how many subscriptions a
//! firmware holds, how long a keyexpr it admits. In the current scope
//! (one SCXML machine per sidecar — §2.1) there is exactly one
//! instance of each registry per build, so no two instances of the
//! same registry kind ever carry *different* capacities. Encoding a
//! per-instance capacity distinction the domain does not have (a
//! `const N` type parameter, or a `DeployCaps` trait) would be
//! speculative generality — the textbook YAGNI position is to make
//! capacity a build-wide constant and let a registry field bind it
//! directly:
//!
//! ```ignore
//! subscribers: BoundedVec<Subscriber<C>, { caps::MAX_SUBSCRIPTIONS }>,
//! ```
//!
//! A `const`-path is a valid const-generic argument on stable Rust
//! (it is a concrete value, not a generic parameter), so this needs
//! no `generic_const_exprs`. If a future round introduces multiple
//! machines per firmware, the instance divergence is resolved at
//! *deploy-codegen* time (the generator emits one capacity profile per
//! machine), not by adding a type parameter here.
//!
//! # Backing-profile interaction
//!
//! Per [`crate::bounded`], `N` is the hard limit only on the FIXED
//! backing (`alloc` off, or `bounded-heapless` on: the MCU profiles); on
//! the growable backing (the AP profile) it is advisory and `push` never
//! fails. So these values bound the MCU footprint and serve as
//! documentation on AP. Before `bounded-heapless`, every MCU deploy linked
//! an allocator and therefore compiled the growable backing, which made
//! every limit here advisory on the MCU too; that feature is what turns
//! them into refusals ([`crate::bounded::ENFORCES_CAPACITY`] says which a
//! build has).
//!
//! # Provenance
//!
//! These are **documented defaults**. The MCU profile's real values
//! are a per-deploy fact that a `deploy.yaml` → `caps` codegen step
//! will emit (the same generator family as the switchboard generator);
//! that wiring is a follow-up. Distinct from protocol constants fixed
//! by the zenoh wire spec (e.g. the 16-byte ZID ceiling) — those are
//! not deploy-tunable and land in a sibling `limits` module when their
//! first consumer (the registry's `own_zid` field) migrates.

/// Maximum byte length of a canonicalized keyexpr stored by a registry
/// (subscription pattern, resolved peer mapping). Bounds
/// [`crate::keyexpr_canon::canonize_keyexpr`]'s output buffer on the
/// no-alloc backing; a pattern whose canonical form exceeds this is
/// rejected with [`crate::keyexpr_canon::KeyexprCanonError::ExceedsCapacity`]
/// rather than silently truncated.
pub const MAX_KEYEXPR_BYTES: usize = 256;

/// Maximum number of concurrently-registered local subscriptions in a
/// [`crate::pubsub::SubscriberRegistry`]. Bounds the registry's
/// subscriber table on the no-alloc backing; a `register` past this is
/// rejected (`RegisterError::TableFull`) rather than growing the table.
pub const MAX_SUBSCRIPTIONS: usize = 16;

/// Maximum number of concurrently-registered local queryables in a
/// [`crate::query::QueryableRegistry`]. Bounds the registry's queryable
/// table on the no-alloc backing; a `register` past this is rejected
/// (`RegisterError::TableFull`) rather than growing the table.
pub const MAX_QUERYABLES: usize = 16;

/// Maximum number of concurrently-outstanding pending z_get queries in a
/// [`crate::reply::ReplyRegistry`]. Bounds the registry's pending table
/// on the no-alloc backing; a `register` past this is rejected
/// (`RegisterError::TableFull`) rather than growing the table. Also
/// bounds the `keep` / `fired` partitions the no-alloc `fire_final_for` /
/// `sweep_timed_out` build on the stack.
pub const MAX_PENDING_QUERIES: usize = 16;

/// Maximum number of installed declaration observers per list
/// (`on_decl` / `on_undecl`) in each of the remote-declaration
/// registries ([`crate::declare::subscriber::RemoteSubscriberRegistry`],
/// [`crate::declare::queryable::RemoteQueryableRegistry`],
/// [`crate::declare::liveliness::LivelinessRegistry`]). Bounds each
/// observer list on the no-alloc backing; an `on_*_declared_sink` past
/// this is rejected (`RegisterError::TableFull`) rather than
/// growing the list. Observers are installed once at startup, so the
/// default is small.
pub const MAX_DECL_OBSERVERS: usize = 8;

/// Maximum number of concurrently-registered liveliness-subscriber
/// interest slots in a
/// [`crate::declare::liveliness_subscriber::LivelinessSubscriberRegistry`].
/// Bounds the registry's slot table on the no-alloc backing; a `register`
/// past this is rejected rather than growing the table.
pub const MAX_LIVELINESS_SUBSCRIPTIONS: usize = 8;

/// Maximum number of liveliness tokens wz itself can declare and hold
/// concurrently in a [`crate::declare::local_token::LocalTokenRegistry`]
/// (the declarer-side mirror of [`MAX_LIVELINESS_SUBSCRIPTIONS`]). Bounds
/// the registry's token table on the no-alloc backing; a `register` past
/// this is rejected (`RegisterError::TableFull`) rather than growing the
/// table. R311hn (Track 2, Decision 2 no-heap emit) — was an unbounded
/// `HashMap` on the prior alloc-only backing.
pub const MAX_LOCAL_TOKENS: usize = 8;

/// Maximum number of concurrently-outstanding pending liveliness GET
/// (snapshot) queries in a
/// [`crate::declare::liveliness_get::LivelinessGetRegistry`]. Bounds the
/// registry's pending table on the no-alloc backing; a `register` past
/// this is rejected (`RegisterError::TableFull`) rather than growing the
/// table. Also bounds the `keep` / `fired` partitions the no-alloc
/// `dispatch_final` / `sweep_timed_out` build on the stack. A liveliness
/// snapshot get is short-lived (one CURRENT Interest, drained on the
/// terminating `Declare(DeclFinal)`), so few are outstanding at once;
/// the default mirrors [`MAX_LIVELINESS_SUBSCRIPTIONS`].
pub const MAX_PENDING_LIVELINESS_GETS: usize = 8;

/// Maximum number of [`crate::declare::local_token::DeclResponseItem`]
/// records the application-layer observer stages for one drain cycle
/// (the declarer-side liveliness interest-response buffer). One inbound
/// CURRENT Interest stages up to [`MAX_LOCAL_TOKENS`] `DeclToken` items
/// plus one `DeclFinal` — 9 items per chain. R311hn (Track 2) — replaces
/// the prior unbounded `Vec<DeclareOwned>` staging.
///
/// R311y341 — this said "the buffer accumulates across the Interests in a
/// single poll batch, so the bound is sized generously", and that sentence
/// straddles two profiles that never meet. Read per backing
/// ([`crate::bounded::BoundedVec`]):
///
/// - **AP (`alloc`)** — the backing is a `Vec` and `N` is ADVISORY; `push`
///   cannot fail. Batching is real here (`dispatch_messages` threads one
///   buffer across every Interest in a frame, and it is `alloc`-gated), so
///   chains do accumulate — but nothing can be dropped, and this constant
///   does not bound anything. It is a footprint declaration, not a limit.
/// - **MCU (no-alloc)** — `N` is the HARD limit `push` enforces, but the
///   `alloc`-gated batching does not exist: the consumer drives
///   `respond_to_interest_borrowed` per Interest, so one 9-item chain meets
///   32 with room to spare.
///
/// The batching and the hard bound therefore sat on OPPOSITE sides of the
/// `alloc` cfg, which is why the swallowed `let _ = push(Final)` in
/// `respond_to_interest_borrowed` was unreachable as shipped. That was a
/// property of the cfg split, NOT a guarantee this constant provides.
///
/// `bounded-heapless` (a fixed backing WITH `alloc`) is exactly the
/// consumer that sentence warned about: the batching path and the hard
/// bound meet. So the stagers no longer push best-effort. Each reply chain
/// is sized first and staged WHOLE -- its items and its terminating `Final`
/// -- or refused and counted
/// ([`crate::pubsub::SubInterestRefusals`], the observer's
/// `token_interest_chains_refused`); a chain is never truncated and never
/// loses its `Final`. What this number still decides is how many chains
/// one frame can be answered with before the next drain.
pub const MAX_PENDING_DECLARES: usize = 32;

/// Maximum number of inbound SUBSCRIBER `Interest`s one
/// [`crate::pubsub::SubscriberRegistry`] remembers — zenoh's per-face
/// `remote-interests` table, session-local half.
///
/// One entry per live remote publisher that armed a write filter over this
/// session (`net/filtering.c` `_z_write_filter_create` emits exactly one
/// Interest per declared publisher), retired on that publisher's
/// `Interest(Final)`. A peer with more concurrently-declared publishers than
/// this simply does not get the surplus ones registered: they still receive
/// the CURRENT dump (which is answered from the message, before registration),
/// so the loss is confined to the FUTURE half — a later local subscriber is
/// not pushed to them. Sized against [`MAX_SUBSCRIPTIONS`] rather than
/// generously: the table is a linear scan on every inbound Interest and every
/// local declare.
pub const MAX_INBOUND_SUB_INTERESTS: usize = 16;

/// Maximum number of keyexpr aliases ONE peer may have declared to this session
/// at a time (`DeclKexpr.id -> keyexpr`, the deploy `limits` key
/// `peer_keyexpr_aliases`). Bounds [`crate::id_map::PeerAliases`] on the fixed
/// backing: a `DeclKexpr` for a NEW id with the table full is refused and
/// counted, the alias is not recorded, and a later reference to it resolves to
/// nothing (the message naming it is dropped, as one naming an undeclared id
/// always was) rather than growing a table the peer controls.
///
/// A fixed backing allocates this many rows of [`MAX_KEYEXPR_BYTES`] text per
/// SESSION, which is why it is a number the deploy file states and not a hidden
/// constant: `deploy/mcu_client_and_group.yaml` carries the same 16, and
/// `tests/session_slot_pool_deploy.rs` holds the two equal.
pub const MAX_PEER_KEYEXPR_ALIASES: usize = 16;

/// Maximum number of declarations of ONE kind (subscribers, queryables, liveliness
/// tokens) a peer may hold open to this session at a time (the deploy `limits`
/// key `remote_decls`). Bounds each of [`crate::id_map::DeclaredKeys`] and
/// [`crate::id_map::DeclaredQueryables`] on the fixed backing: a `Decl*` for a NEW
/// id with its table full is refused and counted and is not announced to the
/// application, as one whose keyexpr does not resolve never was.
pub const MAX_REMOTE_DECLS: usize = 16;

/// Maximum number of data replies a queryable's handlers may have staged for ONE
/// session between two drains (the deploy `limits` key `pending_replies`). On the
/// fixed backing a reply past it is refused with
/// [`crate::query_sink::ReplyError::StagingFull`] and counted; the handler that
/// made it is told, and nothing is built on the heap in its place.
pub const MAX_PENDING_REPLIES: usize = 8;

/// Maximum number of `ResponseFinal`s ONE session may owe between two drains (the
/// deploy `limits` key `pending_finals`). A Request that would need a Final the
/// table cannot hold is refused BEFORE its queryables run, and counted: a query
/// that cannot be terminated is not answered, because a reply with no `Final`
/// after it leaves the peer's `get` open until its own timeout.
pub const MAX_PENDING_FINALS: usize = 8;

/// Maximum byte length of the payload of ONE staged reply, and the bytes of an
/// attachment it carries beside it (the deploy `limits` key
/// `reply_payload_bytes`). A reply that does not fit is refused with
/// [`crate::query_sink::ReplyError::PayloadTooLarge`], never truncated.
pub const MAX_REPLY_PAYLOAD_BYTES: usize = 1024;

/// Maximum byte length of ONE admin reply body (the deploy
/// `session_pool.process.admin_reply_bytes` key): the buffer every admin leg is
/// written into before it is handed to the session's reply stage
/// (`admin_reply::AdminReplyArena`, under `adminspace-core`). A body that does not
/// fit is refused, counted, and answered to the querier as a typed error; it is
/// never cut short.
///
/// An admin reply is STAGED as an ordinary reply, so it is also bound by
/// [`MAX_REPLY_PAYLOAD_BYTES`]: a number above that one would be a buffer that
/// builds replies the stage then refuses. The deploy validator holds the two in
/// that order, and this crate asserts it at compile time.
pub const MAX_ADMIN_REPLY_BYTES: usize = 1024;

const _: () = assert!(
    MAX_ADMIN_REPLY_BYTES <= MAX_REPLY_PAYLOAD_BYTES,
    "an admin reply is staged as a reply, so its bound cannot exceed the reply payload bound"
);

/// Maximum byte length of the keyexpr one admin reply is stamped with:
/// `@/<zid>/<whatami>/<leg>` and, for a per-entity leg, the entity's own
/// keyexpr of up to [`MAX_KEYEXPR_BYTES`], so two of them cover the prefix and
/// any declared keyexpr. A key past it is refused as a typed error, not shortened.
pub const MAX_ADMIN_KEY_BYTES: usize = 2 * MAX_KEYEXPR_BYTES;

/// Maximum byte length of one static-scouting peer locator string
/// (`deploy.connect[]` entry, e.g. `"udp/192.168.1.10:7447"`). Bounds the
/// [`crate::bounded::BoundedString`] each
/// [`crate::scout_static::synth_static_locators`] entry is built into on
/// the no-alloc backing; a configured locator longer than this is rejected
/// (skipped) rather than truncated. Matches the conservative per-locator
/// length the scouting Hello sizing uses (docs/scouting-fsm.md §2.6,
/// "per-locator length of 64 bytes") — long enough for an `ipv6` locator
/// with a `proto/` prefix and port, with margin.
pub const MAX_LOCATOR_LEN: usize = 64;

/// Maximum number of static-scouting peer locators
/// ([`crate::scout_static::synth_static_locators`] output capacity =
/// `deploy.connect[]` length). Bounds the no-alloc synthesis on the MCU
/// backing; a `connect[]` longer than this stops at the cap (a future
/// `deploy.yaml` -> caps codegen step enforces the bound at build time, the
/// same hard-error model as docs/scouting-fsm.md §2.6 hello_max_peers).
/// Mirrors the MCU `hello_max_peers` discovery capacity (deploy
/// `mcu_target.yaml:263 = 8`): a static deploy is a small fixed peer set
/// (e.g. one AP for a fixed AP<->MCU pair), so few configured locators.
pub const MAX_STATIC_CONNECT: usize = 8;
