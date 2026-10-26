// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! These are **documented defaults**, and each is also a number an image
//! can state for itself. Every limit is declared in `deploy/wz-config.toml`
//! (its name, default and help) and its value is read in the generated
//! `caps_generated.rs` as `limit(option_env!("WZ_LIMIT_<NAME>"), <default>)`:
//! the default when the build does not say, the number the build's
//! environment states when it does; each constant below binds a name the
//! code uses to that value. A firmware that only answers two short queries
//! has no use for 16 subscription rows of 256 bytes of key and pays for them
//! in RAM; it states `WZ_LIMIT_MAX_SUBSCRIPTIONS=1` and every table sized by
//! the constant is sized by that. The numbers stay build-wide constants (one
//! value per name per image), because that is the shape of the fact; what is
//! configurable is where the value comes from: for a Zephyr image from
//! Kconfig (`deploy/Kconfig.limits`, generated from the declaration by
//! `scripts/lib/wz_config.py`, which `--check`s that it, the generated module
//! and the bindings below are current), for another front end from whatever
//! sets the environment of the cargo build (the deploy file's `limits` keys
//! are the next such front end). A value that is not a decimal number is a
//! compile error, not a default.
//!
//! Distinct from protocol constants fixed by the zenoh wire spec (e.g. the
//! 16-byte ZID ceiling) — those are not tunable and land in a sibling
//! `limits` module when their first consumer (the registry's `own_zid`
//! field) migrates.

#[path = "caps_generated.rs"]
mod generated;

/// A limit: `stated` is the text of the build's `WZ_LIMIT_<NAME>`, if it set one.
const fn limit(stated: Option<&str>, default: usize) -> usize {
    let Some(text) = stated else {
        return default;
    };
    let digits = text.as_bytes();
    assert!(!digits.is_empty(), "a WZ_LIMIT_* value is empty");
    let mut value = 0usize;
    let mut i = 0;
    while i < digits.len() {
        let digit = digits[i];
        assert!(
            digit.is_ascii_digit(),
            "a WZ_LIMIT_* value is not a decimal number"
        );
        value = value * 10 + (digit - b'0') as usize;
        i += 1;
    }
    value
}

/// Maximum byte length of a canonicalized keyexpr stored by a registry
/// (subscription pattern, resolved peer mapping). Bounds
/// [`crate::keyexpr_canon::canonize_keyexpr`]'s output buffer on the
/// no-alloc backing; a pattern whose canonical form exceeds this is
/// rejected with [`crate::keyexpr_canon::KeyexprCanonError::ExceedsCapacity`]
/// rather than silently truncated.
pub const MAX_KEYEXPR_BYTES: usize = generated::MAX_KEYEXPR_BYTES;

/// Maximum number of concurrently-registered local subscriptions in a
/// [`crate::pubsub::SubscriberRegistry`]. Bounds the registry's
/// subscriber table on the no-alloc backing; a `register` past this is
/// rejected (`RegisterError::TableFull`) rather than growing the table.
pub const MAX_SUBSCRIPTIONS: usize = generated::MAX_SUBSCRIPTIONS;

/// How many distinct keys the receive match cache ([`crate::pubsub::SubscriberRegistry`]'s memory
/// of which subscriptions a key matched) holds at once. A direct-mapped table: a key that maps to
/// a used slot replaces what was there. `0` leaves the cache out: every message is matched against
/// the subscriptions, which reaches the same subscribers in the same order. A count of keys and
/// not a table of sessions: it sizes the cache only.
pub const MATCH_MEMO_SLOTS: usize = generated::MATCH_MEMO_SLOTS;

/// [`MATCH_MEMO_SLOTS`] for a table of the fixed storage policy, which holds its cache in RAM
/// whether or not a slot is used and so states the count apart from the heap's. `0` (the default)
/// leaves the cache out of such a build.
pub const MATCH_MEMO_FIXED_SLOTS: usize = generated::MATCH_MEMO_FIXED_SLOTS;

/// The longest key, in bytes, a fixed-policy match cache slot holds. A longer key is matched on
/// every arrival and not remembered. Read only where [`MATCH_MEMO_FIXED_SLOTS`] is above `0`.
pub const MATCH_MEMO_KEY_BYTES: usize = generated::MATCH_MEMO_KEY_BYTES;

/// How many samples one delivery lane ([`crate::delivery_lane::DeliveryLane`]) holds at once, the
/// `EVENTS` of the lane a host builds. A sample past it is refused and counted. Must be at least
/// `1`: a lane nothing can enter is not a smaller lane.
pub const DELIVERY_LANE_EVENTS: usize = generated::DELIVERY_LANE_EVENTS;

/// How many bytes of copied samples one delivery lane holds at once, the end of the byte area a
/// sample skipped to stay in one piece included. Must be at least `1`.
pub const DELIVERY_LANE_BYTES: usize = generated::DELIVERY_LANE_BYTES;

/// How many callback invocations one delivery lane owes at once. A host that admits a sample once
/// for each subscription it reaches owes one per sample, so this binds there only past
/// [`DELIVERY_LANE_EVENTS`] and is left larger than it. Must be at least `1`.
pub const DELIVERY_LANE_CALLBACKS: usize = generated::DELIVERY_LANE_CALLBACKS;

const _: () = assert!(
    DELIVERY_LANE_EVENTS >= 1 && DELIVERY_LANE_BYTES >= 1 && DELIVERY_LANE_CALLBACKS >= 1,
    "the delivery lane limits must each be at least 1"
);

/// Maximum number of concurrently-registered local queryables in a
/// [`crate::query::QueryableRegistry`]. Bounds the registry's queryable
/// table on the no-alloc backing; a `register` past this is rejected
/// (`RegisterError::TableFull`) rather than growing the table.
pub const MAX_QUERYABLES: usize = generated::MAX_QUERYABLES;

/// Maximum number of concurrently-outstanding pending z_get queries in a
/// [`crate::reply::ReplyRegistry`]. Bounds the registry's pending table
/// on the no-alloc backing; a `register` past this is rejected
/// (`RegisterError::TableFull`) rather than growing the table. Also
/// bounds the `keep` / `fired` partitions the no-alloc `fire_final_for` /
/// `sweep_timed_out` build on the stack.
pub const MAX_PENDING_QUERIES: usize = generated::MAX_PENDING_QUERIES;

/// Maximum number of installed declaration observers per list
/// (`on_decl` / `on_undecl`) in each of the remote-declaration
/// registries ([`crate::declare::subscriber::RemoteSubscriberRegistry`],
/// [`crate::declare::queryable::RemoteQueryableRegistry`],
/// [`crate::declare::liveliness::LivelinessRegistry`]). Bounds each
/// observer list on the no-alloc backing; an `on_*_declared_sink` past
/// this is rejected (`RegisterError::TableFull`) rather than
/// growing the list. Observers are installed once at startup, so the
/// default is small.
pub const MAX_DECL_OBSERVERS: usize = generated::MAX_DECL_OBSERVERS;

/// Maximum number of concurrently-registered liveliness-subscriber
/// interest slots in a
/// [`crate::declare::liveliness_subscriber::LivelinessSubscriberRegistry`].
/// Bounds the registry's slot table on the no-alloc backing; a `register`
/// past this is rejected rather than growing the table.
pub const MAX_LIVELINESS_SUBSCRIPTIONS: usize = generated::MAX_LIVELINESS_SUBSCRIPTIONS;

/// Maximum number of liveliness tokens wz itself can declare and hold
/// concurrently in a [`crate::declare::local_token::LocalTokenRegistry`]
/// (the declarer-side mirror of [`MAX_LIVELINESS_SUBSCRIPTIONS`]). Bounds
/// the registry's token table on the no-alloc backing; a `register` past
/// this is rejected (`RegisterError::TableFull`) rather than growing the
/// table. R311hn (Track 2, Decision 2 no-heap emit) — was an unbounded
/// `HashMap` on the prior alloc-only backing.
pub const MAX_LOCAL_TOKENS: usize = generated::MAX_LOCAL_TOKENS;

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
pub const MAX_PENDING_LIVELINESS_GETS: usize = generated::MAX_PENDING_LIVELINESS_GETS;

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
pub const MAX_PENDING_DECLARES: usize = generated::MAX_PENDING_DECLARES;

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
pub const MAX_INBOUND_SUB_INTERESTS: usize = generated::MAX_INBOUND_SUB_INTERESTS;

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
pub const MAX_PEER_KEYEXPR_ALIASES: usize = generated::MAX_PEER_KEYEXPR_ALIASES;

/// Maximum number of declarations of ONE kind (subscribers, queryables, liveliness
/// tokens) a peer may hold open to this session at a time (the deploy `limits`
/// key `remote_decls`). Bounds each of [`crate::id_map::DeclaredKeys`] and
/// [`crate::id_map::DeclaredQueryables`] on the fixed backing: a `Decl*` for a NEW
/// id with its table full is refused and counted and is not announced to the
/// application, as one whose keyexpr does not resolve never was.
pub const MAX_REMOTE_DECLS: usize = generated::MAX_REMOTE_DECLS;

/// Maximum number of data replies a queryable's handlers may have staged for ONE
/// session between two drains (the deploy `limits` key `pending_replies`). On the
/// fixed backing a reply past it is refused with
/// [`crate::query_sink::ReplyError::StagingFull`] and counted; the handler that
/// made it is told, and nothing is built on the heap in its place.
pub const MAX_PENDING_REPLIES: usize = generated::MAX_PENDING_REPLIES;

/// Maximum number of `ResponseFinal`s ONE session may owe between two drains (the
/// deploy `limits` key `pending_finals`). A Request that would need a Final the
/// table cannot hold is refused BEFORE its queryables run, and counted: a query
/// that cannot be terminated is not answered, because a reply with no `Final`
/// after it leaves the peer's `get` open until its own timeout.
pub const MAX_PENDING_FINALS: usize = generated::MAX_PENDING_FINALS;

/// Maximum byte length of the payload of ONE staged reply, and the bytes of an
/// attachment it carries beside it (the deploy `limits` key
/// `reply_payload_bytes`). A reply that does not fit is refused with
/// [`crate::query_sink::ReplyError::PayloadTooLarge`], never truncated.
pub const MAX_REPLY_PAYLOAD_BYTES: usize = generated::MAX_REPLY_PAYLOAD_BYTES;

/// The bytes ONE session's reply stage holds for what its queryables have staged
/// between two drains: the room for [`MAX_PENDING_REPLIES`] replies of
/// [`MAX_REPLY_PAYLOAD_BYTES`] of payload and a keyexpr of [`MAX_KEYEXPR_BYTES`]
/// each, derived from those three limits and so from the deploy keys that state
/// them (`pending_replies`, `reply_payload_bytes`, `keyexpr_bytes`). On the fixed
/// backing a staged reply's keyexpr, payload, attachment and encoding schema are
/// bytes of this one arena ([`crate::reply_stage::ReplyStage`]); a reply that does
/// not fit what is left is refused and counted.
pub const REPLY_STAGE_BYTES: usize =
    MAX_PENDING_REPLIES * (MAX_REPLY_PAYLOAD_BYTES + MAX_KEYEXPR_BYTES);

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
pub const MAX_ADMIN_REPLY_BYTES: usize = generated::MAX_ADMIN_REPLY_BYTES;

const _: () = assert!(
    MAX_ADMIN_REPLY_BYTES <= MAX_REPLY_PAYLOAD_BYTES,
    "an admin reply is staged as a reply, so its bound cannot exceed the reply payload bound"
);

/// Maximum number of listening locators a node with no allocator reports in its
/// admin `local_data` (the deploy `session_pool.process.admin_locators` key). The
/// node's identity holds that many locator rows of [`MAX_LOCATOR_LEN`] bytes; one
/// more is refused when the identity is built, never dropped.
pub const MAX_ADMIN_LOCATORS: usize = generated::MAX_ADMIN_LOCATORS;

/// Maximum number of links one admin `sessions[]` row lists (the deploy
/// `session_pool.process.admin_session_links` key). A unicast transport has one;
/// the number covers a session that holds a second. A row with more links than this
/// is refused and counted, not listed in part.
pub const MAX_ADMIN_SESSION_LINKS: usize = generated::MAX_ADMIN_SESSION_LINKS;

/// Maximum number of replies a multicast pump of a node with no allocator holds
/// between the observer that stages one and the loop that frames and sends it (the
/// deploy `session_pool.process.multicast_replies` key). A reply past it is dropped and
/// counted by the queue (`wz_session_lwip::multicast_drive::MulticastReplyQueue`),
/// never queued without bound: multicast to a group is best effort, and a querier
/// whose reply was dropped asks again.
pub const MAX_MULTICAST_REPLIES: usize = generated::MAX_MULTICAST_REPLIES;

/// The most tasks a fixed-memory machine's runtime may hold (the deploy
/// `session_pool.process.max_tasks` key): a CEILING on the task table an image
/// declares for itself (`RuntimeCell`'s `TASKS`), not the size of that table. An
/// image's table is the pump per session it holds and room beside them, so it is
/// smaller than this; the images assert `TASKS <= MAX_TASKS` at compile time, and
/// a host test holds this number equal to the deploy file's, so a deploy file that
/// raises the ceiling and an image that outgrows it are each a red build.
pub const MAX_TASKS: usize = generated::MAX_TASKS;

/// The most timers a fixed-memory machine's runtime may hold (the deploy
/// `session_pool.process.max_timers` key): the ceiling on an image's `RuntimeCell`
/// `TIMERS`, held the same way as [`MAX_TASKS`].
pub const MAX_TIMERS: usize = generated::MAX_TIMERS;

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
pub const MAX_LOCATOR_LEN: usize = generated::MAX_LOCATOR_LEN;

/// Maximum number of static-scouting peer locators
/// ([`crate::scout_static::synth_static_locators`] output capacity =
/// `deploy.connect[]` length). Bounds the no-alloc synthesis on the MCU
/// backing; a `connect[]` longer than this stops at the cap (a future
/// `deploy.yaml` -> caps codegen step enforces the bound at build time, the
/// same hard-error model as docs/scouting-fsm.md §2.6 hello_max_peers).
/// Mirrors the MCU `hello_max_peers` discovery capacity (deploy
/// `mcu_target.yaml:263 = 8`): a static deploy is a small fixed peer set
/// (e.g. one AP for a fixed AP<->MCU pair), so few configured locators.
pub const MAX_STATIC_CONNECT: usize = generated::MAX_STATIC_CONNECT;

/// Maximum number of nodes a fixed-memory image holds a session with BY THEIR ZID, beside the
/// [`MAX_STATIC_CONNECT`] locators it is told to connect to: the peers a lifecycle `open` names
/// (decision D6 of `docs/session-lifecycle-intent.md`), whose locators the node holds as hints
/// in a directory (decision D3). It sizes the rows of the connect manager's peer tables past
/// the endpoints, and of the directory (two hints for each node). Each node is a connection
/// machine of about 930 bytes, so the default is 0: an image that is never asked to open a peer
/// by its zid declares none of it, and refuses the open.
pub const MAX_PEER_NODES: usize = generated::MAX_PEER_NODES;

/// Maximum number of queries ONE declared querier has in flight at once, as a
/// [`crate::quota::Quota`] states it: a query past it is refused, and a place comes back
/// when the pending query ends (its final arrives, its deadline passes, or it is
/// unregistered). The bound is per querier and not per session, so one busy querier
/// cannot starve another. **`0` is no bound**, which is upstream's behaviour and the
/// default; this is the one limit here that is a quota and not a table capacity, so `0`
/// is not a table of no rows. It sizes no memory: a pending query is a row of the reply
/// registry whatever this says.
pub const QUERIER_MAX_PENDING_QUERIES: usize = generated::QUERIER_MAX_PENDING_QUERIES;

/// How long, in microseconds, a blocking message may wait with no fragment of it going out,
/// when the `tx-no-progress-deadline` policy is on. It is read only then
/// ([`crate::session_init_params::TxQueueConf`]), and must be at least `1` and at most the
/// total wait, `wait_before_close`, which bounds the message as before. A time and not a
/// table size: it sizes no memory.
pub const TX_NO_PROGRESS_WINDOW_US: usize = generated::TX_NO_PROGRESS_WINDOW_US;

/// How many declarations one turn of a paced declaration replay sends, when the
/// `declaration-sync-pacing` policy is on (`docs/declaration-sync-pacing.md`). It is read only
/// then, by the reconnect supervisor of the heap runtime, and must be at least `1`: a turn that
/// sends nothing never finishes. A count of messages and not a table size: it sizes no memory.
pub const DECLARATION_SYNC_BURST_MESSAGES: usize = generated::DECLARATION_SYNC_BURST_MESSAGES;

/// How long, in milliseconds, a node waits for the peer's answer to an interest it sent before it
/// counts the interest as unanswered and goes on ([`crate::declaration_sync::DeclarationSync`]).
/// It bounds `declarations_synced` and `wait_declarations_stable`, and is read whether or not the
/// `declaration-sync-pacing` policy is on. Must be at least `1`. A time and not a table size: it
/// sizes no memory.
pub const DECLARATION_SYNC_FINAL_TIMEOUT_MS: usize = generated::DECLARATION_SYNC_FINAL_TIMEOUT_MS;

/// How long, in milliseconds, a paced declaration replay waits between two turns, when the
/// `declaration-sync-pacing` policy is on. It is read only then, and must be at least `1`. A time
/// and not a table size: it sizes no memory.
pub const DECLARATION_SYNC_INTERVAL_MS: usize = generated::DECLARATION_SYNC_INTERVAL_MS;

// The numbers of zenoh-pico's value build switches, as the pico C ABI states them. Each defaults
// to pico's own default (`upstream_switch_map.py` holds that, the `maps` rows of
// `deploy/wz-config.toml` that anchor to these), so the drop-in's default build states what
// pico's does, and a pico built with other numbers is matched by stating them
// (`wz_config.py --env pico <config.h>`). None sizes memory; the two batch sizes bound frames, and the fragment ceiling the
// messages rejoined from them.

/// The batch size a unicast session of the pico ABI advertises, pico's `BATCH_UNICAST_SIZE`
/// (`vendor/zenoh-pico/src/protocol/definitions/transport.c` @
/// `msg._body._init._batch_size = Z_BATCH_UNICAST_SIZE;`). At most `u16::MAX`.
pub const PICO_UNICAST_BATCH_BYTES: usize = generated::PICO_UNICAST_BATCH_BYTES;

/// The batch size a group session of the pico ABI advertises in its Join, pico's
/// `BATCH_MULTICAST_SIZE`, which pico requires every member to state alike
/// (`vendor/zenoh-pico/src/transport/multicast/rx.c` @ `(msg->_batch_size != Z_BATCH_MULTICAST_SIZE)`).
/// At most `u16::MAX`.
pub const PICO_MULTICAST_BATCH_BYTES: usize = generated::PICO_MULTICAST_BATCH_BYTES;

/// The lease, in milliseconds, a session of the pico ABI advertises, unicast and in a Join: pico's
/// `Z_TRANSPORT_LEASE`.
pub const PICO_LEASE_MS: usize = generated::PICO_LEASE_MS;

/// How long, in milliseconds, one read step of the pico ABI's cooperative engine waits on its
/// link: pico's `Z_CONFIG_SOCKET_TIMEOUT`, its socket's receive timeout.
pub const PICO_SOCKET_TIMEOUT_MS: usize = generated::PICO_SOCKET_TIMEOUT_MS;

/// How long, in milliseconds, the pico ABI's cooperative engine gives an endpoint to complete the
/// handshake: pico's `Z_TRANSPORT_CONNECT_TIMEOUT`, its handshake's receive deadline
/// (`vendor/zenoh-pico/src/transport/unicast/transport.c` @
/// `z_clock_advance_ms(&recv_deadline, Z_TRANSPORT_CONNECT_TIMEOUT);`).
pub const PICO_CONNECT_TIMEOUT_MS: usize = generated::PICO_CONNECT_TIMEOUT_MS;

/// The largest message, in bytes, a session of the pico ABI rejoins from fragments, unicast and in
/// a group: pico's `FRAG_MAX_SIZE`, whose rule is upstream's `transport/link/rx/max_message_size`
/// (`vendor/zenoh-pico/src/transport/unicast/rx.c` @
/// `if ((_z_wbuf_len(dbuf) + msg->_payload.len) > Z_FRAG_MAX_SIZE) {`), so it is the
/// [`LinkRxConf`](crate::session_init_params::LinkRxConf) those sessions are given.
pub const PICO_FRAG_MAX_BYTES: usize = generated::PICO_FRAG_MAX_BYTES;
