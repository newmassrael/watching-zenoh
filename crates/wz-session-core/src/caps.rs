// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! Per [`crate::bounded`], `N` is the hard limit only on the no-alloc
//! (MCU) backing; on the `alloc` (AP) backing it is advisory and
//! `push` never fails. So these values bound the MCU footprint and
//! serve as documentation on AP.
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
/// plus one `DeclFinal`; the buffer accumulates across the Interests in a
/// single poll batch, so the bound is sized generously. R311hn (Track 2)
/// — replaces the prior unbounded `Vec<DeclareOwned>` staging.
pub const MAX_PENDING_DECLARES: usize = 32;
