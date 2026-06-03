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
/// rejected (`SubscribeError::TableFull`) rather than growing the table.
pub const MAX_SUBSCRIPTIONS: usize = 16;

/// Maximum number of concurrently-registered local queryables in a
/// [`crate::query::QueryableRegistry`]. Bounds the registry's queryable
/// table on the no-alloc backing; a `register` past this is rejected
/// (`QueryableRegisterError::TableFull`) rather than growing the table.
pub const MAX_QUERYABLES: usize = 16;
