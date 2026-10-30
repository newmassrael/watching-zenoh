//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-keyexpr 1.10.2, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! Key expressions of the zenoh family (`zenoh-keyexpr` 1.10.2), over watching-zenoh.
//!
//! This crate is upstream's by name, version, library name and public surface (inventory atom
//! `api-compat-rust`). A key expression is a `/`-separated list of non-empty chunks, some of which
//! are wildcards, and it denotes the set of keys that match it: [`keyexpr`] is the borrowed form,
//! [`OwnedKeyExpr`] the shared owned one, and [`keyexpr::intersects`] and [`keyexpr::includes`] are
//! the two relations between the sets.
//!
//! The language is written from its definition here and not transcribed: a validator that reports
//! the same fault upstream's does for every string, a canonizer, and the two relations as dynamic
//! programs over chunks. `conformance/differential` holds each to upstream's over every string of a
//! small alphabet up to a length, which is the evidence that the two agree.
//!
//! The crate holds the key expression types, their canonization and the relations, and the
//! generator of random key expressions; the key expression formats; and the key expression trees
//! ([`keyexpr_tree`]), with an owning root, [`keyexpr_tree::KeBoxTree`], and with shared nodes
//! reached through a token, [`keyexpr_tree::KeArcTree`].

// A test build links `std` whatever the features say: the unit tests are written against the std
// prelude (`vec!`, `format!`, `ToString`), and the combination without `std` is still held to
// `no_std` for the code it ships by the lib-only build of `--no-default-features`.
#![cfg_attr(not(any(feature = "std", test)), no_std)]
extern crate alloc;

pub mod key_expr;

pub use key_expr::*;
pub mod keyexpr_tree;
