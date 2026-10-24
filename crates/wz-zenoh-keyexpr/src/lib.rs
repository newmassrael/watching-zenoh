// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Key expressions of the zenoh family (`zenoh-keyexpr` 1.10.1), over watching-zenoh.
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
//! The crate is built in slices: the key expression types, their canonization and the relations,
//! and the generator of random key expressions; the key expression formats; and the key expression
//! trees ([`keyexpr_tree`]), of which the shared-ownership one, `KeArcTree`, arrives in the slice
//! after this.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod key_expr;

pub use key_expr::*;
pub mod keyexpr_tree;
