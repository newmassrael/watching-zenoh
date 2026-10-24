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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-collections 1.10.1, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)
//!
//! The small containers of the zenoh family (`zenoh-collections` 1.10.1), over watching-zenoh. The
//! crate is upstream's by name, version, library name and public surface (inventory atom
//! `api-compat-rust`); the containers are written here from what each is for, with no `unsafe`, and
//! `conformance/differential` holds each to upstream's over generated sequences of operations.
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod single_or_vec;
pub use single_or_vec::SingleOrVec;

#[cfg(feature = "std")]
pub mod single_or_box_hashset;
#[cfg(feature = "std")]
pub use single_or_box_hashset::SingleOrBoxHashSet;

#[cfg(feature = "std")]
pub mod ring_buffer;
#[cfg(feature = "std")]
pub use ring_buffer::*;

#[cfg(feature = "std")]
pub mod stack_buffer;
#[cfg(feature = "std")]
pub use stack_buffer::*;

#[cfg(feature = "std")]
pub mod int_hash_map;
#[cfg(feature = "std")]
pub use int_hash_map::*;
