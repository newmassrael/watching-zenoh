// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

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
