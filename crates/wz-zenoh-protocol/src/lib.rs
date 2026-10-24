// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)
//!
//! The messages of the zenoh protocol (`zenoh-protocol` 1.10.1), over watching-zenoh. The crate is
//! upstream's by name, version, library name and public surface (inventory atom `api-compat-rust`).
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod core;
pub mod network;
pub mod scouting;
pub mod transport;

// Zenoh version
pub const VERSION: u8 = 0x09;
