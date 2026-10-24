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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-protocol 1.10.1, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)
//!
//! The messages of the zenoh protocol (`zenoh-protocol` 1.10.1), over watching-zenoh. The crate is
//! upstream's by name, version, library name and public surface (inventory atom `api-compat-rust`).
// A test build links `std` whatever the features say: the unit tests are written against the std
// prelude (`vec!`, `format!`, `ToString`), and the combination without `std` is still held to
// `no_std` for the code it ships by the lib-only build of `--no-default-features`.
#![cfg_attr(not(any(feature = "std", test)), no_std)]
extern crate alloc;

pub mod common;
pub mod core;
pub mod network;
pub mod scouting;
pub mod transport;
pub mod zenoh;

// Zenoh version
pub const VERSION: u8 = 0x09;
