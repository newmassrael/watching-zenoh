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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-shm 1.10.1, file
// src/lib.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](https://docs.rs/zenoh/latest/zenoh)

#[macro_export]
macro_rules! tested_module {
    ($module:ident) => {
        #[cfg(feature = "test")]
        pub mod $module;
        #[cfg(not(feature = "test"))]
        mod $module;
    };
}

#[macro_export]
macro_rules! tested_crate_module {
    ($module:ident) => {
        #[cfg(feature = "test")]
        pub mod $module;
        #[cfg(not(feature = "test"))]
        pub(crate) mod $module;
    };
}

// The crate lands in slices, and what the later ones call is not yet called: the buffers and the
// provider, which use the confirmator, the validator and the metadata storage, come after. Until
// the provider lands (debt-910) the modules that only they reach are allowed to be unused, and
// the allowance is removed with that slice.
#[allow(dead_code)]
pub mod api;
mod cleanup;
#[allow(dead_code)]
pub mod header;
pub mod init;
#[allow(dead_code)]
pub mod metadata;
pub mod posix_shm;
pub mod shm;
pub mod version;
#[allow(dead_code)]
pub mod watchdog;
