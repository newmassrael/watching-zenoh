// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The messages of the network layer: what is declared, pushed, requested and answered between
//! sessions. This file holds, so far, the one type the key expression references of `core` need
//! (`Mapping`); the messages arrive in the slice of the crate that is the network layer.

pub mod request;
pub use request::RequestId;

/// Whose table of key expression ids a scope refers to: the sender's or the receiver's.
#[repr(u8)]
#[derive(Debug, Default, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Mapping {
    #[default]
    Receiver = 0,
    Sender = 1,
}

impl Mapping {
    pub const DEFAULT: Self = Self::Receiver;

    #[cfg(feature = "test")]
    #[doc(hidden)]
    pub fn rand() -> Self {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        if rng.gen_bool(0.5) {
            Mapping::Sender
        } else {
            Mapping::Receiver
        }
    }
}
