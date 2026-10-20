// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The policy a session's gossip is configured with, under the `gossip` feature, and the
//! type that stands in for it without.
//!
//! A drive stance names a policy (`OpenStance::gossip`) and the registry's setup carries one,
//! so the name has to exist in every build for those two shapes to keep their form. Without the
//! feature no policy can be made: the stand-in has no value, a stance's `gossip` is `None`,
//! and the code that reads it is the code of an `Option` that is never `Some`.

#[cfg(feature = "gossip")]
pub use wz_runtime_tokio::gossip_plane::GossipPolicy;

/// Without the `gossip` feature a node cannot gossip, so there is no policy to hold.
#[cfg(not(feature = "gossip"))]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GossipPolicy {}
