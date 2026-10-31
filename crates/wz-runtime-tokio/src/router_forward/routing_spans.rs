// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The spans of upstream's routing code, opened where wz does the same step.
//!
//! Upstream's `zenoh` opens `demux{zid, src}` round the handling of each message a face sends
//! (`zenoh/src/net/primitives/demux.rs` @ `tracing::debug_span!(`, `zid` being the node's own),
//! and `register_subscriber{self, res}` / `register_queryable{self, res}` round the registration
//! of a declaration in the hat of the face's region, each with the one event that
//! `#[tracing::instrument(.., ret)]` makes when the function returns
//! (`zenoh/src/net/routing/hat/broker/pubsub.rs` @ `fn register_subscriber(`). Its own test of its
//! regions counts those events by the node's zid and the hat's region name
//! (`zenoh/tests/regions/main.rs` @ `pub mod predicates_ext`): how many times a node's north hat
//! registered a subscriber or a queryable for a key. That is a count of upstream's steps and not an
//! observable of the API, and it is met only by a routing that takes the same steps and says so
//! the same way.
//!
//! Without the `tracing-spans` feature every function here is empty, and a build pays nothing.
//! With it, a span is opened only where `tracing` has a subscriber that wants the level, as upstream
//! opens `demux` (`tracing::enabled!(tracing::Level::DEBUG).then(..)`).

use wz_session_core::extbound::Region;

use crate::accept_loop::FaceId;
use crate::linkstate_forward::Zid;

/// A span that is open until this drops: nothing without the feature, or where `tracing` wants
/// no span of that level.
pub(super) struct Held {
    #[cfg(feature = "tracing-spans")]
    span: Option<tracing::span::EnteredSpan>,
}

impl Held {
    /// The registration returned `registered`: the one event upstream's `ret` makes inside the
    /// span. A second event inside it would be counted as a second registration.
    #[cfg(feature = "tracing-spans")]
    pub(super) fn returned(&self, registered: bool) {
        if self.span.is_some() {
            tracing::debug!(r#return = registered);
        }
    }

    #[cfg(not(feature = "tracing-spans"))]
    #[inline(always)]
    pub(super) fn returned(&self, _registered: bool) {}
}

/// The handling of one message of face `src` by the node `zid`.
#[cfg(feature = "tracing-spans")]
pub(super) fn demux(zid: Zid, src: FaceId) -> Held {
    Held {
        span: tracing::enabled!(tracing::Level::DEBUG)
            .then(|| tracing::debug_span!("demux", zid = %zid, src = src.0).entered()),
    }
}

#[cfg(not(feature = "tracing-spans"))]
#[inline(always)]
pub(super) fn demux(_zid: Zid, _src: FaceId) -> Held {
    Held {}
}

/// The registration of a subscriber of `keyexpr` in the hat of `region`.
#[cfg(feature = "tracing-spans")]
pub(super) fn register_subscriber(region: &Region, keyexpr: &str) -> Held {
    Held {
        span: tracing::enabled!(tracing::Level::DEBUG).then(|| {
            tracing::debug_span!("register_subscriber", self = %region, res = %keyexpr).entered()
        }),
    }
}

#[cfg(not(feature = "tracing-spans"))]
#[inline(always)]
pub(super) fn register_subscriber(_region: &Region, _keyexpr: &str) -> Held {
    Held {}
}

/// The registration of a queryable of `keyexpr` in the hat of `region`.
#[cfg(feature = "tracing-spans")]
pub(super) fn register_queryable(region: &Region, keyexpr: &str) -> Held {
    Held {
        span: tracing::enabled!(tracing::Level::DEBUG).then(|| {
            tracing::debug_span!("register_queryable", self = %region, res = %keyexpr).entered()
        }),
    }
}

#[cfg(not(feature = "tracing-spans"))]
#[inline(always)]
pub(super) fn register_queryable(_region: &Region, _keyexpr: &str) -> Held {
    Held {}
}
