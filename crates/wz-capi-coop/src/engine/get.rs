// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The requesting end of a query on the cooperative engine.
//!
//! A get is asked of the one peer the session's link reaches, so it has one leg and owes one
//! Final; the session asks no queryable of its own, as zenoh-pico's default build asks none
//! (`Z_FEATURE_LOCAL_QUERYABLE` 0). Its pending entry is session-core's, registered with the
//! observer under the request id the link's actions allocate, with the deadline, the accepted
//! reply keys and the consolidation `QueryOptions` reads, as the tokio engine registers its own.
//!
//! What the entry's sink and hold do with what they are handed, and how a leg's end and its
//! callback reach the deliveries, is the session core's get plane
//! ([`wz_session_core::get_plane`]); this module names it in the engine's types: the port's reply
//! callback, its locks, and whether the session's own queryables answer its gets
//! (`local-queryable`).

use wz_capi_port::cancellation::FanKey;
use wz_capi_port::sync::SessionHeld;
use wz_capi_port::ReplyCallback;
use wz_session_core::get_plane::GetCalls;
use wz_session_core::reply_sink::ReplyView;

use crate::round::CoopCalls;

use super::CoopLocks;

pub(super) use wz_session_core::get_plane::EndedLegs;
pub(crate) use wz_session_core::get_plane::{Ended, LegId};

/// A leg's callback in its row of the plane's.
pub(crate) type LegRow = wz_session_core::get_plane::LegRow<CoopCalls>;
/// The rows of the legs' callbacks, lent by the session's arena.
pub(super) type LegRows = wz_session_core::get_plane::LegRows<CoopCalls>;
/// What the get plane shares between the session's state, the observer's reply sinks and the
/// deliveries.
pub(super) type GetPlane = wz_session_core::get_plane::GetPlane<CoopCalls>;
/// The sink of a leg's pending entry.
pub(crate) type LegSink = wz_session_core::get_plane::LegSink<CoopCalls>;
/// What a consolidating get holds of its replies until its Final.
pub(crate) type LegHold = wz_session_core::get_plane::LegHold<CoopCalls>;

/// A leg the session has pending, with the key of the fan that cancels it when a token can: a row
/// of a table the session's arena lent, one for each get its tables of pending gets hold.
pub(crate) type PendingGet = wz_session_core::pending_get::PendingGet<FanKey>;
pub(super) use wz_session_core::pending_get::GetKind;

impl GetCalls for CoopCalls {
    #[cfg(feature = "local-queryable")]
    type LocalAnswers = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "local-queryable"))]
    type LocalAnswers = wz_session_core::session_tables::Absent;
    type Queues = CoopLocks;

    fn call(callback: &ReplyCallback, reply: &dyn ReplyView) {
        callback.call(reply);
    }

    fn holds_a_session() -> bool {
        SessionHeld::any_here()
    }
}
