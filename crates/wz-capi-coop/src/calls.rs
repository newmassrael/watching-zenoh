// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The calls the engine's rows are made through and the kinds of record a round of them keeps, as
//! the engine's build names them (`CoopCalls`): the one type the session core's round
//! ([`crate::round`]), its queryables' plane and its gets' plane are each of. A build that keeps
//! no round still names them where one of those planes is held.

use wz_session_core::plane_lock::LockFamily;
use wz_session_core::round::{PlaneCalls, RoundCall, RoundCalls, SampleCall};
use wz_session_core::sink::SampleRef;

#[cfg(feature = "query")]
use crate::engine::LegId;
#[cfg(feature = "liveliness")]
use crate::engine::LivelinessCall;
#[cfg(feature = "queryable")]
use crate::engine::QueryableCall;
use crate::engine::SubscriberCall;
#[cfg(all(
    any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ),
    wz_round
))]
use crate::engine::WatchCall;
use crate::form::CoopForm;
#[cfg(feature = "query")]
use wz_capi_port::ReplyCallback;
#[cfg(feature = "liveliness")]
use wz_session_core::declare::liveliness_sample::LivelinessSample;

/// The calls the engine's round owes and the kinds of record it keeps: each kind of row the
/// engine's build keeps none of has the call [`Infallible`](core::convert::Infallible) and a
/// record kind of no size.
pub(crate) enum CoopCalls {}

impl RoundCalls for CoopCalls {
    type Subscriber = SubscriberCall;
    #[cfg(feature = "liveliness")]
    type Liveliness = LivelinessCall;
    #[cfg(not(feature = "liveliness"))]
    type Liveliness = core::convert::Infallible;
    #[cfg(feature = "queryable")]
    type Queryable = QueryableCall;
    #[cfg(not(feature = "queryable"))]
    type Queryable = core::convert::Infallible;
    #[cfg(all(
        any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ),
        wz_round
    ))]
    type Watch = WatchCall;
    #[cfg(not(all(
        any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ),
        wz_round
    )))]
    type Watch = core::convert::Infallible;
    #[cfg(feature = "query")]
    type Leg = LegId;
    #[cfg(not(feature = "query"))]
    type Leg = core::convert::Infallible;
    #[cfg(feature = "query")]
    type ReplyCallback = ReplyCallback;
    #[cfg(not(feature = "query"))]
    type ReplyCallback = core::convert::Infallible;
    #[cfg(feature = "liveliness")]
    type Tokens = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "liveliness"))]
    type Tokens = wz_session_core::session_tables::Absent;
    #[cfg(feature = "query")]
    type Replies = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "query"))]
    type Replies = wz_session_core::session_tables::Absent;
    #[cfg(feature = "queryable")]
    type Queries = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "queryable"))]
    type Queries = wz_session_core::session_tables::Absent;
    #[cfg(all(
        any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ),
        wz_round
    ))]
    type Watches = wz_session_core::session_tables::Present;
    #[cfg(not(all(
        any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ),
        wz_round
    )))]
    type Watches = wz_session_core::session_tables::Absent;
    #[cfg(feature = "local-subscriber")]
    type Capture = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "local-subscriber"))]
    type Capture = wz_session_core::session_tables::Absent;
    #[cfg(feature = "group")]
    type Group = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "group"))]
    type Group = wz_session_core::session_tables::Absent;
    type Locks = CoopSyncLocks;
    #[cfg(all(test, feature = "std", wz_round))]
    type Tally = crate::round::Handed;
    #[cfg(not(all(test, feature = "std", wz_round)))]
    type Tally = ();
    type Form = CoopForm;
}

impl PlaneCalls for CoopCalls {
    #[cfg(feature = "local-queryable")]
    type LocalAnswers = wz_session_core::session_tables::Present;
    #[cfg(not(feature = "local-queryable"))]
    type LocalAnswers = wz_session_core::session_tables::Absent;
    // The read that hands each record out as it is read hands a peer's reply to its get itself
    // (`engine::replies`).
    #[cfg(any(feature = "local-queryable", not(wz_round)))]
    type Captures = wz_session_core::session_tables::Present;
    #[cfg(not(any(feature = "local-queryable", not(wz_round))))]
    type Captures = wz_session_core::session_tables::Absent;
    type Queues = crate::engine::CoopLocks;
}

/// The port's lock, as the lock the round keeps what answers its queries under.
pub(crate) enum CoopSyncLocks {}

impl LockFamily for CoopSyncLocks {
    type Lock<T> = wz_capi_port::sync::Lock<T>;

    unsafe fn init_at<T>(
        place: core::ptr::NonNull<Self::Lock<T>>,
        make: impl FnOnce(&mut core::mem::MaybeUninit<T>) -> &mut T,
    ) {
        // SAFETY: the caller's contract is the lock's.
        unsafe { wz_capi_port::sync::Lock::init_at(place, make) }
    }

    fn with<T, R>(lock: &Self::Lock<T>, f: impl FnOnce(&mut T) -> R) -> R {
        lock.with(f)
    }
}

impl RoundCall for SubscriberCall {
    fn end(self) -> bool {
        SubscriberCall::end(self)
    }
}

impl SampleCall for SubscriberCall {
    fn hand(&self, sample: &SampleRef<'_>) {
        SubscriberCall::hand(self, sample);
    }
}

#[cfg(feature = "liveliness")]
impl RoundCall for LivelinessCall {
    fn end(self) -> bool {
        LivelinessCall::end(self)
    }
}

#[cfg(feature = "liveliness")]
impl wz_session_core::round::TokenCall for LivelinessCall {
    fn same_row(&self, other: &Self) -> bool {
        LivelinessCall::same_row(self, other)
    }

    fn hand(&self, sample: LivelinessSample<'_>) {
        LivelinessCall::hand(self, sample);
    }
}

#[cfg(feature = "queryable")]
impl RoundCall for QueryableCall {
    fn end(self) -> bool {
        QueryableCall::end(self)
    }
}

#[cfg(all(
    any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ),
    wz_round
))]
impl RoundCall for WatchCall {
    fn end(self) -> bool {
        WatchCall::end(self)
    }
}

#[cfg(all(
    any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ),
    wz_round
))]
impl wz_session_core::round::WatchCall for WatchCall {
    fn same_row(&self, other: &Self) -> bool {
        WatchCall::same_row(self, other)
    }

    fn hand(&self, event: wz_session_core::round::DeclEvent<'_>) {
        WatchCall::hand(self, event);
    }
}
