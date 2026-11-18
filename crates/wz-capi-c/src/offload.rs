// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A subscriber whose callback runs off the receive path, as C doors (`rx-callback-offload`,
//! `docs/rx-delivery-lane.md`).
//!
//! ## What the door does
//!
//! [`wz_capi_c_declare_subscriber_offloaded`] is `z_declare_subscriber` with one more argument,
//! the answer a full lane gives. Every place a sample of the subscription arrives (each face, the
//! session's own puts, a joined group) copies it into ONE lane of `DELIVERY_LANE_EVENTS` samples
//! and `DELIVERY_LANE_BYTES` bytes and returns; the C callback runs on a task of the application
//! runtime, one sample after another in the order they were admitted, with no lock of the session
//! held. A slow callback then holds up its own lane and nothing else: not the drive thread of a
//! face, and not the thread that made a put.
//!
//! ## The answers it takes, and the one it refuses
//!
//! `reject` refuses a sample the lane has no room for and counts it; `keep-latest` takes out the
//! newest samples queued behind the one being delivered until the new one fits. Neither ever holds
//! the receive path. `block` is refused with `Z_EUNAVAILABLE`: it makes the receive path wait for
//! room in a drain step that a session's drive loop awaits, and this ABI's subscription is fed by
//! several sessions and by puts on the caller's thread, so there is no one loop whose wait it
//! would be. A declaration that states nothing (NULL, or the `_default` statement) takes `reject`,
//! the answer every build of this door can give. `WZ_CAPI_C_OVERLOAD_BUILD` asks for the build's
//! `subscriber-overload` policy by name, and is refused in a build whose policy is `block`.
//!
//! What the lane holds, refused and took out is read with
//! [`wz_capi_c_subscriber_offload_stats`]. Undeclaring the subscriber stops the lane: a sample
//! waiting at that moment is not delivered, as a sample after an undeclare is not.

use crate::abi::{
    z_loaned_keyexpr_t, z_loaned_session_t, z_loaned_subscriber_t, z_moved_closure_sample_t,
    z_owned_subscriber_t,
};
use crate::ffi::guarded;
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::sub::{declare_subscriber_delivered, offload_of, z_subscriber_options_t, Delivery};
use wz_session_core::link_restriction::LinkRestriction;
use wz_session_core::policy::SubscriberOverload;

/// The build's `subscriber-overload` policy, asked for by name: refused where that is `block`.
pub const WZ_CAPI_C_OVERLOAD_BUILD: u8 = 0;
/// `block`: refused by this door (see the module note).
pub const WZ_CAPI_C_OVERLOAD_BLOCK: u8 = 1;
/// `reject`: a sample the lane has no room for is refused and counted. What a declaration that
/// states nothing takes.
pub const WZ_CAPI_C_OVERLOAD_REJECT: u8 = 2;
/// `keep-latest`: the newest samples queued behind the head are taken out until it fits.
pub const WZ_CAPI_C_OVERLOAD_KEEP_LATEST: u8 = 3;

/// What an offloaded subscriber declaration states beside the zenoh-c options.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct wz_capi_c_offload_options_t {
    /// One of the `WZ_CAPI_C_OVERLOAD_*` values.
    pub overload: u8,
}

/// A snapshot of an offloaded subscriber's lane.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct wz_capi_c_offload_stats_t {
    /// Samples in the lane, the one being delivered included.
    pub queued_events: u64,
    /// The `DELIVERY_LANE_EVENTS` limit.
    pub event_capacity: u64,
    /// Bytes charged for the samples in the lane.
    pub pending_bytes: u64,
    /// The `DELIVERY_LANE_BYTES` limit.
    pub byte_capacity: u64,
    /// Samples refused because every event slot was taken.
    pub refused_events_full: u64,
    /// Samples refused because their bytes did not fit.
    pub refused_bytes_full: u64,
    /// Samples refused because the lane was stopping.
    pub refused_stopping: u64,
    /// Samples admitted and taken out again for a newer one (`keep-latest`).
    pub evicted: u64,
    /// Samples sent reliably that were lost to the lane, refused or taken out.
    pub dropped_reliable: u64,
    /// Samples sent best-effort that were lost to the lane, refused or taken out.
    pub dropped_best_effort: u64,
    /// The answer the lane gives when it is full, as a `WZ_CAPI_C_OVERLOAD_*` value.
    pub overload: u8,
}

/// The answer a C value states, or `None` for a value that names none.
fn overload_of(value: u8) -> Option<SubscriberOverload> {
    match value {
        WZ_CAPI_C_OVERLOAD_BUILD => Some(SubscriberOverload::default()),
        WZ_CAPI_C_OVERLOAD_BLOCK => Some(SubscriberOverload::Block),
        WZ_CAPI_C_OVERLOAD_REJECT => Some(SubscriberOverload::Reject),
        WZ_CAPI_C_OVERLOAD_KEEP_LATEST => Some(SubscriberOverload::KeepLatest),
        _ => None,
    }
}

/// The C value of an answer.
fn overload_value(overload: SubscriberOverload) -> u8 {
    match overload {
        SubscriberOverload::Block => WZ_CAPI_C_OVERLOAD_BLOCK,
        SubscriberOverload::Reject => WZ_CAPI_C_OVERLOAD_REJECT,
        SubscriberOverload::KeepLatest => WZ_CAPI_C_OVERLOAD_KEEP_LATEST,
    }
}

fn wide(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The statement of nothing, which NULL stands for too: `reject`, an answer this lane gives in
/// every build, where the build's own policy may be `block`, which it cannot.
const STATED_NOTHING: wz_capi_c_offload_options_t = wz_capi_c_offload_options_t {
    overload: WZ_CAPI_C_OVERLOAD_REJECT,
};

/// Write the statement of nothing: `reject`. NULL is no write.
///
/// # Safety
/// `this_` must be null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_offload_options_default(
    this_: *mut wz_capi_c_offload_options_t,
) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *this_ = STATED_NOTHING };
}

/// `z_declare_subscriber` whose callback runs off the receive path, behind a lane of its own, with
/// the answer `offload` states to a full lane (NULL for the default statement, `reject`). A value
/// that names no answer is `Z_EINVAL`; `block`, stated or asked of a build whose policy it is
/// (`WZ_CAPI_C_OVERLOAD_BUILD`), is `Z_EUNAVAILABLE`. A refused declaration leaves `subscriber` in
/// its gravestone state and has consumed `callback`, as `z_declare_subscriber` does on every path.
///
/// # Safety
/// As `z_declare_subscriber`; `offload` must be null or a valid statement.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_declare_subscriber_offloaded(
    session: *const z_loaned_session_t,
    subscriber: *mut z_owned_subscriber_t,
    key_expr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_sample_t,
    options: *mut z_subscriber_options_t,
    offload: *const wz_capi_c_offload_options_t,
) -> ZResult {
    // SAFETY: the caller's contract for `offload`.
    let stated = unsafe { offload.as_ref() }
        .copied()
        .unwrap_or(STATED_NOTHING)
        .overload;
    let (links, delivery) = match overload_of(stated) {
        Some(overload) => (Ok(LinkRestriction::Any), Delivery::Offloaded(overload)),
        // Refused through the declaration's own refusal path, which consumes the closure.
        None => (Err(Z_EINVAL), Delivery::Inline),
    };
    // SAFETY: the caller's contract, delegated.
    unsafe {
        declare_subscriber_delivered(
            session, subscriber, key_expr, callback, options, links, delivery,
        )
    }
}

/// Write a snapshot of the lane of `subscriber` into `out`. `Z_ENULL` for a null argument or a
/// subscriber that is gone, `Z_EINVAL` for one that was not declared offloaded; `out` is left as
/// it was on either.
///
/// # Safety
/// `subscriber` must be null or a valid loaned subscriber; `out` null or valid and writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_subscriber_offload_stats(
    subscriber: *const z_loaned_subscriber_t,
    out: *mut wz_capi_c_offload_stats_t,
) -> ZResult {
    guarded(|| {
        if subscriber.is_null() || out.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        if unsafe { (*subscriber).handle }.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let Some(lane) = (unsafe { offload_of(subscriber) }) else {
            return Z_EINVAL;
        };
        let stats = lane.stats();
        // SAFETY: the caller's contract.
        unsafe {
            *out = wz_capi_c_offload_stats_t {
                queued_events: wide(stats.lane.queued_events),
                event_capacity: wide(stats.lane.event_capacity),
                pending_bytes: wide(stats.lane.pending_bytes),
                byte_capacity: wide(stats.lane.byte_capacity),
                refused_events_full: wide(stats.lane.refused.events_full),
                refused_bytes_full: wide(stats.lane.refused.bytes_full),
                refused_stopping: wide(stats.lane.refused.stopping),
                evicted: wide(stats.lane.evicted),
                dropped_reliable: wide(stats.dropped_reliable),
                dropped_best_effort: wide(stats.dropped_best_effort),
                overload: overload_value(lane.overload()),
            }
        };
        Z_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every C value maps to the answer it names, and back; a value past the last names none.
    #[test]
    fn each_overload_value_names_its_answer() {
        assert_eq!(
            overload_of(WZ_CAPI_C_OVERLOAD_BUILD),
            Some(SubscriberOverload::default())
        );
        for (value, answer) in [
            (WZ_CAPI_C_OVERLOAD_BLOCK, SubscriberOverload::Block),
            (WZ_CAPI_C_OVERLOAD_REJECT, SubscriberOverload::Reject),
            (
                WZ_CAPI_C_OVERLOAD_KEEP_LATEST,
                SubscriberOverload::KeepLatest,
            ),
        ] {
            assert_eq!(overload_of(value), Some(answer));
            assert_eq!(overload_value(answer), value);
        }
        assert_eq!(overload_of(WZ_CAPI_C_OVERLOAD_KEEP_LATEST + 1), None);
    }

    /// The default statement is `reject`, which every build takes, and NULL is no write.
    #[test]
    fn the_default_statement_is_reject() {
        let mut options = wz_capi_c_offload_options_t { overload: 9 };
        // SAFETY: a live local, and null.
        unsafe {
            wz_capi_c_offload_options_default(&mut options);
            wz_capi_c_offload_options_default(std::ptr::null_mut());
        }
        assert_eq!(options.overload, WZ_CAPI_C_OVERLOAD_REJECT);
        assert_eq!(
            overload_of(options.overload),
            Some(SubscriberOverload::Reject)
        );
    }

    /// A null subscriber or output is `Z_ENULL` and writes nothing.
    #[test]
    fn stats_of_nothing_is_null() {
        let mut out = wz_capi_c_offload_stats_t::default();
        // SAFETY: null arguments are the case under test.
        unsafe {
            assert_eq!(
                wz_capi_c_subscriber_offload_stats(std::ptr::null(), &mut out),
                Z_ENULL
            );
        }
        assert_eq!(out, wz_capi_c_offload_stats_t::default());
    }
}
