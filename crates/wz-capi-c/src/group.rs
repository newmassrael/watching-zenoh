// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R2932 — zenoh-ext's group membership (`Group` / `Member` / `GroupEvent`)
//! as C doors.
//!
//! ## Why `wz_capi_c_` and not `ze_`
//!
//! Upstream zenoh-c exports NO group surface at the pinned checkout, so there
//! is no `ze_group_*` spelling to follow, and this crate may not mint one:
//! `wz_exports_nothing_the_reference_does_not`
//! (`crates/wz-integration-tests/tests/zenoh_c_abi_symbol_census.rs`) refuses
//! any `z_` / `zc_` / `ze_` export the reference library lacks. A `ze_` name
//! invented here would also be a guess at a name upstream has not chosen, and
//! a wrong guess would be a drop-in symbol with the wrong meaning.
//!
//! ## The naming rule, so the eventual upstream names are predictable
//!
//! Every name below is what zenoh-c's own convention for its `zenoh-ext`
//! surface (the `ze_advanced_*` family) produces for these Rust items, with
//! the prefix `ze_` replaced by `wz_capi_c_` (and `ZE_` by `WZ_CAPI_C_`):
//!
//! - type `T` → `ze_{owned,loaned,moved}_<snake(T)>_t`, with
//!   `ze_<snake(T)>_loan`, `ze_<snake(T)>_drop`, `ze_<snake(T)>_clone`,
//!   `ze_internal_<snake(T)>_null` / `_check`;
//! - method `T::m` → `ze_<snake(T)>_<m>`, the object first, an out-parameter
//!   first for a constructor (`Group::join` → `ze_group_join(this_, ...)`);
//! - a builder → `ze_<snake(T)>_options_t` + `ze_<snake(T)>_options_default`;
//! - an iterator or channel result → a `ze_closure_<snake(item)>` callback,
//!   as zenoh-c turns every such return into a closure;
//! - an enum `E` → `ze_<snake(E)>_t` with `ZE_<SNAKE(E)>_<VARIANT>` values.
//!
//! When upstream ships the surface, each door here compares 1:1 with its `ze_`
//! name, and wz can export those names as aliases then. The member field
//! accessors (`info`, `lease_ms`, `liveliness`, `refresh_ratio`) and the
//! `group_event_*` readers are the exception: upstream keeps those fields
//! private (`Member` has only `id()`) or unpacks events by `match`, so those
//! names apply the rule to a FIELD and are the least certain of the set.
//!
//! ## Threads
//!
//! The event closure runs on a wz runtime worker, never on the thread that
//! called a door, and never twice at once for one group. `view`, `leader`,
//! `size` and the member accessors may be called from inside it.
//! `wz_capi_c_group_subscribe` may not (it answers `Z_EBUSY_MUTEX`), and
//! `wz_capi_c_group_wait_for_view_size` answers at once there instead of
//! waiting on a delivery its own frame is blocking.

#![allow(non_camel_case_types)]

use std::ffi::{c_int, c_void};
use std::sync::Arc;
use std::time::Duration;

use wz_capi_core::faces::SharedSession;
use wz_capi_core::group::{GroupAggregate, GroupError, GroupId, MemberLiveliness};
use wz_runtime_tokio::group::{GroupEvent, Member};
use wz_runtime_tokio::qos::Priority;

use crate::abi::{
    z_closure_drop_callback_t, z_loaned_keyexpr_t, z_loaned_session_t, z_moved_string_t,
    z_view_string_t, Handle,
};
use crate::ffi::{guard_val, guarded, CClosure as FfiClosure};
use crate::keyexpr::keyexpr_str;
use crate::publisher::{priority_from_c, z_priority_t};
use crate::result::{ZResult, Z_EBUSY_MUTEX, Z_EGENERIC, Z_EINVAL, Z_ENULL, Z_OK};
use crate::session::session_state;
use crate::string::{take_moved_string, view_string_over};

// ---------------------------------------------------------------------------
// enums
// ---------------------------------------------------------------------------

/// zenoh-ext `MemberLiveliness`.
pub type wz_capi_c_member_liveliness_t = c_int;
/// The member announces itself on a timer (upstream's default).
pub const WZ_CAPI_C_MEMBER_LIVELINESS_AUTO: wz_capi_c_member_liveliness_t = 0;
/// The member is kept alive by its owner.
pub const WZ_CAPI_C_MEMBER_LIVELINESS_MANUAL: wz_capi_c_member_liveliness_t = 1;

/// zenoh-ext `GroupEvent`'s variants.
pub type wz_capi_c_group_event_kind_t = c_int;
/// A member joined.
pub const WZ_CAPI_C_GROUP_EVENT_KIND_JOIN: wz_capi_c_group_event_kind_t = 0;
/// A member announced it is leaving.
pub const WZ_CAPI_C_GROUP_EVENT_KIND_LEAVE: wz_capi_c_group_event_kind_t = 1;
/// A member's lease elapsed.
pub const WZ_CAPI_C_GROUP_EVENT_KIND_LEASE_EXPIRED: wz_capi_c_group_event_kind_t = 2;
/// The leader changed. Declared and never sent, upstream and here alike.
pub const WZ_CAPI_C_GROUP_EVENT_KIND_NEW_LEADER: wz_capi_c_group_event_kind_t = 3;

// ---------------------------------------------------------------------------
// member
// ---------------------------------------------------------------------------

/// Upstream's `VIEW_REFRESH_LEASE_RATIO`
/// (`zenoh-ext/src/group.rs` @ `const VIEW_REFRESH_LEASE_RATIO: f32 = 0.75f32;`).
const UPSTREAM_REFRESH_RATIO: f32 = 0.75;

/// zenoh-ext `Member`'s builder, as zenoh-c spells builders.
#[repr(C)]
pub struct wz_capi_c_member_options_t {
    /// `Member::info`. NULL for none. Consumed by `wz_capi_c_member_new` on
    /// every path.
    pub info: *mut z_moved_string_t,
    /// `Member::lease`, in milliseconds.
    pub lease_ms: u64,
    /// `Member::refresh_ratio`: the keep-alive period as a fraction of the lease.
    pub refresh_ratio: f32,
    /// `Member::liveliness`.
    pub liveliness: wz_capi_c_member_liveliness_t,
    /// `Member::priority`: the QoS priority of this member's group events.
    pub priority: z_priority_t,
}

/// The member record behind an owned member, and the priority upstream keeps
/// on `Member` beside it (wz keeps it off the wire model, so it rides here).
pub(crate) struct MemberState {
    member: Member,
    priority: Priority,
}

/// An owned member. One handle; wz-own, so there is no upstream size to pad to.
#[repr(C)]
pub struct wz_capi_c_owned_member_t {
    pub(crate) handle: Handle,
}

/// A loaned member — the same layout, so `loan` is a pointer cast.
#[repr(C)]
pub struct wz_capi_c_loaned_member_t {
    pub(crate) handle: Handle,
}

/// A moved member.
#[repr(C)]
pub struct wz_capi_c_moved_member_t {
    pub(crate) _this: wz_capi_c_owned_member_t,
}

impl wz_capi_c_owned_member_t {
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
        }
    }

    fn adopt(state: MemberState) -> Self {
        Self {
            handle: Box::into_raw(Box::new(state)) as Handle,
        }
    }
}

/// A NON-owning member slot over `state`, for lending a member to C for the
/// length of one call. Never released through the member doors.
fn borrowed_member(state: &MemberState) -> wz_capi_c_owned_member_t {
    wz_capi_c_owned_member_t {
        handle: state as *const MemberState as Handle,
    }
}

/// # Safety
/// `this_` must be null or a valid loaned member.
unsafe fn member_state<'a>(this_: *const wz_capi_c_loaned_member_t) -> Option<&'a MemberState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    // SAFETY: a live `MemberState` this crate boxed or lent.
    (!handle.is_null()).then(|| unsafe { &*(handle as *const MemberState) })
}

/// The builder defaults, which are upstream's `Member::new` defaults
/// (`zenoh-ext/src/group.rs` @ `lease: DEFAULT_LEASE,`): no info, an 18 s
/// lease refreshed at 0.75 of it, automatic liveliness, `DataHigh`.
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_member_options_default(this_: *mut wz_capi_c_member_options_t) {
    if this_.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe {
        *this_ = wz_capi_c_member_options_t {
            info: std::ptr::null_mut(),
            lease_ms: wz_runtime_tokio::group::Member::new("").lease.as_millis() as u64,
            refresh_ratio: UPSTREAM_REFRESH_RATIO,
            liveliness: WZ_CAPI_C_MEMBER_LIVELINESS_AUTO,
            priority: Priority::DataHigh as u8 as z_priority_t,
        }
    };
}

/// zenoh-ext `Member::new(mid)` plus the builder. `options` NULL means the
/// defaults. `options->info` is consumed on every path.
///
/// `Z_EINVAL` for a member id with a wildcard, as upstream bails
/// (`zenoh-ext/src/group.rs` @ `Member ID is not allowed to contain wildcards`),
/// for an info that is not UTF-8, and for an unknown liveliness value.
///
/// # Safety
/// `this_` must be writable; `id` null or a valid loaned keyexpr; `options`
/// null or a valid options struct.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_member_new(
    this_: *mut wz_capi_c_owned_member_t,
    id: *const z_loaned_keyexpr_t,
    options: *mut wz_capi_c_member_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved info FIRST, so an error below cannot leak it.
        let info = if options.is_null() {
            None
        } else {
            // SAFETY: the caller's contract.
            unsafe { take_moved_string((*options).info) }
        };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_member_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(mid) = (unsafe { keyexpr_str(id) }) else {
            return Z_ENULL;
        };
        if wz_runtime_tokio::keyexpr_match::is_wild(mid) {
            return Z_EINVAL;
        }
        let mut defaults = wz_capi_c_member_options_t {
            info: std::ptr::null_mut(),
            lease_ms: 0,
            refresh_ratio: 0.0,
            liveliness: 0,
            priority: 0,
        };
        // SAFETY: `defaults` is writable.
        unsafe { wz_capi_c_member_options_default(&mut defaults) };
        let opts = if options.is_null() {
            &defaults
        } else {
            // SAFETY: the caller's contract.
            unsafe { &*options }
        };
        let info = match info.map(String::from_utf8) {
            None => None,
            Some(Ok(text)) => Some(text),
            Some(Err(_)) => return Z_EINVAL,
        };
        let liveliness = match opts.liveliness {
            WZ_CAPI_C_MEMBER_LIVELINESS_AUTO => MemberLiveliness::Auto,
            WZ_CAPI_C_MEMBER_LIVELINESS_MANUAL => MemberLiveliness::Manual,
            _ => return Z_EINVAL,
        };
        let mut member = Member::new(mid)
            .lease(Duration::from_millis(opts.lease_ms))
            .liveliness(liveliness)
            .refresh_ratio(opts.refresh_ratio);
        if let Some(info) = info {
            member = member.info(info);
        }
        // SAFETY: checked non-null above.
        unsafe {
            *this_ = wz_capi_c_owned_member_t::adopt(MemberState {
                member,
                priority: priority_from_c(opts.priority),
            })
        };
        Z_OK
    })
}

/// zenoh-ext `Member::id`, as a view valid while the member is.
///
/// # Safety
/// `this_` null or a valid loaned member; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_member_id(
    this_: *const wz_capi_c_loaned_member_t,
    out: *mut z_view_string_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let id = unsafe { member_state(this_) }.map(|s| s.member.id());
        // SAFETY: checked non-null above.
        unsafe { *out = view_string_over(id.unwrap_or("")) };
        if id.is_some() {
            Z_OK
        } else {
            Z_ENULL
        }
    })
}

/// The member's `info`, as a view. `false` (and an empty view) when it has
/// none. Upstream keeps the field private; see the module doc on naming.
///
/// # Safety
/// `this_` null or a valid loaned member; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_member_info(
    this_: *const wz_capi_c_loaned_member_t,
    out: *mut z_view_string_t,
) -> bool {
    guard_val(false, || {
        if out.is_null() {
            return false;
        }
        // SAFETY: the caller's contract.
        let info = unsafe { member_state(this_) }.and_then(|s| s.member.info.as_deref());
        // SAFETY: checked non-null above.
        unsafe { *out = view_string_over(info.unwrap_or("")) };
        info.is_some()
    })
}

/// The member's lease, in milliseconds; 0 for a null member.
///
/// # Safety
/// `this_` null or a valid loaned member.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_member_lease_ms(this_: *const wz_capi_c_loaned_member_t) -> u64 {
    guard_val(0, || {
        // SAFETY: the caller's contract.
        unsafe { member_state(this_) }.map_or(0, |s| s.member.lease.as_millis() as u64)
    })
}

/// The member's liveliness mode; AUTO for a null member.
///
/// # Safety
/// `this_` null or a valid loaned member.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_member_liveliness(
    this_: *const wz_capi_c_loaned_member_t,
) -> wz_capi_c_member_liveliness_t {
    guard_val(WZ_CAPI_C_MEMBER_LIVELINESS_AUTO, || {
        // SAFETY: the caller's contract.
        match unsafe { member_state(this_) }.map(|s| s.member.liveliness) {
            Some(MemberLiveliness::Manual) => WZ_CAPI_C_MEMBER_LIVELINESS_MANUAL,
            _ => WZ_CAPI_C_MEMBER_LIVELINESS_AUTO,
        }
    })
}

/// The member's refresh ratio; 0 for a null member.
///
/// # Safety
/// `this_` null or a valid loaned member.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_member_refresh_ratio(
    this_: *const wz_capi_c_loaned_member_t,
) -> f32 {
    guard_val(0.0, || {
        // SAFETY: the caller's contract.
        unsafe { member_state(this_) }.map_or(0.0, |s| s.member.refresh_ratio)
    })
}

/// Borrow a member.
///
/// # Safety
/// `this_` null or a valid owned member.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_member_loan(
    this_: *const wz_capi_c_owned_member_t,
) -> *const wz_capi_c_loaned_member_t {
    this_ as *const wz_capi_c_loaned_member_t
}

/// Copy a member into `dst`, which holds a gravestone on failure.
///
/// # Safety
/// `dst` writable; `this_` null or a valid loaned member.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_member_clone(
    dst: *mut wz_capi_c_owned_member_t,
    this_: *const wz_capi_c_loaned_member_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = wz_capi_c_owned_member_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(state) = (unsafe { member_state(this_) }) else {
            return Z_ENULL;
        };
        let copy = MemberState {
            member: state.member.clone(),
            priority: state.priority,
        };
        // SAFETY: checked non-null above.
        unsafe { *dst = wz_capi_c_owned_member_t::adopt(copy) };
        Z_OK
    })
}

/// Take the state out of a moved member, gravestoning the slot.
///
/// # Safety
/// `this_` null or a valid moved member.
unsafe fn take_member(this_: *mut wz_capi_c_moved_member_t) -> Option<Box<MemberState>> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_)._this.handle };
    // SAFETY: the caller's contract.
    unsafe { (*this_)._this = wz_capi_c_owned_member_t::null_value() };
    // SAFETY: a live `Box<MemberState>` this crate leaked in `adopt`.
    (!handle.is_null()).then(|| unsafe { Box::from_raw(handle as *mut MemberState) })
}

/// Release a member. A second drop is a no-op.
///
/// # Safety
/// `this_` null or a valid moved member.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_member_drop(this_: *mut wz_capi_c_moved_member_t) {
    let _ = guarded(|| {
        // SAFETY: the caller's contract.
        drop(unsafe { take_member(this_) });
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_member_null(this_: *mut wz_capi_c_owned_member_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_member_t::null_value() };
    }
}

/// Whether the slot holds a member.
///
/// # Safety
/// `this_` null or a valid owned member.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_member_check(
    this_: *const wz_capi_c_owned_member_t,
) -> bool {
    // SAFETY: the caller's contract.
    !this_.is_null() && !unsafe { (*this_).handle }.is_null()
}

// ---------------------------------------------------------------------------
// closures
// ---------------------------------------------------------------------------

/// The per-member callback `wz_capi_c_group_view` calls.
pub type wz_capi_c_closure_member_callback_t =
    Option<unsafe extern "C" fn(member: *const wz_capi_c_loaned_member_t, context: *mut c_void)>;

/// An owned member closure.
#[repr(C)]
pub struct wz_capi_c_owned_closure_member_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: wz_capi_c_closure_member_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// A loaned member closure.
#[repr(C)]
pub struct wz_capi_c_loaned_closure_member_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: wz_capi_c_closure_member_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// A moved member closure.
#[repr(C)]
pub struct wz_capi_c_moved_closure_member_t {
    pub(crate) _this: wz_capi_c_owned_closure_member_t,
}

/// The per-event callback `wz_capi_c_group_subscribe` installs.
pub type wz_capi_c_closure_group_event_callback_t = Option<
    unsafe extern "C" fn(event: *const wz_capi_c_loaned_group_event_t, context: *mut c_void),
>;

/// An owned group event closure.
#[repr(C)]
pub struct wz_capi_c_owned_closure_group_event_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: wz_capi_c_closure_group_event_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// A loaned group event closure.
#[repr(C)]
pub struct wz_capi_c_loaned_closure_group_event_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: wz_capi_c_closure_group_event_callback_t,
    pub(crate) drop: z_closure_drop_callback_t,
}

/// A moved group event closure.
#[repr(C)]
pub struct wz_capi_c_moved_closure_group_event_t {
    pub(crate) _this: wz_capi_c_owned_closure_group_event_t,
}

/// The bodies of the doors a closure type needs — constructor, gravestone,
/// check, call, drop — written once for both closure types, so the two cannot
/// drift apart. The exported doors below are one-line calls into these.
macro_rules! closure_doors {
    (
        $owned:ident, $loaned:ident, $moved:ident, $callback:ident, $arg:ty
    ) => {
        impl $owned {
            fn null_value() -> Self {
                Self {
                    context: std::ptr::null_mut(),
                    call: None,
                    drop: None,
                }
            }

            /// Adopt the fields of a moved closure, gravestoning the slot, so
            /// the returned value owns the `drop(context)`.
            ///
            /// # Safety
            /// `moved` must be a valid, writable moved closure.
            unsafe fn adopt(moved: *mut $moved) -> FfiClosure<$callback> {
                // SAFETY: the caller's contract.
                let owned = unsafe { &mut (*moved)._this };
                let adopted = FfiClosure::new(owned.context, owned.call, owned.drop);
                *owned = Self::null_value();
                adopted
            }

            /// The C constructor's body.
            ///
            /// # Safety
            /// `this_` null or writable.
            unsafe fn construct(
                this_: *mut Self,
                call: $callback,
                drop: z_closure_drop_callback_t,
                context: *mut c_void,
            ) {
                if !this_.is_null() {
                    // SAFETY: the caller's contract.
                    unsafe {
                        *this_ = Self {
                            context,
                            call,
                            drop,
                        }
                    };
                }
            }

            /// The C gravestone door's body.
            ///
            /// # Safety
            /// `this_` null or writable.
            unsafe fn gravestone(this_: *mut Self) {
                if !this_.is_null() {
                    // SAFETY: the caller's contract.
                    unsafe { *this_ = Self::null_value() };
                }
            }

            /// The C check door's body.
            ///
            /// # Safety
            /// `this_` null or a valid owned closure.
            unsafe fn holds(this_: *const Self) -> bool {
                // SAFETY: the caller's contract.
                !this_.is_null() && unsafe { (*this_).call }.is_some()
            }

            /// The C call door's body.
            ///
            /// # Safety
            /// `closure` null or a valid loaned closure; `arg` what its
            /// callback expects.
            unsafe fn invoke(closure: *const $loaned, arg: $arg) {
                if closure.is_null() {
                    return;
                }
                // SAFETY: the caller's contract.
                let (call, ctx) = unsafe { ((*closure).call, (*closure).context) };
                if let Some(call) = call {
                    // SAFETY: the caller's contract; an unwind across
                    // `extern "C"` is UB, so it is caught.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                        call(arg, ctx);
                    }));
                }
            }

            /// The C drop door's body: runs `drop(context)` once.
            ///
            /// # Safety
            /// `this_` null or a valid moved closure.
            unsafe fn release(this_: *mut $moved) {
                if !this_.is_null() {
                    // SAFETY: the caller's contract; dropping the adopted
                    // value runs the C `drop(context)`.
                    drop(unsafe { Self::adopt(this_) });
                }
            }
        }
    };
}

closure_doors!(
    wz_capi_c_owned_closure_member_t,
    wz_capi_c_loaned_closure_member_t,
    wz_capi_c_moved_closure_member_t,
    wz_capi_c_closure_member_callback_t,
    *const wz_capi_c_loaned_member_t
);

closure_doors!(
    wz_capi_c_owned_closure_group_event_t,
    wz_capi_c_loaned_closure_group_event_t,
    wz_capi_c_moved_closure_group_event_t,
    wz_capi_c_closure_group_event_callback_t,
    *const wz_capi_c_loaned_group_event_t
);

// The exported doors are written out rather than generated: the header gate
// (`scripts/lib/capi_c_wz_door_header.py`) derives the exported set from the
// source text, and a name a macro assembles is a name it cannot see.

/// Build a member closure from its three parts.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_closure_member(
    this_: *mut wz_capi_c_owned_closure_member_t,
    call: wz_capi_c_closure_member_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { wz_capi_c_owned_closure_member_t::construct(this_, call, drop, context) }
}

/// Write the gravestone.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_closure_member_null(
    this_: *mut wz_capi_c_owned_closure_member_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { wz_capi_c_owned_closure_member_t::gravestone(this_) }
}

/// Whether the slot holds a closure.
///
/// # Safety
/// `this_` null or a valid owned closure.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_closure_member_check(
    this_: *const wz_capi_c_owned_closure_member_t,
) -> bool {
    // SAFETY: the caller's contract, delegated.
    unsafe { wz_capi_c_owned_closure_member_t::holds(this_) }
}

/// Borrow a member closure.
///
/// # Safety
/// `this_` null or a valid owned closure.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_closure_member_loan(
    this_: *const wz_capi_c_owned_closure_member_t,
) -> *const wz_capi_c_loaned_closure_member_t {
    this_ as *const wz_capi_c_loaned_closure_member_t
}

/// Call a member closure once.
///
/// # Safety
/// `closure` null or a valid loaned closure; `member` null or a valid loaned
/// member.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_closure_member_call(
    closure: *const wz_capi_c_loaned_closure_member_t,
    member: *const wz_capi_c_loaned_member_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { wz_capi_c_owned_closure_member_t::invoke(closure, member) }
}

/// Release a member closure.
///
/// # Safety
/// `this_` null or a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_closure_member_drop(
    this_: *mut wz_capi_c_moved_closure_member_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { wz_capi_c_owned_closure_member_t::release(this_) }
}

/// Build a group event closure from its three parts.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_closure_group_event(
    this_: *mut wz_capi_c_owned_closure_group_event_t,
    call: wz_capi_c_closure_group_event_callback_t,
    drop: z_closure_drop_callback_t,
    context: *mut c_void,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { wz_capi_c_owned_closure_group_event_t::construct(this_, call, drop, context) }
}

/// Write the gravestone.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_closure_group_event_null(
    this_: *mut wz_capi_c_owned_closure_group_event_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { wz_capi_c_owned_closure_group_event_t::gravestone(this_) }
}

/// Whether the slot holds a closure.
///
/// # Safety
/// `this_` null or a valid owned closure.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_closure_group_event_check(
    this_: *const wz_capi_c_owned_closure_group_event_t,
) -> bool {
    // SAFETY: the caller's contract, delegated.
    unsafe { wz_capi_c_owned_closure_group_event_t::holds(this_) }
}

/// Borrow a group event closure.
///
/// # Safety
/// `this_` null or a valid owned closure.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_closure_group_event_loan(
    this_: *const wz_capi_c_owned_closure_group_event_t,
) -> *const wz_capi_c_loaned_closure_group_event_t {
    this_ as *const wz_capi_c_loaned_closure_group_event_t
}

/// Call a group event closure once.
///
/// # Safety
/// `closure` null or a valid loaned closure; `event` null or a lent event.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_closure_group_event_call(
    closure: *const wz_capi_c_loaned_closure_group_event_t,
    event: *const wz_capi_c_loaned_group_event_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { wz_capi_c_owned_closure_group_event_t::invoke(closure, event) }
}

/// Release a group event closure.
///
/// # Safety
/// `this_` null or a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_closure_group_event_drop(
    this_: *mut wz_capi_c_moved_closure_group_event_t,
) {
    // SAFETY: the caller's contract, delegated.
    unsafe { wz_capi_c_owned_closure_group_event_t::release(this_) }
}

/// The event closure as the aggregate holds it. `Send` by construction (the
/// context is a `SendPtr`), which is all a sink needs: the aggregate calls it
/// under its sink mutex, so two calls on one context never overlap, and from
/// the wz APPLICATION runtime, never from the C application thread.
type CEventClosure = FfiClosure<wz_capi_c_closure_group_event_callback_t>;

// ---------------------------------------------------------------------------
// group event
// ---------------------------------------------------------------------------

/// A group event, lent to the event closure for the length of one call.
/// Opaque in the header.
#[repr(C)]
pub struct wz_capi_c_loaned_group_event_t {
    event: *const GroupEvent,
    /// The joining member, for a JOIN; null otherwise.
    member: *const wz_capi_c_loaned_member_t,
}

/// # Safety
/// `this_` null or an event lent by the delivery.
unsafe fn event_of<'a>(this_: *const wz_capi_c_loaned_group_event_t) -> Option<&'a GroupEvent> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let event = unsafe { (*this_).event };
    // SAFETY: the delivery keeps the event alive across the call.
    (!event.is_null()).then(|| unsafe { &*event })
}

/// Which kind of event this is; JOIN for a null event.
///
/// # Safety
/// `this_` null or an event lent by the delivery.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_event_kind(
    this_: *const wz_capi_c_loaned_group_event_t,
) -> wz_capi_c_group_event_kind_t {
    // SAFETY: the caller's contract.
    match unsafe { event_of(this_) } {
        Some(GroupEvent::Leave(_)) => WZ_CAPI_C_GROUP_EVENT_KIND_LEAVE,
        Some(GroupEvent::LeaseExpired(_)) => WZ_CAPI_C_GROUP_EVENT_KIND_LEASE_EXPIRED,
        Some(GroupEvent::NewLeader(_)) => WZ_CAPI_C_GROUP_EVENT_KIND_NEW_LEADER,
        _ => WZ_CAPI_C_GROUP_EVENT_KIND_JOIN,
    }
}

/// The id of the member the event is about, for every kind.
///
/// # Safety
/// `this_` null or an event lent by the delivery; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_event_member_id(
    this_: *const wz_capi_c_loaned_group_event_t,
    out: *mut z_view_string_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let mid = match unsafe { event_of(this_) } {
            Some(GroupEvent::Join(member)) => Some(member.id()),
            Some(
                GroupEvent::Leave(mid) | GroupEvent::LeaseExpired(mid) | GroupEvent::NewLeader(mid),
            ) => Some(mid.as_str()),
            None => None,
        };
        // SAFETY: checked non-null above.
        unsafe { *out = view_string_over(mid.unwrap_or("")) };
        if mid.is_some() {
            Z_OK
        } else {
            Z_ENULL
        }
    })
}

/// The joining member of a JOIN, valid for the length of the callback; NULL
/// for every other kind, for which upstream carries an id and no record.
///
/// # Safety
/// `this_` null or an event lent by the delivery.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_event_member(
    this_: *const wz_capi_c_loaned_group_event_t,
) -> *const wz_capi_c_loaned_member_t {
    if this_.is_null() {
        return std::ptr::null();
    }
    // SAFETY: the caller's contract.
    unsafe { (*this_).member }
}

/// Hand one event to the C closure.
fn deliver_event(closure: &CEventClosure, event: &GroupEvent) {
    let Some(call) = closure.call else {
        return;
    };
    let state = match event {
        GroupEvent::Join(member) => Some(MemberState {
            member: member.clone(),
            // Priority is not on the wire; a remote record carries upstream's
            // deserialised default.
            priority: Priority::DEFAULT,
        }),
        _ => None,
    };
    let slot = state.as_ref().map(borrowed_member);
    let lent = wz_capi_c_loaned_group_event_t {
        event: event as *const GroupEvent,
        member: slot.as_ref().map_or(std::ptr::null(), |s| {
            s as *const wz_capi_c_owned_member_t as *const wz_capi_c_loaned_member_t
        }),
    };
    let ctx = closure.context.0;
    // SAFETY: the C closure's contract; an unwind across `extern "C"` is UB.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        call(&lent, ctx);
    }));
}

// ---------------------------------------------------------------------------
// group
// ---------------------------------------------------------------------------

/// What an owned group points at. Dropping it leaves the group.
pub(crate) struct GroupHandleState {
    shared: Arc<SharedSession>,
    id: GroupId,
    agg: Arc<GroupAggregate>,
}

impl Drop for GroupHandleState {
    fn drop(&mut self) {
        self.shared.leave_group(self.id);
    }
}

/// An owned group.
#[repr(C)]
pub struct wz_capi_c_owned_group_t {
    pub(crate) handle: Handle,
}

/// A loaned group.
#[repr(C)]
pub struct wz_capi_c_loaned_group_t {
    pub(crate) handle: Handle,
}

/// A moved group.
#[repr(C)]
pub struct wz_capi_c_moved_group_t {
    pub(crate) _this: wz_capi_c_owned_group_t,
}

impl wz_capi_c_owned_group_t {
    fn null_value() -> Self {
        Self {
            handle: std::ptr::null_mut(),
        }
    }
}

/// # Safety
/// `this_` null or a valid loaned group.
unsafe fn group_state<'a>(this_: *const wz_capi_c_loaned_group_t) -> Option<&'a GroupHandleState> {
    if this_.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*this_).handle };
    // SAFETY: a live `Box<GroupHandleState>` this crate leaked.
    (!handle.is_null()).then(|| unsafe { &*(handle as *const GroupHandleState) })
}

/// zenoh-ext `Group::join(session, group, member)`. `member` is consumed on
/// every path; `this_` holds a gravestone on failure.
///
/// `Z_EINVAL` for a group or member id that is not a canonical, wildcard-free
/// key expression, which is what upstream refuses. The member is announced to
/// every peer the session has and every one it gains later, and to the other
/// groups joined on the same session.
///
/// # Safety
/// `this_` writable; `session` null or a valid loaned session; `group` null or
/// a valid loaned keyexpr; `member` null or a valid moved member.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_join(
    this_: *mut wz_capi_c_owned_group_t,
    session: *const z_loaned_session_t,
    group: *const z_loaned_keyexpr_t,
    member: *mut wz_capi_c_moved_member_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract.
        let member = unsafe { take_member(member) };
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_group_t::null_value() };
        // SAFETY: the caller's contract, for each handle.
        let (Some(state), Some(gid), Some(member)) = (
            unsafe { session_state(session) },
            unsafe { keyexpr_str(group) },
            member,
        ) else {
            return Z_ENULL;
        };
        let MemberState { member, priority } = *member;
        let (id, agg) = match state.shared.join_group(gid.to_owned(), member, priority) {
            Ok(joined) => joined,
            Err(
                GroupError::NonCanonicalGroupId(_)
                | GroupError::WildcardGroupId(_)
                | GroupError::NonCanonicalMemberId(_)
                | GroupError::WildcardMemberId(_),
            ) => return Z_EINVAL,
            Err(_) => return Z_EGENERIC,
        };
        let boxed = Box::new(GroupHandleState {
            shared: state.shared.clone(),
            id,
            agg,
        });
        // SAFETY: checked non-null above.
        unsafe { (*this_).handle = Box::into_raw(boxed) as Handle };
        Z_OK
    })
}

/// Write `text` (or an empty view, answering `Z_ENULL`, for `None`).
///
/// # Safety
/// `out` must be null or writable.
unsafe fn write_view(out: *mut z_view_string_t, text: Option<&str>) -> ZResult {
    if out.is_null() {
        return Z_ENULL;
    }
    // SAFETY: the caller's contract.
    unsafe { *out = view_string_over(text.unwrap_or("")) };
    if text.is_some() {
        Z_OK
    } else {
        Z_ENULL
    }
}

/// zenoh-ext `Group::group_id`, as a view valid while the group is.
///
/// # Safety
/// `this_` null or a valid loaned group; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_group_id(
    this_: *const wz_capi_c_loaned_group_t,
    out: *mut z_view_string_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, both handles.
        unsafe { write_view(out, group_state(this_).map(|g| g.agg.group_id())) }
    })
}

/// zenoh-ext `Group::local_member_id`, as a view valid while the group is.
///
/// # Safety
/// `this_` null or a valid loaned group; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_local_member_id(
    this_: *const wz_capi_c_loaned_group_t,
    out: *mut z_view_string_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, both handles.
        unsafe { write_view(out, group_state(this_).map(|g| g.agg.local_member().id())) }
    })
}

/// zenoh-ext `Group::size`: every member this session sees, itself included.
/// 0 for a null group.
///
/// # Safety
/// `this_` null or a valid loaned group.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_size(this_: *const wz_capi_c_loaned_group_t) -> usize {
    guard_val(0, || {
        // SAFETY: the caller's contract.
        unsafe { group_state(this_) }.map_or(0, |g| g.agg.size())
    })
}

/// zenoh-ext `Group::view`: calls `callback` once per member, ordered by id
/// and the local member included, then drops it. Each member is lent for its
/// call; clone it to keep it. The callback runs on the calling thread.
///
/// # Safety
/// `this_` null or a valid loaned group; `callback` null or a valid moved
/// closure.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_view(
    this_: *const wz_capi_c_loaned_group_t,
    callback: *mut wz_capi_c_moved_closure_member_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract; consumed on every path from here.
        let closure = unsafe { wz_capi_c_owned_closure_member_t::adopt(callback) };
        // SAFETY: the caller's contract.
        let Some(group) = (unsafe { group_state(this_) }) else {
            return Z_ENULL;
        };
        if let Some(call) = closure.call {
            for member in group.agg.view() {
                let state = MemberState {
                    member,
                    priority: Priority::DEFAULT,
                };
                let slot = borrowed_member(&state);
                let ctx = closure.context.0;
                // SAFETY: the C closure's contract; an unwind is caught.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                    call(
                        &slot as *const wz_capi_c_owned_member_t
                            as *const wz_capi_c_loaned_member_t,
                        ctx,
                    );
                }));
            }
        }
        Z_OK
    })
}

/// zenoh-ext `Group::leader`: the member with the greatest id, written to
/// `out` as an owned copy.
///
/// # Safety
/// `this_` null or a valid loaned group; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_leader(
    this_: *const wz_capi_c_loaned_group_t,
    out: *mut wz_capi_c_owned_member_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *out = wz_capi_c_owned_member_t::null_value() };
        // SAFETY: the caller's contract.
        let Some(group) = (unsafe { group_state(this_) }) else {
            return Z_ENULL;
        };
        let state = MemberState {
            member: group.agg.leader(),
            priority: Priority::DEFAULT,
        };
        // SAFETY: checked non-null above.
        unsafe { *out = wz_capi_c_owned_member_t::adopt(state) };
        Z_OK
    })
}

/// zenoh-ext `Group::subscribe`, as a callback: every later JOIN / LEAVE /
/// LEASE_EXPIRED is delivered to `callback`. Last-wins, as upstream's is: a
/// second call replaces the first closure and drops it before returning.
/// `callback` is consumed on every path.
///
/// `Z_EBUSY_MUTEX` from inside this group's own event callback, where the
/// closure being replaced is the one running.
///
/// # Safety
/// `this_` null or a valid loaned group; `callback` null or a valid moved
/// closure.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_subscribe(
    this_: *const wz_capi_c_loaned_group_t,
    callback: *mut wz_capi_c_moved_closure_group_event_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract; consumed on every path from here.
        let closure: CEventClosure =
            unsafe { wz_capi_c_owned_closure_group_event_t::adopt(callback) };
        // SAFETY: the caller's contract.
        let Some(group) = (unsafe { group_state(this_) }) else {
            return Z_ENULL;
        };
        match group.agg.subscribe(Box::new(move |event: &GroupEvent| {
            deliver_event(&closure, event)
        })) {
            Ok(displaced) => {
                // Outside every lock: this runs the old closure's drop.
                drop(displaced);
                Z_OK
            }
            Err(_) => Z_EBUSY_MUTEX,
        }
    })
}

/// zenoh-ext `Group::wait_for_view_size`: block until the view holds at least
/// `size` members or `timeout_ms` elapses; whether it got there.
///
/// # Safety
/// `this_` null or a valid loaned group.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_wait_for_view_size(
    this_: *const wz_capi_c_loaned_group_t,
    size: usize,
    timeout_ms: u64,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        unsafe { group_state(this_) }.is_some_and(|g| {
            g.agg
                .wait_for_view_size(size, Duration::from_millis(timeout_ms))
        })
    })
}

/// Borrow a group.
///
/// # Safety
/// `this_` null or a valid owned group.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_loan(
    this_: *const wz_capi_c_owned_group_t,
) -> *const wz_capi_c_loaned_group_t {
    this_ as *const wz_capi_c_loaned_group_t
}

/// Leave the group and release it. The event closure's `drop(context)` has
/// run when this returns, unless it is called from inside that closure. A
/// second drop is a no-op.
///
/// # Safety
/// `this_` null or a valid moved group.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_group_drop(this_: *mut wz_capi_c_moved_group_t) {
    let _ = guarded(|| {
        if this_.is_null() {
            return Z_OK;
        }
        // SAFETY: the caller's contract.
        let handle = unsafe { (*this_)._this.handle };
        // SAFETY: the caller's contract.
        unsafe { (*this_)._this = wz_capi_c_owned_group_t::null_value() };
        if !handle.is_null() {
            // SAFETY: a live `Box<GroupHandleState>` this crate leaked; its
            // `Drop` leaves the group on every session.
            drop(unsafe { Box::from_raw(handle as *mut GroupHandleState) });
        }
        Z_OK
    });
}

/// Write the gravestone.
///
/// # Safety
/// `this_` null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_group_null(this_: *mut wz_capi_c_owned_group_t) {
    if !this_.is_null() {
        // SAFETY: the caller's contract.
        unsafe { *this_ = wz_capi_c_owned_group_t::null_value() };
    }
}

/// Whether the slot holds a group.
///
/// # Safety
/// `this_` null or a valid owned group.
#[no_mangle]
pub unsafe extern "C" fn wz_capi_c_internal_group_check(
    this_: *const wz_capi_c_owned_group_t,
) -> bool {
    // SAFETY: the caller's contract.
    !this_.is_null() && !unsafe { (*this_).handle }.is_null()
}
