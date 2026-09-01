// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The LINK and TRANSPORT event planes — the surface a C program uses to ask
//! which peers a session is connected to, over which links, and to be told when
//! that changes.
//!
//! ## What this closes
//!
//! open-debt item 593 recorded that zenoh-c 1.10.0 added three planes wz builds
//! none of, and that a C program naming their symbols dies at LINK. R2257 built
//! the first (cancellation tokens, nine symbols) and R2258 answered two strays.
//! This module is the remaining large piece: NINETY-TWO symbols on the
//! `unstable` and `unstable-shm` arms, measured as the set difference between
//! upstream's `libzenohc.so` and wz's cdylib rather than counted off a prefix —
//! link 31, transport 25, closures 26, declare 4, info 3, undeclare 2, and
//! `zc_internal_create_transport`.
//!
//! It is ONE plane rather than seven despite that family split, and taking it
//! whole is deliberate. The families are not separable: a `z_link_event_t` is
//! only reachable through a `z_owned_closure_link_event_t`, which is only
//! installed by `z_declare_link_events_listener`, which is only undeclared by
//! `z_undeclare_link_events_listener`. Shipping any verb alone leaves a header
//! that promises a link which fails — the exact defect the item names.
//!
//! ## Gating is MEASURED per arm, not inferred from the header
//!
//! Upstream exports all ninety-two only where `Z_FEATURE_UNSTABLE_API` is set:
//! measured with `nm -D` against all four provisioned arms, the `nounstable` and
//! `nounstable-shm` oracles define ZERO of them. So the module is
//! `zenoh-c-no-unstable-api`-gated, and exporting it unconditionally would put wz
//! ABOVE its reference and red `wz_exports_nothing_the_reference_does_not` —
//! which is what R2257 measured when it made the same call for the cancellation
//! plane.
//!
//! ## Where the values come from
//!
//! Every field is READ off an established face, through
//! [`SharedSession::face_snapshots`](wz_capi_core::faces::SharedSession::face_snapshots).
//! Nothing here is invented:
//!
//! - `src` / `dst` come from `SessionLinkActions::link_endpoints_all`, the
//!   feature-free form of the walk the adminspace renderer already used — one
//!   entry per PHYSICAL link, which is the load-bearing count.
//! - `interfaces` keeps `LinkSubject`'s THREE-state answer. Upstream cannot
//!   express "could not determine" and maps a failed lookup to an empty array;
//!   wz distinguishes them internally, and this ABI has to flatten the two
//!   because the C type has no third state. It flattens toward the EMPTY array
//!   upstream also produces, so a C program sees no shape upstream does not.
//! - `is_streamed` / `reliability` are derived from the link PROTOCOL, which is
//!   where the property lives; see [`InterceptorLink::is_streamed`].
//! - `mtu` is the negotiated batch budget, the same value the fragmenter sizes
//!   against.
//!
//! ## What is honestly UNKNOWN, and says so
//!
//! Two accessors report absence rather than a plausible number, and upstream's
//! own signatures are what make that expressible:
//!
//! - `z_link_priorities` returns `bool`. wz binds a priority band to a link only
//!   under `transport-multilink` + `transport-qos`, and reads it back through no
//!   public accessor at all; with no band installed there is no range to report,
//!   and `false` is the measured answer.
//! - `z_link_group` writes an empty string. zenoh's link group is a multicast
//!   join-group name, and wz's C surface establishes unicast transports only.
//!
//! `z_link_auth_identifier` is the third of that shape but not the same case: it
//! is empty because wz's auth extension records no per-link identity string, not
//! because the link lacks one.

use std::ffi::c_void;
use std::sync::Arc;

use wz_capi_core::faces::{FaceEventKind, FaceSnapshot, LinkSnapshot};

use crate::abi::{
    z_closure_drop_callback_t, z_loaned_session_t, z_moved_string_t, z_owned_string_array_t,
    z_owned_string_t, z_sample_kind_t, Handle, Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT,
};
use crate::ffi::{guard_val, guarded};
use crate::publisher::{z_reliability_t, Z_RELIABILITY_BEST_EFFORT, Z_RELIABILITY_RELIABLE};
use crate::result::{ZResult, Z_EINVAL, Z_ENULL, Z_OK};
use crate::session::session_state;
use crate::zid::z_id_t;

// ---------------------------------------------------------------------------
// The opaque families
// ---------------------------------------------------------------------------

crate::abi::define_opaque!(z_owned_link_t, z_loaned_link_t, z_moved_link_t, 144);
crate::abi::define_opaque!(
    z_owned_link_event_t,
    z_loaned_link_event_t,
    z_moved_link_event_t,
    152
);
crate::abi::define_opaque!(
    z_owned_link_events_listener_t,
    z_loaned_link_events_listener_t,
    z_moved_link_events_listener_t,
    24
);
crate::abi::define_opaque!(
    z_owned_transport_events_listener_t,
    z_loaned_transport_events_listener_t,
    z_moved_transport_events_listener_t,
    24
);

/// Owned transport (zenoh-c `z_owned_transport_t`, `zenoh_opaque.h`:
/// `ALIGN(1) uint8_t _0[19]`, or `[20]` on a shared-memory build).
///
/// A VALUE, not a handle, and the nineteen bytes are why: 16 for the zid plus
/// three one-byte scalars is exactly the whole of upstream's type. That is also
/// why `zc_internal_create_transport` can build one from four arguments and why
/// `z_transport_drop` frees nothing — there is no owned allocation to free, and
/// writing one anyway would make `z_transport_clone` a deep copy of nothing.
///
/// ⚠ THE TYPE ITSELF DIFFERS BY ARM, which is not something the other three
/// families in this module do: `Z_FEATURE_SHARED_MEMORY` adds a twentieth byte
/// for `is_shm`, renames the constructor to `zc_internal_create_transport_shm`
/// (six parameters, not five) and adds `z_transport_is_shm`. MEASURED from
/// `zenoh_opaque.h` on both provisioned oracles rather than inferred: the
/// no-SHM header says 19/20 for transport/event and the SHM one says 20/21.
/// R2258's lesson, applied a round later — a plane's gating is read per arm from
/// the artifact, and this is the case where reading it changed the LAYOUT and
/// not merely the export list.
#[repr(C)]
pub struct z_owned_transport_t {
    pub(crate) zid: [u8; 16],
    pub(crate) whatami: u8,
    pub(crate) is_qos: u8,
    pub(crate) is_multicast: u8,
    /// The SHM arm's twentieth byte. See the type's own note.
    #[cfg(feature = "zenoh-c-shared-memory")]
    pub(crate) is_shm: u8,
}

/// Loaned transport — the same bytes, borrowed.
#[repr(C)]
pub struct z_loaned_transport_t {
    pub(crate) zid: [u8; 16],
    pub(crate) whatami: u8,
    pub(crate) is_qos: u8,
    pub(crate) is_multicast: u8,
    /// See [`z_owned_transport_t::is_shm`].
    #[cfg(feature = "zenoh-c-shared-memory")]
    pub(crate) is_shm: u8,
}

/// Moved transport.
#[repr(C)]
pub struct z_moved_transport_t {
    pub(crate) _this: z_owned_transport_t,
}

/// Owned transport event (zenoh-c `z_owned_transport_event_t`,
/// `zenoh_opaque.h`: `ALIGN(1) uint8_t _0[20]`) — a transport plus which way it
/// moved.
#[repr(C)]
pub struct z_owned_transport_event_t {
    pub(crate) transport: z_owned_transport_t,
    pub(crate) kind: u8,
}

/// Loaned transport event.
#[repr(C)]
pub struct z_loaned_transport_event_t {
    pub(crate) transport: z_owned_transport_t,
    pub(crate) kind: u8,
}

/// Moved transport event.
#[repr(C)]
pub struct z_moved_transport_event_t {
    pub(crate) _this: z_owned_transport_event_t,
}

/// The transport footprint this arm's header declares — 19 without SHM, 20 with
/// it. Named once so the four assertions below cannot drift apart.
#[cfg(not(feature = "zenoh-c-shared-memory"))]
const TRANSPORT_BYTES: usize = 19;
/// See the no-SHM twin.
#[cfg(feature = "zenoh-c-shared-memory")]
const TRANSPORT_BYTES: usize = 20;

const _: () = {
    assert!(std::mem::size_of::<z_owned_transport_t>() == TRANSPORT_BYTES);
    assert!(std::mem::align_of::<z_owned_transport_t>() == 1);
    assert!(std::mem::size_of::<z_loaned_transport_t>() == TRANSPORT_BYTES);
    assert!(std::mem::size_of::<z_moved_transport_t>() == TRANSPORT_BYTES);
    // An event is a transport plus one kind byte, on either arm.
    assert!(std::mem::size_of::<z_owned_transport_event_t>() == TRANSPORT_BYTES + 1);
    assert!(std::mem::align_of::<z_owned_transport_event_t>() == 1);
    assert!(std::mem::size_of::<z_loaned_transport_event_t>() == TRANSPORT_BYTES + 1);
    assert!(std::mem::size_of::<z_moved_transport_event_t>() == TRANSPORT_BYTES + 1);
};

impl z_owned_transport_t {
    /// The gravestone: an all-zero zid, which is the value
    /// `z_internal_transport_check` reads as "not a transport".
    ///
    /// A zid of sixteen zero bytes is not a zid any peer can have — wz mints one
    /// from entropy and refuses a zero — so this needs no separate valid flag,
    /// which is what lets the type stay nineteen bytes.
    #[inline]
    pub(crate) fn null_value() -> Self {
        Self {
            zid: [0u8; 16],
            whatami: 0,
            is_qos: 0,
            is_multicast: 0,
            #[cfg(feature = "zenoh-c-shared-memory")]
            is_shm: 0,
        }
    }

    #[inline]
    fn from_snapshot(snapshot: &FaceSnapshot) -> Self {
        Self {
            zid: snapshot.zid,
            whatami: whatami_c_from_wire(snapshot.whatami),
            is_qos: u8::from(snapshot.is_qos),
            is_multicast: u8::from(snapshot.is_multicast),
            #[cfg(feature = "zenoh-c-shared-memory")]
            is_shm: u8::from(snapshot.is_shm),
        }
    }

    #[inline]
    fn is_live(&self) -> bool {
        self.zid != [0u8; 16]
    }
}

/// zenoh-c's `z_whatami_t` — `Z_WHATAMI_ROUTER = 1`, `PEER = 2`, `CLIENT = 4`
/// (`zenoh_commons.h:228-232`). A BITMASK, unlike wz's dense wire form.
pub type z_whatami_t = std::ffi::c_int;
/// `Z_WHATAMI_ROUTER` = 1.
pub const Z_WHATAMI_ROUTER: z_whatami_t = 1;
/// `Z_WHATAMI_PEER` = 2.
pub const Z_WHATAMI_PEER: z_whatami_t = 2;
/// `Z_WHATAMI_CLIENT` = 4.
pub const Z_WHATAMI_CLIENT: z_whatami_t = 4;

/// Map wz's 2-bit INIT wire role (0 Router, 1 Peer, 2 Client) onto zenoh-c's
/// bitmask spelling.
///
/// The two encodings are genuinely different and the conversion has to happen
/// SOMEWHERE: the wire form is dense because it rides two bits of a header, and
/// the C form is a mask because `z_scout` takes a union of roles. Doing it here,
/// at the ABI boundary, is the same split `peer_identities` documents for the
/// `z_info_*` exports.
///
/// An unrecognised wire value maps to `Z_WHATAMI_PEER` rather than to zero:
/// zero is not a role in upstream's enum, and handing a C `switch` a value none
/// of its cases match is worse than naming the role a session that both
/// publishes and answers is.
#[inline]
fn whatami_c_from_wire(wire: u8) -> u8 {
    let mask = match wire {
        0 => Z_WHATAMI_ROUTER,
        2 => Z_WHATAMI_CLIENT,
        _ => Z_WHATAMI_PEER,
    };
    // Every one of the three fits a byte, which is what makes the 19-byte
    // layout possible; the C accessor widens it back to the enum's `int`.
    mask as u8
}

// ---------------------------------------------------------------------------
// Link state
// ---------------------------------------------------------------------------

/// What an owned link's handle points at — one physical link's readable facts,
/// captured at the moment the snapshot was taken.
///
/// A COPY rather than a borrow of the live face, because upstream's ownership
/// says so: `z_link_clone` produces a link that outlives the callback it was
/// handed to, and a link whose accessors reached into a face would answer
/// differently — or crash — once that face went down. A link value is a reading,
/// and a reading does not change.
struct LinkState {
    src: String,
    dst: String,
    interfaces: Vec<String>,
    mtu: u16,
    is_streamed: bool,
    reliability: Option<z_reliability_t>,
    zid: [u8; 16],
}

impl LinkState {
    fn from_snapshot(link: &LinkSnapshot, zid: [u8; 16]) -> Self {
        Self {
            src: link.src.clone(),
            dst: link.dst.clone(),
            // The three-state answer flattens HERE and nowhere else: upstream's
            // array has no "undetermined", so an undetermined lookup reports the
            // same empty array upstream reports for one.
            interfaces: link.interfaces.clone().unwrap_or_default(),
            mtu: link.mtu,
            // A driver that cannot name its protocol cannot be called streamed;
            // upstream's `z_link_is_streamed` has no third answer, and `false`
            // is the one that does not claim framing wz cannot show.
            is_streamed: link.protocol.map(|p| p.is_streamed()).unwrap_or(false),
            reliability: link.protocol.map(|p| {
                if p.is_reliable() {
                    Z_RELIABILITY_RELIABLE
                } else {
                    Z_RELIABILITY_BEST_EFFORT
                }
            }),
            zid,
        }
    }
}

/// Borrow the state behind a loaned link.
///
/// # Safety
/// `link` must be null or a live loaned link whose handle this crate minted.
#[inline]
unsafe fn link_state<'a>(link: *const z_loaned_link_t) -> Option<&'a LinkState> {
    if link.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*link).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<LinkState>` this module leaked.
    Some(unsafe { &*(handle as *const LinkState) })
}

/// Mint an owned link over `state`.
#[inline]
fn owned_link(state: LinkState) -> z_owned_link_t {
    z_owned_link_t::from_handle(Box::into_raw(Box::new(state)) as Handle)
}

/// Write `text` into `str_out`, or leave a gravestone when it is null.
///
/// # Safety
/// `str_out` must be null or valid and writable.
#[inline]
unsafe fn write_string(str_out: *mut z_owned_string_t, text: &str) {
    if str_out.is_null() {
        return;
    }
    // SAFETY: the caller's contract.
    unsafe { *str_out = crate::string::owned_string_from(text.as_bytes()) };
}

// ---------------------------------------------------------------------------
// The four closures
// ---------------------------------------------------------------------------

/// The C call a link closure carries (`zenoh_commons.h:573`).
pub type z_closure_link_callback_t =
    Option<unsafe extern "C" fn(link: *mut z_loaned_link_t, context: *mut c_void)>;
/// The C call a link-event closure carries (`zenoh_commons.h:606`).
pub type z_closure_link_event_callback_t =
    Option<unsafe extern "C" fn(event: *mut z_loaned_link_event_t, context: *mut c_void)>;
/// The C call a transport closure carries (`zenoh_commons.h:714`).
pub type z_closure_transport_callback_t =
    Option<unsafe extern "C" fn(transport: *mut z_loaned_transport_t, context: *mut c_void)>;
/// The C call a transport-event closure carries (`zenoh_commons.h:747`).
pub type z_closure_transport_event_callback_t =
    Option<unsafe extern "C" fn(event: *mut z_loaned_transport_event_t, context: *mut c_void)>;

/// Define one of the four closure families.
///
/// TRANSPARENT rather than opaque, for the reason
/// [`z_owned_closure_sample_t`](crate::abi::z_owned_closure_sample_t) states:
/// upstream declares the three fields inline because the C side builds the value
/// itself through the `z_closure` macro, so the layout must match field for
/// field and not merely in size.
macro_rules! define_event_closure {
    ($Owned:ident, $Loaned:ident, $Moved:ident, $Callback:ty) => {
        /// Owned closure — context, call, drop.
        #[repr(C)]
        pub struct $Owned {
            pub(crate) context: *mut c_void,
            pub(crate) call: $Callback,
            pub(crate) drop: z_closure_drop_callback_t,
        }

        /// Loaned closure — three `size_t` in upstream's header, the same three
        /// words borrowed.
        #[repr(C)]
        pub struct $Loaned {
            pub(crate) context: *mut c_void,
            pub(crate) call: $Callback,
            pub(crate) drop: z_closure_drop_callback_t,
        }

        /// Moved closure.
        #[repr(C)]
        pub struct $Moved {
            pub(crate) _this: $Owned,
        }

        impl $Owned {
            /// The gravestone: no context, no callbacks.
            #[inline]
            pub(crate) fn null_value() -> Self {
                Self {
                    context: std::ptr::null_mut(),
                    call: None,
                    drop: None,
                }
            }

            /// Take this closure's parts, leaving a gravestone behind — the
            /// move semantics every `z_moved_*` argument has.
            #[inline]
            fn take(&mut self) -> Self {
                std::mem::replace(self, Self::null_value())
            }

            /// Run this closure's C `drop(context)`, once.
            #[inline]
            fn run_drop(&mut self) {
                let taken = self.take();
                if let Some(drop) = taken.drop {
                    // SAFETY: the C side installed both; running `drop` with the
                    // context it was installed with is the contract.
                    unsafe { drop(taken.context) };
                }
            }
        }

        const _: () = {
            assert!(std::mem::size_of::<$Owned>() == 3 * std::mem::size_of::<usize>());
            assert!(std::mem::size_of::<$Loaned>() == std::mem::size_of::<$Owned>());
            assert!(std::mem::size_of::<$Moved>() == std::mem::size_of::<$Owned>());
        };
    };
}

define_event_closure!(
    z_owned_closure_link_t,
    z_loaned_closure_link_t,
    z_moved_closure_link_t,
    z_closure_link_callback_t
);
define_event_closure!(
    z_owned_closure_link_event_t,
    z_loaned_closure_link_event_t,
    z_moved_closure_link_event_t,
    z_closure_link_event_callback_t
);
define_event_closure!(
    z_owned_closure_transport_t,
    z_loaned_closure_transport_t,
    z_moved_closure_transport_t,
    z_closure_transport_callback_t
);
define_event_closure!(
    z_owned_closure_transport_event_t,
    z_loaned_closure_transport_event_t,
    z_moved_closure_transport_event_t,
    z_closure_transport_event_callback_t
);

/// A closure the drive task invokes, held across threads.
///
/// # Safety
/// The premise is the one every C closure on this ABI rests on and it is stated
/// rather than assumed: the C application thread NEVER invokes these. They run
/// only from `face_up` / `face_down`, which are the drive role's own calls, so
/// there is no concurrent invocation for the C side to have to synchronise.
struct EventClosure<T> {
    closure: std::sync::Mutex<T>,
}

// SAFETY: as stated on `EventClosure` — a single invoking role.
unsafe impl<T> Send for EventClosure<T> {}
// SAFETY: as above.
unsafe impl<T> Sync for EventClosure<T> {}

// ---------------------------------------------------------------------------
// Listener state
// ---------------------------------------------------------------------------

/// What a listener handle points at: the registry it is registered with and the
/// id that undeclares it.
///
/// The `Arc<SharedSession>` is held so `z_undeclare_*` works after the C program
/// has dropped its session handle — upstream's listeners are independently
/// owned, and a listener that could not undeclare itself once its session
/// variable went out of scope would leak the C closure's context forever.
struct ListenerState {
    shared: Arc<wz_capi_core::faces::SharedSession>,
    watcher: u64,
}

impl Drop for ListenerState {
    fn drop(&mut self) {
        self.shared.unwatch_faces(self.watcher);
    }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// zenoh-c `z_link_events_listener_options_t` (`zenoh_commons.h:801-810`).
#[repr(C)]
pub struct z_link_events_listener_options_t {
    /// Replay the links already established when the listener is declared.
    pub history: bool,
    /// Restrict to one transport's links, or NULL for all. OWNERSHIP IS TAKEN.
    pub transport: *mut z_moved_transport_t,
}

/// zenoh-c `z_transport_events_listener_options_t` (`zenoh_commons.h:845-851`).
#[repr(C)]
pub struct z_transport_events_listener_options_t {
    /// Replay the transports already connected when the listener is declared.
    pub history: bool,
}

/// zenoh-c `z_info_links_options_t` (`zenoh_commons.h:1047-1054`).
#[repr(C)]
pub struct z_info_links_options_t {
    /// Restrict to one transport's links, or NULL for all. OWNERSHIP IS TAKEN.
    pub transport: *mut z_moved_transport_t,
}

/// Read a moved-transport filter, taking ownership as upstream's doc says it
/// does, and answer the zid to keep.
///
/// # Safety
/// `moved` must be null or a valid moved transport.
#[inline]
unsafe fn take_transport_filter(moved: *mut z_moved_transport_t) -> Option<[u8; 16]> {
    if moved.is_null() {
        return None;
    }
    // SAFETY: the caller's contract. The transport is a VALUE, so "taking
    // ownership" is reading it and gravestoning the source — there is nothing to
    // free, which is exactly why `z_transport_drop` is also a no-op.
    let taken =
        unsafe { std::mem::replace(&mut (*moved)._this, z_owned_transport_t::null_value()) };
    taken.is_live().then_some(taken.zid)
}

// ---------------------------------------------------------------------------
// link accessors
// ---------------------------------------------------------------------------

/// Borrow an owned link (zenoh-c `z_link_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned link.
#[no_mangle]
pub unsafe extern "C" fn z_link_loan(this_: *const z_owned_link_t) -> *const z_loaned_link_t {
    this_.cast()
}

/// Mutably borrow an owned link (zenoh-c `z_link_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned link.
#[no_mangle]
pub unsafe extern "C" fn z_link_loan_mut(this_: *mut z_owned_link_t) -> *mut z_loaned_link_t {
    this_.cast()
}

/// Deep-copy a link (zenoh-c `z_link_clone`).
///
/// # Safety
/// `this_` must be writable; `link` must be null or a live loaned link.
#[no_mangle]
pub unsafe extern "C" fn z_link_clone(this_: *mut z_owned_link_t, link: *const z_loaned_link_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // Written first so a null source leaves a gravestone rather than a stale
        // stack value.
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_link_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        if let Some(state) = unsafe { link_state(link) } {
            let copy = LinkState {
                src: state.src.clone(),
                dst: state.dst.clone(),
                interfaces: state.interfaces.clone(),
                mtu: state.mtu,
                is_streamed: state.is_streamed,
                reliability: state.reliability,
                zid: state.zid,
            };
            // SAFETY: the caller's contract.
            unsafe { *this_ = owned_link(copy) };
        }
    });
}

/// Free a link (zenoh-c `z_link_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved link whose handle is live.
#[no_mangle]
pub unsafe extern "C" fn z_link_drop(this_: *mut z_moved_link_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let handle =
            unsafe { std::mem::replace(&mut (*this_)._this, z_owned_link_t::null_value()) };
        if !handle.handle.is_null() {
            // SAFETY: a `Box<LinkState>` this module leaked, dropped once
            // because the source was gravestoned above.
            drop(unsafe { Box::from_raw(handle.handle as *mut LinkState) });
        }
    });
}

/// Take a loaned link into an owned one (zenoh-c `z_link_take_from_loaned`).
///
/// # Safety
/// `dst` must be writable; `src` must be null or a live loaned link.
#[no_mangle]
pub unsafe extern "C" fn z_link_take_from_loaned(
    dst: *mut z_owned_link_t,
    src: *mut z_loaned_link_t,
) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_link_t::null_value() };
        if src.is_null() {
            return;
        }
        // SAFETY: the caller's contract. The handle MOVES: the loaned view is
        // gravestoned so the same `Box` is not freed twice.
        let handle = unsafe { std::mem::replace(&mut (*src).handle, std::ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { *dst = z_owned_link_t::from_handle(handle) };
    });
}

/// Write this end's locator (zenoh-c `z_link_src`).
///
/// # Safety
/// `link` must be null or live; `str_out` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_link_src(link: *const z_loaned_link_t, str_out: *mut z_owned_string_t) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        let text = unsafe { link_state(link) }
            .map(|s| s.src.as_str())
            .unwrap_or("");
        // SAFETY: the caller's contract.
        unsafe { write_string(str_out, text) };
    });
}

/// Write the peer end's locator (zenoh-c `z_link_dst`).
///
/// # Safety
/// `link` must be null or live; `str_out` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_link_dst(link: *const z_loaned_link_t, str_out: *mut z_owned_string_t) {
    guard_val((), || {
        // SAFETY: the caller's contract, delegated.
        let text = unsafe { link_state(link) }
            .map(|s| s.dst.as_str())
            .unwrap_or("");
        // SAFETY: the caller's contract.
        unsafe { write_string(str_out, text) };
    });
}

/// Write this link's multicast GROUP (zenoh-c `z_link_group`).
///
/// Always empty, and that is a measurement rather than a stub: a group is the
/// multicast join address, and wz's C surface establishes unicast transports
/// only — see this module's header.
///
/// # Safety
/// `link` must be null or live; `str_out` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_link_group(
    link: *const z_loaned_link_t,
    str_out: *mut z_owned_string_t,
) {
    guard_val((), || {
        let _ = link;
        // SAFETY: the caller's contract.
        unsafe { write_string(str_out, "") };
    });
}

/// Write this link's AUTH IDENTIFIER (zenoh-c `z_link_auth_identifier`).
///
/// Always empty: wz's auth extension authenticates the handshake but records no
/// per-link identity string to report back.
///
/// # Safety
/// `link` must be null or live; `str_out` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_link_auth_identifier(
    link: *const z_loaned_link_t,
    str_out: *mut z_owned_string_t,
) {
    guard_val((), || {
        let _ = link;
        // SAFETY: the caller's contract.
        unsafe { write_string(str_out, "") };
    });
}

/// Write this link's NIC names (zenoh-c `z_link_interfaces`).
///
/// # Safety
/// `link` must be null or live; `interfaces_out` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_link_interfaces(
    link: *const z_loaned_link_t,
    interfaces_out: *mut z_owned_string_array_t,
) {
    guard_val((), || {
        if interfaces_out.is_null() {
            return;
        }
        // SAFETY: the caller's contract, delegated.
        let names = unsafe { link_state(link) }
            .map(|s| s.interfaces.clone())
            .unwrap_or_default();
        // SAFETY: the caller's contract.
        unsafe { *interfaces_out = crate::scout::owned_string_array_from(&names) };
    });
}

/// Whether this link carries a byte stream (zenoh-c `z_link_is_streamed`).
///
/// # Safety
/// `link` must be null or a live loaned link.
#[no_mangle]
pub unsafe extern "C" fn z_link_is_streamed(link: *const z_loaned_link_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { link_state(link) }
            .map(|s| s.is_streamed)
            .unwrap_or(false)
    })
}

/// This link's MTU (zenoh-c `z_link_mtu`).
///
/// # Safety
/// `link` must be null or a live loaned link.
#[no_mangle]
pub unsafe extern "C" fn z_link_mtu(link: *const z_loaned_link_t) -> u16 {
    guard_val(0, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { link_state(link) }.map(|s| s.mtu).unwrap_or(0)
    })
}

/// This link's reliability, when it has one (zenoh-c `z_link_reliability`).
///
/// # Safety
/// `link` must be null or live; `reliability_out` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_link_reliability(
    link: *const z_loaned_link_t,
    reliability_out: *mut z_reliability_t,
) -> bool {
    guard_val(false, || {
        if reliability_out.is_null() {
            return false;
        }
        // SAFETY: the caller's contract, delegated.
        match unsafe { link_state(link) }.and_then(|s| s.reliability) {
            Some(value) => {
                // SAFETY: the caller's contract.
                unsafe { *reliability_out = value };
                true
            }
            None => false,
        }
    })
}

/// This link's priority band, when one is bound (zenoh-c `z_link_priorities`).
///
/// Reports absence: wz binds a band only under multilink + QoS and reads it back
/// through no public accessor, so there is no range to report. See this module's
/// header for why that is written as `false` rather than as `0..7`.
///
/// # Safety
/// `link` must be null or live; both outputs must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_link_priorities(
    link: *const z_loaned_link_t,
    min_out: *mut u8,
    max_out: *mut u8,
) -> bool {
    guard_val(false, || {
        let _ = (link, min_out, max_out);
        false
    })
}

/// The peer zid this link reaches (zenoh-c `z_link_zid`).
///
/// # Safety
/// `link` must be null or a live loaned link.
#[no_mangle]
pub unsafe extern "C" fn z_link_zid(link: *const z_loaned_link_t) -> z_id_t {
    guard_val(z_id_t { id: [0u8; 16] }, || {
        // SAFETY: the caller's contract, delegated.
        z_id_t {
            id: unsafe { link_state(link) }
                .map(|s| s.zid)
                .unwrap_or([0u8; 16]),
        }
    })
}

/// Whether an owned link holds a live value (zenoh-c `z_internal_link_check`).
///
/// # Safety
/// `this_` must be null or a valid owned link.
#[no_mangle]
pub unsafe extern "C" fn z_internal_link_check(this_: *const z_owned_link_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Gravestone an owned link (zenoh-c `z_internal_link_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_link_null(this_: *mut z_owned_link_t) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *this_ = z_owned_link_t::null_value() };
        }
    });
}

// ---------------------------------------------------------------------------
// link event
// ---------------------------------------------------------------------------

/// What an owned link event's handle points at.
///
/// The loaned link is held INLINE so `z_link_event_link` can hand back a pointer
/// into it: upstream's accessor returns a borrow of the event's own link, not a
/// copy, and a `z_owned_link_t` built on the stack per call would dangle the
/// moment the accessor returned.
struct LinkEventState {
    loaned: z_loaned_link_t,
    kind: z_sample_kind_t,
}

impl Drop for LinkEventState {
    fn drop(&mut self) {
        let handle = std::mem::replace(&mut self.loaned.handle, std::ptr::null_mut());
        if !handle.is_null() {
            // SAFETY: a `Box<LinkState>` this module leaked into the event;
            // dropped once because the slot is cleared above.
            drop(unsafe { Box::from_raw(handle as *mut LinkState) });
        }
    }
}

/// Borrow the state behind a loaned link event.
///
/// # Safety
/// `event` must be null or a live loaned link event.
#[inline]
unsafe fn link_event_state<'a>(event: *const z_loaned_link_event_t) -> Option<&'a LinkEventState> {
    if event.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    let handle = unsafe { (*event).handle };
    if handle.is_null() {
        return None;
    }
    // SAFETY: a live `Box<LinkEventState>` this module leaked.
    Some(unsafe { &*(handle as *const LinkEventState) })
}

/// Borrow an owned link event (zenoh-c `z_link_event_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned link event.
#[no_mangle]
pub unsafe extern "C" fn z_link_event_loan(
    this_: *const z_owned_link_event_t,
) -> *const z_loaned_link_event_t {
    this_.cast()
}

/// Mutably borrow an owned link event (zenoh-c `z_link_event_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned link event.
#[no_mangle]
pub unsafe extern "C" fn z_link_event_loan_mut(
    this_: *mut z_owned_link_event_t,
) -> *mut z_loaned_link_event_t {
    this_.cast()
}

/// Free a link event (zenoh-c `z_link_event_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved link event whose handle is live.
#[no_mangle]
pub unsafe extern "C" fn z_link_event_drop(this_: *mut z_moved_link_event_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let taken =
            unsafe { std::mem::replace(&mut (*this_)._this, z_owned_link_event_t::null_value()) };
        if !taken.handle.is_null() {
            // SAFETY: a `Box<LinkEventState>` this module leaked; its own `Drop`
            // frees the link inside it.
            drop(unsafe { Box::from_raw(taken.handle as *mut LinkEventState) });
        }
    });
}

/// Take a loaned link event into an owned one (zenoh-c
/// `z_link_event_take_from_loaned`).
///
/// # Safety
/// `dst` must be writable; `src` must be null or a live loaned link event.
#[no_mangle]
pub unsafe extern "C" fn z_link_event_take_from_loaned(
    dst: *mut z_owned_link_event_t,
    src: *mut z_loaned_link_event_t,
) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_link_event_t::null_value() };
        if src.is_null() {
            return;
        }
        // SAFETY: the caller's contract; the handle MOVES.
        let handle = unsafe { std::mem::replace(&mut (*src).handle, std::ptr::null_mut()) };
        // SAFETY: as above.
        unsafe { *dst = z_owned_link_event_t::from_handle(handle) };
    });
}

/// Which way the link moved (zenoh-c `z_link_event_kind`).
///
/// # Safety
/// `event` must be null or a live loaned link event.
#[no_mangle]
pub unsafe extern "C" fn z_link_event_kind(event: *const z_loaned_link_event_t) -> z_sample_kind_t {
    guard_val(Z_SAMPLE_KIND_PUT, || {
        // SAFETY: the caller's contract, delegated.
        unsafe { link_event_state(event) }
            .map(|s| s.kind)
            .unwrap_or(Z_SAMPLE_KIND_PUT)
    })
}

/// Borrow the link this event is about (zenoh-c `z_link_event_link`).
///
/// # Safety
/// `event` must be null or a live loaned link event.
#[no_mangle]
pub unsafe extern "C" fn z_link_event_link(
    event: *const z_loaned_link_event_t,
) -> *const z_loaned_link_t {
    guard_val(std::ptr::null(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { link_event_state(event) } {
            Some(state) => &state.loaned as *const z_loaned_link_t,
            None => std::ptr::null(),
        }
    })
}

/// Mutably borrow the link this event is about (zenoh-c
/// `z_link_event_link_mut`).
///
/// # Safety
/// `event` must be null or a live loaned link event.
#[no_mangle]
pub unsafe extern "C" fn z_link_event_link_mut(
    event: *mut z_loaned_link_event_t,
) -> *mut z_loaned_link_t {
    guard_val(std::ptr::null_mut(), || {
        // SAFETY: the caller's contract, delegated.
        match unsafe { link_event_state(event) } {
            Some(state) => &state.loaned as *const z_loaned_link_t as *mut z_loaned_link_t,
            None => std::ptr::null_mut(),
        }
    })
}

/// Whether an owned link event holds a live value (zenoh-c
/// `z_internal_link_event_check`).
///
/// # Safety
/// `this_` must be null or a valid owned link event.
#[no_mangle]
pub unsafe extern "C" fn z_internal_link_event_check(this_: *const z_owned_link_event_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Gravestone an owned link event (zenoh-c `z_internal_link_event_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_link_event_null(this_: *mut z_owned_link_event_t) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *this_ = z_owned_link_event_t::null_value() };
        }
    });
}

// ---------------------------------------------------------------------------
// transport accessors
// ---------------------------------------------------------------------------

/// Borrow an owned transport (zenoh-c `z_transport_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned transport.
#[no_mangle]
pub unsafe extern "C" fn z_transport_loan(
    this_: *const z_owned_transport_t,
) -> *const z_loaned_transport_t {
    this_.cast()
}

/// Mutably borrow an owned transport (zenoh-c `z_transport_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned transport.
#[no_mangle]
pub unsafe extern "C" fn z_transport_loan_mut(
    this_: *mut z_owned_transport_t,
) -> *mut z_loaned_transport_t {
    this_.cast()
}

/// Copy a transport (zenoh-c `z_transport_clone`).
///
/// # Safety
/// `this_` must be writable; `transport` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_transport_clone(
    this_: *mut z_owned_transport_t,
    transport: *const z_loaned_transport_t,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *this_ = z_owned_transport_t::null_value() };
        if transport.is_null() {
            return;
        }
        // SAFETY: the caller's contract. A transport is nineteen POD bytes, so
        // the clone is a copy and there is nothing to deep-copy.
        let src = unsafe { &*transport };
        // SAFETY: as above.
        unsafe {
            *this_ = z_owned_transport_t {
                zid: src.zid,
                whatami: src.whatami,
                is_qos: src.is_qos,
                is_multicast: src.is_multicast,
                #[cfg(feature = "zenoh-c-shared-memory")]
                is_shm: src.is_shm,
            }
        };
    });
}

/// Free a transport (zenoh-c `z_transport_drop`).
///
/// A gravestone write and nothing else: the type owns no allocation — see
/// [`z_owned_transport_t`].
///
/// # Safety
/// `this_` must be null or a valid moved transport.
#[no_mangle]
pub unsafe extern "C" fn z_transport_drop(this_: *mut z_moved_transport_t) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe { (*this_)._this = z_owned_transport_t::null_value() };
        }
    });
}

/// Take a loaned transport into an owned one (zenoh-c
/// `z_transport_take_from_loaned`).
///
/// # Safety
/// `dst` must be writable; `src` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_transport_take_from_loaned(
    dst: *mut z_owned_transport_t,
    src: *mut z_loaned_transport_t,
) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe { *dst = z_owned_transport_t::null_value() };
        if src.is_null() {
            return;
        }
        // SAFETY: the caller's contract. The source is gravestoned so a caller
        // that takes twice gets one live value, which is the move semantics even
        // though nothing is freed.
        unsafe {
            *dst = z_owned_transport_t {
                zid: std::mem::take(&mut (*src).zid),
                whatami: (*src).whatami,
                is_qos: (*src).is_qos,
                is_multicast: (*src).is_multicast,
                #[cfg(feature = "zenoh-c-shared-memory")]
                is_shm: (*src).is_shm,
            }
        };
    });
}

/// This transport's peer zid (zenoh-c `z_transport_zid`).
///
/// # Safety
/// `transport` must be null or a valid loaned transport.
#[no_mangle]
pub unsafe extern "C" fn z_transport_zid(transport: *const z_loaned_transport_t) -> z_id_t {
    guard_val(z_id_t { id: [0u8; 16] }, || {
        if transport.is_null() {
            return z_id_t { id: [0u8; 16] };
        }
        // SAFETY: the caller's contract.
        z_id_t {
            id: unsafe { (*transport).zid },
        }
    })
}

/// This transport's peer role (zenoh-c `z_transport_whatami`).
///
/// # Safety
/// `transport` must be null or a valid loaned transport.
#[no_mangle]
pub unsafe extern "C" fn z_transport_whatami(
    transport: *const z_loaned_transport_t,
) -> z_whatami_t {
    guard_val(Z_WHATAMI_PEER, || {
        if transport.is_null() {
            return Z_WHATAMI_PEER;
        }
        // SAFETY: the caller's contract.
        z_whatami_t::from(unsafe { (*transport).whatami })
    })
}

/// Whether QoS was negotiated on this transport (zenoh-c `z_transport_is_qos`).
///
/// # Safety
/// `transport` must be null or a valid loaned transport.
#[no_mangle]
pub unsafe extern "C" fn z_transport_is_qos(transport: *const z_loaned_transport_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !transport.is_null() && unsafe { (*transport).is_qos } != 0
    })
}

/// Whether this is a multicast transport (zenoh-c `z_transport_is_multicast`).
///
/// # Safety
/// `transport` must be null or a valid loaned transport.
#[no_mangle]
pub unsafe extern "C" fn z_transport_is_multicast(transport: *const z_loaned_transport_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !transport.is_null() && unsafe { (*transport).is_multicast } != 0
    })
}

/// Whether an owned transport holds a live value (zenoh-c
/// `z_internal_transport_check`).
///
/// # Safety
/// `this_` must be null or a valid owned transport.
#[no_mangle]
pub unsafe extern "C" fn z_internal_transport_check(this_: *const z_owned_transport_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && unsafe { (*this_).is_live() }
    })
}

/// Gravestone an owned transport (zenoh-c `z_internal_transport_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_transport_null(this_: *mut z_owned_transport_t) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *this_ = z_owned_transport_t::null_value() };
        }
    });
}

/// Construct a transport value from its four scalars (zenoh-c
/// `zc_internal_create_transport`).
///
/// Upstream's own test door, and the only producer of a MULTICAST transport
/// value on this ABI — see [`FaceSnapshot::is_multicast`].
///
/// ⚠ NO-SHM ARM ONLY. Upstream's header says so in words — "This function is
/// only available when shared memory is NOT enabled" — and in a
/// `#if (defined(Z_FEATURE_UNSTABLE_API) && !defined(Z_FEATURE_SHARED_MEMORY))`.
/// The SHM arm gets [`zc_internal_create_transport_shm`] instead, which takes a
/// sixth argument.
///
/// # Safety
/// `this_` must be null or writable.
#[cfg(not(feature = "zenoh-c-shared-memory"))]
#[no_mangle]
pub unsafe extern "C" fn zc_internal_create_transport(
    this_: *mut z_owned_transport_t,
    zid: z_id_t,
    whatami: z_whatami_t,
    is_qos: bool,
    is_multicast: bool,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = z_owned_transport_t {
                zid: zid.id,
                // Truncating is safe by the enum's own domain: 1, 2 and 4 all
                // fit a byte. A caller passing something else round-trips
                // whatever fits, which is what upstream's `as u8` does too.
                whatami: whatami as u8,
                is_qos: u8::from(is_qos),
                is_multicast: u8::from(is_multicast),
            }
        };
    });
}

/// Construct a transport value on the SHM arm (zenoh-c
/// `zc_internal_create_transport_shm`).
///
/// The `zc_internal_create_transport` twin, with the sixth argument the
/// twentieth byte needs. See [`z_owned_transport_t`] for why the type differs by
/// arm at all.
///
/// # Safety
/// `this_` must be null or writable.
#[cfg(feature = "zenoh-c-shared-memory")]
#[no_mangle]
pub unsafe extern "C" fn zc_internal_create_transport_shm(
    this_: *mut z_owned_transport_t,
    zid: z_id_t,
    whatami: z_whatami_t,
    is_qos: bool,
    is_multicast: bool,
    is_shm: bool,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *this_ = z_owned_transport_t {
                zid: zid.id,
                whatami: whatami as u8,
                is_qos: u8::from(is_qos),
                is_multicast: u8::from(is_multicast),
                is_shm: u8::from(is_shm),
            }
        };
    });
}

/// Whether SHM was negotiated on this transport (zenoh-c `z_transport_is_shm`).
///
/// SHM arm only, like the byte it reads.
///
/// # Safety
/// `transport` must be null or a valid loaned transport.
#[cfg(feature = "zenoh-c-shared-memory")]
#[no_mangle]
pub unsafe extern "C" fn z_transport_is_shm(transport: *const z_loaned_transport_t) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !transport.is_null() && unsafe { (*transport).is_shm } != 0
    })
}

// ---------------------------------------------------------------------------
// transport event
// ---------------------------------------------------------------------------

/// Borrow an owned transport event (zenoh-c `z_transport_event_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned transport event.
#[no_mangle]
pub unsafe extern "C" fn z_transport_event_loan(
    this_: *const z_owned_transport_event_t,
) -> *const z_loaned_transport_event_t {
    this_.cast()
}

/// Mutably borrow an owned transport event (zenoh-c
/// `z_transport_event_loan_mut`).
///
/// # Safety
/// `this_` must be null or a valid owned transport event.
#[no_mangle]
pub unsafe extern "C" fn z_transport_event_loan_mut(
    this_: *mut z_owned_transport_event_t,
) -> *mut z_loaned_transport_event_t {
    this_.cast()
}

/// Free a transport event (zenoh-c `z_transport_event_drop`).
///
/// A gravestone write: like the transport inside it, the type owns nothing.
///
/// # Safety
/// `this_` must be null or a valid moved transport event.
#[no_mangle]
pub unsafe extern "C" fn z_transport_event_drop(this_: *mut z_moved_transport_event_t) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe {
                (*this_)._this = z_owned_transport_event_t {
                    transport: z_owned_transport_t::null_value(),
                    kind: 0,
                }
            };
        }
    });
}

/// Take a loaned transport event into an owned one (zenoh-c
/// `z_transport_event_take_from_loaned`).
///
/// # Safety
/// `dst` must be writable; `src` must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_transport_event_take_from_loaned(
    dst: *mut z_owned_transport_event_t,
    src: *mut z_loaned_transport_event_t,
) {
    guard_val((), || {
        if dst.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        unsafe {
            *dst = z_owned_transport_event_t {
                transport: z_owned_transport_t::null_value(),
                kind: 0,
            }
        };
        if src.is_null() {
            return;
        }
        // SAFETY: the caller's contract; the source is gravestoned.
        unsafe {
            *dst = z_owned_transport_event_t {
                transport: z_owned_transport_t {
                    zid: std::mem::take(&mut (*src).transport.zid),
                    whatami: (*src).transport.whatami,
                    is_qos: (*src).transport.is_qos,
                    is_multicast: (*src).transport.is_multicast,
                    #[cfg(feature = "zenoh-c-shared-memory")]
                    is_shm: (*src).transport.is_shm,
                },
                kind: (*src).kind,
            }
        };
    });
}

/// Which way the transport moved (zenoh-c `z_transport_event_kind`).
///
/// # Safety
/// `event` must be null or a valid loaned transport event.
#[no_mangle]
pub unsafe extern "C" fn z_transport_event_kind(
    event: *const z_loaned_transport_event_t,
) -> z_sample_kind_t {
    guard_val(Z_SAMPLE_KIND_PUT, || {
        if event.is_null() {
            return Z_SAMPLE_KIND_PUT;
        }
        // SAFETY: the caller's contract.
        z_sample_kind_t::from(unsafe { (*event).kind })
    })
}

/// Borrow the transport this event is about (zenoh-c
/// `z_transport_event_transport`).
///
/// # Safety
/// `event` must be null or a valid loaned transport event.
#[no_mangle]
pub unsafe extern "C" fn z_transport_event_transport(
    event: *const z_loaned_transport_event_t,
) -> *const z_loaned_transport_t {
    guard_val(std::ptr::null(), || {
        if event.is_null() {
            return std::ptr::null();
        }
        // SAFETY: the caller's contract. Owned and loaned transports share a
        // layout, so this is a field borrow rather than a reinterpretation.
        unsafe { std::ptr::addr_of!((*event).transport) }.cast()
    })
}

/// Mutably borrow the transport this event is about (zenoh-c
/// `z_transport_event_transport_mut`).
///
/// # Safety
/// `event` must be null or a valid loaned transport event.
#[no_mangle]
pub unsafe extern "C" fn z_transport_event_transport_mut(
    event: *mut z_loaned_transport_event_t,
) -> *mut z_loaned_transport_t {
    guard_val(std::ptr::null_mut(), || {
        if event.is_null() {
            return std::ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { std::ptr::addr_of_mut!((*event).transport) }.cast()
    })
}

/// Whether an owned transport event holds a live value (zenoh-c
/// `z_internal_transport_event_check`).
///
/// # Safety
/// `this_` must be null or a valid owned transport event.
#[no_mangle]
pub unsafe extern "C" fn z_internal_transport_event_check(
    this_: *const z_owned_transport_event_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && unsafe { (*this_).transport.is_live() }
    })
}

/// Gravestone an owned transport event (zenoh-c
/// `z_internal_transport_event_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_transport_event_null(this_: *mut z_owned_transport_event_t) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe {
                *this_ = z_owned_transport_event_t {
                    transport: z_owned_transport_t::null_value(),
                    kind: 0,
                }
            };
        }
    });
}

// ---------------------------------------------------------------------------
// the four closure families' verbs
// ---------------------------------------------------------------------------

/// Emit the seven verbs a closure family carries.
macro_rules! closure_verbs {
    (
        $Owned:ident, $Loaned:ident, $Moved:ident, $Callback:ty,
        $ctor:ident, $call:ident, $drop:ident, $loan:ident,
        $check:ident, $null:ident
        $(, $loan_mut:ident)?
    ) => {
        /// Construct this closure from its parts (zenoh-c `
        #[doc = stringify!($ctor)]
        /// `).
        ///
        /// # Safety
        /// `this_` must be writable; the two callbacks must be null or valid C
        /// function pointers, and `context` whatever they were written for.
        #[no_mangle]
        pub unsafe extern "C" fn $ctor(
            this_: *mut $Owned,
            call: $Callback,
            drop: z_closure_drop_callback_t,
            context: *mut c_void,
        ) {
            guard_val((), || {
                if this_.is_null() {
                    return;
                }
                // SAFETY: the caller's contract.
                unsafe {
                    *this_ = $Owned {
                        context,
                        call,
                        drop,
                    }
                };
            });
        }

        /// Free this closure, running its C `drop(context)` (zenoh-c `
        #[doc = stringify!($drop)]
        /// `).
        ///
        /// # Safety
        /// `closure_` must be null or a valid moved closure.
        #[no_mangle]
        pub unsafe extern "C" fn $drop(closure_: *mut $Moved) {
            guard_val((), || {
                if closure_.is_null() {
                    return;
                }
                // SAFETY: the caller's contract. `run_drop` gravestones before
                // it calls, so a second drop is a no-op.
                unsafe { (*closure_)._this.run_drop() };
            });
        }

        /// Borrow this closure (zenoh-c `
        #[doc = stringify!($loan)]
        /// `).
        ///
        /// # Safety
        /// `closure` must be null or a valid owned closure.
        #[no_mangle]
        pub unsafe extern "C" fn $loan(closure: *const $Owned) -> *const $Loaned {
            closure.cast()
        }

        $(
            /// Mutably borrow this closure (zenoh-c `
            #[doc = stringify!($loan_mut)]
            /// `).
            ///
            /// # Safety
            /// `closure` must be null or a valid owned closure.
            #[no_mangle]
            pub unsafe extern "C" fn $loan_mut(closure: *mut $Owned) -> *mut $Loaned {
                closure.cast()
            }
        )?

        /// Whether this closure holds a callback (zenoh-c `
        #[doc = stringify!($check)]
        /// `).
        ///
        /// # Safety
        /// `this_` must be null or a valid owned closure.
        #[no_mangle]
        pub unsafe extern "C" fn $check(this_: *const $Owned) -> bool {
            guard_val(false, || {
                // SAFETY: the caller's contract.
                !this_.is_null() && unsafe { (*this_).call }.is_some()
            })
        }

        /// Gravestone this closure (zenoh-c `
        #[doc = stringify!($null)]
        /// `).
        ///
        /// # Safety
        /// `this_` must be null or writable.
        #[no_mangle]
        pub unsafe extern "C" fn $null(this_: *mut $Owned) {
            guard_val((), || {
                if !this_.is_null() {
                    // SAFETY: the caller's contract.
                    unsafe { *this_ = $Owned::null_value() };
                }
            });
        }

        // The `_call` verb is written per family rather than generated: each one
        // takes a different loaned argument, and threading that through the
        // macro would buy nothing over four four-line functions.
        const _: () = {
            assert!(std::mem::size_of::<$Loaned>() == std::mem::size_of::<$Owned>());
        };
    };
}

closure_verbs!(
    z_owned_closure_link_t,
    z_loaned_closure_link_t,
    z_moved_closure_link_t,
    z_closure_link_callback_t,
    z_closure_link,
    z_closure_link_call,
    z_closure_link_drop,
    z_closure_link_loan,
    z_internal_closure_link_check,
    z_internal_closure_link_null,
    z_closure_link_loan_mut
);
closure_verbs!(
    z_owned_closure_link_event_t,
    z_loaned_closure_link_event_t,
    z_moved_closure_link_event_t,
    z_closure_link_event_callback_t,
    z_closure_link_event,
    z_closure_link_event_call,
    z_closure_link_event_drop,
    z_closure_link_event_loan,
    z_internal_closure_link_event_check,
    z_internal_closure_link_event_null
);
closure_verbs!(
    z_owned_closure_transport_t,
    z_loaned_closure_transport_t,
    z_moved_closure_transport_t,
    z_closure_transport_callback_t,
    z_closure_transport,
    z_closure_transport_call,
    z_closure_transport_drop,
    z_closure_transport_loan,
    z_internal_closure_transport_check,
    z_internal_closure_transport_null,
    z_closure_transport_loan_mut
);
closure_verbs!(
    z_owned_closure_transport_event_t,
    z_loaned_closure_transport_event_t,
    z_moved_closure_transport_event_t,
    z_closure_transport_event_callback_t,
    z_closure_transport_event,
    z_closure_transport_event_call,
    z_closure_transport_event_drop,
    z_closure_transport_event_loan,
    z_internal_closure_transport_event_check,
    z_internal_closure_transport_event_null
);

/// Invoke a link closure (zenoh-c `z_closure_link_call`).
///
/// # Safety
/// `closure` must be null or a valid loaned closure; `link` whatever its call
/// was written to accept.
#[no_mangle]
pub unsafe extern "C" fn z_closure_link_call(
    closure: *const z_loaned_closure_link_t,
    link: *mut z_loaned_link_t,
) {
    guard_val((), || {
        if closure.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let held = unsafe { &*closure };
        if let Some(call) = held.call {
            // SAFETY: the C side installed `call` for `context`.
            unsafe { call(link, held.context) };
        }
    });
}

/// Invoke a link-event closure (zenoh-c `z_closure_link_event_call`).
///
/// # Safety
/// As [`z_closure_link_call`].
#[no_mangle]
pub unsafe extern "C" fn z_closure_link_event_call(
    closure: *const z_loaned_closure_link_event_t,
    event: *mut z_loaned_link_event_t,
) {
    guard_val((), || {
        if closure.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let held = unsafe { &*closure };
        if let Some(call) = held.call {
            // SAFETY: as above.
            unsafe { call(event, held.context) };
        }
    });
}

/// Invoke a transport closure (zenoh-c `z_closure_transport_call`).
///
/// # Safety
/// As [`z_closure_link_call`].
#[no_mangle]
pub unsafe extern "C" fn z_closure_transport_call(
    closure: *const z_loaned_closure_transport_t,
    transport: *mut z_loaned_transport_t,
) {
    guard_val((), || {
        if closure.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let held = unsafe { &*closure };
        if let Some(call) = held.call {
            // SAFETY: as above.
            unsafe { call(transport, held.context) };
        }
    });
}

/// Invoke a transport-event closure (zenoh-c `z_closure_transport_event_call`).
///
/// # Safety
/// As [`z_closure_link_call`].
#[no_mangle]
pub unsafe extern "C" fn z_closure_transport_event_call(
    closure: *const z_loaned_closure_transport_event_t,
    event: *mut z_loaned_transport_event_t,
) {
    guard_val((), || {
        if closure.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let held = unsafe { &*closure };
        if let Some(call) = held.call {
            // SAFETY: as above.
            unsafe { call(event, held.context) };
        }
    });
}

// ---------------------------------------------------------------------------
// listeners
// ---------------------------------------------------------------------------

/// Build the loaned link event a C callback is handed, run it, and free it.
///
/// The event is built on this stack frame and torn down before returning, which
/// is upstream's borrow contract: a callback that wants the link past its return
/// calls `z_link_clone` or `z_link_event_take_from_loaned`, and one that does
/// not costs nothing.
fn deliver_link_event(
    closure: &EventClosure<z_owned_closure_link_event_t>,
    kind: FaceEventKind,
    snapshot: &FaceSnapshot,
) {
    let Ok(held) = closure.closure.lock() else {
        return;
    };
    let Some(call) = held.call else {
        return;
    };
    for link in &snapshot.links {
        let state = LinkEventState {
            loaned: z_loaned_link_t::from_handle(Box::into_raw(Box::new(LinkState::from_snapshot(
                link,
                snapshot.zid,
            ))) as Handle),
            kind: kind_of(kind),
        };
        let mut event = z_owned_link_event_t::from_handle(Box::into_raw(Box::new(state)) as Handle);
        // SAFETY: `event` is a live owned event this frame built; the C side
        // installed `call` for `context`.
        unsafe {
            call(
                (&mut event as *mut z_owned_link_event_t).cast(),
                held.context,
            )
        };
        let mut moved = z_moved_link_event_t { _this: event };
        // SAFETY: dropped exactly once — nothing else holds this handle.
        unsafe { z_link_event_drop(&mut moved) };
    }
}

/// Build the loaned transport event a C callback is handed, run it, and free it.
fn deliver_transport_event(
    closure: &EventClosure<z_owned_closure_transport_event_t>,
    kind: FaceEventKind,
    snapshot: &FaceSnapshot,
) {
    let Ok(held) = closure.closure.lock() else {
        return;
    };
    let Some(call) = held.call else {
        return;
    };
    let mut event = z_owned_transport_event_t {
        transport: z_owned_transport_t::from_snapshot(snapshot),
        // The kind is a byte here because the type is nineteen-plus-one bytes
        // wide; the accessor widens it to the `int` upstream returns.
        kind: kind_of(kind) as u8,
    };
    // SAFETY: `event` is a live owned event this frame built.
    unsafe {
        call(
            (&mut event as *mut z_owned_transport_event_t).cast(),
            held.context,
        )
    };
}

/// The sample kind a face transition reports as.
#[inline]
fn kind_of(kind: FaceEventKind) -> z_sample_kind_t {
    match kind {
        FaceEventKind::Up => Z_SAMPLE_KIND_PUT,
        FaceEventKind::Down => Z_SAMPLE_KIND_DELETE,
    }
}

/// Whether a snapshot passes a zid filter.
#[inline]
fn passes(filter: Option<[u8; 16]>, snapshot: &FaceSnapshot) -> bool {
    // `Option::is_none_or` would read better and is stable since 1.82; this
    // workspace's MSRV is 1.81, and clippy's `incompatible_msrv` is right to
    // refuse it.
    #[allow(clippy::unnecessary_map_or)]
    filter.map_or(true, |zid| zid == snapshot.zid)
}

/// Default link-events listener options (zenoh-c
/// `z_link_events_listener_options_default`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_link_events_listener_options_default(
    this_: *mut z_link_events_listener_options_t,
) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe {
                *this_ = z_link_events_listener_options_t {
                    history: false,
                    transport: std::ptr::null_mut(),
                }
            };
        }
    });
}

/// Default transport-events listener options (zenoh-c
/// `z_transport_events_listener_options_default`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_transport_events_listener_options_default(
    this_: *mut z_transport_events_listener_options_t,
) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *this_ = z_transport_events_listener_options_t { history: false } };
        }
    });
}

/// Default `z_info_links` options (zenoh-c `z_info_links_options_default`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_info_links_options_default(this_: *mut z_info_links_options_t) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe {
                *this_ = z_info_links_options_t {
                    transport: std::ptr::null_mut(),
                }
            };
        }
    });
}

/// Install a link-events listener, shared by the owned and background forms.
///
/// # Safety
/// As the two public wrappers.
unsafe fn declare_link_listener(
    session: *const z_loaned_session_t,
    callback: *mut z_moved_closure_link_event_t,
    options: *mut z_link_events_listener_options_t,
) -> Result<Handle, ZResult> {
    if callback.is_null() {
        return Err(Z_ENULL);
    }
    // The callback is TAKEN whatever happens next: upstream's `z_moved_*`
    // contract is that the callee owns it, and a failure path that left it
    // behind would leak the C context on every rejected declare.
    // SAFETY: the caller's contract.
    let taken = unsafe { (*callback)._this.take() };
    let Some(state) = (unsafe { session_state(session) }) else {
        let mut held = taken;
        held.run_drop();
        return Err(Z_ENULL);
    };
    let (history, filter) = if options.is_null() {
        (false, None)
    } else {
        // SAFETY: the caller's contract.
        let opts = unsafe { &mut *options };
        // Taking the filter gravestones it, honouring the "ownership is taken"
        // upstream documents on the field.
        (opts.history, unsafe {
            take_transport_filter(opts.transport)
        })
    };
    let closure = Arc::new(EventClosure {
        closure: std::sync::Mutex::new(taken),
    });
    let shared = state.shared.clone();
    if history {
        for snapshot in shared.face_snapshots() {
            if passes(filter, &snapshot) {
                deliver_link_event(&closure, FaceEventKind::Up, &snapshot);
            }
        }
    }
    let sink = closure.clone();
    let watcher = shared.watch_faces(Arc::new(move |kind, snapshot: &FaceSnapshot| {
        if passes(filter, snapshot) {
            deliver_link_event(&sink, kind, snapshot);
        }
    }));
    Ok(Box::into_raw(Box::new(ListenerState { shared, watcher })) as Handle)
}

/// Declare a link-events listener (zenoh-c `z_declare_link_events_listener`).
///
/// # Safety
/// `session` must be null or a live loaned session; `listener` writable;
/// `callback` a valid moved closure; `options` null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_declare_link_events_listener(
    session: *const z_loaned_session_t,
    listener: *mut z_owned_link_events_listener_t,
    callback: *mut z_moved_closure_link_event_t,
    options: *mut z_link_events_listener_options_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *listener = z_owned_link_events_listener_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        match unsafe { declare_link_listener(session, callback, options) } {
            Ok(handle) => {
                // SAFETY: the caller's contract.
                unsafe { *listener = z_owned_link_events_listener_t::from_handle(handle) };
                Z_OK
            }
            Err(rc) => rc,
        }
    })
}

/// Declare a link-events listener with no handle (zenoh-c
/// `z_declare_background_link_events_listener`).
///
/// The listener lives as long as the session: the `ListenerState` is LEAKED
/// deliberately, which is what "background" means here. There is no handle to
/// undeclare it with, so nothing else could end it.
///
/// # Safety
/// As [`z_declare_link_events_listener`].
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_link_events_listener(
    session: *const z_loaned_session_t,
    callback: *mut z_moved_closure_link_event_t,
    options: *mut z_link_events_listener_options_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        match unsafe { declare_link_listener(session, callback, options) } {
            Ok(handle) => {
                // The `Box<ListenerState>` behind it stays leaked, which is what
                // "background" means: `ListenerState::drop` is the only thing
                // that unwatches, and no handle exists to reach it.
                let _ = handle;
                Z_OK
            }
            Err(rc) => rc,
        }
    })
}

/// Install a transport-events listener, shared by the owned and background
/// forms.
///
/// # Safety
/// As the two public wrappers.
unsafe fn declare_transport_listener(
    session: *const z_loaned_session_t,
    callback: *mut z_moved_closure_transport_event_t,
    options: *const z_transport_events_listener_options_t,
) -> Result<Handle, ZResult> {
    if callback.is_null() {
        return Err(Z_ENULL);
    }
    // SAFETY: the caller's contract — taken unconditionally, as above.
    let taken = unsafe { (*callback)._this.take() };
    let Some(state) = (unsafe { session_state(session) }) else {
        let mut held = taken;
        held.run_drop();
        return Err(Z_ENULL);
    };
    // SAFETY: the caller's contract.
    let history = !options.is_null() && unsafe { (*options).history };
    let closure = Arc::new(EventClosure {
        closure: std::sync::Mutex::new(taken),
    });
    let shared = state.shared.clone();
    if history {
        for snapshot in shared.face_snapshots() {
            deliver_transport_event(&closure, FaceEventKind::Up, &snapshot);
        }
    }
    let sink = closure.clone();
    let watcher = shared.watch_faces(Arc::new(move |kind, snapshot: &FaceSnapshot| {
        deliver_transport_event(&sink, kind, snapshot);
    }));
    Ok(Box::into_raw(Box::new(ListenerState { shared, watcher })) as Handle)
}

/// Declare a transport-events listener (zenoh-c
/// `z_declare_transport_events_listener`).
///
/// # Safety
/// As [`z_declare_link_events_listener`].
#[no_mangle]
pub unsafe extern "C" fn z_declare_transport_events_listener(
    session: *const z_loaned_session_t,
    listener: *mut z_owned_transport_events_listener_t,
    callback: *mut z_moved_closure_transport_event_t,
    options: *const z_transport_events_listener_options_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        unsafe { *listener = z_owned_transport_events_listener_t::null_value() };
        // SAFETY: the caller's contract, delegated.
        match unsafe { declare_transport_listener(session, callback, options) } {
            Ok(handle) => {
                // SAFETY: the caller's contract.
                unsafe { *listener = z_owned_transport_events_listener_t::from_handle(handle) };
                Z_OK
            }
            Err(rc) => rc,
        }
    })
}

/// Declare a transport-events listener with no handle (zenoh-c
/// `z_declare_background_transport_events_listener`).
///
/// # Safety
/// As [`z_declare_background_link_events_listener`].
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_transport_events_listener(
    session: *const z_loaned_session_t,
    callback: *mut z_moved_closure_transport_event_t,
    options: *const z_transport_events_listener_options_t,
) -> ZResult {
    guarded(|| {
        // SAFETY: the caller's contract, delegated.
        match unsafe { declare_transport_listener(session, callback, options) } {
            Ok(handle) => {
                // The `Box<ListenerState>` behind it stays leaked, which is what
                // "background" means: `ListenerState::drop` is the only thing
                // that unwatches, and no handle exists to reach it.
                let _ = handle;
                Z_OK
            }
            Err(rc) => rc,
        }
    })
}

/// Borrow a link-events listener (zenoh-c `z_link_events_listener_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned listener.
#[no_mangle]
pub unsafe extern "C" fn z_link_events_listener_loan(
    this_: *const z_owned_link_events_listener_t,
) -> *const z_loaned_link_events_listener_t {
    this_.cast()
}

/// Borrow a transport-events listener (zenoh-c
/// `z_transport_events_listener_loan`).
///
/// # Safety
/// `this_` must be null or a valid owned listener.
#[no_mangle]
pub unsafe extern "C" fn z_transport_events_listener_loan(
    this_: *const z_owned_transport_events_listener_t,
) -> *const z_loaned_transport_events_listener_t {
    this_.cast()
}

/// Free a listener handle, undeclaring it.
///
/// # Safety
/// `handle` must be null or a live `Box<ListenerState>`.
#[inline]
unsafe fn drop_listener(handle: Handle) {
    if !handle.is_null() {
        // SAFETY: the caller's contract. `ListenerState::drop` unwatches.
        drop(unsafe { Box::from_raw(handle as *mut ListenerState) });
    }
}

/// Free a link-events listener (zenoh-c `z_link_events_listener_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved listener.
#[no_mangle]
pub unsafe extern "C" fn z_link_events_listener_drop(this_: *mut z_moved_link_events_listener_t) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let taken = unsafe {
            std::mem::replace(
                &mut (*this_)._this,
                z_owned_link_events_listener_t::null_value(),
            )
        };
        // SAFETY: as above.
        unsafe { drop_listener(taken.handle) };
    });
}

/// Free a transport-events listener (zenoh-c
/// `z_transport_events_listener_drop`).
///
/// # Safety
/// `this_` must be null or a valid moved listener.
#[no_mangle]
pub unsafe extern "C" fn z_transport_events_listener_drop(
    this_: *mut z_moved_transport_events_listener_t,
) {
    guard_val((), || {
        if this_.is_null() {
            return;
        }
        // SAFETY: the caller's contract.
        let taken = unsafe {
            std::mem::replace(
                &mut (*this_)._this,
                z_owned_transport_events_listener_t::null_value(),
            )
        };
        // SAFETY: as above.
        unsafe { drop_listener(taken.handle) };
    });
}

/// Undeclare a link-events listener (zenoh-c
/// `z_undeclare_link_events_listener`).
///
/// # Safety
/// `this_` must be null or a valid moved listener.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_link_events_listener(
    this_: *mut z_moved_link_events_listener_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let taken = unsafe {
            std::mem::replace(
                &mut (*this_)._this,
                z_owned_link_events_listener_t::null_value(),
            )
        };
        if taken.handle.is_null() {
            // An already-undeclared listener is not a live one, and saying so is
            // what lets a C program tell a double-undeclare from a first.
            return Z_EINVAL;
        }
        // SAFETY: as above.
        unsafe { drop_listener(taken.handle) };
        Z_OK
    })
}

/// Undeclare a transport-events listener (zenoh-c
/// `z_undeclare_transport_events_listener`).
///
/// # Safety
/// `this_` must be null or a valid moved listener.
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_transport_events_listener(
    this_: *mut z_moved_transport_events_listener_t,
) -> ZResult {
    guarded(|| {
        if this_.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let taken = unsafe {
            std::mem::replace(
                &mut (*this_)._this,
                z_owned_transport_events_listener_t::null_value(),
            )
        };
        if taken.handle.is_null() {
            return Z_EINVAL;
        }
        // SAFETY: as above.
        unsafe { drop_listener(taken.handle) };
        Z_OK
    })
}

/// Whether an owned link-events listener is live (zenoh-c
/// `z_internal_link_events_listener_check`).
///
/// # Safety
/// `this_` must be null or a valid owned listener.
#[no_mangle]
pub unsafe extern "C" fn z_internal_link_events_listener_check(
    this_: *const z_owned_link_events_listener_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Gravestone an owned link-events listener (zenoh-c
/// `z_internal_link_events_listener_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_link_events_listener_null(
    this_: *mut z_owned_link_events_listener_t,
) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *this_ = z_owned_link_events_listener_t::null_value() };
        }
    });
}

/// Whether an owned transport-events listener is live (zenoh-c
/// `z_internal_transport_events_listener_check`).
///
/// # Safety
/// `this_` must be null or a valid owned listener.
#[no_mangle]
pub unsafe extern "C" fn z_internal_transport_events_listener_check(
    this_: *const z_owned_transport_events_listener_t,
) -> bool {
    guard_val(false, || {
        // SAFETY: the caller's contract.
        !this_.is_null() && !unsafe { (*this_).handle }.is_null()
    })
}

/// Gravestone an owned transport-events listener (zenoh-c
/// `z_internal_transport_events_listener_null`).
///
/// # Safety
/// `this_` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn z_internal_transport_events_listener_null(
    this_: *mut z_owned_transport_events_listener_t,
) {
    guard_val((), || {
        if !this_.is_null() {
            // SAFETY: the caller's contract.
            unsafe { *this_ = z_owned_transport_events_listener_t::null_value() };
        }
    });
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

/// Enumerate this session's links (zenoh-c `z_info_links`).
///
/// The callback is TAKEN and dropped before returning — upstream's `z_moved_*`
/// contract — so a C program's `drop(context)` runs on the way out of this call
/// rather than at some later, unnamed moment.
///
/// # Safety
/// `session` must be null or live; `callback` a valid moved closure; `options`
/// null or valid.
#[no_mangle]
pub unsafe extern "C" fn z_info_links(
    session: *const z_loaned_session_t,
    callback: *mut z_moved_closure_link_t,
    options: *mut z_info_links_options_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let mut held = unsafe { (*callback)._this.take() };
        let filter = if options.is_null() {
            None
        } else {
            // SAFETY: the caller's contract.
            unsafe { take_transport_filter((*options).transport) }
        };
        let rc = match unsafe { session_state(session) } {
            Some(state) => {
                if let Some(call) = held.call {
                    for snapshot in state.shared.face_snapshots() {
                        if !passes(filter, &snapshot) {
                            continue;
                        }
                        for link in &snapshot.links {
                            let mut owned =
                                owned_link(LinkState::from_snapshot(link, snapshot.zid));
                            // SAFETY: a live owned link this frame built.
                            unsafe {
                                call((&mut owned as *mut z_owned_link_t).cast(), held.context)
                            };
                            let mut moved = z_moved_link_t { _this: owned };
                            // SAFETY: dropped exactly once.
                            unsafe { z_link_drop(&mut moved) };
                        }
                    }
                }
                Z_OK
            }
            None => Z_ENULL,
        };
        held.run_drop();
        rc
    })
}

/// Enumerate this session's transports (zenoh-c `z_info_transports`).
///
/// # Safety
/// `session` must be null or live; `callback` a valid moved closure.
#[no_mangle]
pub unsafe extern "C" fn z_info_transports(
    session: *const z_loaned_session_t,
    callback: *mut z_moved_closure_transport_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ENULL;
        }
        // SAFETY: the caller's contract.
        let mut held = unsafe { (*callback)._this.take() };
        let rc = match unsafe { session_state(session) } {
            Some(state) => {
                if let Some(call) = held.call {
                    for snapshot in state.shared.face_snapshots() {
                        let mut owned = z_owned_transport_t::from_snapshot(&snapshot);
                        // SAFETY: a live owned transport this frame built.
                        unsafe {
                            call(
                                (&mut owned as *mut z_owned_transport_t).cast(),
                                held.context,
                            )
                        };
                    }
                }
                Z_OK
            }
            None => Z_ENULL,
        };
        held.run_drop();
        rc
    })
}

// Keep the two imports the string path needs visible to the compiler even when
// no arm below happens to name them directly.
const _: () = {
    let _ = std::mem::size_of::<z_moved_string_t>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A transport built through upstream's own constructor reads back through
    /// every accessor, INCLUDING the two booleans a session never sets.
    ///
    /// `is_multicast` is the one worth a test on its own: `FaceSnapshot` always
    /// reports `false` for it, so this constructor is the ONLY producer of a
    /// multicast transport value on this ABI, and an accessor that ignored the
    /// field would pass every face-derived check.
    #[test]
    fn a_constructed_transport_reads_back_through_every_accessor() {
        let mut owned = z_owned_transport_t::null_value();
        assert!(!unsafe { z_internal_transport_check(&owned) });

        let zid = z_id_t { id: [7u8; 16] };
        #[cfg(not(feature = "zenoh-c-shared-memory"))]
        unsafe {
            zc_internal_create_transport(&mut owned, zid, Z_WHATAMI_ROUTER, true, true)
        };
        #[cfg(feature = "zenoh-c-shared-memory")]
        unsafe {
            zc_internal_create_transport_shm(&mut owned, zid, Z_WHATAMI_ROUTER, true, true, true)
        };

        assert!(unsafe { z_internal_transport_check(&owned) });
        let loaned = unsafe { z_transport_loan(&owned) };
        assert_eq!(unsafe { z_transport_zid(loaned) }.id, [7u8; 16]);
        assert_eq!(unsafe { z_transport_whatami(loaned) }, Z_WHATAMI_ROUTER);
        assert!(unsafe { z_transport_is_qos(loaned) });
        assert!(unsafe { z_transport_is_multicast(loaned) });
        #[cfg(feature = "zenoh-c-shared-memory")]
        assert!(unsafe { z_transport_is_shm(loaned) });

        // A clone copies the value; the ORIGINAL is untouched, which is what
        // makes `z_info_transports` able to hand the same transport to a
        // callback that clones and one that does not.
        let mut copy = z_owned_transport_t::null_value();
        unsafe { z_transport_clone(&mut copy, loaned) };
        assert_eq!(
            unsafe { z_transport_zid(z_transport_loan(&copy)) }.id,
            [7u8; 16]
        );
        assert!(unsafe { z_internal_transport_check(&owned) });

        let mut moved = z_moved_transport_t { _this: owned };
        unsafe { z_transport_drop(&mut moved) };
        assert!(!unsafe { z_internal_transport_check(&moved._this) });
    }

    /// `z_transport_take_from_loaned` MOVES: the source is gravestoned, so a
    /// caller that takes twice gets one live value.
    ///
    /// Nothing is freed here — a transport owns no allocation — which is exactly
    /// why the move has to be observable some other way. If it were not, "take"
    /// and "clone" would be the same function under two names.
    #[test]
    fn taking_a_transport_gravestones_the_source() {
        let mut owned = z_owned_transport_t::null_value();
        let zid = z_id_t { id: [3u8; 16] };
        #[cfg(not(feature = "zenoh-c-shared-memory"))]
        unsafe {
            zc_internal_create_transport(&mut owned, zid, Z_WHATAMI_PEER, false, false)
        };
        #[cfg(feature = "zenoh-c-shared-memory")]
        unsafe {
            zc_internal_create_transport_shm(&mut owned, zid, Z_WHATAMI_PEER, false, false, false)
        };

        let loaned = unsafe { z_transport_loan_mut(&mut owned) };
        let mut first = z_owned_transport_t::null_value();
        unsafe { z_transport_take_from_loaned(&mut first, loaned) };
        assert!(unsafe { z_internal_transport_check(&first) });

        let mut second = z_owned_transport_t::null_value();
        unsafe { z_transport_take_from_loaned(&mut second, loaned) };
        assert!(
            !unsafe { z_internal_transport_check(&second) },
            "the second take must find a gravestone, not a second live transport"
        );
    }

    /// A link built from a snapshot answers every accessor, and a CLONE outlives
    /// the original.
    ///
    /// The clone half is the load-bearing one: upstream hands a link to a
    /// callback as a borrow, and a C program that wants it afterwards clones.
    /// If the clone shared the original's box, dropping either would leave the
    /// other dangling.
    #[test]
    fn a_link_answers_its_accessors_and_survives_its_original() {
        use wz_capi_core::faces::LinkSnapshot;
        let snapshot = LinkSnapshot {
            src: "tcp/127.0.0.1:7447".to_owned(),
            dst: "tcp/127.0.0.1:35000".to_owned(),
            protocol: Some(
                wz_runtime_tokio::session_glue::InterceptorLink::from_config_str("udp").unwrap(),
            ),
            interfaces: Some(vec!["lo".to_owned()]),
            mtu: 65535,
        };
        let owned = owned_link(LinkState::from_snapshot(&snapshot, [9u8; 16]));
        assert!(unsafe { z_internal_link_check(&owned) });

        let mut clone = z_owned_link_t::null_value();
        unsafe { z_link_clone(&mut clone, z_link_loan(&owned)) };

        // Drop the ORIGINAL, then read the clone. A shared box would be a
        // use-after-free here rather than a wrong answer.
        let mut moved = z_moved_link_t { _this: owned };
        unsafe { z_link_drop(&mut moved) };
        assert!(!unsafe { z_internal_link_check(&moved._this) });

        let loaned = unsafe { z_link_loan(&clone) };
        assert_eq!(unsafe { z_link_mtu(loaned) }, 65535);
        assert_eq!(unsafe { z_link_zid(loaned) }.id, [9u8; 16]);
        // `udp` is one of the two datagram schemes, so BOTH derived answers are
        // the non-default ones — a stub that returned `false`/`RELIABLE` would
        // pass a tcp fixture and fail this one.
        assert!(!unsafe { z_link_is_streamed(loaned) });
        let mut reliability = 0;
        assert!(unsafe { z_link_reliability(loaned, &mut reliability) });
        assert_eq!(reliability, Z_RELIABILITY_BEST_EFFORT);
        // And the honest absence, which upstream's `bool` return is what makes
        // expressible.
        let (mut min, mut max) = (0u8, 0u8);
        assert!(!unsafe { z_link_priorities(loaned, &mut min, &mut max) });

        let mut moved = z_moved_link_t { _this: clone };
        unsafe { z_link_drop(&mut moved) };
    }

    /// A link event lends the link it is about, and freeing the event frees that
    /// link with it.
    #[test]
    fn a_link_event_lends_its_link() {
        use wz_capi_core::faces::LinkSnapshot;
        let snapshot = LinkSnapshot {
            src: "tcp/a".to_owned(),
            dst: "tcp/b".to_owned(),
            protocol: None,
            interfaces: None,
            mtu: 1024,
        };
        let state = LinkEventState {
            loaned: z_loaned_link_t::from_handle(Box::into_raw(Box::new(LinkState::from_snapshot(
                &snapshot, [1u8; 16],
            ))) as Handle),
            kind: Z_SAMPLE_KIND_DELETE,
        };
        let owned = z_owned_link_event_t::from_handle(Box::into_raw(Box::new(state)) as Handle);
        let loaned = unsafe { z_link_event_loan(&owned) };
        assert_eq!(unsafe { z_link_event_kind(loaned) }, Z_SAMPLE_KIND_DELETE);

        let link = unsafe { z_link_event_link(loaned) };
        assert!(!link.is_null());
        assert_eq!(unsafe { z_link_mtu(link) }, 1024);
        // An undetermined protocol reports the two conservative answers rather
        // than guessing.
        assert!(!unsafe { z_link_is_streamed(link) });
        let mut reliability = 0;
        assert!(!unsafe { z_link_reliability(link, &mut reliability) });

        let mut moved = z_moved_link_event_t { _this: owned };
        unsafe { z_link_event_drop(&mut moved) };
        assert!(!unsafe { z_internal_link_event_check(&moved._this) });
    }

    unsafe extern "C" fn count_drop(context: *mut c_void) {
        // SAFETY: the tests below pass an `AtomicUsize` that outlives the call.
        unsafe { (*(context as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst) };
    }

    /// Dropping a closure runs its C `drop(context)` EXACTLY once, however many
    /// times a caller drops it.
    ///
    /// The double-drop half is not hypothetical: `z_declare_*` takes the closure
    /// on both its success and its failure path, and a C program that then drops
    /// its own copy would run the context's destructor a second time.
    #[test]
    fn dropping_a_closure_runs_its_c_drop_once() {
        let runs = AtomicUsize::new(0);
        let mut owned = z_owned_closure_link_event_t::null_value();
        unsafe {
            z_closure_link_event(
                &mut owned,
                None,
                Some(count_drop),
                &runs as *const AtomicUsize as *mut c_void,
            )
        };
        // No `call`, so the closure is not "live" by upstream's check — but its
        // drop still has to run, which is why `check` reads `call` and the drop
        // path does not.
        assert!(!unsafe { z_internal_closure_link_event_check(&owned) });

        let mut moved = z_moved_closure_link_event_t { _this: owned };
        unsafe { z_closure_link_event_drop(&mut moved) };
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        unsafe { z_closure_link_event_drop(&mut moved) };
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "a second drop must be a no-op"
        );
    }

    /// Declaring a listener against a NULL session still consumes the callback.
    ///
    /// This is the leak the `z_moved_*` contract exists to prevent: the callee
    /// owns the closure from the moment it is passed, so a rejected declare that
    /// left the C context un-dropped would leak it on every failure.
    #[test]
    fn a_rejected_declare_still_drops_the_callback() {
        let runs = AtomicUsize::new(0);
        let mut closure = z_owned_closure_transport_event_t::null_value();
        unsafe {
            z_closure_transport_event(
                &mut closure,
                None,
                Some(count_drop),
                &runs as *const AtomicUsize as *mut c_void,
            )
        };
        let mut moved = z_moved_closure_transport_event_t { _this: closure };
        let mut listener = z_owned_transport_events_listener_t::null_value();
        let rc = unsafe {
            z_declare_transport_events_listener(
                std::ptr::null(),
                &mut listener,
                &mut moved,
                std::ptr::null(),
            )
        };
        assert_eq!(rc, Z_ENULL);
        assert!(!unsafe { z_internal_transport_events_listener_check(&listener) });
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "the callback is taken on the failure path too, and must be dropped there"
        );
    }

    /// Undeclaring a listener twice reports the second as invalid rather than OK.
    ///
    /// A `Z_OK` there would tell a C program it had just released a listener it
    /// had already released, which is the same silence a double-free hides in.
    #[test]
    fn undeclaring_twice_is_distinguishable() {
        let mut listener = z_owned_link_events_listener_t::null_value();
        let mut moved = z_moved_link_events_listener_t { _this: listener };
        assert_eq!(
            unsafe { z_undeclare_link_events_listener(&mut moved) },
            Z_EINVAL
        );
        listener = z_owned_link_events_listener_t::null_value();
        let _ = listener;
    }

    /// wz's dense 2-bit INIT role maps onto upstream's BITMASK spelling, and the
    /// three are distinct.
    ///
    /// Measured because the two encodings genuinely disagree — wire 1 is Peer and
    /// C 1 is Router — so an identity mapping would be wrong in a way that only
    /// shows up against a real peer.
    #[test]
    fn the_wire_role_maps_onto_upstreams_bitmask() {
        assert_eq!(z_whatami_t::from(whatami_c_from_wire(0)), Z_WHATAMI_ROUTER);
        assert_eq!(z_whatami_t::from(whatami_c_from_wire(1)), Z_WHATAMI_PEER);
        assert_eq!(z_whatami_t::from(whatami_c_from_wire(2)), Z_WHATAMI_CLIENT);
    }
}
