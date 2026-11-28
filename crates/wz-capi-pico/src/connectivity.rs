// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The CONNECTIVITY plane — which peers a session is connected to, over which
//! links, and being told when that changes (pico `Z_FEATURE_CONNECTIVITY`).
//!
//! A C program asks two questions through this plane and gets two answers:
//! `z_info_transports` / `z_info_links` enumerate what is connected NOW, and
//! `z_declare_transport_events_listener` / `z_declare_link_events_listener` are
//! told when a peer arrives or leaves. A transport is a peer; a link is the
//! connection to it.
//!
//! ## The types are VALUES, and that decides the design
//!
//! Every type here is `_Z_OWNED_TYPE_VALUE`: `z_owned_transport_t` is
//! `{ _z_info_transport_t _val; }`, its loaned form is the value itself, and a
//! callback is handed a pointer to a struct on pico's own stack
//! (`vendor/zenoh-pico/include/zenoh-pico/api/types.h` @
//! `typedef struct _z_info_link_t {`). So the structs below mirror the reference
//! layout field for field — `pico_abi_option_layout` pins every size and offset
//! against the reference headers — and a callback is handed a pointer to a value
//! this module builds on ITS stack. There is no handle, no registry lookup and
//! nothing for a loan to dangle from; a link's two strings are the only owned
//! memory, and they are released by the functions that pico releases them in.
//!
//! ## One hub per session, because the ORDER is pico's
//!
//! pico dispatches a peer's arrival as a transport `PUT` and then a link `PUT`,
//! and its departure as a link `DELETE` and then a transport `DELETE`
//! (`vendor/zenoh-pico/src/api/connectivity.c` @
//! `void _z_connectivity_peer_disconnected(_z_session_t *session, const _z_connectivity_peer_event_data_t *peer,`).
//! A program with both listeners — which is what upstream's own `z_info.c` is —
//! sees that order in its output. The face registry hands each watcher the same
//! event in the order they were registered, so one watcher per LISTENER would
//! make the order the order they were declared in, and the departure would
//! reach the transport listener first. One watcher per SESSION (`Connectivity`,
//! registered once at the open) dispatches in pico's order.
//!
//! ## What a link reports is what PICO's link of that kind reports
//!
//! `z_link_mtu`, `z_link_is_streamed` and `z_link_is_reliable` are read off the
//! link object in pico, which fixes them per link TYPE and not per connection
//! (`vendor/zenoh-pico/src/link/unicast/tcp.c` @ `zl->_cap._flow = Z_LINK_CAP_FLOW_STREAM;`).
//! The registry reports a negotiated batch size instead, which for a pico peer
//! is 2048 and for a TCP link is not what pico says its MTU is. `pico_link_properties`
//! carries pico's five links; a link kind pico does not have (QUIC, unixpipe,
//! vsock, unix-domain sockets, reliable UDP) keeps the registry's answers,
//! since there is no reference to follow.
//!
//! ## Two things pico says in a way that cannot be reproduced, and what is done
//!
//! - `is_qos` and `is_shm` are hard-coded `false` in pico
//!   (`vendor/zenoh-pico/src/api/api.c` @ `void _z_info_transport_from_peer(`): pico
//!   negotiates neither on unicast, and this ABI offers neither either.
//! - `z_link_group`, `z_link_auth_identifier`, `z_link_interfaces`,
//!   `z_link_priorities` and `z_link_reliability` are stubs in pico (empty
//!   string, empty array, `false`). They are the same here, for the same reason
//!   the reference gives: there is nothing behind them.
//!
//! ## Undeclaring waits for the callback, as pico does
//!
//! `z_undeclare_*_events_listener` returns only once no callback of that listener
//! is running and its `drop(context)` has run (pico waits on a sync group).
//! Each listener keeps its closure behind a mutex that every call holds, so the
//! undeclaring thread takes the closure out under it. As in pico, a callback
//! that undeclares its own listener waits for itself.
//!
//! A listener declared with `history` replays the current peers first, on the
//! calling thread, and a peer that arrives meanwhile is QUEUED and delivered
//! after the replay rather than interleaved with it, in the
//! `MAX_CONNECTIVITY_REPLAY_EVENTS` rows reserved with the listener. A PUT still
//! waiting and the DEL of the same row cancel; a DEL waiting and the PUT of its
//! row (a reconnect) are both told, in order; the same kind again is told once.
//! When every row is held, the rest of the window is told by bringing the
//! listener to the faces as they stand, by what the engine noted it was told
//! (`wz_capi_port::told`). The contract that follows, stated as pico's
//! listener has none to compare with: a transport that came and went inside the
//! replay window is not told, and past the queue one reconnect may be lost.
//!
//! ## A row the session's queue lost
//!
//! pico calls its listeners from the task that saw the peer come or go, so a listener misses
//! nothing. Here the rows of faces wait for the hand-out in a queue of `MAX_FACE_WATCH_ROWS`, and
//! a row that finds it full is let go of and counted on the last row kept
//! (`FaceLinkRow::lost_after`). So the hub keeps each row it told came, as it told it, in the
//! `MAX_CONNECTIVITY_TOLD_ROWS` rows reserved with it, and after the row that counts a loss tells
//! what the lost rows changed, against the rows that stand: each row told that no longer stands as
//! it was told is told left, its transport after its face's last kept row, then each row that
//! stands and was not told is told came, its transport first. A row that left and came back with
//! the same ends inside the loss is told neither. A row past the kept rows is told came again at
//! each loss, and its departure, when a loss carries it, is not told.

use core::ffi::{c_int, c_void};
use core::ptr::{addr_of_mut, NonNull};

use wz_capi_port::lodge::{Lent, Strong};
use wz_capi_port::os::{mutex_in, Mutex, MutexGuard};

use wz_capi_port::told::{ToldKey, ToldPlane};
use wz_capi_port::SessionEngine;
use wz_session_core::face::{FaceEventKind, FaceLinkRow, GroupRowText};
use wz_session_core::text_out::{FixedText, TextOut};

use crate::abi::z_owned_string_t;
use crate::bytes::store_owned_string;
use crate::ffi::{catch, guarded, CClosure, HeldIn};
use crate::link_properties::pico_link_properties;
use crate::object_slot::{
    count_in_entity, hold_entity, kept_at, retire_entity, Answering, Kind, Slot,
};
use crate::prelude::*;
use crate::pubsub::{
    z_closure_drop_callback_t, z_sample_kind_t, Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT,
};
use crate::result::{
    ZResult, Z_EINVAL, Z_ERR_NULL, Z_ERR_SESSION_CLOSED, Z_ERR_SYSTEM_OUT_OF_MEMORY, Z_OK,
};
use crate::session::{
    engine_held, engine_ref, session_handle, z_loaned_session_t, Engine, PicoSessionHandle,
};
use crate::string_array::z_owned_string_array_t;
use crate::whatami::z_whatami_t;
use crate::zid::z_id_t;

// ===========================================================================
// the values
// ===========================================================================

/// pico `z_loaned_transport_t` = `_z_info_transport_t` (24 B, 4-aligned
/// measured): the peer's zid, its role as a `z_whatami_t` bitmask, and three
/// flags.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_loaned_transport_t {
    pub zid: z_id_t,
    pub whatami: z_whatami_t,
    pub is_qos: bool,
    pub is_multicast: bool,
    pub is_shm: bool,
}

/// Owned transport (pico `z_owned_transport_t`): the value itself.
#[repr(C)]
pub struct z_owned_transport_t {
    pub(crate) _val: z_loaned_transport_t,
}

/// Moved transport (pico `z_moved_transport_t`).
#[repr(C)]
pub struct z_moved_transport_t {
    pub(crate) _this: z_owned_transport_t,
}

/// pico's `_z_string_t` (32 B measured): a length, a start, and the deleter and
/// context pico frees it with. Here the start is a leaked `Box<[u8]>` and the
/// last two words are unused, so the size is the reference's and the ownership
/// is Rust's; a null start is the null string.
#[repr(C)]
pub struct ConnText {
    len: usize,
    start: *const u8,
    _deleter: usize,
    _context: usize,
}

// SAFETY: the start is either null or the sole owner of a leaked `Box<[u8]>`,
// so moving the value moves the allocation with it.
unsafe impl Send for ConnText {}

impl ConnText {
    const NULL: Self = Self {
        len: 0,
        start: core::ptr::null(),
        _deleter: 0,
        _context: 0,
    };

    fn new(bytes: &[u8]) -> Self {
        Self::of_boxed(bytes.into())
    }

    /// The text `write` writes, in an allocation of its own of the text's length: a link's end
    /// written once, where it is handed out, from the facts its row holds. Written on the stack,
    /// and again on the heap only past the build's locator bound: a unix socket path, or an IPv6
    /// end with its scope under a bound shorter than the longest.
    fn written(write: impl Fn(&mut dyn TextOut)) -> Self {
        let mut inline: FixedText<{ wz_session_core::caps::MAX_LOCATOR_LEN }> = FixedText::new();
        write(&mut inline);
        if let Ok(text) = inline.finish() {
            return Self::new(text.as_bytes());
        }
        let mut text = String::new();
        write(&mut text);
        Self::of_boxed(text.into_bytes().into_boxed_slice())
    }

    fn of_boxed(boxed: Box<[u8]>) -> Self {
        let len = boxed.len();
        Self {
            len,
            start: Box::into_raw(boxed) as *const u8,
            _deleter: 0,
            _context: 0,
        }
    }

    fn is_null(&self) -> bool {
        self.start.is_null()
    }

    fn as_bytes(&self) -> &[u8] {
        if self.start.is_null() {
            &[]
        } else {
            // SAFETY: a non-null start owns `len` bytes (see `new`).
            unsafe { core::slice::from_raw_parts(self.start, self.len) }
        }
    }

    fn duplicate(&self) -> Self {
        if self.is_null() {
            Self::NULL
        } else {
            Self::new(self.as_bytes())
        }
    }

    /// Release the allocation and become the null string.
    ///
    /// # Safety
    /// Not while another copy of this value is still in use: `duplicate` makes
    /// an independent one, a bitwise copy does not.
    unsafe fn release(&mut self) {
        if !self.start.is_null() {
            drop(Box::from_raw(core::ptr::slice_from_raw_parts_mut(
                self.start as *mut u8,
                self.len,
            )));
        }
        *self = Self::NULL;
    }
}

/// pico `z_loaned_link_t` = `_z_info_link_t` (88 B, 8-aligned measured).
#[repr(C)]
pub struct z_loaned_link_t {
    pub zid: z_id_t,
    pub src: ConnText,
    pub dst: ConnText,
    pub mtu: u16,
    pub is_streamed: bool,
    pub is_reliable: bool,
}

/// Owned link (pico `z_owned_link_t`): the value itself.
#[repr(C)]
pub struct z_owned_link_t {
    pub(crate) _val: z_loaned_link_t,
}

/// Moved link (pico `z_moved_link_t`).
#[repr(C)]
pub struct z_moved_link_t {
    pub(crate) _this: z_owned_link_t,
}

/// pico `z_loaned_transport_event_t` = `_z_info_transport_event_t` (28 B).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct z_loaned_transport_event_t {
    pub kind: z_sample_kind_t,
    pub transport: z_loaned_transport_t,
}

/// Owned transport event (pico `z_owned_transport_event_t`).
#[repr(C)]
pub struct z_owned_transport_event_t {
    pub(crate) _val: z_loaned_transport_event_t,
}

/// Moved transport event (pico `z_moved_transport_event_t`).
#[repr(C)]
pub struct z_moved_transport_event_t {
    pub(crate) _this: z_owned_transport_event_t,
}

/// pico `z_loaned_link_event_t` = `_z_info_link_event_t` (96 B, 8-aligned).
#[repr(C)]
pub struct z_loaned_link_event_t {
    pub kind: z_sample_kind_t,
    pub link: z_loaned_link_t,
}

/// Owned link event (pico `z_owned_link_event_t`).
#[repr(C)]
pub struct z_owned_link_event_t {
    pub(crate) _val: z_loaned_link_event_t,
}

/// Moved link event (pico `z_moved_link_event_t`).
#[repr(C)]
pub struct z_moved_link_event_t {
    pub(crate) _this: z_owned_link_event_t,
}

/// What every one of the four values can do, which is what pico's
/// `_Z_OWNED_FUNCTIONS_VALUE_IMPL` asks of each: be null, say whether it holds a
/// peer, copy itself, and release what it owns. The exports are written once
/// over this.
pub(crate) trait ConnValue: Sized {
    /// `_z_info_*_null`.
    fn null() -> Self;
    /// `_z_info_*_check`: the zid is set.
    fn is_set(&self) -> bool;
    /// `_z_info_*_copy`.
    fn duplicate(&self) -> Self;
    /// `_z_info_*_clear`: release what the value owns and become null.
    ///
    /// # Safety
    /// Not while a bitwise copy of the value is still in use.
    unsafe fn clear(&mut self);
}

fn zid_is_set(zid: &z_id_t) -> bool {
    !crate::zid::id_is_zero(zid.id)
}

impl ConnValue for z_loaned_transport_t {
    fn null() -> Self {
        Self {
            zid: z_id_t::empty(),
            whatami: 0,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
        }
    }
    fn is_set(&self) -> bool {
        zid_is_set(&self.zid)
    }
    fn duplicate(&self) -> Self {
        *self
    }
    unsafe fn clear(&mut self) {
        *self = Self::null();
    }
}

impl ConnValue for z_loaned_link_t {
    fn null() -> Self {
        Self {
            zid: z_id_t::empty(),
            src: ConnText::NULL,
            dst: ConnText::NULL,
            mtu: 0,
            is_streamed: false,
            is_reliable: false,
        }
    }
    fn is_set(&self) -> bool {
        zid_is_set(&self.zid)
    }
    fn duplicate(&self) -> Self {
        Self {
            zid: self.zid,
            src: self.src.duplicate(),
            dst: self.dst.duplicate(),
            mtu: self.mtu,
            is_streamed: self.is_streamed,
            is_reliable: self.is_reliable,
        }
    }
    unsafe fn clear(&mut self) {
        self.src.release();
        self.dst.release();
        *self = Self::null();
    }
}

impl ConnValue for z_loaned_transport_event_t {
    fn null() -> Self {
        Self {
            kind: Z_SAMPLE_KIND_PUT,
            transport: z_loaned_transport_t::null(),
        }
    }
    fn is_set(&self) -> bool {
        self.transport.is_set()
    }
    fn duplicate(&self) -> Self {
        *self
    }
    unsafe fn clear(&mut self) {
        *self = Self::null();
    }
}

impl ConnValue for z_loaned_link_event_t {
    fn null() -> Self {
        Self {
            kind: Z_SAMPLE_KIND_PUT,
            link: z_loaned_link_t::null(),
        }
    }
    fn is_set(&self) -> bool {
        self.link.is_set()
    }
    fn duplicate(&self) -> Self {
        Self {
            kind: self.kind,
            link: self.link.duplicate(),
        }
    }
    unsafe fn clear(&mut self) {
        self.link.clear();
        self.kind = Z_SAMPLE_KIND_PUT;
    }
}

/// A link value living on this module's own stack: released when it goes.
struct HeldLink(z_loaned_link_t);

impl Drop for HeldLink {
    fn drop(&mut self) {
        // SAFETY: the value is this guard's alone; a callback that took the
        // strings out did so through `take_from_loaned`, which nulled them.
        unsafe { self.0.clear() };
    }
}

// ===========================================================================
// the peers a session reports
// ===========================================================================

const WHATAMI_ROUTER: z_whatami_t = 1;
const WHATAMI_PEER: z_whatami_t = 2;
const WHATAMI_CLIENT: z_whatami_t = 4;

/// The INIT wire role (`0` router, `1` peer, `2` client) as pico's bitmask
/// (`1 << role`); an unknown role is `0`, pico's "other".
fn pico_whatami(wire: u8) -> z_whatami_t {
    match wire {
        0 => WHATAMI_ROUTER,
        1 => WHATAMI_PEER,
        2 => WHATAMI_CLIENT,
        _ => 0,
    }
}

/// The transport pico reports of the peer `zid` in the wire role `whatami`.
fn pico_transport(zid: [u8; 16], whatami: u8, is_multicast: bool) -> z_loaned_transport_t {
    z_loaned_transport_t {
        zid: z_id_t { id: zid },
        whatami: pico_whatami(whatami),
        // Hard-coded `false` in pico, which negotiates neither on unicast.
        is_qos: false,
        is_multicast,
        is_shm: false,
    }
}

/// Every transport and link pico reports, a row at a time: each unicast face, then each member of
/// each group the session joined, which pico lists as a multicast transport of its own
/// (`vendor/zenoh-pico/src/api/api.c` @
/// `z_result_t z_info_transports(const z_loaned_session_t *zs, z_moved_closure_transport_t *callback) {`).
/// No lock of the session is held between two rows, so a program's callback runs between them.
fn rows(engine: &Engine) -> impl Iterator<Item = FaceLinkRow> + '_ {
    let mut at = 0;
    core::iter::from_fn(move || {
        let row = SessionEngine::face_link_at(engine, at)?;
        // No engine holds a row at `usize::MAX`, so the walk ends there.
        at = at.saturating_add(1);
        Some(row)
    })
}

/// The transport pico reports for the face of `row`.
fn transport_of_row(row: &FaceLinkRow) -> z_loaned_transport_t {
    pico_transport(row.zid, row.whatami, row.is_multicast)
}

/// The text pico's `_z_endpoint_to_string` makes of a group endpoint: the locator without
/// its metadata, then the config keys pico's link for the scheme knows
/// (`crate::endpoint::config_keys`), in its own order and joined by `;`, with NO separator
/// between the two (`vendor/zenoh-pico/src/link/endpoint.c` @
/// `memcpy(curr_dst, config, config_len);`), so `udp/224.0.0.224:7447#iface=lo` reads back as
/// `udp/224.0.0.224:7447iface=lo`.
///
/// pico reads the config up to the first key it does not know and keeps the last value of
/// a key given twice (`vendor/zenoh-pico/src/protocol/config.c` @
/// `z_result_t _z_str_intmap_from_strn(`), and declares no locator metadata key, so the
/// text keeps what pico kept.
///
/// A group is a UDP or a raweth one, so a scheme pico reads no config of is read with no key, and
/// a config pico would have refused (a pair with no `=`) is written as none.
fn pico_group_endpoint_text(endpoint: &str) -> String {
    use crate::endpoint::{config_keys, scheme_of, PicoEndpoint};
    let read = PicoEndpoint::read(endpoint, config_keys(scheme_of(endpoint)).unwrap_or(&[]));
    if read.is_malformed() {
        return read.locator.to_owned();
    }
    // pico writes no separator between the locator and the config.
    read.text("")
}

/// The text pico writes of the endpoint a session joined its group by
/// ([`pico_group_endpoint_text`]), which each member's link starts at: written once, as the
/// session is opened, and read by every door that hands a member's link out.
pub(crate) struct GroupText(GroupRowText);

impl GroupText {
    /// The text of `endpoint`, the one the session joins its group by.
    pub(crate) fn of(endpoint: &str) -> Self {
        Self(GroupRowText::of(&pico_group_endpoint_text(endpoint)))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The link pico reports for one link of an established face.
///
/// A group member's link starts at the endpoint the session joined the group by, as pico
/// labels it (`vendor/zenoh-pico/src/transport/multicast/rx.c` @
/// `entry->common._link_src = _z_endpoint_to_string(&ztm->_common._link->_endpoint);`),
/// written as pico writes an endpoint: the session's `group`, which its open wrote once
/// ([`GroupText`]). A member of a group the session did not join by its open, which no open of
/// this ABI makes, starts at the group's locator. Its other fields are those of the group's own
/// link, which pico reads off the transport
/// (`vendor/zenoh-pico/include/zenoh-pico/api/primitives.h` @ `*mtu = transport->_link->_mtu;`):
/// a raweth group's link is a 1514-byte frame (`vendor/zenoh-pico/src/transport/raweth/link.c`
/// @ `static uint16_t _z_get_link_mtu_raweth(void) { return _ZP_MAX_ETH_FRAME_SIZE; }`),
/// unreliable and unstreamed, and its member has no `dst`: pico labels a member by the address
/// its receive gave, which it renders only as an IPv4 or IPv6 address with a port
/// (`vendor/zenoh-pico/src/transport/multicast/rx.c` @
/// `} else if (remote_addr->len == 16 + sizeof(uint16_t)) {`), and a raweth receive gives four
/// bytes of the source MAC (`vendor/zenoh-pico/src/link/transport/udp/raweth_unix.c` @
/// `addr->len = sizeof(ETH_ALEN);`). MEASURED against the real library: `dst=` and `mtu=1514`.
///
/// Each end is written here, once, into the string handed out, from the facts the row holds of
/// it ([`FaceLinkRow::write_src`], [`FaceLinkRow::write_dst`]).
fn link_of_row(row: &FaceLinkRow, group: Option<&GroupText>) -> z_loaned_link_t {
    let group_endpoint = row.group_endpoint.as_deref();
    let raweth = group_endpoint.is_some_and(|endpoint| endpoint.starts_with("reth/"));
    let (mtu, is_streamed, is_reliable) = if raweth {
        (1514, false, false)
    } else {
        pico_link_properties(row.kind, row.mtu)
    };
    let src = match group.filter(|_| group_endpoint.is_some()) {
        Some(group) => ConnText::new(group.as_bytes()),
        None => ConnText::written(|text| row.write_src(text)),
    };
    let dst = if raweth {
        ConnText::new(&[])
    } else {
        ConnText::written(|text| row.write_dst(text))
    };
    z_loaned_link_t {
        zid: z_id_t { id: row.zid },
        src,
        dst,
        mtu,
        is_streamed,
        is_reliable,
    }
}

// ===========================================================================
// the listeners
// ===========================================================================

/// pico's closure callback shape: `void call(<loaned>*, void *context)`.
pub type Callback<T> = Option<unsafe extern "C" fn(*mut T, *mut c_void)>;

/// How many events wait for a listener's history to be replayed: past them the listener is
/// brought to the faces as they stand when its replay ends (`MAX_CONNECTIVITY_REPLAY_EVENTS`).
const REPLAY_ROWS: usize = wz_session_core::caps::MAX_CONNECTIVITY_REPLAY_EVENTS;

/// An event a listener is told, naming the plane it is of, each as that plane's C callback reads
/// it.
enum ConnEvent {
    /// A transport came (`PUT`) or left.
    Transport(z_loaned_transport_event_t),
    /// A link came (`PUT`) or left.
    Link(z_loaned_link_event_t),
}

impl ConnEvent {
    /// The plane whose listeners are told the event.
    fn plane(&self) -> ToldPlane {
        match self {
            Self::Transport(_) => ToldPlane::Transports,
            Self::Link(_) => ToldPlane::Links,
        }
    }

    /// The event as its plane's callback is handed it, for the length of one call.
    fn as_loaned(&mut self) -> *mut c_void {
        match self {
            Self::Transport(event) => core::ptr::from_mut(event).cast(),
            Self::Link(event) => core::ptr::from_mut(event).cast(),
        }
    }

    /// Release what the event owns and leave it null.
    ///
    /// # Safety
    /// Not while a bitwise copy of the event is still in use.
    unsafe fn clear(&mut self) {
        // SAFETY: the caller's.
        unsafe {
            match self {
                Self::Transport(event) => event.clear(),
                Self::Link(event) => event.clear(),
            }
        }
    }
}

/// A listener's C callback as its delivery holds it: the event's type is left out, as the plane
/// the delivery is of names it, and the delivery hands the callback that plane's events alone
/// ([`Delivery::call`]).
type EventCall = Callback<c_void>;

/// A transport events listener's C callback as its delivery holds it.
fn erase_transport_call(call: Callback<z_loaned_transport_event_t>) -> EventCall {
    call.map(|call| {
        // SAFETY: the two differ in the pointee of the first argument alone, and pointers to sized
        // types are passed alike, so the function is called as it was written to be.
        unsafe {
            core::mem::transmute::<
                unsafe extern "C" fn(*mut z_loaned_transport_event_t, *mut c_void),
                unsafe extern "C" fn(*mut c_void, *mut c_void),
            >(call)
        }
    })
}

/// A link events listener's C callback as its delivery holds it.
fn erase_link_call(call: Callback<z_loaned_link_event_t>) -> EventCall {
    call.map(|call| {
        // SAFETY: as `erase_transport_call`'s.
        unsafe {
            core::mem::transmute::<
                unsafe extern "C" fn(*mut z_loaned_link_event_t, *mut c_void),
                unsafe extern "C" fn(*mut c_void, *mut c_void),
            >(call)
        }
    })
}

/// A change of a row that arrived while a history is replayed: the row's key, and whether it
/// came or left. What the listener is told of it is written when it is told, from the row the
/// engine keeps as it notes the listener told (`SessionEngine::tell_came`,
/// `SessionEngine::tell_went`), so a held change owns nothing and is the same for either plane.
#[derive(Clone, Copy)]
struct Held {
    key: ToldKey,
    came: bool,
}

// A queue row holds no event: the larger plane's event would size the rows of every listener's
// place, whichever plane it is of.
const _: () = assert!(
    core::mem::size_of::<Option<Held>>() < core::mem::size_of::<z_loaned_transport_event_t>() * 2
);

/// Whether a listener's history is being replayed, and what arrives meanwhile, waiting behind it
/// in order, in [`REPLAY_ROWS`] rows reserved with the listener whether it replays or not. What
/// arrives of a row already waiting is folded into it, so a row waits at most twice, its DEL and
/// then its PUT.
struct Replay {
    /// The history is being replayed on the declaring thread and what arrives waits here; once
    /// not, deliveries go straight to the closure.
    replaying: bool,
    rows: [Option<Held>; REPLAY_ROWS],
    len: usize,
    /// A change found every row held: it and what follows it are not held, and the listener is
    /// brought to the faces as they stand once what is held was delivered
    /// ([`Delivery::finish_replay`]).
    overflowed: bool,
}

impl Replay {
    fn new(replaying: bool) -> Self {
        Self {
            replaying,
            rows: [None; REPLAY_ROWS],
            len: 0,
            overflowed: false,
        }
    }

    /// Hold the change of the row of `key`, which `came` or left, behind what waits. A PUT still
    /// waiting and the DEL of its row are neither told: the row came and went inside the replay.
    /// The same change again is told once. A DEL waiting and the PUT of its row are both told, in
    /// order: a reconnect. A change that finds every row held is not held.
    fn hold(&mut self, key: ToldKey, came: bool) {
        if self.overflowed {
            return;
        }
        match self.last_of(&key) {
            Some((at, true)) if !came => self.remove(at),
            Some((_, held)) if held == came => {}
            _ => match self.rows.get_mut(self.len) {
                Some(row) => {
                    *row = Some(Held { key, came });
                    // The row just filled lies below the rows' count.
                    self.len = self.len.saturating_add(1);
                }
                None => self.overflowed = true,
            },
        }
    }

    /// The row the last change of `key` waits in, and whether it tells its row came.
    fn last_of(&self, key: &ToldKey) -> Option<(usize, bool)> {
        self.rows
            .iter()
            .take(self.len)
            .enumerate()
            .rev()
            .find_map(|(at, row)| {
                let held = row.as_ref()?;
                (held.key == *key).then_some((at, held.came))
            })
    }

    /// Let go of the change at `at`, the ones after it moving up a row.
    fn remove(&mut self, at: usize) {
        if let Some(row) = self.rows.get_mut(at) {
            *row = None;
        }
        if let Some(after) = self.rows.get_mut(at..self.len) {
            if !after.is_empty() {
                after.rotate_left(1);
            }
        }
        self.len = self.len.saturating_sub(1);
    }

    /// The first change waiting, taken out.
    fn next(&mut self) -> Option<Held> {
        let first = self.rows.first_mut()?.take()?;
        if let Some(held) = self.rows.get_mut(..self.len) {
            if !held.is_empty() {
                held.rotate_left(1);
            }
        }
        self.len = self.len.saturating_sub(1);
        Some(first)
    }

    /// Whether a change found every row held since this was last asked.
    fn take_overflow(&mut self) -> bool {
        core::mem::take(&mut self.overflowed)
    }
}

/// One declared listener's way to its closure.
///
/// `gate` holds the closure and is held for the length of every call, so the
/// thread that undeclares can take the closure out under it and know nothing is
/// running; `replay` is only ever held briefly and never across a call, so a peer
/// arriving during a replay is queued rather than made to wait.
pub(crate) struct Delivery {
    /// The plane whose events the closure reads.
    plane: ToldPlane,
    gate: Mutex<Option<CClosure<EventCall>>>,
    replay: Mutex<Replay>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock()
}

impl Delivery {
    /// A delivery of `plane`'s events to `closure`, holding what arrives while `replaying`, made
    /// in `place`, where it stays: its locks are made there ([`mutex_in`]).
    ///
    /// # Safety
    /// `place` is valid for writes of a `Self`, aligned for it and holds none; the delivery is not
    /// moved from it until it is dropped there. `closure`'s function reads `plane`'s events.
    unsafe fn write_in(
        place: NonNull<Self>,
        plane: ToldPlane,
        closure: CClosure<EventCall>,
        replaying: bool,
    ) {
        let at = place.as_ptr();
        // SAFETY: the caller's: each field is written once through a pointer to it, not null as
        // it is inside the place, and each lock is made there.
        unsafe {
            addr_of_mut!((*at).plane).write(plane);
            mutex_in(NonNull::new_unchecked(addr_of_mut!((*at).gate)), |gate| {
                gate.write(Some(closure))
            });
            mutex_in(
                NonNull::new_unchecked(addr_of_mut!((*at).replay)),
                |replay| replay.write(Replay::new(replaying)),
            );
        }
    }

    /// Deliver the event `event` writes of the row of `key`, which `came` or left, or hold the
    /// change while the history is being replayed: its event is written when it is told
    /// ([`Self::finish_replay`]).
    fn deliver(&self, key: ToldKey, came: bool, event: impl FnOnce() -> ConnEvent) {
        {
            let mut replay = lock(&self.replay);
            if replay.replaying {
                replay.hold(key, came);
                return;
            }
        }
        self.call(event());
    }

    /// Call the closure with `event`, then release the event. A listener that
    /// has been undeclared has no closure and the event is just released, as is an event of a
    /// plane the closure does not read.
    fn call(&self, mut event: ConnEvent) {
        {
            let gate = lock(&self.gate);
            if let Some(closure) = gate.as_ref() {
                if let Some(call) = closure.call.filter(|_| event.plane() == self.plane) {
                    let context = closure.context.0;
                    let loaned = event.as_loaned();
                    // A panic unwinding out of the C callback across this
                    // `extern "C"` boundary is UB and would tear down the drive
                    // thread.
                    // SAFETY: the function reads this delivery's plane's events (`write_in`),
                    // and `loaned` is one of them, standing for the call.
                    let _ = catch(|| unsafe { call(loaned, context) });
                }
            }
        }
        // SAFETY: the event is this frame's alone; a callback that kept the
        // peer took it out through `take_from_loaned`, which nulled it.
        unsafe { event.clear() };
    }

    /// Deliver what arrived during the replay, in order, and go live. A held change is told
    /// only when `tell`, asked whether its row `came` and of which row, writes its event, which
    /// it does from the row the engine keeps when the listener is to hear it
    /// (`SessionEngine::tell_came`, `SessionEngine::tell_went`); once the queue is drained after
    /// it ran out of rows, `converge` brings the listener to the faces as they stand. The replay
    /// ends only when the queue is found empty and whole under its lock, so an event cannot be
    /// delivered ahead of one still held.
    fn finish_replay(
        &self,
        mut tell: impl FnMut(bool, &ToldKey) -> Option<ConnEvent>,
        mut converge: impl FnMut(&Self),
    ) {
        loop {
            let next = {
                let mut replay = lock(&self.replay);
                if !replay.replaying {
                    return;
                }
                match replay.next() {
                    Some(held) => Some(held),
                    None if replay.take_overflow() => None,
                    None => {
                        replay.replaying = false;
                        return;
                    }
                }
            };
            match next {
                Some(held) => {
                    if let Some(event) = tell(held.came, &held.key) {
                        self.call(event);
                    }
                }
                None => converge(self),
            }
        }
    }

    /// Take the closure out, once nothing is running it, and run its
    /// `drop(context)` here. Idempotent.
    fn retire(&self) {
        let closure = lock(&self.gate).take();
        drop(closure);
        // What was still held is told to no one: a held change owns nothing to let go of.
        *lock(&self.replay) = Replay::new(false);
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Behind an owned listener of either plane: its session's hub and its id there, which the
/// listener's undeclare takes off the hub. It lies in the listener's place, a place of the
/// session's own for the listener's plane (`crate::object_slot::Kind::TransportEventsListener`,
/// `crate::object_slot::Kind::LinkEventsListener`).
pub(crate) struct ListenerState {
    hub: Strong<Connectivity>,
    id: u64,
}

/// What a listener's place keeps past its handle, which the hub calls: its delivery, of its
/// plane, and the transport a link listener is filtered to, if any.
pub(crate) struct Listener {
    delivery: Delivery,
    /// `(zid, is_multicast)` — pico's transport filter matches on exactly these
    /// two (`vendor/zenoh-pico/src/api/api.c` @
    /// `bool _z_info_transport_filter_match(`). `None` for a transport listener.
    filter: Option<([u8; 16], bool)>,
}

impl Listener {
    /// Whether the listener is told of a change of `row`: unless it is filtered to another
    /// transport.
    fn wants(&self, row: &FaceLinkRow) -> bool {
        self.filter
            .is_none_or(|(zid, multicast)| zid == row.zid && multicast == row.is_multicast)
    }

    /// Whether the listener is told of `row` as it stands: a transport listener by its face's
    /// first row, a link listener by each row it wants.
    fn hears(&self, row: &FaceLinkRow) -> bool {
        match self.delivery.plane {
            ToldPlane::Transports => row.link == 0,
            ToldPlane::Links => self.wants(row),
        }
    }
}

/// A listener's place, of either plane: its handle's state, which the handle lets go of (none for
/// a background listener), and what the hub calls, kept past it; the last of the handle, the
/// hub's hold and a dispatch in flight gives the place back (`crate::object_slot::Answering`).
pub(crate) type ListenerPlace = Answering<ListenerState, Listener>;

/// A declared listener as the hub holds it: its id, its object, and the hub's hold of its place,
/// which keeps the place standing while a dispatch can reach it.
struct Entry {
    id: u64,
    object: *mut ListenerState,
    held: HeldIn,
}

// SAFETY: the object is reached only through the place the entry holds, whose kept part is behind
// its own locks; the entry is moved between threads only under the hub's lock.
unsafe impl Send for Entry {}

/// A row of a hub's listeners: the listener that holds it, if any, and whether a replay keeps it.
#[derive(Default)]
struct ListenerRow {
    entry: Option<Entry>,
    /// Whether the history of the row's listener is being replayed. The engine notes what the
    /// listener was told under its row (`wz_capi_port::told`), so the row is not given to another
    /// listener until the replay forgot those notes, even when the listener was undeclared
    /// meanwhile (from its own callback, say): a listener given the row then would find the notes
    /// as its own.
    replaying: bool,
}

/// The first of `rows` no listener holds and no replay keeps.
fn free_row(rows: &[ListenerRow]) -> Option<usize> {
    rows.iter()
        .position(|row| row.entry.is_none() && !row.replaying)
}

/// A hub's listeners: for each plane a row for each listener the session's limit of the plane
/// admits, a row's place among its plane's being its listener's place in the plane's told notes
/// (`wz_capi_port::told`), and the id the next listener of either plane is given.
struct Table {
    transports: [ListenerRow; wz_session_core::caps::MAX_TRANSPORT_EVENTS_LISTENERS],
    links: [ListenerRow; wz_session_core::caps::MAX_LINK_EVENTS_LISTENERS],
    last_id: u64,
}

impl Table {
    fn new() -> Self {
        Self {
            transports: core::array::from_fn(|_| ListenerRow::default()),
            links: core::array::from_fn(|_| ListenerRow::default()),
            last_id: 0,
        }
    }

    /// The rows of `plane`'s listeners.
    fn rows(&self, plane: ToldPlane) -> &[ListenerRow] {
        match plane {
            ToldPlane::Transports => &self.transports,
            ToldPlane::Links => &self.links,
        }
    }

    /// The rows of `plane`'s listeners, to change.
    fn rows_mut(&mut self, plane: ToldPlane) -> &mut [ListenerRow] {
        match plane {
            ToldPlane::Transports => &mut self.transports,
            ToldPlane::Links => &mut self.links,
        }
    }

    /// Every row, of either plane.
    fn every_row(&mut self) -> impl Iterator<Item = &mut ListenerRow> {
        self.transports.iter_mut().chain(self.links.iter_mut())
    }
}

/// What the listener whose state is at `object` keeps past its handle.
///
/// # Safety
/// `object` is the state of a listener's place that stands while the returned borrow is used.
unsafe fn listener_at<'a>(object: *const ListenerState) -> &'a Listener {
    // SAFETY: the caller's: the place holds a `ListenerPlace`, whose kept part is read only
    // through its locks.
    unsafe { &*kept_at::<ListenerState, Listener>(object) }
}

/// Let go of a listener taken off the hub: its closure, once no call is running it, and the hub's
/// hold of its place, which gives the place back when its owner went first.
fn retire_entry(entry: Entry) {
    // SAFETY: the entry's hold keeps the place standing until it is dropped below.
    unsafe { listener_at(entry.object) }.delivery.retire();
    // The hold may be the place's last, whose give-back takes the session's lock.
    debug_assert!(
        !wz_capi_port::sync::SessionHeld::any_here(),
        "a connectivity listener's place is let go of under a session's lock"
    );
    drop(entry.held);
}

/// Count the closure of the listener at `object` in its place: the place stands until its
/// `drop(context)` has run, which the hub's let-go runs while it still holds the place, and
/// nothing is allocated for the closure's release.
///
/// # Safety
/// As [`count_in_entity`]: `object` is the place of a [`ListenerPlace`] its owner filled and
/// holds.
unsafe fn count_closure(object: *const ListenerState) {
    // SAFETY: the caller's.
    let delivery = &unsafe { listener_at(object) }.delivery;
    if let Some(closure) = lock(&delivery.gate).as_mut() {
        // SAFETY: the caller's.
        unsafe { count_in_entity::<ListenerState, Listener, _>(object, closure) };
    }
}

/// The event `listener` of `plane`, whose history is being replayed, is told of its row of
/// `key`, which `came` or left: written from the row the engine keeps as it notes the listener
/// told ([`wz_capi_port::told`]), a member's starting at the session's `group`; `None` when the
/// listener is not to be told.
fn told(
    engine: &Engine,
    group: Option<&GroupText>,
    (plane, listener): (ToldPlane, usize),
    came: bool,
    key: &ToldKey,
) -> Option<ConnEvent> {
    let (kind, row) = if came {
        (
            Z_SAMPLE_KIND_PUT,
            SessionEngine::tell_came(engine, plane, listener, key)?,
        )
    } else {
        (
            Z_SAMPLE_KIND_DELETE,
            SessionEngine::tell_went(engine, plane, listener, key)?,
        )
    };
    Some(event_of_row(plane, kind, &row, group))
}

/// The key of the row an event of `plane` of `row` is of: a transport is its face's first row.
fn key_of_row(plane: ToldPlane, row: &FaceLinkRow) -> ToldKey {
    match plane {
        ToldPlane::Transports => ToldKey {
            link: 0,
            ..ToldKey::of_row(row)
        },
        ToldPlane::Links => ToldKey::of_row(row),
    }
}

/// The event of `plane` that tells `row` came (`PUT`) or left, as `kind` says: its face's
/// transport, or its link, a member's starting at the session's `group`.
fn event_of_row(
    plane: ToldPlane,
    kind: z_sample_kind_t,
    row: &FaceLinkRow,
    group: Option<&GroupText>,
) -> ConnEvent {
    match plane {
        ToldPlane::Transports => ConnEvent::Transport(z_loaned_transport_event_t {
            kind,
            transport: transport_of_row(row),
        }),
        ToldPlane::Links => ConnEvent::Link(z_loaned_link_event_t {
            kind,
            link: link_of_row(row, group),
        }),
    }
}

/// Bring the listener of row `slot` of `plane`, whose queue ran out of rows while its history
/// was replayed, to the rows as they stand: each row it was told came that has gone is told left,
/// then each row that stands, that it hears and that it was not told is told came. A row that went
/// and came back under its key is told neither, the one reconnect the contract says may be lost
/// past the queue.
fn converge(
    engine: &Engine,
    group: Option<&GroupText>,
    plane: ToldPlane,
    slot: usize,
    listener: &Listener,
) {
    while let Some(gone) = SessionEngine::first_told_gone(engine, plane, slot) {
        let Some(event) = told(
            engine,
            group,
            (plane, slot),
            false,
            &key_of_row(plane, &gone),
        ) else {
            break;
        };
        listener.delivery.call(event);
    }
    for row in rows(engine).filter(|row| listener.hears(row)) {
        if let Some(event) = told(engine, group, (plane, slot), true, &key_of_row(plane, &row)) {
            listener.delivery.call(event);
        }
    }
}

/// How many face rows the hub keeps as it told its listeners they came
/// (`MAX_CONNECTIVITY_TOLD_ROWS`).
const TOLD_ROWS: usize = wz_session_core::caps::MAX_CONNECTIVITY_TOLD_ROWS;

/// The face rows the hub told its listeners came and not yet that they left, each as it told it,
/// in [`TOLD_ROWS`] rows reserved with the hub: what a loss of the session's queue of face rows is
/// told against ([`Connectivity::catch_up`]). A row that finds every row held is told, not kept.
struct Told {
    rows: [Option<FaceLinkRow>; TOLD_ROWS],
}

impl Told {
    fn new() -> Self {
        Self {
            rows: core::array::from_fn(|_| None),
        }
    }

    /// The place of the row of `key`.
    fn place_of(&self, key: &ToldKey) -> Option<usize> {
        self.rows.iter().position(|held| {
            held.as_ref()
                .is_some_and(|held| ToldKey::of_row(held) == *key)
        })
    }

    /// Keep `row`, told came, in place of the row of its key or in a free place: whether it is
    /// news, which a row kept already with the same ends is not.
    fn came(&mut self, row: &FaceLinkRow) -> bool {
        let at = self.place_of(&ToldKey::of_row(row));
        if at
            .and_then(|at| self.rows.get(at))
            .and_then(Option::as_ref)
            .is_some_and(|held| same_ends(held, row))
        {
            return false;
        }
        let at = at.or_else(|| self.rows.iter().position(Option::is_none));
        if let Some(place) = at.and_then(|at| self.rows.get_mut(at)) {
            *place = Some(row.clone());
        }
        true
    }

    /// Let go of the row of `key`, told left.
    fn went(&mut self, key: &ToldKey) {
        if let Some(place) = self.place_of(key).and_then(|at| self.rows.get_mut(at)) {
            *place = None;
        }
    }

    /// Whether a row of the face `row` is of is kept.
    fn holds_face_of(&self, row: &FaceLinkRow) -> bool {
        self.rows
            .iter()
            .flatten()
            .any(|held| held.zid == row.zid && held.is_multicast == row.is_multicast)
    }
}

/// Whether `a` and `b`, rows of one key, are of one link: a link that went and came back under
/// its key has other ends.
fn same_ends(a: &FaceLinkRow, b: &FaceLinkRow) -> bool {
    a.ends == b.ends && a.group_endpoint == b.group_endpoint
}

/// Whether the row of `told`'s key stands, as `standing` reads the rows one at a time, with the
/// ends it was told with: one that stands with other ends went and came back.
fn stands_as_told(told: &FaceLinkRow, standing: &impl Fn(usize) -> Option<FaceLinkRow>) -> bool {
    let key = ToldKey::of_row(told);
    let mut at: usize = 0;
    while let Some(row) = standing(at) {
        if ToldKey::of_row(&row) == key {
            return same_ends(&row, told);
        }
        // No engine holds a row at `usize::MAX`, so the walk ends there.
        at = at.saturating_add(1);
    }
    false
}

/// The transport and link listeners of ONE session, the watcher that feeds
/// them, and the rows it told them came; see the module doc for why there is one.
pub(crate) struct Connectivity {
    listeners: Mutex<Table>,
    told: Mutex<Told>,
    /// The text of the endpoint the session joined its group by, `None` for a session that
    /// joined none.
    group: Option<GroupText>,
}

impl Connectivity {
    /// A session's hub with no listener and nothing told, made in `place`, which its session
    /// lent, with its locks made there, and the text of the session's `group`, which its open
    /// wrote; the place goes back with the last count of the hub, which a listener's handle may
    /// hold past the session.
    pub(crate) fn new(place: Lent<Self>, group: Option<GroupText>) -> Strong<Self> {
        let make = |place: NonNull<Self>| {
            let at = place.as_ptr();
            // SAFETY: the place is the lent one's, valid for one hub, holding none, never moved;
            // each lock is made once through a pointer to it, not null as it is inside the place.
            unsafe {
                mutex_in(
                    NonNull::new_unchecked(addr_of_mut!((*at).listeners)),
                    |table| table.write(Table::new()),
                );
                mutex_in(NonNull::new_unchecked(addr_of_mut!((*at).told)), |told| {
                    told.write(Told::new())
                });
                addr_of_mut!((*at).group).write(group);
            }
        };
        // SAFETY: `make` makes the whole hub in the place it is handed.
        unsafe { Strong::lodge_at(place, make) }
    }

    /// The text of the endpoint the session joined its group by, which a member's link starts at.
    fn group(&self) -> Option<&GroupText> {
        self.group.as_ref()
    }

    /// The listener of `plane` of the first row from `at` on that holds one, and a hold of its
    /// place for the call, with `at` moved past its row; `None` past the last row. The table's
    /// lock is let go of before this returns, so a call made with the hold does not wait on it.
    fn next_listener(
        &self,
        plane: ToldPlane,
        at: &mut usize,
    ) -> Option<(*mut ListenerState, HeldIn)> {
        let table = lock(&self.listeners);
        let rows = table.rows(plane);
        while let Some(row) = rows.get(*at) {
            *at = at.saturating_add(1);
            if let Some(entry) = &row.entry {
                // SAFETY: the entry's place stands while the entry holds it, which it does under
                // the lock held here.
                let hold = unsafe { hold_entity::<ListenerState, Listener>(entry.object) };
                return Some((entry.object, hold));
            }
        }
        None
    }

    /// The entry of listener `id`, of either plane, taken off the table; `None` when no listener
    /// has that id.
    fn take(&self, id: u64) -> Option<Entry> {
        lock(&self.listeners)
            .every_row()
            .find_map(|row| row.entry.take_if(|entry| entry.id == id))
    }

    /// Any entry left in the table, taken off it.
    fn take_any(&self) -> Option<Entry> {
        lock(&self.listeners)
            .every_row()
            .find_map(|row| row.entry.take())
    }

    /// Put the listener whose owner holds the place at `object` in a free row of `plane`, holding
    /// its place for the hub, and tell `name` its id before the row can be read: the row's place
    /// among the plane's, which the listener's told bits are noted under while it replays
    /// (`wz_capi_port::told`), and which a listener that `replays` holds until
    /// [`Self::end_replay`] even past its undeclare. `None` when every row of the plane is held,
    /// the listener's closure let go of and its owner's place given back.
    ///
    /// # Safety
    /// `object` is a place of a [`ListenerPlace`] its owner filled and holds, and lets go of here
    /// when this answers `None`.
    unsafe fn admit(
        &self,
        plane: ToldPlane,
        object: *mut ListenerState,
        name: impl FnOnce(u64),
        replays: bool,
    ) -> Option<usize> {
        // SAFETY: the caller's: the owner holds the place.
        let held = unsafe { hold_entity::<ListenerState, Listener>(object) };
        let mut table = lock(&self.listeners);
        let id = table.last_id.wrapping_add(1);
        let rows = table.rows_mut(plane);
        if let Some(slot) = free_row(rows) {
            if let Some(row) = rows.get_mut(slot) {
                name(id);
                row.entry = Some(Entry { id, object, held });
                row.replaying = replays;
                table.last_id = id;
                return Some(slot);
            }
        }
        drop(table);
        retire_entry(Entry { id, object, held });
        // SAFETY: the caller's: the owner lets go of the place once, here, with no other hold left.
        unsafe { retire_entity::<ListenerState, Listener>(object) };
        None
    }

    /// The replay of the listener of row `slot` of `plane` ended and the engine forgot what it
    /// was told (`SessionEngine::forget_told`): the row is free for another listener once its own
    /// went.
    fn end_replay(&self, plane: ToldPlane, slot: usize) {
        if let Some(row) = lock(&self.listeners).rows_mut(plane).get_mut(slot) {
            row.replaying = false;
        }
    }

    /// A row of a face that arrived or left: tell every listener, in pico's order.
    ///
    /// Arrival is the transport, at the face's first row, then each link; departure is each
    /// link, then the transport, at the face's last row. A face with no link is told by one row,
    /// which is its transport alone.
    ///
    /// The rows the session's queue lost after `row` (`row.lost_after`) happened after it, so they
    /// are told after it, against the rows that stand, which `standing` reads one at a time
    /// ([`Self::catch_up`]).
    pub(crate) fn on_face_row(
        &self,
        kind: FaceEventKind,
        row: &FaceLinkRow,
        standing: impl Fn(usize) -> Option<FaceLinkRow>,
    ) {
        let has_link = row.links > 0;
        match kind {
            FaceEventKind::Up => {
                // A row a catch-up told came ahead of it, as it is, is not told again.
                let news = lock(&self.told).came(row);
                if news && row.link == 0 {
                    self.fan(ToldPlane::Transports, Z_SAMPLE_KIND_PUT, row);
                }
                if news && has_link {
                    self.fan(ToldPlane::Links, Z_SAMPLE_KIND_PUT, row);
                }
            }
            FaceEventKind::Down => {
                lock(&self.told).went(&ToldKey::of_row(row));
                if has_link {
                    self.fan(ToldPlane::Links, Z_SAMPLE_KIND_DELETE, row);
                }
                if row.is_last_of_face() {
                    self.fan(ToldPlane::Transports, Z_SAMPLE_KIND_DELETE, row);
                }
            }
        }
        if row.lost_after > 0 {
            self.catch_up(&standing);
        }
    }

    /// The row the hub keeps at `at`, copied out so no lock is held past it; `None` past the last.
    fn told_at(&self, at: usize) -> Option<Option<FaceLinkRow>> {
        lock(&self.told).rows.get(at).cloned()
    }

    /// Tell every listener what rows the session's queue lost changed, against the rows that stand,
    /// which `standing` reads one at a time: each row told came that no longer stands as it was
    /// told is told left, the transport after its face's last kept row, then each row that stands
    /// and was not told is told came, the transport before its face's first. A listener whose
    /// history is being replayed holds what this tells as it holds any row.
    fn catch_up(&self, standing: &impl Fn(usize) -> Option<FaceLinkRow>) {
        let mut at: usize = 0;
        while let Some(held) = self.told_at(at) {
            at = at.saturating_add(1);
            let Some(row) = held else {
                continue;
            };
            if stands_as_told(&row, standing) {
                continue;
            }
            let face_left = {
                let mut told = lock(&self.told);
                told.went(&ToldKey::of_row(&row));
                !told.holds_face_of(&row)
            };
            if row.links > 0 {
                self.fan(ToldPlane::Links, Z_SAMPLE_KIND_DELETE, &row);
            }
            if face_left {
                self.fan(ToldPlane::Transports, Z_SAMPLE_KIND_DELETE, &row);
            }
        }
        let mut at: usize = 0;
        while let Some(row) = standing(at) {
            at = at.saturating_add(1);
            let face_told = {
                let mut told = lock(&self.told);
                if told.place_of(&ToldKey::of_row(&row)).is_some() {
                    continue;
                }
                let face_told = told.holds_face_of(&row);
                told.came(&row);
                face_told
            };
            if !face_told {
                self.fan(ToldPlane::Transports, Z_SAMPLE_KIND_PUT, &row);
            }
            if row.links > 0 {
                self.fan(ToldPlane::Links, Z_SAMPLE_KIND_PUT, &row);
            }
        }
    }

    /// Tell each listener of `plane` that `row` came or left, as `kind` says: a transport listener
    /// its face's transport, a link listener its link when it is filtered to none or to its
    /// transport.
    fn fan(&self, plane: ToldPlane, kind: z_sample_kind_t, row: &FaceLinkRow) {
        let key = key_of_row(plane, row);
        let mut at = 0;
        while let Some((object, hold)) = self.next_listener(plane, &mut at) {
            // SAFETY: `hold` keeps the place, and so its listener, standing for the call.
            let listener = unsafe { listener_at(object) };
            if listener.wants(row) {
                listener
                    .delivery
                    .deliver(key, kind == Z_SAMPLE_KIND_PUT, || {
                        event_of_row(plane, kind, row, self.group())
                    });
            }
            drop(hold);
        }
    }

    /// A listener of `plane` in a place of `engine`'s session for the plane, its owner holding
    /// it: its delivery to `closure` holding what arrives while it replays its `history`, `filter`
    /// kept with it, and its closure counted in the place. `None` when every place of the plane is
    /// held; the closure is let go of then, which runs its `drop(context)`.
    fn place_listener(
        hub: &Strong<Self>,
        engine: &crate::session::EngineHold,
        plane: ToldPlane,
        history: bool,
        filter: Option<([u8; 16], bool)>,
        closure: CClosure<EventCall>,
    ) -> Option<*mut ListenerState> {
        let kind = match plane {
            ToldPlane::Transports => Kind::TransportEventsListener,
            ToldPlane::Links => Kind::LinkEventsListener,
        };
        let place = Slot::<ListenerPlace>::take_entity(engine, kind)?;
        let state = ListenerState {
            hub: hub.clone(),
            id: 0,
        };
        let write_state = |at: NonNull<ListenerState>| {
            // SAFETY: the place `write_at` hands is valid for writes of the state and holds none.
            unsafe { at.as_ptr().write(state) }
        };
        let write_kept = |at: NonNull<Listener>| {
            let listener = at.as_ptr();
            // SAFETY: the place is the listener's, valid for its delivery and filter, holding
            // none, never moved while the listener's place stands; each field is written once
            // through a pointer to it, not null as it is inside the place; the door erased a
            // callback of `plane`.
            unsafe {
                Delivery::write_in(
                    NonNull::new_unchecked(addr_of_mut!((*listener).delivery)),
                    plane,
                    closure,
                    history,
                );
                addr_of_mut!((*listener).filter).write(filter);
            }
        };
        let write = |at: *mut ListenerPlace| {
            // SAFETY: the slot hands a place valid for writes of a `ListenerPlace`, holding none;
            // the two writers write its state and what it keeps whole.
            unsafe { Answering::write_at(at, write_state, write_kept) }
        };
        // SAFETY: `write` leaves a whole `ListenerPlace` in the place it is handed.
        let object = unsafe { place.fill_in_place(write) }.cast::<ListenerState>();
        // SAFETY: the place was filled just above and its owner holds it; the closure is counted
        // in it before anything can call it or let it go.
        unsafe { count_closure(object) };
        Some(object)
    }

    /// Declare a listener of `plane` in a place of `engine`'s session, replaying the rows that stand
    /// first when `history` is set; `filter` narrows a link listener to one transport. Its object,
    /// which its owner lets go of with [`release_listener`]. `_Z_ERR_SYSTEM_OUT_OF_MEMORY` when
    /// every place or every row of the plane is held (the session's
    /// `MAX_TRANSPORT_EVENTS_LISTENERS` or `MAX_LINK_EVENTS_LISTENERS`); the closure is let go of
    /// then, which runs its `drop(context)`.
    fn declare(
        hub: &Strong<Self>,
        engine: &crate::session::EngineHold,
        plane: ToldPlane,
        history: bool,
        filter: Option<([u8; 16], bool)>,
        closure: CClosure<EventCall>,
    ) -> Result<*mut ListenerState, ZResult> {
        let Some(object) = Self::place_listener(hub, engine, plane, history, filter, closure)
        else {
            return Err(Z_ERR_SYSTEM_OUT_OF_MEMORY);
        };
        // Registered BEFORE the rows are read, so a row that arrives in between is queued rather
        // than missed.
        // SAFETY: the place was filled by `place_listener` and its owner holds it; the id is
        // written before the entry can be read.
        let Some(slot) = (unsafe { hub.admit(plane, object, |id| (*object).id = id, history) })
        else {
            return Err(Z_ERR_SYSTEM_OUT_OF_MEMORY);
        };
        if history {
            // SAFETY: the owner holds the place for the length of the replay.
            let listener = unsafe { listener_at(object) };
            let engine = crate::session::EngineHold::as_ref(engine);
            let group = hub.group();
            for row in rows(engine).filter(|row| listener.hears(row)) {
                if let Some(event) =
                    told(engine, group, (plane, slot), true, &key_of_row(plane, &row))
                {
                    listener.delivery.call(event);
                }
            }
            listener.delivery.finish_replay(
                |came, key| told(engine, group, (plane, slot), came, key),
                |_| converge(engine, group, plane, slot, listener),
            );
            SessionEngine::forget_told(engine, plane, slot);
            hub.end_replay(plane, slot);
        }
        Ok(object)
    }

    /// Take listener `id`, of either plane, off the hub and let go of it; nothing when no listener
    /// has that id.
    fn undeclare(&self, id: u64) {
        if let Some(entry) = self.take(id) {
            retire_entry(entry);
        }
    }

    /// Let go of every listener, which releases their C contexts.
    pub(crate) fn shutdown(&self) {
        while let Some(entry) = self.take_any() {
            retire_entry(entry);
        }
    }
}

// ===========================================================================
// closures
// ===========================================================================

/// Generates one pico closure family — `z_owned_closure_<x>_t` and its loaned
/// and moved forms, the constructor, and the eight functions around them.
///
/// pico defines all four connectivity families with ONE macro
/// (`_Z_OWNED_FUNCTIONS_CLOSURE_IMPL`), and the layout is the ABI: `z_closure`
/// in C11 is a macro that writes `{ context, call, drop }` straight into the
/// struct, so a family that differed from its siblings would be a silent memory
/// corruption and not a link error. One definition here for the same reason.
macro_rules! closure_family {
    (
        arg: $arg:ty,
        owned: $owned:ident, loaned: $loaned:ident, moved: $moved:ident,
        ctor: $ctor:ident, call: $call:ident, drop: $drop:ident, loan: $loan:ident,
        mv: $mv:ident, take: $take:ident, check: $check:ident, null: $null:ident $(,)?
    ) => {
        /// Owned closure (24 B measured): `{ context, call, drop }`.
        #[repr(C)]
        pub struct $owned {
            pub(crate) context: *mut c_void,
            pub(crate) call: Callback<$arg>,
            pub(crate) drop: z_closure_drop_callback_t,
        }

        /// Loaned closure, same layout.
        #[repr(C)]
        pub struct $loaned {
            pub(crate) context: *mut c_void,
            pub(crate) call: Callback<$arg>,
            pub(crate) drop: z_closure_drop_callback_t,
        }

        /// Moved closure.
        #[repr(C)]
        pub struct $moved {
            pub(crate) _this: $owned,
        }

        impl $owned {
            fn null_value() -> Self {
                Self {
                    context: core::ptr::null_mut(),
                    call: None,
                    drop: None,
                }
            }
        }

        /// Build a closure from its parts.
        #[no_mangle]
        pub unsafe extern "C" fn $ctor(
            closure: *mut $owned,
            call: Callback<$arg>,
            drop: z_closure_drop_callback_t,
            context: *mut c_void,
        ) -> ZResult {
            if closure.is_null() {
                return Z_ERR_NULL;
            }
            *closure = $owned {
                context,
                call,
                drop,
            };
            Z_OK
        }

        /// Call a closure with `arg`.
        #[no_mangle]
        pub unsafe extern "C" fn $call(closure: *const $loaned, arg: *mut $arg) {
            if closure.is_null() {
                return;
            }
            if let Some(call) = (*closure).call {
                call(arg, (*closure).context);
            }
        }

        /// Release a closure: run its `drop(context)` once and null it.
        #[no_mangle]
        pub unsafe extern "C" fn $drop(closure: *mut $moved) {
            if closure.is_null() {
                return;
            }
            let taken = core::mem::replace(&mut (*closure)._this, $owned::null_value());
            if let Some(dropfn) = taken.drop {
                dropfn(taken.context);
            }
        }

        /// Borrow a closure — offset-0 identity.
        #[no_mangle]
        pub unsafe extern "C" fn $loan(closure: *const $owned) -> *const $loaned {
            closure as *const $loaned
        }

        /// Move-cast a closure.
        #[no_mangle]
        pub unsafe extern "C" fn $mv(closure: *mut $owned) -> *mut $moved {
            closure as *mut $moved
        }

        /// Take a moved closure, nulling the source so its `drop` runs once.
        #[no_mangle]
        pub unsafe extern "C" fn $take(closure: *mut $owned, src: *mut $moved) {
            if closure.is_null() || src.is_null() {
                return;
            }
            *closure = core::mem::replace(&mut (*src)._this, $owned::null_value());
        }

        /// Whether a closure carries a callback.
        #[no_mangle]
        pub unsafe extern "C" fn $check(closure: *const $owned) -> bool {
            !closure.is_null() && (*closure).call.is_some()
        }

        /// Null a closure.
        #[no_mangle]
        pub unsafe extern "C" fn $null(closure: *mut $owned) {
            if !closure.is_null() {
                *closure = $owned::null_value();
            }
        }
    };
}

closure_family! {
    arg: z_loaned_transport_t,
    owned: z_owned_closure_transport_t, loaned: z_loaned_closure_transport_t,
    moved: z_moved_closure_transport_t,
    ctor: z_closure_transport, call: z_closure_transport_call,
    drop: z_closure_transport_drop, loan: z_closure_transport_loan,
    mv: z_closure_transport_move, take: z_closure_transport_take,
    check: z_internal_closure_transport_check, null: z_internal_closure_transport_null,
}

closure_family! {
    arg: z_loaned_link_t,
    owned: z_owned_closure_link_t, loaned: z_loaned_closure_link_t,
    moved: z_moved_closure_link_t,
    ctor: z_closure_link, call: z_closure_link_call,
    drop: z_closure_link_drop, loan: z_closure_link_loan,
    mv: z_closure_link_move, take: z_closure_link_take,
    check: z_internal_closure_link_check, null: z_internal_closure_link_null,
}

closure_family! {
    arg: z_loaned_transport_event_t,
    owned: z_owned_closure_transport_event_t, loaned: z_loaned_closure_transport_event_t,
    moved: z_moved_closure_transport_event_t,
    ctor: z_closure_transport_event, call: z_closure_transport_event_call,
    drop: z_closure_transport_event_drop, loan: z_closure_transport_event_loan,
    mv: z_closure_transport_event_move, take: z_closure_transport_event_take,
    check: z_internal_closure_transport_event_check,
    null: z_internal_closure_transport_event_null,
}

closure_family! {
    arg: z_loaned_link_event_t,
    owned: z_owned_closure_link_event_t, loaned: z_loaned_closure_link_event_t,
    moved: z_moved_closure_link_event_t,
    ctor: z_closure_link_event, call: z_closure_link_event_call,
    drop: z_closure_link_event_drop, loan: z_closure_link_event_loan,
    mv: z_closure_link_event_move, take: z_closure_link_event_take,
    check: z_internal_closure_link_event_check,
    null: z_internal_closure_link_event_null,
}

/// Adopt a moved closure's parts and null the source: from here the returned
/// value owns the `drop(context)`.
///
/// # Safety
/// `callback` must be valid; `read` must project its fields.
unsafe fn adopt<T, O>(
    callback: *mut T,
    read: impl FnOnce(&mut T) -> (*mut c_void, Callback<O>, z_closure_drop_callback_t),
    clear: impl FnOnce(&mut T),
) -> CClosure<Callback<O>> {
    let (context, call, drop) = read(&mut *callback);
    clear(&mut *callback);
    CClosure::uncounted(context, call, drop)
}

// ===========================================================================
// the value families
// ===========================================================================

/// Generates the nine exports pico's `_Z_OWNED_FUNCTIONS_VALUE_IMPL` makes for a
/// value type, over [`ConnValue`].
macro_rules! value_family {
    (
        value: $val:ty, owned: $owned:ident, loaned: $loaned:ident, moved: $moved:ident,
        null: $null:ident, check: $check:ident, loan: $loan:ident, loan_mut: $loan_mut:ident,
        mv: $mv:ident, take: $take:ident, take_from_loaned: $tfl:ident,
        clone: $clone:ident, drop: $drop:ident $(,)?
    ) => {
        /// Null an owned value.
        #[no_mangle]
        pub unsafe extern "C" fn $null(obj: *mut $owned) {
            if !obj.is_null() {
                core::ptr::write(&mut (*obj)._val, <$val as ConnValue>::null());
            }
        }

        /// Whether an owned value holds a peer.
        #[no_mangle]
        pub unsafe extern "C" fn $check(obj: *const $owned) -> bool {
            !obj.is_null() && <$val as ConnValue>::is_set(&(*obj)._val)
        }

        /// Borrow an owned value — the value itself.
        #[no_mangle]
        pub unsafe extern "C" fn $loan(obj: *const $owned) -> *const $loaned {
            if obj.is_null() {
                return core::ptr::null();
            }
            &(*obj)._val as *const $val as *const $loaned
        }

        /// Borrow an owned value mutably.
        #[no_mangle]
        pub unsafe extern "C" fn $loan_mut(obj: *mut $owned) -> *mut $loaned {
            if obj.is_null() {
                return core::ptr::null_mut();
            }
            &mut (*obj)._val as *mut $val as *mut $loaned
        }

        /// Move-cast an owned value.
        #[no_mangle]
        pub unsafe extern "C" fn $mv(obj: *mut $owned) -> *mut $moved {
            obj as *mut $moved
        }

        /// Take a moved value, nulling the source.
        #[no_mangle]
        pub unsafe extern "C" fn $take(obj: *mut $owned, src: *mut $moved) {
            if obj.is_null() || src.is_null() {
                return;
            }
            core::ptr::write(&mut (*obj)._val, <$val as ConnValue>::null());
            core::mem::swap(&mut (*obj)._val, &mut (*src)._this._val);
        }

        /// Move a loaned value into an owned one, nulling the source.
        #[no_mangle]
        pub unsafe extern "C" fn $tfl(obj: *mut $owned, src: *mut $loaned) -> ZResult {
            if obj.is_null() || src.is_null() {
                return Z_ERR_NULL;
            }
            let src = &mut *(src as *mut $val);
            core::ptr::write(&mut (*obj)._val, <$val as ConnValue>::null());
            core::mem::swap(&mut (*obj)._val, src);
            Z_OK
        }

        /// Copy a loaned value into an owned one.
        #[no_mangle]
        pub unsafe extern "C" fn $clone(obj: *mut $owned, src: *const $loaned) -> ZResult {
            if obj.is_null() || src.is_null() {
                return Z_ERR_NULL;
            }
            core::ptr::write(
                &mut (*obj)._val,
                <$val as ConnValue>::duplicate(&*(src as *const $val)),
            );
            Z_OK
        }

        /// Release a moved value.
        #[no_mangle]
        pub unsafe extern "C" fn $drop(obj: *mut $moved) {
            if !obj.is_null() {
                <$val as ConnValue>::clear(&mut (*obj)._this._val);
            }
        }
    };
}

// pico's loaned type IS the value, so each loaned name below is an alias.
value_family! {
    value: z_loaned_transport_t, owned: z_owned_transport_t, loaned: z_loaned_transport_t,
    moved: z_moved_transport_t,
    null: z_internal_transport_null, check: z_internal_transport_check,
    loan: z_transport_loan, loan_mut: z_transport_loan_mut,
    mv: z_transport_move, take: z_transport_take, take_from_loaned: z_transport_take_from_loaned,
    clone: z_transport_clone, drop: z_transport_drop,
}

value_family! {
    value: z_loaned_link_t, owned: z_owned_link_t, loaned: z_loaned_link_t,
    moved: z_moved_link_t,
    null: z_internal_link_null, check: z_internal_link_check,
    loan: z_link_loan, loan_mut: z_link_loan_mut,
    mv: z_link_move, take: z_link_take, take_from_loaned: z_link_take_from_loaned,
    clone: z_link_clone, drop: z_link_drop,
}

value_family! {
    value: z_loaned_transport_event_t, owned: z_owned_transport_event_t,
    loaned: z_loaned_transport_event_t, moved: z_moved_transport_event_t,
    null: z_internal_transport_event_null, check: z_internal_transport_event_check,
    loan: z_transport_event_loan, loan_mut: z_transport_event_loan_mut,
    mv: z_transport_event_move, take: z_transport_event_take,
    take_from_loaned: z_transport_event_take_from_loaned,
    clone: z_transport_event_clone, drop: z_transport_event_drop,
}

value_family! {
    value: z_loaned_link_event_t, owned: z_owned_link_event_t,
    loaned: z_loaned_link_event_t, moved: z_moved_link_event_t,
    null: z_internal_link_event_null, check: z_internal_link_event_check,
    loan: z_link_event_loan, loan_mut: z_link_event_loan_mut,
    mv: z_link_event_move, take: z_link_event_take,
    take_from_loaned: z_link_event_take_from_loaned,
    clone: z_link_event_clone, drop: z_link_event_drop,
}

// ===========================================================================
// accessors
// ===========================================================================

/// The peer's zid (pico `z_transport_zid`).
#[no_mangle]
pub unsafe extern "C" fn z_transport_zid(transport: *const z_loaned_transport_t) -> z_id_t {
    if transport.is_null() {
        return z_id_t::empty();
    }
    (*transport).zid
}

/// The peer's role as a `z_whatami_t` bitmask (pico `z_transport_whatami`).
#[no_mangle]
pub unsafe extern "C" fn z_transport_whatami(
    transport: *const z_loaned_transport_t,
) -> z_whatami_t {
    if transport.is_null() {
        return 0;
    }
    (*transport).whatami
}

/// Whether QoS was negotiated (pico `z_transport_is_qos`; always `false`).
#[no_mangle]
pub unsafe extern "C" fn z_transport_is_qos(transport: *const z_loaned_transport_t) -> bool {
    !transport.is_null() && (*transport).is_qos
}

/// Whether the transport is multicast (pico `z_transport_is_multicast`).
#[no_mangle]
pub unsafe extern "C" fn z_transport_is_multicast(transport: *const z_loaned_transport_t) -> bool {
    !transport.is_null() && (*transport).is_multicast
}

/// Whether shared memory was negotiated (pico `z_transport_is_shm`; always
/// `false`).
#[no_mangle]
pub unsafe extern "C" fn z_transport_is_shm(transport: *const z_loaned_transport_t) -> bool {
    !transport.is_null() && (*transport).is_shm
}

/// The peer's zid (pico `z_link_zid`).
#[no_mangle]
pub unsafe extern "C" fn z_link_zid(link: *const z_loaned_link_t) -> z_id_t {
    if link.is_null() {
        return z_id_t::empty();
    }
    (*link).zid
}

/// Copy a link string into an owned string; the null string stays null.
unsafe fn copy_text(text: &ConnText, out: *mut z_owned_string_t) -> ZResult {
    if out.is_null() {
        return Z_ERR_NULL;
    }
    *out = z_owned_string_t::null_value();
    if text.is_null() {
        return Z_OK;
    }
    store_owned_string(out, text.as_bytes())
}

/// This end's locator (pico `z_link_src`).
#[no_mangle]
pub unsafe extern "C" fn z_link_src(
    link: *const z_loaned_link_t,
    str_out: *mut z_owned_string_t,
) -> ZResult {
    if link.is_null() {
        return Z_ERR_NULL;
    }
    copy_text(&(*link).src, str_out)
}

/// The peer end's locator (pico `z_link_dst`).
#[no_mangle]
pub unsafe extern "C" fn z_link_dst(
    link: *const z_loaned_link_t,
    str_out: *mut z_owned_string_t,
) -> ZResult {
    if link.is_null() {
        return Z_ERR_NULL;
    }
    copy_text(&(*link).dst, str_out)
}

/// The link's MTU (pico `z_link_mtu`).
#[no_mangle]
pub unsafe extern "C" fn z_link_mtu(link: *const z_loaned_link_t) -> u16 {
    if link.is_null() {
        return 0;
    }
    (*link).mtu
}

/// Whether the link carries a byte stream (pico `z_link_is_streamed`).
#[no_mangle]
pub unsafe extern "C" fn z_link_is_streamed(link: *const z_loaned_link_t) -> bool {
    !link.is_null() && (*link).is_streamed
}

/// Whether the link delivers reliably (pico `z_link_is_reliable`).
#[no_mangle]
pub unsafe extern "C" fn z_link_is_reliable(link: *const z_loaned_link_t) -> bool {
    !link.is_null() && (*link).is_reliable
}

/// The link's multicast group (pico `z_link_group`): the null string, as pico's
/// stub answers.
#[no_mangle]
pub unsafe extern "C" fn z_link_group(
    _link: *const z_loaned_link_t,
    str_out: *mut z_owned_string_t,
) {
    if !str_out.is_null() {
        *str_out = z_owned_string_t::null_value();
    }
}

/// The link's authenticated identity (pico `z_link_auth_identifier`): the null
/// string, as pico's stub answers.
#[no_mangle]
pub unsafe extern "C" fn z_link_auth_identifier(
    _link: *const z_loaned_link_t,
    str_out: *mut z_owned_string_t,
) {
    if !str_out.is_null() {
        *str_out = z_owned_string_t::null_value();
    }
}

/// The network interfaces the link uses (pico `z_link_interfaces`): the null
/// array, as pico's stub answers.
#[no_mangle]
pub unsafe extern "C" fn z_link_interfaces(
    _link: *const z_loaned_link_t,
    interfaces_out: *mut z_owned_string_array_t,
) {
    if !interfaces_out.is_null() {
        *interfaces_out = z_owned_string_array_t::null_value();
    }
}

/// The link's priority range (pico `z_link_priorities`): `false`, as pico's
/// stub answers.
#[no_mangle]
pub unsafe extern "C" fn z_link_priorities(
    _link: *const z_loaned_link_t,
    _min_out: *mut u8,
    _max_out: *mut u8,
) -> bool {
    false
}

/// The link's reliability (pico `z_link_reliability`): `false`, as pico's stub
/// answers.
#[no_mangle]
pub unsafe extern "C" fn z_link_reliability(
    _link: *const z_loaned_link_t,
    _reliability_out: *mut c_int,
) -> bool {
    false
}

/// The event's kind (pico `z_transport_event_kind`).
#[no_mangle]
pub unsafe extern "C" fn z_transport_event_kind(
    event: *const z_loaned_transport_event_t,
) -> z_sample_kind_t {
    if event.is_null() {
        return Z_SAMPLE_KIND_PUT;
    }
    (*event).kind
}

/// The transport inside an event (pico `z_transport_event_transport`).
#[no_mangle]
pub unsafe extern "C" fn z_transport_event_transport(
    event: *const z_loaned_transport_event_t,
) -> *const z_loaned_transport_t {
    if event.is_null() {
        return core::ptr::null();
    }
    &(*event).transport
}

/// The transport inside an event, mutably (pico
/// `z_transport_event_transport_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_transport_event_transport_mut(
    event: *mut z_loaned_transport_event_t,
) -> *mut z_loaned_transport_t {
    if event.is_null() {
        return core::ptr::null_mut();
    }
    &mut (*event).transport
}

/// The event's kind (pico `z_link_event_kind`).
#[no_mangle]
pub unsafe extern "C" fn z_link_event_kind(event: *const z_loaned_link_event_t) -> z_sample_kind_t {
    if event.is_null() {
        return Z_SAMPLE_KIND_PUT;
    }
    (*event).kind
}

/// The link inside an event (pico `z_link_event_link`).
#[no_mangle]
pub unsafe extern "C" fn z_link_event_link(
    event: *const z_loaned_link_event_t,
) -> *const z_loaned_link_t {
    if event.is_null() {
        return core::ptr::null();
    }
    &(*event).link
}

/// The link inside an event, mutably (pico `z_link_event_link_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_link_event_link_mut(
    event: *mut z_loaned_link_event_t,
) -> *mut z_loaned_link_t {
    if event.is_null() {
        return core::ptr::null_mut();
    }
    &mut (*event).link
}

// ===========================================================================
// enumeration
// ===========================================================================

/// The hub of the session behind `zs`, if it is a live session this ABI opened.
unsafe fn hub_of<'a>(
    zs: *const z_loaned_session_t,
) -> Option<(&'a PicoSessionHandle, &'a Strong<Connectivity>)> {
    let handle = session_handle(zs)?;
    Some((handle, &handle.ext.connectivity))
}

/// Call `closure` once per connected transport (pico `z_info_transports`).
///
/// The closure is consumed on every path, as pico's is.
#[no_mangle]
pub unsafe extern "C" fn z_info_transports(
    zs: *const z_loaned_session_t,
    callback: *mut z_moved_closure_transport_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        let closure: CClosure<Callback<z_loaned_transport_t>> = adopt(
            callback,
            |c| (c._this.context, c._this.call, c._this.drop),
            |c| c._this = z_owned_closure_transport_t::null_value(),
        );
        let Some(handle) = session_handle(zs) else {
            return Z_ERR_NULL;
        };
        for row in rows(engine_ref(handle)).filter(|row| row.link == 0) {
            let mut transport = transport_of_row(&row);
            if let Some(call) = closure.call {
                call(&mut transport, closure.context.0);
            }
        }
        Z_OK
    })
}

/// Options of `z_info_links` (pico `z_info_links_options_t`, 8 B): the
/// transport to restrict the links to, which the call takes ownership of.
#[repr(C)]
pub struct z_info_links_options_t {
    pub transport: *mut z_moved_transport_t,
}

/// Default `z_info_links` options (pico `z_info_links_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_info_links_options_default(options: *mut z_info_links_options_t) {
    if !options.is_null() {
        (*options).transport = core::ptr::null_mut();
    }
}

/// Take the transport filter out of an options' moved transport, releasing the
/// transport either way; `Err` when it was handed over empty.
unsafe fn take_filter(transport: *mut z_moved_transport_t) -> Result<Option<([u8; 16], bool)>, ()> {
    if transport.is_null() {
        return Ok(None);
    }
    let value = &mut (*transport)._this._val;
    let filter = if value.is_set() {
        Ok(Some((value.zid.id, value.is_multicast)))
    } else {
        Err(())
    };
    value.clear();
    filter
}

/// Call `closure` once per connected link (pico `z_info_links`), optionally
/// restricted to one transport.
///
/// The closure and the transport filter are consumed on every path.
#[no_mangle]
pub unsafe extern "C" fn z_info_links(
    zs: *const z_loaned_session_t,
    callback: *mut z_moved_closure_link_t,
    options: *mut z_info_links_options_t,
) -> ZResult {
    guarded(|| {
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        let closure: CClosure<Callback<z_loaned_link_t>> = adopt(
            callback,
            |c| (c._this.context, c._this.call, c._this.drop),
            |c| c._this = z_owned_closure_link_t::null_value(),
        );
        let transport = if options.is_null() {
            core::ptr::null_mut()
        } else {
            (*options).transport
        };
        let filter = match take_filter(transport) {
            Ok(filter) => filter,
            Err(()) => return Z_EINVAL,
        };
        let Some(handle) = session_handle(zs) else {
            return Z_ERR_NULL;
        };
        let group = handle.ext.connectivity.group();
        for row in rows(engine_ref(handle)) {
            if let Some((zid, multicast)) = filter {
                if zid != row.zid || multicast != row.is_multicast {
                    continue;
                }
            }
            let mut held = HeldLink(link_of_row(&row, group));
            if let Some(call) = closure.call {
                call(&mut held.0, closure.context.0);
            }
        }
        Z_OK
    })
}

// ===========================================================================
// listeners
// ===========================================================================

/// Options of the transport listener (pico
/// `z_transport_events_listener_options_t`, 1 B).
#[repr(C)]
pub struct z_transport_events_listener_options_t {
    /// Replay the current transports as `PUT` events first.
    pub history: bool,
}

/// Options of the link listener (pico `z_link_events_listener_options_t`, 16 B).
#[repr(C)]
pub struct z_link_events_listener_options_t {
    /// Replay the current links as `PUT` events first.
    pub history: bool,
    /// Restrict the listener to one transport; the call takes ownership of it.
    pub transport: *mut z_moved_transport_t,
}

/// Default transport listener options (pico
/// `z_transport_events_listener_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_transport_events_listener_options_default(
    options: *mut z_transport_events_listener_options_t,
) {
    if !options.is_null() {
        (*options).history = false;
    }
}

/// Default link listener options (pico `z_link_events_listener_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_link_events_listener_options_default(
    options: *mut z_link_events_listener_options_t,
) {
    if !options.is_null() {
        (*options).history = false;
        (*options).transport = core::ptr::null_mut();
    }
}

/// Undeclare the listener of either plane whose state is at `object` and let go of its handle:
/// taken off its hub, its closure let go of once no call is running it (which runs its
/// `drop(context)`), and its state dropped; the place goes back with the last of the handle and
/// a dispatch in flight.
///
/// # Safety
/// `object` is a live handle [`Connectivity::declare`] answered, let go of once, here.
unsafe fn release_listener(object: *mut ListenerState) {
    // SAFETY: the caller's: the state stands until `retire_entity` below.
    unsafe { (*object).hub.undeclare((*object).id) };
    // SAFETY: the caller's; the owner lets go of the place once, here.
    unsafe { retire_entity::<ListenerState, Listener>(object) };
}

/// Generates the handle functions of one listener family: the owned, loaned and
/// moved forms and the six exports around them.
macro_rules! listener_family {
    (
        owned: $owned:ident, loaned: $loaned:ident, moved: $moved:ident,
        null: $null:ident, check: $check:ident, loan: $loan:ident, loan_mut: $loan_mut:ident,
        mv: $mv:ident, take: $take:ident $(,)?
    ) => {
        /// Owned listener (40 B measured): our handle in slot 0, zero padding to
        /// the reference size.
        #[repr(C)]
        pub struct $owned {
            pub(crate) handle: *mut c_void,
            pub(crate) _pad: [*mut c_void; 4],
        }

        /// Loaned listener, same layout.
        #[repr(C)]
        pub struct $loaned {
            pub(crate) handle: *mut c_void,
            pub(crate) _pad: [*mut c_void; 4],
        }

        /// Moved listener.
        #[repr(C)]
        pub struct $moved {
            pub(crate) _this: $owned,
        }

        impl $owned {
            fn null_value() -> Self {
                Self {
                    handle: core::ptr::null_mut(),
                    _pad: [core::ptr::null_mut(); 4],
                }
            }

            fn of(handle: *mut c_void) -> Self {
                Self {
                    handle,
                    _pad: [core::ptr::null_mut(); 4],
                }
            }
        }

        /// Null an owned listener.
        #[no_mangle]
        pub unsafe extern "C" fn $null(listener: *mut $owned) {
            if !listener.is_null() {
                *listener = $owned::null_value();
            }
        }

        /// Whether an owned listener is declared.
        #[no_mangle]
        pub unsafe extern "C" fn $check(listener: *const $owned) -> bool {
            !listener.is_null() && !(*listener).handle.is_null()
        }

        /// Borrow an owned listener.
        #[no_mangle]
        pub unsafe extern "C" fn $loan(listener: *const $owned) -> *const $loaned {
            listener as *const $loaned
        }

        /// Borrow an owned listener mutably.
        #[no_mangle]
        pub unsafe extern "C" fn $loan_mut(listener: *mut $owned) -> *mut $loaned {
            listener as *mut $loaned
        }

        /// Move-cast an owned listener.
        #[no_mangle]
        pub unsafe extern "C" fn $mv(listener: *mut $owned) -> *mut $moved {
            listener as *mut $moved
        }

        /// Take a moved listener, nulling the source.
        #[no_mangle]
        pub unsafe extern "C" fn $take(listener: *mut $owned, src: *mut $moved) {
            if listener.is_null() || src.is_null() {
                return;
            }
            *listener = core::mem::replace(&mut (*src)._this, $owned::null_value());
        }
    };
}

listener_family! {
    owned: z_owned_transport_events_listener_t, loaned: z_loaned_transport_events_listener_t,
    moved: z_moved_transport_events_listener_t,
    null: z_internal_transport_events_listener_null,
    check: z_internal_transport_events_listener_check,
    loan: z_transport_events_listener_loan, loan_mut: z_transport_events_listener_loan_mut,
    mv: z_transport_events_listener_move, take: z_transport_events_listener_take,
}

listener_family! {
    owned: z_owned_link_events_listener_t, loaned: z_loaned_link_events_listener_t,
    moved: z_moved_link_events_listener_t,
    null: z_internal_link_events_listener_null,
    check: z_internal_link_events_listener_check,
    loan: z_link_events_listener_loan, loan_mut: z_link_events_listener_loan_mut,
    mv: z_link_events_listener_move, take: z_link_events_listener_take,
}

/// Declare a transport listener (pico `z_declare_transport_events_listener`).
///
/// A null or closed session refuses with `_Z_ERR_SESSION_CLOSED`. As pico does,
/// a NULL session is refused BEFORE the closure is taken, so the caller still
/// owns it; a session that is closed is refused after. A session that holds as
/// many listeners as its `MAX_TRANSPORT_EVENTS_LISTENERS` admits refuses with
/// `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, the closure released.
#[no_mangle]
pub unsafe extern "C" fn z_declare_transport_events_listener(
    zs: *const z_loaned_session_t,
    listener: *mut z_owned_transport_events_listener_t,
    callback: *mut z_moved_closure_transport_event_t,
    options: *const z_transport_events_listener_options_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() || callback.is_null() {
            return Z_ERR_NULL;
        }
        *listener = z_owned_transport_events_listener_t::null_value();
        let Some((handle, hub)) = hub_of(zs) else {
            return Z_ERR_SESSION_CLOSED;
        };
        let closure = adopt(
            callback,
            |c| {
                let call = erase_transport_call(c._this.call);
                (c._this.context, call, c._this.drop)
            },
            |c| c._this = z_owned_closure_transport_event_t::null_value(),
        );
        if handle.drive.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        let history = !options.is_null() && (*options).history;
        let plane = ToldPlane::Transports;
        match Connectivity::declare(hub, engine_held(handle), plane, history, None, closure) {
            Ok(object) => {
                *listener = z_owned_transport_events_listener_t::of(object.cast());
                Z_OK
            }
            Err(refused) => refused,
        }
    })
}

/// Declare a transport listener with no handle (pico
/// `z_declare_background_transport_events_listener`): it lives as long as the
/// session.
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_transport_events_listener(
    zs: *const z_loaned_session_t,
    callback: *mut z_moved_closure_transport_event_t,
    options: *const z_transport_events_listener_options_t,
) -> ZResult {
    guarded(|| {
        let mut listener = z_owned_transport_events_listener_t::null_value();
        let rc = z_declare_transport_events_listener(zs, &mut listener, callback, options);
        if rc != Z_OK {
            return rc;
        }
        // The handle is let go of without undeclaring: the listener stays, its place held by the
        // hub until the session's end.
        retire_entity::<ListenerState, Listener>(listener.handle.cast::<ListenerState>());
        Z_OK
    })
}

/// Undeclare a transport listener (pico `z_undeclare_transport_events_listener`).
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_transport_events_listener(
    listener: *mut z_moved_transport_events_listener_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() {
            return Z_OK;
        }
        let object = core::mem::replace(&mut (*listener)._this.handle, core::ptr::null_mut());
        if !object.is_null() {
            release_listener(object.cast::<ListenerState>());
        }
        Z_OK
    })
}

/// Drop a transport listener (pico `z_transport_events_listener_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_transport_events_listener_drop(
    listener: *mut z_moved_transport_events_listener_t,
) {
    let _ = z_undeclare_transport_events_listener(listener);
}

/// Declare a link listener (pico `z_declare_link_events_listener`).
///
/// The moved transport in the options is consumed on every path. A transport it
/// holds nothing in refuses with `_Z_ERR_INVALID`, after the closure has been
/// taken and released. A session that holds as many link listeners as its
/// `MAX_LINK_EVENTS_LISTENERS` admits refuses with `_Z_ERR_SYSTEM_OUT_OF_MEMORY`,
/// the closure released.
#[no_mangle]
pub unsafe extern "C" fn z_declare_link_events_listener(
    zs: *const z_loaned_session_t,
    listener: *mut z_owned_link_events_listener_t,
    callback: *mut z_moved_closure_link_event_t,
    options: *mut z_link_events_listener_options_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() || callback.is_null() {
            return Z_ERR_NULL;
        }
        *listener = z_owned_link_events_listener_t::null_value();
        let Some((handle, hub)) = hub_of(zs) else {
            return Z_ERR_SESSION_CLOSED;
        };
        let closure = adopt(
            callback,
            |c| {
                let call = erase_link_call(c._this.call);
                (c._this.context, call, c._this.drop)
            },
            |c| c._this = z_owned_closure_link_event_t::null_value(),
        );
        let (history, transport) = if options.is_null() {
            (false, core::ptr::null_mut())
        } else {
            ((*options).history, (*options).transport)
        };
        let filter = match take_filter(transport) {
            Ok(filter) => filter,
            Err(()) => return Z_EINVAL,
        };
        if handle.drive.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        let plane = ToldPlane::Links;
        match Connectivity::declare(hub, engine_held(handle), plane, history, filter, closure) {
            Ok(object) => {
                *listener = z_owned_link_events_listener_t::of(object.cast());
                Z_OK
            }
            Err(refused) => refused,
        }
    })
}

/// Declare a link listener with no handle (pico
/// `z_declare_background_link_events_listener`): it lives as long as the
/// session.
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_link_events_listener(
    zs: *const z_loaned_session_t,
    callback: *mut z_moved_closure_link_event_t,
    options: *mut z_link_events_listener_options_t,
) -> ZResult {
    guarded(|| {
        let mut listener = z_owned_link_events_listener_t::null_value();
        let rc = z_declare_link_events_listener(zs, &mut listener, callback, options);
        if rc != Z_OK {
            return rc;
        }
        // The handle is let go of without undeclaring, as a background transport listener's.
        retire_entity::<ListenerState, Listener>(listener.handle.cast::<ListenerState>());
        Z_OK
    })
}

/// Undeclare a link listener (pico `z_undeclare_link_events_listener`).
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_link_events_listener(
    listener: *mut z_moved_link_events_listener_t,
) -> ZResult {
    guarded(|| {
        if listener.is_null() {
            return Z_OK;
        }
        let object = core::mem::replace(&mut (*listener)._this.handle, core::ptr::null_mut());
        if !object.is_null() {
            release_listener(object.cast::<ListenerState>());
        }
        Z_OK
    })
}

/// Drop a link listener (pico `z_link_events_listener_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_link_events_listener_drop(
    listener: *mut z_moved_link_events_listener_t,
) {
    let _ = z_undeclare_link_events_listener(listener);
}

/// The hub's own behaviour, over the tokio engine's registry as the engine a listener is declared
/// on: the hub reads the faces through the port, and a registry with no face is an engine with
/// none to replay.
/// Also the counting allocator of the library's test binary, which other modules' tests read
/// through `allocations`.
#[cfg(all(test, feature = "engine-tokio"))]
pub(crate) mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use std::sync::OnceLock;
    use wz_capi_core::faces::SharedSession;
    use wz_session_core::face::{FaceSnapshot, LinkSnapshot};
    use wz_session_core::link::LinkKind;

    use wz_capi_core::runtime::runtime_impl::TokioTime;

    /// What a test callback saw, in order, and how many times its context was
    /// released. Leaked, so a raw pointer to it can ride as the C `context`.
    #[derive(Default)]
    struct Log {
        seen: Mutex<Vec<String>>,
        released: AtomicUsize,
        /// A delivery the transport callback re-enters, to put an arrival in the
        /// middle of a replay.
        reenter: OnceLock<(Strong<Delivery>, u8)>,
    }

    fn log() -> &'static Log {
        Box::leak(Box::default())
    }

    fn ctx(log: &'static Log) -> *mut c_void {
        log as *const Log as *mut c_void
    }

    fn seen(log: &Log) -> Vec<String> {
        lock(&log.seen).clone()
    }

    fn kind_name(kind: z_sample_kind_t) -> &'static str {
        if kind == Z_SAMPLE_KIND_PUT {
            "PUT"
        } else {
            "DEL"
        }
    }

    unsafe extern "C" fn on_transport(
        event: *mut z_loaned_transport_event_t,
        context: *mut c_void,
    ) {
        let log = &*(context as *const Log);
        let event = &*event;
        lock(&log.seen).push(format!(
            "transport {} {}",
            kind_name(event.kind),
            event.transport.zid.id[0]
        ));
        if let Some((delivery, arriving)) = log.reenter.get() {
            // Only the REPLAYED peers (zids 1 and 2) re-enter. A delivery that
            // re-entered once the listener is live would call the closure from
            // inside the call that holds it, which is the self-wait pico has too
            // when a callback undeclares its own listener; the replay is the one
            // window in which a delivery is queued and not called.
            if matches!(event.transport.zid.id[0], 1 | 2) {
                arrive(delivery, Z_SAMPLE_KIND_PUT, *arriving);
            }
        }
    }

    unsafe extern "C" fn on_link(event: *mut z_loaned_link_event_t, context: *mut c_void) {
        let log = &*(context as *const Log);
        let event = &*event;
        lock(&log.seen).push(format!(
            "link {} {}",
            kind_name(event.kind),
            String::from_utf8_lossy(event.link.src.as_bytes())
        ));
    }

    unsafe extern "C" fn released(context: *mut c_void) {
        (*(context as *const Log))
            .released
            .fetch_add(1, Ordering::SeqCst);
    }

    fn transport_closure(log: &'static Log) -> CClosure<EventCall> {
        CClosure::uncounted(
            ctx(log),
            erase_transport_call(Some(on_transport)),
            Some(released),
        )
    }

    /// A replaying delivery to `log`'s transport closure, made in a box of its own with its locks
    /// made there, as a listener's is made in its place.
    fn replaying_delivery(log: &'static Log) -> Strong<Delivery> {
        let closure = transport_closure(log);
        let make = |place: NonNull<Delivery>| {
            // SAFETY: the place is the box's, valid for one delivery, holding none, never moved;
            // the closure reads transport events.
            unsafe { Delivery::write_in(place, ToldPlane::Transports, closure, true) }
        };
        // SAFETY: `make` makes the whole delivery in the place it is handed.
        unsafe { Strong::try_boxed_in(make) }.expect("the test's heap")
    }

    /// A session's hub in a box of its own.
    fn hub_in_heap() -> Strong<Connectivity> {
        Connectivity::new(Lent::try_boxed().expect("the test's heap"), None)
    }

    /// A transport listener of `hub`, as the door declares one.
    fn declare_transport(
        hub: &Strong<Connectivity>,
        engine: &crate::session::EngineHold,
        history: bool,
        closure: CClosure<EventCall>,
    ) -> Result<*mut ListenerState, ZResult> {
        let plane = ToldPlane::Transports;
        Connectivity::declare(hub, engine, plane, history, None, closure)
    }

    /// A link listener of `hub`, filtered to the transport `filter` names, as the door declares one.
    fn declare_link(
        hub: &Strong<Connectivity>,
        engine: &crate::session::EngineHold,
        history: bool,
        filter: Option<([u8; 16], bool)>,
        closure: CClosure<EventCall>,
    ) -> Result<*mut ListenerState, ZResult> {
        Connectivity::declare(hub, engine, ToldPlane::Links, history, filter, closure)
    }

    fn link_closure(log: &'static Log) -> CClosure<EventCall> {
        CClosure::uncounted(ctx(log), erase_link_call(Some(on_link)), Some(released))
    }

    /// The key of the transport `transport_with_zid(first)` reports.
    fn key_of(first: u8) -> ToldKey {
        ToldKey {
            zid: transport_with_zid(first).zid.id,
            is_multicast: false,
            link: 0,
        }
    }

    /// The transport event `kind` of the peer whose zid starts with `first`.
    fn event_of(kind: z_sample_kind_t, first: u8) -> ConnEvent {
        ConnEvent::Transport(z_loaned_transport_event_t {
            kind,
            transport: transport_with_zid(first),
        })
    }

    /// Hand `delivery` the transport event `kind` of the peer whose zid starts with `first`, as
    /// the hub hands it a change of a row.
    fn arrive(delivery: &Delivery, kind: z_sample_kind_t, first: u8) {
        delivery.deliver(key_of(first), kind == Z_SAMPLE_KIND_PUT, || {
            event_of(kind, first)
        });
    }

    /// The event a held change of the row of `key` is told by, as an engine that tells every
    /// change writes it.
    fn as_told(came: bool, key: &ToldKey) -> Option<ConnEvent> {
        let kind = if came {
            Z_SAMPLE_KIND_PUT
        } else {
            Z_SAMPLE_KIND_DELETE
        };
        Some(event_of(kind, key.zid[0]))
    }

    pub(crate) use crate::test_heap::allocations;

    fn transport_with_zid(first: u8) -> z_loaned_transport_t {
        let mut zid = [0u8; 16];
        zid[0] = first;
        z_loaned_transport_t {
            zid: z_id_t { id: zid },
            whatami: WHATAMI_PEER,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
        }
    }

    /// Tell `hub` of `face` as an engine tells it, a row at a time.
    fn tell(hub: &Connectivity, kind: FaceEventKind, face: &FaceSnapshot) {
        FaceLinkRow::each_of_snapshot(face, |row| hub.on_face_row(kind, &row, |_| None));
    }

    /// The transport pico reports for `face`, read off its first row as an event's is.
    fn transport_of(face: &FaceSnapshot) -> z_loaned_transport_t {
        transport_of_row(&FaceLinkRow::of_face_alone(face))
    }

    /// The link pico reports for `link` of the peer `zid`, read off its row as an event's is.
    fn link_of(zid: [u8; 16], link: &LinkSnapshot) -> z_loaned_link_t {
        let face = FaceSnapshot {
            zid,
            whatami: 1,
            is_qos: false,
            is_multicast: link.group.is_some(),
            is_shm: false,
            links: vec![link.clone()],
        };
        // The group's text, as the session's open writes it when it joins the group.
        let group = link
            .group
            .as_ref()
            .map(|group| GroupText::of(&group.endpoint));
        link_of_row(
            &FaceLinkRow::of_snapshot(&face, 0).expect("the face's one link"),
            group.as_ref(),
        )
    }

    fn face(first: u8, multicast: bool, src: &str) -> FaceSnapshot {
        let mut zid = [0u8; 16];
        zid[0] = first;
        FaceSnapshot {
            zid,
            whatami: 1,
            is_qos: true,
            is_multicast: multicast,
            is_shm: true,
            links: vec![LinkSnapshot {
                src: src.to_owned(),
                dst: "tcp/127.0.0.1:1".to_owned(),
                kind: Some(LinkKind::Tcp),
                interfaces: None,
                mtu: 2048,
                group: None,
                cert_common_name: None,
                priorities: None,
                reliable: None,
            }],
        }
    }

    fn shared() -> SharedSession {
        SharedSession::new(
            TokioTime::new(),
            [0x11; 16].into(),
            wz_session_core::policy::SessionPolicy::defaults(),
        )
        .expect("test host entropy")
    }

    /// A group endpoint is written as pico writes one. MEASURED first: the real
    /// `z_info` printed `src=udp/224.0.0.225:7449iface=lo` for a group joined as
    /// `udp/224.0.0.225:7449#iface=lo`.
    #[test]
    fn a_group_endpoint_reads_as_pico_writes_it() {
        for (joined, pico) in [
            (
                "udp/224.0.0.224:7447#iface=lo",
                "udp/224.0.0.224:7447iface=lo",
            ),
            ("udp/224.0.0.224:7447", "udp/224.0.0.224:7447"),
            // pico's own key order, whatever the order given.
            (
                "udp/224.0.0.224:7447#join=224.0.0.9;iface=eth0",
                "udp/224.0.0.224:7447iface=eth0;join=224.0.0.9",
            ),
            // The last of a key given twice.
            (
                "udp/224.0.0.224:7447#iface=a;iface=b",
                "udp/224.0.0.224:7447iface=b",
            ),
            // Read up to the first key pico does not know.
            (
                "udp/224.0.0.224:7447#iface=lo;ttl=5;tout=1",
                "udp/224.0.0.224:7447iface=lo",
            ),
            // No locator metadata.
            (
                "udp/224.0.0.224:7447?rel=0#iface=lo",
                "udp/224.0.0.224:7447iface=lo",
            ),
            // A raweth endpoint keeps the raweth link's keys. MEASURED on the real library:
            // `src=reth/30:03:8c:c8:00:a2iface=lo;whitelist=30:03:8c:c8:00:a1,`.
            (
                "reth/30:03:8c:c8:00:a2#iface=lo;whitelist=30:03:8c:c8:00:a1,",
                "reth/30:03:8c:c8:00:a2iface=lo;whitelist=30:03:8c:c8:00:a1,",
            ),
            (
                "reth/30:03:8c:c8:00:a2#whitelist=30:03:8c:c8:00:a1,;mapping=a#aa:bb:cc:dd:ee:01#,;ethtype=72e0;iface=lo",
                "reth/30:03:8c:c8:00:a2iface=lo;ethtype=72e0;mapping=a#aa:bb:cc:dd:ee:01#,;whitelist=30:03:8c:c8:00:a1,",
            ),
        ] {
            assert_eq!(pico_group_endpoint_text(joined), pico, "{joined}");
        }
    }

    /// A group member's link reads as pico's does: from the endpoint the session joined
    /// by, written as pico writes it, to the member's address, with the UDP multicast
    /// link's fixed properties. A unicast link keeps its own `src`.
    ///
    /// # Control
    ///
    /// Reading `src` off the snapshot whatever its group reds the first assert with the
    /// node's own locator.
    #[test]
    fn a_group_members_link_starts_at_the_joined_endpoint() {
        let member = LinkSnapshot {
            src: "udp/127.0.0.1:40000".to_owned(),
            dst: "udp/127.0.0.1:40001".to_owned(),
            kind: Some(LinkKind::Udp),
            interfaces: None,
            mtu: 0,
            group: Some(wz_capi_core::faces::GroupLink {
                locator: "udp/224.0.0.224:7447".to_owned(),
                endpoint: "udp/224.0.0.224:7447#iface=lo".to_owned(),
            }),
            cert_common_name: None,
            priorities: None,
            reliable: None,
        };
        let held = HeldLink(link_of([7; 16], &member));
        assert_eq!(held.0.src.as_bytes(), b"udp/224.0.0.224:7447iface=lo");
        assert_eq!(held.0.dst.as_bytes(), b"udp/127.0.0.1:40001");
        assert_eq!(
            (held.0.mtu, held.0.is_streamed, held.0.is_reliable),
            (1450, false, false)
        );
        let unicast = face(7, false, "tcp/127.0.0.1:7447");
        let held = HeldLink(link_of(unicast.zid, &unicast.links[0]));
        assert_eq!(held.0.src.as_bytes(), b"tcp/127.0.0.1:7447");
    }

    /// A raweth group member's link reads as the real library's: from the joined endpoint
    /// with the raweth link's keys, to no `dst`, with the raweth link's 1514-byte frame.
    /// MEASURED on the real library (`pico_raweth_on_wz_capi.rs`).
    ///
    /// # Control
    ///
    /// The UDP group's member above keeps its `dst` and the UDP link's 1450.
    #[test]
    fn a_raweth_group_members_link_reads_as_pico_labels_it() {
        let member = LinkSnapshot {
            src: "reth/30:03:8c:c8:00:a2".to_owned(),
            dst: "reth/30:03:8c:c8:00:a1".to_owned(),
            kind: None,
            interfaces: None,
            mtu: 0,
            group: Some(wz_capi_core::faces::GroupLink {
                locator: "reth/aa:bb:cc:dd:ee:ff".to_owned(),
                endpoint: "reth/30:03:8c:c8:00:a2#iface=lo;whitelist=30:03:8c:c8:00:a1,".to_owned(),
            }),
            cert_common_name: None,
            priorities: None,
            reliable: None,
        };
        let held = HeldLink(link_of([7; 16], &member));
        assert_eq!(
            held.0.src.as_bytes(),
            b"reth/30:03:8c:c8:00:a2iface=lo;whitelist=30:03:8c:c8:00:a1,"
        );
        assert_eq!(held.0.dst.as_bytes(), b"");
        assert_eq!(
            (held.0.mtu, held.0.is_streamed, held.0.is_reliable),
            (1514, false, false)
        );
    }

    /// Arrival is the transport and then its link; departure is the link and
    /// then the transport — pico's order, which a program holding both
    /// listeners sees in its output.
    ///
    /// # Control
    ///
    /// Dispatching a departure transport-first (the order a watcher per
    /// listener would give, since the transport listener is declared first) reds
    /// the last two lines.
    #[test]
    fn arrival_is_the_transport_then_the_link_and_departure_the_link_then_the_transport() {
        let hub = hub_in_heap();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        // Declared transport FIRST, so a registry that hands each watcher the
        // event in declaration order would put the transport ahead on a
        // departure too.
        let transport = declare_transport(&hub, &engine, false, transport_closure(log))
            .expect("a place is free");
        let link =
            declare_link(&hub, &engine, false, None, link_closure(log)).expect("a place is free");

        let peer = face(7, false, "tcp/127.0.0.1:7447");
        tell(&hub, FaceEventKind::Up, &peer);
        tell(&hub, FaceEventKind::Down, &peer);
        assert_eq!(
            seen(log),
            [
                "transport PUT 7",
                "link PUT tcp/127.0.0.1:7447",
                "link DEL tcp/127.0.0.1:7447",
                "transport DEL 7",
            ]
        );
        // SAFETY: the listeners declared above, each let go of once.
        unsafe {
            release_listener(transport);
            release_listener(link);
        }
    }

    /// Tell `hub` of `face` as an engine tells it, its last row counting `lost` rows the queue
    /// lost after it, the faces that stand then being `standing`.
    fn tell_losing(
        hub: &Connectivity,
        kind: FaceEventKind,
        face: &FaceSnapshot,
        lost: usize,
        standing: &[FaceSnapshot],
    ) {
        let mut stand = Vec::new();
        for face in standing {
            FaceLinkRow::each_of_snapshot(face, |row| stand.push(row));
        }
        let mut rows = Vec::new();
        FaceLinkRow::each_of_snapshot(face, |row| rows.push(row));
        if let Some(last) = rows.last_mut() {
            last.lost_after = lost;
        }
        for row in &rows {
            hub.on_face_row(kind, row, |at| stand.get(at).cloned());
        }
    }

    /// Rows the session's queue lost are told after the row that counts them, against the faces
    /// that stand, so the listeners end told the faces as they stand: a face whose departure was
    /// lost is told left, one whose arrival was lost is told came, one that stands with other ends
    /// is told left and came, and one that stands as it was told is told nothing more, each in
    /// pico's order; what the catch-up told is kept, so a later loss tells it again only when it
    /// changed.
    ///
    /// # Control
    ///
    /// Reading `lost_after` with nothing (the lost rows told to no listener) leaves the last
    /// eight lines of the first sequence untold and reds the first assertion; a catch-up that keeps
    /// nothing it told came tells peers 1 and 3 again at the second loss, and one that tells a row
    /// kept already as it is tells peer 3 again, each of which reds the second.
    #[test]
    fn rows_the_queue_lost_are_told_against_the_faces_that_stand() {
        let hub = hub_in_heap();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let transport = declare_transport(&hub, &engine, false, transport_closure(log))
            .expect("a place is free");
        let link =
            declare_link(&hub, &engine, false, None, link_closure(log)).expect("a place is free");

        tell(
            &hub,
            FaceEventKind::Up,
            &face(1, false, "tcp/127.0.0.1:7001"),
        );
        tell(
            &hub,
            FaceEventKind::Up,
            &face(2, false, "tcp/127.0.0.1:7002"),
        );
        // Lost after peer 4 came: peer 2 left, peer 1 left and came back from another port, and
        // peer 3 came.
        let four = face(4, false, "tcp/127.0.0.1:7004");
        let standing = [
            face(1, false, "tcp/127.0.0.1:7011"),
            four.clone(),
            face(3, false, "tcp/127.0.0.1:7003"),
        ];
        tell_losing(&hub, FaceEventKind::Up, &four, 3, &standing);
        assert_eq!(
            seen(log),
            [
                "transport PUT 1",
                "link PUT tcp/127.0.0.1:7001",
                "transport PUT 2",
                "link PUT tcp/127.0.0.1:7002",
                "transport PUT 4",
                "link PUT tcp/127.0.0.1:7004",
                "link DEL tcp/127.0.0.1:7001",
                "transport DEL 1",
                "link DEL tcp/127.0.0.1:7002",
                "transport DEL 2",
                "transport PUT 1",
                "link PUT tcp/127.0.0.1:7011",
                "transport PUT 3",
                "link PUT tcp/127.0.0.1:7003",
            ]
        );

        // Peer 3's arrival the queue kept after the loss was told by the catch-up already.
        tell(&hub, FaceEventKind::Up, &standing[2]);
        // Lost after peer 4 left: nothing that changed the faces.
        let after = [standing[0].clone(), standing[2].clone()];
        tell_losing(&hub, FaceEventKind::Down, &four, 1, &after);
        assert_eq!(
            seen(log).split_off(14),
            ["link DEL tcp/127.0.0.1:7004", "transport DEL 4"],
            "the faces the catch-up told are not told again"
        );
        // SAFETY: the listeners declared above, each let go of once.
        unsafe {
            release_listener(transport);
            release_listener(link);
        }
    }

    /// A link listener bound to one transport hears that transport's links and
    /// nobody else's; the transport is identified by zid AND multicast flag, as
    /// pico's filter matches.
    ///
    /// # Control
    ///
    /// Matching on the zid alone reds the multicast leg.
    #[test]
    fn a_link_filter_matches_the_zid_and_the_multicast_flag() {
        let hub = hub_in_heap();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let mut zid = [0u8; 16];
        zid[0] = 7;
        let link = declare_link(&hub, &engine, false, Some((zid, false)), link_closure(log))
            .expect("a place is free");

        tell(&hub, FaceEventKind::Up, &face(7, false, "tcp/a"));
        tell(&hub, FaceEventKind::Up, &face(8, false, "tcp/other-zid"));
        tell(&hub, FaceEventKind::Up, &face(7, true, "tcp/multicast"));
        assert_eq!(seen(log), ["link PUT tcp/a"]);
        // SAFETY: the listener declared above, let go of once.
        unsafe { release_listener(link) };
    }

    /// An arrival that lands while the history is being replayed is delivered
    /// AFTER it, in order, and not dropped, interleaved or made to wait.
    ///
    /// The transport callback itself delivers a second peer during the replay of
    /// the first, which is the only way to stand inside the window on one
    /// thread.
    ///
    /// # Control
    ///
    /// Delivering straight to the closure while replaying (no queue) puts the
    /// second peer ahead of the history's end and reds the order; holding the
    /// second arrival of the same peer as a row of its own reds the count.
    #[test]
    fn an_arrival_during_the_history_replay_is_queued_behind_it() {
        let log = log();
        let delivery = replaying_delivery(log);
        log.reenter.set((delivery.clone(), 9)).ok();

        // The replay: two peers connected now.
        for first in [1u8, 2] {
            delivery.call(event_of(Z_SAMPLE_KIND_PUT, first));
        }
        // The callback re-entered `deliver` while replaying: nothing ran yet.
        assert_eq!(
            seen(log),
            ["transport PUT 1", "transport PUT 2"],
            "what arrives during the replay waits for it"
        );

        delivery.finish_replay(as_told, |_| {});
        assert_eq!(
            seen(log),
            ["transport PUT 1", "transport PUT 2", "transport PUT 9"],
            "it is delivered after the history, once though each replayed peer re-entered"
        );

        // Live now: a further arrival goes straight through.
        arrive(&delivery, Z_SAMPLE_KIND_DELETE, 5);
        assert_eq!(
            seen(log).last().map(String::as_str),
            Some("transport DEL 5")
        );
    }

    /// A transport that came and went while the history was replayed is not told:
    /// its PUT still waiting and its DEL cancel, and what waits around them is
    /// told in order.
    ///
    /// # Control
    ///
    /// Holding the DEL behind the PUT (no cancel) tells both and reds the list.
    #[test]
    fn a_transport_that_came_and_went_inside_the_replay_is_not_told() {
        let log = log();
        let delivery = replaying_delivery(log);
        arrive(&delivery, Z_SAMPLE_KIND_PUT, 4);
        arrive(&delivery, Z_SAMPLE_KIND_PUT, 3);
        arrive(&delivery, Z_SAMPLE_KIND_DELETE, 3);
        arrive(&delivery, Z_SAMPLE_KIND_PUT, 6);
        delivery.finish_replay(as_told, |_| {});
        assert_eq!(seen(log), ["transport PUT 4", "transport PUT 6"]);
    }

    /// A transport that left and came back while the history was replayed is told
    /// both, in order: a reconnect, which a listener that saw the first link must
    /// hear end before the second begins. Its DEL told twice is told once.
    ///
    /// # Control
    ///
    /// Cancelling a waiting DEL against the PUT after it, as a PUT is against a
    /// DEL, reds the list.
    #[test]
    fn a_reconnect_inside_the_replay_is_told_as_both_in_order() {
        let log = log();
        let delivery = replaying_delivery(log);
        arrive(&delivery, Z_SAMPLE_KIND_DELETE, 5);
        arrive(&delivery, Z_SAMPLE_KIND_DELETE, 5);
        arrive(&delivery, Z_SAMPLE_KIND_PUT, 5);
        delivery.finish_replay(as_told, |_| {});
        assert_eq!(seen(log), ["transport DEL 5", "transport PUT 5"]);
    }

    /// A queue that runs out of rows holds what fit, lets go of the rest, and once
    /// what it held was told hands the listener to the convergence, once, which is
    /// what brings it to the faces as they stand (`converge`). An
    /// event the engine says the listener is not to hear is not told.
    ///
    /// # Control
    ///
    /// Dropping the arrival past the rows without marking the queue overflowed
    /// leaves the convergence uncalled and reds both assertions after the replay.
    #[test]
    fn a_queue_past_its_rows_converges_once_what_it_held_was_told() {
        let log = log();
        let delivery = replaying_delivery(log);
        let firsts: Vec<u8> = (0..REPLAY_ROWS)
            .map(|at| u8::try_from(at).expect("a few rows").saturating_add(10))
            .collect();
        for first in &firsts {
            arrive(&delivery, Z_SAMPLE_KIND_PUT, *first);
        }
        // Past the rows: let go of, and what follows it too.
        arrive(&delivery, Z_SAMPLE_KIND_PUT, 99);
        let mut converged = 0;
        delivery.finish_replay(
            // The engine says the listener is not to hear the first row held.
            |came, key| {
                if *key == key_of(firsts[0]) {
                    None
                } else {
                    as_told(came, key)
                }
            },
            |delivery| {
                converged += 1;
                delivery.call(event_of(Z_SAMPLE_KIND_PUT, 99));
            },
        );
        let mut told: Vec<String> = firsts
            .iter()
            .skip(1)
            .map(|first| format!("transport PUT {first}"))
            .collect();
        told.push("transport PUT 99".to_owned());
        assert_eq!(converged, 1, "the convergence runs once");
        assert_eq!(seen(log), told);
    }

    /// What waits for a replay waits in the rows reserved with its listener: holding
    /// as many events as the rows, and one past them, allocates nothing.
    ///
    /// # Control
    ///
    /// A queue that grows on the heap (`VecDeque`) allocates on the first event
    /// it holds and reds the count.
    #[test]
    fn holding_a_replays_arrivals_allocates_nothing() {
        let log = log();
        let delivery = replaying_delivery(log);
        let held = allocations(|| {
            for at in 0..=REPLAY_ROWS {
                let first = u8::try_from(at).unwrap_or(u8::MAX);
                arrive(&delivery, Z_SAMPLE_KIND_PUT, first);
            }
        });
        assert_eq!(held, 0, "the arrivals are held in place");
        // The allocator counts at all: a box made under it is counted.
        let control = allocations(|| drop(core::hint::black_box(Box::new(1u64))));
        assert_eq!(control, 1);
    }

    /// A row whose listener's history is being replayed is given to no other listener until the
    /// replay ended, even once no listener holds it: what the engine noted under the row belongs
    /// to the replay until it forgot it. The replay's end frees the row of its own plane alone.
    ///
    /// # Control
    ///
    /// A free row read from the entries alone (the replay's mark ignored) reds the first
    /// assertion; an end of a replay that frees the row of the other plane reds the last.
    #[test]
    fn a_row_a_replay_keeps_is_given_to_no_other_listener_until_it_ended() {
        let mut rows: [ListenerRow; 2] = Default::default();
        rows[0].replaying = true;
        assert_eq!(free_row(&rows), Some(1), "the replay keeps row 0");
        rows[1].replaying = true;
        assert_eq!(free_row(&rows), None, "both rows kept");

        let hub = hub_in_heap();
        for plane in [ToldPlane::Transports, ToldPlane::Links] {
            for row in lock(&hub.listeners).rows_mut(plane) {
                row.replaying = true;
            }
        }
        hub.end_replay(ToldPlane::Transports, 0);
        assert_eq!(
            free_row(lock(&hub.listeners).rows(ToldPlane::Transports)),
            Some(0),
            "the replay that ended frees it"
        );
        hub.end_replay(ToldPlane::Transports, usize::MAX);
        assert_eq!(
            free_row(lock(&hub.listeners).rows(ToldPlane::Transports)),
            Some(0),
            "a row past the plane's is no row"
        );
        assert_eq!(
            free_row(lock(&hub.listeners).rows(ToldPlane::Links)),
            None,
            "the link plane's row 0 is still kept"
        );
    }

    /// Ids are the hub's, not a plane's: undeclaring a link listener by its id takes no transport
    /// listener, though each is the first of its plane.
    ///
    /// # Control
    ///
    /// A table that numbers each plane's listeners apart gives both the id 1, and the undeclare
    /// of the link listener's takes the transport listener, which then hears nothing and reds the
    /// list.
    #[test]
    fn undeclaring_a_listener_takes_no_listener_of_the_other_plane() {
        let hub = hub_in_heap();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let transport = declare_transport(&hub, &engine, false, transport_closure(log))
            .expect("a transport row is free");
        let link = declare_link(&hub, &engine, false, None, link_closure(log))
            .expect("a link row is free");
        // SAFETY: the listeners' owner holds them until the end of the test.
        let (transport_id, link_id) = unsafe { ((*transport).id, (*link).id) };
        assert_ne!(transport_id, link_id, "the hub numbers its listeners once");
        hub.undeclare(link_id);
        tell(&hub, FaceEventKind::Up, &face(5, false, "tcp/z"));
        assert_eq!(seen(log), ["transport PUT 5"]);
        // SAFETY: the listeners declared above, each let go of once.
        unsafe {
            release_listener(transport);
            release_listener(link);
        }
        assert_eq!(log.released.load(Ordering::SeqCst), 2);
    }

    /// A delivery hands its closure the events of its own plane alone: a link event handed to a
    /// transport listener's delivery reaches no callback and is released, and the delivery goes on
    /// telling transport events.
    ///
    /// # Control
    ///
    /// A call that hands the closure whatever event it is given calls the transport callback with
    /// a link event, which logs a transport line and reds the first assertion.
    #[test]
    fn a_delivery_hands_its_closure_the_events_of_its_plane_alone() {
        let log = log();
        let delivery = replaying_delivery(log);
        let peer = face(7, false, "tcp/127.0.0.1:7447");
        delivery.call(ConnEvent::Link(z_loaned_link_event_t {
            kind: Z_SAMPLE_KIND_PUT,
            link: link_of(peer.zid, &peer.links[0]),
        }));
        assert!(
            seen(log).is_empty(),
            "a link event reaches no transport callback"
        );
        delivery.call(event_of(Z_SAMPLE_KIND_PUT, 3));
        assert_eq!(seen(log), ["transport PUT 3"]);
    }

    /// Undeclaring runs the closure's `drop(context)` exactly once, before it
    /// returns, and what arrives afterwards is silent.
    ///
    /// A dispatcher that copied the listener out of the set before the undeclare
    /// — which is what a face event in flight holds — is held across it, because
    /// that is the case that matters: the context is released by the undeclare
    /// and not whenever that copy goes, which is pico's wait on its sync group.
    ///
    /// # Control
    ///
    /// Leaving the closure in place on undeclare (releasing the listener only
    /// when the last copy goes) reds the release count.
    #[test]
    fn undeclaring_releases_the_context_once_and_silences_the_listener() {
        let hub = hub_in_heap();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let object = declare_transport(&hub, &engine, false, transport_closure(log))
            .expect("a place is free");
        // SAFETY: the listener's owner holds it until the end of the test.
        let id = unsafe { (*object).id };
        tell(&hub, FaceEventKind::Up, &face(3, false, "tcp/x"));
        assert_eq!(log.released.load(Ordering::SeqCst), 0);

        let mut at = 0;
        let in_flight = hub.next_listener(ToldPlane::Transports, &mut at);
        assert!(in_flight.is_some(), "the dispatcher holds the listener");
        hub.undeclare(id);
        assert_eq!(
            log.released.load(Ordering::SeqCst),
            1,
            "the context is released by the time undeclare returns"
        );
        tell(&hub, FaceEventKind::Down, &face(3, false, "tcp/x"));
        assert_eq!(
            seen(log),
            ["transport PUT 3"],
            "an undeclared listener hears nothing"
        );

        hub.undeclare(id);
        assert_eq!(
            log.released.load(Ordering::SeqCst),
            1,
            "a second undeclare is a no-op"
        );
        // The dispatcher's hold going changes nothing: the closure was released.
        drop(in_flight);
        assert_eq!(log.released.load(Ordering::SeqCst), 1);
        // SAFETY: the listener declared above, let go of once.
        unsafe { release_listener(object) };
        assert_eq!(log.released.load(Ordering::SeqCst), 1);
    }

    /// Shutting the hub down — a session ending — releases every listener's
    /// context, background ones included.
    #[test]
    fn shutting_the_hub_down_releases_every_context() {
        let hub = hub_in_heap();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let transport = declare_transport(&hub, &engine, false, transport_closure(log))
            .expect("a place is free");
        let link =
            declare_link(&hub, &engine, false, None, link_closure(log)).expect("a place is free");
        hub.shutdown();
        assert_eq!(log.released.load(Ordering::SeqCst), 2);
        hub.shutdown();
        assert_eq!(
            log.released.load(Ordering::SeqCst),
            2,
            "shutdown is idempotent"
        );
        // The handle let go of after the end finds its listener released already.
        // SAFETY: the listeners declared above, each let go of once.
        unsafe {
            release_listener(transport);
            release_listener(link);
        }
        assert_eq!(log.released.load(Ordering::SeqCst), 2);
    }

    /// A hub lies in the place its session lent until the last count of it is let go of: a
    /// listener's handle holds one past the session's own. Turned red by a hub that gives its
    /// place back with the session's count while a listener still reaches it, or never.
    #[test]
    fn a_hub_keeps_its_lent_place_while_a_listener_holds_it() {
        static PLACES: wz_capi_port::lodge::StaticPlaces<Connectivity, 1> =
            wz_capi_port::lodge::StaticPlaces::new();
        let hub = Connectivity::new(PLACES.lend().expect("CONTROL: a fresh table lends"), None);
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let transport = declare_transport(&hub, &engine, false, transport_closure(log))
            .expect("a place is free");
        drop(hub);
        assert_eq!(PLACES.lent(), 1, "the listener still holds the hub");
        // SAFETY: the listener declared above, let go of once.
        unsafe { release_listener(transport) };
        assert_eq!(PLACES.lent(), 0, "the last count gave the place back");
    }

    /// A hub holds as many transport listeners as its rows, and one more is refused with
    /// nothing declared and its context released; a row given back is taken again. Turned red by
    /// a hub that admits a listener past its rows, or one whose undeclare leaves its row held.
    #[test]
    fn a_listener_past_the_hubs_rows_is_refused_and_released() {
        let hub = hub_in_heap();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let rows = wz_session_core::caps::MAX_TRANSPORT_EVENTS_LISTENERS;
        let held: Vec<*mut ListenerState> = (0..rows)
            .map(|_| {
                declare_transport(&hub, &engine, false, transport_closure(log))
                    .expect("a row is free")
            })
            .collect();
        assert_eq!(
            declare_transport(&hub, &engine, false, transport_closure(log)).err(),
            Some(Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
        assert_eq!(
            log.released.load(Ordering::SeqCst),
            1,
            "the refused closure is released"
        );
        let mut held = held.into_iter();
        let first = held.next().expect("at least one row");
        // SAFETY: each listener declared above, let go of once.
        unsafe { release_listener(first) };
        let again = declare_transport(&hub, &engine, false, transport_closure(log))
            .expect("the row given back is taken again");
        for object in held.chain([again]) {
            // SAFETY: as above.
            unsafe { release_listener(object) };
        }
        assert_eq!(log.released.load(Ordering::SeqCst), rows + 2);
    }

    /// A hub holds as many link listeners as its rows, apart from its transport listeners', and
    /// one more is refused with nothing declared and its context released; an undeclared one
    /// hears nothing and its row is taken again. Turned red by a hub that admits a link listener
    /// past its rows, one that counts them against the transport listeners' rows, or one whose
    /// undeclare leaves its row held or its listener told.
    #[test]
    fn a_link_listener_past_the_hubs_rows_is_refused_and_released() {
        let hub = hub_in_heap();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let transport = declare_transport(&hub, &engine, false, transport_closure(log))
            .expect("a transport row is free");
        let rows = wz_session_core::caps::MAX_LINK_EVENTS_LISTENERS;
        let held: Vec<*mut ListenerState> = (0..rows)
            .map(|_| {
                declare_link(&hub, &engine, false, None, link_closure(log))
                    .expect("a link row is free")
            })
            .collect();
        assert_eq!(
            declare_link(&hub, &engine, false, None, link_closure(log)).err(),
            Some(Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
        assert_eq!(
            log.released.load(Ordering::SeqCst),
            1,
            "the refused closure is released"
        );
        let mut held = held.into_iter();
        let first = held.next().expect("at least one row");
        // SAFETY: each listener declared above, let go of once.
        unsafe { release_listener(first) };
        assert_eq!(log.released.load(Ordering::SeqCst), 2);
        tell(&hub, FaceEventKind::Up, &face(4, false, "tcp/y"));
        assert_eq!(
            seen(log)
                .iter()
                .filter(|line| line.starts_with("link"))
                .count(),
            rows - 1,
            "the undeclared listener hears nothing"
        );
        let again = declare_link(&hub, &engine, false, None, link_closure(log))
            .expect("the row given back is taken again");
        for object in held.chain([again]) {
            // SAFETY: as above.
            unsafe { release_listener(object) };
        }
        // SAFETY: as above.
        unsafe { release_listener(transport) };
        assert_eq!(log.released.load(Ordering::SeqCst), rows + 3);
    }

    /// The wire role becomes pico's bitmask, and an unknown role becomes
    /// pico's "other".
    #[test]
    fn the_wire_role_becomes_pico_bitmask() {
        assert_eq!(
            [
                pico_whatami(0),
                pico_whatami(1),
                pico_whatami(2),
                pico_whatami(3)
            ],
            [1, 2, 4, 0]
        );
    }

    /// pico's transport reports no QoS and no SHM whatever the face negotiated,
    /// and keeps the multicast flag.
    #[test]
    fn a_transport_reports_pico_hard_coded_flags() {
        let transport = transport_of(&face(4, true, "tcp/x"));
        assert!(!transport.is_qos && !transport.is_shm);
        assert!(transport.is_multicast);
        assert_eq!(transport.whatami, WHATAMI_PEER);
    }

    /// Copying a link copies its strings, releasing one copy leaves the other
    /// standing, and taking a link out of a loan nulls the loan.
    ///
    /// # Control
    ///
    /// A clone that shares the strings frees them twice and reds the readback
    /// (or the allocator).
    #[test]
    fn a_link_clone_is_independent_and_take_from_loaned_moves() {
        unsafe {
            let mut original = z_owned_link_t {
                _val: link_of(
                    [5; 16],
                    &LinkSnapshot {
                        src: "tcp/src".into(),
                        dst: "tcp/dst".into(),
                        kind: Some(LinkKind::Tcp),
                        interfaces: None,
                        mtu: 1,
                        group: None,
                        cert_common_name: None,
                        priorities: None,
                        reliable: None,
                    },
                ),
            };
            assert!(z_internal_link_check(&original));

            let mut copy = core::mem::MaybeUninit::<z_owned_link_t>::uninit();
            assert_eq!(
                z_link_clone(copy.as_mut_ptr(), z_link_loan(&original)),
                Z_OK
            );
            let mut copy = copy.assume_init();
            assert_ne!(
                copy._val.src.start, original._val.src.start,
                "the strings are copied"
            );

            z_link_drop(z_link_move(&mut original));
            assert!(
                !z_internal_link_check(&original),
                "dropping a link clears it in place"
            );
            // The original's strings are gone; the copy still reads.
            let mut text = z_owned_string_t::null_value();
            assert_eq!(z_link_src(z_link_loan(&copy), &mut text), Z_OK);
            assert_eq!(
                core::slice::from_raw_parts(
                    crate::bytes::z_string_data(crate::bytes::z_string_loan(&text)) as *const u8,
                    crate::bytes::z_string_len(crate::bytes::z_string_loan(&text)),
                ),
                b"tcp/src"
            );
            crate::bytes::z_string_drop(crate::bytes::z_string_move(&mut text));

            // take_from_loaned moves: the destination holds it, the source is null.
            let mut moved = core::mem::MaybeUninit::<z_owned_link_t>::uninit();
            assert_eq!(
                z_link_take_from_loaned(moved.as_mut_ptr(), z_link_loan_mut(&mut copy)),
                Z_OK
            );
            let mut moved = moved.assume_init();
            assert!(z_internal_link_check(&moved));
            assert!(
                !z_internal_link_check(&copy),
                "the source of a move is null"
            );
            z_link_drop(z_link_move(&mut moved));
            assert!(!z_internal_link_check(&moved));
        }
    }

    /// `z_link_group`, `z_link_auth_identifier`, `z_link_interfaces`,
    /// `z_link_priorities` and `z_link_reliability` are pico's stubs, and say
    /// nothing rather than something plausible.
    #[test]
    fn the_stub_accessors_say_nothing() {
        unsafe {
            let link = link_of(
                [1; 16],
                &LinkSnapshot {
                    src: "tcp/s".into(),
                    dst: "tcp/d".into(),
                    kind: Some(LinkKind::Tcp),
                    interfaces: Some(vec!["eth0".into()]),
                    mtu: 1,
                    group: None,
                    cert_common_name: None,
                    priorities: None,
                    reliable: None,
                },
            );
            let mut group = z_owned_string_t::null_value();
            z_link_group(&link, &mut group);
            assert!(group.handle.is_null());
            let mut auth = z_owned_string_t::null_value();
            z_link_auth_identifier(&link, &mut auth);
            assert!(auth.handle.is_null());
            let mut interfaces = z_owned_string_array_t::null_value();
            z_link_interfaces(&link, &mut interfaces);
            assert!(interfaces.handle.is_null());
            let (mut lo, mut hi, mut reliability) = (9u8, 9u8, 9 as c_int);
            assert!(!z_link_priorities(&link, &mut lo, &mut hi));
            assert!(!z_link_reliability(&link, &mut reliability));
            assert_eq!(
                (lo, hi, reliability),
                (9, 9, 9),
                "a false answer writes nothing"
            );
            let mut link = link;
            link.clear();
        }
    }

    /// The listener option defaults are pico's: no history, no transport.
    #[test]
    fn the_option_defaults_are_pico() {
        unsafe {
            let mut transport = z_transport_events_listener_options_t { history: true };
            z_transport_events_listener_options_default(&mut transport);
            assert!(!transport.history);
            let mut link = z_link_events_listener_options_t {
                history: true,
                transport: 1 as *mut z_moved_transport_t,
            };
            z_link_events_listener_options_default(&mut link);
            assert!(!link.history && link.transport.is_null());
            let mut info = z_info_links_options_t {
                transport: 1 as *mut z_moved_transport_t,
            };
            z_info_links_options_default(&mut info);
            assert!(info.transport.is_null());
        }
    }

    /// The four closure families are the same struct: building one writes
    /// `{ context, call, drop }`, taking one nulls the source so `drop` runs
    /// once, and dropping runs it and nulls.
    #[test]
    fn a_closure_takes_and_drops_once() {
        unsafe {
            let log = log();
            let mut closure = z_owned_closure_link_event_t {
                context: core::ptr::null_mut(),
                call: None,
                drop: None,
            };
            assert_eq!(
                z_closure_link_event(&mut closure, Some(on_link), Some(released), ctx(log)),
                Z_OK
            );
            assert!(z_internal_closure_link_event_check(&closure));

            let mut taken = core::mem::MaybeUninit::<z_owned_closure_link_event_t>::uninit();
            z_internal_closure_link_event_null(taken.as_mut_ptr());
            z_closure_link_event_take(taken.as_mut_ptr(), z_closure_link_event_move(&mut closure));
            assert!(
                !z_internal_closure_link_event_check(&closure),
                "the source is nulled"
            );

            let mut taken = taken.assume_init();
            z_closure_link_event_drop(z_closure_link_event_move(&mut taken) as *mut _);
            z_closure_link_event_drop(z_closure_link_event_move(&mut taken) as *mut _);
            assert_eq!(
                log.released.load(Ordering::SeqCst),
                1,
                "drop(context) ran once"
            );
        }
    }
}

/// The rows the hub keeps as it told its listeners they came, with any engine.
#[cfg(test)]
mod told_tests {
    use super::*;
    use wz_session_core::face::{LentEnd, RowEnds, RowText};
    use wz_session_core::link::{LinkEnds, LinkKind};

    /// A link's two ends are written into the strings handed out from the facts its row holds,
    /// as the driver's ends write them, an end past a row's bound whole too.
    ///
    /// # Control
    ///
    /// A door that writes the row's ends with another scheme, or writes none, reds the TCP
    /// link's assertion; one that writes into the row's bound alone cuts the long name and reds
    /// the pipe's.
    #[test]
    fn a_links_ends_are_written_where_they_are_handed_out() {
        let local = core::net::SocketAddr::from(([10, 0, 0, 2], 40000));
        let peer = core::net::SocketAddr::from(([10, 0, 0, 1], 7447));
        let long = "p".repeat(wz_session_core::caps::MAX_LOCATOR_LEN + 1);
        for lent in [
            LinkEnds::ip(LinkKind::Tcp, local, peer),
            LinkEnds::named(LinkKind::Unixpipe, "/tmp/a", &long),
        ] {
            let mut told = row(1, "");
            told.ends = RowEnds::lent(Some(lent));
            let held = HeldLink(link_of_row(&told, None));
            let (mut src, mut dst) = (String::new(), String::new());
            lent.write_src(&mut src);
            lent.write_dst(&mut dst);
            assert_eq!(
                (held.0.src.as_bytes(), held.0.dst.as_bytes()),
                (src.as_bytes(), dst.as_bytes()),
                "{lent:?}"
            );
        }
        let mut told = row(1, "");
        told.ends = RowEnds::Lent {
            kind: LinkKind::Tcp,
            src: LentEnd::Ip(local),
            dst: LentEnd::Ip(peer),
        };
        let held = HeldLink(link_of_row(&told, None));
        assert_eq!(held.0.dst.as_bytes(), b"tcp/10.0.0.1:7447");
    }

    /// A group member's link starts at the text the session's open wrote of the group's endpoint,
    /// and goes to the member's address; a unicast link of the same session starts at its own end.
    ///
    /// # Control
    ///
    /// A door that reads the group's text for every row reds the unicast link's assertion; one
    /// that ignores it reds the member's, which then starts at the group's locator.
    #[test]
    fn a_members_link_starts_at_the_text_the_open_wrote() {
        let joined = "udp/224.0.0.224:7447#iface=lo";
        let group = GroupText::of(joined);
        let mut member = row(2, "");
        member.is_multicast = true;
        member.ends = RowEnds::Member {
            src: RowText::of("udp/224.0.0.224:7447"),
            at: core::net::SocketAddr::from(([192, 0, 2, 9], 7447)),
        };
        member.group_endpoint = Some(wz_session_core::face::GroupRowText::of(joined));
        let held = HeldLink(link_of_row(&member, Some(&group)));
        assert_eq!(
            (held.0.src.as_bytes(), held.0.dst.as_bytes()),
            (
                &b"udp/224.0.0.224:7447iface=lo"[..],
                &b"udp/192.0.2.9:7447"[..]
            )
        );
        let held = HeldLink(link_of_row(&member, None));
        assert_eq!(held.0.src.as_bytes(), b"udp/224.0.0.224:7447");
        let unicast = row(3, "tcp/127.0.0.1:7447");
        let held = HeldLink(link_of_row(&unicast, Some(&group)));
        assert_eq!(held.0.src.as_bytes(), b"tcp/127.0.0.1:7447");
    }

    /// The row of a peer whose zid starts with `n`'s bytes, from `src`.
    fn row(n: usize, src: &str) -> FaceLinkRow {
        let mut zid = [0u8; 16];
        zid[..8].copy_from_slice(&u64::try_from(n).expect("a small n").to_le_bytes());
        FaceLinkRow {
            zid,
            whatami: 1,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
            link: 0,
            links: 1,
            ends: RowEnds::Written {
                src: RowText::of(src),
                dst: RowText::of("tcp/127.0.0.1:1"),
            },
            kind: None,
            mtu: 0,
            group_endpoint: None,
            lost_after: 0,
        }
    }

    fn kept(told: &Told) -> usize {
        told.rows.iter().flatten().count()
    }

    /// A row told came is kept once per key, the last told in place of an earlier one of its key;
    /// one that finds every place held is not kept, and a row told left frees its place.
    ///
    /// # Control
    ///
    /// Answering news for a row kept as it is reds the second assertion; keeping a row in a free
    /// place without looking for its key first reds the count after the third; keeping one past
    /// the places (overwriting a held place) reds the assertion on the row past them.
    #[test]
    fn the_told_rows_are_kept_once_per_key_within_their_places() {
        let mut told = Told::new();
        assert!(told.came(&row(1, "tcp/127.0.0.1:7001")));
        assert!(
            !told.came(&row(1, "tcp/127.0.0.1:7001")),
            "the same row again is no news"
        );
        assert!(
            told.came(&row(1, "tcp/127.0.0.1:7011")),
            "other ends are news"
        );
        assert_eq!(kept(&told), 1, "one row per key");
        assert_eq!(
            told.rows.iter().flatten().next().map(FaceLinkRow::src_text),
            Some("tcp/127.0.0.1:7011".to_owned()),
            "the row last told stands in for the earlier one"
        );
        for n in 2..=TOLD_ROWS.saturating_add(1) {
            assert!(told.came(&row(n, "tcp/127.0.0.1:7000")));
        }
        let past = row(TOLD_ROWS.saturating_add(1), "tcp/127.0.0.1:7000");
        assert!(
            told.place_of(&ToldKey::of_row(&past)).is_none(),
            "a row past the places is not kept"
        );
        assert_eq!(kept(&told), TOLD_ROWS);
        told.went(&ToldKey::of_row(&row(1, "")));
        assert!(
            !told.holds_face_of(&row(1, "")),
            "a row told left is let go of"
        );
        assert!(told.came(&past));
        assert!(
            told.place_of(&ToldKey::of_row(&past)).is_some(),
            "the place it freed takes the next row"
        );
    }
}

/// The places of the transport events listeners of a session of the cooperative engine, let go
/// of as the session ends. A place given back takes the session's lock, so one given back under
/// it fails the debug build's mark of a held lock (`wz_capi_port::sync::SessionHeld`) at once
/// instead of waiting on itself.
#[cfg(all(test, not(feature = "engine-tokio"), feature = "peer"))]
mod place_tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::session::{
        engine_held, listening_on_loopback, z_close, z_owned_session_t, z_session_drop,
        z_session_loan, z_session_loan_mut, z_session_move,
    };

    unsafe extern "C" fn on_event(_: *mut z_loaned_transport_event_t, _: *mut c_void) {}

    /// How many places of `kind` `engine` has free: each claimed, then all given back.
    fn free(engine: &crate::session::EngineHold, kind: Kind) -> usize {
        let claimed: Vec<Slot<u64>> =
            core::iter::from_fn(|| Slot::<u64>::take_entity(engine, kind)).collect();
        claimed.len()
    }

    /// A closure that counts its drops in `drops`.
    fn counting(drops: &'static AtomicUsize) -> z_owned_closure_transport_event_t {
        unsafe extern "C" fn on_drop(context: *mut c_void) {
            // SAFETY: the context is the test's `'static` counter.
            unsafe { &*context.cast::<AtomicUsize>() }.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: a zeroed closure is the null one, which the constructor overwrites.
        let mut closure: z_owned_closure_transport_event_t = unsafe { core::mem::zeroed() };
        // SAFETY: a local closure; the context outlives every listener.
        let made = unsafe {
            z_closure_transport_event(
                &mut closure,
                Some(on_event),
                Some(on_drop),
                core::ptr::from_ref(drops).cast_mut().cast(),
            )
        };
        assert_eq!(made, Z_OK);
        closure
    }

    /// Run `declare`, a declare of one transport listener on `engine`'s session, and check that it
    /// took one of the session's places.
    fn taking_a_place(engine: &crate::session::EngineHold, declare: impl FnOnce() -> ZResult) {
        let places = free(engine, Kind::TransportEventsListener);
        assert_eq!(declare(), Z_OK);
        assert_eq!(
            Some(free(engine, Kind::TransportEventsListener)),
            places.checked_sub(1),
            "the listener holds a place"
        );
    }

    /// A background listener on a session of `engine`'s, in a place of its own.
    fn declare_background(
        session: &z_owned_session_t,
        engine: &crate::session::EngineHold,
        drops: &'static AtomicUsize,
    ) {
        let mut closure = counting(drops);
        taking_a_place(engine, || {
            // SAFETY: a live session and a local closure, consumed by the declare.
            unsafe {
                z_declare_background_transport_events_listener(
                    z_session_loan(session),
                    z_closure_transport_event_move(&mut closure),
                    core::ptr::null(),
                )
            }
        });
    }

    /// A listener with a handle on a session of `engine`'s, in a place of its own: the handle.
    fn declare_handled(
        session: &z_owned_session_t,
        engine: &crate::session::EngineHold,
        drops: &'static AtomicUsize,
    ) -> z_owned_transport_events_listener_t {
        let mut closure = counting(drops);
        let mut listener = z_owned_transport_events_listener_t::null_value();
        taking_a_place(engine, || {
            // SAFETY: a live session, a local handle and a local closure, consumed by the declare.
            unsafe {
                z_declare_transport_events_listener(
                    z_session_loan(session),
                    &mut listener,
                    z_closure_transport_event_move(&mut closure),
                    core::ptr::null(),
                )
            }
        });
        listener
    }

    /// The engine of the session `session` holds.
    fn engine_of_session(session: &z_owned_session_t) -> crate::session::EngineHold {
        // SAFETY: a live session of this frame's caller.
        let handle = unsafe { session_handle(z_session_loan(session)) };
        engine_held(handle.expect("an open session has its handle")).clone()
    }

    /// Closing a session lets go of its listener's closure with no lock of the session held: a
    /// background listener's place with it, and a handle's listener's place at the handle's
    /// undeclare after the close. Each on a session of its own, as a session opens under the pico
    /// preset, whose `MAX_TRANSPORT_EVENTS_LISTENERS` admits one listener. Turned red, in a debug
    /// build, by a close that gives a place back under the session's lock.
    #[test]
    fn closing_a_session_lets_its_listeners_go_with_no_lock_held() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        let kind = Kind::TransportEventsListener;

        let mut session = listening_on_loopback();
        let engine = engine_of_session(&session);
        let places = free(&engine, kind);
        declare_background(&session, &engine, &DROPS);
        // SAFETY: the session is live and owned here.
        let closed = unsafe { z_close(z_session_loan_mut(&mut session), core::ptr::null()) };
        assert_eq!(closed, Z_OK);
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            1,
            "the close released the background listener's context"
        );
        assert_eq!(
            free(&engine, kind),
            places,
            "the close gave the background listener's place back"
        );
        drop(engine);
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };

        let mut session = listening_on_loopback();
        let engine = engine_of_session(&session);
        let places = free(&engine, kind);
        let mut listener = declare_handled(&session, &engine, &DROPS);
        // SAFETY: the session is live and owned here.
        let closed = unsafe { z_close(z_session_loan_mut(&mut session), core::ptr::null()) };
        assert_eq!(closed, Z_OK);
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            2,
            "the close released the handle's listener's context"
        );
        assert_eq!(
            Some(free(&engine, kind)),
            places.checked_sub(1),
            "the handle holds its place past the close"
        );
        // SAFETY: the handle written by the declare above, let go of once.
        let undeclared = unsafe {
            z_undeclare_transport_events_listener(z_transport_events_listener_move(&mut listener))
        };
        assert_eq!(undeclared, Z_OK);
        assert!(listener.handle.is_null());
        assert_eq!(DROPS.load(Ordering::SeqCst), 2, "nothing is released twice");
        assert_eq!(
            free(&engine, kind),
            places,
            "the undeclare gave the place back"
        );
        drop(engine);
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// Dropping the session with no close lets go of its listener as the session goes, with no
    /// lock of the session held; a listener undeclared by its handle before gives its place back
    /// to the next. Turned red, in a debug build, by a drop that gives a place back under the
    /// session's lock.
    #[test]
    fn dropping_a_session_lets_its_listeners_go_with_no_lock_held() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        let mut session = listening_on_loopback();
        let engine = engine_of_session(&session);
        let places = free(&engine, Kind::TransportEventsListener);
        let mut listener = declare_handled(&session, &engine, &DROPS);
        // SAFETY: the handle written by the declare above, let go of once.
        let undeclared = unsafe {
            z_undeclare_transport_events_listener(z_transport_events_listener_move(&mut listener))
        };
        assert_eq!(undeclared, Z_OK);
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            1,
            "the undeclare released its context"
        );
        assert_eq!(
            free(&engine, Kind::TransportEventsListener),
            places,
            "the undeclare gave its place back"
        );
        declare_background(&session, &engine, &DROPS);
        drop(engine);
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            2,
            "the session's end released the background listener's context"
        );
    }

    /// A session holds as many transport listeners as its places, and one more is refused with
    /// `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, nothing declared and its context released. Turned red by a
    /// declare that holds a listener past the session's places, or keeps a refused closure.
    #[test]
    fn a_listener_past_the_sessions_places_is_refused_and_released() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        let mut session = listening_on_loopback();
        let engine = engine_of_session(&session);
        let places = free(&engine, Kind::TransportEventsListener);
        assert!(places > 0, "the session lays transport listener places out");
        for _ in 0..places {
            declare_background(&session, &engine, &DROPS);
        }
        let mut closure = counting(&DROPS);
        let mut listener = z_owned_transport_events_listener_t::null_value();
        // SAFETY: a live session, a local handle and a local closure, consumed by the declare.
        let refused = unsafe {
            z_declare_transport_events_listener(
                z_session_loan(&session),
                &mut listener,
                z_closure_transport_event_move(&mut closure),
                core::ptr::null(),
            )
        };
        assert_eq!(refused, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(listener.handle.is_null(), "nothing is declared");
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            1,
            "the refused closure is released"
        );
        drop(engine);
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
        assert_eq!(
            Some(DROPS.load(Ordering::SeqCst)),
            places.checked_add(1),
            "the session's end released every background listener's context"
        );
    }

    /// A link events listener lies in a place of its session's own, and its undeclare gives the
    /// place back. Turned red by a link listener kept outside its session's places, or by an
    /// undeclare that leaves its place held.
    #[test]
    fn a_link_events_listener_holds_a_place_of_its_session() {
        unsafe extern "C" fn on_link_event(_: *mut z_loaned_link_event_t, _: *mut c_void) {}
        let mut session = listening_on_loopback();
        let engine = engine_of_session(&session);
        let places = free(&engine, Kind::LinkEventsListener);
        assert!(places > 0, "the session lays link listener places out");
        // SAFETY: a zeroed closure is the null one, which the constructor overwrites.
        let mut closure: z_owned_closure_link_event_t = unsafe { core::mem::zeroed() };
        // SAFETY: a local closure with no context.
        let made = unsafe {
            z_closure_link_event(
                &mut closure,
                Some(on_link_event),
                None,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(made, Z_OK);
        let mut listener = z_owned_link_events_listener_t::null_value();
        // SAFETY: a live session and a local closure, consumed by the declare.
        let declared = unsafe {
            z_declare_link_events_listener(
                z_session_loan(&session),
                &mut listener,
                z_closure_link_event_move(&mut closure),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(declared, Z_OK);
        assert_eq!(
            free(&engine, Kind::LinkEventsListener),
            places - 1,
            "the listener holds a place"
        );
        // SAFETY: the handle written by the declare above, let go of once.
        let undeclared =
            unsafe { z_undeclare_link_events_listener(z_link_events_listener_move(&mut listener)) };
        assert_eq!(undeclared, Z_OK);
        assert_eq!(
            free(&engine, Kind::LinkEventsListener),
            places,
            "the undeclare gives the place back"
        );
        drop(engine);
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }
}
