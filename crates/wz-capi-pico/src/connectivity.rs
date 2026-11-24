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

use alloc::sync::Arc;
use core::ffi::{c_int, c_void};

use wz_capi_port::os::{Mutex, MutexGuard};

use wz_capi_port::told::{ToldKey, ToldPlane};
use wz_capi_port::SessionEngine;
use wz_session_core::face::{FaceEventKind, FaceLinkRow, FaceSnapshot, LinkSnapshot};
use wz_session_core::link::LinkKind;

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
    engine_of, engine_ref, session_handle, z_loaned_session_t, Engine, PicoSessionHandle,
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
        let boxed: Box<[u8]> = bytes.into();
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
    zid.id.iter().any(|b| *b != 0)
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

/// The transport pico reports for one established face.
fn transport_of(snapshot: &FaceSnapshot) -> z_loaned_transport_t {
    pico_transport(snapshot.zid, snapshot.whatami, snapshot.is_multicast)
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
        at += 1;
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

/// The link pico reports for one link of an established face.
///
/// A group member's link starts at the endpoint the session joined the group by, as pico
/// labels it (`vendor/zenoh-pico/src/transport/multicast/rx.c` @
/// `entry->common._link_src = _z_endpoint_to_string(&ztm->_common._link->_endpoint);`),
/// written as pico writes an endpoint ([`pico_group_endpoint_text`]). Its other fields are
/// those of the group's own link, which pico reads off the transport
/// (`vendor/zenoh-pico/include/zenoh-pico/api/primitives.h` @ `*mtu = transport->_link->_mtu;`):
/// a raweth group's link is a 1514-byte frame (`vendor/zenoh-pico/src/transport/raweth/link.c`
/// @ `static uint16_t _z_get_link_mtu_raweth(void) { return _ZP_MAX_ETH_FRAME_SIZE; }`),
/// unreliable and unstreamed, and its member has no `dst`: pico labels a member by the address
/// its receive gave, which it renders only as an IPv4 or IPv6 address with a port
/// (`vendor/zenoh-pico/src/transport/multicast/rx.c` @
/// `} else if (remote_addr->len == 16 + sizeof(uint16_t)) {`), and a raweth receive gives four
/// bytes of the source MAC (`vendor/zenoh-pico/src/link/transport/udp/raweth_unix.c` @
/// `addr->len = sizeof(ETH_ALEN);`). MEASURED against the real library: `dst=` and `mtu=1514`.
fn link_of(zid: [u8; 16], link: &LinkSnapshot) -> z_loaned_link_t {
    pico_link(
        zid,
        &link.src,
        &link.dst,
        (link.kind, link.mtu),
        link.group.as_ref().map(|group| group.endpoint.as_str()),
    )
}

/// The link pico reports for the link of `row`, as [`link_of`] reads a snapshot's.
fn link_of_row(row: &FaceLinkRow) -> z_loaned_link_t {
    pico_link(
        row.zid,
        &row.src,
        &row.dst,
        (row.kind, row.mtu),
        row.group_endpoint.as_deref(),
    )
}

/// The link pico reports from `src` to `dst` of a link of `kind` and `mtu`, a group member's
/// starting at the endpoint the group was joined by.
fn pico_link(
    zid: [u8; 16],
    src: &str,
    dst: &str,
    (kind, mtu): (Option<LinkKind>, u16),
    group_endpoint: Option<&str>,
) -> z_loaned_link_t {
    let raweth = group_endpoint.is_some_and(|endpoint| endpoint.starts_with("reth/"));
    let (mtu, is_streamed, is_reliable) = if raweth {
        (1514, false, false)
    } else {
        pico_link_properties(kind, mtu)
    };
    let src = match group_endpoint {
        Some(endpoint) => ConnText::new(pico_group_endpoint_text(endpoint).as_bytes()),
        None => ConnText::new(src.as_bytes()),
    };
    let dst = if raweth { "" } else { dst };
    z_loaned_link_t {
        zid: z_id_t { id: zid },
        src,
        dst: ConnText::new(dst.as_bytes()),
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

/// An event a listener may be handed while its history is replayed, which says whether the row it
/// is of came (`PUT`) or left.
pub(crate) trait Arrival: ConnValue {
    /// Whether the event tells its row came.
    fn came(&self) -> bool;
}

impl Arrival for z_loaned_transport_event_t {
    fn came(&self) -> bool {
        self.kind == Z_SAMPLE_KIND_PUT
    }
}

impl Arrival for z_loaned_link_event_t {
    fn came(&self) -> bool {
        self.kind == Z_SAMPLE_KIND_PUT
    }
}

/// What arrives while a history is replayed, waiting behind it in order, each event with the key
/// of the row it is of, in [`REPLAY_ROWS`] rows reserved with the listener. What arrives of a row
/// already waiting is folded into it, so a row holds at most two events, its DEL and then its PUT.
struct Pending<E> {
    rows: [Option<(E, ToldKey)>; REPLAY_ROWS],
    len: usize,
    /// An event found every row held: it and what follows it are not held, and the listener is
    /// brought to the faces as they stand once what is held was delivered
    /// ([`Delivery::finish_replay`]).
    overflowed: bool,
}

impl<E: Arrival> Pending<E> {
    fn new() -> Self {
        Self {
            rows: core::array::from_fn(|_| None),
            len: 0,
            overflowed: false,
        }
    }

    /// Hold `event` of the row of `key` behind what waits. A PUT still waiting and the DEL of
    /// its row are neither told: the row came and went inside the replay. The same kind of event
    /// again is told once. A DEL waiting and the PUT of its row are both told, in order: a
    /// reconnect. An event that finds every row held is let go of.
    fn hold(&mut self, mut event: E, key: ToldKey) {
        if !self.overflowed {
            match self.last_of(&key) {
                Some((at, true)) if !event.came() => self.remove(at),
                Some((_, came)) if came == event.came() => {}
                _ => match self.rows.get_mut(self.len) {
                    Some(row) => {
                        *row = Some((event, key));
                        // The row just filled lies below the rows' count.
                        self.len = self.len.saturating_add(1);
                        return;
                    }
                    None => self.overflowed = true,
                },
            }
        }
        // SAFETY: the event is this frame's alone: it was not held.
        unsafe { event.clear() };
    }

    /// The row the last event of `key` waits in, and whether it tells its row came.
    fn last_of(&self, key: &ToldKey) -> Option<(usize, bool)> {
        self.rows
            .iter()
            .take(self.len)
            .enumerate()
            .rev()
            .find_map(|(at, row)| {
                let (event, held) = row.as_ref()?;
                (held == key).then(|| (at, event.came()))
            })
    }

    /// Let go of the event at `at`, the ones after it moving up a row.
    fn remove(&mut self, at: usize) {
        if let Some((mut event, _)) = self.rows.get_mut(at).and_then(Option::take) {
            // SAFETY: held events are owned by the queue.
            unsafe { event.clear() };
        }
        if let Some(after) = self.rows.get_mut(at..self.len) {
            if !after.is_empty() {
                after.rotate_left(1);
            }
        }
        self.len = self.len.saturating_sub(1);
    }

    /// The first event waiting, taken out.
    fn next(&mut self) -> Option<(E, ToldKey)> {
        let first = self.rows.first_mut()?.take()?;
        if let Some(held) = self.rows.get_mut(..self.len) {
            if !held.is_empty() {
                held.rotate_left(1);
            }
        }
        self.len = self.len.saturating_sub(1);
        Some(first)
    }

    /// Whether an event found every row held since this was last asked.
    fn take_overflow(&mut self) -> bool {
        core::mem::take(&mut self.overflowed)
    }

    /// Let go of every event waiting.
    fn release(&mut self) {
        while let Some((mut event, _)) = self.next() {
            // SAFETY: held events are owned by the queue.
            unsafe { event.clear() };
        }
        self.overflowed = false;
    }
}

/// Where a listener's deliveries stand.
enum Phase<E> {
    /// The history is being replayed on the declaring thread; what arrives
    /// meanwhile waits here, in order.
    Replaying(Pending<E>),
    /// Deliveries go straight to the closure.
    Live,
}

/// One declared listener's way to its closure.
///
/// `gate` holds the closure and is held for the length of every call, so the
/// thread that undeclares can take the closure out under it and know nothing is
/// running; `phase` is only ever held briefly and never across a call, so a peer
/// arriving during a replay is queued rather than made to wait.
pub(crate) struct Delivery<E: Arrival + Send> {
    gate: Mutex<Option<CClosure<Callback<E>>>>,
    phase: Mutex<Phase<E>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock()
}

impl<E: Arrival + Send> Delivery<E> {
    fn new(closure: CClosure<Callback<E>>, replaying: bool) -> Self {
        Self {
            gate: Mutex::new(Some(closure)),
            phase: Mutex::new(if replaying {
                Phase::Replaying(Pending::new())
            } else {
                Phase::Live
            }),
        }
    }

    /// Deliver `event` of the row of `key`, or hold it while the history is being replayed.
    fn deliver(&self, event: E, key: ToldKey) {
        {
            let mut phase = lock(&self.phase);
            if let Phase::Replaying(pending) = &mut *phase {
                pending.hold(event, key);
                return;
            }
        }
        self.call(event);
    }

    /// Call the closure with `event`, then release the event. A listener that
    /// has been undeclared has no closure and the event is just released.
    fn call(&self, mut event: E) {
        {
            let gate = lock(&self.gate);
            if let Some(closure) = gate.as_ref() {
                if let Some(call) = closure.call {
                    let context = closure.context.0;
                    // A panic unwinding out of the C callback across this
                    // `extern "C"` boundary is UB and would tear down the drive
                    // thread.
                    let _ = catch(|| unsafe { call(&mut event as *mut E, context) });
                }
            }
        }
        // SAFETY: the event is this frame's alone; a callback that kept the
        // peer took it out through `take_from_loaned`, which nulled it.
        unsafe { event.clear() };
    }

    /// Deliver what arrived during the replay, in order, and go live. A held event is told only
    /// when `tell` says the listener is to hear it, asked whether its row `came` and of which
    /// row (`SessionEngine::tell_came`, `SessionEngine::tell_went`); once the queue is drained
    /// after it ran out of rows, `converge` brings the listener to the faces as they stand. The
    /// phase is switched only when the queue is found empty and whole under its lock, so an event
    /// cannot be delivered ahead of one still held.
    fn finish_replay(
        &self,
        mut tell: impl FnMut(bool, &ToldKey) -> bool,
        mut converge: impl FnMut(&Self),
    ) {
        loop {
            let next = {
                let mut phase = lock(&self.phase);
                match &mut *phase {
                    Phase::Replaying(pending) => match pending.next() {
                        Some(held) => Some(held),
                        None if pending.take_overflow() => None,
                        None => {
                            *phase = Phase::Live;
                            return;
                        }
                    },
                    Phase::Live => return,
                }
            };
            match next {
                Some((mut event, key)) => {
                    if tell(event.came(), &key) {
                        self.call(event);
                    } else {
                        // SAFETY: the event is this frame's alone: it is not told.
                        unsafe { event.clear() };
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
        // What was still held is released with the listener: a delivery kept in a place is never
        // dropped, so nothing else would free it.
        let mut phase = lock(&self.phase);
        if let Phase::Replaying(pending) = &mut *phase {
            pending.release();
        }
        *phase = Phase::Live;
    }
}

impl<E: Arrival + Send> Drop for Delivery<E> {
    fn drop(&mut self) {
        self.retire();
    }
}

/// What a listener's place keeps past its handle that the hub lets go of with the listener: its
/// closure, once no call is running it.
trait LetGo {
    fn let_go(&self);
}

impl<E: Arrival + Send> LetGo for Delivery<E> {
    fn let_go(&self) {
        self.retire();
    }
}

/// What a link events listener's place keeps past its handle: its delivery and the transport it
/// is filtered to, if any.
pub(crate) struct LinkListener {
    delivery: Delivery<z_loaned_link_event_t>,
    /// `(zid, is_multicast)` — pico's transport filter matches on exactly these
    /// two (`vendor/zenoh-pico/src/api/api.c` @
    /// `bool _z_info_transport_filter_match(`).
    filter: Option<([u8; 16], bool)>,
}

impl LinkListener {
    fn wants(&self, transport: &z_loaned_transport_t) -> bool {
        self.filter.is_none_or(|(zid, multicast)| {
            zid == transport.zid.id && multicast == transport.is_multicast
        })
    }
}

impl LetGo for LinkListener {
    fn let_go(&self) {
        self.delivery.retire();
    }
}

/// Behind an owned transport events listener: its session's hub and its id there, which the
/// listener's undeclare takes off the hub. It lies in the listener's place, a place of the
/// session's own for the kind (`crate::object_slot::Kind::TransportEventsListener`).
pub(crate) struct TransportListenerState {
    hub: Arc<Connectivity>,
    id: u64,
}

/// A transport events listener's place: its handle's state, which the handle lets go of (none for
/// a background listener), and the delivery the hub calls, kept past it; the last of the handle,
/// the hub's hold and a dispatch in flight gives the place back (`crate::object_slot::Answering`).
pub(crate) type TransportPlace = Answering<TransportListenerState, TransportKept>;

/// What a transport events listener's place keeps past its handle: the delivery the hub calls.
pub(crate) type TransportKept = Delivery<z_loaned_transport_event_t>;

/// Behind an owned link events listener, as [`TransportListenerState`] is behind a transport one,
/// in a place of the session's own for the kind (`crate::object_slot::Kind::LinkEventsListener`).
pub(crate) struct LinkListenerState {
    hub: Arc<Connectivity>,
    id: u64,
}

/// A link events listener's place, as [`TransportPlace`] is a transport one's: what it keeps past
/// its handle is its delivery and its filter.
pub(crate) type LinkPlace = Answering<LinkListenerState, LinkListener>;

/// A listener's state as its place lays it beside what the place keeps past it.
trait Listened {
    type Kept: LetGo;
}

impl Listened for TransportListenerState {
    type Kept = TransportKept;
}

impl Listened for LinkListenerState {
    type Kept = LinkListener;
}

/// A declared listener as the hub holds it: its id, its object, and the hub's hold of its place,
/// which keeps the place standing while a dispatch can reach it.
struct Entry<S> {
    id: u64,
    object: *mut S,
    held: HeldIn,
}

// SAFETY: the object is reached only through the place the entry holds, whose kept part is behind
// its own locks; the entry is moved between threads only under the hub's lock.
unsafe impl<S> Send for Entry<S> {}

/// The hub's listeners of one kind: a row for each the session's limit of the kind admits, and
/// the id the next one is given.
struct Table<S, const N: usize> {
    rows: [Option<Entry<S>>; N],
    /// The rows whose listener's history is being replayed. The engine notes what the listener
    /// was told under its row (`wz_capi_port::told`), so the row is not given to another listener
    /// until the replay forgot those notes, even when the listener was undeclared meanwhile (from
    /// its own callback, say): a listener given the row then would find the notes as its own.
    replaying: [bool; N],
    last_id: u64,
}

impl<S, const N: usize> Table<S, N> {
    fn new() -> Self {
        Self {
            rows: core::array::from_fn(|_| None),
            replaying: [false; N],
            last_id: 0,
        }
    }

    /// The first row no listener holds and no replay keeps.
    fn free_row(&self) -> Option<usize> {
        self.rows
            .iter()
            .zip(&self.replaying)
            .position(|(row, replaying)| row.is_none() && !replaying)
    }
}

type TransportTable =
    Table<TransportListenerState, { wz_session_core::caps::MAX_TRANSPORT_EVENTS_LISTENERS }>;
type LinkTable = Table<LinkListenerState, { wz_session_core::caps::MAX_LINK_EVENTS_LISTENERS }>;

/// The listener of the first row of `table` from `at` on that holds one, and a hold of its place
/// for the call, with `at` moved past its row; `None` past the last row. The table's lock is let
/// go of before this returns, so a call made with the hold does not wait on it.
fn next_in<S: Listened, const N: usize>(
    table: &Mutex<Table<S, N>>,
    at: &mut usize,
) -> Option<(*mut S, HeldIn)> {
    let table = lock(table);
    while let Some(row) = table.rows.get(*at) {
        *at += 1;
        if let Some(entry) = row {
            // SAFETY: the entry's place stands while the entry holds it, which it does under the
            // lock held here.
            let hold = unsafe { hold_entity::<S, S::Kept>(entry.object) };
            return Some((entry.object, hold));
        }
    }
    None
}

/// The entry of listener `id`, taken off `table`; `None` when no listener has that id.
fn take_in<S, const N: usize>(table: &Mutex<Table<S, N>>, id: u64) -> Option<Entry<S>> {
    let mut table = lock(table);
    let row = table
        .rows
        .iter_mut()
        .find(|row| row.as_ref().is_some_and(|entry| entry.id == id))?;
    row.take()
}

/// Any entry left in `table`, taken off it.
fn take_any_in<S, const N: usize>(table: &Mutex<Table<S, N>>) -> Option<Entry<S>> {
    lock(table).rows.iter_mut().find_map(Option::take)
}

/// Let go of a listener taken off the hub: its closure, once no call is running it, and the hub's
/// hold of its place, which gives the place back when its owner went first.
fn retire_entry<S: Listened>(entry: Entry<S>) {
    // SAFETY: the entry's hold keeps the place standing until it is dropped below.
    unsafe { (*kept_at::<S, S::Kept>(entry.object)).let_go() };
    // The hold may be the place's last, whose give-back takes the session's lock.
    debug_assert!(
        !wz_capi_port::sync::SessionHeld::any_here(),
        "a connectivity listener's place is let go of under a session's lock"
    );
    drop(entry.held);
}

/// Put the listener whose owner holds the place at `object` in a free row of `table`, holding its
/// place for the hub, and tell `name` its id before the row can be read: the row, which the
/// listener's told bits are noted under while it replays (`wz_capi_port::told`), and which a
/// listener that `replays` holds until [`end_replay`] even past its undeclare. `None` when every
/// row is held, the listener's closure let go of and its owner's place given back.
///
/// # Safety
/// `object` is a place of `Answering<S, S::Kept>` its owner filled and holds, and lets go of here
/// when this answers `None`.
unsafe fn admit<S: Listened, const N: usize>(
    table: &Mutex<Table<S, N>>,
    object: *mut S,
    name: impl FnOnce(u64),
    replays: bool,
) -> Option<usize> {
    // SAFETY: the caller's: the owner holds the place.
    let held = unsafe { hold_entity::<S, S::Kept>(object) };
    let mut rows = lock(table);
    let id = rows.last_id.wrapping_add(1);
    if let Some(at) = rows.free_row() {
        rows.last_id = id;
        name(id);
        rows.rows[at] = Some(Entry { id, object, held });
        rows.replaying[at] = replays;
        return Some(at);
    }
    drop(rows);
    retire_entry(Entry { id, object, held });
    // SAFETY: the caller's: the owner lets go of the place once, here, with no other hold left.
    unsafe { retire_entity::<S, S::Kept>(object) };
    None
}

/// The replay of the listener of row `at` of `table` ended and the engine forgot what it was told
/// (`SessionEngine::forget_told`): the row is free for another listener once its own went.
fn end_replay<S, const N: usize>(table: &Mutex<Table<S, N>>, at: usize) {
    if let Some(replaying) = lock(table).replaying.get_mut(at) {
        *replaying = false;
    }
}

/// Count the closure `gate` holds in the place of the listener at `object`: the place stands until
/// its `drop(context)` has run, which the hub's let-go runs while it still holds the place, and
/// nothing is allocated for the closure's release.
///
/// # Safety
/// As [`count_in_entity`]: `object` is the place of an `Answering<S, K>` its owner filled and
/// holds, and `gate` lies in it.
unsafe fn count_closure<S, K, C>(object: *const S, gate: &Mutex<Option<CClosure<C>>>) {
    if let Some(closure) = lock(gate).as_mut() {
        // SAFETY: the caller's.
        unsafe { count_in_entity::<S, K, C>(object, closure) };
    }
}

/// Whether `listener` of `plane`, whose history is being replayed, is to be told an event that
/// its row of `key` `came` or left ([`wz_capi_port::told`]).
fn told(engine: &Engine, plane: ToldPlane, listener: usize, came: bool, key: &ToldKey) -> bool {
    if came {
        SessionEngine::tell_came(engine, plane, listener, key)
    } else {
        SessionEngine::tell_went(engine, plane, listener, key)
    }
}

/// Bring the transport listener of row `listener`, whose queue ran out of rows while its history
/// was replayed, to the faces as they stand: each row it was told came that has gone is told left,
/// then each row that stands and it was not told is told came. A row that went and came back under
/// its key is told neither, the one reconnect the contract says may be lost past the queue.
fn converge_transports(engine: &Engine, listener: usize, delivery: &TransportKept) {
    let plane = ToldPlane::Transports;
    while let Some(row) = SessionEngine::first_told_gone(engine, plane, listener) {
        if !SessionEngine::tell_went(engine, plane, listener, &ToldKey::of_row(&row)) {
            break;
        }
        delivery.call(z_loaned_transport_event_t {
            kind: Z_SAMPLE_KIND_DELETE,
            transport: transport_of_row(&row),
        });
    }
    for row in rows(engine).filter(|row| row.link == 0) {
        if SessionEngine::tell_came(engine, plane, listener, &ToldKey::of_row(&row)) {
            delivery.call(z_loaned_transport_event_t {
                kind: Z_SAMPLE_KIND_PUT,
                transport: transport_of_row(&row),
            });
        }
    }
}

/// Bring the link listener of row `slot` to the links as they stand, as [`converge_transports`]
/// does a transport listener, the links it is filtered to only.
fn converge_links(engine: &Engine, slot: usize, listener: &LinkListener) {
    let plane = ToldPlane::Links;
    while let Some(row) = SessionEngine::first_told_gone(engine, plane, slot) {
        if !SessionEngine::tell_went(engine, plane, slot, &ToldKey::of_row(&row)) {
            break;
        }
        listener.delivery.call(z_loaned_link_event_t {
            kind: Z_SAMPLE_KIND_DELETE,
            link: link_of_row(&row),
        });
    }
    for row in rows(engine) {
        if listener.wants(&transport_of_row(&row))
            && SessionEngine::tell_came(engine, plane, slot, &ToldKey::of_row(&row))
        {
            listener.delivery.call(z_loaned_link_event_t {
                kind: Z_SAMPLE_KIND_PUT,
                link: link_of_row(&row),
            });
        }
    }
}

/// The transport and link listeners of ONE session, and the watcher that feeds
/// them; see the module doc for why there is one.
pub(crate) struct Connectivity {
    transports: Mutex<TransportTable>,
    links: Mutex<LinkTable>,
}

impl Connectivity {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            transports: Mutex::new(Table::new()),
            links: Mutex::new(Table::new()),
        })
    }

    /// The transport listener of the first row from `at` on, held for a call (`next_in`).
    fn next_transport(&self, at: &mut usize) -> Option<(*mut TransportListenerState, HeldIn)> {
        next_in(&self.transports, at)
    }

    /// A face arrived or left: tell every listener, in pico's order.
    ///
    /// Arrival is the transport, then its link; departure is the link, then the
    /// transport.
    pub(crate) fn on_face_event(&self, kind: FaceEventKind, snapshot: &FaceSnapshot) {
        match kind {
            FaceEventKind::Up => {
                self.fan_transport(Z_SAMPLE_KIND_PUT, snapshot);
                self.fan_links(Z_SAMPLE_KIND_PUT, snapshot);
            }
            FaceEventKind::Down => {
                self.fan_links(Z_SAMPLE_KIND_DELETE, snapshot);
                self.fan_transport(Z_SAMPLE_KIND_DELETE, snapshot);
            }
        }
    }

    fn fan_transport(&self, kind: z_sample_kind_t, snapshot: &FaceSnapshot) {
        let key = ToldKey {
            zid: snapshot.zid,
            is_multicast: snapshot.is_multicast,
            link: 0,
        };
        let mut at = 0;
        while let Some((object, hold)) = self.next_transport(&mut at) {
            // SAFETY: `hold` keeps the place, and so its delivery, standing for the call.
            let delivery = unsafe { &*kept_at::<TransportListenerState, TransportKept>(object) };
            delivery.deliver(
                z_loaned_transport_event_t {
                    kind,
                    transport: transport_of(snapshot),
                },
                key,
            );
            drop(hold);
        }
    }

    fn fan_links(&self, kind: z_sample_kind_t, snapshot: &FaceSnapshot) {
        let transport = transport_of(snapshot);
        let mut at = 0;
        while let Some((object, hold)) = next_in(&self.links, &mut at) {
            // SAFETY: `hold` keeps the place, and so its listener, standing for the call.
            let listener = unsafe { &*kept_at::<LinkListenerState, LinkListener>(object) };
            if listener.wants(&transport) {
                for (index, link) in snapshot.links.iter().enumerate() {
                    listener.delivery.deliver(
                        z_loaned_link_event_t {
                            kind,
                            link: link_of(snapshot.zid, link),
                        },
                        ToldKey {
                            zid: snapshot.zid,
                            is_multicast: snapshot.is_multicast,
                            link: index,
                        },
                    );
                }
            }
            drop(hold);
        }
    }

    /// Declare a transport listener in a place of `engine`'s session, replaying the peers
    /// connected now first when `history` is set: its object, which its owner lets go of with
    /// [`release_transport_listener`]. `_Z_ERR_SYSTEM_OUT_OF_MEMORY` when every place or every
    /// row of the hub is held; the closure is let go of then, which runs its `drop(context)`.
    fn declare_transport(
        self: &Arc<Self>,
        engine: &Arc<Engine>,
        history: bool,
        closure: CClosure<Callback<z_loaned_transport_event_t>>,
    ) -> Result<*mut TransportListenerState, ZResult> {
        let Some(place) =
            Slot::<TransportPlace>::take_entity(engine, Kind::TransportEventsListener)
        else {
            return Err(Z_ERR_SYSTEM_OUT_OF_MEMORY);
        };
        let object = place
            .fill(Answering::keeping(
                TransportListenerState {
                    hub: Arc::clone(self),
                    id: 0,
                },
                Delivery::new(closure, history),
            ))
            .cast::<TransportListenerState>();
        // SAFETY: the place was filled just above and its owner holds it; the closure is counted
        // in it before anything can call it or let it go.
        unsafe {
            count_closure::<TransportListenerState, TransportKept, _>(
                object,
                &(*kept_at::<TransportListenerState, TransportKept>(object)).gate,
            );
        }
        // Registered BEFORE the peers are read, so a peer that arrives in
        // between is queued rather than missed.
        // SAFETY: the place was filled just above and its owner holds it; the id is written
        // before the entry can be read.
        let Some(slot) =
            (unsafe { admit(&self.transports, object, |id| (*object).id = id, history) })
        else {
            return Err(Z_ERR_SYSTEM_OUT_OF_MEMORY);
        };
        if history {
            // SAFETY: the owner holds the place for the length of the replay.
            let delivery = unsafe { &*kept_at::<TransportListenerState, TransportKept>(object) };
            let engine = Arc::as_ref(engine);
            let plane = ToldPlane::Transports;
            for row in rows(engine).filter(|row| row.link == 0) {
                if SessionEngine::tell_came(engine, plane, slot, &ToldKey::of_row(&row)) {
                    delivery.call(z_loaned_transport_event_t {
                        kind: Z_SAMPLE_KIND_PUT,
                        transport: transport_of_row(&row),
                    });
                }
            }
            delivery.finish_replay(
                |came, key| told(engine, plane, slot, came, key),
                |delivery| converge_transports(engine, slot, delivery),
            );
            SessionEngine::forget_told(engine, plane, slot);
            end_replay(&self.transports, slot);
        }
        Ok(object)
    }

    /// Declare a link listener in a place of `engine`'s session, replaying the links connected
    /// now first when `history` is set; `filter` narrows it to one transport. Its object, which
    /// its owner lets go of with [`release_link_listener`]; refused as
    /// [`Self::declare_transport`] is, by the session's `MAX_LINK_EVENTS_LISTENERS`.
    fn declare_link(
        self: &Arc<Self>,
        engine: &Arc<Engine>,
        history: bool,
        filter: Option<([u8; 16], bool)>,
        closure: CClosure<Callback<z_loaned_link_event_t>>,
    ) -> Result<*mut LinkListenerState, ZResult> {
        let Some(place) = Slot::<LinkPlace>::take_entity(engine, Kind::LinkEventsListener) else {
            return Err(Z_ERR_SYSTEM_OUT_OF_MEMORY);
        };
        let object = place
            .fill(Answering::keeping(
                LinkListenerState {
                    hub: Arc::clone(self),
                    id: 0,
                },
                LinkListener {
                    delivery: Delivery::new(closure, history),
                    filter,
                },
            ))
            .cast::<LinkListenerState>();
        // SAFETY: as in `declare_transport`.
        unsafe {
            count_closure::<LinkListenerState, LinkListener, _>(
                object,
                &(*kept_at::<LinkListenerState, LinkListener>(object))
                    .delivery
                    .gate,
            );
        }
        // SAFETY: as in `declare_transport`.
        let Some(slot) = (unsafe { admit(&self.links, object, |id| (*object).id = id, history) })
        else {
            return Err(Z_ERR_SYSTEM_OUT_OF_MEMORY);
        };
        if history {
            // SAFETY: the owner holds the place for the length of the replay.
            let listener = unsafe { &*kept_at::<LinkListenerState, LinkListener>(object) };
            let engine = Arc::as_ref(engine);
            let plane = ToldPlane::Links;
            for row in rows(engine) {
                if listener.wants(&transport_of_row(&row))
                    && SessionEngine::tell_came(engine, plane, slot, &ToldKey::of_row(&row))
                {
                    listener.delivery.call(z_loaned_link_event_t {
                        kind: Z_SAMPLE_KIND_PUT,
                        link: link_of_row(&row),
                    });
                }
            }
            listener.delivery.finish_replay(
                |came, key| told(engine, plane, slot, came, key),
                |_| converge_links(engine, slot, listener),
            );
            SessionEngine::forget_told(engine, plane, slot);
            end_replay(&self.links, slot);
        }
        Ok(object)
    }

    fn undeclare_transport(&self, id: u64) {
        if let Some(entry) = take_in(&self.transports, id) {
            retire_entry(entry);
        }
    }

    fn undeclare_link(&self, id: u64) {
        if let Some(entry) = take_in(&self.links, id) {
            retire_entry(entry);
        }
    }

    /// Let go of every listener, which releases their C contexts.
    pub(crate) fn shutdown(&self) {
        while let Some(entry) = take_any_in(&self.transports) {
            retire_entry(entry);
        }
        while let Some(entry) = take_any_in(&self.links) {
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
) -> Option<(&'a PicoSessionHandle, &'a Arc<Connectivity>)> {
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
        for row in rows(engine_ref(handle)) {
            if let Some((zid, multicast)) = filter {
                if zid != row.zid || multicast != row.is_multicast {
                    continue;
                }
            }
            let mut held = HeldLink(link_of_row(&row));
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

/// Undeclare the transport events listener whose state is at `object` and let go of its handle:
/// taken off its hub, its closure let go of once no call is running it (which runs its
/// `drop(context)`), and its state dropped; the place goes back with the last of the handle and
/// a dispatch in flight.
///
/// # Safety
/// `object` is a live handle [`Connectivity::declare_transport`] answered, let go of once, here.
unsafe fn release_transport_listener(object: *mut TransportListenerState) {
    // SAFETY: the caller's: the state stands until `retire_entity` below.
    unsafe { (*object).hub.undeclare_transport((*object).id) };
    // SAFETY: the caller's; the owner lets go of the place once, here.
    unsafe { retire_entity::<TransportListenerState, TransportKept>(object) };
}

/// Undeclare the link events listener whose state is at `object` and let go of its handle, as
/// [`release_transport_listener`] does a transport one.
///
/// # Safety
/// `object` is a live handle [`Connectivity::declare_link`] answered, let go of once, here.
unsafe fn release_link_listener(object: *mut LinkListenerState) {
    // SAFETY: the caller's: the state stands until `retire_entity` below.
    unsafe { (*object).hub.undeclare_link((*object).id) };
    // SAFETY: the caller's; the owner lets go of the place once, here.
    unsafe { retire_entity::<LinkListenerState, LinkListener>(object) };
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
            |c| (c._this.context, c._this.call, c._this.drop),
            |c| c._this = z_owned_closure_transport_event_t::null_value(),
        );
        if handle.drive.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        let history = !options.is_null() && (*options).history;
        match hub.declare_transport(&engine_of(handle), history, closure) {
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
        retire_entity::<TransportListenerState, TransportKept>(
            listener.handle.cast::<TransportListenerState>(),
        );
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
            release_transport_listener(object.cast::<TransportListenerState>());
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
            |c| (c._this.context, c._this.call, c._this.drop),
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
        match hub.declare_link(&engine_of(handle), history, filter, closure) {
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
        retire_entity::<LinkListenerState, LinkListener>(
            listener.handle.cast::<LinkListenerState>(),
        );
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
            release_link_listener(object.cast::<LinkListenerState>());
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

    use std::sync::OnceLock;
    use wz_capi_core::faces::SharedSession;
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
        reenter: OnceLock<(Arc<Delivery<z_loaned_transport_event_t>>, u8)>,
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
                delivery.deliver(
                    z_loaned_transport_event_t {
                        kind: Z_SAMPLE_KIND_PUT,
                        transport: transport_with_zid(*arriving),
                    },
                    key_of(*arriving),
                );
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

    fn transport_closure(log: &'static Log) -> CClosure<Callback<z_loaned_transport_event_t>> {
        CClosure::uncounted(ctx(log), Some(on_transport), Some(released))
    }

    fn link_closure(log: &'static Log) -> CClosure<Callback<z_loaned_link_event_t>> {
        CClosure::uncounted(ctx(log), Some(on_link), Some(released))
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
    fn event_of(kind: z_sample_kind_t, first: u8) -> z_loaned_transport_event_t {
        z_loaned_transport_event_t {
            kind,
            transport: transport_with_zid(first),
        }
    }

    /// Every allocation of the test's own thread while `run` runs, counted.
    pub(crate) fn allocations(run: impl FnOnce()) -> usize {
        COUNTING.with(|count| count.set(Some(0)));
        run();
        COUNTING.with(|count| count.take()).unwrap_or(0)
    }

    std::thread_local! {
        static COUNTING: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    }

    /// The test binary's allocator: the system's, counting on a thread that asked
    /// ([`allocations`]).
    struct Counting;

    // SAFETY: every call is the system allocator's; the count is a thread's own cell.
    unsafe impl std::alloc::GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
            let _ = COUNTING.try_with(|count| {
                if let Some(seen) = count.get() {
                    count.set(Some(seen.saturating_add(1)));
                }
            });
            // SAFETY: the caller's.
            unsafe { std::alloc::System.alloc(layout) }
        }

        unsafe fn dealloc(&self, at: *mut u8, layout: std::alloc::Layout) {
            // SAFETY: the caller's.
            unsafe { std::alloc::System.dealloc(at, layout) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Counting = Counting;

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
        let hub = Connectivity::new();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        // Declared transport FIRST, so a registry that hands each watcher the
        // event in declaration order would put the transport ahead on a
        // departure too.
        let transport = hub
            .declare_transport(&engine, false, transport_closure(log))
            .expect("a place is free");
        let link = hub
            .declare_link(&engine, false, None, link_closure(log))
            .expect("a place is free");

        let peer = face(7, false, "tcp/127.0.0.1:7447");
        hub.on_face_event(FaceEventKind::Up, &peer);
        hub.on_face_event(FaceEventKind::Down, &peer);
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
            release_transport_listener(transport);
            release_link_listener(link);
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
        let hub = Connectivity::new();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let mut zid = [0u8; 16];
        zid[0] = 7;
        let link = hub
            .declare_link(&engine, false, Some((zid, false)), link_closure(log))
            .expect("a place is free");

        hub.on_face_event(FaceEventKind::Up, &face(7, false, "tcp/a"));
        hub.on_face_event(FaceEventKind::Up, &face(8, false, "tcp/other-zid"));
        hub.on_face_event(FaceEventKind::Up, &face(7, true, "tcp/multicast"));
        assert_eq!(seen(log), ["link PUT tcp/a"]);
        // SAFETY: the listener declared above, let go of once.
        unsafe { release_link_listener(link) };
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
        let delivery = Arc::new(Delivery::new(transport_closure(log), true));
        log.reenter.set((Arc::clone(&delivery), 9)).ok();

        // The replay: two peers connected now.
        for first in [1u8, 2] {
            delivery.call(z_loaned_transport_event_t {
                kind: Z_SAMPLE_KIND_PUT,
                transport: transport_with_zid(first),
            });
        }
        // The callback re-entered `deliver` while replaying: nothing ran yet.
        assert_eq!(
            seen(log),
            ["transport PUT 1", "transport PUT 2"],
            "what arrives during the replay waits for it"
        );

        delivery.finish_replay(|_, _| true, |_| {});
        assert_eq!(
            seen(log),
            ["transport PUT 1", "transport PUT 2", "transport PUT 9"],
            "it is delivered after the history, once though each replayed peer re-entered"
        );

        // Live now: a further arrival goes straight through.
        delivery.deliver(event_of(Z_SAMPLE_KIND_DELETE, 5), key_of(5));
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
        let delivery = Delivery::new(transport_closure(log), true);
        delivery.deliver(event_of(Z_SAMPLE_KIND_PUT, 4), key_of(4));
        delivery.deliver(event_of(Z_SAMPLE_KIND_PUT, 3), key_of(3));
        delivery.deliver(event_of(Z_SAMPLE_KIND_DELETE, 3), key_of(3));
        delivery.deliver(event_of(Z_SAMPLE_KIND_PUT, 6), key_of(6));
        delivery.finish_replay(|_, _| true, |_| {});
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
        let delivery = Delivery::new(transport_closure(log), true);
        delivery.deliver(event_of(Z_SAMPLE_KIND_DELETE, 5), key_of(5));
        delivery.deliver(event_of(Z_SAMPLE_KIND_DELETE, 5), key_of(5));
        delivery.deliver(event_of(Z_SAMPLE_KIND_PUT, 5), key_of(5));
        delivery.finish_replay(|_, _| true, |_| {});
        assert_eq!(seen(log), ["transport DEL 5", "transport PUT 5"]);
    }

    /// A queue that runs out of rows holds what fit, lets go of the rest, and once
    /// what it held was told hands the listener to the convergence, once, which is
    /// what brings it to the faces as they stand (`converge_transports`). An
    /// event the engine says the listener is not to hear is not told.
    ///
    /// # Control
    ///
    /// Dropping the arrival past the rows without marking the queue overflowed
    /// leaves the convergence uncalled and reds both assertions after the replay.
    #[test]
    fn a_queue_past_its_rows_converges_once_what_it_held_was_told() {
        let log = log();
        let delivery = Delivery::new(transport_closure(log), true);
        let firsts: Vec<u8> = (0..REPLAY_ROWS)
            .map(|at| u8::try_from(at).expect("a few rows").saturating_add(10))
            .collect();
        for first in &firsts {
            delivery.deliver(event_of(Z_SAMPLE_KIND_PUT, *first), key_of(*first));
        }
        // Past the rows: let go of, and what follows it too.
        delivery.deliver(event_of(Z_SAMPLE_KIND_PUT, 99), key_of(99));
        let mut converged = 0;
        delivery.finish_replay(
            // The engine says the listener is not to hear the first row held.
            |_, key| *key != key_of(firsts[0]),
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
        let delivery = Delivery::new(transport_closure(log), true);
        let held = allocations(|| {
            for at in 0..=REPLAY_ROWS {
                let first = u8::try_from(at).unwrap_or(u8::MAX);
                delivery.deliver(event_of(Z_SAMPLE_KIND_PUT, first), key_of(first));
            }
        });
        assert_eq!(held, 0, "the arrivals are held in place");
        // The allocator counts at all: a box made under it is counted.
        let control = allocations(|| drop(core::hint::black_box(Box::new(1u64))));
        assert_eq!(control, 1);
    }

    /// A row whose listener's history is being replayed is given to no other listener until the
    /// replay ended, even once no listener holds it: what the engine noted under the row belongs
    /// to the replay until it forgot it.
    ///
    /// # Control
    ///
    /// A free row read from `rows` alone (the replay's mark ignored) reds the first assertion.
    #[test]
    fn a_row_a_replay_keeps_is_given_to_no_other_listener_until_it_ended() {
        let table = Mutex::new(Table::<TransportListenerState, 2>::new());
        lock(&table).replaying[0] = true;
        assert_eq!(lock(&table).free_row(), Some(1), "the replay keeps row 0");
        lock(&table).replaying[1] = true;
        assert_eq!(lock(&table).free_row(), None, "both rows kept");
        end_replay(&table, 0);
        assert_eq!(
            lock(&table).free_row(),
            Some(0),
            "the replay that ended frees it"
        );
        end_replay(&table, 9);
        assert_eq!(
            lock(&table).free_row(),
            Some(0),
            "a row past the table is no row"
        );
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
        let hub = Connectivity::new();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let object = hub
            .declare_transport(&engine, false, transport_closure(log))
            .expect("a place is free");
        // SAFETY: the listener's owner holds it until the end of the test.
        let id = unsafe { (*object).id };
        hub.on_face_event(FaceEventKind::Up, &face(3, false, "tcp/x"));
        assert_eq!(log.released.load(Ordering::SeqCst), 0);

        let mut at = 0;
        let in_flight = hub.next_transport(&mut at);
        assert!(in_flight.is_some(), "the dispatcher holds the listener");
        hub.undeclare_transport(id);
        assert_eq!(
            log.released.load(Ordering::SeqCst),
            1,
            "the context is released by the time undeclare returns"
        );
        hub.on_face_event(FaceEventKind::Down, &face(3, false, "tcp/x"));
        assert_eq!(
            seen(log),
            ["transport PUT 3"],
            "an undeclared listener hears nothing"
        );

        hub.undeclare_transport(id);
        assert_eq!(
            log.released.load(Ordering::SeqCst),
            1,
            "a second undeclare is a no-op"
        );
        // The dispatcher's hold going changes nothing: the closure was released.
        drop(in_flight);
        assert_eq!(log.released.load(Ordering::SeqCst), 1);
        // SAFETY: the listener declared above, let go of once.
        unsafe { release_transport_listener(object) };
        assert_eq!(log.released.load(Ordering::SeqCst), 1);
    }

    /// Shutting the hub down — a session ending — releases every listener's
    /// context, background ones included.
    #[test]
    fn shutting_the_hub_down_releases_every_context() {
        let hub = Connectivity::new();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let transport = hub
            .declare_transport(&engine, false, transport_closure(log))
            .expect("a place is free");
        let link = hub
            .declare_link(&engine, false, None, link_closure(log))
            .expect("a place is free");
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
            release_transport_listener(transport);
            release_link_listener(link);
        }
        assert_eq!(log.released.load(Ordering::SeqCst), 2);
    }

    /// A hub holds as many transport listeners as its rows, and one more is refused with
    /// nothing declared and its context released; a row given back is taken again. Turned red by
    /// a hub that admits a listener past its rows, or one whose undeclare leaves its row held.
    #[test]
    fn a_listener_past_the_hubs_rows_is_refused_and_released() {
        let hub = Connectivity::new();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let rows = wz_session_core::caps::MAX_TRANSPORT_EVENTS_LISTENERS;
        let held: Vec<*mut TransportListenerState> = (0..rows)
            .map(|_| {
                hub.declare_transport(&engine, false, transport_closure(log))
                    .expect("a row is free")
            })
            .collect();
        assert_eq!(
            hub.declare_transport(&engine, false, transport_closure(log))
                .err(),
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
        unsafe { release_transport_listener(first) };
        let again = hub
            .declare_transport(&engine, false, transport_closure(log))
            .expect("the row given back is taken again");
        for object in held.chain([again]) {
            // SAFETY: as above.
            unsafe { release_transport_listener(object) };
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
        let hub = Connectivity::new();
        let engine: Arc<Engine> = Arc::new(shared());
        let log = log();
        let transport = hub
            .declare_transport(&engine, false, transport_closure(log))
            .expect("a transport row is free");
        let rows = wz_session_core::caps::MAX_LINK_EVENTS_LISTENERS;
        let held: Vec<*mut LinkListenerState> = (0..rows)
            .map(|_| {
                hub.declare_link(&engine, false, None, link_closure(log))
                    .expect("a link row is free")
            })
            .collect();
        assert_eq!(
            hub.declare_link(&engine, false, None, link_closure(log))
                .err(),
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
        unsafe { release_link_listener(first) };
        assert_eq!(log.released.load(Ordering::SeqCst), 2);
        hub.on_face_event(FaceEventKind::Up, &face(4, false, "tcp/y"));
        assert_eq!(
            seen(log)
                .iter()
                .filter(|line| line.starts_with("link"))
                .count(),
            rows - 1,
            "the undeclared listener hears nothing"
        );
        let again = hub
            .declare_link(&engine, false, None, link_closure(log))
            .expect("the row given back is taken again");
        for object in held.chain([again]) {
            // SAFETY: as above.
            unsafe { release_link_listener(object) };
        }
        // SAFETY: as above.
        unsafe { release_transport_listener(transport) };
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

/// The places of the transport events listeners of a session of the cooperative engine, let go
/// of as the session ends. A place given back takes the session's lock, so one given back under
/// it fails the debug build's mark of a held lock (`wz_capi_port::sync::SessionHeld`) at once
/// instead of waiting on itself.
#[cfg(all(test, not(feature = "engine-tokio"), feature = "peer"))]
mod place_tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::session::{
        listening_on_loopback, z_close, z_owned_session_t, z_session_drop, z_session_loan,
        z_session_loan_mut, z_session_move,
    };

    unsafe extern "C" fn on_event(_: *mut z_loaned_transport_event_t, _: *mut c_void) {}

    /// How many places of `kind` `engine` has free: each claimed, then all given back.
    fn free(engine: &Arc<Engine>, kind: Kind) -> usize {
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

    /// A background listener and one with a handle, on a session of `engine`'s, each in a place:
    /// the handle's listener.
    fn declare_both(
        session: &z_owned_session_t,
        engine: &Arc<Engine>,
        drops: &'static AtomicUsize,
    ) -> z_owned_transport_events_listener_t {
        let places = free(engine, Kind::TransportEventsListener);
        let mut background = counting(drops);
        let mut handled = counting(drops);
        let mut listener = z_owned_transport_events_listener_t::null_value();
        // SAFETY: a live session and local closures, each consumed by its declare.
        unsafe {
            assert_eq!(
                z_declare_background_transport_events_listener(
                    z_session_loan(session),
                    z_closure_transport_event_move(&mut background),
                    core::ptr::null(),
                ),
                Z_OK
            );
            assert_eq!(
                z_declare_transport_events_listener(
                    z_session_loan(session),
                    &mut listener,
                    z_closure_transport_event_move(&mut handled),
                    core::ptr::null(),
                ),
                Z_OK
            );
        }
        assert_eq!(
            free(engine, Kind::TransportEventsListener),
            places - 2,
            "each listener holds a place"
        );
        listener
    }

    /// The engine of the session `session` holds.
    fn engine_of_session(session: &z_owned_session_t) -> Arc<Engine> {
        // SAFETY: a live session of this frame's caller.
        let handle = unsafe { session_handle(z_session_loan(session)) };
        engine_of(handle.expect("an open session has its handle"))
    }

    /// Closing the session lets go of both listeners' closures and of the background listener's
    /// place, with no lock of the session held, and the handle's undeclare after the close lets
    /// go of its place. Turned red, in a debug build, by a close that gives a place back under the
    /// session's lock.
    #[test]
    fn closing_a_session_lets_its_listeners_go_with_no_lock_held() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        let mut session = listening_on_loopback();
        let engine = engine_of_session(&session);
        let mut listener = declare_both(&session, &engine, &DROPS);
        // SAFETY: the session is live and owned here.
        let closed = unsafe { z_close(z_session_loan_mut(&mut session), core::ptr::null()) };
        assert_eq!(closed, Z_OK);
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            2,
            "the close released both contexts"
        );
        // SAFETY: the handle written by the declare above, let go of once.
        let undeclared = unsafe {
            z_undeclare_transport_events_listener(z_transport_events_listener_move(&mut listener))
        };
        assert_eq!(undeclared, Z_OK);
        assert!(listener.handle.is_null());
        assert_eq!(DROPS.load(Ordering::SeqCst), 2, "nothing is released twice");
        drop(engine);
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
    }

    /// Dropping the session with no close lets go of the listeners as the session goes, with no
    /// lock of the session held. Turned red, in a debug build, by a drop that gives a place back
    /// under the session's lock.
    #[test]
    fn dropping_a_session_lets_its_listeners_go_with_no_lock_held() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        let mut session = listening_on_loopback();
        let engine = engine_of_session(&session);
        let mut listener = declare_both(&session, &engine, &DROPS);
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
        drop(engine);
        // SAFETY: the session is owned here, and given up by this call.
        unsafe { z_session_drop(z_session_move(&mut session)) };
        assert_eq!(
            DROPS.load(Ordering::SeqCst),
            2,
            "the session's end released the background listener's context"
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
