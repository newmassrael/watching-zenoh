// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! after the replay rather than interleaved with it or dropped.

use std::collections::VecDeque;
use std::ffi::{c_int, c_void};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use wz_capi_core::faces::{FaceEventKind, FaceSnapshot, LinkSnapshot, SharedSession};
use wz_capi_core::listeners::ListenerSet;
use wz_runtime_tokio::session_glue::LinkKind;

use crate::abi::z_owned_string_t;
use crate::bytes::store_owned_string;
use crate::ffi::{guarded, CClosure};
use crate::pubsub::{
    z_closure_drop_callback_t, z_sample_kind_t, Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT,
};
use crate::result::{ZResult, Z_EINVAL, Z_ERR_NULL, Z_ERR_SESSION_CLOSED, Z_OK};
use crate::scout::{z_owned_string_array_t, z_whatami_t};
use crate::session::{session_state, z_loaned_session_t};
use crate::session_ext::PicoSessionExt;
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
        start: std::ptr::null(),
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
            unsafe { std::slice::from_raw_parts(self.start, self.len) }
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
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
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
trait ConnValue: Sized {
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
    z_loaned_transport_t {
        zid: z_id_t { id: snapshot.zid },
        whatami: pico_whatami(snapshot.whatami),
        // Hard-coded `false` in pico, which negotiates neither on unicast.
        is_qos: false,
        is_multicast: snapshot.is_multicast,
        is_shm: false,
    }
}

/// `(mtu, is_streamed, is_reliable)` of a link, as pico's link of that kind
/// answers.
///
/// pico's five links fix all three per TYPE (`_z_get_link_mtu_tcp` and its
/// siblings, and `zl->_cap._flow` / `zl->_cap._is_reliable` beside them). A kind
/// pico has no link for keeps what the registry reports. A link whose kind the
/// driver cannot name reports pico's own zeros, which is what pico answers for a
/// transport with no link object at all
/// (`vendor/zenoh-pico/include/zenoh-pico/api/primitives.h` @
/// `static inline void _z_transport_link_properties_from_transport(`).
pub(crate) fn pico_link_properties(kind: Option<LinkKind>, reported_mtu: u16) -> (u16, bool, bool) {
    match kind {
        None => (0, false, false),
        // pico: stream, reliable, `return 65535;`.
        Some(LinkKind::Tcp) | Some(LinkKind::Tls) => (65535, true, true),
        // pico: datagram, unreliable, `return 1450;`.
        Some(LinkKind::Udp) => (1450, false, false),
        // pico: datagram, RELIABLE, `return 65535;` — the one link where the two
        // flags differ.
        Some(LinkKind::Ws) => (65535, false, true),
        // pico: datagram, unreliable, `_Z_SERIAL_MTU_SIZE`.
        Some(LinkKind::Serial) => (1500, false, false),
        Some(
            other @ (LinkKind::UdpReliable
            | LinkKind::Quic
            | LinkKind::QuicDatagram
            | LinkKind::Unixpipe
            | LinkKind::UnixsockStream
            | LinkKind::Vsock),
        ) => (reported_mtu, other.is_streamed(), other.is_reliable()),
    }
}

/// The link pico reports for one link of an established face.
fn link_of(zid: [u8; 16], link: &LinkSnapshot) -> z_loaned_link_t {
    let (mtu, is_streamed, is_reliable) = pico_link_properties(link.kind, link.mtu);
    z_loaned_link_t {
        zid: z_id_t { id: zid },
        src: ConnText::new(link.src.as_bytes()),
        dst: ConnText::new(link.dst.as_bytes()),
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

/// Where a listener's deliveries stand.
enum Phase<E> {
    /// The history is being replayed on the declaring thread; what arrives
    /// meanwhile waits here, in order.
    Replaying(VecDeque<E>),
    /// Deliveries go straight to the closure.
    Live,
}

/// One declared listener's way to its closure.
///
/// `gate` holds the closure and is held for the length of every call, so the
/// thread that undeclares can take the closure out under it and know nothing is
/// running; `phase` is only ever held briefly and never across a call, so a peer
/// arriving during a replay is queued rather than made to wait.
struct Delivery<E: ConnValue + Send> {
    gate: Mutex<Option<CClosure<Callback<E>>>>,
    phase: Mutex<Phase<E>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<E: ConnValue + Send> Delivery<E> {
    fn new(closure: CClosure<Callback<E>>, replaying: bool) -> Self {
        Self {
            gate: Mutex::new(Some(closure)),
            phase: Mutex::new(if replaying {
                Phase::Replaying(VecDeque::new())
            } else {
                Phase::Live
            }),
        }
    }

    /// Deliver `event`, or queue it while the history is being replayed.
    fn deliver(&self, event: E) {
        {
            let mut phase = lock(&self.phase);
            if let Phase::Replaying(queue) = &mut *phase {
                queue.push_back(event);
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
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                        call(&mut event as *mut E, context)
                    }));
                }
            }
        }
        // SAFETY: the event is this frame's alone; a callback that kept the
        // peer took it out through `take_from_loaned`, which nulled it.
        unsafe { event.clear() };
    }

    /// Deliver what arrived during the replay, in order, and go live. The phase
    /// is switched only when the queue is found empty under its lock, so an
    /// event cannot be delivered ahead of one still queued.
    fn finish_replay(&self) {
        loop {
            let next = {
                let mut phase = lock(&self.phase);
                match &mut *phase {
                    Phase::Replaying(queue) => match queue.pop_front() {
                        Some(event) => event,
                        None => {
                            *phase = Phase::Live;
                            return;
                        }
                    },
                    Phase::Live => return,
                }
            };
            self.call(next);
        }
    }

    /// Take the closure out, once nothing is running it, and run its
    /// `drop(context)` here. Idempotent.
    fn retire(&self) {
        let closure = lock(&self.gate).take();
        drop(closure);
        // What was still queued is released with the listener.
        let mut phase = lock(&self.phase);
        if let Phase::Replaying(queue) = &mut *phase {
            for mut event in queue.drain(..) {
                // SAFETY: queued events are owned by the queue.
                unsafe { event.clear() };
            }
        }
    }
}

impl<E: ConnValue + Send> Drop for Delivery<E> {
    fn drop(&mut self) {
        self.retire();
    }
}

/// A link listener: its delivery and the transport it is filtered to, if any.
struct LinkListener {
    delivery: Delivery<z_loaned_link_event_t>,
    /// `(zid, is_multicast)` — pico's transport filter matches on exactly these
    /// two (`vendor/zenoh-pico/src/api/api.c` @
    /// `bool _z_info_transport_filter_match(`).
    filter: Option<([u8; 16], bool)>,
}

impl LinkListener {
    // `Option::is_none_or` would read better and is stable since 1.82; this
    // workspace's MSRV is 1.81, and clippy's `incompatible_msrv` is right to
    // refuse it.
    #[allow(clippy::unnecessary_map_or)]
    fn wants(&self, transport: &z_loaned_transport_t) -> bool {
        self.filter.map_or(true, |(zid, multicast)| {
            zid == transport.zid.id && multicast == transport.is_multicast
        })
    }
}

/// The transport and link listeners of ONE session, and the watcher that feeds
/// them; see the module doc for why there is one.
pub(crate) struct Connectivity {
    transports: ListenerSet<Delivery<z_loaned_transport_event_t>>,
    links: ListenerSet<LinkListener>,
}

impl Connectivity {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            transports: ListenerSet::new(),
            links: ListenerSet::new(),
        })
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
        for listener in self.transports.snapshot() {
            listener.deliver(z_loaned_transport_event_t {
                kind,
                transport: transport_of(snapshot),
            });
        }
    }

    fn fan_links(&self, kind: z_sample_kind_t, snapshot: &FaceSnapshot) {
        let transport = transport_of(snapshot);
        for listener in self.links.snapshot() {
            if !listener.wants(&transport) {
                continue;
            }
            for link in &snapshot.links {
                listener.delivery.deliver(z_loaned_link_event_t {
                    kind,
                    link: link_of(snapshot.zid, link),
                });
            }
        }
    }

    /// Declare a transport listener, replaying the peers connected now first
    /// when `history` is set.
    fn declare_transport(
        &self,
        shared: &SharedSession,
        history: bool,
        closure: CClosure<Callback<z_loaned_transport_event_t>>,
    ) -> u64 {
        let delivery = Arc::new(Delivery::new(closure, history));
        // Registered BEFORE the peers are read, so a peer that arrives in
        // between is queued rather than missed.
        let id = self.transports.insert(Arc::clone(&delivery));
        if history {
            for snapshot in shared.face_snapshots() {
                delivery.call(z_loaned_transport_event_t {
                    kind: Z_SAMPLE_KIND_PUT,
                    transport: transport_of(&snapshot),
                });
            }
            delivery.finish_replay();
        }
        id
    }

    /// Declare a link listener, replaying the links connected now first when
    /// `history` is set. `filter` narrows it to one transport.
    fn declare_link(
        &self,
        shared: &SharedSession,
        history: bool,
        filter: Option<([u8; 16], bool)>,
        closure: CClosure<Callback<z_loaned_link_event_t>>,
    ) -> u64 {
        let listener = Arc::new(LinkListener {
            delivery: Delivery::new(closure, history),
            filter,
        });
        let id = self.links.insert(Arc::clone(&listener));
        if history {
            for snapshot in shared.face_snapshots() {
                if !listener.wants(&transport_of(&snapshot)) {
                    continue;
                }
                for link in &snapshot.links {
                    listener.delivery.call(z_loaned_link_event_t {
                        kind: Z_SAMPLE_KIND_PUT,
                        link: link_of(snapshot.zid, link),
                    });
                }
            }
            listener.delivery.finish_replay();
        }
        id
    }

    fn undeclare_transport(&self, id: u64) {
        if let Some(listener) = self.transports.remove(id) {
            listener.retire();
        }
    }

    fn undeclare_link(&self, id: u64) {
        if let Some(listener) = self.links.remove(id) {
            listener.delivery.retire();
        }
    }

    /// Let go of every listener, which releases their C contexts.
    pub(crate) fn shutdown(&self) {
        for listener in self.transports.snapshot() {
            listener.retire();
        }
        for listener in self.links.snapshot() {
            listener.delivery.retire();
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
                    context: std::ptr::null_mut(),
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
            let taken = std::mem::replace(&mut (*closure)._this, $owned::null_value());
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
            *closure = std::mem::replace(&mut (*src)._this, $owned::null_value());
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
    CClosure::new(context, call, drop)
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
                std::ptr::write(&mut (*obj)._val, <$val as ConnValue>::null());
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
                return std::ptr::null();
            }
            &(*obj)._val as *const $val as *const $loaned
        }

        /// Borrow an owned value mutably.
        #[no_mangle]
        pub unsafe extern "C" fn $loan_mut(obj: *mut $owned) -> *mut $loaned {
            if obj.is_null() {
                return std::ptr::null_mut();
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
            std::ptr::write(&mut (*obj)._val, <$val as ConnValue>::null());
            std::mem::swap(&mut (*obj)._val, &mut (*src)._this._val);
        }

        /// Move a loaned value into an owned one, nulling the source.
        #[no_mangle]
        pub unsafe extern "C" fn $tfl(obj: *mut $owned, src: *mut $loaned) -> ZResult {
            if obj.is_null() || src.is_null() {
                return Z_ERR_NULL;
            }
            let src = &mut *(src as *mut $val);
            std::ptr::write(&mut (*obj)._val, <$val as ConnValue>::null());
            std::mem::swap(&mut (*obj)._val, src);
            Z_OK
        }

        /// Copy a loaned value into an owned one.
        #[no_mangle]
        pub unsafe extern "C" fn $clone(obj: *mut $owned, src: *const $loaned) -> ZResult {
            if obj.is_null() || src.is_null() {
                return Z_ERR_NULL;
            }
            std::ptr::write(
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
    if !text.is_null() {
        store_owned_string(out, text.as_bytes());
    }
    Z_OK
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
        return std::ptr::null();
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
        return std::ptr::null_mut();
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
        return std::ptr::null();
    }
    &(*event).link
}

/// The link inside an event, mutably (pico `z_link_event_link_mut`).
#[no_mangle]
pub unsafe extern "C" fn z_link_event_link_mut(
    event: *mut z_loaned_link_event_t,
) -> *mut z_loaned_link_t {
    if event.is_null() {
        return std::ptr::null_mut();
    }
    &mut (*event).link
}

// ===========================================================================
// enumeration
// ===========================================================================

/// The hub of the session behind `zs`, if it is a live session this ABI opened.
unsafe fn hub_of<'a>(
    zs: *const z_loaned_session_t,
) -> Option<(&'a wz_capi_core::drive::SessionState, &'a Arc<Connectivity>)> {
    let state = session_state(zs)?;
    let ext = state.abi_extension::<PicoSessionExt>()?;
    Some((state, &ext.connectivity))
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
        let Some(state) = session_state(zs) else {
            return Z_ERR_NULL;
        };
        for snapshot in state.shared.face_snapshots() {
            let mut transport = transport_of(&snapshot);
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
        (*options).transport = std::ptr::null_mut();
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
            std::ptr::null_mut()
        } else {
            (*options).transport
        };
        let filter = match take_filter(transport) {
            Ok(filter) => filter,
            Err(()) => return Z_EINVAL,
        };
        let Some(state) = session_state(zs) else {
            return Z_ERR_NULL;
        };
        for snapshot in state.shared.face_snapshots() {
            let peer = transport_of(&snapshot);
            if let Some((zid, multicast)) = filter {
                if zid != peer.zid.id || multicast != peer.is_multicast {
                    continue;
                }
            }
            for link in &snapshot.links {
                let mut held = HeldLink(link_of(snapshot.zid, link));
                if let Some(call) = closure.call {
                    call(&mut held.0, closure.context.0);
                }
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
        (*options).transport = std::ptr::null_mut();
    }
}

/// Which kind of listener a handle names.
#[derive(Clone, Copy)]
enum ListenerKind {
    Transport,
    Link,
}

/// Behind an owned listener: the hub it was declared on and its id.
struct ListenerHandle {
    hub: Arc<Connectivity>,
    kind: ListenerKind,
    id: u64,
}

impl ListenerHandle {
    fn undeclare(&self) {
        match self.kind {
            ListenerKind::Transport => self.hub.undeclare_transport(self.id),
            ListenerKind::Link => self.hub.undeclare_link(self.id),
        }
    }
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
                    handle: std::ptr::null_mut(),
                    _pad: [std::ptr::null_mut(); 4],
                }
            }

            fn of(handle: Box<ListenerHandle>) -> Self {
                Self {
                    handle: Box::into_raw(handle).cast(),
                    _pad: [std::ptr::null_mut(); 4],
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
            *listener = std::mem::replace(&mut (*src)._this, $owned::null_value());
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

/// Undeclare the listener behind `handle` and free the handle; `Z_OK` when there
/// was nothing to undeclare.
unsafe fn release_listener(handle: &mut *mut c_void) -> ZResult {
    if handle.is_null() {
        return Z_OK;
    }
    let boxed = Box::from_raw((*handle).cast::<ListenerHandle>());
    *handle = std::ptr::null_mut();
    boxed.undeclare();
    Z_OK
}

/// Declare a transport listener (pico `z_declare_transport_events_listener`).
///
/// A null or closed session refuses with `_Z_ERR_SESSION_CLOSED`. As pico does,
/// a NULL session is refused BEFORE the closure is taken, so the caller still
/// owns it; a session that is closed is refused after.
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
        let Some((state, hub)) = hub_of(zs) else {
            return Z_ERR_SESSION_CLOSED;
        };
        let closure = adopt(
            callback,
            |c| (c._this.context, c._this.call, c._this.drop),
            |c| c._this = z_owned_closure_transport_event_t::null_value(),
        );
        if state.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        let history = !options.is_null() && (*options).history;
        let id = hub.declare_transport(&state.shared, history, closure);
        *listener = z_owned_transport_events_listener_t::of(Box::new(ListenerHandle {
            hub: Arc::clone(hub),
            kind: ListenerKind::Transport,
            id,
        }));
        Z_OK
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
        // The handle is let go of without undeclaring: the listener stays.
        drop(Box::from_raw(listener.handle.cast::<ListenerHandle>()));
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
        release_listener(&mut (*listener)._this.handle)
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
/// taken and released.
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
        let Some((state, hub)) = hub_of(zs) else {
            return Z_ERR_SESSION_CLOSED;
        };
        let closure = adopt(
            callback,
            |c| (c._this.context, c._this.call, c._this.drop),
            |c| c._this = z_owned_closure_link_event_t::null_value(),
        );
        let (history, transport) = if options.is_null() {
            (false, std::ptr::null_mut())
        } else {
            ((*options).history, (*options).transport)
        };
        let filter = match take_filter(transport) {
            Ok(filter) => filter,
            Err(()) => return Z_EINVAL,
        };
        if state.is_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        let id = hub.declare_link(&state.shared, history, filter, closure);
        *listener = z_owned_link_events_listener_t::of(Box::new(ListenerHandle {
            hub: Arc::clone(hub),
            kind: ListenerKind::Link,
            id,
        }));
        Z_OK
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
        drop(Box::from_raw(listener.handle.cast::<ListenerHandle>()));
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
        release_listener(&mut (*listener)._this.handle)
    })
}

/// Drop a link listener (pico `z_link_events_listener_drop`).
#[no_mangle]
pub unsafe extern "C" fn z_link_events_listener_drop(
    listener: *mut z_moved_link_events_listener_t,
) {
    let _ = z_undeclare_link_events_listener(listener);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::OnceLock;

    use wz_runtime_tokio::runtime_impl::TokioTime;

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
                delivery.deliver(z_loaned_transport_event_t {
                    kind: Z_SAMPLE_KIND_PUT,
                    transport: transport_with_zid(*arriving),
                });
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
        CClosure::new(ctx(log), Some(on_transport), Some(released))
    }

    fn link_closure(log: &'static Log) -> CClosure<Callback<z_loaned_link_event_t>> {
        CClosure::new(ctx(log), Some(on_link), Some(released))
    }

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
            }],
        }
    }

    fn shared() -> SharedSession {
        SharedSession::new(TokioTime::new(), vec![0x11; 16]).expect("test host entropy")
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
        let shared = shared();
        let log = log();
        // Declared transport FIRST, so a registry that hands each watcher the
        // event in declaration order would put the transport ahead on a
        // departure too.
        hub.declare_transport(&shared, false, transport_closure(log));
        hub.declare_link(&shared, false, None, link_closure(log));

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
        let shared = shared();
        let log = log();
        let mut zid = [0u8; 16];
        zid[0] = 7;
        hub.declare_link(&shared, false, Some((zid, false)), link_closure(log));

        hub.on_face_event(FaceEventKind::Up, &face(7, false, "tcp/a"));
        hub.on_face_event(FaceEventKind::Up, &face(8, false, "tcp/other-zid"));
        hub.on_face_event(FaceEventKind::Up, &face(7, true, "tcp/multicast"));
        assert_eq!(seen(log), ["link PUT tcp/a"]);
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
    /// second peer ahead of the history's end and reds the order.
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

        delivery.finish_replay();
        assert_eq!(
            seen(log),
            [
                "transport PUT 1",
                "transport PUT 2",
                "transport PUT 9",
                "transport PUT 9"
            ],
            "it is delivered after the history, in arrival order (once per replayed \
             peer that re-entered)"
        );

        // Live now: a further arrival goes straight through.
        delivery.deliver(z_loaned_transport_event_t {
            kind: Z_SAMPLE_KIND_DELETE,
            transport: transport_with_zid(5),
        });
        assert_eq!(
            seen(log).last().map(String::as_str),
            Some("transport DEL 5")
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
        let shared = shared();
        let log = log();
        let id = hub.declare_transport(&shared, false, transport_closure(log));
        hub.on_face_event(FaceEventKind::Up, &face(3, false, "tcp/x"));
        assert_eq!(log.released.load(Ordering::SeqCst), 0);

        let in_flight = hub.transports.snapshot();
        assert_eq!(in_flight.len(), 1, "the dispatcher holds the listener");
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
        // The dispatcher's copy going changes nothing: the closure was released.
        drop(in_flight);
        assert_eq!(log.released.load(Ordering::SeqCst), 1);
    }

    /// Shutting the hub down — a session ending — releases every listener's
    /// context, background ones included.
    #[test]
    fn shutting_the_hub_down_releases_every_context() {
        let hub = Connectivity::new();
        let shared = shared();
        let log = log();
        hub.declare_transport(&shared, false, transport_closure(log));
        hub.declare_link(&shared, false, None, link_closure(log));
        hub.shutdown();
        assert_eq!(log.released.load(Ordering::SeqCst), 2);
        hub.shutdown();
        assert_eq!(
            log.released.load(Ordering::SeqCst),
            2,
            "shutdown is idempotent"
        );
    }

    /// The link a face reports follows pico's table for the kinds pico has and
    /// the registry's answer for the rest.
    ///
    /// # Control
    ///
    /// Reporting the negotiated MTU for TCP (2048 from a pico peer) where pico's
    /// link says 65535 reds the first row.
    #[test]
    fn a_link_reports_what_pico_reports_for_its_kind() {
        let reported = 777;
        let table = [
            (Some(LinkKind::Tcp), (65535, true, true)),
            (Some(LinkKind::Tls), (65535, true, true)),
            (Some(LinkKind::Udp), (1450, false, false)),
            (Some(LinkKind::Ws), (65535, false, true)),
            (Some(LinkKind::Serial), (1500, false, false)),
            (None, (0, false, false)),
            // pico has no such link: the registry's answers stand.
            (Some(LinkKind::Quic), (reported, true, true)),
            (Some(LinkKind::QuicDatagram), (reported, false, false)),
            (Some(LinkKind::UdpReliable), (reported, true, true)),
            (Some(LinkKind::Unixpipe), (reported, true, true)),
        ];
        for (kind, want) in table {
            assert_eq!(pico_link_properties(kind, reported), want, "{kind:?}");
        }
        // Every kind the registry can report has a row above or an arm there;
        // this is the population, derived from the enum.
        for kind in LinkKind::ALL {
            let _ = pico_link_properties(Some(*kind), reported);
        }
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
                    },
                ),
            };
            assert!(z_internal_link_check(&original));

            let mut copy = std::mem::MaybeUninit::<z_owned_link_t>::uninit();
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
                std::slice::from_raw_parts(
                    crate::bytes::z_string_data(crate::bytes::z_string_loan(&text)) as *const u8,
                    crate::bytes::z_string_len(crate::bytes::z_string_loan(&text)),
                ),
                b"tcp/src"
            );
            crate::bytes::z_string_drop(crate::bytes::z_string_move(&mut text));

            // take_from_loaned moves: the destination holds it, the source is null.
            let mut moved = std::mem::MaybeUninit::<z_owned_link_t>::uninit();
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
                context: std::ptr::null_mut(),
                call: None,
                drop: None,
            };
            assert_eq!(
                z_closure_link_event(&mut closure, Some(on_link), Some(released), ctx(log)),
                Z_OK
            );
            assert!(z_internal_closure_link_event_check(&closure));

            let mut taken = std::mem::MaybeUninit::<z_owned_closure_link_event_t>::uninit();
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
