// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! zephyr-admin-loopback (Rust staticlib) -- the witness that an ADMIN NODE on Zephyr's own sockets
//! takes a secure channel, learns the zid of the key its peer proved, and decides its lifecycle
//! verbs by that zid (decision D12 of `docs/session-lifecycle-intent.md`, steps 3 and 4).
//!
//! The node under test is `wz_session_mcu::slot_admin::AcceptingAdminNode` over the stack of
//! `fixed_tls`'s shape: `IpStack<ZephyrUdpSocket, ZephyrTcpDial, TlsDial<..>>`, its sessions taken
//! from `IpStack::tls_acceptor(TlsListener<ZephyrTcpListener>)`, its admin queryable registered
//! with `Verbs(StoreNode<Commanders>)` as the in-band verbs. It has no allocator.
//!
//! One thread plays both ends on the loopback interface, because the channel keeps one arena with
//! no lock. The peer is the fixed-memory CLIENT node of `wz_session_mcu::slot_node`, dialling the
//! admin node over `tls/`; the admin node is stepped from the client's application each round, and
//! from the client's dial while it waits for the handshake (a dial blocks, and the listener it
//! waits for would never get its turn otherwise).
//!
//! What is held: the admin node accepts the client's session; the session is established and its
//! peer VERIFIED (the zid the client claimed is the zid its key names), and that zid is the one the
//! client's key names; the commander list names that zid for `status` only, and the verdicts the
//! node gives for the zid it OBSERVED on the live session are an answer for `status`, a refusal for
//! `close` (a zid listed for one verb commands no other), and a refusal of `status` for a zid
//! nothing proved. The query transport itself is not exercised: the permit the node decides with is
//! given the zid of a real session.
#![no_std]

use core::cell::{Cell, RefCell, UnsafeCell};
use core::ops::ControlFlow;

use wz::runtime_zephyr::glue::{log, log_parts, stack_usage, yield_us};
use wz::runtime_zephyr::net::{await_board_ipv4, ZephyrNetError, ZephyrUdpSocket};
use wz::runtime_zephyr::stream::{ZephyrTcpDial, ZephyrTcpListener, ZephyrTcpSocket};
use wz::runtime_zephyr::{ZephyrClock, ZephyrEntropy};
use wz_runtime_coop::ip_stack::{IpDriver, IpStack, IpTlsAcceptor};
use wz_runtime_coop::session_drive::{LinkOpenError, SlotStack};
use wz_runtime_coop::stream_link::{StreamDial, StreamSocket};
use wz_runtime_coop::{ClockSource, CoopLocalSet};
use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::entropy::EntropySource;
use wz_session_core::lifecycle_node::{lifecycle_verdict, Command, Commander, Verdict};
use wz_session_core::lifecycle_wire::{RefusedReason, StatusVerdict};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::locator_directory::DirectoryZid;
use wz_session_core::reply_sink::{ReplyKind, ReplySink, ReplyView};
use wz_session_core::sample::QosLevel;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{ObserverCell, Requesters};
use wz_session_core::text_out::{FixedText, LogPart};
use wz_session_core::zid_hex::write_zenoh_hex;
use wz_session_core::WhatAmI;
use wz_session_mcu::admin_fixed::{
    host_admin_queryable_fixed_with_open, AdminHost, AdminSinks, FixedNodeIdentity,
    FixedNodeStatus, Verbs,
};
use wz_session_mcu::admin_host::{host_connect_writes_fixed, ConnectControl};
use wz_session_mcu::app_layer::{GetRequest, NoReplies, SessionEvents, SlotDispatch};
use wz_session_mcu::connect_manager::{Commanders, StaticEndpoints, StoreNode};
use wz_session_mcu::slot_admin::AcceptingAdminNode;
use wz_session_mcu::slot_client::{DocumentSinks, Listening};
use wz_session_mcu::slot_dial::SessionFactory;
use wz_session_mcu::slot_host::SessionHost;
use wz_session_mcu::slot_node::{
    ClientNode, Declared, Entities, NoPlane, NodeApp, NodeHandle, NodeIdentity, NodeLoop, NodePort,
    NodeStorage, SessionLayer, SIGNING_KEY_BYTES,
};
use wz_tls_mbedtls::channel::{start_on_platform_arena, IdentitySlot};
use wz_tls_mbedtls::stream::{AcceptBudget, HandshakeBudget, TlsDial, TlsListener};
use LogPart::{Str, U64};

// The panic handler, the critical section over the kernel IRQ lock and no allocator: the glue every
// fixed-memory wz Zephyr image carries.
wz::runtime_zephyr::zephyr_image_no_heap!();

/// The board's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`, as this build was configured.
const TICK_HZ: u32 = wz::runtime_zephyr::tick_hz_from_build!();
type Clock = ZephyrClock<TICK_HZ>;

/// The loopback address both ends use, and the port the admin node accepts secure channels on.
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const PORT: u16 = 7471;
/// The batch both nodes negotiate.
const BATCH: u16 = 1472;
/// The longest the witness lets the whole run take, in milliseconds of the kernel's tick.
const DEADLINE_MS: u64 = 120_000;
/// The longest the listener lets one inbound handshake take.
const ACCEPT_TIMEOUT_MS: u64 = 60_000;

/// Sessions each node holds at most.
const SESSIONS: usize = 1;
/// Sessions the admin node holds that a peer opened.
const ACCEPTS: usize = 1;
const TASKS: usize = SESSIONS + 1;
/// The admin node's session task holds the application layer with its requesters (about 4.9 KB,
/// twice for an `async fn`'s by-value argument), as the lwIP admin node's does.
const SERVER_TASK_BYTES: usize = 12288;
/// The client that only answers keeps no table of requests, but its session task also holds the
/// secure channel's stream driver (a cell of 384 bytes refused it, measured: "too large").
const CLIENT_TASK_BYTES: usize = 16384;
const TIMERS: usize = 4;
const RX: usize = BATCH as usize + 64;
const TX: usize = BATCH as usize;
/// The bytes of the arenas the nodes' loops are built in. A witness has no budget row to hold them
/// to, so they are given room: the client's loop checks its number when it is compiled (a build
/// that outgrows it stops), and the admin node's is checked when it is built at start.
const CLIENT_RUN: usize = 4096;
const SERVER_RUN: usize = 16384;

/// The stack of both nodes: Zephyr's sockets, with `tls/` dialled and listened on through the
/// secure channel over Zephyr's TCP.
type Stack = IpStack<ZephyrUdpSocket, ZephyrTcpDial, TlsDial<ZephyrTcpDial>>;
type Driver = <Stack as SlotStack>::Driver;

/// The stack of the dialling node: the same, whose TCP waits for its peer by stepping the admin
/// node. Another type, for another driver; the two nodes share nothing.
type ClientStack = IpStack<ZephyrUdpSocket, ZephyrTcpDial, TlsDial<SteppingDial>>;

/// The listener of secure channels, and the acceptor the admin node takes its sessions from.
type Acceptor = IpTlsAcceptor<TlsListener<ZephyrTcpListener>, ZephyrUdpSocket, ZephyrTcpSocket>;

type ServerStorage = NodeStorage<
    Clock,
    Stack,
    ZephyrEntropy,
    TASKS,
    SERVER_TASK_BYTES,
    TIMERS,
    SESSIONS,
    RX,
    TX,
    SERVER_RUN,
>;
type ClientStorage = NodeStorage<
    Clock,
    ClientStack,
    ZephyrEntropy,
    TASKS,
    CLIENT_TASK_BYTES,
    TIMERS,
    SESSIONS,
    RX,
    TX,
    CLIENT_RUN,
>;

static SERVER: ServerStorage = ServerStorage::new();
static CLIENT: ClientStorage = ClientStorage::new();

/// What the admin node starts with and which is not zero: the counters and the write permit.
struct Control {
    status: FixedNodeStatus<SESSIONS>,
    control: ConnectControl,
}

// SAFETY: the profile's rule: one cooperative loop on one thread reaches it.
unsafe impl Sync for Control {}

static CONTROL: Control = Control {
    status: FixedNodeStatus::new(true),
    control: ConnectControl::new(true),
};
static ADMIN: AdminHost<1024> = AdminHost::new();

/// A value written once at start and read after, on the one thread the program runs on.
struct Once<T>(UnsafeCell<Option<T>>);

// SAFETY: the profile's rule: one thread runs the program, and a value is written once before the
// readers exist.
unsafe impl<T> Sync for Once<T> {}

impl<T> Once<T> {
    const fn new() -> Self {
        Self(UnsafeCell::new(None))
    }

    /// Keep `value`, once; the value comes back from a second call.
    fn set(&'static self, value: T) -> Result<&'static mut T, T> {
        // SAFETY: one thread, and `Some` is never replaced, so no other reference to the contents
        // exists while this one is made.
        let slot = unsafe { &mut *self.0.get() };
        if slot.is_some() {
            return Err(value);
        }
        Ok(slot.insert(value))
    }

    /// The value, if kept.
    fn get(&'static self) -> Option<&'static mut T> {
        // SAFETY: as `set`; the callers do not nest (the admin node's step is not reached from
        // inside the admin node).
        unsafe { (*self.0.get()).as_mut() }
    }
}

/// The commanders of the node: `status` is the client's zid, and nothing else is anyone's. The
/// list is a `static` of the zid the client's key named at start, so it is written once, and the
/// permit that reads it is the node's own `Commanders`.
static LISTED: Once<[DirectoryZid; 1]> = Once::new();
static OPEN: Once<Verbs<StoreNode<Commanders>>> = Once::new();

/// The registrations the admin node's observer holds: the config-write subscriber and the admin
/// queryable, which binds the in-band verbs.
type Sinks = AdminSinks<1024, SESSIONS, Verbs<StoreNode<Commanders>>>;

/// The admin node, in its arena, and the runtime's loop that runs its sessions.
type Node = AcceptingAdminNode<
    'static,
    Clock,
    Stack,
    Stack,
    ServerFactory,
    Acceptor,
    SESSIONS,
    SESSIONS,
    ACCEPTS,
>;

struct ServerParts {
    local: CoopLocalSet<Clock>,
    node: &'static mut Node,
}

static SERVER_PARTS: Once<ServerParts> = Once::new();

/// One round of the admin node: the sessions' tasks, then the node's tick. Called by the client
/// node's application each round, and by the client's dial while it waits for the handshake.
fn step_server() {
    let Some(parts) = SERVER_PARTS.get() else {
        return;
    };
    parts.local.run_until_idle();
    parts.node.tick(Clock::default().now_us() / 1000);
}

/// A stream whose wait for its peer gives the admin node a round first.
struct SteppingSocket {
    inner: ZephyrTcpSocket,
}

impl StreamSocket for SteppingSocket {
    type Error = ZephyrNetError;

    fn local(&self) -> ([u8; 4], u16) {
        self.inner.local()
    }

    fn peer(&self) -> ([u8; 4], u16) {
        self.inner.peer()
    }

    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), ZephyrNetError> {
        self.inner.send_parts(parts)
    }

    fn wait_readable(&self, timeout_ms: core::ffi::c_int) {
        step_server();
        self.inner.wait_readable(timeout_ms);
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, ZephyrNetError> {
        self.inner.try_read(buf)
    }

    fn shutdown(&self) {
        self.inner.shutdown();
    }
}

/// Zephyr's TCP connect, whose streams step the admin node while they wait.
#[derive(Clone, Copy)]
struct SteppingDial;

impl StreamDial for SteppingDial {
    type Stream = SteppingSocket;

    fn dial(&self, addr: [u8; 4], port: u16) -> Result<SteppingSocket, LinkOpenError> {
        ZephyrTcpDial
            .dial(addr, port)
            .map(|inner| SteppingSocket { inner })
    }
}

/// What the admin node makes its sessions from: the entropy, the parameters and the application
/// layer (the process-wide observer with the node's admin surface registered on it).
struct ServerFactory {
    zid: [u8; CREDENTIAL_ZID_BYTES],
    key: [u8; SIGNING_KEY_BYTES],
    observer: &'static ObserverCell<Sinks>,
}

impl SessionFactory<Clock, Driver> for ServerFactory {
    type Entropy = ZephyrEntropy;
    type Events = SlotDispatch<Clock, NoReplies, NoReplies, Sinks, Driver>;

    fn entropy(&mut self) -> ZephyrEntropy {
        ZephyrEntropy
    }

    /// zenoh 1.x's handshake shape, with a batch the receive slot holds whole. A node that accepts
    /// presents itself as a peer.
    fn params(&mut self) -> SessionInitParams {
        SessionInitParams {
            whatami: WhatAmI::Peer,
            zid: zid_bytes(&self.zid),
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: BATCH,
            lease_ms: 10_000,
            keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
            initial_sn: 0,
            cookie: cookie_bytes(&[]),
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
            link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
            cookie_signing_key: SigningKey::from_slice(&self.key).expect("32-byte key"),
        }
    }

    fn events(
        &mut self,
        handle: &wz_runtime_coop::session_runtime::SessionHandle<Clock, Driver>,
    ) -> Self::Events {
        SlotDispatch::new(self.observer, handle.clone(), Requesters::new())
    }
}

/// The board's console and sleep, and its stack watch: what the nodes' loop cannot know.
struct Port;

impl NodePort for Port {
    const NAME: &'static str = "zephyr-wz-client";

    fn log(&mut self, line: &[LogPart<'_>]) {
        log_parts(line);
    }

    fn idle(&mut self, us: u32) {
        yield_us(i32::try_from(us).unwrap_or(i32::MAX));
    }
}

/// The identities of the two ends.
static SERVER_IDENTITY: IdentitySlot = IdentitySlot::new();
static CLIENT_IDENTITY: IdentitySlot = IdentitySlot::new();

/// The queries the client asks the admin node over its session, in order, and what each was answered:
/// the keys of the verbs, a `status` the session's key is listed for and a `close` it is not.
const ASKS: usize = 2;
/// The most of a reply's payload that is kept (a verdict document is well under it).
const REPLY_BYTES: usize = 192;

/// What one query came to.
struct Answer {
    /// The payload of its reply, and how many bytes of it are kept.
    text: [Cell<u8>; REPLY_BYTES],
    len: Cell<usize>,
    /// The reply was an error reply, or the query timed out.
    failed: Cell<bool>,
}

impl Answer {
    const fn new() -> Self {
        Self {
            text: [const { Cell::new(0) }; REPLY_BYTES],
            len: Cell::new(0),
            failed: Cell::new(false),
        }
    }

    /// Whether the kept payload contains `needle`.
    fn holds(&self, needle: &str) -> bool {
        let needle = needle.as_bytes();
        let len = self.len.get();
        len >= needle.len()
            && (0..=len - needle.len()).any(|at| {
                needle
                    .iter()
                    .enumerate()
                    .all(|(i, byte)| self.text[at + i].get() == *byte)
            })
    }
}

/// The client's queries, all zero bytes.
struct Asking {
    /// How many have been asked, and how many have ended (their final or their timeout).
    asked: Cell<usize>,
    ended: Cell<usize>,
    /// The session refused a query it was asked to send.
    refused: Cell<bool>,
    answers: [Answer; ASKS],
}

// SAFETY: the profile's rule: one cooperative loop on one thread reaches it.
unsafe impl Sync for Asking {}

static ASKING: Asking = Asking {
    asked: Cell::new(0),
    ended: Cell::new(0),
    refused: Cell::new(false),
    answers: [const { Answer::new() }; ASKS],
};

/// The keys of the queries, written once before the client starts.
static ASK_KEYS: Once<[FixedText<96>; ASKS]> = Once::new();

/// The sink of query `index`: what its reply says is kept, and its end is counted.
#[derive(Clone, Copy)]
struct AskSink {
    index: usize,
}

impl ReplySink for AskSink {
    fn on_reply(&mut self, reply: &dyn ReplyView) {
        let answer = &ASKING.answers[self.index];
        if reply.kind() == ReplyKind::Err {
            answer.failed.set(true);
            return;
        }
        let payload = reply.payload();
        for (cell, byte) in answer.text.iter().zip(payload) {
            cell.set(*byte);
        }
        answer.len.set(payload.len().min(REPLY_BYTES));
    }

    fn on_final(&mut self, _rid: u64) {
        ASKING.ended.set(ASKING.ended.get() + 1);
    }

    fn on_timeout(&mut self, _rid: u64) {
        ASKING.answers[self.index].failed.set(true);
        ASKING.ended.set(ASKING.ended.get() + 1);
    }
}

/// What the client's sessions report to: the node's dispatch, which asks the queries above one at a
/// time, the next when the one before has ended.
struct AskLayer;

impl<C, D> SessionLayer<C, D> for AskLayer
where
    C: ClockSource + Default + 'static,
    D: BoxedLinkDriver + ?Sized + 'static,
{
    type Events = AskEvents<C, D>;

    fn events(
        &mut self,
        observer: &'static ObserverCell<DocumentSinks>,
        handle: &wz_runtime_coop::session_runtime::SessionHandle<C, D>,
    ) -> Self::Events {
        AskEvents {
            inner: SlotDispatch::new(
                observer,
                handle.clone(),
                Requesters::<AskSink, NoReplies>::new(),
            ),
        }
    }
}

struct AskEvents<C, D>
where
    C: ClockSource + Default + 'static,
    D: BoxedLinkDriver + ?Sized + 'static,
{
    inner: SlotDispatch<C, AskSink, NoReplies, DocumentSinks, D>,
}

impl<C, D> AskEvents<C, D>
where
    C: ClockSource + Default + 'static,
    D: BoxedLinkDriver + ?Sized + 'static,
{
    /// Whether a query waits for a turn that can send it.
    fn ask_pending(&self) -> bool {
        self.inner.is_established()
            && ASKING.asked.get() < ASKS
            && ASKING.ended.get() >= ASKING.asked.get()
    }

    /// Ask the next query, when the session can send it and the one before has ended.
    fn ask_due(&mut self) {
        if !self.ask_pending() {
            return;
        }
        let index = ASKING.asked.get();
        let Some(keys) = ASK_KEYS.get() else {
            return;
        };
        let request = GetRequest {
            keyexpr: keys[index].prefix(),
            parameters: b"",
            consolidation: None,
            target: None,
            timeout_ms: 20_000,
            qos: QosLevel::DEFAULT,
        };
        match self.inner.get(&request, AskSink { index }) {
            Ok(_) => ASKING.asked.set(index + 1),
            Err(_) => ASKING.refused.set(true),
        }
    }
}

impl<C, D> SessionEvents for AskEvents<C, D>
where
    C: ClockSource + Default + 'static,
    D: BoxedLinkDriver + ?Sized + 'static,
{
    fn on_event(&mut self, event: IterationEvent<'_, '_>) {
        self.inner.on_event(event);
        self.ask_due();
    }

    /// Answers the record beside it and asks nothing: the request would be written on top of the
    /// record. A query that is due is left to the next event.
    fn on_record(&mut self, record: wz_session_core::driver_loop::InPlaceRecord<'_, '_>) {
        self.inner.on_record(record);
        if self.ask_pending() {
            self.inner.wake_now();
        }
    }
}

/// The application the client node runs each round: it steps the admin node, and holds the
/// verdicts.
struct Witness {
    client_zid: [u8; CREDENTIAL_ZID_BYTES],
    /// The admin node's accepted session has been seen verified, and the permit decided for the zid
    /// it observed; what remains is the answers to the queries asked through the session.
    checked: bool,
    /// Every verdict was held.
    concluded: bool,
}

impl Witness {
    /// The answers to the queries the client asked the admin node through the TLS session: the
    /// `status` its key is listed for was answered with a status document, and the `close` it is not
    /// listed for was refused by name. The verdict reaches the client as a reply to a GET, so the
    /// zid the node decided by is the one the session carried, not one the witness handed it.
    fn finish(&mut self) -> ControlFlow<i32> {
        if ASKING.refused.get() {
            log(c"wz: FAIL - the client's session refused to send a query");
            return ControlFlow::Break(1);
        }
        if ASKING.ended.get() < ASKS {
            return ControlFlow::Continue(());
        }
        let (status, close) = (&ASKING.answers[0], &ASKING.answers[1]);
        if status.failed.get() || !status.holds("\"verdict\":\"status\"") {
            log(c"wz: FAIL - a GET for status through the session was not answered with a status");
            return ControlFlow::Break(1);
        }
        log(c"wz: a GET for status through the TLS session was answered with a status document");
        if close.failed.get() || !close.holds("\"verdict\":\"refused\"") {
            log(c"wz: FAIL - a GET for close through the session was not refused by name");
            return ControlFlow::Break(1);
        }
        log(c"wz: a GET for close through the same session was refused by name");
        self.concluded = true;
        ControlFlow::Break(0)
    }
}

impl NodeApp for Witness {
    fn after_tick(&mut self, now_ms: u64, node: &dyn NodeHandle) -> ControlFlow<i32> {
        step_server();
        if now_ms > DEADLINE_MS {
            log(c"wz: FAIL - the admin node saw no verified session in time");
            return ControlFlow::Break(1);
        }
        if self.concluded {
            return ControlFlow::Break(0);
        }
        if self.checked {
            return self.finish();
        }
        let Some(parts) = SERVER_PARTS.get() else {
            return ControlFlow::Break(1);
        };
        // The zid the admin node's own session says the key of its peer proved.
        let mut observed: Option<DirectoryZid> = None;
        for session in parts.node.accepted() {
            let actions = session.actions();
            if actions.is_established() && actions.peer_identity_verified() {
                observed = actions.peer_zid_array();
            }
        }
        let Some(observed) = observed else {
            return ControlFlow::Continue(());
        };
        if !node.peer_verified() {
            // The client has not yet seen the admin node's key prove its zid.
            return ControlFlow::Continue(());
        }
        log(c"wz: the admin node holds an established session whose peer proved its zid");
        if observed != self.client_zid {
            log(c"wz: FAIL - the zid the admin node observed is not the client key's");
            return ControlFlow::Break(1);
        }
        log(c"wz: the zid the admin node observed is the zid of the client's key");

        let Some(open) = OPEN.get() else {
            return ControlFlow::Break(1);
        };
        let peer = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
        let mut out = FixedText::<256>::new();
        let node = &open.0;
        let listed_status = lifecycle_verdict(
            node,
            Command::Status { peer },
            Commander::Verified(&observed),
            &mut out,
        );
        if !matches!(listed_status, Verdict::Status(StatusVerdict::Status { .. })) {
            log(c"wz: FAIL - the commander the session proved was not answered for status");
            return ControlFlow::Break(1);
        }
        log(c"wz: the commander the session proved is answered for status");
        let mut out = FixedText::<256>::new();
        let listed_close = lifecycle_verdict(
            node,
            Command::Close { peer },
            Commander::Verified(&observed),
            &mut out,
        );
        if !matches!(listed_close, Verdict::Close(_)) || is_answered_close(&listed_close) {
            log(c"wz: FAIL - a commander listed for status alone commanded close");
            return ControlFlow::Break(1);
        }
        log(c"wz: a commander listed for status alone is refused close");
        let mut out = FixedText::<256>::new();
        let stranger = [0x5a; CREDENTIAL_ZID_BYTES];
        let unlisted = lifecycle_verdict(
            node,
            Command::Status { peer },
            Commander::Verified(&stranger),
            &mut out,
        );
        if unlisted != Verdict::Status(StatusVerdict::Refused(RefusedReason::StatusNotPermitted)) {
            log(c"wz: FAIL - a zid nobody listed was answered for status");
            return ControlFlow::Break(1);
        }
        log(c"wz: a zid nobody listed is refused status");
        self.checked = true;
        ControlFlow::Continue(())
    }
}

/// Whether a close verdict is one that took the peer out, and not a refusal.
fn is_answered_close(verdict: &Verdict) -> bool {
    !matches!(
        verdict,
        Verdict::Close(wz_session_core::lifecycle_wire::CloseVerdict::Refused(_))
    )
}

/// Register the admin node's own surface on its observer: the config-write subscriber and the
/// admin queryable binding the in-band verbs.
#[inline(never)]
fn install_observer(
    zid_hex: &str,
    locators: &[&str],
    open: &'static Verbs<StoreNode<Commanders>>,
) -> Result<&'static ObserverCell<Sinks>, &'static core::ffi::CStr> {
    let identity = FixedNodeIdentity::new(zid_hex, "peer", "wz-zephyr-admin-loopback", locators)
        .map_err(|_| c"wz: FAIL - the node's identity does not fit its fixed fields")?;
    static APP: wz_session_mcu::app_layer::SlotApp<Sinks> =
        wz_session_mcu::app_layer::SlotApp::new();
    let installed = APP.install_with(|observer| {
        if host_connect_writes_fixed(&mut observer.subscribers, zid_hex, "peer", &CONTROL.control)
            .is_err()
        {
            return Err(c"wz: FAIL - the node's observer refused its config subscriber");
        }
        if host_admin_queryable_fixed_with_open(
            &mut observer.queryables,
            identity,
            &CONTROL.status,
            &ADMIN,
            Some(&CONTROL.control),
            Some(&CONTROL.control),
            open,
        )
        .is_err()
        {
            return Err(c"wz: FAIL - the node's observer refused its admin queryable");
        }
        Ok(())
    });
    match installed {
        Ok((observer, Ok(()))) => Ok(observer),
        Ok((_, Err(why))) => Err(why),
        Err(_) => Err(c"wz: FAIL - the observer was installed twice"),
    }
}

/// Build the admin node, in its storage's arena. `Err` is the console line of a node that could not
/// start.
#[inline(never)]
fn start_server(
    zid: [u8; CREDENTIAL_ZID_BYTES],
    key: [u8; SIGNING_KEY_BYTES],
    identity: &'static wz_tls_mbedtls::channel::Identity,
    client_zid: DirectoryZid,
    address: [u8; 4],
) -> Result<(), &'static core::ffi::CStr> {
    // The commander list: the client's zid may ask `status`, and nothing else is anyone's.
    let listed = LISTED
        .set([client_zid])
        .map_err(|_| c"wz: FAIL - the commander list was written twice")?;
    let commanders = Commanders {
        status: &*listed,
        ..Commanders::NONE
    };
    let open = OPEN
        .set(Verbs(StoreNode::new(&SERVER.peers, commanders)))
        .map_err(|_| c"wz: FAIL - the verbs were bound twice")?;

    let mut zid_text: FixedText<33> = FixedText::new();
    let _ = write_zenoh_hex(&zid, &mut zid_text);
    let observer = install_observer(zid_text.prefix(), &[], open)?;

    let Some(runtime) = SERVER.runtime.start::<Driver>(Clock::default()) else {
        return Err(c"wz: FAIL - the admin node's runtime was started twice");
    };
    let local = CoopLocalSet::new(&runtime);
    let stack: Stack = IpStack::new(address, &SERVER.rx, &SERVER.tx, ZephyrTcpDial).with_tls(
        TlsDial::new(ZephyrTcpDial, identity).with_accept(AcceptBudget {
            clock: clock_ms,
            timeout_ms: ACCEPT_TIMEOUT_MS,
        }),
    );
    let Ok(port) = ZephyrTcpListener::listen(address, PORT, 2) else {
        return Err(c"wz: FAIL - the admin node could not listen");
    };
    let tls = TlsDial::new(ZephyrTcpDial, identity).with_accept(AcceptBudget {
        clock: clock_ms,
        timeout_ms: ACCEPT_TIMEOUT_MS,
    });
    let Ok(listener) = tls.listener(port) else {
        return Err(c"wz: FAIL - the admin node's listener could not take secure channels");
    };
    let acceptor = stack.tls_acceptor(listener);

    let parts = SERVER
        .run
        .put(|| {
            let host = SessionHost::new(
                CoopLocalSet::new(&runtime),
                &SERVER.sessions,
                &SERVER.pumps,
                stack,
            );
            host
        })
        .ok_or(c"wz: FAIL - the admin node's arena is too small")?;
    let host: &'static SessionHost<Clock, Stack, ZephyrEntropy, SESSIONS, SESSIONS> = parts;
    let factory = SERVER
        .run
        .put(|| RefCell::new(ServerFactory { zid, key, observer }))
        .ok_or(c"wz: FAIL - the admin node's arena is too small")?;
    let factory: &'static RefCell<ServerFactory> = factory;
    let node = AcceptingAdminNode::new(
        host,
        stack,
        acceptor,
        factory,
        &CONTROL.control,
        &SERVER.peers,
        &CONTROL.status,
        zid_text.prefix(),
        "peer",
        SessionTimeouts::spec_defaults(),
    )
    .map_err(|_| c"wz: FAIL - the node's admin keys do not fit")?;
    let node = SERVER
        .run
        .put(|| node)
        .ok_or(c"wz: FAIL - the admin node's arena is too small")?;
    SERVER_PARTS
        .set(ServerParts { local, node })
        .map_err(|_| c"wz: FAIL - the admin node was started twice")?;
    Ok(())
}

/// Milliseconds on the kernel's monotonic tick: the clock the listener's deadline reads.
fn clock_ms() -> u64 {
    Clock::default().now_us() / 1000
}

/// The endpoint the client dials.
static ENDPOINTS: StaticEndpoints = StaticEndpoints::new(&["tls/127.0.0.1:7471"]);

static DECLARED: Declared<0> = Declared::new();

/// Entry point the Zephyr C `main()` calls. Returns 0 on PASS.
#[no_mangle]
pub extern "C" fn wz_app_main() -> i32 {
    log(c"wz: admin node over Zephyr's own sockets, secure channel, starting");
    if start_on_platform_arena().is_err() {
        log(c"wz: FAIL - the secure channel could not start");
        return 1;
    }
    let (Ok(server_id), Ok(client_id)) = (
        SERVER_IDENTITY.generate(c"CN=wz-zephyr-admin"),
        CLIENT_IDENTITY.generate(c"CN=wz-zephyr-commander"),
    ) else {
        log(c"wz: FAIL - an end could not make its identity");
        return 1;
    };
    let mut key = [0u8; SIGNING_KEY_BYTES];
    let mut client_key = [0u8; SIGNING_KEY_BYTES];
    if ZephyrEntropy.try_fill_bytes(&mut key).is_err()
        || ZephyrEntropy.try_fill_bytes(&mut client_key).is_err()
    {
        log(c"wz: FAIL - the board's entropy source could not fill a signing key");
        return 2;
    }
    let Some(address) = await_board_ipv4(30_000).or(Some(LOOPBACK)) else {
        return 1;
    };
    let _ = address;
    if let Err(why) = start_server(server_id.zid(), key, server_id, client_id.zid(), LOOPBACK) {
        log(why);
        return 3;
    }
    // The queries the client asks the admin node once its session is up: the verbs, under the zid the
    // node announces. `peer` is any zid (a node held by it, or none): the commander is what is judged.
    {
        use core::fmt::Write;
        let mut server_hex: FixedText<33> = FixedText::new();
        write_zenoh_hex(&server_id.zid(), &mut server_hex);
        let mut status: FixedText<96> = FixedText::new();
        let mut close: FixedText<96> = FixedText::new();
        let peer = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
        let _ = write!(
            status,
            "@/{}/peer/session/status/{peer}",
            server_hex.prefix()
        );
        let _ = write!(close, "@/{}/peer/session/close/{peer}", server_hex.prefix());
        if ASK_KEYS.set([status, close]).is_err() {
            log(c"wz: FAIL - the queries were written twice");
            return 1;
        }
    }

    // The dialling node: the fixed-memory client over the same sockets, whose `tls/` dial steps the
    // admin node while it waits.
    let stack: ClientStack = IpStack::new(LOOPBACK, &CLIENT.rx, &CLIENT.tx, ZephyrTcpDial)
        .with_tls(
            TlsDial::new(SteppingDial, client_id).with_budget(HandshakeBudget {
                wait_ms: 5,
                waits: 12_000,
            }),
        );
    let Some(identity) = NodeIdentity::new(&client_id.zid(), client_key) else {
        log(c"wz: FAIL - the client's identity does not fit");
        return 1;
    };
    let client = ClientNode {
        storage: &CLIENT,
        declared: &DECLARED,
        clock: Clock::default(),
        stack,
        listening: Listening::NONE,
        plane: NoPlane,
        identity,
        batch_size: BATCH,
        entropy: || ZephyrEntropy,
        endpoints: &ENDPOINTS,
        peers: &[],
        documents: &[],
        entities: Entities::NONE,
        layer: AskLayer,
        idle_sleep_us: 5_000,
        report_every_ms: 0,
    };
    let app = Witness {
        client_zid: client_id.zid(),
        checked: false,
        concluded: false,
    };
    let mut port = Port;
    match client.start(&mut port, app, |_, _| {
        log(c"wz: the client is set up and dials the admin node");
    }) {
        Ok(mut running) => running.drive(&mut port),
        Err(code) => code,
    }
}

// Silence of the helpers the witness keeps for its diagnostics.
const _: fn() = || {
    let _ = stack_usage;
    let _ = Cell::new(0u8);
    let _: Option<IpDriver<ZephyrUdpSocket, ZephyrTcpSocket>> = None;
    let _ = (Str(""), U64(0));
};
