// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The admin node of the Zephyr image on the fixed-memory profile (fixed-memory step
//! S9c): the node of `run` in `lib.rs` with every table it holds in a `static` this
//! file declares, over the slot profile's pieces (`wz_session_lwip::slot_node`), the
//! stack of `net_lwip`'s fixed form and the console line of `glue::log_args`.
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions, dialled and accepted | `NODE.sessions`, `pumps`, the runtime's task table | [`SESSIONS`] |
//! | sockets | `net_lwip::SOCKETS`: one for the listener, one per session | [`SOCKETS`] |
//! | the listener's lanes | `NODE.listener` | [`LANES`] |
//! | the observer, with the admin queryable and the config subscriber | `NODE.app` | the registries' own capacities |
//! | the interfaces | the static pools of `net_lwip` | `net_lwip::MAX_PORTS` |
//! | the endpoints it dials, the sessions it reports | the connect manager, `NODE.status` | `caps::MAX_STATIC_CONNECT`, [`SESSIONS`] |
//!
//! # What this build is, and is not
//!
//! The node's own storage is above. The image is NOT allocator-free yet, and the reasons
//! are not this file's: `zephyr_image!` declares the global allocator over the kernel
//! heap and `wz-runtime-zephyr` links `alloc` (its console line, its stack line, its
//! clock-check line), the MAC drivers' bring-up lines are built with `format!`, and
//! the session tier (`wz-session-core`, the codec owned mirrors) allocates. What it does
//! show is that the node SHELL asks the heap for nothing it does not have to: its sessions,
//! sockets, interfaces, endpoint list, status rows and console lines are fixed.
//!
//! Not built with `west` (no Zephyr SDK here): the staticlib compiles through the S8
//! gate's stand-in for the board's build values, which is a compile and a link-input
//! check, and nothing was booted on the T2G kit.

use core::cell::RefCell;

use wz::link_lwip::LwipLink;
use wz::runtime_coop::session_drive::PumpSlots;
use wz::runtime_coop::session_runtime::SessionHandle;
use wz::runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz::runtime_zephyr::glue::{log, log_args, stack_usage, yield_ms};
use wz::runtime_zephyr::stack::StackWatch;
use wz::runtime_zephyr::{ZephyrClock, ZephyrEntropy};
use wz::session_lwip::admin_fixed::{
    host_admin_queryable_fixed, AdminHost, AdminSinks, FixedNodeIdentity, FixedNodeStatus,
};
use wz::session_lwip::admin_host::{host_connect_writes_fixed, ConnectControl};
use wz::session_lwip::app_layer::{NoReplies, SlotApp, SlotDispatch};
use wz::session_lwip::driver::LwipUdpDriver;
use wz::session_lwip::listener::SessionListener;
use wz::session_lwip::session_host::SessionHost;
use wz::session_lwip::slot_node::{SessionFactory, SlotAdminNode};
use wz::session_lwip::{LwipLinks, LwipSessionLink};
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{Requesters, SlotObserverOf};
use wz_session_core::text_out::FixedText;
use wz_session_core::zid_hex::write_zenoh_hex;
use wz_session_core::WhatAmI;

use crate::net_lwip::{LwipMacNet, MAX_PORTS, SOCKETS as SOCKET_POOL};
use crate::{BATCH_SIZE, LISTEN_PORT, STACK_CHECK_MS, TICK_HZ};

/// Sessions the node holds at most, dialled and accepted together: the process's
/// `max_sessions`.
pub const SESSIONS: usize = 2;
/// Sockets of the pool: one for the listener and one per session the node dials.
pub const SOCKETS: usize = SESSIONS + 1;
/// Peers that may be admitted at once on the listening socket.
const LANES: usize = 1;
/// The runtime's task table: a pump task per session, with room beside them.
const TASKS: usize = SESSIONS + 1;
/// Bytes of one task cell: the pump's handle and the application layer's state. The
/// layer is about 4.9 KB (its requesters are 4.8 KB of them) and an `async fn` holds a
/// by-value argument twice, so the cell is sized for two of them and the handle; the
/// same number the host test of the slot node holds to the measured size.
const TASK_BYTES: usize = 12288;
/// Timers the runtime holds: the handshake and lease deadlines of the sessions.
const TIMERS: usize = 4;
/// The widest locator text: `udp/255.255.255.255:65535`.
const LOCATOR_BYTES: usize = 32;
/// The version the node reports.
const VERSION: &str = "wz-zephyr-admin-node";

type Clock = ZephyrClock<TICK_HZ>;
type Host = SessionHost<Clock, &'static LwipLink, ZephyrEntropy, SESSIONS, SESSIONS>;
type Node<'a> = SlotAdminNode<'a, Clock, &'static LwipLink, Factory, SESSIONS, SESSIONS, LANES>;

/// Everything the node declares, in one `static`.
struct Statics {
    runtime: RuntimeCell<Clock, TASKS, TASK_BYTES, TIMERS>,
    sessions:
        SessionSlots<CoopRuntime<Clock>, CoopTime<Clock>, LwipUdpDriver, ZephyrEntropy, SESSIONS>,
    pumps: PumpSlots<Clock, LwipSessionLink<&'static LwipLink>, SESSIONS>,
    listener: SessionListener<LANES>,
    status: FixedNodeStatus<SESSIONS>,
    /// Writes are PERMITTED on this node: upstream's default is to refuse, and the node
    /// opts in, because being reconfigured is what it is for.
    control: ConnectControl,
    admin: AdminHost<1024>,
    app: SlotApp<Sinks>,
}

/// The registrations the node's observer holds, all closed types: the config-write
/// subscriber and the admin queryable.
type Sinks = AdminSinks<1024, SESSIONS>;

// SAFETY: the profile's rule, stated on the type: the node is driven by one cooperative
// loop on one thread, which is the only thing that reaches these tables; each member is
// `Sync` by the same rule.
unsafe impl Sync for Statics {}

impl Statics {
    const fn new() -> Self {
        Self {
            runtime: RuntimeCell::new(),
            sessions: SessionSlots::new(),
            pumps: PumpSlots::new(),
            listener: SessionListener::new(),
            status: FixedNodeStatus::new(true),
            control: ConnectControl::new(true),
            admin: AdminHost::new(),
            app: SlotApp::new(),
        }
    }
}

static NODE: Statics = Statics::new();

/// What the node makes its sessions from: the entropy, the parameters and the
/// application layer (the process-wide observer, with the node's own admin surface
/// registered on it).
struct Factory {
    zid: [u8; 6],
    key: [u8; 32],
    observer: &'static RefCell<SlotObserverOf<Sinks>>,
}

impl SessionFactory<Clock> for Factory {
    type Entropy = ZephyrEntropy;
    type Events = SlotDispatch<Clock, NoReplies, NoReplies, Sinks>;

    fn entropy(&mut self) -> ZephyrEntropy {
        ZephyrEntropy
    }

    /// zenoh 1.x's handshake shape, with a batch the MCU's receive slot holds whole.
    fn params(&mut self) -> SessionInitParams {
        SessionInitParams {
            version: 0x09,
            whatami: WhatAmI::Peer,
            zid: zid_bytes(&self.zid),
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: BATCH_SIZE,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: cookie_bytes(&[]),
            tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
            cookie_signing_key: SigningKey::from_slice(&self.key).expect("32-byte key"),
        }
    }

    fn events(&mut self, handle: &SessionHandle<Clock>) -> Self::Events {
        SlotDispatch::new(self.observer, handle.clone(), Requesters::new())
    }
}

/// `udp/a.b.c.d:port` for `address`, in fixed text.
fn locator(address: [u8; 4]) -> FixedText<LOCATOR_BYTES> {
    use core::fmt::Write;
    let [a, b, c, d] = address;
    let mut text = FixedText::new();
    let _ = write!(text, "udp/{a}.{b}.{c}.{d}:{LISTEN_PORT}");
    text
}

/// Assemble the node over `net` and run it. Returns only when it cannot start; the value
/// is the reason, as a nonzero code the C `main()` prints. The heap form's `run`, over
/// the statics above.
pub fn run(mut net: LwipMacNet) -> i32 {
    // The cookie-signing key is a secret, so it comes from the board's entropy source and
    // a board that cannot supply it stops the node: a predictable key is worse than no
    // node.
    let mut key = [0u8; 32];
    if ZephyrEntropy.try_fill_bytes(&mut key).is_err() {
        log(c"wz: FAIL - the board's entropy source could not fill the signing key");
        return 2;
    }

    let clock = Clock::default();
    let Some(runtime) = NODE.runtime.start(clock) else {
        log(c"wz: FAIL - the runtime was started twice");
        return 3;
    };
    let local = CoopLocalSet::new(&runtime);
    let zid = net.zid();
    let link = net.link();

    // The zid in the zenoh hex form, in fixed text.
    let mut zid_text: FixedText<33> = FixedText::new();
    let _ = write_zenoh_hex(&zid, &mut zid_text);
    let zid_hex = zid_text.prefix();

    // The locators: one per link, in fixed text, as the identity reports them.
    let mut locators = [const { FixedText::<LOCATOR_BYTES>::new() }; MAX_PORTS];
    let count = net.addresses().len();
    for (text, address) in locators.iter_mut().zip(net.addresses()) {
        *text = locator(*address);
    }
    let mut locator_refs = [""; MAX_PORTS];
    for (slot, text) in locator_refs.iter_mut().zip(&locators).take(count) {
        *slot = text.prefix();
    }

    // The application's registrations, on the observer every session of the node
    // dispatches to: the config-write subscriber and the admin queryable. A node whose
    // registrations were refused would run without its admin space: stop instead, with
    // the reason.
    let mut observer = SlotObserverOf::<Sinks>::new();
    if host_connect_writes_fixed(&mut observer.subscribers, zid_hex, "peer", &NODE.control).is_err()
    {
        log(c"wz: FAIL - the node's observer refused its config subscriber");
        return 3;
    }
    let identity = match FixedNodeIdentity::new(zid_hex, "peer", VERSION, &locator_refs[..count]) {
        Ok(identity) => identity,
        Err(_) => {
            log(c"wz: FAIL - the node's identity does not fit its fixed fields");
            return 3;
        }
    };
    if host_admin_queryable_fixed(
        &mut observer.queryables,
        identity,
        &NODE.status,
        &NODE.admin,
        Some(&NODE.control),
        Some(&NODE.control),
    )
    .is_err()
    {
        log(c"wz: FAIL - the node's observer refused its admin queryable");
        return 3;
    }
    let Ok(observer) = NODE.app.install(observer) else {
        log(c"wz: FAIL - the observer was installed twice");
        return 3;
    };

    let host: Host = SessionHost::new(
        CoopLocalSet::new(&runtime),
        &NODE.sessions,
        &NODE.pumps,
        link,
    );
    let links = LwipLinks::new(link, &SOCKET_POOL);
    let factory = RefCell::new(Factory { zid, key, observer });
    let node = Node::new(
        &host,
        &links,
        &factory,
        &NODE.listener,
        &NODE.control,
        &NODE.status,
        zid_hex,
        "peer",
        LISTEN_PORT,
        SessionTimeouts::spec_defaults(),
    );
    let mut node = match node {
        Ok(node) => node,
        Err(_) => {
            log(c"wz: FAIL - the node's admin keys do not fit");
            return 3;
        }
    };
    // The line a lane (or a person at the console) waits for: who the node claims to be
    // and where it is, one locator per link.
    log_args(format_args!(
        "ZEPHYR-WZ-ADMIN READY {} {} {}",
        zid_hex, locator_refs[0], locator_refs[1],
    ));

    let mut reported = 0;
    let mut generation = None;
    // The node is the stack's only tenant, so its own reading of it is the one that
    // counts: a line when the peak grows, which a lane reads the last of.
    let mut stack = StackWatch::new();
    let mut next_stack_check_ms = 0u64;
    loop {
        local.run_until_idle();
        net.pump();
        let now_ms = clock.now_us() / 1000;
        node.tick(now_ms);
        if now_ms >= next_stack_check_ms {
            next_stack_check_ms = now_ms + STACK_CHECK_MS;
            if let Some(usage) = stack.observe_peak(stack_usage()) {
                log_args(format_args!(
                    "stack: peak {} of {} bytes",
                    usage.peak(),
                    usage.size
                ));
            }
        }

        let (written, endpoints) = NODE.control.endpoints();
        if generation != Some(written) {
            generation = Some(written);
            log_args(format_args!(
                "zephyr-admin-node: connect/endpoints = {endpoints:?}"
            ));
        }
        let sessions = NODE.status.session_count();
        if sessions != reported {
            reported = sessions;
            log_args(format_args!("zephyr-admin-node: {reported} session(s)"));
        }
        // The net stack's own threads, and the tick, need this thread's CPU.
        yield_ms(1);
    }
}
