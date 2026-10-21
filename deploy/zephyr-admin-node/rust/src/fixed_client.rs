// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The client node of the Zephyr image on the fixed-memory profile: the node of `run_client` in
//! `lib.rs` with every table it holds in a `static` this file declares, over the session host and
//! the dialler every stack shares (`wz_session_mcu::slot_host`, `slot_dial`, `slot_client`) and
//! Zephyr's sockets as the stack (`wz_runtime_zephyr::net::ZephyrStack`).
//!
//! | what | where | bound |
//! | --- | --- | --- |
//! | sessions, dialled | `NODE.sessions`, `pumps`, the runtime's task table | [`SESSIONS`] |
//! | the link's receive buffer | inside each session's slot, the driver's array | [`RX`] |
//! | the frame being sent | inside each session's slot, the driver's lent array | [`TX`] |
//! | the observer, with the two queryables | `NODE.app` | the registry's own capacity |
//! | the endpoint it dials | [`crate::ENDPOINTS`], a `static` list | the connect manager's rows |
//! | the declarations it sends | [`DECLARATIONS`], a `static` slice | its length |
//!
//! # What this build is, and is not
//!
//! The node's own storage is above, and with it the Rust image has NO allocator: it declares none
//! (`zephyr_image_no_heap!`), `wz-runtime-zephyr` is built without its `alloc`, and the session
//! tier is the slot profile's, so no crate of the graph names `alloc`. The no-allocator link gate
//! takes that as its proof: a program that allocates anywhere does not link without a global
//! allocator. What it does NOT cover is the Zephyr kernel's own heap (its network stack and POSIX
//! layer), which the image still configures; `CONFIG_HEAP_MEM_POOL_SIZE` is what the kernel is
//! given for it, and what the kernel takes of it after start-up is measured, not assumed.
//!
//! The CMake build selects this profile with `CONFIG_WZ_FIXED_MEMORY` for the client node
//! (`CONFIG_WZ_NODE_CLIENT`), the same switch the lwIP admin node has.

use core::cell::RefCell;

use wz::runtime_zephyr::glue::{log, log_args, stack_usage, yield_us};
use wz::runtime_zephyr::net::{await_board_ipv4, board_zid_fixed, FixedUdpDriver, ZephyrStack};
use wz::runtime_zephyr::stack::StackWatch;
use wz::runtime_zephyr::{ZephyrClock, ZephyrEntropy};
use wz_runtime_coop::session_drive::{DriverPump, PumpSlots};
use wz_runtime_coop::session_runtime::SessionHandle;
use wz_runtime_coop::{ClockSource, CoopLocalSet, CoopRuntime, CoopTime, RuntimeCell};
use wz_session_core::entropy::EntropySource;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::slot_observer::{ObserverCell, Requesters};
use wz_session_core::text_out::FixedText;
use wz_session_core::zid_hex::write_zenoh_hex;
use wz_session_core::WhatAmI;
use wz_session_mcu::app_layer::{NoReplies, SlotApp, SlotDispatch};
use wz_session_mcu::slot_client::{
    register_document, Declaration, DeclarationKind, DocumentSinks, SlotClientNode,
};
use wz_session_mcu::slot_dial::SessionFactory;
use wz_session_mcu::slot_host::SessionHost;

use crate::{
    BATCH_SIZE, CONFIG_BODY, CONFIG_KEY, ENDPOINTS, IDLE_SLEEP_US, NODE_ID, STACK_CHECK_MS,
    STATUS_BODY, STATUS_KEY, TICK_HZ,
};

/// Sessions the node holds at most: the one it dials.
const SESSIONS: usize = 1;
/// The runtime's task table: a pump task per session, with room beside it.
const TASKS: usize = SESSIONS + 1;
/// Bytes of one task cell: the pump's handle and the application layer's state. The layer is a
/// few pointers, because a node that asks nothing keeps no table of requests (`Requests`), and
/// an `async fn` holds a by-value argument twice; the cell is sized well past that, and a task
/// the cell could not hold is refused and counted rather than run.
const TASK_BYTES: usize = 1024;
/// Timers the runtime holds: the handshake and lease deadlines of the session.
const TIMERS: usize = 4;
/// Extra bytes a link's receive buffer holds beyond one batch, so a datagram that carries a batch
/// and a transport header is not truncated.
const RX_SLACK: usize = 64;
/// The receive buffer of the session's driver.
const RX: usize = BATCH_SIZE as usize + RX_SLACK;
/// The storage the session's frames are encoded into: the largest frame it sends is one batch, which
/// is the budget the driver states as its link's frame bound.
const TX: usize = BATCH_SIZE as usize;
/// How long the node waits for the board to have an address: a DHCP lease on a slow link takes
/// seconds, and a board with no link or no server never gets one.
const ADDRESS_WAIT_MS: u32 = 30_000;

type Clock = ZephyrClock<TICK_HZ>;
/// The requests a session of this node holds: none. It answers queries and asks none, so it keeps
/// no table of pending gets, and the application layer its task holds is a few pointers.
type Requests = Requesters<NoReplies, NoReplies, 0, 0>;
type Driver = FixedUdpDriver<RX, TX>;
type Stack = ZephyrStack<RX, TX>;

/// The table of session slots this image places: one type for the assertion below and the
/// probe.
type Slots = SessionSlots<CoopRuntime<Clock>, CoopTime<Clock>, Driver, ZephyrEntropy, SESSIONS>;
/// The bytes ONE typed session slot takes in this image, as the compiler lays it out for the
/// target the image is built for.
const SLOT_BYTES: usize = Slots::slot_bytes();

/// The measured size of one typed session slot, as the SIZE of a symbol: see `fixed_node.rs`.
#[cfg(feature = "slot-bytes-probe")]
#[no_mangle]
#[used]
pub static WZ_SESSION_SLOT_BYTES: [u8; SLOT_BYTES] = [0; SLOT_BYTES];

// The tables are held under the numbers the deploy file states for the machine (`session_pool`):
// the sessions fit the generated table, the runtime's tables fit the task and timer ceilings,
// and ONE typed session slot, as the compiler lays it out for the target, fits the generated slot
// ceiling. A deploy file that lowers a number, or an image that outgrows one, is a build failure
// that names the line.
const _: () = {
    use wz_session_core::caps::{MAX_TASKS, MAX_TIMERS};
    use wz_session_core::session_slot_pool_mcu::{SLOT_COUNT, SLOT_SIZE};
    assert!(
        SESSIONS <= SLOT_COUNT,
        "SESSIONS exceeds the generated session table"
    );
    assert!(
        TASKS <= MAX_TASKS,
        "TASKS exceeds the deploy file's max_tasks"
    );
    assert!(
        TIMERS <= MAX_TIMERS,
        "TIMERS exceeds the deploy file's max_timers"
    );
    assert!(
        SLOT_BYTES <= SLOT_SIZE,
        "one typed session slot exceeds the generated slot ceiling"
    );
};

type Host = SessionHost<Clock, Stack, ZephyrEntropy, SESSIONS, SESSIONS>;

/// The node's big tables, in one `static` whose initial value is ALL ZERO BYTES, so the linker
/// places it in `.bss` (RAM) and not in `.data` (RAM and a copy of it in flash): one non-zero byte
/// anywhere in a `static` moves all of it.
struct Statics {
    runtime: RuntimeCell<Clock, TASKS, TASK_BYTES, TIMERS>,
    sessions: Slots,
    pumps: PumpSlots<Clock, DriverPump<Driver>, SESSIONS>,
    app: SlotApp<DocumentSinks>,
}

// SAFETY: the profile's rule, stated on the type: the node is driven by one cooperative loop on
// one thread, which is the only thing that reaches these tables; each member is `Sync` by the
// same rule.
unsafe impl Sync for Statics {}

impl Statics {
    const fn new() -> Self {
        Self {
            runtime: RuntimeCell::new(),
            sessions: SessionSlots::new(),
            pumps: PumpSlots::new(),
            app: SlotApp::new(),
        }
    }
}

static NODE: Statics = Statics::new();

/// The queryables the node declares on each session, in the order of their registrations.
static DECLARATIONS: [Declaration; 2] = [
    Declaration {
        kind: DeclarationKind::Queryable,
        key: STATUS_KEY,
    },
    Declaration {
        kind: DeclarationKind::Queryable,
        key: CONFIG_KEY,
    },
];

/// What the node makes its sessions from: the entropy, the parameters and the application layer
/// (the process-wide observer, with the two queryables registered on it).
struct Factory {
    zid: [u8; wz::runtime_zephyr::net::ZID_MAX],
    zid_len: usize,
    key: [u8; 32],
    observer: &'static ObserverCell<DocumentSinks>,
}

impl SessionFactory<Clock> for Factory {
    type Entropy = ZephyrEntropy;
    type Events = SlotDispatch<Clock, NoReplies, NoReplies, DocumentSinks, 0, 0>;

    fn entropy(&mut self) -> ZephyrEntropy {
        ZephyrEntropy
    }

    /// zenoh 1.x's handshake shape, with a batch the MCU's receive slot holds whole.
    fn params(&mut self) -> SessionInitParams {
        SessionInitParams {
            whatami: WhatAmI::Client,
            zid: zid_bytes(&self.zid[..self.zid_len]),
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
        SlotDispatch::new(self.observer, handle.clone(), Requests::new())
    }
}

/// Build the observer in `NODE.app`, where it stays, and register the node's two queryables on
/// it. The reason, as the console line, when one is refused.
///
/// Its own function, not inlined into [`run`], for the stack: the observer itself is large and is
/// never a value (see `fixed_node::install_observer`).
#[inline(never)]
fn install_observer() -> Result<&'static ObserverCell<DocumentSinks>, &'static core::ffi::CStr> {
    let installed = NODE.app.install_with(|observer| {
        if register_document(&mut observer.queryables, STATUS_KEY, STATUS_BODY).is_err()
            || register_document(&mut observer.queryables, CONFIG_KEY, CONFIG_BODY).is_err()
        {
            return Err(c"wz: FAIL - the node's observer refused a queryable");
        }
        Ok(())
    });
    match installed {
        Ok((observer, Ok(()))) => Ok(observer),
        Ok((_, Err(why))) => Err(why),
        Err(_) => Err(c"wz: FAIL - the observer was installed twice"),
    }
}

/// Assemble the node and run it. Returns only when it cannot start; the value is the reason, as a
/// nonzero code the C `main()` prints. The heap client's `run_client`, over the statics above.
pub fn run() -> i32 {
    // The cookie-signing key is a secret, so it comes from the board's entropy source and a board
    // that cannot supply it stops the node: a predictable key is worse than no node.
    let mut key = [0u8; 32];
    if ZephyrEntropy.try_fill_bytes(&mut key).is_err() {
        log(c"wz: FAIL - the board's entropy source could not fill the signing key");
        return 2;
    }
    let Some(address) = await_board_ipv4(ADDRESS_WAIT_MS) else {
        log(c"wz: FAIL - the board's interface never got an IPv4 address");
        return 1;
    };
    let Some((zid, zid_len)) = board_zid_fixed() else {
        log(c"wz: FAIL - the board gave no identity to derive a zenoh id from");
        return 1;
    };

    let clock = Clock::default();
    let Some(runtime) = NODE.runtime.start(clock) else {
        log(c"wz: FAIL - the runtime was started twice");
        return 3;
    };
    let local = CoopLocalSet::new(&runtime);

    // The zid in the zenoh hex form, in fixed text.
    let mut zid_text: FixedText<33> = FixedText::new();
    let _ = write_zenoh_hex(&zid[..zid_len], &mut zid_text);
    let zid_hex = zid_text.prefix();

    // The application's registrations, on the observer the session dispatches to. A node whose
    // registrations were refused would declare what nothing answers: stop instead, with the
    // reason.
    let observer = match install_observer() {
        Ok(observer) => observer,
        Err(why) => {
            log(why);
            return 3;
        }
    };

    let stack = Stack::new(address);
    let host: Host = SessionHost::new(
        CoopLocalSet::new(&runtime),
        &NODE.sessions,
        &NODE.pumps,
        stack,
    );
    let factory = RefCell::new(Factory {
        zid,
        zid_len,
        key,
        observer,
    });
    let mut node = SlotClientNode::new(
        &host,
        stack,
        &factory,
        &ENDPOINTS,
        SessionTimeouts::spec_defaults(),
        &DECLARATIONS,
    );
    // The line a lane (or a person at the console) waits for: who the node claims to be and the
    // router it dials.
    log_args(format_args!(
        "ZEPHYR-WZ-CLIENT READY {} {} {}",
        NODE_ID,
        zid_hex,
        env!("WZ_CLIENT_ENDPOINT")
    ));

    let mut established = false;
    let mut stack_watch = StackWatch::new();
    let mut next_stack_check_ms = 0u64;
    loop {
        local.run_until_idle();
        let now_ms = clock.now_us() / 1000;
        node.tick(now_ms);
        if now_ms >= next_stack_check_ms {
            next_stack_check_ms = now_ms + STACK_CHECK_MS;
            if let Some(usage) = stack_watch.observe_peak(stack_usage()) {
                log_args(format_args!(
                    "stack: peak {} of {} bytes",
                    usage.peak(),
                    usage.size
                ));
            }
        }
        // A line when the session comes and goes, which is all a lab waits for.
        if node.is_established() != established {
            established = !established;
            log_args(format_args!(
                "zephyr-wz-client: session {}",
                if established { "established" } else { "lost" }
            ));
        }
        // The stack's own wait on a socket is what gives the CPU away while a session is held
        // (its read waits for a datagram). Between two dials of a router that is not up the node
        // holds no socket: it sleeps the tick itself then, or it spins above the network stack's
        // threads and starves them.
        if !node.holds_session() {
            yield_us(IDLE_SLEEP_US);
        }
    }
}
