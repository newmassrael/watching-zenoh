// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The fixed-memory node of a DECLARATION, as a Linux process.
//!
//! The second front end of the host's fixed-memory node (the first is `host-slot-node`, which reads
//! its router and documents from the command line). This one takes them from a node declaration
//! (`deploy/nodes/*.toml`) that `scripts/lib/wz_node.py --emit` turned into constants; the build
//! names the file in `WZ_DECLARED_RS`. Nothing is read when it runs: the endpoint it dials and the
//! documents it answers with were fixed when it was built, so what the declaration states is what
//! the program does, and a declaration the node cannot hold does not build (the `const` assertions
//! below are the second check, after the generator's own).
//!
//! The mechanism is `wz_session_mcu::slot_node`'s, the host's console, sleep, identity and tuning
//! are `host_slot_node_glue`'s, and this file is only the composition of the two from constants.
//!
//! ```text
//! declared-node
//! ```
#![no_std]
#![no_main]

#[cfg(not(feature = "tls"))]
use host_slot_node_glue::fresh_zid;
#[cfg(feature = "tls")]
use host_slot_node_glue::tls;
use host_slot_node_glue::tuning::{
    BATCH_SIZE, DOC_MAX, IDLE_SLEEP_US, IDLE_WAIT_MS, RX, SESSIONS, TASKS, TASK_BYTES_ANSWERING,
    TIMERS, TX,
};
use host_slot_node_glue::{fresh_signing_key, ConsoleName, HostPort};
use wz_runtime_posix::glue::log;
#[cfg(feature = "tls")]
use wz_runtime_posix::glue::log_args;
#[cfg(not(feature = "tls"))]
use wz_runtime_posix::slot::PosixStack;
#[cfg(not(feature = "tls"))]
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::caps::MAX_QUERYABLES;
use wz_session_mcu::connect_manager::StaticEndpoints;
use wz_session_mcu::slot_node::{
    documents_of, Answering, BodyPool, ClientNode, Declared, NodeIdentity, NodePort, NodeStorage,
};

wz_runtime_posix::posix_image_no_heap!();

/// What the declaration states, generated: `NODE_ID`, `ROUTER`, `TLS`, `DOCS` and `DOCUMENTS`.
mod declared {
    include!(env!("WZ_DECLARED_RS"));
}

use declared::{DOCS, DOCUMENTS, ROUTER, TLS};

const _: () = assert!(
    DOCS <= MAX_QUERYABLES,
    "the declaration has more queryables than the registry holds"
);
const _: () = assert!(
    TLS == cfg!(feature = "tls"),
    "the declaration's endpoint is `tls/` exactly when the node is built with the `tls` feature"
);
const _: () = {
    let mut at = 0;
    while at < DOCS {
        assert!(
            DOCUMENTS[at].1 <= DOC_MAX,
            "a document of the declaration is longer than the body pool"
        );
        at += 1;
    }
};

type Clock = PosixClock;
#[cfg(not(feature = "tls"))]
type Stack = PosixStack;
#[cfg(feature = "tls")]
type Stack = tls::Stack;

/// The node's big tables, in one `static` whose initial value is ALL ZERO BYTES, so the linker
/// places it in `.bss` and not in `.data`.
type Storage =
    NodeStorage<Clock, Stack, PosixEntropy, TASKS, TASK_BYTES_ANSWERING, TIMERS, SESSIONS, RX, TX>;

static NODE: Storage = Storage::new();

/// The bytes every document is made of.
static BODY: BodyPool<DOC_MAX> = BodyPool::new();

/// The endpoint the node dials: the declaration's, checked against a locator row when this is built.
static ENDPOINTS: StaticEndpoints = StaticEndpoints::new(&[ROUTER]);

/// The queryables the node declares on each session, in the order of their registrations.
static DECLARED: Declared<DOCS> = Declared::new();

/// The name this front end's console lines carry.
struct Console;

impl ConsoleName for Console {
    const NAME: &'static str = declared::NODE_ID;
}

/// The documents the declaration chose, in the shape the registry takes them.
fn chosen() -> [Option<(&'static str, usize)>; DOCS] {
    let mut out = [None; DOCS];
    let mut at = 0;
    while at < DOCS {
        out[at] = Some(DOCUMENTS[at]);
        at += 1;
    }
    out
}

/// Assemble the node and run it. Returns only when it cannot start; the value is the process's exit
/// code.
fn run() -> i32 {
    let key = match fresh_signing_key() {
        Ok(key) => key,
        Err(why) => {
            log(why);
            return 2;
        }
    };
    #[cfg(not(feature = "tls"))]
    let zid = match fresh_zid() {
        Ok(zid) => zid,
        Err(why) => {
            log(why);
            return 2;
        }
    };
    // Over the secure channel the node's zid is the one its key names (decision D1), and its
    // certificate is printed for the router's operator to pin.
    #[cfg(feature = "tls")]
    let (channel_identity, zid) = match tls::identity() {
        Ok(identity) => {
            identity.certificate_pem(log_args);
            (identity, identity.zid())
        }
        Err(why) => {
            log(why);
            return 2;
        }
    };

    let Some(identity) = NodeIdentity::new(&zid, key) else {
        log("wz: FAIL - the zenoh id does not fit");
        return 2;
    };
    let (documents, taken) = match documents_of(&BODY, &chosen()) {
        Ok(found) => found,
        Err(why) => {
            log(why);
            return 3;
        }
    };

    let node = ClientNode {
        storage: &NODE,
        declared: &DECLARED,
        clock: Clock::default(),
        #[cfg(not(feature = "tls"))]
        stack: Stack::new([0; 4], &NODE.rx, &NODE.tx, PosixTcpDial).with_idle_wait_ms(IDLE_WAIT_MS),
        #[cfg(feature = "tls")]
        stack: tls::stack([0; 4], &NODE.rx, &NODE.tx, channel_identity)
            .with_idle_wait_ms(IDLE_WAIT_MS),
        identity,
        batch_size: BATCH_SIZE,
        entropy: || PosixEntropy,
        endpoints: &ENDPOINTS,
        documents: &documents[..taken],
        layer: Answering,
        idle_sleep_us: IDLE_SLEEP_US,
        report_every_ms: 0,
    };
    // The line a lab (or a person at the console) waits for, once the node is built: the same one
    // `host-slot-node` says, so a lab that waits for it waits for either.
    node.run(&mut HostPort::<Console>::new(), &mut (), |port, zid_hex| {
        port.log(format_args!("HOST-WZ-CLIENT READY {zid_hex} {ROUTER}"));
    })
}

#[no_mangle]
pub extern "C" fn main(
    _argc: core::ffi::c_int,
    _argv: *const *const core::ffi::c_char,
) -> core::ffi::c_int {
    run()
}
