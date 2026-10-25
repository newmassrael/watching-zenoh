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

use core::ops::ControlFlow;
#[cfg(not(feature = "tls"))]
use host_slot_node_glue::fresh_zid;
#[cfg(feature = "tls")]
use host_slot_node_glue::tls;
use host_slot_node_glue::tuning::{
    BATCH_SIZE, DOC_MAX, IDLE_SLEEP_US, IDLE_WAIT_MS, RX, SESSIONS, TASKS, TASK_BYTES_PUBLISHING,
    TIMERS, TX,
};
use host_slot_node_glue::{fresh_signing_key, ConsoleName, HostPort};
use wz_runtime_posix::glue::{log, log_args};
#[cfg(not(feature = "tls"))]
use wz_runtime_posix::slot::PosixStack;
#[cfg(not(feature = "tls"))]
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::caps::{MAX_QUERYABLES, MAX_REPLY_PAYLOAD_BYTES, MAX_SUBSCRIPTIONS};
use wz_session_core::sample_kind::SampleKind;
use wz_session_mcu::connect_manager::StaticEndpoints;
use wz_session_mcu::latest::{LatestCells, LatestRef, LatestWatch};
use wz_session_mcu::slot_node::{
    documents_of, BodyPool, ClientNode, Declared, Entities, Mirror, NodeApp, NodeHandle,
    NodeIdentity, NodePort, NodeStorage, Subscription,
};
use wz_session_mcu::slot_publisher::{Publication, PublishCounts, PublishWatch, Publishing};

wz_runtime_posix::posix_image_no_heap!();

/// What the declaration states, generated: `NODE_ID`, `ROUTER`, `TLS`, `DOCS` and `DOCUMENTS`.
mod declared {
    include!(env!("WZ_DECLARED_RS"));
}

use declared::{
    DECLARATION_SHA256, DOCS, DOCUMENTS, MIRRORED, MIRRORS, NODE_ID, PUBLISHED, PUBLISHERS, ROUTER,
    SAMPLE_MAX, SUBSCRIBERS, SUBSCRIPTIONS, TLS,
};

/// The declarations the node sends on a session: its documents, the queryables that answer from a
/// subscription, and the subscriptions.
const DECLS: usize = DOCS + MIRRORS + SUBSCRIBERS;

/// The revision of how this executable is driven. It takes no argument and reads no document, so the
/// surface is the console lines a lab waits for; it moves when one of them is removed or changes
/// meaning, and not when a node declaration changes.
#[allow(dead_code)]
const SURFACE_REVISION: u32 = 1;

wz_abi_stamp::stamp!(
    family = "declared-node",
    revision = SURFACE_REVISION,
    layout = [],
);

// Which node this is and the digest of the declaration it was built from, so a tool that describes
// the file for another operating system reads both from it and holds them to the declaration.
wz_abi_stamp::facts!(
    lists = [
        ("node_id", &[NODE_ID]),
        ("declaration_sha256", &[DECLARATION_SHA256])
    ]
);

const _: () = assert!(
    DOCS + MIRRORS <= MAX_QUERYABLES,
    "the declaration has more queryables than the registry holds"
);
const _: () = assert!(
    SUBSCRIBERS <= MAX_SUBSCRIPTIONS,
    "the declaration has more subscriptions than the subscriber table holds"
);
const _: () = {
    let mut at = 0;
    while at < SUBSCRIBERS {
        assert!(
            SUBSCRIPTIONS[at].1 >= 1 && SUBSCRIPTIONS[at].1 <= SAMPLE_MAX,
            "a subscription keeps no bytes, or more than the cells hold"
        );
        at += 1;
    }
    let mut at = 0;
    while at < MIRRORS {
        let from = MIRRORED[at].1;
        assert!(
            from < SUBSCRIBERS,
            "a queryable answers from a subscription that is not there"
        );
        assert!(
            SUBSCRIPTIONS[from].1 <= MAX_REPLY_PAYLOAD_BYTES,
            "a queryable answers from a subscription that keeps more than a reply holds"
        );
        at += 1;
    }
};
const _: () = {
    let mut at = 0;
    while at < PUBLISHERS {
        assert!(
            PUBLISHED[at].1 >= 1,
            "a publisher has a period of no milliseconds"
        );
        assert!(
            PUBLISHED[at].2 <= DOC_MAX,
            "a publisher puts a document longer than the body pool"
        );
        at += 1;
    }
};
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
    NodeStorage<Clock, Stack, PosixEntropy, TASKS, TASK_BYTES_PUBLISHING, TIMERS, SESSIONS, RX, TX>;

static NODE: Storage = Storage::new();

/// The bytes every document is made of.
static BODY: BodyPool<DOC_MAX> = BodyPool::new();

/// The endpoint the node dials: the declaration's, checked against a locator row when this is built.
static ENDPOINTS: StaticEndpoints = StaticEndpoints::new(&[ROUTER]);

/// The declarations the node sends on each session, in the order of their registrations.
static DECLARED: Declared<DECLS> = Declared::new();

/// The latest sample of each subscription, in the cells the declaration sized.
static CELLS: LatestCells<SUBSCRIBERS, SAMPLE_MAX> = LatestCells::new();

/// How many puts each publisher sent and had refused.
static COUNTS: PublishCounts<PUBLISHERS> = PublishCounts::new();

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

/// The subscriptions the declaration chose, each with the cell that keeps its latest sample.
fn subscriptions() -> [Subscription; SUBSCRIBERS] {
    core::array::from_fn(|at| Subscription {
        key: SUBSCRIPTIONS[at].0,
        cell: LatestRef {
            slots: &CELLS,
            index: at,
        },
        capacity: SUBSCRIPTIONS[at].1,
    })
}

/// The queryables that answer from a subscription, each with the cell it reads.
fn mirrors() -> [Mirror; MIRRORS] {
    core::array::from_fn(|at| Mirror {
        key: MIRRORED[at].0,
        cell: LatestRef {
            slots: &CELLS,
            index: MIRRORED[at].1,
        },
    })
}

/// The publications the declaration chose: each key, its period and a document of the declared
/// length, a prefix of the body pool.
fn publications() -> [Publication; PUBLISHERS] {
    core::array::from_fn(|at| Publication {
        key: PUBLISHED[at].0,
        period_ms: PUBLISHED[at].1,
        body: BODY.text(PUBLISHED[at].2).unwrap_or(""),
    })
}

/// What the node says when a subscription takes a sample: the console line a lab waits for, once for
/// each round that found a cell moved. The payload is in hex, so the line is one line whatever the
/// bytes are; `seq` is how many samples the cell has taken, so a run of samples that arrived between
/// two rounds shows as a jump. A publisher is said the same way, as `HOST-WZ-PUBLISHED <key>
/// sent=<n> refused=<n>`, once for each round that found its counts moved.
struct Report {
    watch: LatestWatch<SUBSCRIBERS>,
    published: PublishWatch<PUBLISHERS>,
}

impl NodeApp for Report {
    fn after_tick(&mut self, _now_ms: u64, _node: &dyn NodeHandle) -> ControlFlow<i32> {
        self.published.poll(&COUNTS, |at, sent, refused| {
            log_args(format_args!(
                "HOST-WZ-PUBLISHED {} sent={} refused={}",
                PUBLISHED[at].0, sent, refused
            ));
        });
        self.watch.poll(&CELLS, SUBSCRIBERS, |_, sample| {
            let mut hex = [0u8; 2 * SAMPLE_MAX];
            for (at, byte) in sample.payload.iter().enumerate() {
                hex[2 * at] = b"0123456789abcdef"[usize::from(byte >> 4)];
                hex[2 * at + 1] = b"0123456789abcdef"[usize::from(byte & 15)];
            }
            match sample.kind {
                SampleKind::Put => log_args(format_args!(
                    "HOST-WZ-SAMPLE {} put len={} kept={} seq={} hex={}",
                    sample.key,
                    sample.received_len,
                    sample.payload.len(),
                    sample.sequence,
                    core::str::from_utf8(&hex[..2 * sample.payload.len()]).unwrap_or("")
                )),
                SampleKind::Del => log_args(format_args!(
                    "HOST-WZ-SAMPLE {} del seq={}",
                    sample.key, sample.sequence
                )),
            }
        });
        ControlFlow::Continue(())
    }
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

    let (subscribed, mirrored) = (subscriptions(), mirrors());
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
        entities: Entities {
            subscriptions: &subscribed,
            mirrors: &mirrored,
        },
        layer: Publishing {
            publications: publications(),
            counts: &COUNTS,
        },
        idle_sleep_us: IDLE_SLEEP_US,
        report_every_ms: 0,
    };
    // The line a lab (or a person at the console) waits for, once the node is built: the same one
    // `host-slot-node` says, so a lab that waits for it waits for either.
    let mut report = Report {
        watch: LatestWatch::new(),
        published: PublishWatch::new(),
    };
    node.run(
        &mut HostPort::<Console>::new(),
        &mut report,
        |port, zid_hex| {
            port.log(format_args!("HOST-WZ-CLIENT READY {zid_hex} {ROUTER}"));
        },
    )
}

#[no_mangle]
pub extern "C" fn main(
    _argc: core::ffi::c_int,
    _argv: *const *const core::ffi::c_char,
) -> core::ffi::c_int {
    run()
}
