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
    BATCH_SIZE, DOC_MAX, IDLE_SLEEP_US, IDLE_WAIT_MS, RX, TASK_BYTES_ACTIVE, TIMERS, TX,
};
use host_slot_node_glue::{fresh_signing_key, ConsoleName, HostPort};
use wz_runtime_posix::glue::{log, log_args};
#[cfg(not(feature = "tls"))]
use wz_runtime_posix::slot::PosixStack;
#[cfg(not(feature = "tls"))]
use wz_runtime_posix::stream::PosixTcpDial;
#[cfg(feature = "listen")]
use wz_runtime_posix::stream::PosixTcpListener;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::caps::{MAX_QUERYABLES, MAX_REPLY_PAYLOAD_BYTES, MAX_SUBSCRIPTIONS};
use wz_session_core::sample_kind::SampleKind;
use wz_session_mcu::connect_manager::StaticEndpoints;
use wz_session_mcu::latest::{Latest, LatestCells, LatestRef, LatestWatch};
use wz_session_mcu::slot_active::Active;
use wz_session_mcu::slot_client::Listening;
use wz_session_mcu::slot_node::{
    documents_of, BodyPool, ClientNode, Declared, Entities, Mirror, NodeApp, NodeHandle,
    NodeIdentity, NodePort, NodeStorage, Subscription,
};
use wz_session_mcu::slot_publisher::{Publication, PublishCounts, PublishWatch};
#[cfg(feature = "get")]
use wz_session_mcu::slot_querier::{Query, QueryState, QueryWatch};

wz_runtime_posix::posix_image_no_heap!();

/// What the declaration states, generated: `NODE_ID`, `DIALED`, `LISTEN`, `TLS`, `DOCS` and
/// `DOCUMENTS`, and the rest of the constants of `scripts/lib/wz_node.py --emit`.
mod declared {
    include!(env!("WZ_DECLARED_RS"));
}

#[cfg(feature = "get")]
use declared::QUERIED;
use declared::{
    ACCEPTS, CELLS, DECLARATION_SHA256, DIALED, DOCS, DOCUMENTS, LISTEN, LISTENS, MIRRORED,
    MIRRORS, NODE_ID, PUBLISHED, PUBLISHERS, QUERIERS, SAMPLE_MAX, SESSIONS, SUBSCRIBERS,
    SUBSCRIPTIONS, TLS, TOKENS, TOKEN_KEYS,
};
#[cfg(feature = "listen")]
use declared::{LISTEN_ADDR, LISTEN_PORT};

/// The runtime's task table: a pump task per session, the dialled and the accepted, and nothing
/// else runs as a task.
const TASKS: usize = SESSIONS;

/// The declarations the node sends on a session: its documents, the queryables that answer from a
/// cell, the subscriptions and the liveliness tokens.
const DECLS: usize = DOCS + MIRRORS + SUBSCRIBERS + TOKENS;

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
            from < CELLS,
            "a queryable answers from a cell that is not there"
        );
        assert!(
            cell_bytes(from) <= MAX_REPLY_PAYLOAD_BYTES,
            "a queryable answers from a cell that keeps more than a reply holds"
        );
        at += 1;
    }
};
const _: () = assert!(
    CELLS == SUBSCRIBERS + QUERIERS,
    "the cells are the subscriptions' and the queriers'"
);
const _: () = assert!(
    TOKENS == 0 || cfg!(feature = "token"),
    "the declaration has a liveliness token and the node is not built with the `token` feature that declares it"
);
const _: () = assert!(
    QUERIERS == 0 || cfg!(feature = "get"),
    "the declaration has a querier and the node is not built with the `get` feature that asks"
);
const _: () = {
    let mut at = 0;
    while at < QUERIERS {
        assert!(
            queried_bytes(at) >= 1 && queried_bytes(at) <= SAMPLE_MAX,
            "a querier keeps no bytes, or more than the cells hold"
        );
        at += 1;
    }
};

/// The bytes the cell `at` keeps: the subscriptions' first, then the queriers'.
const fn cell_bytes(at: usize) -> usize {
    if at < SUBSCRIBERS {
        SUBSCRIPTIONS[at].1
    } else {
        queried_bytes(at - SUBSCRIBERS)
    }
}

/// The bytes the replies of querier `at` are kept to.
#[cfg(feature = "get")]
const fn queried_bytes(at: usize) -> usize {
    QUERIED[at].3
}

/// A node built without `get` has no querier (`QUERIERS` is asserted to be 0), so no cell is one.
#[cfg(not(feature = "get"))]
const fn queried_bytes(_at: usize) -> usize {
    0
}
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
const _: () = assert!(
    LISTENS == cfg!(feature = "listen"),
    "the declaration has a listening endpoint exactly when the node is built with the `listen` feature"
);
const _: () = assert!(
    LISTENS == (ACCEPTS > 0),
    "a node listens exactly when it holds sessions a peer opened"
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
    NodeStorage<Clock, Stack, PosixEntropy, TASKS, TASK_BYTES_ACTIVE, TIMERS, SESSIONS, RX, TX>;

static NODE: Storage = Storage::new();

/// The bytes every document is made of.
static BODY: BodyPool<DOC_MAX> = BodyPool::new();

/// The endpoints the node dials: the declaration's, checked against a locator row when this is
/// built. A node that only listens dials none.
static ENDPOINTS: StaticEndpoints = StaticEndpoints::new(&DIALED);

/// The declarations the node sends on each session, in the order of their registrations.
static DECLARED: Declared<DECLS> = Declared::new();

/// The latest of each cell, in the cells the declaration sized: the subscriptions' samples and then
/// the queriers' replies.
static LATEST: LatestCells<CELLS, SAMPLE_MAX> = LatestCells::new();

/// How many puts each publisher sent and had refused.
static COUNTS: PublishCounts<PUBLISHERS> = PublishCounts::new();

/// Where the replies of the queriers are kept, and how many queries each asked and had answered.
#[cfg(feature = "get")]
static QUERY_STATE: QueryState<QUERIERS> = QueryState::new();

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
            slots: &LATEST,
            index: at,
        },
        capacity: SUBSCRIPTIONS[at].1,
    })
}

/// The queryables that answer from a cell (a subscription's or a querier's), each with the cell it
/// reads.
fn mirrors() -> [Mirror; MIRRORS] {
    core::array::from_fn(|at| Mirror {
        key: MIRRORED[at].0,
        cell: LatestRef {
            slots: &LATEST,
            index: MIRRORED[at].1,
        },
    })
}

/// The queries the declaration chose: each key, its period, how long it may stay pending and how
/// much of a reply is kept.
#[cfg(feature = "get")]
fn queries() -> [Query; QUERIERS] {
    core::array::from_fn(|at| Query {
        key: QUERIED[at].0,
        period_ms: QUERIED[at].1,
        timeout_ms: QUERIED[at].2,
        reply_bytes: QUERIED[at].3,
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
    watch: LatestWatch<CELLS>,
    published: PublishWatch<PUBLISHERS>,
    #[cfg(feature = "get")]
    queried: QueryWatch<QUERIERS>,
}

impl NodeApp for Report {
    fn after_tick(&mut self, _now_ms: u64, _node: &dyn NodeHandle) -> ControlFlow<i32> {
        self.published.poll(&COUNTS, |at, sent, refused| {
            log_args(format_args!(
                "HOST-WZ-PUBLISHED {} sent={} refused={}",
                PUBLISHED[at].0, sent, refused
            ));
        });
        #[cfg(feature = "get")]
        self.queried.poll(&QUERY_STATE, |at, tally| {
            log_args(format_args!(
                "HOST-WZ-ASKED {} asked={} replies={} errors={} finals={} timeouts={} refused={}",
                QUERIED[at].0,
                tally.asked,
                tally.replied,
                tally.errors,
                tally.finals,
                tally.timeouts,
                tally.refused
            ));
        });
        // The subscriptions' cells come first, then the queriers'.
        self.watch.poll_range(&LATEST, 0, SUBSCRIBERS, |_, sample| {
            say_cell("HOST-WZ-SAMPLE", &sample)
        });
        self.watch
            .poll_range(&LATEST, SUBSCRIBERS, CELLS, |_, sample| {
                say_cell("HOST-WZ-REPLY", &sample)
            });
        ControlFlow::Continue(())
    }
}

/// One cell, said on one line whatever its bytes are: `<tag> <key> put len= kept= seq= hex=`, or
/// `<tag> <key> del seq=` for a delete.
fn say_cell(tag: &str, sample: &Latest<'_>) {
    let mut hex = [0u8; 2 * SAMPLE_MAX];
    for (at, byte) in sample.payload.iter().enumerate() {
        hex[2 * at] = b"0123456789abcdef"[usize::from(byte >> 4)];
        hex[2 * at + 1] = b"0123456789abcdef"[usize::from(byte & 15)];
    }
    match sample.kind {
        SampleKind::Put => log_args(format_args!(
            "{} {} put len={} kept={} seq={} hex={}",
            tag,
            sample.key,
            sample.received_len,
            sample.payload.len(),
            sample.sequence,
            core::str::from_utf8(&hex[..2 * sample.payload.len()]).unwrap_or("")
        )),
        SampleKind::Del => log_args(format_args!(
            "{} {} del seq={}",
            tag, sample.key, sample.sequence
        )),
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
    #[cfg(not(feature = "tls"))]
    let stack = Stack::new([0; 4], &NODE.rx, &NODE.tx, PosixTcpDial).with_idle_wait_ms(IDLE_WAIT_MS);
    #[cfg(feature = "tls")]
    let stack = tls::stack([0; 4], &NODE.rx, &NODE.tx, channel_identity)
        .with_idle_wait_ms(IDLE_WAIT_MS);
    // The port is bound before the node is built, so the line a lab waits for is said only once a
    // connection to it would be taken.
    #[cfg(feature = "listen")]
    let listening = match PosixTcpListener::bind(LISTEN_ADDR, LISTEN_PORT) {
        Ok(listener) => Listening::<_, ACCEPTS>::new(stack.acceptor(listener)),
        Err(why) => {
            log_args(format_args!("wz: FAIL - cannot listen on {LISTEN}: {why:?}"));
            return 3;
        }
    };
    #[cfg(not(feature = "listen"))]
    let listening = Listening::NONE;
    let node = ClientNode {
        storage: &NODE,
        declared: &DECLARED,
        clock: Clock::default(),
        stack,
        listening,
        identity,
        batch_size: BATCH_SIZE,
        entropy: || PosixEntropy,
        endpoints: &ENDPOINTS,
        documents: &documents[..taken],
        entities: Entities {
            subscriptions: &subscribed,
            mirrors: &mirrored,
            tokens: &TOKEN_KEYS,
        },
        layer: Active::<PUBLISHERS, QUERIERS> {
            publications: publications(),
            counts: &COUNTS,
            #[cfg(feature = "get")]
            queries: queries(),
            #[cfg(feature = "get")]
            state: &QUERY_STATE,
        },
        idle_sleep_us: IDLE_SLEEP_US,
        report_every_ms: 0,
    };
    // The line a lab (or a person at the console) waits for, once the node is built: the same one
    // `host-slot-node` says, so a lab that waits for it waits for either.
    // The replies of the queriers are kept after the subscriptions' samples, in the same cells.
    #[cfg(feature = "get")]
    QUERY_STATE.attach(&LATEST, SUBSCRIBERS, &queries());
    let mut report = Report {
        watch: LatestWatch::new(),
        published: PublishWatch::new(),
        #[cfg(feature = "get")]
        queried: QueryWatch::new(),
    };
    node.run(
        &mut HostPort::<Console>::new(),
        &mut report,
        |port, zid_hex| {
            // The router it dials, or `-` for a node that dials none.
            port.log(format_args!(
                "HOST-WZ-CLIENT READY {zid_hex} {}",
                DIALED.first().copied().unwrap_or("-")
            ));
            if LISTENS {
                port.log(format_args!("HOST-WZ-LISTEN {LISTEN}"));
            }
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
