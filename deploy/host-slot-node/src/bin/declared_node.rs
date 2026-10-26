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
#[cfg(feature = "multicast")]
use host_slot_node_glue::group::{HostGroupTransport, PosixGroupBind};
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
use wz_session_mcu::connect_manager::{DeclaredPeer, StaticEndpoints};
#[cfg(feature = "multicast")]
use wz_session_mcu::group_drive::MulticastSlots;
use wz_session_mcu::latest::{Latest, LatestCells, LatestRef, LatestWatch};
use wz_session_mcu::slot_active::Active;
use wz_session_mcu::slot_client::Listening;
#[cfg(feature = "multicast")]
use wz_session_mcu::slot_group::{GroupState, GroupTiming, SlotGroup};
#[cfg(not(feature = "multicast"))]
use wz_session_mcu::slot_node::NoPlane;
use wz_session_mcu::slot_node::{
    documents_of, BodyPool, ClientNode, Declared, Entities, Mirror, NodeApp, NodeHandle,
    NodeIdentity, NodePort, NodeStorage, Subscription,
};
use wz_session_mcu::slot_publisher::{
    Body, MadeBuffer, Process, Publication, PublishCounts, PublishWatch,
};
#[cfg(feature = "get")]
use wz_session_mcu::slot_querier::{Query, QueryState, QueryWatch};
use wz_session_mcu::slot_replay::{Decimal, Replay, ReplayCounts, ReplayWatch, Sample, Schedule};

wz_runtime_posix::posix_image_no_heap!();

/// What the declaration states, generated: `NODE_ID`, `DIALED`, `LISTEN`, `TLS`, `DOCS` and
/// `DOCUMENTS`, and the rest of the constants of `scripts/lib/wz_node.py --emit`.
mod declared {
    include!(env!("WZ_DECLARED_RS"));
}

#[cfg(feature = "get")]
use declared::QUERIED;
use declared::{
    ACCEPTS, CELLS, DECLARATION_SHA256, DIALED, DOCS, DOCUMENTS, GROUPS, LISTEN, LISTENS, MIRRORED,
    MIRRORS, NODE_ID, PEERS, PEER_NODES, PUBLISHED, PUBLISHERS, QUERIERS, REPLAYED, REPLAYS,
    REPLAY_SAMPLES, SAMPLE_MAX, SESSIONS, SUBSCRIBERS, SUBSCRIPTIONS, TLS, TOKENS, TOKEN_KEYS,
};
#[cfg(feature = "multicast")]
use declared::{GROUP, GROUP_ADDR, GROUP_PORT, GROUP_TTL, MEMBERS};
#[cfg(feature = "listen")]
use declared::{LISTEN_ADDR, LISTEN_PORT};

/// The runtime's task table: a pump task per session, the dialled and the accepted, and one for the
/// group the node is a member of; nothing else runs as a task.
const TASKS: usize = SESSIONS + GROUPS;

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

/// The gap of a publisher's arrival process, in nanoseconds: its period, its Poisson mean or the
/// gap between its bursts.
const fn gap_nanos(process: Process) -> u64 {
    match process {
        Process::Periodic { gap_nanos } | Process::Burst { gap_nanos, .. } => gap_nanos,
        Process::Poisson { mean_gap_nanos, .. } => mean_gap_nanos,
    }
}
const _: () = {
    let mut at = 0;
    while at < PUBLISHERS {
        assert!(
            gap_nanos(PUBLISHED[at].1) >= 1_000_000,
            "a publisher's gap is shorter than the millisecond the node's clock counts"
        );
        match PUBLISHED[at].3 {
            None => assert!(
                PUBLISHED[at].2 <= DOC_MAX,
                "a publisher puts a document longer than the body pool"
            ),
            Some(_) => {
                assert!(PUBLISHED[at].2 >= 1, "a publisher makes a body of no bytes");
                assert!(
                    GROUPS == 0,
                    "a publisher of a node with a group makes a body for each put, which the group cannot carry"
                );
            }
        }
        at += 1;
    }
};

/// The longest body the node makes for a put, a publisher's or a replayed sample's once mutated: the
/// size of its one buffer, and none for a node that makes no body.
const MADE_MAX: usize = {
    let (mut at, mut most) = (0, 0);
    while at < PUBLISHERS {
        if PUBLISHED[at].3.is_some() && PUBLISHED[at].2 > most {
            most = PUBLISHED[at].2;
        }
        at += 1;
    }
    let mut at = 0;
    while at < REPLAY_SAMPLES.len() {
        let (_, body, _, mutation) = REPLAY_SAMPLES[at];
        let len = mutation.output_len(body.len());
        if len > most {
            most = len;
        }
        at += 1;
    }
    most
};

// Every replay is a range of the samples, and the ranges are the samples: the generator writes them
// so, and a row that did not would play another replay's samples.
const _: () = {
    let (mut at, mut next) = (0, 0);
    while at < REPLAYS {
        let (_, _, _, _, _, first, count) = REPLAYED[at];
        assert!(
            first == next && count >= 1,
            "a replay is not the next range of the samples"
        );
        next = first + count;
        at += 1;
    }
    assert!(
        next == REPLAY_SAMPLES.len(),
        "a sample belongs to no replay"
    );
    assert!(
        REPLAYS == 0 || GROUPS == 0,
        "a replay of a node with a group mutates its samples into a buffer the group cannot carry"
    );
};

/// The replays' samples, as the layer plays them: read-only data.
static SAMPLES: [Sample; REPLAY_SAMPLES.len()] = {
    let mut out = [Sample {
        key: "",
        body: &[],
        captured_at_ms: None,
        mutation: wz_session_mcu::slot_replay::Mutation::None,
    }; REPLAY_SAMPLES.len()];
    let mut at = 0;
    while at < REPLAY_SAMPLES.len() {
        let (key, body, captured_at_ms, mutation) = REPLAY_SAMPLES[at];
        out[at] = Sample {
            key,
            body,
            captured_at_ms,
            mutation,
        };
        at += 1;
    }
    out
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
const _: () = assert!(
    (GROUPS == 1) == cfg!(feature = "multicast"),
    "the declaration has a multicast endpoint exactly when the node is built with the `multicast` feature"
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

/// The peers the node holds by their zid beside the router it dials, from the declaration (decision
/// D7 of `docs/session-lifecycle-intent.md`, the third transport): no verb asks for them.
static PEER_TABLE: [DeclaredPeer; PEERS] = peer_table();

const fn peer_table() -> [DeclaredPeer; PEERS] {
    let mut table = [DeclaredPeer {
        zid: [0; 16],
        locator: "",
    }; PEERS];
    let mut at = 0;
    while at < PEERS {
        table[at] = DeclaredPeer {
            zid: PEER_NODES[at].0,
            locator: PEER_NODES[at].1,
        };
        at += 1;
    }
    table
}

/// The declarations the node sends on each session, in the order of their registrations.
static DECLARED: Declared<DECLS> = Declared::new();

/// The cell the group's session lives in, the one the node's group takes, and what the group keeps
/// for the loop: the peer tables its pump dispatches against and the members it has.
#[cfg(feature = "multicast")]
static GROUP_CELLS: MulticastSlots<Clock, HostGroupTransport, MEMBERS, 1> = MulticastSlots::new();
#[cfg(feature = "multicast")]
static GROUP_STATE: GroupState = GroupState::new();

/// The latest of each cell, in the cells the declaration sized: the subscriptions' samples and then
/// the queriers' replies.
static LATEST: LatestCells<CELLS, SAMPLE_MAX> = LatestCells::new();

/// How many puts each publisher sent and had refused, and how late the latest was.
static COUNTS: PublishCounts<PUBLISHERS> = PublishCounts::new();

/// The bytes a body made for each put, or a replayed sample mutated, is written into, one for the
/// node's sessions.
static MADE: MadeBuffer<MADE_MAX> = MadeBuffer::new();

/// What each replay put, had refused and mutated, how late, and how many times it played through.
static REPLAY_COUNTS: ReplayCounts<REPLAYS> = ReplayCounts::new();

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

/// The publications the declaration chose: each key, its arrival process, and a document of the
/// declared length (a prefix of the body pool) or a body made for each put by its fill.
fn publications() -> [Publication; PUBLISHERS] {
    core::array::from_fn(|at| {
        let (key, arrivals, bytes, fill) = PUBLISHED[at];
        let body = match fill {
            None => Body::Text(BODY.text(bytes).unwrap_or("")),
            Some(fill) => Body::Made { size: bytes, fill },
        };
        Publication {
            key,
            arrivals,
            body,
        }
    })
}

/// The replays the declaration chose: each a range of the samples and the schedule its words make,
/// or the console line, as the reason, when a speed is not a decimal (the generator refuses one, so
/// this is the image refusing to start rather than to guess a speed).
fn replays() -> Result<[Replay; REPLAYS], &'static str> {
    let mut out = [Replay {
        name: "",
        samples: &[],
        schedule: Schedule::default(),
    }; REPLAYS];
    for (slot, &(name, timing, gap_ms, speed, max_gap_ms, first, count)) in
        out.iter_mut().zip(REPLAYED.iter())
    {
        let speed = Decimal::parse(speed)
            .map_err(|_| "wz: FAIL - a replay's speed is not a decimal")?
            .as_f64();
        *slot = Replay {
            name,
            samples: &SAMPLES[first..first + count],
            schedule: Schedule {
                timing,
                gap_millis: gap_ms,
                speed,
                max_gap_millis: Some(max_gap_ms),
                max_total_millis: None,
            },
        };
    }
    Ok(out)
}

/// What the node says when a subscription takes a sample: the console line a lab waits for, once for
/// each round that found a cell moved. The payload is in hex, so the line is one line whatever the
/// bytes are; `seq` is how many samples the cell has taken, so a run of samples that arrived between
/// two rounds shows as a jump. A publisher is said the same way, as `HOST-WZ-PUBLISHED <key>
/// sent=<n> refused=<n> late_max_ms=<n>`, once for each round that found its counts moved: the last
/// is how late its latest put was against its intended time, which a node that could not keep its
/// arrival process says rather than thin its puts. A replay is said as `HOST-WZ-REPLAYED <key>
/// sent=<n> refused=<n> mutated=<n> late_max_ms=<n> played=<n>`, `played` the times it was put to
/// its last sample (once a session).
struct Report {
    watch: LatestWatch<CELLS>,
    published: PublishWatch<PUBLISHERS>,
    replayed: ReplayWatch<REPLAYS>,
    #[cfg(feature = "get")]
    queried: QueryWatch<QUERIERS>,
    /// The group's joins, join refusals, JOINs its member table turned away and members when they
    /// were last said.
    #[cfg(feature = "multicast")]
    group: (u32, u32, u32, u32),
}

impl NodeApp for Report {
    fn after_tick(&mut self, _now_ms: u64, _node: &dyn NodeHandle) -> ControlFlow<i32> {
        // The group, said once for each round that found it changed: `HOST-WZ-GROUP <locator>
        // joins=<n> refused=<n> turned_away=<n> members=<n>`. A lab waits for `members=1` to know
        // the node has admitted a peer's JOIN, for `joins=1` to know the group is joined at all, and
        // reads `turned_away` above none as the member table being full: the peers it turned away
        // are not members, and nothing else on the line says they tried.
        #[cfg(feature = "multicast")]
        {
            let now = (
                GROUP_STATE.joins(),
                GROUP_STATE.join_refused(),
                GROUP_STATE.members_turned_away(),
                GROUP_STATE.members(),
            );
            if now != self.group {
                self.group = now;
                log_args(format_args!(
                    "HOST-WZ-GROUP {} joins={} refused={} turned_away={} members={}",
                    GROUP, now.0, now.1, now.2, now.3
                ));
            }
        }
        self.published
            .poll(&COUNTS, |at, sent, refused, late_max_ms| {
                log_args(format_args!(
                    "HOST-WZ-PUBLISHED {} sent={} refused={} late_max_ms={}",
                    PUBLISHED[at].0, sent, refused, late_max_ms
                ));
            });
        self.replayed.poll(
            &REPLAY_COUNTS,
            |at, (sent, refused, mutated, late_max_ms, played)| {
                log_args(format_args!(
                    "HOST-WZ-REPLAYED {} sent={} refused={} mutated={} late_max_ms={} played={}",
                    REPLAYED[at].0, sent, refused, mutated, late_max_ms, played
                ));
            },
        );
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

    let played = match replays() {
        Ok(played) => played,
        Err(why) => {
            log(why);
            return 3;
        }
    };

    let (subscribed, mirrored) = (subscriptions(), mirrors());
    #[cfg(not(feature = "tls"))]
    let stack =
        Stack::new([0; 4], &NODE.rx, &NODE.tx, PosixTcpDial).with_idle_wait_ms(IDLE_WAIT_MS);
    #[cfg(feature = "tls")]
    let stack =
        tls::stack([0; 4], &NODE.rx, &NODE.tx, channel_identity).with_idle_wait_ms(IDLE_WAIT_MS);
    // The port is bound before the node is built, so the line a lab waits for is said only once a
    // connection to it would be taken.
    #[cfg(feature = "listen")]
    let listening = match PosixTcpListener::bind(LISTEN_ADDR, LISTEN_PORT) {
        Ok(listener) => Listening::<_, ACCEPTS>::new(stack.acceptor(listener)),
        Err(why) => {
            log_args(format_args!(
                "wz: FAIL - cannot listen on {LISTEN}: {why:?}"
            ));
            return 3;
        }
    };
    #[cfg(not(feature = "listen"))]
    let listening = Listening::NONE;
    // The group is joined by the node's first round, and the line a lab waits for says when.
    #[cfg(feature = "multicast")]
    let plane = SlotGroup {
        slots: &GROUP_CELLS,
        state: &GROUP_STATE,
        bind: PosixGroupBind {
            group: GROUP_ADDR,
            port: GROUP_PORT,
            ttl: GROUP_TTL,
        },
        publications: publications(),
        counts: &COUNTS,
        timing: GroupTiming::ZENOH,
    };
    #[cfg(not(feature = "multicast"))]
    let plane = NoPlane;
    let node = ClientNode {
        storage: &NODE,
        declared: &DECLARED,
        clock: Clock::default(),
        stack,
        listening,
        plane,
        identity,
        batch_size: BATCH_SIZE,
        entropy: || PosixEntropy,
        endpoints: &ENDPOINTS,
        peers: &PEER_TABLE,
        documents: &documents[..taken],
        entities: Entities {
            subscriptions: &subscribed,
            mirrors: &mirrored,
            tokens: &TOKEN_KEYS,
        },
        layer: Active::<PUBLISHERS, QUERIERS, REPLAYS, MADE_MAX> {
            publications: publications(),
            counts: &COUNTS,
            replays: played,
            replay_counts: &REPLAY_COUNTS,
            made: &MADE,
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
    let report = Report {
        watch: LatestWatch::new(),
        published: PublishWatch::new(),
        replayed: ReplayWatch::new(),
        #[cfg(feature = "get")]
        queried: QueryWatch::new(),
        #[cfg(feature = "multicast")]
        group: (0, 0, 0, 0),
    };
    // Out of band, a test agent tells the node which peer to hold (decision D7).
    #[cfg(feature = "control")]
    let report = host_slot_node_glue::control::WithControl::new(
        report,
        host_slot_node_glue::control::HostOpener::new(
            wz_session_mcu::connect_manager::NodeOpener::in_store(&NODE.peers),
        ),
    );
    let mut report = report;
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
