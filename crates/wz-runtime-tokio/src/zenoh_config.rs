// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y579 (G8) — emit a STOCK-zenoh JSON5 config, and validate a topology
//! before anything is started.
//!
//! ## What was missing
//!
//! [`WzConfig`](crate::config::WzConfig) is deliberately wz's own TYPED config,
//! positioned against zenoh's stringly JSON5 blob — illegal states
//! unrepresentable, no JSON pointer into an untyped tree. That is the right
//! shape for configuring wz. It is no help at all to anything that has to
//! configure a STOCK zenoh node: a wz deployment that stands up a zenohd
//! alongside itself, a test harness that wants the router to carry the same
//! transport parameters wz negotiated, an operator asking whether a topology
//! can work before spending a startup on it. For all of those, wz had no
//! schema to lean on and the answer was a hand-written JSON5 blob.
//!
//! This module closes that in both directions:
//!
//! * **emit** — `ZenohNodeConfig::to_json5` renders the config zenoh's own
//!   `-c` flag reads, with the key paths taken from the reference's
//!   `DEFAULT_CONFIG.json5` rather than from memory.
//! R311y844 — the three names below are CODE SPANS, not intra-doc links. This
//! module is `#[cfg(feature = "zenoh-config-emit")]`, and a module doc's link
//! to an item of its own module does not resolve in a gated module (the same
//! link in an ITEM doc does). Layer C1bz runs on default features, so it
//! cannot see this file at all: the count is a hand measurement, and it was
//! 190-with-the-feature against a 189 budget until this line stopped being a
//! link.
//!
//! * **validate** — `ZenohNodeConfig::validate` answers "can this NODE work"
//!   WITHOUT starting it: an unknown link protocol, a node that can reach
//!   nothing, the QoS-with-lowlatency pair zenoh's own config documents as
//!   incompatible. `validate_for_build` adds the one verdict that depends on
//!   the reader — a scheme this build has no link backend for (R2070).
//! * **validate_topology** (R2070b) — the SET question the line above used to
//!   claim and could not keep. It said "can this topology work", but the
//!   receiver is one config and the body reads `self`; a dial nobody listens
//!   on, two nodes claiming one address, and a set of nothing but clients are
//!   all invisible from inside a single node. `validate_topology` takes the
//!   slice and answers them, and the wording here was corrected in the same
//!   round — a doc that promises a wider scope than the code has is worse
//!   than a missing check, because the reader stops looking.
//! * **ingest** (R311y842) — `ZenohNodeConfig::from_json5` reads the file
//!   `zenohd -c` reads.
//!
//! (The three item names in this module doc are CODE SPANS, not intra-doc
//! links, for the reason `json5`'s module doc records: a link from a
//! cfg-gated module's own `//!` doc to its own item does not resolve, while
//! the same link inside an ITEM's doc below does. Measured here under
//! `--features zenoh-config-emit`, which is a feature set Layer C1bz never
//! selects, so nothing would have caught them.)
//!
//! ## Why the READ direction is the one that makes wz a replacement
//!
//! Emit and validate serve a wz deployment that stands a stock zenoh node up
//! NEXT to itself. Neither helps the operator who wants to stand wz up INSTEAD
//! of that node: until R311y842 every wz setting arrived as a bespoke
//! command-line flag, so the config file the deployment already had was an
//! input to nothing, and "drop-in" meant hand-translating a document into
//! ninety flags. A replacement that cannot read the deployment's own
//! configuration is not one.
//!
//! The reader is deliberately PARTIAL and says so out loud. wz models 14 of
//! the 111 leaf keys a real zenohd resolves, and
//! `ZenohConfigIngest::ignored` names every key in the document that is not
//! one of them. The alternative shapes are both worse: refusing an unknown key
//! makes the reader useless against a real config, and applying what it knows
//! while staying silent lets an operator believe a TLS root-CA path took
//! effect. The partition is also what a coverage census compares against the
//! upstream surface, which is why it is a value rather than a log line.
//!
//! ## Why the validator is worth having when zenoh will also complain
//!
//! Because zenoh complains at a different time and about a different thing. A
//! bad protocol scheme surfaces as a failed listener some milliseconds after
//! startup, in a log; a client with no way to reach anything does not fail at
//! all, it simply never connects. The defects below are the ones that are
//! cheap to state up front and expensive to diagnose from behaviour.
//!
//! Its judgment is not self-certified: `zenoh_config_emit_zenohd_interop`
//! spawns a REAL zenohd on an emitted config and requires it to come up AND
//! carry the parameters that were emitted, and pairs that with a config the
//! validator rejects, which the same zenohd also refuses.
//!
//! ## Scope
//!
//! The emitted surface is the topology-and-transport subset: mode, endpoints,
//! scouting, the transport parameters wz itself negotiates, adminspace and
//! timestamping. It is NOT the whole zenoh config, and does not pretend to be
//! — the routing / plugins / storages trees are a stock-zenoh concern wz has
//! no typed opinion about, and emitting defaults for them would be inventing
//! configuration rather than translating it. Everything omitted takes zenoh's
//! own default, which is what a partial JSON5 config means to zenoh.

use core::fmt::Write as _;

use wz_codecs::whatami::WhatAmI;
use wz_session_core::json::escape_into;
use wz_session_core::json5::{number_as_u64, Json5Value};
// R2070b (open-debt item 486) — the topology pass compares endpoints, and the
// tested parser is the one the dial seam already uses. Writing a second
// splitter here would be a second opinion about IPv6 brackets and `#iface=`
// spans, which is exactly the kind of near-copy this module has been paying
// off all round.
use wz_session_core::locator::{parse_any_locator, AnyLocator, Proto};

/// Link protocols a stock zenoh 1.5.0 can carry, read off the reference's own
/// `io/zenoh-links/*/src/lib.rs` `*_LOCATOR_PREFIX` constants plus
/// `zenoh-link-unixpipe`'s (which lives one module deeper). `quic-datagram`
/// is absent on purpose: its link crate declares the prefix `"quic"`, so it
/// shares a scheme rather than adding one.
pub const ZENOH_LINK_PROTOCOLS: &[&str] = &[
    "tcp",
    "udp",
    "tls",
    "quic",
    "serial",
    "unixsock-stream",
    "unixpipe",
    "vsock",
    "ws",
];

/// Every link scheme wz can serve, paired with the cargo feature that compiles
/// its backend in.
///
/// R2070 (open-debt item 487) — the catalogue, as opposed to
/// `crate::compiled_in_link_schemes()`, which is what ONE build has. Both
/// answers are needed and they are different sentences: a 2026-08-23 external
/// review read this tree and reported `ws` as a MISSING transport, when `ws`
/// is implemented, feature-gated, and carries two zenohd interop witnesses —
/// it simply is not on by default, and nothing said so in a place a reader
/// would find. This table is that place, and it is what lets
/// [`ConfigDefect::ProtocolNotCompiledIn`] end with the flag to flip instead
/// of leaving an operator to guess it.
///
/// The mapping is NOT the identity, which is the whole reason it is written
/// down: `unixsock-stream` is served by `transport-link-unixsock`, and a
/// message that derived the feature name from the scheme would be wrong for
/// exactly the scheme fewest people know by heart.
pub const LINK_SCHEME_FEATURES: &[(&str, &str)] = &[
    ("tcp", "transport-link-tcp"),
    ("udp", "transport-link-udp"),
    ("tls", "transport-link-tls"),
    ("quic", "transport-link-quic"),
    ("serial", "transport-link-serial"),
    ("unixsock-stream", "transport-link-unixsock"),
    ("unixpipe", "transport-link-unixpipe"),
    ("vsock", "transport-link-vsock"),
    ("ws", "transport-link-ws"),
];

/// The cargo feature that compiles in `scheme`'s link backend, if wz serves
/// that scheme at all. See [`LINK_SCHEME_FEATURES`].
pub fn link_scheme_feature(scheme: &str) -> Option<&'static str> {
    LINK_SCHEME_FEATURES
        .iter()
        .find(|(s, _)| *s == scheme)
        .map(|(_, feature)| *feature)
}

/// A reason a topology cannot work, stated before anything is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigDefect {
    /// An endpoint with no `<proto>/<address>` split at all.
    MalformedEndpoint {
        /// The endpoint as given.
        endpoint: String,
    },
    /// An endpoint whose protocol is not one stock zenoh carries. Catching
    /// this here matters because zenoh reports it as a listener that failed
    /// to open, well after startup and only in a log.
    UnknownProtocol {
        /// The endpoint as given.
        endpoint: String,
        /// The scheme that was not recognised.
        protocol: String,
    },
    /// An endpoint whose protocol IS one stock zenoh carries, but which the
    /// binary judging the config was not built with — so the node this config
    /// starts cannot bind or dial it.
    ///
    /// R2070 (open-debt item 487) — this is the one defect that is a property
    /// of the READER rather than of the file, which is why it is reported only
    /// when [`ZenohNodeConfig::validate_for_build`] is told which schemes the
    /// reader has. A config emitted for a stock zenohd must NOT collect it:
    /// zenohd carries all nine, and narrowing the emit verdict to this build's
    /// features would reject files that are perfectly correct for their
    /// target.
    ProtocolNotCompiledIn {
        /// The endpoint as given.
        endpoint: String,
        /// The scheme this build has no link backend for.
        protocol: String,
    },
    /// The same listen endpoint twice. zenoh binds them in order and the
    /// second fails with an address-in-use whose cause is not obvious from
    /// the message.
    DuplicateListenEndpoint {
        /// The repeated endpoint.
        endpoint: String,
    },
    /// The node has no way to reach any peer: nothing to connect to, nothing
    /// listening, and multicast scouting off. This one does not FAIL at
    /// runtime — the node starts cleanly and is simply alone forever, which
    /// is the most expensive kind of misconfiguration to diagnose.
    Unreachable,
    /// `qos` and `lowlatency` together. zenoh's own `DEFAULT_CONFIG.json5`
    /// states the LowLatency transport does not preserve QoS prioritisation
    /// and that the two are incompatible.
    QosWithLowlatency,
    /// A zero batch size. Nothing can be sent.
    ZeroBatchSize,
    /// A zero lease. Every link is instantly expired.
    ZeroLease,
    /// Fewer than one link per session.
    ZeroMaxLinks,
}

impl core::fmt::Display for ConfigDefect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigDefect::MalformedEndpoint { endpoint } => {
                write!(f, "endpoint {endpoint:?} is not <proto>/<address>")
            }
            ConfigDefect::UnknownProtocol { endpoint, protocol } => write!(
                f,
                "endpoint {endpoint:?} uses protocol {protocol:?}, which stock zenoh does not carry"
            ),
            // The feature comes from `LINK_SCHEME_FEATURES` rather than from
            // the scheme name: the mapping is not the identity, and the one
            // place it differs (`unixsock-stream` -> `transport-link-unixsock`)
            // is the scheme an operator is least likely to know by heart. A
            // scheme with no entry is possible only if wz cannot serve it at
            // all, and then the honest ending is silence, not a guess.
            ConfigDefect::ProtocolNotCompiledIn { endpoint, protocol } => {
                write!(
                    f,
                    "endpoint {endpoint:?} uses protocol {protocol:?}, which stock zenoh \
                     carries but this build has no link backend for"
                )?;
                match link_scheme_feature(protocol) {
                    Some(feature) => write!(f, " (compile it in with the {feature} feature)"),
                    None => Ok(()),
                }
            }
            ConfigDefect::DuplicateListenEndpoint { endpoint } => {
                write!(f, "listen endpoint {endpoint:?} appears more than once")
            }
            ConfigDefect::Unreachable => write!(
                f,
                "nothing to connect to, nothing listening, and multicast scouting off"
            ),
            ConfigDefect::QosWithLowlatency => write!(
                f,
                "qos and lowlatency are mutually exclusive (zenoh DEFAULT_CONFIG.json5)"
            ),
            ConfigDefect::ZeroBatchSize => write!(f, "batch_size is 0"),
            ConfigDefect::ZeroLease => write!(f, "lease is 0"),
            ConfigDefect::ZeroMaxLinks => write!(f, "max_links is 0"),
        }
    }
}

/// A reason a set of nodes cannot form the network their configs describe —
/// a question no single config can be asked.
///
/// R2070b (open-debt item 486) — [`ZenohNodeConfig::validate`] judges ONE
/// node, and its doc said "this topology", which is a promise one receiver
/// cannot keep: the body reads `self` and has no channel through which
/// another node could be seen. Every defect below ends the same way — the
/// nodes start cleanly and nothing attaches — which is the failure
/// [`ConfigDefect::Unreachable`] calls the most expensive to diagnose, one
/// level up where nobody was looking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopologyDefect {
    /// A node dials an endpoint that no node in the set listens on.
    DanglingConnectTarget {
        /// Which node dials it — its `id` when the config states one, else
        /// its position in the slice.
        node: String,
        /// The connect endpoint as given.
        endpoint: String,
    },
    /// Two or more nodes claim the same concrete listen address. At most one
    /// of them can bind it.
    ListenEndpointCollision {
        /// The endpoint they share, as the first of them spells it.
        endpoint: String,
        /// Every node claiming it, in slice order.
        nodes: Vec<String>,
    },
    /// Every node is a `client`. A zenoh client dials and never listens
    /// (upstream `orchestrator.rs`'s `start_client` reads `connect` and
    /// scouting only, and binds no listener), so a set of them has nothing
    /// to attach to.
    NoNodeAccepts,
}

impl core::fmt::Display for TopologyDefect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TopologyDefect::DanglingConnectTarget { node, endpoint } => write!(
                f,
                "{node} connects to {endpoint:?}, which no node here listens on"
            ),
            TopologyDefect::ListenEndpointCollision { endpoint, nodes } => write!(
                f,
                "listen endpoint {endpoint:?} is claimed by {}",
                nodes.join(", ")
            ),
            TopologyDefect::NoNodeAccepts => write!(
                f,
                "every node is a client, and a zenoh client never listens"
            ),
        }
    }
}

/// What an endpoint says about WHERE it is, reduced to the part two endpoints
/// can be compared on.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EndpointHost {
    /// A wildcard bind (`0.0.0.0`, `[::]`) — it answers on every interface,
    /// so it can serve a dial addressed to any host.
    Any,
    /// A literal address. Two different literals are two different hosts.
    Ip(std::net::IpAddr),
    /// A DNS name, unresolved on purpose (resolution is the dial layer's job
    /// and would make this verdict depend on the network it is judging).
    Name(String),
}

/// An endpoint reduced to what a topology question needs, or `None` when the
/// string does not parse — which [`ZenohNodeConfig::validate`] already reports
/// per node and this pass must not report a second time.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EndpointFace {
    /// An IP-family endpoint: the two things that must agree for a dial to
    /// land, plus the host that may or may not pin one machine.
    Ip {
        /// The scheme, compared as the parsed value rather than as text.
        proto: Proto,
        /// The host, to whatever precision the string states it.
        host: EndpointHost,
        /// The port.
        port: u16,
    },
    /// A serial / unixsock / unixpipe / vsock endpoint, whose address IS its
    /// whole string. Compared verbatim, because none of them has a host part
    /// this pass could reason about.
    NonIp(String),
}

impl EndpointFace {
    fn of(endpoint: &str) -> Option<EndpointFace> {
        match parse_any_locator(endpoint).ok()? {
            AnyLocator::Ip(ip) => Some(EndpointFace::Ip {
                proto: ip.proto,
                host: if ip.addr.ip().is_unspecified() {
                    EndpointHost::Any
                } else {
                    EndpointHost::Ip(ip.addr.ip())
                },
                port: ip.addr.port(),
            }),
            AnyLocator::Named {
                proto, host, port, ..
            } => Some(EndpointFace::Ip {
                proto,
                host: EndpointHost::Name(host),
                port,
            }),
            _ => Some(EndpointFace::NonIp(String::from(endpoint))),
        }
    }

    /// Whether a dial to `self` could be answered by a node listening on
    /// `listener`.
    ///
    /// Deliberately ASYMMETRIC and deliberately generous: a pair this cannot
    /// rule out is treated as a match, because the defect it feeds is a
    /// negative ("nobody listens on it") and a false positive there would tell
    /// an operator their working deployment is broken. A name and a literal
    /// are therefore compatible — the name might resolve to it, and only the
    /// network knows.
    fn could_be_answered_by(&self, listener: &EndpointFace) -> bool {
        match (self, listener) {
            (
                EndpointFace::Ip {
                    proto: dp,
                    host: dh,
                    port: dport,
                },
                EndpointFace::Ip {
                    proto: lp,
                    host: lh,
                    port: lport,
                },
            ) => {
                if dp != lp || dport != lport {
                    return false;
                }
                match (dh, lh) {
                    // A wildcard listen answers whatever addressed it.
                    (_, EndpointHost::Any) | (EndpointHost::Any, _) => true,
                    // Two literals, or two names, are comparable and decide it.
                    (EndpointHost::Ip(a), EndpointHost::Ip(b)) => a == b,
                    (EndpointHost::Name(a), EndpointHost::Name(b)) => a == b,
                    // A name against a literal: unresolvable here, so allowed.
                    _ => true,
                }
            }
            (EndpointFace::NonIp(a), EndpointFace::NonIp(b)) => a == b,
            _ => false,
        }
    }

    /// Whether this listen endpoint pins ONE machine, and so whether a second
    /// node claiming the same string is necessarily a collision.
    ///
    /// A wildcard does not: two nodes on two machines both bind `0.0.0.0`
    /// legitimately, every day. Nor does loopback: `127.0.0.1:7447` on two
    /// machines is two separate, working (if unreachable) binds. Nor does a
    /// path-shaped scheme, since two machines each have their own `/tmp`.
    /// What is left — a routable literal, or a name, which resolves to one
    /// host — is a claim only one node can win.
    fn pins_one_machine(&self) -> bool {
        match self {
            EndpointFace::Ip { host, .. } => match host {
                EndpointHost::Any => false,
                EndpointHost::Ip(addr) => !addr.is_loopback(),
                EndpointHost::Name(_) => true,
            },
            EndpointFace::NonIp(_) => false,
        }
    }
}

/// Every reason this SET of nodes cannot form the network its configs
/// describe, in a stable order.
///
/// R2070b (open-debt item 486) — the sibling of
/// [`ZenohNodeConfig::validate_for_build`], not an extension of it. The
/// defects here cannot be asked of one config, so folding them into the
/// per-node verdict would hand a single-node caller a false positive on every
/// one of them; and each is a question about the SET, which is why the set is
/// the receiver.
///
/// The slice is read as a CLOSED deployment: "no node listens on it" means no
/// node *here*. A set that is a fragment of a larger network — a node dialing
/// an external zenohd, say — will collect
/// [`TopologyDefect::DanglingConnectTarget`] for the endpoints it reaches
/// outward on, and that is the correct answer to the question this function
/// asks rather than a defect in it. Nothing is inferred about the network:
/// no name is resolved and no address is probed, so the verdict is a property
/// of the configs and reproduces without a network to run on.
///
/// A malformed or unknown-protocol endpoint is NOT reported here.
/// [`ZenohNodeConfig::validate`] already names it per node, and saying it
/// twice would make one typo look like two faults.
pub fn validate_topology(nodes: &[ZenohNodeConfig]) -> Vec<TopologyDefect> {
    // The node's name is built ONCE, here, so every defect below spells the
    // same node the same way. Two call sites deriving it independently is two
    // places for the identity to drift from the row it labels.
    let named: Vec<(String, &ZenohNodeConfig)> = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let name = match &node.id {
                Some(id) => id.clone(),
                None => format!("node[{i}]"),
            };
            (name, node)
        })
        .collect();

    let listeners: Vec<EndpointFace> = named
        .iter()
        .flat_map(|(_, node)| node.listen.iter())
        .filter_map(|endpoint| EndpointFace::of(endpoint))
        .collect();

    let mut out = Vec::new();

    for (name, node) in &named {
        for endpoint in &node.connect {
            let Some(face) = EndpointFace::of(endpoint) else {
                continue;
            };
            if !listeners.iter().any(|l| face.could_be_answered_by(l)) {
                out.push(TopologyDefect::DanglingConnectTarget {
                    node: name.clone(),
                    endpoint: endpoint.clone(),
                });
            }
        }
    }

    // A collision is reported ONCE, against the endpoint's first speller, with
    // every claimant listed — one finding about one address, rather than one
    // per node, which would turn a two-node clash into two separate reports of
    // the same fact.
    //
    // Claimants are counted by SLICE POSITION and not by name. A node that
    // lists the same endpoint twice is `ConfigDefect::DuplicateListenEndpoint`
    // and belongs to the per-node pass; deduplicating by name instead would
    // ALSO swallow the real collision between two nodes that share an `id`,
    // which is a worse trade than the one it saves.
    let mut seen: Vec<(EndpointFace, String, Vec<usize>)> = Vec::new();
    for (index, (_, node)) in named.iter().enumerate() {
        for endpoint in &node.listen {
            let Some(face) = EndpointFace::of(endpoint) else {
                continue;
            };
            if !face.pins_one_machine() {
                continue;
            }
            match seen.iter_mut().find(|(f, _, _)| *f == face) {
                Some((_, _, claimants)) => {
                    if !claimants.contains(&index) {
                        claimants.push(index);
                    }
                }
                None => seen.push((face, endpoint.clone(), vec![index])),
            }
        }
    }
    for (_, endpoint, claimants) in seen {
        if claimants.len() > 1 {
            out.push(TopologyDefect::ListenEndpointCollision {
                endpoint,
                nodes: claimants.iter().map(|i| named[*i].0.clone()).collect(),
            });
        }
    }

    // Upstream `start_client` (`zenoh/src/net/runtime/orchestrator.rs`) reads
    // `connect` and the scouting block and binds no listener, so a set with no
    // router and no peer has nobody to attach to. An EMPTY set is not this
    // defect: it describes no deployment, and answering it would be answering
    // a question nobody asked.
    if !named.is_empty() && named.iter().all(|(_, node)| node.mode == WhatAmI::Client) {
        out.push(TopologyDefect::NoNodeAccepts);
    }

    out
}

/// Admin-space exposure of the emitted node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminspaceConfig {
    /// `adminspace/permissions/read`.
    pub read: bool,
    /// `adminspace/permissions/write`.
    pub write: bool,
}

/// The topology-and-transport subset of a stock zenoh node's config.
///
/// Every field maps to exactly one zenoh config key (named in its doc), so a
/// reader can move between this struct and `DEFAULT_CONFIG.json5` without a
/// translation table — the same rule the `dissect` field names follow.
///
/// R311y849 dropped `Eq` from the derive and kept `PartialEq`. `connect/retry`
/// carries upstream's `period_increase_factor`, which is an `f64`
/// (`connection_retry.rs:36`), and `Eq` is a promise of reflexivity that no
/// float type can make. [`RetryPolicy`](crate::retry_period::RetryPolicy) is
/// `PartialEq`-only for exactly this reason, so the bound was going to be lost
/// at whichever key first carried a real number. Nothing keyed a map or a set on
/// this struct (checked, not assumed), so the removal costs no caller anything —
/// and the honest alternative, an `Eq` impl written by hand over a field that
/// can be NaN, is a lie the compiler would then trust.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ZenohNodeConfig {
    /// `mode`.
    pub mode: WhatAmI,
    /// `listen/endpoints`.
    pub listen: Vec<String>,
    /// `connect/endpoints`.
    pub connect: Vec<String>,
    /// `scouting/multicast/enabled`.
    pub multicast_scouting: bool,
    /// R2063 (open-debt item 214) — `routing/peer/mode`.
    ///
    /// `true` is upstream's `linkstate`, the default; `false` is
    /// `peer-to-peer`. A `bool` and not a two-variant enum because that is the
    /// shape the sink already has — `wz-ap-demo`'s `--peer-mode` parses to
    /// `full_linkstate: bool` — and a third spelling here would be a type the
    /// reader converts and nothing else consumes.
    ///
    /// ⚠ WHAT THIS HONOURS, precisely: it switches the DISCOVERY plane
    /// (link-state ingest and re-flood) so a wz peer can learn and
    /// gossip-autoconnect inside a default-configured zenoh subsystem. The
    /// demo's own `--peer-mode` doc is explicit that the DATA plane in
    /// `peer-to-peer` is not claimed, and reading the key does not widen that.
    pub peer_linkstate: bool,
    /// `transport/link/tx/batch_size`.
    pub batch_size: u16,
    /// `transport/link/tx/lease` (milliseconds).
    pub lease_ms: u64,
    /// `transport/unicast/max_links`.
    pub max_links: usize,
    /// `transport/unicast/qos/enabled`.
    pub qos: bool,
    /// `transport/unicast/lowlatency`.
    pub lowlatency: bool,
    /// `transport/unicast/compression/enabled`.
    pub compression: bool,
    /// `timestamping/enabled`.
    pub timestamping: bool,
    /// `adminspace` — `None` leaves the block out entirely, which is not the
    /// same as emitting `enabled: false`: an omitted key takes zenoh's
    /// default, and saying so explicitly is a decision the caller should have
    /// to make rather than inherit.
    pub adminspace: Option<AdminspaceConfig>,
    /// R311y844 — the ten below are keys wz ALREADY acts on, which the reader
    /// could not be told until this round. `Option` where a real zenohd
    /// resolves the key to `null` when unset (measured by execution, not read
    /// off a document): a `None` here is "the file gave no instruction", which
    /// is a different fact from any value this struct could invent, and
    /// [`ZenohNodeConfig::to_json5`] leaves those keys out rather than
    /// asserting a default zenoh did not state.
    ///
    /// `id` — the zid, hex. wz's `--zid`.
    pub id: Option<String>,
    /// `namespace` — the keyexpr prefix. wz's `--namespace`.
    pub namespace: Option<String>,
    /// `queries_default_timeout`, milliseconds. wz's `--query-timeout-ms`.
    pub queries_default_timeout_ms: Option<u64>,
    /// `routing/interests/timeout`, milliseconds. wz's `--interest-timeout`,
    /// which names this key in its own parse site.
    pub interests_timeout_ms: Option<u64>,
    /// `scouting/timeout`, milliseconds. wz's `--scout-timeout-ms`.
    pub scouting_timeout_ms: Option<u64>,
    /// `transport/multicast/qos/enabled`. wz's `--multicast-qos`. A real
    /// zenohd resolves this to `false`, so the default below is zenoh's.
    pub multicast_qos: bool,
    /// `transport/shared_memory/enabled`. wz's `--shm`.
    ///
    /// A real zenohd resolves this to **`true`** — measured — while the demo's
    /// `--shm` is opt-in, so the two implementations disagree on the DEFAULT.
    /// The field carries zenoh's, because that is what an absent key means to
    /// the operator's file; the expansion still acts only on a value the
    /// document NAMED, so an unmentioned key changes no invocation.
    pub shared_memory: bool,
    /// `transport/link/tls/root_ca_certificate`. wz's `--tls-ca`.
    pub tls_root_ca: Option<String>,
    /// `transport/link/tls/listen_certificate`. wz's `--tls-cert`.
    pub tls_listen_certificate: Option<String>,
    /// `transport/link/tls/listen_private_key`. wz's `--tls-key`.
    pub tls_listen_private_key: Option<String>,
    /// R311y845 — the three below say WHERE a node listens for its peers, and
    /// until this round wz's answer was a constant. `wz-ap-demo`'s `SCOUT_GROUP`
    /// was `224.0.0.224` compiled in, with a doc that named this very key as
    /// the upstream override and reasoned "not a CLI knob: zenoh exposes the
    /// override in its config, not its scouting API" — which was right about
    /// where the knob belongs and left the config unable to reach it.
    ///
    /// This is the sharpest shape of the R311y844 class rather than another
    /// instance of it: the socket layer has taken the group, the interface and
    /// the TTL as PARAMETERS since R311y454
    /// ([`McastSocketConfig`](crate::McastSocketConfig)), so wz could always
    /// have joined another group. A node that cannot be told where to look
    /// discovers nothing on a network that moved its group — and discovery is
    /// the first thing that has to work for a drop-in.
    ///
    /// `scouting/multicast/address` — the scouting socket, `<ip>:<port>`.
    /// A `SocketAddr` upstream, not a locator string (measured off
    /// `ScoutingMulticastConf::address`, `zenoh-config/src/lib.rs:500`), so
    /// `udp/224.0.0.224:7446` is NOT what this key carries.
    pub scout_multicast_address: Option<String>,
    /// `scouting/multicast/interface` — which interface's membership is
    /// installed and which one the beacon leaves by. `"auto"` is upstream's
    /// spelling of "pick one", and is carried through as given rather than
    /// resolved here: the socket layer already reads `None` as auto.
    pub scout_multicast_interface: Option<String>,
    /// `scouting/multicast/ttl` — the multicast hop limit. Upstream's default
    /// is `1` (one subnet); `None` leaves the OS default, which is also 1.
    pub scout_multicast_ttl: Option<u32>,
    /// R311y846 — `scouting/multicast/listen`: whether this node ANSWERS a
    /// Scout, upstream's "listen for scout messages on UDP multicast and reply
    /// to them" (`DEFAULT_CONFIG.json5:163`).
    ///
    /// The direction the three keys above do not cover. They say WHERE the node
    /// looks; this says whether anyone can find IT — and until R311y846 wz had
    /// no behaviour to attach it to at all, which is why it sat in
    /// `UNHONOURED_UPSTREAM_CONFIG_KEYS` while its siblings moved out.
    ///
    /// `Option<bool>` and NOT a plain `bool` defaulting to upstream's `true`,
    /// for the reason the three above are Options: a running zenohd resolves
    /// this key to `null`, so defaulting it here would make an unmentioned key
    /// indistinguishable from a stated one at the expansion boundary.
    pub scout_multicast_listen: Option<bool>,
    /// R311y849 — `connect/retry`: how long a refused dial waits before the next
    /// attempt, and how that wait grows
    /// (`period_init_ms` / `period_max_ms` / `period_increase_factor`).
    ///
    /// The R311y844 class again — wz has run this schedule since R311y786, with
    /// zenoh's own defaults, and the file could not state it. What makes this one
    /// worth a round rather than a line is that the divergence is SILENT and
    /// operational: an operator whose router boots slowly widens the ceiling in
    /// their config, drops wz in, and gets 1s/2s/4s with nothing logged to
    /// contradict them. Discovery has to work for a drop-in; so does the pacing
    /// of a reconnect, because that is what a deployment does after every
    /// restart.
    ///
    /// One `Option` for the whole subtree rather than three, because that is how
    /// upstream resolves it: a running zenohd renders `connect` as
    /// `{"endpoints":[],"exit_on_failure":null,"retry":null,"timeout_ms":null}`
    /// (measured), so `retry` is a single opaque leaf and `None` here is exactly
    /// its `null`. Reading it as three keys would invent a surface the census
    /// denominator does not have.
    ///
    /// [`RetryPolicy`](crate::retry_period::RetryPolicy) rather than a local
    /// triple: it is the type the consumer already takes, and the round that
    /// added it made the point that one transcription of the arithmetic is what
    /// keeps the two re-dial substrates from drifting. A second shape here would
    /// be a third.
    pub connect_retry: Option<crate::retry_period::RetryPolicy>,
}

impl Default for ZenohNodeConfig {
    /// zenoh's own defaults for the subset this struct covers, so a caller
    /// that overrides one field is not silently redefining the other ten.
    fn default() -> Self {
        Self {
            mode: WhatAmI::Peer,
            listen: Vec::new(),
            connect: Vec::new(),
            multicast_scouting: true,
            // R2063 (item 214) — upstream's default is `linkstate`
            // (`DEFAULT_CONFIG.json5`'s `routing.peer.mode`), and R2051's rule
            // applies: a documented default is not a behaviour, so this
            // matches what the SINK already defaults to -- `--peer-mode`
            // absent is `full_linkstate = true` (`wz-ap-demo/src/main.rs:290`).
            peer_linkstate: true,
            batch_size: 65_535,
            lease_ms: 10_000,
            max_links: 1,
            qos: true,
            lowlatency: false,
            compression: false,
            timestamping: false,
            adminspace: None,
            // R311y844 — every one of these is zenoh's own resolved value for
            // an unset key, taken from a running zenohd rather than from
            // `DEFAULT_CONFIG.json5`: five resolve to `null` (no instruction),
            // multicast qos to `false`, and shared memory to `true`.
            id: None,
            namespace: None,
            queries_default_timeout_ms: None,
            interests_timeout_ms: None,
            scouting_timeout_ms: None,
            multicast_qos: false,
            shared_memory: true,
            tls_root_ca: None,
            tls_listen_certificate: None,
            tls_listen_private_key: None,
            // R311y845 — all three resolve to `null` on a running zenohd (no
            // instruction), NOT to the values `DEFAULT_CONFIG.json5` documents
            // in its comments. Defaulting them to `224.0.0.224:7446` / `auto` /
            // `1` here would make an unmentioned key look like a stated one at
            // the expansion boundary, which is the distinction `named` exists
            // to keep.
            scout_multicast_address: None,
            scout_multicast_interface: None,
            scout_multicast_ttl: None,
            scout_multicast_listen: None,
            // R311y849 — `None` and NOT `RetryPolicy::ZENOH_DEFAULT`, even though
            // that is the schedule an unset key produces. The two are the same
            // BEHAVIOUR and different FACTS: `None` is "the file said nothing",
            // which `to_json5` must leave out and the argv expansion must not
            // spell. Seeding the default here would emit a `connect.retry` block
            // zenoh never resolved and hand the demo a flag the operator never
            // typed -- the exact asymmetry the five R311y844 Options exist for.
            connect_retry: None,
        }
    }
}

impl ZenohNodeConfig {
    /// Carry wz's own negotiated transport parameters onto a stock zenoh node.
    ///
    /// This is the whole point of the type: a zenohd stood up next to a wz
    /// deployment should not be configured by hand to a batch size and lease
    /// that wz already knows. Only the parameters wz genuinely holds are
    /// taken — topology (endpoints, scouting) is not in `WzConfig` and stays
    /// the caller's to set.
    pub fn from_wz(cfg: &crate::config::WzConfig) -> Self {
        let mut out = Self {
            mode: cfg.whatami,
            batch_size: cfg.batch_size,
            lease_ms: cfg.lease_ms,
            ..Self::default()
        };
        #[cfg(feature = "transport-multilink")]
        {
            out.max_links = cfg.max_links;
        }
        #[cfg(feature = "transport-qos")]
        {
            out.qos = cfg.qos;
        }
        // A `WzConfig` built by `from_init_params` mirrors handshake-fixed
        // values; a default-constructed one carries the `0` sentinels. Emitting
        // a 0 would produce a config zenoh accepts and cannot run, so the
        // sentinel falls back to zenoh's default and `validate` still reports
        // a genuine 0 the caller set on purpose.
        if out.batch_size == 0 {
            out.batch_size = Self::default().batch_size;
        }
        if out.lease_ms == 0 {
            out.lease_ms = Self::default().lease_ms;
        }
        out
    }

    /// Add a listen endpoint (`listen/endpoints`).
    pub fn listening_on(mut self, endpoint: impl Into<String>) -> Self {
        self.listen.push(endpoint.into());
        self
    }

    /// Add a connect endpoint (`connect/endpoints`).
    pub fn connecting_to(mut self, endpoint: impl Into<String>) -> Self {
        self.connect.push(endpoint.into());
        self
    }

    /// Set `scouting/multicast/enabled`.
    pub fn with_multicast_scouting(mut self, on: bool) -> Self {
        self.multicast_scouting = on;
        self
    }

    /// Set the `adminspace` block.
    pub fn with_adminspace(mut self, read: bool, write: bool) -> Self {
        self.adminspace = Some(AdminspaceConfig { read, write });
        self
    }

    /// Every reason THIS NODE cannot work, in a stable order. An empty result
    /// means the config is coherent — NOT that the node will find a peer,
    /// which is a question about the network rather than the config.
    ///
    /// R2070b (open-debt item 486) — this doc said "this topology" for many
    /// rounds, and one receiver cannot answer that: the body below reads
    /// `self` and has no channel through which a second node could be seen.
    /// The set-level questions live in [`validate_topology`], which takes the
    /// slice; they are deliberately NOT folded in here, because a caller
    /// holding one config would then be told its perfectly good node is
    /// broken.
    ///
    /// This is the verdict for a STOCK zenohd: the reader is assumed to carry
    /// every scheme zenoh does. To judge the same file for the wz binary
    /// holding it, use [`ZenohNodeConfig::validate_for_build`].
    pub fn validate(&self) -> Vec<ConfigDefect> {
        self.validate_for_build(None)
    }

    /// [`ZenohNodeConfig::validate`], plus the one verdict that depends on who
    /// is reading: `compiled_in_schemes`, when supplied, is the set of link
    /// schemes the READER can actually bind and dial, and an endpoint outside
    /// it collects [`ConfigDefect::ProtocolNotCompiledIn`].
    ///
    /// R2070 (open-debt item 487) — the argument is an `Option` rather than a
    /// narrowed constant because the two directions of this module genuinely
    /// disagree. Emitting a config FOR a stock zenohd must accept all nine
    /// schemes; starting a wz node FROM one must accept only what that node
    /// was built with. Folding the second into the first would make the emit
    /// path reject correct files, so the caller says which question it is
    /// asking. `wz-runtime-tokio`'s answer for its own binary is
    /// `crate::compiled_in_link_schemes()`.
    ///
    /// A scheme zenoh does not carry AT ALL stays a single
    /// [`ConfigDefect::UnknownProtocol`]: it is already refused, and saying it
    /// twice would turn one typo into two lines of a start-up refusal.
    pub fn validate_for_build(&self, compiled_in_schemes: Option<&[&str]>) -> Vec<ConfigDefect> {
        let mut out = Vec::new();
        for endpoint in self.listen.iter().chain(self.connect.iter()) {
            match endpoint.split_once('/') {
                None => out.push(ConfigDefect::MalformedEndpoint {
                    endpoint: endpoint.clone(),
                }),
                Some((proto, _)) => {
                    if !ZENOH_LINK_PROTOCOLS.contains(&proto) {
                        out.push(ConfigDefect::UnknownProtocol {
                            endpoint: endpoint.clone(),
                            protocol: String::from(proto),
                        });
                    } else if compiled_in_schemes.is_some_and(|s| !s.contains(&proto)) {
                        out.push(ConfigDefect::ProtocolNotCompiledIn {
                            endpoint: endpoint.clone(),
                            protocol: String::from(proto),
                        });
                    }
                }
            }
        }
        for (i, endpoint) in self.listen.iter().enumerate() {
            if self.listen[..i].contains(endpoint) {
                out.push(ConfigDefect::DuplicateListenEndpoint {
                    endpoint: endpoint.clone(),
                });
            }
        }
        if self.connect.is_empty() && self.listen.is_empty() && !self.multicast_scouting {
            out.push(ConfigDefect::Unreachable);
        }
        if self.qos && self.lowlatency {
            out.push(ConfigDefect::QosWithLowlatency);
        }
        if self.batch_size == 0 {
            out.push(ConfigDefect::ZeroBatchSize);
        }
        if self.lease_ms == 0 {
            out.push(ConfigDefect::ZeroLease);
        }
        if self.max_links == 0 {
            out.push(ConfigDefect::ZeroMaxLinks);
        }
        out
    }

    /// Render the config zenoh's `-c` flag reads.
    ///
    /// If the result is written to a file for `zenohd -c`, that file MUST have
    /// a `.json5`, `.json` or `.yaml` extension: zenoh dispatches its parser on
    /// the extension and panics outright on a file without one
    /// (`commons/zenoh-config/src/lib.rs:1286`). This is stated here because
    /// the failure happens before any byte of the config is read, so nothing
    /// about the emitted content can hint at it.
    ///
    /// Emitted as strict JSON, which is a subset of JSON5 — zenoh's parser
    /// takes both, and a JSON5-only flourish (unquoted keys, trailing commas)
    /// would buy nothing and cost the ability to check the output with a JSON
    /// parser. Keys are emitted in the order they appear in
    /// `DEFAULT_CONFIG.json5`, so a diff against the reference reads top to
    /// bottom.
    pub fn to_json5(&self) -> String {
        let mut out = String::from("{\n");
        out.push_str("  \"mode\": ");
        escape_into(self.mode.to_str(), &mut out);
        out.push_str(",\n  \"connect\": { \"endpoints\": ");
        push_endpoints(&self.connect, &mut out);
        // R311y849 — `connect.retry`, inside the block already open, and written
        // in FULL when it is written at all. The ingest side merges a partial
        // block against zenoh's defaults, so by the time a policy exists here all
        // three numbers are decided; emitting only the stated ones would hand the
        // reader a document whose meaning depends on which fields the ORIGINAL
        // file happened to name.
        if let Some(retry) = self.connect_retry {
            let _ = write!(
                out,
                ", \"retry\": {{ \"period_init_ms\": {}, \"period_max_ms\": {}, \
                 \"period_increase_factor\": {} }}",
                retry.period_init_ms, retry.period_max_ms, retry.period_increase_factor
            );
        }
        out.push_str(" },\n  \"listen\": { \"endpoints\": ");
        push_endpoints(&self.listen, &mut out);
        out.push_str(" }");
        // R311y844 — the top-level scalars wz now carries, each emitted only
        // when the config HOLDS one. A real zenohd resolves every one of them
        // to `null` when unset (measured off a running node, not read off
        // `DEFAULT_CONFIG.json5`), so writing a value where the caller has none
        // would be wz asserting a default zenoh does not have.
        if let Some(id) = &self.id {
            out.push_str(",\n  \"id\": ");
            escape_into(id, &mut out);
        }
        if let Some(ns) = &self.namespace {
            out.push_str(",\n  \"namespace\": ");
            escape_into(ns, &mut out);
        }
        if let Some(ms) = self.queries_default_timeout_ms {
            let _ = write!(out, ",\n  \"queries_default_timeout\": {ms}");
        }
        if let Some(ms) = self.interests_timeout_ms {
            let _ = write!(
                out,
                ",\n  \"routing\": {{ \"interests\": {{ \"timeout\": {ms} }} }}"
            );
        }
        // `scouting` carries FIVE honoured keys now (R311y845 added the three
        // `multicast` socket keys), so they share one object: a second
        // top-level `"scouting"` would be a duplicate key, and zenoh's serde
        // takes the last one and drops the first. The same rule applies one
        // level down — `multicast` is opened ONCE and every one of its keys
        // written inside it.
        out.push_str(",\n  \"scouting\": { \"multicast\": { \"enabled\": ");
        let _ = write!(out, "{}", self.multicast_scouting);
        if let Some(addr) = &self.scout_multicast_address {
            out.push_str(", \"address\": ");
            escape_into(addr, &mut out);
        }
        if let Some(iface) = &self.scout_multicast_interface {
            out.push_str(", \"interface\": ");
            escape_into(iface, &mut out);
        }
        if let Some(ttl) = self.scout_multicast_ttl {
            let _ = write!(out, ", \"ttl\": {ttl}");
        }
        if let Some(listen) = self.scout_multicast_listen {
            let _ = write!(out, ", \"listen\": {listen}");
        }
        out.push_str(" }");
        if let Some(ms) = self.scouting_timeout_ms {
            let _ = write!(out, ", \"timeout\": {ms}");
        }
        out.push_str(" },\n  \"timestamping\": { \"enabled\": ");
        let _ = write!(out, "{}", self.timestamping);
        out.push_str(" },\n  \"transport\": {\n    \"unicast\": {\n");
        let _ = writeln!(out, "      \"max_links\": {},", self.max_links);
        let _ = writeln!(out, "      \"lowlatency\": {},", self.lowlatency);
        let _ = writeln!(out, "      \"qos\": {{ \"enabled\": {} }},", self.qos);
        let _ = writeln!(
            out,
            "      \"compression\": {{ \"enabled\": {} }}",
            self.compression
        );
        // R311y844 — `multicast` and `shared_memory` are siblings of `unicast`
        // INSIDE `transport`, not second top-level `"transport"` objects: a
        // duplicate key is not a merge, and zenoh's serde takes the last one
        // and silently drops everything the first carried.
        let _ = writeln!(
            out,
            "    }},\n    \"multicast\": {{ \"qos\": {{ \"enabled\": {} }} }},",
            self.multicast_qos
        );
        let _ = writeln!(
            out,
            "    \"shared_memory\": {{ \"enabled\": {} }},",
            self.shared_memory
        );
        out.push_str("    \"link\": {\n      \"tx\": {\n");
        let _ = writeln!(out, "        \"batch_size\": {},", self.batch_size);
        let _ = writeln!(out, "        \"lease\": {}", self.lease_ms);
        out.push_str("      }");
        // The TLS block, likewise inside `link` and likewise only for the paths
        // the caller holds: an empty string here is a filename nothing opens,
        // and a `null` is what zenoh itself resolves an unset one to.
        let tls: Vec<(&str, &String)> = [
            ("root_ca_certificate", self.tls_root_ca.as_ref()),
            ("listen_certificate", self.tls_listen_certificate.as_ref()),
            ("listen_private_key", self.tls_listen_private_key.as_ref()),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect();
        if !tls.is_empty() {
            out.push_str(",\n      \"tls\": {");
            for (i, (key, value)) in tls.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let _ = write!(out, "\n        \"{key}\": ");
                escape_into(value, &mut out);
            }
            out.push_str("\n      }");
        }
        out.push_str("\n    }\n  }");
        if let Some(admin) = self.adminspace {
            out.push_str(",\n  \"adminspace\": { \"enabled\": true, \"permissions\": ");
            let _ = write!(
                out,
                "{{ \"read\": {}, \"write\": {} }} }}",
                admin.read, admin.write
            );
        }
        out.push_str("\n}\n");
        out
    }
}

/// Every upstream config leaf path [`ZenohNodeConfig::from_json5`] HONOURS,
/// in the order `to_json5` emits them.
///
/// This is the SSOT for both directions and for the coverage census: the
/// reader reads exactly these, the emitter writes exactly these, and
/// [`ZenohConfigIngest::ignored`] is "every leaf the document carried that is
/// not in here". A path added to the reader without being added here would
/// report itself ignored while being applied — which is why
/// `every_honoured_key_is_actually_read` drives each entry to a non-default
/// value and requires the ingest to move.
pub const HONOURED_CONFIG_KEYS: &[&str] = &[
    "mode",
    "connect/endpoints",
    "listen/endpoints",
    "scouting/multicast/enabled",
    "timestamping/enabled",
    "transport/unicast/max_links",
    "transport/unicast/lowlatency",
    "transport/unicast/qos/enabled",
    "transport/unicast/compression/enabled",
    "transport/link/tx/batch_size",
    "transport/link/tx/lease",
    "adminspace/enabled",
    "adminspace/permissions/read",
    "adminspace/permissions/write",
    // R311y844 — ten keys wz ALREADY acts on, which the reader could not be
    // told. Each was in `UNHONOURED_UPSTREAM_CONFIG_KEYS` under a list whose
    // doc says "wz models the topology-and-transport subset it can act on" —
    // and that list conflated two different sentences: "wz cannot do this" and
    // "the reader does not read this". Every key below is the second: the demo
    // has carried a flag for it for rounds, so an operator could get the
    // behaviour by hand and not from the file they already have.
    "id",
    "namespace",
    "queries_default_timeout",
    "routing/interests/timeout",
    "scouting/timeout",
    "transport/multicast/qos/enabled",
    "transport/shared_memory/enabled",
    "transport/link/tls/root_ca_certificate",
    "transport/link/tls/listen_certificate",
    "transport/link/tls/listen_private_key",
    // R311y845 — WHERE the node looks for its peers. These three MOVED from
    // `UNHONOURED_UPSTREAM_CONFIG_KEYS`, so the surface total below is
    // unchanged: they are resolved leaves of a real zenohd either way, and all
    // that changed is which half of the partition they sit in.
    "scouting/multicast/address",
    "scouting/multicast/interface",
    "scouting/multicast/ttl",
    // R311y846 — the fourth, and the one that took a BEHAVIOUR to move rather
    // than only a reader. The three above were the y844 class (wz could already
    // do it and the reader could not be told); this one wz genuinely could not
    // do, because no wz mode ever answered a Scout. It moves here now that
    // `scouting_responder` exists. Surface total below unchanged: it is a
    // resolved leaf of a real zenohd either way.
    "scouting/multicast/listen",
    // R311y849 — the PACING of a reconnect, where the four above are its
    // addressing. Back in the y844 class: wz has run this schedule since
    // R311y786 and the file could not state it. What the round had to fix first
    // is that the CLI could not state it either for the mode that dials -- the
    // `--peer` arm took `--connect-retry`, dropped it, and dropped its
    // validation with it, so a key routed there before this round would have
    // been honoured on paper and inert in fact.
    "connect/retry",
    // R2063 (open-debt item 214) — MOVED from
    // `UNHONOURED_UPSTREAM_CONFIG_KEYS`, and the reason is the item's own:
    // that list carries two unrelated things under one name, and this key was
    // the second kind -- not "wz cannot act on it" but "the reader had not
    // learned it". The demo's `--peer-mode` has switched the discovery plane
    // for rounds and its `--help` CITES this key by name (`usage.rs:128`), so
    // an operator reading that line and putting it in their file got nothing.
    "routing/peer/mode",
];

/// R311y849 — the leaves that live INSIDE a honoured key which is a subtree
/// rather than a scalar.
///
/// Deliberately NOT part of [`HONOURED_CONFIG_KEYS`], which is one half of the
/// CENSUS partition and must carry exactly the leaves a real zenohd resolves. A
/// zenohd whose file never mentions `connect.retry` renders it as a single
/// `null` (measured), so the surface has one leaf there and adding three would
/// inflate the denominator with keys upstream does not show.
///
/// What this list is for is the `ignored` report, which walks the OPERATOR's
/// document rather than the upstream surface — and an operator who writes the
/// block writes its three fields. Without this they would each be reported as
/// "wz did not apply this" while wz had just applied them.
///
/// It is an exact-match list and not a `starts_with` rule on purpose. Measured:
/// a real zenohd handed `connect: { retry: { period_init_mss: 250 } }` starts
/// anyway and drops the field with no complaint at all — so a prefix rule would
/// make wz silently swallow the same typo. wz does not REFUSE it either (that
/// would be stricter than the acceptance boundary the census pins), it REPORTS
/// it, which is the one thing upstream does not do for the operator.
const HONOURED_SUBTREE_LEAVES: &[&str] = &[
    "connect/retry/period_init_ms",
    "connect/retry/period_max_ms",
    "connect/retry/period_increase_factor",
];

/// Every leaf key a real zenoh 1.5.0 resolves that wz does NOT honour.
///
/// Together with [`HONOURED_CONFIG_KEYS`] this is the UPSTREAM CONFIG SURFACE
/// — the whole of it, obtained by execution rather than by reading
/// `DEFAULT_CONFIG.json5` (which documents a subset and comments most of it
/// out). `wz_reads_a_stock_zenohd_config` adjudicates it against a running
/// zenohd's own resolved config, so this list is a claim about zenoh that
/// zenoh checks, not a wz-side opinion.
///
/// These are not defects. wz models the topology-and-transport subset it can
/// act on; `transport/auth/*` needs an auth stack, `plugins*` a plugin host,
/// `qos/*` and `downsampling` an interceptor chain configured from the same
/// file. Naming them is what turns "wz does not honour this" from an absence
/// nobody can see into a recorded fact with a place to change.
pub const UNHONOURED_UPSTREAM_CONFIG_KEYS: &[&str] = &[
    "access_control/default_permission",
    "access_control/enabled",
    "access_control/policies",
    "access_control/rules",
    "access_control/subjects",
    "aggregation/publishers",
    "aggregation/subscribers",
    "connect/exit_on_failure",
    // R311y849 removed `connect/retry` from here -- it moved to
    // `HONOURED_CONFIG_KEYS`. Its two siblings STAY, and not for want of
    // attention: for a peer, upstream resolves `timeout_ms` to -1 (retry
    // forever) and `exit_on_failure` to false, which is precisely what wz does,
    // so wz already matches the DEFAULT and what remains unhonoured is a
    // non-default value -- a bounded give-up and a process that exits on it.
    // Those are lifecycle behaviours wz has no substrate for, which is a
    // different kind of debt from a reader that was never taught a key.
    "connect/timeout_ms",
    "downsampling",
    "listen/exit_on_failure",
    "listen/retry",
    "listen/timeout_ms",
    "low_pass_filter",
    "metadata",
    "open/return_conditions/connect_scouted",
    "open/return_conditions/declares",
    "plugins",
    "plugins_loading/enabled",
    "plugins_loading/search_dirs",
    "qos/network",
    "qos/publication",
    "routing/peer/linkstate/transport_weights",
    // R2063 (item 214) — `routing/peer/mode` MOVED to HONOURED_CONFIG_KEYS.
    // It was in this list not because wz cannot act on it but because the
    // reader had not learned it, which is exactly the two-kinds-under-one-name
    // the item records. The demo's `--help` was already citing it.
    "routing/router/linkstate/transport_weights",
    "routing/router/peers_failover_brokering",
    "scouting/delay",
    "scouting/gossip/autoconnect",
    "scouting/gossip/autoconnect_strategy",
    "scouting/gossip/enabled",
    "scouting/gossip/multihop",
    "scouting/gossip/target",
    "scouting/multicast/autoconnect",
    "scouting/multicast/autoconnect_strategy",
    "timestamping/drop_future_timestamp",
    "transport/auth/pubkey/key_size",
    "transport/auth/pubkey/known_keys_file",
    "transport/auth/pubkey/private_key_file",
    "transport/auth/pubkey/private_key_pem",
    "transport/auth/pubkey/public_key_file",
    "transport/auth/pubkey/public_key_pem",
    "transport/auth/usrpwd/dictionary_file",
    "transport/auth/usrpwd/password",
    "transport/auth/usrpwd/user",
    "transport/link/protocols",
    "transport/link/rx/buffer_size",
    "transport/link/rx/max_message_size",
    "transport/link/tcp/so_rcvbuf",
    "transport/link/tcp/so_sndbuf",
    "transport/link/tls/close_link_on_expiration",
    "transport/link/tls/connect_certificate",
    "transport/link/tls/connect_private_key",
    "transport/link/tls/enable_mtls",
    "transport/link/tls/so_rcvbuf",
    "transport/link/tls/so_sndbuf",
    "transport/link/tls/verify_name_on_connect",
    "transport/link/tx/keep_alive",
    "transport/link/tx/queue/allocation/mode",
    "transport/link/tx/queue/batching/enabled",
    "transport/link/tx/queue/batching/time_limit",
    "transport/link/tx/queue/congestion_control/block/wait_before_close",
    "transport/link/tx/queue/congestion_control/drop/max_wait_before_drop_fragments",
    "transport/link/tx/queue/congestion_control/drop/wait_before_drop",
    "transport/link/tx/queue/size/background",
    "transport/link/tx/queue/size/control",
    "transport/link/tx/queue/size/data",
    "transport/link/tx/queue/size/data_high",
    "transport/link/tx/queue/size/data_low",
    "transport/link/tx/queue/size/interactive_high",
    "transport/link/tx/queue/size/interactive_low",
    "transport/link/tx/queue/size/real_time",
    "transport/link/tx/sequence_number_resolution",
    "transport/link/tx/threads",
    "transport/link/unixpipe/file_access_mask",
    "transport/multicast/compression/enabled",
    "transport/multicast/join_interval",
    "transport/multicast/max_sessions",
    "transport/shared_memory/mode",
    "transport/unicast/accept_pending",
    "transport/unicast/accept_timeout",
    "transport/unicast/max_sessions",
    "transport/unicast/open_timeout",
];

/// Is `path` a key stock zenoh knows — itself, or under a subtree it knows?
///
/// The DESCENDANT half is not a looseness: several upstream keys are whole
/// subtrees that resolve to `null` when unset (`connect/retry`, `metadata`,
/// `plugins`), so a config that fills one in carries leaves BELOW the path the
/// resolved tree shows. Refusing those would refuse valid configs.
///
/// The residual, stated rather than hidden: zenoh's own check is finer. It
/// deserialises into typed structs with `deny_unknown_fields`, so it refuses a
/// bogus field INSIDE `connect/retry` too, where this accepts anything under a
/// known opaque node. wz's boundary is therefore a SUPERSET of zenoh's by
/// exactly the fields nested inside subtrees wz does not model.
/// The only keys below which a real zenohd accepts leaves this tree's census
/// surface does not list.
///
/// R2078 (open-debt item 501) — MEASURED, one zenohd run per entry, at the
/// pinned checkout. Two kinds sit here together because the acceptance boundary
/// treats them the same:
///
/// * OPAQUE subtrees whose contents upstream does not validate at all —
///   `plugins` (a plugin's own config), `metadata` (free-form), and
///   `connect/retry`, which is the one exception in an otherwise strict tree
///   (measured: a real zenohd handed `connect: { retry: { period_init_mss: 250 } }`
///   starts and drops the field, while the same typo under `transport/link/tx`
///   or `transport/link/tls` refuses to start).
/// * MODE-DEPENDENT keys, whose value may be a `{ router, peer, client }` table
///   instead of the value itself. Every one of them was run: the table form
///   starts. The two `autoconnect_strategy` keys nest one level FURTHER
///   (`{ peer: { to_router: "always" } }`, `DEFAULT_CONFIG.json5:159-162`), which
///   is why a prefix rule and not a fixed depth.
///
/// ⛔ This list is what keeps the tightening below from becoming the OPPOSITE
/// defect. Refusing a document a real zenohd accepts is worse than accepting one
/// it refuses: the first stops a working deployment, the second only fails to
/// catch a typo. Every entry earns its place by execution.
pub const DEEPENABLE_UPSTREAM_KEYS: &[&str] = &[
    "connect/endpoints",
    "connect/exit_on_failure",
    "connect/retry",
    "connect/timeout_ms",
    "listen/endpoints",
    "listen/exit_on_failure",
    // R2079 — `listen/retry` was MISSING from R2078's list, which made wz refuse
    // `listen: { retry: { period_init_ms: 250 } }` — a file a real zenohd starts
    // on. It is `connect/retry`'s twin and opaque for the same reason; R2078
    // enumerated the mode-dependent keys from upstream's declarations and did
    // not think to look for a second opaque subtree beside the one it knew.
    // Found by sweeping the WHOLE surface against a real zenohd rather than by
    // re-reading the list.
    "listen/retry",
    "listen/timeout_ms",
    "metadata",
    "plugins",
    "scouting/gossip/autoconnect",
    "scouting/gossip/autoconnect_strategy",
    "scouting/gossip/target",
    "scouting/multicast/autoconnect",
    "scouting/multicast/autoconnect_strategy",
    "scouting/multicast/listen",
    "timestamping/enabled",
];

/// Whether upstream would accept this leaf path at all.
///
/// R2078 (open-debt item 501) — this used to accept anything BELOW a key it
/// knew, and that prefix rule was the last judge in exactly one place: a typo
/// under an UNHONOURED key, whose value wz never reads and therefore never
/// type-checks. `access_control: { enabled: { xyz: true } }` passed here and a
/// real zenohd refuses to start on it, so a typo the operator's OLD node caught
/// ran silently under wz — the precise inverse of a drop-in.
///
/// The rule is now EXACT, with [`DEEPENABLE_UPSTREAM_KEYS`] as the measured
/// exception. `wz_reads_a_stock_zenohd_config`'s boundary leg holds both
/// directions against a real zenohd.
fn upstream_knows(path: &str) -> bool {
    let under = |known: &&str| {
        path.len() > known.len() && path.starts_with(*known) && path.as_bytes()[known.len()] == b'/'
    };
    HONOURED_CONFIG_KEYS
        .iter()
        .chain(UNHONOURED_UPSTREAM_CONFIG_KEYS)
        .any(|known| path == *known)
        || HONOURED_SUBTREE_LEAVES.contains(&path)
        || DEEPENABLE_UPSTREAM_KEYS.iter().any(under)
}

/// The result of reading a stock zenoh config: what wz took from it, and —
/// just as load-bearing — what it did not.
///
/// The ignored list is not diagnostics padding. A config reader that applies
/// the keys it knows and says nothing about the rest lets an operator run a
/// node believing `transport/link/tls/root_ca_certificate` took effect. Every
/// leaf the document carried that wz does not honour is named here, so the
/// caller can print it, and so a census can compare the partition against the
/// upstream surface.
/// R311y849 dropped `Eq` here for the reason it dropped it from
/// [`ZenohNodeConfig`], which this wraps: the float in `connect/retry` reaches
/// this type through that field, so the bound could not survive on the wrapper
/// once it had left the wrapped.
#[derive(Debug, Clone, PartialEq)]
pub struct ZenohConfigIngest {
    /// The subset wz models, with an absent or `null` key left at its zenoh
    /// default.
    pub config: ZenohNodeConfig,
    /// The [`HONOURED_CONFIG_KEYS`] the document actually NAMED, in table
    /// order.
    ///
    /// Distinct from reading [`ZenohConfigIngest::config`], and the
    /// distinction is load-bearing for any caller that turns a config into
    /// instructions: `qos` resolves to `true` for a document that never
    /// mentioned it, so a caller acting on the merged value alone would carry
    /// a decision the operator never made. A key present but `null` is NOT
    /// named — that is zenoh's own spelling of "left unset".
    pub named: Vec<&'static str>,
    /// Leaf paths the document carried that wz does not honour, sorted.
    pub ignored: Vec<String>,
}

/// Why a stock zenoh config could not be read.
///
/// A key ZENOH knows and wz does not honour is never one of these — it is
/// reported through [`ZenohConfigIngest::ignored`], because a real deployment's
/// config is full of them and refusing those would make the reader useless. A
/// key NEITHER implementation knows IS one, and that split was settled by
/// measurement rather than taste (R311y842): a real zenohd refuses an unknown
/// field outright (`unknown field 'x', expected one of ...`, serde
/// `deny_unknown_fields`), so a wz that accepted it would let a TYPO through
/// on exactly the migration where the operator's old node would have caught
/// it — silently running a node whose mistyped setting never applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigIngestError {
    /// The document is not JSON5.
    Syntax(wz_session_core::json5::Json5Error),
    /// The top level is not an object.
    NotAnObject,
    /// A honoured key carried the wrong JSON type.
    WrongType {
        /// The key path.
        path: &'static str,
        /// What that key has to be.
        expected: &'static str,
    },
    /// `mode` named something that is not a zenoh node role.
    UnknownMode {
        /// The value as given.
        value: String,
    },
    /// A honoured numeric key carried a value outside its type.
    OutOfRange {
        /// The key path.
        path: &'static str,
        /// The value as given.
        value: String,
    },
    /// A key stock zenoh does not know either — a typo, or a config for
    /// something that is not zenoh. Refused because zenoh refuses it.
    UnknownKey {
        /// The key path as the document spelled it.
        path: String,
    },
}

impl core::fmt::Display for ConfigIngestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigIngestError::Syntax(e) => write!(f, "not a JSON5 document: {e}"),
            ConfigIngestError::NotAnObject => write!(f, "the top level is not an object"),
            ConfigIngestError::WrongType { path, expected } => {
                write!(f, "{path} must be {expected}")
            }
            ConfigIngestError::UnknownMode { value } => {
                write!(f, "mode {value:?} is not one of router, peer, client")
            }
            ConfigIngestError::OutOfRange { path, value } => {
                write!(f, "{path} value {value} is out of range")
            }
            ConfigIngestError::UnknownKey { path } => {
                write!(f, "unknown config key {path:?}; stock zenoh refuses it too")
            }
        }
    }
}

impl core::error::Error for ConfigIngestError {}

/// A honoured key's value, with zenoh's "null means default" already applied.
fn honoured<'a>(doc: &'a Json5Value, path: &str) -> Option<&'a Json5Value> {
    match doc.get(path) {
        // zenoh's own resolved config writes `null` for every key left unset,
        // so a null is the ABSENCE of an instruction rather than one.
        Some(Json5Value::Null) | None => None,
        other => other,
    }
}

/// The honoured keys upstream spells as `ModeDependentValue<T>` — either the
/// value itself, or a `{ router, peer, client }` table the node resolves with
/// its OWN mode.
///
/// R2075 (open-debt item 499) — this is not a wz convention, it is upstream's
/// type (`commons/zenoh-config/src/mode_dependent.rs:78`, `Unique(T)` or
/// `Dependent(ModeValues<T>)`, where `ModeValues` is three `Option<T>`), read at
/// the pinned checkout. Every key below is declared with it in
/// `commons/zenoh-config/src/lib.rs`, and a real zenohd starts on the table
/// spelling: handed `listen: { endpoints: { router: [..], peer: [..] } }` with
/// `mode: "router"` it binds the ROUTER entry and says so
/// (`Zenoh can be reached at: …`), measured rather than inferred.
///
/// Until this round wz's reader accepted only the `Unique` spelling and
/// answered the other with `WrongType`, which is worse than not honouring a key:
/// the node does not start at all. Two of the four are `listen/endpoints` and
/// `connect/endpoints`, so the refusal reached the most ordinary config there
/// is.
///
/// A table that names no entry for THIS node's mode is "no instruction", not an
/// error — that is exactly what upstream's `.get(whatami)` returns, and a wz
/// node must fall back to the same default a zenohd would.
pub const MODE_DEPENDENT_CONFIG_KEYS: &[&str] = &[
    "connect/endpoints",
    "listen/endpoints",
    "scouting/multicast/listen",
    "timestamping/enabled",
];

/// The three fields `ModeValues` has, and the only keys a mode table may carry.
const MODE_TABLE_FIELDS: &[&str] = &["router", "peer", "client"];

/// Whether `leaf` sits INSIDE one of the mode-dependent keys.
///
/// Those leaves (`listen/endpoints/router`) are wz's to honour, so they must not
/// fall into the ignored partition — a reader that resolved the table and then
/// reported its leaves as "wz does not honour this" would be contradicting
/// itself in the same breath.
fn inside_a_mode_table(leaf: &str) -> bool {
    MODE_DEPENDENT_CONFIG_KEYS.iter().any(|key| {
        leaf.len() > key.len() && leaf.starts_with(key) && leaf.as_bytes()[key.len()] == b'/'
    })
}

/// Resolve one value the way upstream's `.get(whatami)` does.
///
/// `Ok(None)` is "this document gives THIS node no instruction here", which a
/// caller must treat exactly as an absent key. An object whose fields are not
/// all mode names is an ERROR rather than a value: upstream's `ModeValues`
/// would refuse it, and silently reading it as `Unique` would let a typo
/// (`rooter:`) look like a setting that took effect.
fn for_this_mode<'a>(
    value: &'a Json5Value,
    mode: WhatAmI,
    path: &'static str,
) -> Result<Option<&'a Json5Value>, ConfigIngestError> {
    let Json5Value::Object(fields) = value else {
        return Ok(Some(value));
    };
    if fields.is_empty()
        || !fields
            .iter()
            .all(|(name, _)| MODE_TABLE_FIELDS.contains(&name.as_str()))
    {
        return Err(ConfigIngestError::WrongType {
            path,
            expected: "a value, or a { router, peer, client } table",
        });
    }
    let want = mode.to_str();
    Ok(fields
        .iter()
        .find(|(name, _)| name == want)
        .map(|(_, v)| v)
        .filter(|v| !matches!(v, Json5Value::Null)))
}

fn bool_of(value: &Json5Value, path: &'static str) -> Result<bool, ConfigIngestError> {
    match value {
        Json5Value::Bool(b) => Ok(*b),
        _ => Err(ConfigIngestError::WrongType {
            path,
            expected: "a boolean",
        }),
    }
}

fn want_bool(doc: &Json5Value, path: &'static str) -> Result<Option<bool>, ConfigIngestError> {
    match honoured(doc, path) {
        None => Ok(None),
        Some(v) => bool_of(v, path).map(Some),
    }
}

/// [`want_bool`] for a key upstream declares `ModeDependentValue<bool>`.
fn want_bool_for_mode(
    doc: &Json5Value,
    path: &'static str,
    mode: WhatAmI,
) -> Result<Option<bool>, ConfigIngestError> {
    let Some(value) = honoured(doc, path) else {
        return Ok(None);
    };
    match for_this_mode(value, mode, path)? {
        None => Ok(None),
        Some(v) => bool_of(v, path).map(Some),
    }
}

fn want_u64(doc: &Json5Value, path: &'static str) -> Result<Option<u64>, ConfigIngestError> {
    match honoured(doc, path) {
        None => Ok(None),
        Some(Json5Value::Number(text)) => {
            number_as_u64(text)
                .map(Some)
                .ok_or_else(|| ConfigIngestError::OutOfRange {
                    path,
                    value: text.clone(),
                })
        }
        Some(_) => Err(ConfigIngestError::WrongType {
            path,
            expected: "a non-negative integer",
        }),
    }
}

/// R311y849 — a honoured key whose value is a REAL number. The only one is
/// `connect/retry/period_increase_factor`, which upstream types `f64`
/// (`connection_retry.rs:36`), so `2` and `1.5` are both configurations a stock
/// file can carry and [`want_u64`] would refuse the second.
///
/// Finiteness is checked HERE and the range is not, and the split is deliberate.
/// A NaN or an infinity is not a number this key can mean under any policy, so
/// it is a type error; whether a factor below 1.0 is allowed is a POLICY, and
/// this crate has exactly one place that decides it — `--connect-retry`'s
/// parser, which every route into the schedule goes through, config included.
/// Deciding it twice is how the two answers start to differ.
fn want_f64(doc: &Json5Value, path: &'static str) -> Result<Option<f64>, ConfigIngestError> {
    match honoured(doc, path) {
        None => Ok(None),
        Some(Json5Value::Number(text)) => match text.parse::<f64>() {
            Ok(v) if v.is_finite() => Ok(Some(v)),
            _ => Err(ConfigIngestError::OutOfRange {
                path,
                value: text.clone(),
            }),
        },
        Some(_) => Err(ConfigIngestError::WrongType {
            path,
            expected: "a number",
        }),
    }
}

/// R311y844 — a honoured key whose value is a string (a path, a keyexpr, a hex
/// zid). An EMPTY string is refused rather than carried: every consumer of one
/// is a path or an identifier, and "" reaches them as a filename nothing opens
/// or a prefix that matches everything, which is a mistake the file should be
/// told about here rather than at bind time.
fn want_string(
    doc: &Json5Value,
    path: &'static str,
    expected: &'static str,
) -> Result<Option<String>, ConfigIngestError> {
    match honoured(doc, path) {
        None => Ok(None),
        Some(Json5Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
        Some(Json5Value::String(_)) => Err(ConfigIngestError::WrongType { path, expected }),
        Some(_) => Err(ConfigIngestError::WrongType { path, expected }),
    }
}

fn endpoints_of(value: &Json5Value, path: &'static str) -> Result<Vec<String>, ConfigIngestError> {
    let Json5Value::Array(items) = value else {
        return Err(ConfigIngestError::WrongType {
            path,
            expected: "an array of endpoint strings",
        });
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Json5Value::String(s) = item else {
            return Err(ConfigIngestError::WrongType {
                path,
                expected: "an array of endpoint strings",
            });
        };
        out.push(s.clone());
    }
    Ok(out)
}

/// R2075 — both endpoint lists are `ModeDependentValue<Vec<EndPoint>>`
/// upstream, so the table spelling has to resolve here rather than be refused.
fn want_endpoints(
    doc: &Json5Value,
    path: &'static str,
    mode: WhatAmI,
) -> Result<Option<Vec<String>>, ConfigIngestError> {
    let Some(value) = honoured(doc, path) else {
        return Ok(None);
    };
    match for_this_mode(value, mode, path)? {
        None => Ok(None),
        Some(v) => endpoints_of(v, path).map(Some),
    }
}

impl ZenohNodeConfig {
    /// Read the config a stock zenoh node would have been started with.
    ///
    /// This is the inverse of [`ZenohNodeConfig::to_json5`] over
    /// [`HONOURED_CONFIG_KEYS`], and the two share that table so they cannot
    /// drift. Keys outside it are reported rather than refused — see
    /// [`ZenohConfigIngest`].
    ///
    /// An absent key takes zenoh's default rather than wz's, because that is
    /// what a partial config means to zenoh: the document says what to change,
    /// not what everything is.
    pub fn from_json5(source: &str) -> Result<ZenohConfigIngest, ConfigIngestError> {
        let doc = wz_session_core::json5::parse(source).map_err(ConfigIngestError::Syntax)?;
        if !matches!(doc, Json5Value::Object(_)) {
            return Err(ConfigIngestError::NotAnObject);
        }

        // The ACCEPTANCE BOUNDARY, matched to zenoh's before anything is read.
        // Checked first so a typo is reported as a typo rather than as a
        // missing value somewhere downstream.
        let leaves = doc.leaf_paths();
        if let Some(unknown) = leaves.iter().find(|p| !upstream_knows(p)) {
            return Err(ConfigIngestError::UnknownKey {
                path: unknown.clone(),
            });
        }

        let mut out = Self::default();
        let mut named: Vec<&'static str> = Vec::new();

        if let Some(mode) = honoured(&doc, "mode") {
            let Json5Value::String(name) = mode else {
                return Err(ConfigIngestError::WrongType {
                    path: "mode",
                    expected: "a string",
                });
            };
            // Matched against `to_str` so the two directions cannot disagree
            // about a spelling.
            out.mode = [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client]
                .into_iter()
                .find(|w| w.to_str() == name)
                .ok_or_else(|| ConfigIngestError::UnknownMode {
                    value: name.clone(),
                })?;
            named.push("mode");
        }
        // R2075 — the mode-dependent keys are all read AFTER `mode` above, and
        // that ordering is load-bearing: the table is resolved with this node's
        // own mode, exactly as upstream's `.get(whatami)` does.
        if let Some(v) = want_endpoints(&doc, "connect/endpoints", out.mode)? {
            out.connect = v;
            named.push("connect/endpoints");
        }
        // R311y849 — `connect/retry`, read next to the endpoints it paces.
        //
        // The subtree is ONE census leaf, so it is named ONCE in `named` no
        // matter how many of its three fields the file states. Any one of them
        // present means the file HAS an instruction here, and the two it did not
        // state fall back to zenoh's own resolved values -- which is what
        // upstream does with a partial block, and is why the fallbacks are read
        // off `RetryPolicy::ZENOH_DEFAULT` rather than off this struct's
        // `Default` (that one is `None`, an absence, and has no numbers to give).
        {
            let init = want_u64(&doc, "connect/retry/period_init_ms")?;
            let max = want_u64(&doc, "connect/retry/period_max_ms")?;
            let factor = want_f64(&doc, "connect/retry/period_increase_factor")?;
            if init.is_some() || max.is_some() || factor.is_some() {
                let base = crate::retry_period::RetryPolicy::ZENOH_DEFAULT;
                out.connect_retry = Some(crate::retry_period::RetryPolicy {
                    period_init_ms: init.unwrap_or(base.period_init_ms),
                    period_max_ms: max.unwrap_or(base.period_max_ms),
                    period_increase_factor: factor.unwrap_or(base.period_increase_factor),
                });
                named.push("connect/retry");
            }
        }
        if let Some(v) = want_endpoints(&doc, "listen/endpoints", out.mode)? {
            out.listen = v;
            named.push("listen/endpoints");
        }
        // R2063 (open-debt item 214) — `routing/peer/mode`, which this demo's
        // own `--help` has been citing as a key it implements while the reader
        // did not know it. Matched against the two spellings upstream defines
        // and nothing else: an unknown value is an ERROR rather than a silent
        // fall back to `linkstate`, because a config that asks for
        // `peer-to-peer` and quietly gets link-state discovery is the failure
        // this key exists to prevent.
        if let Some(v) = honoured(&doc, "routing/peer/mode") {
            let Json5Value::String(name) = v else {
                return Err(ConfigIngestError::WrongType {
                    path: "routing/peer/mode",
                    expected: "a string",
                });
            };
            out.peer_linkstate = match name.as_str() {
                "linkstate" => true,
                "peer-to-peer" => false,
                _ => {
                    return Err(ConfigIngestError::WrongType {
                        path: "routing/peer/mode",
                        expected: "`linkstate` or `peer-to-peer`",
                    })
                }
            };
            named.push("routing/peer/mode");
        }
        if let Some(v) = want_bool(&doc, "scouting/multicast/enabled")? {
            out.multicast_scouting = v;
            named.push("scouting/multicast/enabled");
        }
        // R311y845 — the scouting SOCKET. Upstream types `address` as a
        // `SocketAddr` and so refuses a malformed one at deserialization; the
        // parse here is what keeps that refusal, and it is worth keeping: the
        // failure mode of accepting `"224.0.0.224"` (no port) is a node that
        // starts, reports the key honoured, and joins nothing.
        if let Some(v) = want_string(&doc, "scouting/multicast/address", "an <ip>:<port> socket")? {
            if v.parse::<std::net::SocketAddrV4>().is_err() {
                return Err(ConfigIngestError::WrongType {
                    path: "scouting/multicast/address",
                    expected: "an <ip>:<port> socket",
                });
            }
            out.scout_multicast_address = Some(v);
            named.push("scouting/multicast/address");
        }
        if let Some(v) = want_string(
            &doc,
            "scouting/multicast/interface",
            "an interface name or address",
        )? {
            out.scout_multicast_interface = Some(v);
            named.push("scouting/multicast/interface");
        }
        if let Some(v) = want_u64(&doc, "scouting/multicast/ttl")? {
            out.scout_multicast_ttl =
                Some(u32::try_from(v).map_err(|_| ConfigIngestError::OutOfRange {
                    path: "scouting/multicast/ttl",
                    value: v.to_string(),
                })?);
            named.push("scouting/multicast/ttl");
        }
        // R311y846 — the ANSWERING half. Read next to the three socket keys
        // because it is the same subsystem read the other way round: those
        // three say where to look, this says whether to be findable.
        if let Some(v) = want_bool_for_mode(&doc, "scouting/multicast/listen", out.mode)? {
            out.scout_multicast_listen = Some(v);
            named.push("scouting/multicast/listen");
        }
        if let Some(v) = want_bool_for_mode(&doc, "timestamping/enabled", out.mode)? {
            out.timestamping = v;
            named.push("timestamping/enabled");
        }
        if let Some(v) = want_u64(&doc, "transport/unicast/max_links")? {
            out.max_links = usize::try_from(v).map_err(|_| ConfigIngestError::OutOfRange {
                path: "transport/unicast/max_links",
                value: v.to_string(),
            })?;
            named.push("transport/unicast/max_links");
        }
        if let Some(v) = want_bool(&doc, "transport/unicast/lowlatency")? {
            out.lowlatency = v;
            named.push("transport/unicast/lowlatency");
        }
        if let Some(v) = want_bool(&doc, "transport/unicast/qos/enabled")? {
            out.qos = v;
            named.push("transport/unicast/qos/enabled");
        }
        if let Some(v) = want_bool(&doc, "transport/unicast/compression/enabled")? {
            out.compression = v;
            named.push("transport/unicast/compression/enabled");
        }
        if let Some(v) = want_u64(&doc, "transport/link/tx/batch_size")? {
            out.batch_size = u16::try_from(v).map_err(|_| ConfigIngestError::OutOfRange {
                path: "transport/link/tx/batch_size",
                value: v.to_string(),
            })?;
            named.push("transport/link/tx/batch_size");
        }
        if let Some(v) = want_u64(&doc, "transport/link/tx/lease")? {
            out.lease_ms = v;
            named.push("transport/link/tx/lease");
        }
        // R311y844 — the ten keys wz already acts on. Read in
        // HONOURED_CONFIG_KEYS order so `named` reports them the way the table
        // lists them.
        if let Some(v) = want_string(&doc, "id", "a hex zenoh id")? {
            out.id = Some(v);
            named.push("id");
        }
        if let Some(v) = want_string(&doc, "namespace", "a keyexpr")? {
            out.namespace = Some(v);
            named.push("namespace");
        }
        if let Some(v) = want_u64(&doc, "queries_default_timeout")? {
            out.queries_default_timeout_ms = Some(v);
            named.push("queries_default_timeout");
        }
        if let Some(v) = want_u64(&doc, "routing/interests/timeout")? {
            out.interests_timeout_ms = Some(v);
            named.push("routing/interests/timeout");
        }
        if let Some(v) = want_u64(&doc, "scouting/timeout")? {
            out.scouting_timeout_ms = Some(v);
            named.push("scouting/timeout");
        }
        if let Some(v) = want_bool(&doc, "transport/multicast/qos/enabled")? {
            out.multicast_qos = v;
            named.push("transport/multicast/qos/enabled");
        }
        if let Some(v) = want_bool(&doc, "transport/shared_memory/enabled")? {
            out.shared_memory = v;
            named.push("transport/shared_memory/enabled");
        }
        if let Some(v) = want_string(&doc, "transport/link/tls/root_ca_certificate", "a path")? {
            out.tls_root_ca = Some(v);
            named.push("transport/link/tls/root_ca_certificate");
        }
        if let Some(v) = want_string(&doc, "transport/link/tls/listen_certificate", "a path")? {
            out.tls_listen_certificate = Some(v);
            named.push("transport/link/tls/listen_certificate");
        }
        if let Some(v) = want_string(&doc, "transport/link/tls/listen_private_key", "a path")? {
            out.tls_listen_private_key = Some(v);
            named.push("transport/link/tls/listen_private_key");
        }
        // `adminspace` is a block rather than a field: an absent block is not
        // `enabled: false`, which is why the struct models it as an Option and
        // why `enabled: false` here has to erase the block rather than record
        // two permissions nobody can use.
        let admin_enabled = want_bool(&doc, "adminspace/enabled")?;
        let admin_read = want_bool(&doc, "adminspace/permissions/read")?;
        let admin_write = want_bool(&doc, "adminspace/permissions/write")?;
        // Read all three unconditionally rather than only under `enabled`: a
        // document that sets a permission without the flag would otherwise be
        // neither honoured NOR reported ignored, which is the one outcome this
        // whole partition exists to make impossible.
        for (key, present) in [
            ("adminspace/enabled", admin_enabled.is_some()),
            ("adminspace/permissions/read", admin_read.is_some()),
            ("adminspace/permissions/write", admin_write.is_some()),
        ] {
            if present {
                named.push(key);
            }
        }
        let admin_described =
            admin_enabled.is_some() || admin_read.is_some() || admin_write.is_some();
        if admin_described && admin_enabled != Some(false) {
            out.adminspace = Some(AdminspaceConfig {
                read: admin_read.unwrap_or(true),
                write: admin_write.unwrap_or(false),
            });
        }

        let mut ignored: Vec<String> = leaves
            .into_iter()
            .filter(|p| {
                !HONOURED_CONFIG_KEYS.contains(&p.as_str())
                    && !HONOURED_SUBTREE_LEAVES.contains(&p.as_str())
                    // R2075 — a mode table's own leaves (`listen/endpoints/router`)
                    // are wz's to honour, so reporting them as unhonoured would
                    // contradict the resolution that just happened.
                    && !inside_a_mode_table(p)
            })
            .collect();
        ignored.dedup();
        Ok(ZenohConfigIngest {
            config: out,
            named,
            ignored,
        })
    }
}

fn push_endpoints(endpoints: &[String], out: &mut String) {
    out.push('[');
    for (i, e) in endpoints.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        escape_into(e, out);
    }
    out.push(']');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_config_is_zenohs_own_defaults() {
        let c = ZenohNodeConfig::default();
        assert!(c.validate().is_empty(), "{:?}", c.validate());
        let json = c.to_json5();
        // The values are zenoh's, so the emit must reproduce them literally.
        assert!(json.contains("\"batch_size\": 65535"), "{json}");
        assert!(json.contains("\"lease\": 10000"), "{json}");
        assert!(json.contains("\"max_links\": 1"), "{json}");
        assert!(json.contains("\"qos\": { \"enabled\": true }"), "{json}");
        assert!(json.contains("\"mode\": \"peer\""), "{json}");
        // Omitted rather than defaulted: an absent adminspace block and an
        // emitted `enabled: false` are different instructions to zenoh.
        assert!(!json.contains("adminspace"), "{json}");
    }

    #[test]
    fn endpoints_render_as_a_json_array() {
        let c = ZenohNodeConfig::default()
            .listening_on("tcp/127.0.0.1:7447")
            .connecting_to("quic/example:7447")
            .with_multicast_scouting(false)
            .with_adminspace(true, false);
        let json = c.to_json5();
        assert!(
            json.contains("\"listen\": { \"endpoints\": [\"tcp/127.0.0.1:7447\"] }"),
            "{json}"
        );
        assert!(
            json.contains("\"connect\": { \"endpoints\": [\"quic/example:7447\"] }"),
            "{json}"
        );
        assert!(
            json.contains("\"adminspace\": { \"enabled\": true, \"permissions\": { \"read\": true, \"write\": false } }"),
            "{json}"
        );
        assert!(c.validate().is_empty(), "{:?}", c.validate());
    }

    #[test]
    fn the_validator_names_each_defect() {
        let c = ZenohNodeConfig {
            multicast_scouting: false,
            ..Default::default()
        };
        assert_eq!(c.validate(), vec![ConfigDefect::Unreachable]);

        let c = ZenohNodeConfig::default().listening_on("carrier-pigeon/aviary:1");
        assert_eq!(
            c.validate(),
            vec![ConfigDefect::UnknownProtocol {
                endpoint: String::from("carrier-pigeon/aviary:1"),
                protocol: String::from("carrier-pigeon"),
            }]
        );

        let c = ZenohNodeConfig::default().listening_on("tcp-no-slash");
        assert_eq!(
            c.validate(),
            vec![ConfigDefect::MalformedEndpoint {
                endpoint: String::from("tcp-no-slash"),
            }]
        );

        let c = ZenohNodeConfig::default()
            .listening_on("tcp/127.0.0.1:7447")
            .listening_on("tcp/127.0.0.1:7447");
        assert_eq!(
            c.validate(),
            vec![ConfigDefect::DuplicateListenEndpoint {
                endpoint: String::from("tcp/127.0.0.1:7447"),
            }]
        );

        // zenoh's own config states these two are incompatible, and the
        // measured zenohd refuses to start on the pair.
        let c = ZenohNodeConfig {
            lowlatency: true,
            ..Default::default()
        };
        assert!(
            c.qos,
            "the default carries qos, which is what makes the pair a conflict"
        );
        assert_eq!(c.validate(), vec![ConfigDefect::QosWithLowlatency]);

        let c = ZenohNodeConfig {
            batch_size: 0,
            lease_ms: 0,
            max_links: 0,
            ..Default::default()
        };
        assert_eq!(
            c.validate(),
            vec![
                ConfigDefect::ZeroBatchSize,
                ConfigDefect::ZeroLease,
                ConfigDefect::ZeroMaxLinks
            ]
        );
    }

    #[test]
    fn every_declared_protocol_passes_and_a_typo_of_one_does_not() {
        for proto in ZENOH_LINK_PROTOCOLS {
            let c = ZenohNodeConfig::default().listening_on(format!("{proto}/x:1"));
            assert!(
                c.validate().is_empty(),
                "{proto} was rejected: {:?}",
                c.validate()
            );
            // One character off must NOT pass — otherwise the check is a
            // prefix match dressed up as a set membership.
            let c = ZenohNodeConfig::default().listening_on(format!("{proto}x/x:1"));
            assert!(!c.validate().is_empty(), "{proto}x was accepted");
        }
    }

    // R2070 (open-debt item 487) — the two directions of this module disagree
    // about the SAME file, and each half of this test is one of them. Before
    // this round only the emit half existed, so a config naming a scheme this
    // build has no backend for passed clean and failed at bind instead.
    #[test]
    fn a_scheme_the_build_cannot_open_is_a_defect_for_a_wz_node_but_not_for_an_emit() {
        let c = ZenohNodeConfig::default().listening_on("vsock/2:7447");
        // EMIT: unchanged, and it must stay unchanged — a stock zenohd carries
        // vsock whatever this binary was built with.
        assert!(
            c.validate().is_empty(),
            "the emit verdict narrowed: {:?}",
            c.validate()
        );
        // WZ NODE: the same file, judged for a reader that can only open tcp.
        assert_eq!(
            c.validate_for_build(Some(&["tcp"])),
            vec![ConfigDefect::ProtocolNotCompiledIn {
                endpoint: String::from("vsock/2:7447"),
                protocol: String::from("vsock"),
            }]
        );
        // A scheme the reader DOES carry is not a defect — otherwise the check
        // would be "any endpoint at all" wearing a protocol's name.
        let c = ZenohNodeConfig::default().listening_on("tcp/127.0.0.1:7447");
        assert!(
            c.validate_for_build(Some(&["tcp"])).is_empty(),
            "{:?}",
            c.validate_for_build(Some(&["tcp"]))
        );
        // A scheme NOBODY carries stays exactly one defect. Two lines for one
        // typo would be the reader repeating itself at start-up refusal time.
        let c = ZenohNodeConfig::default().listening_on("carrier-pigeon/aviary:1");
        assert_eq!(
            c.validate_for_build(Some(&["tcp"])),
            vec![ConfigDefect::UnknownProtocol {
                endpoint: String::from("carrier-pigeon/aviary:1"),
                protocol: String::from("carrier-pigeon"),
            }]
        );
        // CONNECT endpoints are judged too, not just listen — the harm is
        // symmetric (a dial that cannot be made is a node alone forever).
        let c = ZenohNodeConfig::default().connecting_to("ws/example.org:7447");
        assert_eq!(
            c.validate_for_build(Some(&["tcp", "udp"])),
            vec![ConfigDefect::ProtocolNotCompiledIn {
                endpoint: String::from("ws/example.org:7447"),
                protocol: String::from("ws"),
            }]
        );
    }

    // R2070 (open-debt item 487) — the census is only worth anything if it
    // says what the BUILD does rather than what a list says, so the oracle
    // here is `bind_locator` itself, asked once per upstream scheme. Gated on
    // the session-open module's own predicate: without it there is nothing to
    // ask, which is exactly the case `compiled_in_link_schemes` answers with
    // an empty set.
    #[cfg(all(feature = "transport-link-tcp", feature = "transport-unicast"))]
    #[tokio::test]
    async fn the_compiled_in_scheme_census_agrees_with_what_bind_locator_does() {
        use crate::session_open::{
            bind_endpoint, COMPILED_IN_LINK_SCHEMES, NOT_COMPILED_IN_MARKER,
        };

        // One probe endpoint per scheme, each chosen so that a build which DOES
        // carry the backend leaves nothing behind: port 0 for the IP family
        // (an ephemeral bind, dropped at once), a path under `/proc` for the
        // two filesystem schemes (no directory can be made there, so no socket
        // can be left), and a device name that is not a tty for serial.
        const PROBES: &[(&str, &str)] = &[
            ("tcp", "tcp/127.0.0.1:0"),
            ("udp", "udp/127.0.0.1:0"),
            ("tls", "tls/127.0.0.1:0"),
            ("quic", "quic/127.0.0.1:0"),
            ("serial", "serial//dev/wz-no-such-tty#baudrate=9600"),
            ("unixsock-stream", "unixsock-stream//proc/wz-no-dir/x.sock"),
            ("unixpipe", "unixpipe//proc/wz-no-dir/x.pipe"),
            ("vsock", "vsock/2:0"),
            ("ws", "ws/127.0.0.1:0"),
        ];

        // The population is the UPSTREAM surface, so a scheme zenoh gains
        // arrives here as a missing probe rather than as silence.
        for proto in ZENOH_LINK_PROTOCOLS {
            assert!(
                PROBES.iter().any(|(scheme, _)| scheme == proto),
                "{proto} has no probe: a scheme entered ZENOH_LINK_PROTOCOLS \
                 without anyone deciding whether this build can open it"
            );
        }
        // And the census may not name a scheme the upstream list does not —
        // the ratchet that keeps `quic-datagram` from acquiring a scheme of
        // its own here while its link crate keeps sharing `"quic"`.
        for scheme in COMPILED_IN_LINK_SCHEMES {
            assert!(
                ZENOH_LINK_PROTOCOLS.contains(scheme),
                "{scheme} is compiled in but is not a scheme stock zenoh carries"
            );
        }

        for (scheme, endpoint) in PROBES {
            let refusal = match bind_endpoint(endpoint).await {
                Ok(listener) => {
                    drop(listener);
                    None
                }
                // Every other failure — no cert, address unavailable, no such
                // device — means the backend IS here and the address is not.
                Err(e) => {
                    let message = e.to_string();
                    message.contains(NOT_COMPILED_IN_MARKER).then_some(message)
                }
            };
            assert_eq!(
                refusal.is_none(),
                COMPILED_IN_LINK_SCHEMES.contains(scheme),
                "{scheme}: the census says compiled-in={}, but bind_endpoint({endpoint:?}) says {}",
                COMPILED_IN_LINK_SCHEMES.contains(scheme),
                if refusal.is_some() {
                    "the backend is absent"
                } else {
                    "the backend is here"
                },
            );
            // And the SECOND column of the catalogue is checked against the
            // arm's own words. Each cfg-off arm names the feature that would
            // turn it on, a literal sitting beside the `#[cfg(feature = ...)]`
            // the compiler checks — so a scheme paired with the wrong feature
            // here is caught by the refusal itself rather than by a second
            // copy of the pairing. Nothing else reads that column, which is
            // how a hint like "enable transport-link-tls" could otherwise end
            // up printed for a `ws/...` endpoint.
            if let Some(message) = refusal {
                let feature = link_scheme_feature(scheme)
                    .unwrap_or_else(|| panic!("{scheme} is refusable but has no catalogue entry"));
                assert!(
                    message.contains(feature),
                    "{scheme}: the catalogue says {feature}, but the arm refusing it says {message:?}"
                );
            }
        }
    }

    // R2070b (open-debt item 486) — the topology pass. Every defect is stated
    // as a PAIR: the case that must be reported, and the neighbouring case
    // that must NOT be, because each of these three has a legitimate shape one
    // character away from it and a false positive here tells an operator their
    // working deployment is broken.
    fn node(mode: WhatAmI, id: &str) -> ZenohNodeConfig {
        ZenohNodeConfig {
            mode,
            id: Some(String::from(id)),
            multicast_scouting: false,
            ..Default::default()
        }
    }

    #[test]
    fn a_connect_target_nobody_listens_on_is_named_with_the_node_that_dials_it() {
        let dialer = node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.9:7447");
        let listener = node(WhatAmI::Router, "R").listening_on("tcp/10.0.0.5:7447");
        assert_eq!(
            validate_topology(&[dialer.clone(), listener.clone()]),
            vec![TopologyDefect::DanglingConnectTarget {
                node: String::from("A"),
                endpoint: String::from("tcp/10.0.0.9:7447"),
            }],
            "the dangling dial was not reported, or not against its dialer"
        );

        // CONTROL 1 — the same shape with the ports agreed is NOT a defect.
        let dialer = node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.5:7447");
        assert!(validate_topology(&[dialer, listener.clone()]).is_empty());

        // CONTROL 2 — a WILDCARD listen answers a dial addressed to a name it
        // could never be compared with. Ruling this a defect is the single
        // most likely way to break a real deployment, since `0.0.0.0` is what
        // a router listens on and a name is what its clients dial.
        let dialer = node(WhatAmI::Client, "A").connecting_to("tcp/router.example:7447");
        let wildcard = node(WhatAmI::Router, "R").listening_on("tcp/0.0.0.0:7447");
        assert!(
            validate_topology(&[dialer, wildcard]).is_empty(),
            "a wildcard listen was not credited with answering a named dial"
        );

        // CONTROL 3 — the PORT still decides. A wildcard on the wrong port
        // answers nothing, which is what keeps control 2 from being "anything
        // matches anything".
        let dialer = node(WhatAmI::Client, "A").connecting_to("tcp/router.example:7447");
        let wrong_port = node(WhatAmI::Router, "R").listening_on("tcp/0.0.0.0:7448");
        assert_eq!(
            validate_topology(&[dialer, wrong_port]),
            vec![TopologyDefect::DanglingConnectTarget {
                node: String::from("A"),
                endpoint: String::from("tcp/router.example:7447"),
            }]
        );

        // CONTROL 4 — the SCHEME decides too, on the same argument.
        let dialer = node(WhatAmI::Client, "A").connecting_to("udp/10.0.0.5:7447");
        assert_eq!(
            validate_topology(&[dialer, listener]),
            vec![TopologyDefect::DanglingConnectTarget {
                node: String::from("A"),
                endpoint: String::from("udp/10.0.0.5:7447"),
            }]
        );
    }

    #[test]
    fn two_nodes_claiming_one_concrete_address_collide_and_two_wildcards_do_not() {
        let a = node(WhatAmI::Peer, "A").listening_on("tcp/10.0.0.5:7447");
        let b = node(WhatAmI::Peer, "B").listening_on("tcp/10.0.0.5:7447");
        assert_eq!(
            validate_topology(&[a, b]),
            vec![TopologyDefect::ListenEndpointCollision {
                endpoint: String::from("tcp/10.0.0.5:7447"),
                nodes: vec![String::from("A"), String::from("B")],
            }],
            "the collision must name BOTH claimants, once"
        );

        // CONTROL 1 — two WILDCARD listens are two machines doing the ordinary
        // thing. This is the case that makes the check worth restricting.
        let a = node(WhatAmI::Peer, "A").listening_on("tcp/0.0.0.0:7447");
        let b = node(WhatAmI::Peer, "B").listening_on("tcp/0.0.0.0:7447");
        assert!(
            validate_topology(&[a, b]).is_empty(),
            "two wildcard binds were called a collision"
        );

        // CONTROL 2 — loopback likewise: two hosts each have their own.
        let a = node(WhatAmI::Peer, "A").listening_on("tcp/127.0.0.1:7447");
        let b = node(WhatAmI::Peer, "B").listening_on("tcp/127.0.0.1:7447");
        assert!(validate_topology(&[a, b]).is_empty());

        // CONTROL 3 — the SAME node listing an endpoint twice is already
        // `DuplicateListenEndpoint` from the per-node pass, and must not be
        // re-reported here as a collision with itself.
        let solo = node(WhatAmI::Peer, "A")
            .listening_on("tcp/10.0.0.5:7447")
            .listening_on("tcp/10.0.0.5:7447");
        assert!(
            validate_topology(std::slice::from_ref(&solo)).is_empty(),
            "a node colliding with itself is the per-node pass's finding"
        );
        assert_eq!(
            solo.validate(),
            vec![ConfigDefect::DuplicateListenEndpoint {
                endpoint: String::from("tcp/10.0.0.5:7447"),
            }],
            "and the per-node pass must still be the one that says it"
        );
    }

    #[test]
    fn a_set_of_only_clients_has_nobody_to_attach_to() {
        let a = node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.5:7447");
        let b = node(WhatAmI::Client, "B").connecting_to("tcp/10.0.0.5:7447");
        let defects = validate_topology(&[a.clone(), b.clone()]);
        assert!(
            defects.contains(&TopologyDefect::NoNodeAccepts),
            "an all-client set was not called out: {defects:?}"
        );

        // CONTROL 1 — ONE router turns it into an ordinary deployment, and the
        // dangling dials go with it.
        let r = node(WhatAmI::Router, "R").listening_on("tcp/10.0.0.5:7447");
        assert!(validate_topology(&[a, b, r]).is_empty());

        // CONTROL 2 — an EMPTY set describes no deployment. Reporting it would
        // be answering a question nobody asked, and would make the defect fire
        // on every caller that has not read its files yet.
        assert!(validate_topology(&[]).is_empty());
    }

    #[test]
    fn the_topology_pass_is_silent_about_what_the_per_node_pass_already_says() {
        // A malformed endpoint, an unknown protocol, and a node with no way
        // out at all: three defects the per-node verdict names. Saying any of
        // them again here would make one typo look like two faults.
        let bad = ZenohNodeConfig {
            mode: WhatAmI::Peer,
            id: Some(String::from("A")),
            multicast_scouting: false,
            ..Default::default()
        }
        .connecting_to("tcp-no-slash")
        .connecting_to("carrier-pigeon/aviary:1");
        let per_node = bad.validate();
        assert!(
            per_node.len() >= 2,
            "the per-node pass stopped naming these: {per_node:?}"
        );
        assert!(
            validate_topology(std::slice::from_ref(&bad)).is_empty(),
            "the topology pass repeated a per-node defect"
        );
    }

    // R2070 (open-debt item 487) — the catalogue half. `LINK_SCHEME_FEATURES`
    // is prose in a const until something reads BOTH of its columns, and the
    // right reader for the second column is cargo's own manifest: a feature
    // that gets renamed (which has happened in this crate — the `zenoh-config`
    // / `zenoh-config-emit` drift is still an open item) would otherwise leave
    // a defect message telling an operator to enable a feature that no longer
    // exists.
    #[test]
    fn every_scheme_names_a_cargo_feature_that_this_crate_actually_declares() {
        // The manifest is read from the SHIPPED file, not from a fixture, so
        // the assertion is about the crate rather than about a copy of it.
        const MANIFEST: &str = include_str!("../Cargo.toml");

        let mut catalogued: Vec<&str> = LINK_SCHEME_FEATURES.iter().map(|(s, _)| *s).collect();
        let mut upstream: Vec<&str> = ZENOH_LINK_PROTOCOLS.to_vec();
        catalogued.sort_unstable();
        upstream.sort_unstable();
        assert_eq!(
            catalogued, upstream,
            "the scheme catalogue and the upstream link list have diverged"
        );

        for (scheme, feature) in LINK_SCHEME_FEATURES {
            assert!(
                MANIFEST
                    .lines()
                    .any(|line| line.starts_with(&format!("{feature} ="))),
                "{scheme} names the {feature} feature, which this crate does not declare"
            );
            assert_eq!(link_scheme_feature(scheme), Some(*feature));
        }
        // A scheme wz has no backend for at all would answer `None`, and the
        // defect message would then end without a flag rather than with a
        // wrong one.
        assert_eq!(link_scheme_feature("carrier-pigeon"), None);

        // The message an operator reads must carry the flag, not merely the
        // diagnosis — that is the half the 2026-08-23 external review needed
        // and did not have.
        let named = ConfigDefect::ProtocolNotCompiledIn {
            endpoint: String::from("unixsock-stream//tmp/z.sock"),
            protocol: String::from("unixsock-stream"),
        }
        .to_string();
        assert!(
            named.contains("transport-link-unixsock"),
            "the defect did not name the feature: {named}"
        );
    }

    // R2070 — the census the binary actually answers with must agree with the
    // module's, which is what makes `compiled_in_link_schemes()` safe to call
    // from a caller that has no session-open module to reach into.
    #[test]
    fn the_always_compiled_accessor_answers_what_the_module_holds() {
        #[cfg(all(feature = "transport-link-tcp", feature = "transport-unicast"))]
        assert_eq!(
            crate::compiled_in_link_schemes(),
            crate::session_open::COMPILED_IN_LINK_SCHEMES
        );
        #[cfg(not(all(feature = "transport-link-tcp", feature = "transport-unicast")))]
        assert!(
            crate::compiled_in_link_schemes().is_empty(),
            "a build with no session-open module can open no scheme at all"
        );
    }

    #[test]
    fn wz_transport_parameters_carry_onto_the_emitted_node() {
        // Built by FIELD ASSIGNMENT, not a struct literal with
        // `..Default::default()`: under `routing-peer` `WzConfig` carries a
        // PRIVATE `interceptors` field, and the literal form then fails to
        // compile with E0451 — on that feature arm only, which is why Layer
        // C1bf's per-crate `--all-features` clippy is where it surfaces and
        // why clippy's `field_reassign_with_default` suggestion must be
        // declined here.
        #[allow(clippy::field_reassign_with_default)]
        let wz = {
            let mut wz = crate::config::WzConfig::default();
            wz.whatami = WhatAmI::Router;
            wz.batch_size = 4096;
            wz.lease_ms = 7000;
            wz
        };
        let z = ZenohNodeConfig::from_wz(&wz);
        assert_eq!(z.mode, WhatAmI::Router);
        assert_eq!(z.batch_size, wz.batch_size);
        assert_eq!(z.lease_ms, wz.lease_ms);
        let json = z.to_json5();
        assert!(json.contains("\"mode\": \"router\""), "{json}");
        assert!(
            json.contains(&format!("\"batch_size\": {}", wz.batch_size)),
            "{json}"
        );
        assert!(
            json.contains(&format!("\"lease\": {}", wz.lease_ms)),
            "{json}"
        );
    }

    /// The emit and the ingest are inverses over [`HONOURED_CONFIG_KEYS`].
    ///
    /// This is the property that keeps the two directions from drifting: a
    /// field added to the emitter and forgotten in the reader (or the reverse)
    /// breaks it without anyone having to remember to write a case for that
    /// field.
    #[test]
    fn emit_and_ingest_are_inverses_over_the_honoured_keys() {
        for original in [
            ZenohNodeConfig::default(),
            ZenohNodeConfig::default()
                .listening_on("tcp/127.0.0.1:7447")
                .listening_on("ws/0.0.0.0:8000")
                .connecting_to("quic/example:7447")
                .with_multicast_scouting(false)
                .with_adminspace(true, true),
            ZenohNodeConfig {
                mode: WhatAmI::Router,
                batch_size: 4096,
                lease_ms: 7000,
                max_links: 4,
                qos: false,
                lowlatency: true,
                compression: true,
                timestamping: true,
                ..ZenohNodeConfig::default()
            },
            // R311y845 — a node told to look somewhere else entirely, which is
            // the whole point of the three keys: emit it, read it back, and the
            // group has to survive the round trip.
            ZenohNodeConfig {
                scout_multicast_address: Some(String::from("224.0.0.99:7999")),
                scout_multicast_interface: Some(String::from("eth0")),
                scout_multicast_ttl: Some(4),
                ..ZenohNodeConfig::default()
            },
        ] {
            let ingest = ZenohNodeConfig::from_json5(&original.to_json5())
                .unwrap_or_else(|e| panic!("{e} for {original:?}"));
            assert_eq!(ingest.config, original);
            // Nothing wz emits may be a key wz cannot read back.
            assert!(ingest.ignored.is_empty(), "{:?}", ingest.ignored);
        }
    }

    /// R311y845 — a scouting address that is not `<ip>:<port>` is REFUSED, not
    /// carried.
    ///
    /// Upstream types the key as a `SocketAddr` and so refuses the same
    /// documents at deserialization; keeping that refusal is what stops the
    /// worst outcome this key has, which is not a crash but a node that starts,
    /// prints `scouting/multicast/address` among its honoured keys, and is
    /// alone on the network because the value never resolved to a group.
    ///
    /// The PORT case is the one worth naming: `"224.0.0.99"` is a perfectly
    /// good address and a useless scouting socket, and it is exactly what an
    /// operator abbreviating the key would write.
    #[test]
    fn a_scouting_address_that_is_not_a_socket_is_refused_rather_than_carried() {
        for bad in [
            r#"{ "scouting": { "multicast": { "address": "224.0.0.99" } } }"#,
            r#"{ "scouting": { "multicast": { "address": "not-an-address" } } }"#,
            r#"{ "scouting": { "multicast": { "address": "" } } }"#,
        ] {
            let err = ZenohNodeConfig::from_json5(bad).unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigIngestError::WrongType {
                        path: "scouting/multicast/address",
                        ..
                    }
                ),
                "{bad} -> {err:?}"
            );
        }
        // The CONTROL: the same key with a port parses, so the refusals above
        // are attributable to the malformed value and not to the key itself
        // being unreadable.
        let ok = ZenohNodeConfig::from_json5(
            r#"{ "scouting": { "multicast": { "address": "224.0.0.99:7999" } } }"#,
        )
        .unwrap();
        assert_eq!(
            ok.config.scout_multicast_address.as_deref(),
            Some("224.0.0.99:7999")
        );
    }

    /// Every entry of [`HONOURED_CONFIG_KEYS`] is genuinely READ.
    ///
    /// The table is the SSOT for the ignored partition, so an entry the reader
    /// does not actually consult would report itself honoured while doing
    /// nothing — the exact failure the ignored list exists to prevent. Each
    /// key is driven to a value that differs from the default and the ingest
    /// is required to move.
    #[test]
    fn every_honoured_key_is_actually_read() {
        let cases: &[(&str, &str)] = &[
            ("mode", r#"{ "mode": "client" }"#),
            (
                "connect/endpoints",
                r#"{ "connect": { "endpoints": ["tcp/1.2.3.4:7447"] } }"#,
            ),
            (
                "listen/endpoints",
                r#"{ "listen": { "endpoints": ["tcp/1.2.3.4:7447"] } }"#,
            ),
            (
                "scouting/multicast/enabled",
                r#"{ "scouting": { "multicast": { "enabled": false } } }"#,
            ),
            (
                "timestamping/enabled",
                r#"{ "timestamping": { "enabled": true } }"#,
            ),
            (
                "transport/unicast/max_links",
                r#"{ "transport": { "unicast": { "max_links": 7 } } }"#,
            ),
            (
                "transport/unicast/lowlatency",
                r#"{ "transport": { "unicast": { "lowlatency": true } } }"#,
            ),
            (
                "transport/unicast/qos/enabled",
                r#"{ "transport": { "unicast": { "qos": { "enabled": false } } } }"#,
            ),
            (
                "transport/unicast/compression/enabled",
                r#"{ "transport": { "unicast": { "compression": { "enabled": true } } } }"#,
            ),
            (
                "transport/link/tx/batch_size",
                r#"{ "transport": { "link": { "tx": { "batch_size": 4096 } } } }"#,
            ),
            (
                "transport/link/tx/lease",
                r#"{ "transport": { "link": { "tx": { "lease": 7000 } } } }"#,
            ),
            (
                "adminspace/enabled",
                r#"{ "adminspace": { "enabled": true } }"#,
            ),
            (
                "adminspace/permissions/read",
                r#"{ "adminspace": { "enabled": true, "permissions": { "read": false } } }"#,
            ),
            (
                "adminspace/permissions/write",
                r#"{ "adminspace": { "enabled": true, "permissions": { "write": true } } }"#,
            ),
            // R311y844 — the ten wz already acted on and could not be told.
            ("id", r#"{ "id": "0102030405060708" }"#),
            ("namespace", r#"{ "namespace": "demo/ns" }"#),
            (
                "queries_default_timeout",
                r#"{ "queries_default_timeout": 12000 }"#,
            ),
            (
                "routing/interests/timeout",
                r#"{ "routing": { "interests": { "timeout": 9000 } } }"#,
            ),
            ("scouting/timeout", r#"{ "scouting": { "timeout": 2500 } }"#),
            (
                "transport/multicast/qos/enabled",
                r#"{ "transport": { "multicast": { "qos": { "enabled": true } } } }"#,
            ),
            (
                "transport/shared_memory/enabled",
                r#"{ "transport": { "shared_memory": { "enabled": false } } }"#,
            ),
            (
                "transport/link/tls/root_ca_certificate",
                r#"{ "transport": { "link": { "tls": { "root_ca_certificate": "/etc/ca.pem" } } } }"#,
            ),
            (
                "transport/link/tls/listen_certificate",
                r#"{ "transport": { "link": { "tls": { "listen_certificate": "/etc/srv.pem" } } } }"#,
            ),
            (
                "transport/link/tls/listen_private_key",
                r#"{ "transport": { "link": { "tls": { "listen_private_key": "/etc/srv.key" } } } }"#,
            ),
            // R311y845 — WHERE the node looks. Each is driven to a value that
            // is NOT the upstream default (`224.0.0.224:7446` / `auto` / `1`),
            // so a reader that quietly kept the compiled-in group would fail
            // here instead of reporting the key honoured.
            (
                "scouting/multicast/address",
                r#"{ "scouting": { "multicast": { "address": "224.0.0.99:7999" } } }"#,
            ),
            (
                "scouting/multicast/interface",
                r#"{ "scouting": { "multicast": { "interface": "eth0" } } }"#,
            ),
            (
                "scouting/multicast/ttl",
                r#"{ "scouting": { "multicast": { "ttl": 4 } } }"#,
            ),
            // R311y846 — whether the node is FINDABLE. Driven to `false`, which
            // is the non-default (upstream's is `true`), so a reader that
            // hardcoded "always answer" fails here rather than reporting the key
            // honoured while ignoring what it said.
            (
                "scouting/multicast/listen",
                r#"{ "scouting": { "multicast": { "listen": false } } }"#,
            ),
            // R311y849 — the re-dial PACING. All three fields driven off
            // zenoh's own `1000 / 4000 / 2`, and the factor given as `1.5` so it
            // is a value `want_u64` could not have carried: a reader that read
            // the factor as an integer would fail here rather than report the
            // key honoured while rounding what the file said.
            (
                "connect/retry",
                r#"{ "connect": { "retry": { "period_init_ms": 250,
                                            "period_max_ms": 9000,
                                            "period_increase_factor": 1.5 } } }"#,
            ),
            // R2063 (open-debt item 214) — `peer-to-peer` and not `linkstate`,
            // because the default is `linkstate` and this gate requires the
            // ingest to MOVE. A fixture naming the default would report the key
            // honoured while proving only that the reader did not crash.
            (
                "routing/peer/mode",
                r#"{ "routing": { "peer": { "mode": "peer-to-peer" } } }"#,
            ),
        ];
        // The case list IS the table, so a key added to one and not the other
        // fails here rather than going unmeasured.
        let covered: Vec<&str> = cases.iter().map(|(k, _)| *k).collect();
        assert_eq!(covered, HONOURED_CONFIG_KEYS.to_vec());

        for (key, doc) in cases {
            let ingest = ZenohNodeConfig::from_json5(doc).unwrap_or_else(|e| panic!("{key}: {e}"));
            assert!(
                ingest.ignored.is_empty(),
                "{key} reported ignored: {:?}",
                ingest.ignored
            );
            assert!(
                ingest.named.contains(key),
                "{key} was read but not reported as named: {:?}",
                ingest.named
            );
            assert_ne!(
                ingest.config,
                ZenohNodeConfig::default(),
                "{key} parsed but changed nothing"
            );
        }
    }

    /// A resolved value is not an instruction: `qos` reads `true` out of a
    /// document that never mentioned it, so a caller that turns a config into
    /// actions has to be able to tell the two apart.
    #[test]
    fn what_the_document_said_is_distinguishable_from_what_it_defaulted_to() {
        let quiet = ZenohNodeConfig::from_json5(r#"{ "mode": "peer" }"#).unwrap();
        assert!(quiet.config.qos, "zenoh's default is on");
        assert_eq!(quiet.named, vec!["mode"]);

        let loud = ZenohNodeConfig::from_json5(
            r#"{ "mode": "peer", "transport": { "unicast": { "qos": { "enabled": true } } } }"#,
        )
        .unwrap();
        assert_eq!(loud.config, quiet.config, "the same resolved value ...");
        assert_eq!(
            loud.named,
            vec!["mode", "transport/unicast/qos/enabled"],
            "... reached two different ways"
        );

        // A null is zenoh's own spelling of "left unset", so it is not named.
        let nulled = ZenohNodeConfig::from_json5(
            r#"{ "mode": "peer", "transport": { "unicast": { "qos": { "enabled": null } } } }"#,
        )
        .unwrap();
        assert_eq!(nulled.named, vec!["mode"]);
    }

    /// An adminspace permission set without the `enabled` flag must be either
    /// honoured or reported — never silently dropped between the two.
    #[test]
    fn an_adminspace_permission_without_the_flag_is_not_lost_between_the_two_lists() {
        let ingest = ZenohNodeConfig::from_json5(
            r#"{ "adminspace": { "permissions": { "write": true } } }"#,
        )
        .unwrap();
        assert_eq!(
            ingest.config.adminspace,
            Some(AdminspaceConfig {
                read: true,
                write: true
            })
        );
        assert_eq!(ingest.named, vec!["adminspace/permissions/write"]);
        assert!(ingest.ignored.is_empty(), "{:?}", ingest.ignored);
    }

    /// A key wz does not model is APPLIED BY NOBODY and SAID OUT LOUD.
    #[test]
    fn an_unmodelled_key_is_reported_rather_than_refused_or_swallowed() {
        let ingest = ZenohNodeConfig::from_json5(
            r#"{
                mode: "peer",
                transport: {
                    link: {
                        tls: { root_ca_certificate: "/etc/ca.pem" },
                        tx: { batch_size: 4096, threads: 8 },
                    },
                },
                queries_default_timeout: 10000,
                plugins: {},
            }"#,
        )
        .unwrap();
        // Refusing would make the reader useless against a real config.
        assert_eq!(ingest.config.batch_size, 4096);
        // Swallowing would let an operator believe a key took effect.
        //
        // R311y844 — the FIXTURE is unchanged and two of its four reported keys
        // left this list, which is the whole of that round: `queries_default_timeout`
        // and the TLS root CA were never keys wz could not act on, only keys
        // the reader had not been taught, so they are honoured now and the
        // document's remaining two (`plugins`, `transport/link/tx/threads`)
        // carry the property this test is about.
        assert_eq!(
            ingest.ignored,
            vec!["plugins", "transport/link/tx/threads",]
        );
    }

    /// R311y849 — `connect/retry` is ONE census leaf holding THREE numbers, so
    /// a file may state any subset of them. What a partial block must not do is
    /// leave the unstated fields at zero: that is not a slower retry, it is a
    /// re-dial hot loop, and it is the value `RetryPolicy`'s hand-written
    /// `Default` exists to refuse.
    ///
    /// The three cases below are the three arms that can produce a policy, and
    /// the fourth — a block naming nothing — has to stay `None`, because that is
    /// the difference between "the file said nothing" and "the file asked for
    /// zenoh's defaults", which `to_json5` and the argv expansion both act on.
    #[test]
    fn a_partial_connect_retry_block_fills_the_rest_from_zenoh_defaults() {
        let base = crate::retry_period::RetryPolicy::ZENOH_DEFAULT;

        let only_init =
            ZenohNodeConfig::from_json5(r#"{ "connect": { "retry": { "period_init_ms": 25 } } }"#)
                .expect("a lone period_init_ms is a valid block");
        assert_eq!(
            only_init.config.connect_retry,
            Some(crate::retry_period::RetryPolicy {
                period_init_ms: 25,
                period_max_ms: base.period_max_ms,
                period_increase_factor: base.period_increase_factor,
            }),
            "an unstated ceiling must fall back to zenoh's, never to 0"
        );
        assert!(
            only_init.named.contains(&"connect/retry"),
            "any stated field means the file HAS an instruction here"
        );

        let only_factor = ZenohNodeConfig::from_json5(
            r#"{ "connect": { "retry": { "period_increase_factor": 1 } } }"#,
        )
        .expect("a lone factor is a valid block");
        assert_eq!(
            only_factor.config.connect_retry,
            Some(crate::retry_period::RetryPolicy {
                period_init_ms: base.period_init_ms,
                period_max_ms: base.period_max_ms,
                // `1` arrives as an integer token and must still read as a float.
                period_increase_factor: 1.0,
            })
        );

        // The subtree is named ONCE however many of its fields the file states —
        // the census denominator has one leaf here, not three.
        let all_three = ZenohNodeConfig::from_json5(
            r#"{ "connect": { "retry": { "period_init_ms": 1, "period_max_ms": 2,
                                        "period_increase_factor": 3 } } }"#,
        )
        .expect("a full block is valid");
        assert_eq!(
            all_three
                .named
                .iter()
                .filter(|k| **k == "connect/retry")
                .count(),
            1
        );

        // And the absence case: no `connect` block at all leaves `None`, which
        // is a different fact from zenoh's defaults even though it BEHAVES as
        // them.
        let silent = ZenohNodeConfig::from_json5(r#"{ "mode": "peer" }"#).expect("valid");
        assert_eq!(silent.config.connect_retry, None);
        assert!(!silent.named.contains(&"connect/retry"));
    }

    /// R311y849 — a typo INSIDE the honoured `connect/retry` subtree must be
    /// reported, not swallowed by the rule that lets the subtree's real fields
    /// through.
    ///
    /// The upstream behaviour this sits against was measured, not assumed: a
    /// real zenohd given `connect: { retry: { period_init_mss: 250 } }` STARTS,
    /// resolves `retry` to three nulls, and says nothing. So wz does not refuse
    /// it either -- the acceptance boundary stays upstream's -- and the whole
    /// value wz adds here is the sentence upstream never prints.
    #[test]
    fn a_typo_inside_the_retry_block_is_reported_rather_than_absorbed() {
        let ingest = ZenohNodeConfig::from_json5(
            r#"{ "connect": { "retry": { "period_init_ms": 25, "period_init_mss": 250 } } }"#,
        )
        .expect("upstream starts on this, so wz must not refuse it");
        assert_eq!(
            ingest.ignored,
            vec![String::from("connect/retry/period_init_mss")],
            "the misspelling did nothing and the operator has to be told"
        );
        assert_eq!(
            ingest
                .config
                .connect_retry
                .expect("the correctly spelled field still applies")
                .period_init_ms,
            25
        );
    }

    /// R311y849 — a factor that cannot be a number is a TYPE error here, while a
    /// factor that is a number but not a policy anyone means (below 1.0) is left
    /// to `--connect-retry`'s parser. Two boundaries, one owner each; this pins
    /// which one this layer keeps.
    #[test]
    fn a_non_finite_retry_factor_is_refused_but_a_shrinking_one_is_passed_on() {
        assert!(
            ZenohNodeConfig::from_json5(
                r#"{ "connect": { "retry": { "period_increase_factor": "fast" } } }"#
            )
            .is_err(),
            "a string is not a number"
        );
        let shrinking = ZenohNodeConfig::from_json5(
            r#"{ "connect": { "retry": { "period_increase_factor": 0.5 } } }"#,
        )
        .expect("0.5 is a number, so this layer carries it");
        assert_eq!(
            shrinking
                .config
                .connect_retry
                .expect("a policy")
                .period_increase_factor,
            0.5,
            "the refusal belongs to the flag parser, which every route goes \
             through -- deciding it twice is how the two answers drift"
        );
    }

    /// wz's ACCEPTANCE BOUNDARY is zenoh's: a key zenoh knows and wz does not
    /// honour is reported, a key NEITHER knows is refused.
    ///
    /// The second half is not symmetry for its own sake — it was measured. A
    /// real zenohd handed `transport: { link_unknown_to_wz: { .. } }` refuses
    /// to start: "unknown field `link_unknown_to_wz`, expected one of
    /// `unicast`, `multicast`, `link`, `shared_memory`, `auth`". A wz that
    /// accepted it would let a typo through on exactly the migration where the
    /// operator's old node caught it.
    #[test]
    fn a_key_stock_zenoh_refuses_is_refused_here_too() {
        for (doc, path) in [
            (
                r#"{ "transport": { "link_unknown_to_wz": { "nothing": true } } }"#,
                "transport/link_unknown_to_wz/nothing",
            ),
            // A near miss of a real key is the case that matters most.
            (r#"{ "modes": "peer" }"#, "modes"),
            (
                r#"{ "listen": { "endpoint": ["tcp/1.2.3.4:7447"] } }"#,
                "listen/endpoint",
            ),
        ] {
            assert_eq!(
                ZenohNodeConfig::from_json5(doc).unwrap_err(),
                ConfigIngestError::UnknownKey {
                    path: String::from(path)
                },
                "{doc}"
            );
        }

        // The descendant rule: an upstream key that resolves to `null` is an
        // opaque SUBTREE, and a config filling it in carries leaves below the
        // path the resolved tree shows. Refusing those would refuse valid
        // configs.
        //
        // R311y849 — `connect/retry/period_init_ms` LEFT this expectation, and
        // the departure is the round's result rather than a fixture repair: the
        // subtree is honoured now, so its fields are applied and reporting them
        // as ignored would be the false statement. The two that remain are still
        // filled-in subtrees of keys wz does not honour, which is what this
        // assertion is actually for -- a honoured subtree and an unhonoured one
        // must partition the same document differently, and this now shows both
        // in one call.
        let filled = ZenohNodeConfig::from_json5(
            r#"{ "connect": { "retry": { "period_init_ms": 1000 } },
                 "metadata": { "name": "strawberry" },
                 "plugins": { "rest": { "http_port": 8000 } } }"#,
        )
        .expect("a filled-in upstream subtree is a valid config");
        assert_eq!(
            filled.ignored,
            vec!["metadata/name", "plugins/rest/http_port"]
        );
        assert_eq!(
            filled
                .config
                .connect_retry
                .expect("the honoured subtree applied")
                .period_init_ms,
            1000
        );
    }

    /// The two key lists are the upstream surface, so they must be disjoint and
    /// each internally unique — a path in both would be honoured and reported
    /// at once.
    #[test]
    fn the_two_halves_of_the_upstream_surface_do_not_overlap() {
        let mut all: Vec<&str> = HONOURED_CONFIG_KEYS
            .iter()
            .chain(UNHONOURED_UPSTREAM_CONFIG_KEYS)
            .copied()
            .collect();
        let total = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), total, "a path appears in both halves");
        // Pinned as a value so a silently shrinking surface is visible here as
        // well as in the zenohd census.
        assert_eq!(total, 111);
        let mut unhonoured = UNHONOURED_UPSTREAM_CONFIG_KEYS.to_vec();
        unhonoured.sort_unstable();
        assert_eq!(
            unhonoured,
            UNHONOURED_UPSTREAM_CONFIG_KEYS.to_vec(),
            "the unhonoured list is compared against a sorted census, so it \
             has to be sorted itself"
        );
    }

    /// zenoh writes `null` for every key it left unset, so a null is the
    /// ABSENCE of an instruction, not an instruction to zero the field.
    #[test]
    fn a_null_at_a_honoured_key_leaves_zenohs_default_rather_than_erasing_it() {
        let ingest = ZenohNodeConfig::from_json5(
            r#"{ "mode": "peer",
                 "transport": { "link": { "tx": { "batch_size": null, "lease": null } },
                                "unicast": { "max_links": null } } }"#,
        )
        .unwrap();
        assert_eq!(ingest.config, ZenohNodeConfig::default());
        assert!(ingest.config.validate().is_empty());
        // A null is not an unmodelled key either — wz knows that key.
        assert!(ingest.ignored.is_empty(), "{:?}", ingest.ignored);
    }

    /// A key wz DOES honour, carrying a value it cannot mean, is a hard error
    /// rather than a default — that one the operator has to see.
    #[test]
    fn a_honoured_key_with_an_impossible_value_is_refused_at_the_key() {
        for (doc, want) in [
            (
                r#"{ "mode": "gateway" }"#,
                ConfigIngestError::UnknownMode {
                    value: "gateway".into(),
                },
            ),
            (
                r#"{ "mode": 5 }"#,
                ConfigIngestError::WrongType {
                    path: "mode",
                    expected: "a string",
                },
            ),
            (
                r#"{ "listen": { "endpoints": "tcp/1.2.3.4:7447" } }"#,
                ConfigIngestError::WrongType {
                    path: "listen/endpoints",
                    expected: "an array of endpoint strings",
                },
            ),
            (
                r#"{ "transport": { "unicast": { "qos": { "enabled": 1 } } } }"#,
                ConfigIngestError::WrongType {
                    path: "transport/unicast/qos/enabled",
                    expected: "a boolean",
                },
            ),
            (
                // 65536 is one past a u16 — zenoh's own ceiling for the field.
                r#"{ "transport": { "link": { "tx": { "batch_size": 65536 } } } }"#,
                ConfigIngestError::OutOfRange {
                    path: "transport/link/tx/batch_size",
                    value: "65536".into(),
                },
            ),
        ] {
            assert_eq!(ZenohNodeConfig::from_json5(doc).unwrap_err(), want, "{doc}");
        }
        assert!(matches!(
            ZenohNodeConfig::from_json5("[]").unwrap_err(),
            ConfigIngestError::NotAnObject
        ));
        assert!(matches!(
            ZenohNodeConfig::from_json5("{").unwrap_err(),
            ConfigIngestError::Syntax(_)
        ));
    }

    /// An `adminspace` BLOCK is not a field: absent, present-and-off, and
    /// present-and-on are three different instructions.
    #[test]
    fn the_adminspace_block_keeps_its_three_states() {
        assert_eq!(
            ZenohNodeConfig::from_json5("{}").unwrap().config.adminspace,
            None
        );
        assert_eq!(
            ZenohNodeConfig::from_json5(r#"{ "adminspace": { "enabled": false } }"#)
                .unwrap()
                .config
                .adminspace,
            None
        );
        // zenoh's own defaults for the permissions when the block says only
        // `enabled` (DEFAULT_CONFIG.json5: read true, write false).
        assert_eq!(
            ZenohNodeConfig::from_json5(r#"{ "adminspace": { "enabled": true } }"#)
                .unwrap()
                .config
                .adminspace,
            Some(AdminspaceConfig {
                read: true,
                write: false
            })
        );
    }

    /// The reader takes the JSON5 an operator's file is actually written in,
    /// not the strict-JSON subset wz's own emitter happens to produce.
    #[test]
    fn a_hand_written_json5_config_reads_the_same_as_its_strict_json_twin() {
        let json5 = ZenohNodeConfig::from_json5(
            r#"
            /// The operator's own file, comments and all.
            {
              mode: 'router',           // single quotes are JSON5
              listen: { endpoints: ["tcp/0.0.0.0:7447",], },  /* trailing comma */
            }
            "#,
        )
        .unwrap();
        let strict = ZenohNodeConfig::from_json5(
            r#"{"mode": "router", "listen": {"endpoints": ["tcp/0.0.0.0:7447"]}}"#,
        )
        .unwrap();
        assert_eq!(json5, strict);
        assert_eq!(json5.config.mode, WhatAmI::Router);
        assert_eq!(json5.config.listen, vec!["tcp/0.0.0.0:7447".to_string()]);
    }

    #[test]
    fn the_zero_sentinel_of_an_unpopulated_wz_config_is_not_emitted() {
        // A default `WzConfig` carries `0` for the handshake-fixed fields (it
        // has not opened anything yet). Emitting that produces a config zenoh
        // accepts and cannot run, so the sentinel takes zenoh's default.
        let wz = crate::config::WzConfig::default();
        assert_eq!(wz.batch_size, 0);
        let z = ZenohNodeConfig::from_wz(&wz);
        assert_eq!(z.batch_size, 65_535);
        assert_eq!(z.lease_ms, 10_000);
        assert!(z.validate().is_empty(), "{:?}", z.validate());
    }

    // ── R2075 (open-debt item 499) — upstream's mode-dependent spelling ──
    //
    // Each witness below states the spelling that was REFUSED and the one that
    // already worked, in the same test. The pairing matters more than usual
    // here: the failure this round removes is not a wrong value, it is a node
    // that does not start, so a reader that merely stopped erroring would look
    // fixed while resolving the wrong entry.

    /// Build `{ mode: "router", <path as nested objects>: <value> }`.
    ///
    /// From the slash path rather than hand-written per key, so the sweep below
    /// can be driven by the constant instead of by a second list that would
    /// drift from it.
    fn doc_with(path: &str, value: &str) -> String {
        let segs: Vec<&str> = path.split('/').collect();
        let mut out = String::from("{ mode: \"router\", ");
        for (i, seg) in segs.iter().enumerate() {
            out.push_str(seg);
            out.push_str(": ");
            if i + 1 < segs.len() {
                out.push_str("{ ");
            }
        }
        out.push_str(value);
        for _ in 1..segs.len() {
            out.push_str(" }");
        }
        out.push_str(" }");
        out
    }

    /// A `{ router, peer, client }` table resolves to THIS node's own entry.
    ///
    /// The same bytes handed to three nodes of different modes must yield three
    /// different answers — that is what makes this a RESOLUTION and not a parse.
    /// A reader that returned the first entry, or the whole table, would pass a
    /// test that only asked whether it stopped erroring.
    #[test]
    fn a_mode_table_resolves_to_this_nodes_own_entry() {
        const TABLE: &str = r#"{ mode: "MODE",
             listen: { endpoints: { router: ["tcp/10.0.0.1:7447"],
                                    peer:   ["tcp/10.0.0.2:7447"],
                                    client: ["tcp/10.0.0.3:7447"] } } }"#;
        for (mode, want) in [
            ("router", "tcp/10.0.0.1:7447"),
            ("peer", "tcp/10.0.0.2:7447"),
            ("client", "tcp/10.0.0.3:7447"),
        ] {
            let ingest = ZenohNodeConfig::from_json5(&TABLE.replace("MODE", mode))
                .unwrap_or_else(|e| panic!("{mode}: {e:?}"));
            assert_eq!(ingest.config.listen, vec![String::from(want)], "{mode}");
            assert!(ingest.named.contains(&"listen/endpoints"), "{mode}");
        }

        // The `Unique` spelling, beside it and unchanged.
        let plain = ZenohNodeConfig::from_json5(
            r#"{ mode: "router", listen: { endpoints: ["tcp/10.0.0.9:7447"] } }"#,
        )
        .expect("the plain spelling still reads");
        assert_eq!(plain.config.listen, vec![String::from("tcp/10.0.0.9:7447")]);
    }

    /// A table that names no entry for this node is NO INSTRUCTION, not an
    /// error — the same fallback a real zenohd takes, whose `.get(whatami)`
    /// returns `None` and leaves the key at its default.
    #[test]
    fn a_mode_table_without_this_nodes_entry_is_no_instruction() {
        let ingest = ZenohNodeConfig::from_json5(
            r#"{ mode: "client", listen: { endpoints: { router: ["tcp/10.0.0.1:7447"] } } }"#,
        )
        .expect("a table that does not mention clients is not an error");
        assert!(
            ingest.config.listen.is_empty(),
            "{:?}",
            ingest.config.listen
        );
        assert!(!ingest.named.contains(&"listen/endpoints"));
    }

    /// An object whose fields are not ALL mode names is REFUSED rather than read
    /// as a value. `rooter:` is one keystroke from `router:`, and a reader that
    /// shrugged at it would let the operator believe the setting took effect.
    ///
    /// ⛔ The MIXED table is the case that carries this test, and it was added
    /// because a mutation found the first cut vacuous: with only the all-wrong
    /// table below, weakening the check from `all` to `any` changed nothing,
    /// because no field was a mode name either way. A typo NEXT TO a valid entry
    /// is also the realistic operator mistake — the one where a config half
    /// works and the half that does not is silent.
    #[test]
    fn a_table_whose_fields_are_not_all_modes_is_refused() {
        for doc in [
            r#"{ mode: "router", listen: { endpoints: { rooter: ["tcp/10.0.0.1:7447"] } } }"#,
            r#"{ mode: "router", listen: { endpoints: { router: ["tcp/10.0.0.1:7447"],
                                                        rooter: ["tcp/10.0.0.2:7447"] } } }"#,
        ] {
            let err = match ZenohNodeConfig::from_json5(doc) {
                Ok(read) => panic!("`rooter` is not a mode, and it read anyway: {read:?}\n{doc}"),
                Err(e) => e,
            };
            assert!(
                matches!(
                    err,
                    ConfigIngestError::WrongType {
                        path: "listen/endpoints",
                        ..
                    }
                ),
                "{err:?}\n{doc}"
            );
        }
    }

    /// EVERY key upstream declares mode-dependent takes both spellings, swept
    /// from the constant rather than from a list written here.
    ///
    /// A key added to `MODE_DEPENDENT_CONFIG_KEYS` without a reader that
    /// resolves its table reds this, and so does one that is not honoured at all
    /// — the two halves of "this constant describes the reader".
    #[test]
    fn every_mode_dependent_key_takes_both_spellings() {
        assert!(
            !MODE_DEPENDENT_CONFIG_KEYS.is_empty(),
            "an empty population is green for the wrong reason"
        );
        for key in MODE_DEPENDENT_CONFIG_KEYS {
            assert!(
                HONOURED_CONFIG_KEYS.contains(key),
                "{key} is declared mode-dependent and is not honoured at all"
            );
            let value = match *key {
                "connect/endpoints" | "listen/endpoints" => "[\"tcp/10.0.0.1:7447\"]",
                _ => "true",
            };
            let plain = doc_with(key, value);
            ZenohNodeConfig::from_json5(&plain)
                .unwrap_or_else(|e| panic!("{key} plain spelling: {e:?}\n{plain}"));
            let table = doc_with(key, &format!("{{ router: {value} }}"));
            ZenohNodeConfig::from_json5(&table)
                .unwrap_or_else(|e| panic!("{key} table spelling: {e:?}\n{table}"));
        }
    }

    // ── R2078 (open-debt item 501) — the acceptance boundary, tightened ──

    /// A typo BELOW an unhonoured key is refused, and the shapes that
    /// legitimately deepen are still read.
    ///
    /// The pair is the whole trade. Tightening is only worth doing if it stops
    /// exactly what a real zenohd stops and nothing else: refusing a document
    /// upstream accepts would stop a working deployment, which is a worse
    /// failure than letting a typo through. Both halves are measured against a
    /// real zenohd by `wz_reads_a_stock_zenohd_config`'s boundary leg; these are
    /// the same claims where a unit test can hold them.
    #[test]
    fn a_typo_below_an_unhonoured_key_is_refused_and_the_deepenable_shapes_are_not() {
        for doc in [
            // Nothing in wz READS these, so before this round nothing
            // type-checked them either and the prefix rule said yes.
            r#"{ mode: "peer", access_control: { enabled: { xyz: true } } }"#,
            r#"{ mode: "peer", transport: { auth: { usrpwd: { user: { xyz: 1 } } } } }"#,
            r#"{ mode: "peer", transport: { link: { tls: { root_ca_certificat: "/x" } } } }"#,
        ] {
            let err = match ZenohNodeConfig::from_json5(doc) {
                Ok(read) => panic!("a key upstream refuses was accepted: {read:?}\n{doc}"),
                Err(e) => e,
            };
            assert!(
                matches!(err, ConfigIngestError::UnknownKey { .. }),
                "{err:?}\n{doc}"
            );
        }

        // The controls: each deepens BELOW a key the surface names, and a real
        // zenohd starts on every one of them.
        for doc in [
            r#"{ mode: "peer", plugins: { rest: { http_port: 8000 } } }"#,
            r#"{ mode: "peer", metadata: { name: "strawberry" } }"#,
            r#"{ mode: "peer", connect: { retry: { period_init_mss: 250 } } }"#,
            r#"{ mode: "peer", connect: { timeout_ms: { router: 1000, peer: 2000 } } }"#,
            r#"{ mode: "peer", scouting: { gossip: { autoconnect_strategy:
                 { peer: { to_router: "always" } } } } }"#,
        ] {
            ZenohNodeConfig::from_json5(doc)
                .unwrap_or_else(|e| panic!("a document zenohd accepts was refused: {e:?}\n{doc}"));
        }
    }

    /// Every key in the deepenable exception list is one the census surface
    /// actually names.
    ///
    /// An entry that names nothing would widen the boundary for a path upstream
    /// has no key at, which is the direction that quietly re-opens what this
    /// round closed. The list is also required NON-EMPTY: an empty one would
    /// make the boundary exact everywhere and refuse `plugins.rest.http_port`.
    #[test]
    fn every_deepenable_key_is_one_the_upstream_surface_names() {
        assert!(!DEEPENABLE_UPSTREAM_KEYS.is_empty());
        for key in DEEPENABLE_UPSTREAM_KEYS {
            assert!(
                HONOURED_CONFIG_KEYS.contains(key) || UNHONOURED_UPSTREAM_CONFIG_KEYS.contains(key),
                "{key} is an exception to the boundary and is not in the surface at all"
            );
        }
        // And every key upstream declares mode-dependent must be here: the table
        // spelling is legal on all of them, so a missing one is a refusal wz
        // would issue and zenohd would not.
        for key in MODE_DEPENDENT_CONFIG_KEYS {
            assert!(
                DEEPENABLE_UPSTREAM_KEYS.contains(key),
                "{key} takes a `{{ router, peer, client }}` table and the boundary \
                 would refuse it"
            );
        }
    }

    /// Build `{ mode: "peer", <path as nested objects>: <value> }`.
    fn nested(path: &str, value: &str) -> String {
        let segs: Vec<&str> = path.split('/').collect();
        let mut out = String::from("{ mode: \"peer\", ");
        for (i, seg) in segs.iter().enumerate() {
            out.push_str(seg);
            out.push_str(": ");
            if i + 1 < segs.len() {
                out.push_str("{ ");
            }
        }
        out.push_str(value);
        for _ in 1..segs.len() {
            out.push_str(" }");
        }
        out.push_str(" }");
        out
    }

    /// EVERY surface key outside the deepenable list refuses a deeper shape.
    ///
    /// R2079 (open-debt item 502) — the exhaustive half, on wz's side, and it is
    /// here rather than in the zenohd lane because it needs no oracle and can
    /// therefore cover the WHOLE surface instead of a sample. A key that quietly
    /// gained prefix-acceptance would show up here as an acceptance, which is
    /// the direction that re-opens R2078.
    ///
    /// The value is `{ zzz_not_a_mode: 1 }` on purpose: it is not a mode name, so
    /// a mode-dependent key refuses it too. The claim is about the SHAPE being
    /// rejected at the boundary, not about the value being right.
    #[test]
    fn every_surface_key_outside_the_deepenable_list_refuses_a_deeper_shape() {
        let mut checked = 0usize;
        for key in HONOURED_CONFIG_KEYS
            .iter()
            .chain(UNHONOURED_UPSTREAM_CONFIG_KEYS)
        {
            if DEEPENABLE_UPSTREAM_KEYS.contains(key) {
                continue;
            }
            let doc = nested(key, "{ zzz_not_a_mode: 1 }");
            let err = match ZenohNodeConfig::from_json5(&doc) {
                Ok(read) => panic!("{key}: a deeper shape was accepted: {read:?}\n{doc}"),
                Err(e) => e,
            };
            assert!(
                matches!(err, ConfigIngestError::UnknownKey { .. }),
                "{key}: refused, but not at the boundary: {err:?}\n{doc}"
            );
            checked += 1;
        }
        assert!(
            checked > 80,
            "only {checked} key(s) were checked; the surface constants moved and \
             this sweep is no longer covering them"
        );
    }

    /// A mode table's own leaves are NOT reported as keys wz does not honour.
    ///
    /// Saying `listen/endpoints/router` was ignored would contradict the
    /// resolution that just consumed it, and would send an operator looking for
    /// a flag that already exists.
    #[test]
    fn a_mode_tables_leaves_are_not_reported_as_unhonoured() {
        let ingest = ZenohNodeConfig::from_json5(
            r#"{ mode: "router", listen: { endpoints: { router: ["tcp/10.0.0.1:7447"] } } }"#,
        )
        .expect("a mode table reads");
        assert!(ingest.ignored.is_empty(), "{:?}", ingest.ignored);
    }
}
