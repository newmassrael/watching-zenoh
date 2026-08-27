// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

// `pub use`, not a private import: the two `autoconnect` fields below are typed
// with these, so a consumer of this module has to be able to NAME them —
// R311y428's rule (a public constructor whose parameter type is unnameable
// through the facade cannot be called there).
pub use wz_codecs::whatami::{WhatAmI, WhatAmIMatcher};
// R2141 (open-debt item 223) — the policy types the two `autoconnect` keys
// resolve INTO, imported rather than mirrored here. A second two-spelling
// vocabulary in the reader is exactly the drift this module removes elsewhere
// (`mode` is matched against `WhatAmI::to_str` "so the two directions cannot
// disagree about a spelling"), and the reader's whole job is to produce the
// typed value a consumer installs. `wz-routing-graph` is a leaf crate over
// `wz-codecs`, so the `zenoh-config-emit` feature pulling it adds no cycle; no
// footprint preset carries that feature.
pub use wz_routing_graph::{AutoConnectStrategies, AutoConnectStrategy};
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
    /// R2117 (open-debt item 498) — an endpoint DECLARED to be listened on by
    /// a node outside this set, that no node in the set dials.
    ///
    /// The control that makes declaring one safe. Widening the listener set
    /// from argv can only ever silence a `DanglingConnectTarget`, so without
    /// this a careless `--check-topology-external` would turn a real typo
    /// quiet -- the false-positive direction inverting, which is what the
    /// register item flagged as not-for-one-round. Every declaration has to
    /// EARN its place by answering something, so over-declaring is reported
    /// rather than free.
    UnusedExternalListener {
        /// The endpoint as declared.
        endpoint: String,
    },
    /// R2117 (open-debt item 498) — an endpoint declared external that a node
    /// IN the set already listens on.
    ///
    /// Not silenced and not merely redundant: the operator has said the set is
    /// a fragment at a point where it is not, so the report would credit an
    /// outside node for a dial this deployment answers itself. A reader acting
    /// on that goes looking for a machine that has nothing to do with it.
    ExternalShadowsListener {
        /// The endpoint as declared.
        endpoint: String,
        /// The node in the set that already answers it.
        node: String,
    },
    /// R2117 (open-debt item 498) — a declared external endpoint that does not
    /// parse as one.
    ///
    /// Reported HERE, unlike a malformed endpoint inside a config: that one is
    /// `ZenohNodeConfig::validate`'s to name and saying it twice would make one
    /// typo look like two faults. A string typed at argv has no per-node pass
    /// to be named by, so silence would be the only alternative -- and a
    /// declaration this pass cannot read is one that widens nothing while the
    /// operator believes it did.
    MalformedExternalListener {
        /// The endpoint as declared.
        endpoint: String,
    },
}

/// R2117 (open-debt item 498) — one dial that a DECLARED EXTERNAL listener
/// answered rather than a node in the set.
///
/// Not a defect and not nothing. A green verdict over a fragment rests on an
/// assumption the operator supplied at argv, and a report that swallowed it
/// would read exactly like a closed deployment that checks out on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternallyAnswered {
    /// Which node dials it.
    pub node: String,
    /// The connect endpoint as given.
    pub endpoint: String,
}

/// R2117 (open-debt item 498) — what a set verdict says when the set is a
/// FRAGMENT: the defects, and the assumptions the answer rests on.
///
/// Two fields rather than one list, because they are read differently: a
/// defect stops the deployment and an assumption is shown beside a verdict
/// that passed. Folding the second into the first would fail a deployment for
/// being a fragment, which is the state this whole axis exists to make
/// checkable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyVerdict {
    /// Every reason the set cannot form its network.
    pub defects: Vec<TopologyDefect>,
    /// Every dial an external declaration answered, in slice order.
    pub externally_answered: Vec<ExternallyAnswered>,
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
            TopologyDefect::UnusedExternalListener { endpoint } => write!(
                f,
                "{endpoint:?} was declared external and no node here dials it, \
                 so it widens the set without answering anything"
            ),
            TopologyDefect::ExternalShadowsListener { endpoint, node } => write!(
                f,
                "{endpoint:?} was declared external and {node} in this set \
                 already listens on it"
            ),
            TopologyDefect::MalformedExternalListener { endpoint } => write!(
                f,
                "{endpoint:?} was declared external and is not an endpoint this \
                 reader can parse"
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
    validate_topology_with_external(nodes, &[]).defects
}

/// R2117 (open-debt item 498) — the same question asked of a FRAGMENT: a set
/// of nodes that attaches to one or more listeners this deployment does not
/// manage.
///
/// # Why the closed reading needed a widening rather than a softening
///
/// [`validate_topology`]'s contract is a closed deployment, and that is the
/// right default: "no node listens on it" naming no node *here* is what makes
/// a dangling dial findable at all. But the shape this project is measured
/// against -- a set of wz nodes attached to a stock zenohd somebody else runs
/// -- is a fragment, and against it every outward dial came back a defect. The
/// verdict was correct and the surface was unusable for the common case.
///
/// So the operator NAMES the outside listeners, and the set is widened by
/// exactly what they named. Nothing is resolved or probed: an external
/// endpoint is compared by the same `EndpointFace` rules a listener inside
/// the set is, so the verdict stays a property of the documents plus the argv.
///
/// # Why declaring one is not free
///
/// Widening the listener set can only silence a defect, so a careless
/// declaration turns a real typo quiet -- the false-positive direction
/// inverting, which is the trade the register item said one round must not
/// make alone. It is not made here either: the widening is BIDIRECTIONAL.
/// A declaration that answers no dial is [`TopologyDefect::UnusedExternalListener`],
/// one the set already answers is [`TopologyDefect::ExternalShadowsListener`],
/// and one that does not parse is [`TopologyDefect::MalformedExternalListener`].
/// Every dial an external declaration DID answer comes back in
/// [`TopologyVerdict::externally_answered`], so a green verdict shows the
/// assumption it rests on instead of reading like a closed deployment.
///
/// [`TopologyDefect::NoNodeAccepts`] is also conditioned on it, and has to be:
/// a set of clients attached to an external router is the single most ordinary
/// fragment there is, and reporting "every node is a client" at it would fail
/// the very deployment this widening exists to serve.
pub fn validate_topology_with_external(
    nodes: &[ZenohNodeConfig],
    external: &[String],
) -> TopologyVerdict {
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

    // R2117 (open-debt item 498) — the declared outside listeners, parsed by
    // the SAME reader the set's own listen endpoints go through. A string that
    // does not parse is named rather than dropped: dropping it would widen
    // nothing while the operator believes it did.
    let mut outside: Vec<(String, EndpointFace)> = Vec::new();
    for endpoint in external {
        match EndpointFace::of(endpoint) {
            Some(face) => outside.push((endpoint.clone(), face)),
            None => out.push(TopologyDefect::MalformedExternalListener {
                endpoint: endpoint.clone(),
            }),
        }
    }
    // A declaration the set already answers is reported against the node that
    // answers it, so the reader is sent to the config that makes the
    // declaration wrong rather than to the machine it names.
    for (endpoint, face) in &outside {
        if let Some((name, _)) = named.iter().find(|(_, node)| {
            node.listen.iter().any(|l| {
                EndpointFace::of(l).is_some_and(|listener| face.could_be_answered_by(&listener))
            })
        }) {
            out.push(TopologyDefect::ExternalShadowsListener {
                endpoint: endpoint.clone(),
                node: name.clone(),
            });
        }
    }

    let mut externally_answered = Vec::new();
    // "Accounted for", not "used". A declaration the set already answers is
    // reported as a SHADOW and must not also be reported as unused: the dial
    // it covers is satisfied internally, so it never reaches the outside pass.
    // Two findings for one mistake is the shape this file refuses one pass
    // over -- a malformed endpoint is named per node OR here, never both --
    // and the shadow is the more specific of the two, because it names the
    // config that makes the declaration wrong.
    let mut answered_something: Vec<bool> = outside
        .iter()
        .map(|(endpoint, _)| {
            out.iter().any(|d| {
                matches!(d, TopologyDefect::ExternalShadowsListener { endpoint: e, .. } if e == endpoint)
            })
        })
        .collect();
    for (name, node) in &named {
        for endpoint in &node.connect {
            let Some(face) = EndpointFace::of(endpoint) else {
                continue;
            };
            if listeners.iter().any(|l| face.could_be_answered_by(l)) {
                continue;
            }
            // Not answered here. Every external declaration that could answer
            // it is marked used -- all of them, not the first: two declarations
            // that both cover a dial are two claims about the deployment, and
            // crediting one would leave the other looking unused.
            let mut reached = false;
            for (at, (_, outside_face)) in outside.iter().enumerate() {
                if face.could_be_answered_by(outside_face) {
                    answered_something[at] = true;
                    reached = true;
                }
            }
            if reached {
                externally_answered.push(ExternallyAnswered {
                    node: name.clone(),
                    endpoint: endpoint.clone(),
                });
            } else {
                out.push(TopologyDefect::DanglingConnectTarget {
                    node: name.clone(),
                    endpoint: endpoint.clone(),
                });
            }
        }
    }
    for (at, (endpoint, _)) in outside.iter().enumerate() {
        if !answered_something[at] {
            out.push(TopologyDefect::UnusedExternalListener {
                endpoint: endpoint.clone(),
            });
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
    //
    // R2117 (open-debt item 498) — and NOT when an outside listener was
    // declared. A set of clients attached to a router somebody else runs is
    // the most ordinary fragment there is; reporting "every node is a client"
    // at it would fail the exact deployment this widening exists to serve. The
    // declaration is what makes the difference, and an empty one leaves the
    // closed reading exactly as it was.
    if outside.is_empty()
        && !named.is_empty()
        && named.iter().all(|(_, node)| node.mode == WhatAmI::Client)
    {
        out.push(TopologyDefect::NoNodeAccepts);
    }

    TopologyVerdict {
        defects: out,
        externally_answered,
    }
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
    /// R2141 (open-debt item 223) — `scouting/multicast/autoconnect`: WHICH ROLES
    /// this node opens a session to when it discovers them on the group.
    ///
    /// The third direction, and the one that makes the other two do something.
    /// `address` / `interface` / `ttl` say where to look; `listen` says whether
    /// to be findable; this says what to DO about a node that answers. Until this
    /// round wz did nothing at all — a wz node could be findable and could
    /// resolve one dial target for a one-shot session (`--scout`), but had no
    /// counterpart to zenoh's `Runtime::autoconnect_all`, so the key sat in
    /// `UNHONOURED_UPSTREAM_CONFIG_KEYS` beside `_strategy` below.
    ///
    /// A [`WhatAmIMatcher`] and not a `Vec<WhatAmI>`, because that is what
    /// upstream's value IS once its mode row is selected
    /// (`ModeDependentValue<WhatAmIMatcher>`), and because an EMPTY set is a real
    /// instruction — `autoconnect: []` is what a stock ROUTER's config resolves
    /// to, and it means "dial nobody". `Some(empty)` and `None` are therefore
    /// different answers and the type keeps them apart.
    pub scout_multicast_autoconnect: Option<WhatAmIMatcher>,
    /// R2141 (open-debt item 223) — `scouting/multicast/autoconnect_strategy`:
    /// the tie-break applied once a discovered node's role is admitted, PER
    /// TARGET ROLE.
    ///
    /// This key is why item 223 was a design round and not the wiring round it
    /// claimed to be. Its value is
    /// `ModeDependentValue<TargetDependentValue<AutoConnectStrategy>>`: the outer
    /// layer is selected by THIS node's mode (resolved here, at read time), the
    /// inner by the DISCOVERED node's role (resolvable only at use time). wz's
    /// `AutoConnect` carried a single `AutoConnectStrategy` and could not
    /// represent the inner table at all, so honouring the key meant changing the
    /// type — see `wz_routing_graph::AutoConnectStrategies`.
    pub scout_multicast_autoconnect_strategy: Option<AutoConnectStrategies>,
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
            // R2109 (open-debt item 514) — the CONSTANT, not a second spelling
            // of it. This field is what a document that names no `mode`
            // resolves to, and [`LIBRARY_DEFAULT_MODE`] is where that fact is
            // graded against upstream.
            mode: LIBRARY_DEFAULT_MODE,
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
            // R2141 — `None` is "the document said nothing", which a running
            // zenohd renders as `null`; `Some(empty matcher)` is the different
            // and real instruction "dial nobody". The default cannot be the
            // second without inventing an instruction.
            scout_multicast_autoconnect: None,
            scout_multicast_autoconnect_strategy: None,
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
        // R2141 — the two autoconnect keys, in UPSTREAM's own spelling: the role
        // set is a LIST of role names (`["router", "peer"]`, the only shape
        // `WhatAmIMatcherVisitor` accepts — it implements `visit_seq` and nothing
        // else), and the strategy is either a bare kebab-case name or a
        // `{ to_router: .., to_peer: .. }` table. Rendering the matcher as a
        // string, or the strategy in wz's own `to_router=always` flag spelling,
        // would emit a document a real zenohd refuses to start on.
        if let Some(matcher) = self.scout_multicast_autoconnect {
            out.push_str(", \"autoconnect\": [");
            let mut first = true;
            for role in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
                if matcher.matches(role) {
                    if !first {
                        out.push_str(", ");
                    }
                    first = false;
                    escape_into(role.to_str(), &mut out);
                }
            }
            out.push(']');
        }
        if let Some(strategy) = self.scout_multicast_autoconnect_strategy {
            out.push_str(", \"autoconnect_strategy\": ");
            match strategy {
                AutoConnectStrategies::Unique(s) => escape_into(s.to_config_str(), &mut out),
                AutoConnectStrategies::PerTarget {
                    to_router,
                    to_peer,
                    to_client,
                } => {
                    out.push('{');
                    let mut first = true;
                    for (role, set) in [
                        (WhatAmI::Router, to_router),
                        (WhatAmI::Peer, to_peer),
                        (WhatAmI::Client, to_client),
                    ] {
                        let Some(s) = set else { continue };
                        if !first {
                            out.push(',');
                        }
                        first = false;
                        let _ = write!(out, " \"to_{}\": ", role.to_str());
                        escape_into(s.to_config_str(), &mut out);
                    }
                    out.push_str(" }");
                }
            }
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
    // R2141 (open-debt item 223) — the two keys that made the multicast plane
    // DIAL. Item 223 filed them as a wiring round on the strength of wz already
    // having an `AutoConnect`; both halves of that had to be corrected before
    // they could move. Upstream's `responder` does not dial either (the item's
    // stated reason), so what was missing is the separate `autoconnect_all`
    // shape; and `_strategy`'s value is target-dependent, which wz's flattened
    // policy could not represent — see `wz_routing_graph::AutoConnectStrategies`.
    //
    // Surface total unchanged: both are resolved leaves of a real zenohd either
    // way, and all that moved is which half of the partition they sit in.
    "scouting/multicast/autoconnect",
    "scouting/multicast/autoconnect_strategy",
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
    // R2141 (open-debt item 223) — `scouting/multicast/autoconnect` and
    // `_strategy` MOVED OUT of here, into `HONOURED_CONFIG_KEYS`. Their gossip
    // twins two lines up stay: the gossip plane's policy is installed from the
    // command line (`--autoconnect`), not from the file, and moving those keys
    // is a different seam with a different witness.
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

/// The unhonoured keys wz genuinely CANNOT act on — the first of the two kinds
/// [`UNHONOURED_UPSTREAM_CONFIG_KEYS`] used to carry under one name.
///
/// R2148 (open-debt item 214) — that list's doc said only "wz models the
/// topology-and-transport subset it can act on", and that sentence conflated
/// two unrelated facts: "wz has no subsystem for this" and "wz does this
/// already and the READER was never told the key". The difference is the whole
/// of "what is not supported": the first is a feature nobody has built, the
/// second is a file an operator already has that silently does nothing. R311y844
/// moved ten keys of the second kind and left the rest unswept.
///
/// Every key here needs a SUBSYSTEM wz does not have. WHICH subsystem is no
/// longer prose: [`UNHONOURED_BEYOND_GROUPS`] carries the same grouping as data,
/// with a wz-code ANCHOR per group that a static gate requires to be ABSENT. The
/// bullets below are the human half of those rows and name the same anchors —
/// the gate checks that they do, so the two cannot drift.
///
/// * `aggregation/*` — a declaration-aggregation strategy (`AggregationConf`).
/// * `qos/*` — a QoS-OVERWRITE interceptor (`QosOverwriteItemConf`). R2150 split
///   this from `downsampling` / `low_pass_filter`, which are rules on the
///   `InterceptorChain` wz HAS; `interceptor/` holds `access_control`,
///   `downsampling` and `low_pass`, and no overwriter.
/// * `plugins_loading/search_dirs` — plugin auto-discovery from a search path
///   (`PluginSearchDirs`). wz loads a plugin by explicit path only.
/// * `transport/auth/*` — a credential store (`CredentialStore`). wz has the
///   WIRE half (the auth-body codec has foreign witnesses) and nothing to
///   configure it from.
/// * `transport/link/*` — a configurable link-TX surface (`LinkTxConf`):
///   upstream's priority-queue sizing, batching, congestion-control waits and
///   socket buffers, none of which wz exposes as configuration.
/// * `transport/{unicast,multicast}/*`, `transport/shared_memory/mode` — a
///   configurable session table (`TransportUnicastConf`): accept backlog,
///   session caps, open/accept timeouts.
/// * `connect/exit_on_failure`, `listen/*` — dial/listen failure policy
///   (`ListenConfig`). R2150 narrowed `connect/*` to the one member for which
///   this is still true: `connect/timeout_ms` IS implemented, by
///   `StaticConnectRetry::timeout_ms`.
/// * `open/return_conditions/*` — a session-open readiness barrier
///   (`ReturnConditionsConf`).
/// * `routing/*` — configurable link-state weighting and failover brokering
///   (`RoutingConf`).
/// * `scouting/delay` — a startup scouting delay (`ScoutingDelay`).
/// * `timestamping/drop_future_timestamp` — a future-timestamp drop policy
///   (`TimestampingConf`).
/// * `metadata` — a config-metadata surface (`ConfigMetadata`). Free-form
///   operator annotation upstream never reads either; `AdminLocalData` emits a
///   hardcoded null where it would land.
/// * `scouting/gossip/enabled` — ⚠ the one judgement call in this list. wz HAS
///   the gossip plane (see [`UNHONOURED_READER_GAP`]), but no gate that turns it
///   OFF (`set_gossip_enabled`), so honouring this key means BUILDING the switch
///   rather than teaching the reader. If that switch is ever added, this row
///   moves.
///
/// # What R2151 (open-debt item 540) moved OUT of here, and how it was found
///
/// Eleven rows. `access_control/*` (5) sat under "a policy engine (subjects,
/// rules, permissions)" while `wz-access-control` IS one — `AclConfig` carries
/// `default_permission` and an ordered `Vec<AclRule>`, each rule a subject
/// selector, flow set, message set and permission. `plugins` and
/// `plugins_loading/enabled` (2) sat under "a plugin host" while `PluginRegistry`
/// loads, starts, stops and admin-reports dynamic plugins and the demo takes
/// `--plugin`. `transport/link/tls/{connect_certificate,connect_private_key,
/// enable_mtls,verify_name_on_connect}` (4) sat under the link-knob group while
/// `tls_config.rs` carries `ClientAuthPem` and `ServerNameVerification`.
///
/// None of the three was found by a text sweep, and that is the finding item 540
/// was filed for. Measured this round: matching each key's own leaf identifier
/// against wz's code yields 30 of 72 candidates and is dominated by homonyms
/// (`data` alone hits 127 sites) while still MISSING `connect_certificate`,
/// whose wz spelling is `cert_chain_pem`; matching key segments against wz's
/// module and crate names yields a different 30 and misses the TLS group
/// entirely, because `tls` is a segment twelve surface keys share. Upstream's
/// own config type names do no better: wz mirrors them when it implements
/// (`AclConfig`, `DownsamplingRule`, `LowPassRule`) but not always
/// (`PluginsConfig` → `PluginRegistry`, `TLSConf` → `tls_config`), so that
/// derivation caught one of the three.
///
/// So there is no sweep that answers this, and the answer is the group table:
/// EVERY key here belongs to a group, and every group states the thing wz would
/// need as a name that must not exist in wz's code. That is a claim per row
/// rather than per sweep, and it is what a future capability reds against.
pub const UNHONOURED_BEYOND_WZ: &[&str] = &[
    "aggregation/publishers",
    "aggregation/subscribers",
    "connect/exit_on_failure",
    "listen/exit_on_failure",
    "listen/retry",
    "listen/timeout_ms",
    "metadata",
    "open/return_conditions/connect_scouted",
    "open/return_conditions/declares",
    "plugins_loading/search_dirs",
    "qos/network",
    "qos/publication",
    "routing/peer/linkstate/transport_weights",
    "routing/router/linkstate/transport_weights",
    "routing/router/peers_failover_brokering",
    "scouting/delay",
    "scouting/gossip/enabled",
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
    "transport/link/tls/so_rcvbuf",
    "transport/link/tls/so_sndbuf",
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

/// The unhonoured keys wz ALREADY ACTS ON and the reader was never told — the
/// second kind, and the one that costs an operator something today.
///
/// R2148 (open-debt item 214). A key here is not a missing feature: the deploy
/// can get the behaviour by hand, so a file that states it looks like it works
/// and does nothing. That is strictly worse than an unimplemented key, which at
/// least fails visibly.
///
/// EVERY ENTRY IS EVIDENCED BY wz's OWN SOURCE NAMING THE UPSTREAM KEY, which
/// is what makes this classification a reading rather than a guess — wz asserts
/// the mapping and the reader contradicts it:
///
/// * `scouting/gossip/multihop` — `wz_routing_graph::LinkstateNetwork` carries a
///   `gossip_multihop` field with a `set_gossip_multihop` setter, and its doc
///   cites `scouting.gossip.multihop` by name.
/// * `scouting/gossip/target` — `linkstate_forward.rs` has `default_gossip_target`
///   and `set_gossip_target`, and its doc calls the value "config-sourceable by
///   a deploy" while citing the zenoh key. The knob was built FOR a config that
///   cannot reach it.
/// * `scouting/gossip/autoconnect` / `_strategy` — `wz_routing_graph::autoconnect`
///   and the `AutoConnectStrategies` R2141 built for the MULTICAST twins of these
///   two keys, which are honoured. The demo exposes `--autoconnect` and
///   `--autoconnect-strategy` for the gossip plane specifically.
/// * `connect/timeout_ms` — `StaticConnectRetry::timeout_ms`, the bound on the
///   WHOLE static dial, carrying upstream's `-1` (infinite) / `0` (no retry) /
///   positive reading. R2150 moved it: it sat under a group sentence saying
///   wz's session-open path implements no `connect/*` behaviour at all, beside
///   `connect/retry`, which wz HONOURS.
/// * `downsampling` — `DownsamplingRule` on the composable `InterceptorChain`,
///   driven today by `--downsample` / `--downsample-freq` (upstream's Hertz
///   unit) / `--downsample-link-protocol` / `--downsample-interface`.
/// * `low_pass_filter` — `LowPassRule` on the same chain, driven by
///   `--max-payload`. R2150 moved both: the group sentence that held them
///   claimed wz needed an interceptor chain, and wz has one.
/// * `access_control/{default_permission,enabled,policies,rules,subjects}` —
///   the `wz-access-control` crate. `AclConfig` carries `default_permission`
///   and an ordered `Vec<AclRule>`; each rule carries a `SubjectSelector`, a
///   flow set, a message set and a permission, which is upstream's rule model
///   with the subject inlined instead of named. `enabled` is here rather than
///   with `scouting/gossip/enabled` because wz's OFF state EXISTS and is the
///   default — a peer with no policy installed enforces nothing — so the reader
///   would not be building a switch, only choosing not to install. `policies`
///   is upstream's rules-by-name × subjects-by-name join, which a reader
///   expands into wz's inline rules; `subjects` reaches only wz's zid axis,
///   which is the partiality this list already warns about below, not absence.
/// * `plugins`, `plugins_loading/enabled` — `PluginRegistry`, which loads,
///   starts, stops and admin-reports `DynamicPlugin`s, driven today by the
///   demo's repeated `--plugin`. `plugins_loading/search_dirs` stays in
///   [`UNHONOURED_BEYOND_WZ`]: wz loads by explicit path and has no discovery.
/// * `transport/link/tls/{connect_certificate,connect_private_key,enable_mtls,
///   verify_name_on_connect}` — `tls_config.rs`. `ClientAuthPem` carries the
///   client `cert_chain_pem` + `private_key_pem` an mTLS dial presents, and
///   `ServerNameVerification` is the `verify_name_on_connect` axis, named after
///   `Z_CONFIG_TLS_VERIFY_NAME_ON_CONNECT` in its own doc. The C ABI already
///   exposes both.
///
/// ⚠ Being here is NOT a claim that the move is mechanical. R311y844's ten were
/// moved one at a time, and `scouting/multicast/autoconnect` needed R2141 to
/// build a strategy representation first. This list says the capability EXISTS,
/// not that the reader change is free.
pub const UNHONOURED_READER_GAP: &[&str] = &[
    "access_control/default_permission",
    "access_control/enabled",
    "access_control/policies",
    "access_control/rules",
    "access_control/subjects",
    "connect/timeout_ms",
    "downsampling",
    "low_pass_filter",
    "plugins",
    "plugins_loading/enabled",
    "scouting/gossip/autoconnect",
    "scouting/gossip/autoconnect_strategy",
    "scouting/gossip/multihop",
    "scouting/gossip/target",
    "transport/link/tls/connect_certificate",
    "transport/link/tls/connect_private_key",
    "transport/link/tls/enable_mtls",
    "transport/link/tls/verify_name_on_connect",
];

/// WHICH subsystem each [`UNHONOURED_BEYOND_WZ`] key would need, as data —
/// `(what wz would need, the wz-code anchor that must be ABSENT, the keys)`.
///
/// R2151 (open-debt item 540) — the mirror of [`UNHONOURED_CITATION_LEDGER`],
/// and the half that one structurally could not reach. That ledger's population
/// is the keys wz's source NAMES: nineteen of seventy-nine, with the other sixty
/// reported as outside what it claims. A key wz grew a capability for under a
/// spelling of its own leaves no citation, so it stays in
/// [`UNHONOURED_BEYOND_WZ`] silently — and an operator's file that states it then
/// looks like it works and does nothing.
///
/// # Why a table and not a sweep
///
/// Three derivations were measured this round and all three are FLOORS. Leaf
/// identifiers: 30 of 72 candidates, dominated by homonyms, and it misses
/// `connect_certificate` because wz calls it `cert_chain_pem`. Key segments
/// against wz's module and crate names: a different 30, and it misses the whole
/// TLS group because `tls` is a segment twelve surface keys share. Upstream's own
/// config type names: catches `access_control` (wz mirrored `AclConfig`) and
/// neither of the other two (`PluginsConfig` → `PluginRegistry`, `TLSConf` →
/// `tls_config`). A sweep that finds a third of what is there, differently each
/// time, is a candidate generator, not a gate.
///
/// So the obligation is per ROW instead. Every key in [`UNHONOURED_BEYOND_WZ`]
/// belongs to exactly one group here — the gate derives that from the list, so a
/// new key with no group reds rather than defaulting — and every group names the
/// thing wz would need as an identifier that must NOT appear in wz's code, with
/// comments stripped first. When wz grows that thing, the anchor appears and the
/// group reds; that is the whole mechanism.
///
/// # What it cannot do, stated rather than hidden
///
/// An absence claim is satisfiable by naming something nobody would ever write.
/// Nothing here stops that, and the gate's two other checks are what raise the
/// cost: the anchor must also appear in [`UNHONOURED_BEYOND_WZ`]'s own doc, next
/// to the sentence a human reads, and the groups must account for every key. A
/// determined author can still sub-group a failure away ("wz lacks the X-with-Y
/// subsystem"); what they cannot do is leave a key ungrouped or write an anchor
/// the prose does not carry.
pub const UNHONOURED_BEYOND_GROUPS: &[(&str, &str, &[&str])] = &[
    (
        "a declaration-aggregation strategy",
        "AggregationConf",
        &["aggregation/publishers", "aggregation/subscribers"],
    ),
    (
        "a QoS-overwrite interceptor",
        "QosOverwriteItemConf",
        &["qos/network", "qos/publication"],
    ),
    (
        "plugin auto-discovery from a search path",
        "PluginSearchDirs",
        &["plugins_loading/search_dirs"],
    ),
    (
        "a credential store",
        "CredentialStore",
        &[
            "transport/auth/pubkey/key_size",
            "transport/auth/pubkey/known_keys_file",
            "transport/auth/pubkey/private_key_file",
            "transport/auth/pubkey/private_key_pem",
            "transport/auth/pubkey/public_key_file",
            "transport/auth/pubkey/public_key_pem",
            "transport/auth/usrpwd/dictionary_file",
            "transport/auth/usrpwd/password",
            "transport/auth/usrpwd/user",
        ],
    ),
    (
        "a configurable link-TX surface",
        "LinkTxConf",
        &[
            "transport/link/protocols",
            "transport/link/rx/buffer_size",
            "transport/link/rx/max_message_size",
            "transport/link/tcp/so_rcvbuf",
            "transport/link/tcp/so_sndbuf",
            "transport/link/tls/close_link_on_expiration",
            "transport/link/tls/so_rcvbuf",
            "transport/link/tls/so_sndbuf",
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
        ],
    ),
    (
        "a configurable session table",
        "TransportUnicastConf",
        &[
            "transport/multicast/compression/enabled",
            "transport/multicast/join_interval",
            "transport/multicast/max_sessions",
            "transport/shared_memory/mode",
            "transport/unicast/accept_pending",
            "transport/unicast/accept_timeout",
            "transport/unicast/max_sessions",
            "transport/unicast/open_timeout",
        ],
    ),
    (
        "a dial/listen failure policy",
        "ListenConfig",
        &[
            "connect/exit_on_failure",
            "listen/exit_on_failure",
            "listen/retry",
            "listen/timeout_ms",
        ],
    ),
    (
        "a session-open readiness barrier",
        "ReturnConditionsConf",
        &[
            "open/return_conditions/connect_scouted",
            "open/return_conditions/declares",
        ],
    ),
    (
        "configurable link-state weighting and failover brokering",
        "RoutingConf",
        &[
            "routing/peer/linkstate/transport_weights",
            "routing/router/linkstate/transport_weights",
            "routing/router/peers_failover_brokering",
        ],
    ),
    (
        "a startup scouting delay",
        "ScoutingDelay",
        &["scouting/delay"],
    ),
    (
        "a future-timestamp drop policy",
        "TimestampingConf",
        &["timestamping/drop_future_timestamp"],
    ),
    ("a config-metadata surface", "ConfigMetadata", &["metadata"]),
    (
        "a gate that turns the gossip plane off",
        "set_gossip_enabled",
        &["scouting/gossip/enabled"],
    ),
];

/// The legal KINDS a [`UNHONOURED_CITATION_LEDGER`] row may carry, and the one
/// place a new one is added.
///
/// Kept as data rather than as a Rust `enum` because the gate that evaluates
/// each kind's evidence is a static reader outside this crate, and the R2138
/// rule for that shape is that the gate DERIVES its vocabulary from the source
/// instead of carrying a copy. A typo'd kind is then a red in
/// `every_unhonoured_citation_row_is_legal_and_matches_its_list`, not a row the
/// gate silently skips.
///
/// R2150 deliberately ships FOUR, each with at least one row. A fifth,
/// `upstream-only` (the doc names a symbol that exists only upstream), was
/// drafted and DROPPED: after the sweep every candidate for it turned out to be
/// one of the four below, and item 539's own example of that kind —
/// `get_global_connect_timeout` beside `connect/timeout_ms` — turned out to be a
/// misclassified `wz-has-it`. A branch with no population is a branch nobody
/// has ever run.
pub const UNHONOURED_CITATION_KINDS: &[&str] = &[
    "asserted-ignored",
    "foreign-node-config",
    "not-this-key",
    "wz-has-it",
];

/// WHY wz's own source spells an upstream key wz does not honour — one row per
/// such key, `(key, kind, anchor)`.
///
/// R2150 (open-debt item 539) — the sibling of the split R2148 made. That round
/// divided [`UNHONOURED_UPSTREAM_CONFIG_KEYS`] into "wz cannot" and "the reader
/// was never told", and
/// `every_unhonoured_key_says_which_kind_of_unhonoured_it_is` forces the
/// division to be TOTAL, DISJOINT, un-orphaned and to sum. None of those four
/// asks whether a row's kind is RIGHT. A `UNHONOURED_BEYOND_WZ` row that
/// becomes a reader gap — because wz grows the capability — reds nothing, and
/// that is the worse half of the class: an operator's file that states the key
/// looks like it works and does nothing.
///
/// # The rule item 539 pre-refuted, and why this is not it
///
/// "wz's source names the key, therefore wz honours it" is FALSE, and the item
/// measured three counter-reasons before filing. The sweep this ledger answers
/// to found a fourth and a fifth, so the answer is not a single predicate but a
/// DECLARED kind per row, each with its own machine-checked anchor:
///
/// * `wz-has-it` — the citation IS the capability. The row must sit in
///   [`UNHONOURED_READER_GAP`], and `anchor` names a wz symbol that must EXIST
///   in wz's code (not merely in its prose).
/// * `not-this-key` — a DIFFERENT wz mechanism is what the citing site is
///   about. `transport/unicast/accept_timeout` is item 539's own example: the
///   citing doc is a unixpipe-only `HANDSHAKE_TIMEOUT` that happens to match
///   the key's default, over a listener upstream gives no bound at all.
///   `anchor` names that other mechanism, and it must EXIST.
/// * `asserted-ignored` — the citing line is wz's own test asserting the key is
///   IGNORED. The strongest citation there is, and it says the opposite of
///   "honoured". `anchor` is the word that must appear on the citing line.
/// * `foreign-node-config` — wz spells the key to configure the OTHER
///   implementation. Every interop leg that launches a stock `zenohd` with
///   `transport/auth/...` is this. `anchor` is the marker every citing FILE
///   must carry.
///
/// # What this cannot do, stated rather than hidden
///
/// The population is derived from a text sweep, so it is exactly the keys wz
/// NAMES — not the capabilities wz HAS. A capability wz grows under a spelling
/// of its own produces no citation and no row: `low_pass_filter` was such a
/// case until this round, and it took reading a group sentence, not the sweep,
/// to find it. The residue is open-debt item 540. What the ledger does buy is
/// that a wrong kind now costs a symbol that must exist and a list the row must
/// sit in, instead of a sentence.
pub const UNHONOURED_CITATION_LEDGER: &[(&str, &str, &str)] = &[
    (
        "access_control/default_permission",
        "wz-has-it",
        "AclConfig",
    ),
    ("access_control/enabled", "wz-has-it", "AclPolicy"),
    ("access_control/policies", "wz-has-it", "AclRule"),
    ("access_control/rules", "wz-has-it", "AclRule"),
    ("access_control/subjects", "wz-has-it", "SubjectSelector"),
    ("connect/timeout_ms", "wz-has-it", "StaticConnectRetry"),
    ("downsampling", "wz-has-it", "DownsamplingRule"),
    ("low_pass_filter", "wz-has-it", "LowPassRule"),
    ("metadata", "not-this-key", "AdminLocalData"),
    ("plugins", "wz-has-it", "PluginRegistry"),
    ("plugins_loading/enabled", "wz-has-it", "PluginRegistry"),
    // The citing site is `PluginRegistry`'s doc, drawing the line at this key:
    // the host is wz's, the DISCOVERY is not. A citation that says "not this
    // one" is still a citation, and it needs a verdict like any other.
    (
        "plugins_loading/search_dirs",
        "not-this-key",
        "PluginRegistry",
    ),
    (
        "scouting/gossip/autoconnect",
        "wz-has-it",
        "should_autoconnect",
    ),
    (
        "scouting/gossip/autoconnect_strategy",
        "wz-has-it",
        "AutoConnectStrategies",
    ),
    (
        "scouting/gossip/multihop",
        "wz-has-it",
        "set_gossip_multihop",
    ),
    ("scouting/gossip/target", "wz-has-it", "set_gossip_target"),
    (
        "transport/auth/pubkey/known_keys_file",
        "foreign-node-config",
        "zenohd",
    ),
    (
        "transport/auth/pubkey/private_key_file",
        "foreign-node-config",
        "zenohd",
    ),
    (
        "transport/auth/pubkey/public_key_file",
        "foreign-node-config",
        "zenohd",
    ),
    (
        "transport/auth/usrpwd/dictionary_file",
        "foreign-node-config",
        "zenohd",
    ),
    (
        "transport/auth/usrpwd/password",
        "foreign-node-config",
        "zenohd",
    ),
    (
        "transport/auth/usrpwd/user",
        "foreign-node-config",
        "zenohd",
    ),
    (
        "transport/link/tls/connect_certificate",
        "wz-has-it",
        "ClientAuthPem",
    ),
    (
        "transport/link/tls/connect_private_key",
        "wz-has-it",
        "ClientAuthPem",
    ),
    (
        "transport/link/tls/enable_mtls",
        "wz-has-it",
        "ClientAuthPem",
    ),
    (
        "transport/link/tls/verify_name_on_connect",
        "wz-has-it",
        "ServerNameVerification",
    ),
    ("transport/link/tx/threads", "asserted-ignored", "ignored"),
    (
        "transport/multicast/join_interval",
        "foreign-node-config",
        "zenohd",
    ),
    (
        "transport/unicast/accept_timeout",
        "not-this-key",
        "HANDSHAKE_TIMEOUT",
    ),
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
/// Honoured keys whose EFFECT is witnessed on the WIRE — read back out of a
/// frame the node actually wrote, not out of a struct it filled in.
///
/// R2083 (open-debt item 220) — the distinction this constant exists for is the
/// one 220 names: an oracle that compares VALUES shows wz read what zenoh read,
/// and says nothing about wz DOING it. R2082 built the first such chain
/// (`batch_size`, dissected out of the InitSyn the demo sent) after item 211
/// observed that a discarded value opens a session just as well as an honoured
/// one. A key here has that chain; a key not here does not, and the sweep in
/// `wz-ap-demo`'s tests makes which is which a per-key fact rather than prose.
///
/// ⚠ It is SHORT on purpose and must not be padded. Adding a key here is a claim
/// that a leg reads it off a frame, and `wz_reads_a_stock_zenohd_config`'s wire
/// leg is driven by this constant — a name added without a witness reds there.
///
/// R2085 (open-debt item 505) adds `transport/link/tx/lease`, the first entry
/// read out of a frame BEYOND the demo's first. `lease` is announced in the
/// OPEN, and a listener that never answers the InitSyn gives the node no reason
/// to send one — which is why 211 could prove only one of the two values it
/// named. The leg now returns an InitAck built by `handshake_encode::encode_init`
/// and reads the OPEN that follows.
///
/// R2086 adds two transport CAPABILITIES. They carry no value on the wire —
/// each is a UNIT extension on the InitSyn (`ext_name.rs`: `low_latency` 0x5,
/// `compression` 0x6) — so what the leg reads is whether the node offered it at
/// all, which is the whole of what the file asked for.
///
/// R2087 (open-debt item 506) adds the THIRD such key,
/// `transport/unicast/qos/enabled` (`qos` 0x1), and it is the one that had to be
/// BUILT rather than measured. R2086 asked it both ways and got the same offer
/// set either way, because the demo's initiator offer took no qos argument at
/// all: the key was honoured by the reader, expanded into `--qos`, and the flag
/// selected only the AGGREGATED multilink path, so on a single-link open it
/// reached nothing. Unlike its two siblings, this one is half of an EXCLUSIVE
/// pair — zenoh bails on qos + lowlatency at `unicast/manager.rs:264` — so
/// wiring it meant refusing the pair, not just adding a third boolean.
///
/// R2095 (open-debt item 513) adds the FOURTH capability,
/// `transport/shared_memory/enabled`, and — more importantly — WIDENS what
/// every entry above claims.
///
/// # The claim's scope, which item 513 was filed to move
///
/// Until R2095 these keys were proven on ONE of wz's two dial paths. The leg's
/// fixture said `mode: "client"` and the comment beside it said why: a peer
/// document had begun selecting the peer MESH, and the mesh built no
/// [`SessionOffer`](crate::session_open::SessionOffer) at all, so
/// `initiator_offer` was reached from the single-session `Role::Initiator` arm
/// and from nowhere else. The three capability keys were therefore proven of
/// `--connect` and of nothing else — a narrowing that was written down rather
/// than hidden, and left as this item's work.
///
/// The leg now asks every key of THREE run-modes — `--connect`, `--peer` and
/// `--router-hat` — from the same document, and a key is declared here only
/// when all three carry it. `peer_loop` threads a per-node offer through both
/// its dial and its accept sites (`accept_loop.rs`, `FaceSources::offer`), which
/// is upstream's own shape: `StateOpen` and `StateAccept` are built from the
/// same `manager.config.unicast.*`.
///
/// ⚠ The `shm` row is the Init offer (`extshm::SHM_INIT_EXT_HEADER`, ZBuf at
/// id `0x2`), NOT the UNIT at the same numeric id that R311y505's cross-impl
/// note is about. The two live in one module and one sentence has covered both;
/// the leg measured which one the InitSyn actually carries rather than reading
/// that sentence.
pub const CONFIG_KEYS_PROVEN_ON_THE_WIRE: &[&str] = &[
    "id",
    "transport/link/tx/batch_size",
    "transport/link/tx/lease",
    "transport/shared_memory/enabled",
    "transport/unicast/lowlatency",
    "transport/unicast/compression/enabled",
    "transport/unicast/qos/enabled",
];

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
    /// R2081 (open-debt item 500) — honoured keys the document states as a
    /// `{ router, peer, client }` table that names no row for THIS node's mode.
    ///
    /// The third answer, and it is neither of the other two: not [`named`], which
    /// would claim an instruction this node never got; not [`ignored`], which
    /// would say wz cannot read the key when it reads it fine and correctly did
    /// nothing. A caller that reports only the first two tells an operator
    /// nothing about a file that speaks entirely to other nodes — the outcome
    /// [`ZenohNodeConfig::from_json5`]'s own comment calls the one this partition
    /// exists to make impossible.
    ///
    /// [`named`]: ZenohConfigIngest::named
    /// [`ignored`]: ZenohConfigIngest::ignored
    pub stated_for_other_modes: Vec<&'static str>,
}

impl ZenohConfigIngest {
    /// The FOURTH answer: what this document's silence about `mode` means.
    ///
    /// R2109 (open-debt item 514). `Some` exactly when the document named no
    /// `mode` — which is not a key the other three partitions can carry, because
    /// they all enumerate keys the file WROTE. A silence has no leaf to sit
    /// beside, and until this round that made it unreportable: the expansion
    /// records a `mode` verdict only when [`named`] carries the key, so the one
    /// document whose role nobody stated is the one the report said nothing
    /// about.
    ///
    /// [`read_as`] is read off [`config`] rather than from
    /// [`LIBRARY_DEFAULT_MODE`], so the sentence states what THIS ingest
    /// produced. The two are the same value by construction — an unnamed `mode`
    /// leaves the field at its default, and that default IS the constant — and
    /// deriving it here rather than restating it is what keeps the report honest
    /// if they ever stop being.
    ///
    /// [`named`]: ZenohConfigIngest::named
    /// [`config`]: ZenohConfigIngest::config
    /// [`read_as`]: UnstatedMode::read_as
    pub fn mode_left_unstated(&self) -> Option<UnstatedMode> {
        (!self.named.contains(&"mode")).then_some(UnstatedMode {
            read_as: self.config.mode,
            a_daemon_reads: DAEMON_DEFAULT_MODE,
        })
    }
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
    // R2141 — both new keys are declared mode-dependent upstream, and their
    // DEFAULTS differ per mode, which is what makes the table spelling ordinary
    // rather than exotic here: `autoconnect` is `[]` for a router, `["router",
    // "peer"]` for a peer and `["router"]` for a client (`DEFAULT_CONFIG.json5`).
    "scouting/multicast/autoconnect",
    "scouting/multicast/autoconnect_strategy",
    "scouting/multicast/listen",
    "timestamping/enabled",
];

/// The three fields `ModeValues` has, and the only keys a mode table may carry.
const MODE_TABLE_FIELDS: &[&str] = &["router", "peer", "client"];

/// What a stock zenoh node BINDS when its document names no `listen/endpoints`
/// at all.
///
/// R2091b (open-debt item 511) — this is upstream's own default, quoted from
/// `DEFAULT_CONFIG.json5` in the pinned checkout, where the key is written as a
/// mode table: `endpoints: { router: ["tcp/[::]:7447"], peer: ["tcp/[::]:0"] }`.
/// A `client` row is ABSENT there, and its absence is the instruction: a zenoh
/// client never listens.
///
/// ## Why this is a value and not a silence
///
/// The expansion this feeds has a standing rule -- only keys the document NAMED
/// are applied, never a value that merely resolved to a default -- and that rule
/// exists to stop a merged `qos: true` from adding `--qos` to every invocation.
/// It is about not inventing a DIFFERENCE. Here the default is not a difference:
/// it is what a real zenohd does with the very same file, and wz's silence was
/// the divergence. Measured against a real zenohd rather than inferred: given
/// `{ mode: "router", connect: [..] }` it answers on port 7447 on every
/// interface; given the same document as `peer` it answers on an ephemeral port;
/// and given `{ mode: "client", listen: [..] }` it starts and binds NOTHING,
/// naming no locator at all.
///
/// A document that NAMES the key -- including as an explicitly EMPTY list --
/// suppresses this, and that is upstream's behaviour too (measured: an empty
/// list starts a node that binds nothing). So the caller must consult
/// [`ZenohConfigIngest::named`] before reaching for it, exactly as it would for
/// any other key.
pub fn default_listen_endpoint(mode: WhatAmI) -> Option<&'static str> {
    match mode {
        WhatAmI::Router => Some("tcp/[::]:7447"),
        WhatAmI::Peer => Some("tcp/[::]:0"),
        WhatAmI::Client => None,
    }
}

/// The run-mode a document that names NO `mode` comes up in, as the zenoh
/// LIBRARY reads that silence.
///
/// Upstream's own default, in two places that agree: `zenoh-config`'s
/// `defaults::mode` is `WhatAmI::Peer`, and `DEFAULT_CONFIG.json5` documents it
/// as the uncommented `mode: "peer"` near the top of the file. A library node's
/// runtime resolves an absent key through that constant
/// (`unwrap_or_default!(config.mode())`), so this is what the silence MEANS to
/// every zenoh node that is not the daemon.
///
/// Named here rather than spelled a second time in
/// [`ZenohNodeConfig::default`], which now reads it: two pins that must move
/// together are one pin, and an upstream release that moved this default would
/// otherwise have to be chased twice.
pub const LIBRARY_DEFAULT_MODE: WhatAmI = WhatAmI::Peer;

/// The run-mode the SAME silence comes up in when a zenoh DAEMON reads it.
///
/// R2109 (open-debt item 514) — `zenohd` overwrites an absent `mode` before it
/// builds a runtime at all: `if config.mode().is_none() { config.set_mode(
/// Some(WhatAmI::Router)) }` (`zenohd/src/main.rs` in the pinned checkout).
/// Measured rather than quoted: handed a one-line `{ listen: [..] }` document, a
/// real zenohd prints `"mode":"router"` in its own resolved config.
///
/// ## Why wz keeps the LIBRARY reading and states this one
///
/// Neither reading is wrong. `wz-ap-demo` is a library node, so the library
/// default is the correct comparand and R2092 decided it that way. What item
/// 514 is about is the half that decision does not cover: the north star is a
/// replacement for zenoh AND for zenohd, and an operator who swaps a zenohd out
/// for wz with a mode-less file gets a PEER standing where a router used to be
/// — silently, because nothing in the report mentions a key the file never
/// named. This constant exists so the report can say it; the sentence is
/// [`UnstatedMode`], reached through [`ZenohConfigIngest::mode_left_unstated`].
///
/// R2109 chose to SAY it rather than to offer a daemon-reading switch. The
/// switch is expressible — it would be an argv flag, not a `cfg!`, so it would
/// not fall foul of the line R2091 drew about the same file coming up
/// differently per BUILD — but it answers a question nobody has asked: this
/// tree ships no daemon, and a flag that changes a node's role would owe its own
/// witness on the wire to be worth anything. The harm the register records is
/// the word "silently", and a line in the report is what removes it.
pub const DAEMON_DEFAULT_MODE: WhatAmI = WhatAmI::Router;

/// What a document's silence about `mode` means — in BOTH readings at once.
///
/// R2109 (open-debt item 514). Two roles rather than one, because the fact IS a
/// divergence: a line saying only "this node is a peer" reports wz's own
/// behaviour and gives an operator nothing to act on, and the thing they need to
/// act on is that the daemon they are replacing read the same bytes the other
/// way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnstatedMode {
    /// The run-mode wz selected — [`LIBRARY_DEFAULT_MODE`], carried as a value
    /// rather than re-quoted so a reader sees what THIS document actually got.
    pub read_as: WhatAmI,
    /// The run-mode a zenoh DAEMON would have selected from the same silence.
    pub a_daemon_reads: WhatAmI,
}

impl core::fmt::Display for UnstatedMode {
    /// The operator's sentence. Both roles are rendered from the values, so a
    /// round that moves either constant moves this line with it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "this document names no `mode`, so it is read as `{}` (the zenoh \
             library default); a zenoh daemon reads the same silence as `{}`. \
             Name `mode` to make the file say which.",
            self.read_as.to_str(),
            self.a_daemon_reads.to_str()
        )
    }
}

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

/// What a mode-dependent key said to THIS node.
///
/// R2081 (open-debt item 500) — three answers, because the two that used to
/// collapse into one are not the same fact. `Absent` is "the document is silent
/// here"; `ForOtherModes` is "the document HAS an instruction and it is not for
/// this node", which an operator needs told: their file says something, and this
/// node is not who it says it to. Both used to arrive at the caller as `None`,
/// so the second went into neither `named` nor `ignored` and no report carried
/// it — the one outcome `from_json5`'s own comment says the partition exists to
/// make impossible.
enum ModeRead<T> {
    /// The document does not mention the key.
    Absent,
    /// A `{ router, peer, client }` table that names no row for this mode.
    ForOtherModes,
    /// A value for this node.
    Value(T),
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
) -> Result<ModeRead<bool>, ConfigIngestError> {
    let Some(value) = honoured(doc, path) else {
        return Ok(ModeRead::Absent);
    };
    match for_this_mode(value, mode, path)? {
        None => Ok(ModeRead::ForOtherModes),
        Some(v) => bool_of(v, path).map(ModeRead::Value),
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
) -> Result<ModeRead<Vec<String>>, ConfigIngestError> {
    let Some(value) = honoured(doc, path) else {
        return Ok(ModeRead::Absent);
    };
    match for_this_mode(value, mode, path)? {
        None => Ok(ModeRead::ForOtherModes),
        Some(v) => endpoints_of(v, path).map(ModeRead::Value),
    }
}

/// R2141 — `scouting/multicast/autoconnect`'s value: a LIST of role names.
///
/// Upstream accepts only a sequence here — `WhatAmIMatcher`'s `Deserialize` calls
/// `deserialize_seq` and its visitor implements `visit_seq` alone
/// (`commons/zenoh-protocol/src/core/whatami.rs`), so `"router|peer"` is not a
/// spelling a real zenohd reads and must not be one wz reads either. An EMPTY
/// list is valid and means the empty matcher — a stock router's own default.
///
/// A name outside the three roles is an ERROR rather than a skipped entry: it is
/// the same class as `mode: "rooter"`, and silently dropping it would leave the
/// operator with a policy narrower than the one they wrote.
fn matcher_of(value: &Json5Value, path: &'static str) -> Result<WhatAmIMatcher, ConfigIngestError> {
    let Json5Value::Array(items) = value else {
        return Err(ConfigIngestError::WrongType {
            path,
            expected: "a list of role names (\"router\" / \"peer\" / \"client\")",
        });
    };
    let mut matcher = WhatAmIMatcher::empty();
    for item in items {
        let Json5Value::String(name) = item else {
            return Err(ConfigIngestError::WrongType {
                path,
                expected: "a list of role names (\"router\" / \"peer\" / \"client\")",
            });
        };
        // Matched against `to_str`, the same way `mode` is, so the two directions
        // cannot disagree about a spelling.
        matcher = match [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client]
            .into_iter()
            .find(|w| w.to_str() == name)
        {
            Some(WhatAmI::Router) => matcher.router(),
            Some(WhatAmI::Peer) => matcher.peer(),
            Some(WhatAmI::Client) => matcher.client(),
            None => {
                return Err(ConfigIngestError::UnknownMode {
                    value: name.clone(),
                })
            }
        };
    }
    Ok(matcher)
}

/// [`matcher_of`] for the key upstream declares
/// `ModeDependentValue<WhatAmIMatcher>`.
fn want_matcher_for_mode(
    doc: &Json5Value,
    path: &'static str,
    mode: WhatAmI,
) -> Result<ModeRead<WhatAmIMatcher>, ConfigIngestError> {
    let Some(value) = honoured(doc, path) else {
        return Ok(ModeRead::Absent);
    };
    match for_this_mode(value, mode, path)? {
        None => Ok(ModeRead::ForOtherModes),
        Some(v) => matcher_of(v, path).map(ModeRead::Value),
    }
}

/// R2141 — `scouting/multicast/autoconnect_strategy`'s value, AFTER its mode row
/// has been selected: either a bare strategy name or a
/// `{ to_router, to_peer, to_client }` table.
///
/// The two `to_`-prefixed field sets are what make the outer resolution
/// unambiguous, and this is where that pays off: `for_this_mode` refuses an
/// object whose fields are not all mode names, so the caller must try the TARGET
/// reading for exactly the objects it rejects — which is upstream's own
/// precedence (`ModeValues` first, `TargetDependentValue` as the fallback,
/// `mode_dependent.rs`). `ModeValues` carries `deny_unknown_fields` there, and
/// `for_this_mode`'s all-fields-are-mode-names check is wz's form of it.
fn strategies_of(
    value: &Json5Value,
    path: &'static str,
) -> Result<AutoConnectStrategies, ConfigIngestError> {
    match value {
        Json5Value::String(name) => AutoConnectStrategy::from_config_str(name)
            .map(AutoConnectStrategies::Unique)
            .ok_or(ConfigIngestError::WrongType {
                path,
                expected: "\"always\" or \"greater-zid\"",
            }),
        Json5Value::Object(fields) => {
            let mut to_router = None;
            let mut to_peer = None;
            let mut to_client = None;
            for (name, v) in fields {
                let slot = match name.as_str() {
                    "to_router" => &mut to_router,
                    "to_peer" => &mut to_peer,
                    "to_client" => &mut to_client,
                    _ => {
                        return Err(ConfigIngestError::WrongType {
                            path,
                            expected: "a { to_router, to_peer, to_client } table",
                        })
                    }
                };
                let Json5Value::String(spelling) = v else {
                    return Err(ConfigIngestError::WrongType {
                        path,
                        expected: "\"always\" or \"greater-zid\"",
                    });
                };
                *slot = Some(AutoConnectStrategy::from_config_str(spelling).ok_or(
                    ConfigIngestError::WrongType {
                        path,
                        expected: "\"always\" or \"greater-zid\"",
                    },
                )?);
            }
            Ok(AutoConnectStrategies::PerTarget {
                to_router,
                to_peer,
                to_client,
            })
        }
        _ => Err(ConfigIngestError::WrongType {
            path,
            expected: "\"always\" or \"greater-zid\", or a { to_router, .. } table",
        }),
    }
}

/// [`strategies_of`] under the MODE layer — the doubly-dependent key.
///
/// Order matters and is upstream's: a `{ router: .. }` object is a MODE table and
/// a `{ to_router: .. }` object is a TARGET table, and only the field names tell
/// them apart. So the mode reading is attempted first and its refusal of a
/// non-mode object is what selects the target reading; a document that is neither
/// fails inside [`strategies_of`], naming the shape it expected.
fn want_strategies_for_mode(
    doc: &Json5Value,
    path: &'static str,
    mode: WhatAmI,
) -> Result<ModeRead<AutoConnectStrategies>, ConfigIngestError> {
    let Some(value) = honoured(doc, path) else {
        return Ok(ModeRead::Absent);
    };
    match for_this_mode(value, mode, path) {
        Ok(None) => Ok(ModeRead::ForOtherModes),
        Ok(Some(v)) => strategies_of(v, path).map(ModeRead::Value),
        // Not a mode table -> read the whole value as a TARGET table. The error
        // is DISCARDED rather than propagated because it was the answer to a
        // different question; if this reading fails too, its own error stands.
        Err(_) => strategies_of(value, path).map(ModeRead::Value),
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
        // R2081 (open-debt item 500) — keys the document states for OTHER modes.
        // Neither honoured (this node got no instruction) nor ignored (wz reads
        // the key perfectly well), and until this round in neither list, so an
        // operator whose file says nothing to THIS node was told nothing about
        // that.
        let mut other_modes: Vec<&'static str> = Vec::new();

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
        match want_endpoints(&doc, "connect/endpoints", out.mode)? {
            ModeRead::Value(v) => {
                out.connect = v;
                named.push("connect/endpoints");
            }
            ModeRead::ForOtherModes => other_modes.push("connect/endpoints"),
            ModeRead::Absent => {}
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
        match want_endpoints(&doc, "listen/endpoints", out.mode)? {
            ModeRead::Value(v) => {
                out.listen = v;
                named.push("listen/endpoints");
            }
            ModeRead::ForOtherModes => other_modes.push("listen/endpoints"),
            ModeRead::Absent => {}
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
        match want_bool_for_mode(&doc, "scouting/multicast/listen", out.mode)? {
            ModeRead::Value(v) => {
                out.scout_multicast_listen = Some(v);
                named.push("scouting/multicast/listen");
            }
            ModeRead::ForOtherModes => other_modes.push("scouting/multicast/listen"),
            ModeRead::Absent => {}
        }
        // R2141 (open-debt item 223) — the two autoconnect keys, read AFTER
        // `mode` for the reason every mode-dependent key is: the table is
        // resolved with this node's own role, exactly as upstream's
        // `.get(whatami)` does.
        match want_matcher_for_mode(&doc, "scouting/multicast/autoconnect", out.mode)? {
            ModeRead::Value(v) => {
                out.scout_multicast_autoconnect = Some(v);
                named.push("scouting/multicast/autoconnect");
            }
            ModeRead::ForOtherModes => other_modes.push("scouting/multicast/autoconnect"),
            ModeRead::Absent => {}
        }
        match want_strategies_for_mode(&doc, "scouting/multicast/autoconnect_strategy", out.mode)? {
            ModeRead::Value(v) => {
                out.scout_multicast_autoconnect_strategy = Some(v);
                named.push("scouting/multicast/autoconnect_strategy");
            }
            ModeRead::ForOtherModes => other_modes.push("scouting/multicast/autoconnect_strategy"),
            ModeRead::Absent => {}
        }
        match want_bool_for_mode(&doc, "timestamping/enabled", out.mode)? {
            ModeRead::Value(v) => {
                out.timestamping = v;
                named.push("timestamping/enabled");
            }
            ModeRead::ForOtherModes => other_modes.push("timestamping/enabled"),
            ModeRead::Absent => {}
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
            stated_for_other_modes: other_modes,
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

    // R2117 (open-debt item 498) — the FRAGMENT. Every case below is stated as
    // a pair for the reason the closed-deployment cases above are: widening a
    // listener set can only ever silence a defect, so each control is the
    // shape that must stay red.
    #[test]
    fn a_fragment_attached_to_a_declared_outside_listener_checks_out() {
        // The ordinary shape this project is measured against: wz clients
        // attached to a stock zenohd somebody else runs.
        let a = node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.9:7447");
        let b = node(WhatAmI::Client, "B").connecting_to("tcp/10.0.0.9:7447");
        let set = [a, b];

        // CONTROL — read as CLOSED, this is two defects and a third: both
        // dials dangle and nothing accepts. That is the state item 498 filed.
        let closed = validate_topology(&set);
        assert_eq!(
            closed.len(),
            3,
            "the closed reading must still refuse a fragment: {closed:?}"
        );
        assert!(closed.contains(&TopologyDefect::NoNodeAccepts));

        // Declared, it is a working deployment, and the report SAYS what it
        // assumed rather than reading like a set that answers for itself.
        let verdict = validate_topology_with_external(&set, &[String::from("tcp/10.0.0.9:7447")]);
        assert!(
            verdict.defects.is_empty(),
            "a declared outside listener must answer these dials: {:?}",
            verdict.defects
        );
        assert_eq!(
            verdict.externally_answered,
            vec![
                ExternallyAnswered {
                    node: String::from("A"),
                    endpoint: String::from("tcp/10.0.0.9:7447"),
                },
                ExternallyAnswered {
                    node: String::from("B"),
                    endpoint: String::from("tcp/10.0.0.9:7447"),
                },
            ],
            "a green verdict over a fragment must name the assumption it rests on"
        );
    }

    #[test]
    fn a_declaration_that_answers_nothing_is_reported_rather_than_free() {
        // The whole reason widening is safe: it costs something. A stray
        // declaration cannot sit there quietly silencing the next typo.
        let a = node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.9:7447");
        let verdict = validate_topology_with_external(
            std::slice::from_ref(&a),
            &[
                String::from("tcp/10.0.0.9:7447"),
                String::from("tcp/10.0.0.8:7447"),
            ],
        );
        assert_eq!(
            verdict.defects,
            vec![TopologyDefect::UnusedExternalListener {
                endpoint: String::from("tcp/10.0.0.8:7447"),
            }],
            "an external declaration nothing dials must be named: {:?}",
            verdict.defects
        );

        // CONTROL — the declaration that DID answer is not reported, so the
        // check is about being unused rather than about being declared.
        let verdict = validate_topology_with_external(&[a], &[String::from("tcp/10.0.0.9:7447")]);
        assert!(verdict.defects.is_empty(), "{:?}", verdict.defects);
    }

    #[test]
    fn a_declaration_the_set_already_answers_is_named_against_the_node_that_answers_it() {
        let dialer = node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.5:7447");
        let listener = node(WhatAmI::Router, "R").listening_on("tcp/10.0.0.5:7447");
        let verdict = validate_topology_with_external(
            &[dialer, listener],
            &[String::from("tcp/10.0.0.5:7447")],
        );
        assert_eq!(
            verdict.defects,
            vec![TopologyDefect::ExternalShadowsListener {
                endpoint: String::from("tcp/10.0.0.5:7447"),
                node: String::from("R"),
            }],
            "the reader must be sent to the config that makes the declaration \
             wrong: {:?}",
            verdict.defects
        );
        // And the dial is NOT credited to the outside, because the set answers
        // it -- crediting it would send someone to a machine that has nothing
        // to do with this deployment.
        assert!(verdict.externally_answered.is_empty());
    }

    #[test]
    fn a_declaration_this_reader_cannot_parse_is_named_rather_than_dropped() {
        // Dropping it would widen nothing while the operator believes it did,
        // and the dial would come back dangling with no hint that the typo is
        // in their own argv.
        let a = node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.9:7447");
        let verdict = validate_topology_with_external(&[a], &[String::from("not-an-endpoint")]);
        assert!(
            verdict
                .defects
                .contains(&TopologyDefect::MalformedExternalListener {
                    endpoint: String::from("not-an-endpoint"),
                }),
            "an unparseable declaration must be named: {:?}",
            verdict.defects
        );
        // And the dial it failed to cover is still dangling, so the operator
        // gets both halves of what went wrong.
        assert!(verdict
            .defects
            .contains(&TopologyDefect::DanglingConnectTarget {
                node: String::from("A"),
                endpoint: String::from("tcp/10.0.0.9:7447"),
            }));
    }

    #[test]
    fn an_empty_declaration_leaves_the_closed_reading_exactly_as_it_was() {
        // The property every existing caller depends on: `validate_topology`
        // is this function with no declarations, and a set of clients with no
        // outside listener is still `NoNodeAccepts`.
        let a = node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.9:7447");
        let listener = node(WhatAmI::Router, "R").listening_on("tcp/10.0.0.5:7447");
        for set in [vec![a.clone()], vec![a, listener]] {
            assert_eq!(
                validate_topology(&set),
                validate_topology_with_external(&set, &[]).defects,
                "the closed reading must be the widened one over an empty set"
            );
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
            // R2141 (open-debt item 223) — the two keys that make the multicast
            // plane DIAL. Each is driven off the default a document that says
            // nothing resolves to for THIS reader's default mode (`peer`):
            // `["router", "peer"]` and `Unique(Always)`.
            //
            // The matcher fixture is `["client"]` — a set the peer default does
            // NOT contain in either direction, so a reader that ignored the list
            // and installed the default fails here. The strategy fixture is the
            // TARGET TABLE, which is the shape that could not be represented at
            // all before this round: a reader that flattened it to one strategy
            // would parse the document and store a value that answers every
            // target alike.
            (
                "scouting/multicast/autoconnect",
                r#"{ "scouting": { "multicast": { "autoconnect": ["client"] } } }"#,
            ),
            (
                "scouting/multicast/autoconnect_strategy",
                r#"{ "scouting": { "multicast": { "autoconnect_strategy":
                     { "to_router": "always", "to_peer": "greater-zid" } } } }"#,
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
                // R2141 — the two autoconnect keys are the first mode-dependent
                // ones whose value is neither a bool nor an endpoint list.
                "scouting/multicast/autoconnect" => "[\"router\", \"peer\"]",
                "scouting/multicast/autoconnect_strategy" => "\"greater-zid\"",
                _ => "true",
            };
            let plain = doc_with(key, value);
            ZenohNodeConfig::from_json5(&plain)
                .unwrap_or_else(|e| panic!("{key} plain spelling: {e:?}\n{plain}"));
            let table = doc_with(key, &format!("{{ router: {value} }}"));
            ZenohNodeConfig::from_json5(&table)
                .unwrap_or_else(|e| panic!("{key} table spelling: {e:?}\n{table}"));
        }

        // R2141 — `autoconnect_strategy` is the one key with a THIRD spelling:
        // its value nests a TARGET table under the mode layer, so all three of
        // `"always"`, `{ router: .. }` and `{ to_router: .. }` are documents a
        // real zenohd starts on (`ModeDependentValue<TargetDependentValue<..>>`,
        // `mode_dependent.rs`). The sweep above cannot reach the third, because
        // it is written against keys whose two layers are one.
        //
        // The pair below is what makes the ambiguity resolution testable at all:
        // both objects are `{ <name>: <strategy> }` and only the FIELD NAME says
        // which layer it belongs to.
        const STRATEGY: &str = "scouting/multicast/autoconnect_strategy";
        for (spelling, want) in [
            (
                "{ to_router: \"always\", to_peer: \"greater-zid\" }",
                AutoConnectStrategies::PerTarget {
                    to_router: Some(AutoConnectStrategy::Always),
                    to_peer: Some(AutoConnectStrategy::GreaterZid),
                    to_client: None,
                },
            ),
            (
                // A MODE table whose row for `router` is itself a TARGET table —
                // the doubly-nested shape `DEFAULT_CONFIG.json5` itself writes.
                "{ router: { to_peer: \"greater-zid\" } }",
                AutoConnectStrategies::PerTarget {
                    to_router: None,
                    to_peer: Some(AutoConnectStrategy::GreaterZid),
                    to_client: None,
                },
            ),
        ] {
            let doc = doc_with(STRATEGY, spelling);
            let ingest = ZenohNodeConfig::from_json5(&doc)
                .unwrap_or_else(|e| panic!("{STRATEGY} {spelling}: {e:?}\n{doc}"));
            assert_eq!(
                ingest.config.scout_multicast_autoconnect_strategy,
                Some(want),
                "{spelling}"
            );
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

    /// A table that names no row for this node lands in the THIRD list, and the
    /// SAME document read by the mode it does name lands in `named`.
    ///
    /// R2081 (open-debt item 500) — the pair is the point. One document, two
    /// readers, two different answers, and neither of them is `ignored`: wz reads
    /// the key perfectly well in both cases. Before this round the first case
    /// reached no list at all, so an operator whose file spoke only to other
    /// nodes was told nothing about it.
    #[test]
    fn a_table_stated_only_for_other_modes_is_reported_as_exactly_that() {
        const DOC: &str =
            r#"{ mode: "MODE", listen: { endpoints: { router: ["tcp/10.0.0.1:7447"] } } }"#;

        let theirs = ZenohNodeConfig::from_json5(&DOC.replace("MODE", "client"))
            .expect("a table that does not mention clients is readable");
        assert_eq!(theirs.stated_for_other_modes, vec!["listen/endpoints"]);
        assert!(!theirs.named.contains(&"listen/endpoints"));
        assert!(theirs.ignored.is_empty(), "{:?}", theirs.ignored);
        assert!(theirs.config.listen.is_empty());

        let mine = ZenohNodeConfig::from_json5(&DOC.replace("MODE", "router"))
            .expect("the same document, read by the mode it names");
        assert!(mine.named.contains(&"listen/endpoints"));
        assert!(
            mine.stated_for_other_modes.is_empty(),
            "{:?}",
            mine.stated_for_other_modes
        );
        assert_eq!(mine.config.listen, vec![String::from("tcp/10.0.0.1:7447")]);

        // And the control for the axis itself: a document with no table at all
        // must not put anything in the new list.
        let plain = ZenohNodeConfig::from_json5(
            r#"{ mode: "client", listen: { endpoints: ["tcp/10.0.0.9:7447"] } }"#,
        )
        .expect("the plain spelling still reads");
        assert!(plain.stated_for_other_modes.is_empty());
        assert!(plain.named.contains(&"listen/endpoints"));
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

    /// Every unhonoured key says WHICH KIND of unhonoured it is.
    ///
    /// R2148 (open-debt item 214) — the item's output is not a smaller number,
    /// it is a split of the NAMES: while "wz cannot do this" and "the reader was
    /// never told" share one list, "what is not supported" has no answer. This
    /// test is what stops them re-merging. A key added to
    /// [`UNHONOURED_UPSTREAM_CONFIG_KEYS`] without being classed lands in
    /// neither list and reds here, so the decision cannot be skipped — which is
    /// the whole reason the two lists RESTATE the keys instead of one being
    /// derived as the other's complement. A complement would classify every
    /// future key silently, which is exactly how this item would come back.
    ///
    /// The same shape the defaults leg uses for the honoured half: four classes
    /// that must account for `HONOURED_CONFIG_KEYS` exactly.
    #[test]
    fn every_unhonoured_key_says_which_kind_of_unhonoured_it_is() {
        assert!(!UNHONOURED_BEYOND_WZ.is_empty());
        assert!(
            !UNHONOURED_READER_GAP.is_empty(),
            "an empty reader-gap list makes the split vacuous — every key would \
             be 'wz cannot', which is the undivided state this test exists to \
             end"
        );

        let both: Vec<&&str> = UNHONOURED_BEYOND_WZ
            .iter()
            .filter(|k| UNHONOURED_READER_GAP.contains(k))
            .collect();
        assert!(
            both.is_empty(),
            "classed as BOTH kinds: {both:?} — a key wz cannot act on and \
             already acts on is two different answers to one question"
        );

        let unclassed: Vec<&&str> = UNHONOURED_UPSTREAM_CONFIG_KEYS
            .iter()
            .filter(|k| !UNHONOURED_BEYOND_WZ.contains(k) && !UNHONOURED_READER_GAP.contains(k))
            .collect();
        assert!(
            unclassed.is_empty(),
            "unhonoured and unclassed: {unclassed:?}. Every unhonoured key needs \
             a decision about WHY it is unhonoured — a subsystem wz lacks \
             (UNHONOURED_BEYOND_WZ), or a capability wz has whose key the reader \
             was never told (UNHONOURED_READER_GAP). Deciding is the point; the \
             lists are where the decision is recorded."
        );

        let orphaned: Vec<&&str> = UNHONOURED_BEYOND_WZ
            .iter()
            .chain(UNHONOURED_READER_GAP)
            .filter(|k| !UNHONOURED_UPSTREAM_CONFIG_KEYS.contains(k))
            .collect();
        assert!(
            orphaned.is_empty(),
            "classed but no longer unhonoured: {orphaned:?} — a classification \
             that outlived its key. If it became honoured, drop it from the \
             class in the round that moved it."
        );

        assert_eq!(
            UNHONOURED_BEYOND_WZ.len() + UNHONOURED_READER_GAP.len(),
            UNHONOURED_UPSTREAM_CONFIG_KEYS.len(),
            "the two kinds are disjoint and total above, so their sizes must sum \
             — a mismatch here means a duplicate inside one of them"
        );

        // The breakdown, not the total: "79 classed" would read the same whether
        // the reader-gap list held 4 keys or 0, and 0 is the undivided state.
        println!(
            "unhonoured upstream keys: {} total — {} beyond wz, {} reader gap {:?}",
            UNHONOURED_UPSTREAM_CONFIG_KEYS.len(),
            UNHONOURED_BEYOND_WZ.len(),
            UNHONOURED_READER_GAP.len(),
            UNHONOURED_READER_GAP
        );
    }

    /// A citation row is legal, unique, and sits in the list its KIND claims.
    ///
    /// R2150 (open-debt item 539) — the half of the evidence rule a unit test
    /// can answer without reading the tree. The other half — that the key is
    /// actually cited somewhere, and that the anchor names something that does
    /// or does not exist in wz's code — needs a sweep over every tracked `.rs`
    /// file and lives in `scripts/lib/unhonoured_kind_evidence_gate.py`. The
    /// split is deliberate rather than tidy: a predicate written in two places
    /// is two things to get wrong (R2147 wrote one three times and two of the
    /// three were missing a guard), so the LIST SHAPE is owned here and the
    /// TREE EVIDENCE is owned there, with no overlap.
    ///
    /// `wz-has-it` is checked in BOTH directions on purpose. One direction
    /// ("a `wz-has-it` row must be a reader gap") catches a row moved out of
    /// [`UNHONOURED_READER_GAP`] with its kind left behind; the other ("a
    /// reader gap must have a `wz-has-it` row") catches a key moved IN without
    /// evidence, which is the misclassification item 539 is named for.
    #[test]
    fn every_unhonoured_citation_row_is_legal_and_matches_its_list() {
        assert!(
            !UNHONOURED_CITATION_LEDGER.is_empty(),
            "an empty ledger passes every check below — a gate whose population \
             is zero reports green about nothing"
        );

        let bad_kind: Vec<&(&str, &str, &str)> = UNHONOURED_CITATION_LEDGER
            .iter()
            .filter(|(_, kind, _)| !UNHONOURED_CITATION_KINDS.contains(kind))
            .collect();
        assert!(
            bad_kind.is_empty(),
            "kind not in UNHONOURED_CITATION_KINDS: {bad_kind:?} — the static \
             gate dispatches on this word, and a word it does not know is a row \
             it would skip"
        );

        let mut seen: Vec<&str> = UNHONOURED_CITATION_LEDGER
            .iter()
            .map(|(k, ..)| *k)
            .collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "a key carries two citation rows — two answers to one question, \
             which is the shape the two-list split exists to refuse"
        );

        let not_unhonoured: Vec<&str> = UNHONOURED_CITATION_LEDGER
            .iter()
            .map(|(k, ..)| *k)
            .filter(|k| !UNHONOURED_UPSTREAM_CONFIG_KEYS.contains(k))
            .collect();
        assert!(
            not_unhonoured.is_empty(),
            "citation row for a key that is not unhonoured: {not_unhonoured:?} \
             — if it became honoured, drop its row in the round that moved it"
        );

        let misplaced: Vec<&(&str, &str, &str)> = UNHONOURED_CITATION_LEDGER
            .iter()
            .filter(|(key, kind, _)| {
                let claims_capability = *kind == "wz-has-it";
                claims_capability != UNHONOURED_READER_GAP.contains(key)
            })
            .collect();
        assert!(
            misplaced.is_empty(),
            "kind and list disagree: {misplaced:?}. `wz-has-it` means wz ALREADY \
             ACTS ON the key, which is what UNHONOURED_READER_GAP is; every \
             other kind means the citation is about something else, which is \
             UNHONOURED_BEYOND_WZ. Moving a row between the lists without \
             moving its kind is exactly the un-caught misclassification item \
             539 names."
        );

        let unevidenced: Vec<&&str> = UNHONOURED_READER_GAP
            .iter()
            .filter(|k| {
                !UNHONOURED_CITATION_LEDGER
                    .iter()
                    .any(|(key, kind, _)| key == *k && *kind == "wz-has-it")
            })
            .collect();
        assert!(
            unevidenced.is_empty(),
            "reader gap with no `wz-has-it` row: {unevidenced:?} — the list's \
             own doc says every entry is evidenced by wz's source naming the \
             key, and until this row exists that sentence is prose"
        );

        // The breakdown, per kind, and a floor on each: a kind with no rows is
        // a branch of the static gate nobody has ever run, and "19 rows" reads
        // the same whether that is true or not.
        for kind in UNHONOURED_CITATION_KINDS {
            let rows: Vec<&str> = UNHONOURED_CITATION_LEDGER
                .iter()
                .filter(|(_, k, _)| k == kind)
                .map(|(key, ..)| *key)
                .collect();
            assert!(
                !rows.is_empty(),
                "citation kind `{kind}` has no rows — drop the kind or find its \
                 member; an unexercised branch is not coverage"
            );
            println!("citation kind {kind}: {} row(s) {rows:?}", rows.len());
        }
    }

    /// Every key wz CANNOT act on says which subsystem it would need.
    ///
    /// R2151 (open-debt item 540) — the list-shape half of the mirror, split
    /// from the tree-evidence half the same way R2150 split the citation
    /// ledger: this test owns TOTALITY and DISJOINTNESS, and
    /// `unhonoured_kind_evidence_gate.py` owns "the anchor is absent from wz's
    /// code" and "the doc names it", which need a sweep. No predicate is
    /// written in both places.
    ///
    /// Totality is the load-bearing half. A key added to
    /// [`UNHONOURED_BEYOND_WZ`] with no group is a key whose "wz cannot do
    /// this" rests on nothing, and that is the state every one of the eleven
    /// rows R2151 moved was in.
    #[test]
    fn every_key_wz_cannot_act_on_names_the_subsystem_it_would_need() {
        assert!(
            !UNHONOURED_BEYOND_GROUPS.is_empty(),
            "an empty group table accounts for nothing and passes every check \
             below by having no rows"
        );

        let mut grouped: Vec<&str> = UNHONOURED_BEYOND_GROUPS
            .iter()
            .flat_map(|(_, _, keys)| keys.iter().copied())
            .collect();
        let before = grouped.len();
        grouped.sort_unstable();
        grouped.dedup();
        assert_eq!(
            before,
            grouped.len(),
            "a key is in two groups — two answers to 'which subsystem does this \
             need', which is the undivided state the table exists to end"
        );

        let ungrouped: Vec<&&str> = UNHONOURED_BEYOND_WZ
            .iter()
            .filter(|k| !grouped.contains(k))
            .collect();
        assert!(
            ungrouped.is_empty(),
            "beyond-wz key in no group: {ungrouped:?}. Saying wz cannot act on a \
             key is a claim about a subsystem wz does not have; name it in \
             UNHONOURED_BEYOND_GROUPS so the static gate can check it is still \
             absent."
        );

        let stale: Vec<&&str> = grouped
            .iter()
            .filter(|k| !UNHONOURED_BEYOND_WZ.contains(k))
            .collect();
        assert!(
            stale.is_empty(),
            "grouped key that is no longer beyond wz: {stale:?} — if it became \
             a reader gap or honoured, drop it from its group in the round that \
             moved it"
        );

        let mut anchors: Vec<&str> = UNHONOURED_BEYOND_GROUPS
            .iter()
            .map(|(_, anchor, _)| *anchor)
            .collect();
        let n = anchors.len();
        anchors.sort_unstable();
        anchors.dedup();
        assert_eq!(
            n,
            anchors.len(),
            "two groups share an anchor — then they are one group, and the \
             split is telling a reader something the data does not"
        );

        for (need, anchor, keys) in UNHONOURED_BEYOND_GROUPS {
            assert!(
                !keys.is_empty(),
                "group `{need}` ({anchor}) holds no key — an absence claim about \
                 nothing"
            );
            println!("beyond group {anchor}: {} key(s) — {need}", keys.len());
        }
    }

    /// Whether `path` names something strictly INSIDE `key`.
    ///
    /// The length guard is not decoration: `path == key` would index one byte
    /// past the end of `path`. `upstream_knows` spells the same predicate the
    /// same way, and the three tests below share this one rather than each
    /// restating it — a partition rule written three times is three things to
    /// get wrong, and two of the three drafts here were missing the guard.
    fn strictly_below(path: &str, key: &str) -> bool {
        path.len() > key.len() && path.starts_with(key) && path.as_bytes()[key.len()] == b'/'
    }

    /// Which side claims the leaves a document can put BELOW a surface key.
    ///
    /// R2147 (open-debt items 215 and 217) — the population is
    /// [`DEEPENABLE_UPSTREAM_KEYS`], and it is not a list of interesting cases:
    /// it is DEFINED as the keys below which a real zenohd accepts leaves this
    /// tree's census surface does not list, one zenohd run per entry. So it is
    /// exactly the set of places where the census DENOMINATOR is a function of
    /// what the operator's file fills in, which is the sentence both items are
    /// about. Deriving it rather than naming cases is the whole method here: a
    /// key that becomes deepenable joins this population by joining that list.
    ///
    /// Each member must be claimed by exactly one mechanism, and WHICH one is
    /// forced by whether wz honours the key:
    ///
    /// * MODE — the key is in [`MODE_DEPENDENT_CONFIG_KEYS`], so its deeper
    ///   leaves are the `{ router, peer, client }` table wz just resolved and
    ///   `inside_a_mode_table` keeps them out of the ignored partition;
    /// * SUBTREE — the key has entries in [`HONOURED_SUBTREE_LEAVES`], so the
    ///   named fields of a honoured block are claimed one by one;
    /// * OPAQUE — nothing claims them, so they fall into `ignored`.
    ///
    /// A HONOURED key that is OPAQUE is item 215's defect: wz would apply the
    /// block and report its own fields as "wz does not honour this" in the same
    /// breath. Nothing caught that before this test — R2141 moved three
    /// deepenable keys into the honoured half and got it right by hand, and
    /// R311y849 added [`HONOURED_SUBTREE_LEAVES`] for `connect/retry` by hand.
    /// So this is a ratchet over a population that is currently clean, not a fix
    /// for a live defect, and saying so is part of the claim.
    #[test]
    fn every_denominator_shifting_key_is_claimed_by_the_side_that_honours_it() {
        assert!(
            !DEEPENABLE_UPSTREAM_KEYS.is_empty(),
            "the population is empty, so every rule below is vacuous"
        );

        let mut mode = Vec::new();
        let mut subtree = Vec::new();
        let mut opaque = Vec::new();
        for key in DEEPENABLE_UPSTREAM_KEYS {
            let honoured = HONOURED_CONFIG_KEYS.contains(key);
            let claimed_by_table = MODE_DEPENDENT_CONFIG_KEYS.contains(key);
            let claimed_by_fields = HONOURED_SUBTREE_LEAVES
                .iter()
                .any(|leaf| strictly_below(leaf, key));
            assert!(
                !(claimed_by_table && claimed_by_fields),
                "{key} is claimed twice: a mode table and named subtree fields \
                 are two different readings of the same leaves"
            );

            if claimed_by_table {
                mode.push(*key);
            } else if claimed_by_fields {
                subtree.push(*key);
            } else {
                opaque.push(*key);
            }

            if honoured {
                assert!(
                    claimed_by_table || claimed_by_fields,
                    "{key} is HONOURED and its deeper leaves are claimed by \
                     nothing, so a file that fills the block gets it applied and \
                     its own fields reported as unhonoured. Add the fields to \
                     HONOURED_SUBTREE_LEAVES, or the key to \
                     MODE_DEPENDENT_CONFIG_KEYS if upstream spells it \
                     `ModeDependentValue`."
                );
            } else {
                assert!(
                    !claimed_by_fields,
                    "{key} is NOT honoured yet has entries in \
                     HONOURED_SUBTREE_LEAVES — claiming leaves under a key wz \
                     does not apply hides them from the operator"
                );
            }
        }

        // The breakdown, not the total: a floor on the sum would be met by one
        // bucket growing while another emptied, and an empty bucket is a rule
        // that stopped being exercised.
        println!(
            "denominator-shifting keys: {} total — {} mode-table {mode:?}, \
             {} named-subtree {subtree:?}, {} opaque {opaque:?}",
            DEEPENABLE_UPSTREAM_KEYS.len(),
            mode.len(),
            subtree.len(),
            opaque.len()
        );
        assert!(!mode.is_empty(), "the mode-table bucket emptied");
        assert!(!subtree.is_empty(), "the named-subtree bucket emptied");
        assert!(!opaque.is_empty(), "the opaque bucket emptied");
    }

    /// The census denominator is the surface of a document that fills NOTHING.
    ///
    /// R2147 (open-debt item 217) — `wz_reads_a_stock_zenohd_config`'s census
    /// leg takes its denominator from a running zenohd handed `census_config`,
    /// and that fixture's doc comment says why it fills nothing: measured, the
    /// same census run against the OPERATOR fixture reported `metadata/name`
    /// where the canonical surface has `metadata`, because that fixture fills
    /// the subtree in. Until this test the reason lived only in that prose.
    ///
    /// The checkable form of it is here, in the constants, because that is
    /// where a violation has to surface. Filling a deepenable key in the fixture
    /// swaps `metadata` for `metadata/name` in the resolved surface, so the
    /// census leg's exact set comparison against
    /// [`UNHONOURED_UPSTREAM_CONFIG_KEYS`] REDS — and the only way to make it
    /// green again is to put the deeper leaf into a surface constant, which is
    /// what this test refuses. The fixture is guarded through the constants it
    /// would have to move, which is why this needs no zenohd and runs in every
    /// lane that compiles the crate; the census leg itself is `#[ignore]`d and
    /// only hosted Layer Z reaches it.
    #[test]
    fn the_census_denominator_is_the_surface_of_a_document_that_fills_nothing() {
        let below_a_deepenable_key = |path: &str| {
            DEEPENABLE_UPSTREAM_KEYS
                .iter()
                .any(|key| strictly_below(path, key))
        };

        let mut checked = 0usize;
        for key in HONOURED_CONFIG_KEYS
            .iter()
            .chain(UNHONOURED_UPSTREAM_CONFIG_KEYS)
        {
            assert!(
                !below_a_deepenable_key(key),
                "{key} sits BELOW a deepenable key, so the surface it belongs to \
                 was resolved from a document that FILLED that subtree. The \
                 denominator would then be the fixture's surface rather than \
                 upstream's, and the honoured fraction would silently start \
                 counting something else."
            );
            checked += 1;
        }
        assert_eq!(
            checked,
            HONOURED_CONFIG_KEYS.len() + UNHONOURED_UPSTREAM_CONFIG_KEYS.len(),
            "the sweep did not reach the whole surface"
        );

        // The other direction: the fields of a honoured subtree are claimed for
        // the `ignored` report and must NOT be in the surface, or one census
        // leaf would be counted as several and the denominator would inflate
        // without any fixture changing at all.
        assert!(!HONOURED_SUBTREE_LEAVES.is_empty());
        for leaf in HONOURED_SUBTREE_LEAVES {
            assert!(
                !HONOURED_CONFIG_KEYS.contains(leaf)
                    && !UNHONOURED_UPSTREAM_CONFIG_KEYS.contains(leaf),
                "{leaf} is a subtree FIELD and also a surface key — a real \
                 zenohd resolves one leaf there, so the surface must carry the \
                 subtree and not its contents"
            );
            let owner = leaf.rsplit_once('/').expect("a field has a parent").0;
            assert!(
                HONOURED_CONFIG_KEYS.contains(&owner),
                "{leaf} names fields under {owner}, which wz does not honour"
            );
            assert!(
                DEEPENABLE_UPSTREAM_KEYS.contains(&owner),
                "{leaf} names fields under {owner}, which a real zenohd does not \
                 accept a deeper shape at — measured by `deepenable_audit.py`"
            );
        }
        println!(
            "census denominator: {} surface key(s), none below any of the {} \
             denominator-shifting keys; {} honoured subtree field(s) held OUT of \
             the surface",
            checked,
            DEEPENABLE_UPSTREAM_KEYS.len(),
            HONOURED_SUBTREE_LEAVES.len()
        );
    }

    /// What the reader ACTUALLY does with a leaf below each of those keys.
    ///
    /// R2147 (open-debt items 215 and 217) — the test above is set arithmetic
    /// over four constants, and set arithmetic can agree with itself while the
    /// reader does something else. This drives every member of the same derived
    /// population through `from_json5` and asserts which partition the deeper
    /// leaf lands in, which is the thing an operator sees.
    ///
    /// No per-key value knowledge is needed, and that is deliberate — a table of
    /// values would be a copy of the reader's own type expectations:
    ///
    /// * the mode-table probe names `router` while the document says
    ///   `mode: "peer"`, so `for_this_mode` returns "no instruction for this
    ///   node" WITHOUT ever inspecting the value;
    /// * the subtree probe uses an integer, which
    ///   `a_partial_connect_retry_block_fills_the_rest_from_zenoh_defaults`
    ///   measured reads as a float too, so one literal covers both field types;
    /// * the opaque probe's value is never read by anything.
    #[test]
    fn every_denominator_shifting_key_puts_its_deeper_leaves_in_the_right_partition() {
        let (mut mode_n, mut subtree_n, mut opaque_n) = (0usize, 0usize, 0usize);

        for key in DEEPENABLE_UPSTREAM_KEYS {
            let fields: Vec<&&str> = HONOURED_SUBTREE_LEAVES
                .iter()
                .filter(|leaf| strictly_below(leaf, key))
                .collect();

            if MODE_DEPENDENT_CONFIG_KEYS.contains(key) {
                let doc = nested(key, "{ router: 1 }");
                let ingest = ZenohNodeConfig::from_json5(&doc)
                    .unwrap_or_else(|e| panic!("{key}: a mode table was refused: {e:?}\n{doc}"));
                let leaf = format!("{key}/router");
                assert!(
                    !ingest.ignored.contains(&leaf),
                    "{key}: `{leaf}` was reported as a key wz does not honour, \
                     but it is a row of a mode table wz just resolved\n{:?}",
                    ingest.ignored
                );
                assert!(
                    ingest.stated_for_other_modes.contains(key),
                    "{key}: a table naming only `router` says nothing to a peer, \
                     so the operator has to be told it was stated for another \
                     mode\n{:?}",
                    ingest.stated_for_other_modes
                );
                mode_n += 1;
            } else if !fields.is_empty() {
                for field in &fields {
                    let doc = nested(field, "1");
                    let ingest = ZenohNodeConfig::from_json5(&doc).unwrap_or_else(|e| {
                        panic!("{field}: a honoured subtree field was refused: {e:?}\n{doc}")
                    });
                    assert!(
                        !ingest.ignored.iter().any(|p| p == **field),
                        "{key}: `{field}` was reported unhonoured while wz \
                         applied the block it belongs to\n{:?}",
                        ingest.ignored
                    );
                    assert!(
                        ingest.named.contains(key),
                        "{key}: a stated field must name the subtree once\n{:?}",
                        ingest.named
                    );
                }
                // And a field the list does NOT name is still reported: the
                // acceptance boundary lets it through (a real zenohd starts on
                // it) and wz's answer to that is to REPORT it, which is the one
                // thing upstream does not do for the operator.
                let stray = format!("{key}/zzz_probe_leaf");
                let doc = nested(&stray, "1");
                let ingest = ZenohNodeConfig::from_json5(&doc)
                    .unwrap_or_else(|e| panic!("{stray}: refused: {e:?}\n{doc}"));
                assert!(
                    ingest.ignored.contains(&stray),
                    "{key}: `{stray}` is not one of the block's fields and was \
                     swallowed silently\n{:?}",
                    ingest.ignored
                );
                subtree_n += 1;
            } else {
                let stray = format!("{key}/zzz_probe_leaf");
                let doc = nested(&stray, "1");
                let ingest = ZenohNodeConfig::from_json5(&doc)
                    .unwrap_or_else(|e| panic!("{stray}: refused: {e:?}\n{doc}"));
                assert!(
                    ingest.ignored.contains(&stray),
                    "{key}: an opaque subtree's contents must be REPORTED, or an \
                     operator believes a block took effect that wz never read\n{:?}",
                    ingest.ignored
                );
                assert!(
                    !ingest.named.contains(key),
                    "{key}: wz does not honour this key, so nothing under it may \
                     name it\n{:?}",
                    ingest.named
                );
                opaque_n += 1;
            }
        }

        println!(
            "deeper-leaf partitions driven: {mode_n} mode-table, {subtree_n} \
             named-subtree, {opaque_n} opaque"
        );
        assert_eq!(
            mode_n + subtree_n + opaque_n,
            DEEPENABLE_UPSTREAM_KEYS.len(),
            "a member of the population was driven through no probe at all"
        );
        // Per-bucket floors. A total floor would let the opaque bucket carry a
        // shrinking mode bucket, and the mode arm is the one R2141 grew.
        assert!(mode_n > 0 && subtree_n > 0 && opaque_n > 0);
    }
}
