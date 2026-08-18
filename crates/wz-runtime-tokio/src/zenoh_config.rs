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
//! * **validate** — `ZenohNodeConfig::validate` answers "can this topology
//!   work" WITHOUT starting a node: an unknown link protocol, a client that
//!   can reach nothing, the QoS-with-lowlatency pair zenoh's own config
//!   documents as incompatible.
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Every reason this topology cannot work, in a stable order. An empty
    /// result means the config is coherent — NOT that the node will find a
    /// peer, which is a question about the network rather than the config.
    pub fn validate(&self) -> Vec<ConfigDefect> {
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
    "connect/retry",
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
    "routing/peer/mode",
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
fn upstream_knows(path: &str) -> bool {
    HONOURED_CONFIG_KEYS
        .iter()
        .chain(UNHONOURED_UPSTREAM_CONFIG_KEYS)
        .any(|known| {
            path == *known
                || (path.len() > known.len()
                    && path.starts_with(known)
                    && path.as_bytes()[known.len()] == b'/')
        })
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

fn want_bool(doc: &Json5Value, path: &'static str) -> Result<Option<bool>, ConfigIngestError> {
    match honoured(doc, path) {
        None => Ok(None),
        Some(Json5Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(ConfigIngestError::WrongType {
            path,
            expected: "a boolean",
        }),
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

fn want_endpoints(
    doc: &Json5Value,
    path: &'static str,
) -> Result<Option<Vec<String>>, ConfigIngestError> {
    match honoured(doc, path) {
        None => Ok(None),
        Some(Json5Value::Array(items)) => {
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
            Ok(Some(out))
        }
        Some(_) => Err(ConfigIngestError::WrongType {
            path,
            expected: "an array of endpoint strings",
        }),
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
        if let Some(v) = want_endpoints(&doc, "connect/endpoints")? {
            out.connect = v;
            named.push("connect/endpoints");
        }
        if let Some(v) = want_endpoints(&doc, "listen/endpoints")? {
            out.listen = v;
            named.push("listen/endpoints");
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
        if let Some(v) = want_bool(&doc, "scouting/multicast/listen")? {
            out.scout_multicast_listen = Some(v);
            named.push("scouting/multicast/listen");
        }
        if let Some(v) = want_bool(&doc, "timestamping/enabled")? {
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
            .filter(|p| !HONOURED_CONFIG_KEYS.contains(&p.as_str()))
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
        let filled = ZenohNodeConfig::from_json5(
            r#"{ "connect": { "retry": { "period_init_ms": 1000 } },
                 "metadata": { "name": "strawberry" },
                 "plugins": { "rest": { "http_port": 8000 } } }"#,
        )
        .expect("a filled-in upstream subtree is a valid config");
        assert_eq!(
            filled.ignored,
            vec![
                "connect/retry/period_init_ms",
                "metadata/name",
                "plugins/rest/http_port"
            ]
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
}
