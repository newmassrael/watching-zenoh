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
//! * **emit** — [`ZenohNodeConfig::to_json5`] renders the config zenoh's own
//!   `-c` flag reads, with the key paths taken from the reference's
//!   `DEFAULT_CONFIG.json5` rather than from memory.
//! * **validate** — [`ZenohNodeConfig::validate`] answers "can this topology
//!   work" WITHOUT starting a node: an unknown link protocol, a client that
//!   can reach nothing, the QoS-with-lowlatency pair zenoh's own config
//!   documents as incompatible.
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
        out.push_str(" },\n  \"scouting\": { \"multicast\": { \"enabled\": ");
        let _ = write!(out, "{}", self.multicast_scouting);
        out.push_str(" } },\n  \"timestamping\": { \"enabled\": ");
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
        out.push_str("    },\n    \"link\": {\n      \"tx\": {\n");
        let _ = writeln!(out, "        \"batch_size\": {},", self.batch_size);
        let _ = writeln!(out, "        \"lease\": {}", self.lease_ms);
        out.push_str("      }\n    }\n  }");
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
