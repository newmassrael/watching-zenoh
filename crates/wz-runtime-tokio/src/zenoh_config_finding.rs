// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ZA-3469 — a config verdict as FIELDS, for a reader that does not parse prose.
//!
//! The three reasons a config can be turned away are three enums in
//! `zenoh_config`: `ConfigDefect` (this node cannot work), `TopologyDefect`
//! (this SET of nodes cannot work) and `ConfigIngestError` (the document was
//! not read at all). Each already carries the facts a reader wants — a node, an
//! endpoint, a key path — as separate fields, and each renders them into ONE
//! sentence through `Display`. That sentence is the right thing to show a
//! person and the wrong thing to hand a program: a consumer that attaches a
//! reason to the config field it is about would have to parse the sentence
//! back, and prose is the half that may be reworded in any release.
//!
//! This module is the projection the sentence was made from. A `Finding` is
//! one defect with its variant name, its prose, the endpoint it is about, and
//! the `BlamedSite`s it points at — each site a node and a config key path.
//!
//! ## Why the key is derived HERE and not left to the consumer
//!
//! Which key a defect blames is a fact about the defect, not about whoever
//! reads it. `ZeroBatchSize` is about `transport/link/tx/batch_size` whether
//! the reader is a C door, a CLI or an inspector, and a consumer that spelled
//! the mapping itself would hold a second copy of the variant list that goes
//! stale in the direction that reports nothing. The `match` arms below carry no
//! wildcard, so a variant added to any of the three enums does not compile
//! until it says what it blames, and
//! `every_blamed_key_is_one_the_reader_honours` holds each spelling against the
//! reader's own key list.
//!
//! ## One row per site
//!
//! A defect can point at several places: `Unreachable` at the three keys that
//! could have given the node a peer, `ListenEndpointCollision` at every node
//! that claims the address. A finding therefore carries a LIST of sites, and a
//! flattened table (variant, node, key, endpoint) is one row per site with the
//! finding repeated. The list is never empty: a defect that blames nothing
//! (an external declaration, which lives in argv rather than in any config)
//! still has one site with neither a node nor a key, so "one row per site"
//! never drops a defect.

use core::fmt::{Debug, Display};

use crate::zenoh_config::{ConfigDefect, ConfigIngestError, EndpointList, TopologyDefect};

/// `mode`.
const KEY_MODE: &str = "mode";
/// `scouting/multicast/enabled`.
const KEY_SCOUTING_MULTICAST: &str = "scouting/multicast/enabled";
/// `transport/unicast/qos/enabled`.
const KEY_UNICAST_QOS: &str = "transport/unicast/qos/enabled";
/// `transport/unicast/lowlatency`.
const KEY_UNICAST_LOWLATENCY: &str = "transport/unicast/lowlatency";
/// `transport/link/tx/batch_size`.
const KEY_BATCH_SIZE: &str = "transport/link/tx/batch_size";
/// `transport/link/tx/lease`.
const KEY_LEASE: &str = "transport/link/tx/lease";
/// `transport/unicast/max_links`.
const KEY_MAX_LINKS: &str = "transport/unicast/max_links";

/// One place a finding is about: a config key path, in a node.
///
/// Either half can be absent, and each absence means something different. No
/// node: the finding is about a single config read on its own, which has no
/// name. No key: the finding is about something that is not a config key at
/// all (a declaration typed at argv), or about a document that never got far
/// enough to have a key at fault (not JSON5, not an object).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlamedSite {
    /// The node, as the caller named it, else by its `id`, else by position.
    pub node: Option<String>,
    /// The config key path at fault, `/`-separated as zenoh spells it.
    pub key: Option<String>,
}

impl BlamedSite {
    /// A site in `node` at `key`; either may be absent.
    pub fn at(node: Option<&str>, key: Option<&str>) -> BlamedSite {
        BlamedSite {
            node: node.map(String::from),
            key: key.map(String::from),
        }
    }
}

/// One defect, as fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Finding {
    /// The defect's variant name — the stable half. It is taken from the
    /// variant's own `Debug` output rather than typed in a table, so it cannot
    /// name a variant that no longer exists.
    pub variant: String,
    /// The prose `Display` gives. Reworded freely between releases; show it,
    /// do not branch on it.
    pub message: String,
    /// The endpoint the defect is about, when it is about one.
    pub endpoint: Option<String>,
    /// Where the defect points. Never empty.
    pub sites: Vec<BlamedSite>,
}

impl Finding {
    /// Describe `defect`: its variant name, its prose, the endpoint it is about
    /// and where it points.
    ///
    /// `sites` empty is normalised to one site with neither node nor key, which
    /// is the invariant `Finding::sites` states rather than a case the caller
    /// has to remember.
    pub fn describing<D: Debug + Display>(
        defect: &D,
        endpoint: Option<&str>,
        sites: Vec<BlamedSite>,
    ) -> Finding {
        let sites = if sites.is_empty() {
            vec![BlamedSite::at(None, None)]
        } else {
            sites
        };
        Finding {
            variant: variant_name(defect),
            message: defect.to_string(),
            endpoint: endpoint.map(String::from),
            sites,
        }
    }
}

/// The variant identifier of an enum value: the leading identifier of its
/// `Debug` output, which opens with the variant name for every enum shape
/// (unit, tuple and struct).
///
/// Derived rather than tabulated, because a hand-typed name is a second copy of
/// the variant list that survives a rename of the variant it names.
pub fn variant_name<D: Debug>(defect: &D) -> String {
    let debug = format!("{defect:?}");
    debug
        .split(|c: char| c == '{' || c == '(' || c.is_whitespace())
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// One site per key, all in `node`. A defect that names no key still names its
/// node, so the site is kept with an absent key rather than dropped.
fn sites_in(node: Option<&str>, keys: &[&str]) -> Vec<BlamedSite> {
    if keys.is_empty() {
        return vec![BlamedSite::at(node, None)];
    }
    keys.iter()
        .map(|key| BlamedSite::at(node, Some(*key)))
        .collect()
}

impl ConfigDefect {
    /// This defect as fields. `node` names the config it was found in, when
    /// the caller has a name for it; a config judged on its own has none.
    pub fn finding(&self, node: Option<&str>) -> Finding {
        let (endpoint, keys): (Option<&str>, Vec<&str>) = match self {
            ConfigDefect::MalformedEndpoint { endpoint, list }
            | ConfigDefect::UnknownProtocol { endpoint, list, .. }
            | ConfigDefect::ProtocolNotCompiledIn { endpoint, list, .. } => {
                (Some(endpoint), vec![list.key()])
            }
            ConfigDefect::DuplicateListenEndpoint { endpoint } => {
                (Some(endpoint), vec![EndpointList::Listen.key()])
            }
            // The three places that could have given the node a peer, in the
            // order the sentence lists them.
            ConfigDefect::Unreachable => (
                None,
                vec![
                    EndpointList::Connect.key(),
                    EndpointList::Listen.key(),
                    KEY_SCOUTING_MULTICAST,
                ],
            ),
            ConfigDefect::QosWithLowlatency => {
                (None, vec![KEY_UNICAST_QOS, KEY_UNICAST_LOWLATENCY])
            }
            ConfigDefect::ZeroBatchSize => (None, vec![KEY_BATCH_SIZE]),
            ConfigDefect::ZeroLease => (None, vec![KEY_LEASE]),
            ConfigDefect::ZeroMaxLinks => (None, vec![KEY_MAX_LINKS]),
        };
        Finding::describing(self, endpoint, sites_in(node, &keys))
    }
}

impl ConfigIngestError {
    /// This refusal as fields. `node` names the config that was refused, when
    /// the caller has a name for it.
    ///
    /// A refusal that is not about any one key — the text is not JSON5, or its
    /// top level is not an object — keeps its node and has no key.
    pub fn finding(&self, node: Option<&str>) -> Finding {
        let key: Option<&str> = match self {
            ConfigIngestError::Syntax(_) | ConfigIngestError::NotAnObject => None,
            ConfigIngestError::WrongType { path, .. }
            | ConfigIngestError::OutOfRange { path, .. }
            | ConfigIngestError::UnreadableNumber { path, .. }
            | ConfigIngestError::MalformedZid { path, .. } => Some(*path),
            ConfigIngestError::UnknownMode { .. } => Some(KEY_MODE),
            ConfigIngestError::UnknownKey { path } => Some(path.as_str()),
        };
        let keys: Vec<&str> = key.into_iter().collect();
        Finding::describing(self, None, sites_in(node, &keys))
    }
}

impl TopologyDefect {
    /// This defect as fields. The nodes are already named inside the defect,
    /// by whatever name the verdict was asked with.
    pub fn finding(&self) -> Finding {
        match self {
            TopologyDefect::DanglingConnectTarget { node, endpoint } => Finding::describing(
                self,
                Some(endpoint),
                sites_in(Some(node), &[EndpointList::Connect.key()]),
            ),
            TopologyDefect::ListenEndpointCollision { endpoint, nodes } => Finding::describing(
                self,
                Some(endpoint),
                nodes
                    .iter()
                    .flat_map(|node| sites_in(Some(node), &[EndpointList::Listen.key()]))
                    .collect(),
            ),
            TopologyDefect::NoNodeAccepts { nodes } => Finding::describing(
                self,
                None,
                nodes
                    .iter()
                    .flat_map(|node| sites_in(Some(node), &[KEY_MODE]))
                    .collect(),
            ),
            // Declared at argv: about an endpoint, and in no config at all.
            TopologyDefect::UnusedExternalListener { endpoint }
            | TopologyDefect::MalformedExternalListener { endpoint } => {
                Finding::describing(self, Some(endpoint), Vec::new())
            }
            TopologyDefect::ExternalShadowsListener { endpoint, node } => Finding::describing(
                self,
                Some(endpoint),
                sites_in(Some(node), &[EndpointList::Listen.key()]),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zenoh_config::{
        validate_labelled_topology, validate_topology, LabelledNode, WhatAmI, ZenohNodeConfig,
        HONOURED_CONFIG_KEYS,
    };
    use wz_session_core::json5::{self, Json5Value, UpstreamNumberError};

    /// A node with an `id` and no scouting, so the only defects a set of them
    /// raises are the ones the case is about.
    fn node(mode: WhatAmI, id: &str) -> ZenohNodeConfig {
        ZenohNodeConfig {
            mode,
            id: Some(String::from(id)),
            multicast_scouting: false,
            ..Default::default()
        }
    }

    fn keys_of(finding: &Finding) -> Vec<&str> {
        finding
            .sites
            .iter()
            .filter_map(|site| site.key.as_deref())
            .collect()
    }

    /// The whole point of the field: the same string sitting in the OTHER list
    /// blames the OTHER key, so the key is the list the endpoint was read
    /// from and not something found by searching for it afterwards.
    #[test]
    fn an_endpoint_defect_blames_the_list_it_was_read_from() {
        let config = ZenohNodeConfig::default()
            .listening_on("nonsense")
            .connecting_to("nonsense");
        let findings: Vec<Finding> = config
            .validate()
            .iter()
            .map(|defect| defect.finding(None))
            .collect();
        assert_eq!(findings.len(), 2, "{findings:?}");
        // Listen is judged first, and that order is the verdict's own.
        assert_eq!(
            findings[0].sites,
            vec![BlamedSite::at(None, Some("listen/endpoints"))]
        );
        assert_eq!(
            findings[1].sites,
            vec![BlamedSite::at(None, Some("connect/endpoints"))]
        );
        for finding in &findings {
            assert_eq!(finding.variant, "MalformedEndpoint");
            assert_eq!(finding.endpoint.as_deref(), Some("nonsense"));
        }

        // The same holds for the other two endpoint defects, and for the
        // build-scoped one that only the reader-aware verdict raises.
        let config = ZenohNodeConfig::default()
            .connecting_to("carrier-pigeon/aviary:1")
            .connecting_to("vsock/2:7447");
        let findings: Vec<Finding> = config
            .validate_for_build(Some(&["tcp"]))
            .iter()
            .map(|defect| defect.finding(None))
            .collect();
        let variants: Vec<&str> = findings.iter().map(|f| f.variant.as_str()).collect();
        assert_eq!(variants, ["UnknownProtocol", "ProtocolNotCompiledIn"]);
        for finding in &findings {
            assert_eq!(keys_of(finding), ["connect/endpoints"]);
        }
    }

    /// A key path a defect blames has to be a place the offending value can be
    /// FOUND: the emitted document is where a config with that value writes it,
    /// so a spelling that is not there is a key nobody could look under.
    #[test]
    fn a_blamed_key_is_where_the_offending_value_is_written() {
        let unreachable = ZenohNodeConfig::default().with_multicast_scouting(false);
        let qos_lowlatency = ZenohNodeConfig {
            qos: true,
            lowlatency: true,
            ..Default::default()
        };
        let zero_batch = ZenohNodeConfig {
            batch_size: 0,
            ..Default::default()
        };
        let zero_lease = ZenohNodeConfig {
            lease_ms: 0,
            ..Default::default()
        };
        let zero_links = ZenohNodeConfig {
            max_links: 0,
            ..Default::default()
        };
        let duplicated = ZenohNodeConfig::default()
            .listening_on("tcp/10.0.0.5:7447")
            .listening_on("tcp/10.0.0.5:7447");
        let cases: [(&str, ZenohNodeConfig); 6] = [
            ("Unreachable", unreachable),
            ("QosWithLowlatency", qos_lowlatency),
            ("ZeroBatchSize", zero_batch),
            ("ZeroLease", zero_lease),
            ("ZeroMaxLinks", zero_links),
            ("DuplicateListenEndpoint", duplicated),
        ];
        for (variant, config) in cases {
            let document = json5::parse(&config.to_json5()).expect("the emitter writes JSON5");
            let findings: Vec<Finding> = config
                .validate()
                .iter()
                .map(|defect| defect.finding(None))
                .filter(|finding| finding.variant == variant)
                .collect();
            assert_eq!(findings.len(), 1, "{variant}: {findings:?}");
            for key in keys_of(&findings[0]) {
                let value = document.get(key);
                assert!(
                    value.is_some(),
                    "{variant} blames `{key}`, which the emitted document does not carry"
                );
                if let (Some(Json5Value::Array(items)), Some(endpoint)) =
                    (value, findings[0].endpoint.as_deref())
                {
                    assert!(
                        items.contains(&Json5Value::String(String::from(endpoint))),
                        "{variant}: `{key}` does not hold the endpoint {endpoint:?} it is blamed for"
                    );
                }
            }
        }
    }

    /// Every key a defect can blame is one the READER honours. A spelling typed
    /// into a `match` arm and later renamed in the honoured list would keep
    /// compiling and point a consumer at a key that no longer exists.
    #[test]
    fn every_blamed_key_is_one_the_reader_honours() {
        let endpoint = || String::from("x");
        let node = || String::from("n");
        let mut findings: Vec<Finding> = Vec::new();
        for list in [EndpointList::Listen, EndpointList::Connect] {
            findings.push(
                ConfigDefect::MalformedEndpoint {
                    endpoint: endpoint(),
                    list,
                }
                .finding(None),
            );
            findings.push(
                ConfigDefect::UnknownProtocol {
                    endpoint: endpoint(),
                    protocol: endpoint(),
                    list,
                }
                .finding(None),
            );
            findings.push(
                ConfigDefect::ProtocolNotCompiledIn {
                    endpoint: endpoint(),
                    protocol: endpoint(),
                    list,
                }
                .finding(None),
            );
        }
        for defect in [
            ConfigDefect::DuplicateListenEndpoint {
                endpoint: endpoint(),
            },
            ConfigDefect::Unreachable,
            ConfigDefect::QosWithLowlatency,
            ConfigDefect::ZeroBatchSize,
            ConfigDefect::ZeroLease,
            ConfigDefect::ZeroMaxLinks,
        ] {
            findings.push(defect.finding(None));
        }
        for defect in [
            TopologyDefect::DanglingConnectTarget {
                node: node(),
                endpoint: endpoint(),
            },
            TopologyDefect::ListenEndpointCollision {
                endpoint: endpoint(),
                nodes: vec![node(), node()],
            },
            TopologyDefect::NoNodeAccepts {
                nodes: vec![node()],
            },
            TopologyDefect::UnusedExternalListener {
                endpoint: endpoint(),
            },
            TopologyDefect::ExternalShadowsListener {
                endpoint: endpoint(),
                node: node(),
            },
            TopologyDefect::MalformedExternalListener {
                endpoint: endpoint(),
            },
        ] {
            findings.push(defect.finding());
        }
        findings.push(
            ConfigIngestError::UnknownMode {
                value: String::from("gateway"),
            }
            .finding(None),
        );
        assert!(findings.len() > 15, "the population shrank: {findings:?}");
        for finding in &findings {
            for key in keys_of(finding) {
                assert!(
                    HONOURED_CONFIG_KEYS.contains(&key),
                    "{} blames `{key}`, which the reader does not honour",
                    finding.variant
                );
            }
        }
    }

    /// The refusals a document can draw, each read through the real ingest so
    /// the key asserted is the one the reader named and not one this test made
    /// up.
    #[test]
    fn a_refused_document_blames_the_key_the_reader_named() {
        for (document, variant, key) in [
            (r#"{ "mode": "gateway" }"#, "UnknownMode", Some("mode")),
            (r#"{ "mode": 5 }"#, "WrongType", Some("mode")),
            (
                r#"{ "transport": { "link": { "tx": { "batch_size": 65536 } } } }"#,
                "OutOfRange",
                Some("transport/link/tx/batch_size"),
            ),
            (
                r#"{ "routing": { "router": { "linkstate": { "transport_weights":
                     [ { "dst_zid": "ABC", "weight": 10 } ] } } } }"#,
                "MalformedZid",
                Some("routing/router/linkstate/transport_weights"),
            ),
            (
                r#"{ "routing": { "router": { "linkstate": { "transport_weights":
                     { "dst_zid": "1", "weight": 10 } } } } }"#,
                "UnknownKey",
                Some("routing/router/linkstate/transport_weights/dst_zid"),
            ),
            ("[]", "NotAnObject", None),
            ("{", "Syntax", None),
        ] {
            let error = ZenohNodeConfig::from_json5(document).unwrap_err();
            let finding = error.finding(Some("edge"));
            assert_eq!(finding.variant, variant, "{document}");
            assert_eq!(finding.message, error.to_string());
            assert_eq!(finding.endpoint, None);
            // The node is kept even when no key is at fault: the caller still
            // needs to know WHICH config was refused.
            assert_eq!(
                finding.sites,
                vec![BlamedSite::at(Some("edge"), key)],
                "{document}"
            );
        }

        // Not reachable from a document a test can spell without also writing
        // an oversize literal into the emitted config, so it is built directly.
        let unreadable = ConfigIngestError::UnreadableNumber {
            path: "transport/link/tx/batch_size",
            reason: UpstreamNumberError::NotAnI64(String::from("99999999999999999999")),
        };
        assert_eq!(
            unreadable.finding(None).sites,
            vec![BlamedSite::at(None, Some("transport/link/tx/batch_size"))]
        );
    }

    /// The topology defects, each raised by the verdict itself over sets a
    /// reader would recognise, and each blaming the nodes and key it should.
    #[test]
    fn a_topology_defect_blames_each_node_it_is_about() {
        let dial = node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.9:7447");
        let router = node(WhatAmI::Router, "R").listening_on("tcp/10.0.0.5:7447");
        let dangling = validate_topology(&[dial.clone(), router.clone()]);
        assert_eq!(dangling.len(), 1, "{dangling:?}");
        let finding = dangling[0].finding();
        assert_eq!(finding.variant, "DanglingConnectTarget");
        assert_eq!(finding.endpoint.as_deref(), Some("tcp/10.0.0.9:7447"));
        assert_eq!(
            finding.sites,
            vec![BlamedSite::at(Some("A"), Some("connect/endpoints"))]
        );

        let twin = node(WhatAmI::Router, "S").listening_on("tcp/10.0.0.5:7447");
        let collision = validate_topology(&[router, twin]);
        assert_eq!(collision.len(), 1, "{collision:?}");
        let finding = collision[0].finding();
        assert_eq!(finding.variant, "ListenEndpointCollision");
        assert_eq!(
            finding.sites,
            vec![
                BlamedSite::at(Some("R"), Some("listen/endpoints")),
                BlamedSite::at(Some("S"), Some("listen/endpoints")),
            ],
            "one site per claimant"
        );

        let clients = validate_topology(&[
            node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.5:7447"),
            node(WhatAmI::Client, "B").connecting_to("tcp/10.0.0.5:7447"),
        ]);
        let finding = clients
            .iter()
            .find(|defect| matches!(defect, TopologyDefect::NoNodeAccepts { .. }))
            .expect("an all-client set is called out")
            .finding();
        assert_eq!(finding.endpoint, None);
        assert_eq!(
            finding.sites,
            vec![
                BlamedSite::at(Some("A"), Some("mode")),
                BlamedSite::at(Some("B"), Some("mode")),
            ],
            "the defect is about every node, and says which"
        );

        // The three external-declaration defects. Two of them are about no
        // config at all, and must still be one site rather than none.
        let a = node(WhatAmI::Client, "A").connecting_to("tcp/10.0.0.9:7447");
        let r = node(WhatAmI::Router, "R").listening_on("tcp/10.0.0.5:7447");
        let nodes = [LabelledNode::new(None, &a), LabelledNode::new(None, &r)];
        let verdict = validate_labelled_topology(
            &nodes,
            &[
                String::from("tcp/10.0.0.9:7447"),
                String::from("tcp/10.0.0.5:7447"),
                String::from("tcp/10.0.0.77:7447"),
                String::from("not-an-endpoint"),
            ],
        );
        let mut by_variant: Vec<(String, Finding)> = verdict
            .defects
            .iter()
            .map(|defect| {
                let finding = defect.finding();
                (finding.variant.clone(), finding)
            })
            .collect();
        by_variant.sort_by(|a, b| a.0.cmp(&b.0));
        let names: Vec<&str> = by_variant.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "ExternalShadowsListener",
                "MalformedExternalListener",
                "UnusedExternalListener"
            ],
            "{verdict:?}"
        );
        assert_eq!(
            by_variant[0].1.sites,
            vec![BlamedSite::at(Some("R"), Some("listen/endpoints"))]
        );
        assert_eq!(by_variant[1].1.sites, vec![BlamedSite::at(None, None)]);
        assert_eq!(by_variant[1].1.endpoint.as_deref(), Some("not-an-endpoint"));
        assert_eq!(by_variant[2].1.sites, vec![BlamedSite::at(None, None)]);
    }

    /// A caller's label wins over the config's `id`, which wins over the
    /// position; the labelled entry point is the same verdict as the unlabelled
    /// one and differs only in what it calls its nodes.
    #[test]
    fn a_topology_verdict_calls_a_node_by_the_name_it_was_given() {
        let with_id = node(WhatAmI::Client, "zid-1").connecting_to("tcp/10.0.0.9:7447");
        let without_id = ZenohNodeConfig {
            mode: WhatAmI::Client,
            multicast_scouting: false,
            ..Default::default()
        }
        .connecting_to("tcp/10.0.0.9:7448");
        let labelled = ZenohNodeConfig {
            mode: WhatAmI::Client,
            multicast_scouting: false,
            id: Some(String::from("zid-3")),
            ..Default::default()
        }
        .connecting_to("tcp/10.0.0.9:7449");

        let nodes = [
            LabelledNode::new(None, &with_id),
            LabelledNode::new(None, &without_id),
            LabelledNode::new(Some("gateway-west"), &labelled),
        ];
        let verdict = validate_labelled_topology(&nodes, &[]);
        let dangling: Vec<&str> = verdict
            .defects
            .iter()
            .filter_map(|defect| match defect {
                TopologyDefect::DanglingConnectTarget { node, .. } => Some(node.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            dangling,
            ["zid-1", "node[1]", "gateway-west"],
            "id, then position, and a label over an id"
        );
        assert!(verdict.defects.contains(&TopologyDefect::NoNodeAccepts {
            nodes: vec![
                String::from("zid-1"),
                String::from("node[1]"),
                String::from("gateway-west"),
            ],
        }));

        // The unlabelled entry point IS this one with no labels.
        let plain = [with_id.clone(), without_id.clone(), labelled.clone()];
        let unlabelled = [
            LabelledNode::new(None, &plain[0]),
            LabelledNode::new(None, &plain[1]),
            LabelledNode::new(None, &plain[2]),
        ];
        assert_eq!(
            validate_labelled_topology(&unlabelled, &[]).defects,
            validate_topology(&plain)
        );

        // A label is a name and not an identity: two nodes sharing one are
        // still two nodes, and their collision is still a collision.
        let x = node(WhatAmI::Router, "x").listening_on("tcp/10.0.0.5:7447");
        let y = node(WhatAmI::Router, "y").listening_on("tcp/10.0.0.5:7447");
        let same = [
            LabelledNode::new(Some("edge"), &x),
            LabelledNode::new(Some("edge"), &y),
        ];
        assert_eq!(
            validate_labelled_topology(&same, &[]).defects,
            vec![TopologyDefect::ListenEndpointCollision {
                endpoint: String::from("tcp/10.0.0.5:7447"),
                nodes: vec![String::from("edge"), String::from("edge")],
            }]
        );
    }

    /// The name is read off `Debug` for every enum shape, and a finding always
    /// has somewhere to point.
    #[test]
    fn a_finding_names_its_variant_and_always_has_a_site() {
        assert_eq!(variant_name(&ConfigDefect::Unreachable), "Unreachable");
        assert_eq!(variant_name(&ConfigIngestError::NotAnObject), "NotAnObject");
        assert_eq!(
            variant_name(&ConfigIngestError::Syntax(
                json5::parse("{").expect_err("an unterminated object")
            )),
            "Syntax",
            "a tuple variant"
        );
        assert_eq!(
            variant_name(&ConfigDefect::MalformedEndpoint {
                endpoint: String::from("x"),
                list: EndpointList::Listen,
            }),
            "MalformedEndpoint",
            "a struct variant"
        );

        let bare = Finding::describing(&ConfigDefect::Unreachable, None, Vec::new());
        assert_eq!(bare.sites, vec![BlamedSite::at(None, None)]);
        let named = ConfigDefect::ZeroLease.finding(Some("edge"));
        assert_eq!(
            named.sites,
            vec![BlamedSite::at(
                Some("edge"),
                Some("transport/link/tx/lease")
            )]
        );
        assert_eq!(named.message, ConfigDefect::ZeroLease.to_string());
    }
}
