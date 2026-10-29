// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The §5.16 QoS overwrite interceptor — the wz mirror of zenoh
//! `zenoh/src/net/routing/interceptor/qos_overwrite.rs` @ `pub(crate) fn qos_overwrite_interceptor_factories(`,
//! configured under `qos/network`.
//!
//! It is the one interceptor on the chain that does not admit or drop: it REWRITES. A rule names
//! the messages it governs (a Put, a Delete, a Query), narrows them by who is on the other end of
//! the face, by key, by the QoS they already carry and by the size of their payload, and sets the
//! priority, the congestion control and the express flag of what it selects. The chain consults
//! it through [`Interceptor::overwrite_qos`], which is given the QoS a message has so far and
//! answers the QoS it should leave with, and the forwarder that ran the chain writes the answer
//! into the message ([`apply_qos`]).
//!
//! # What upstream does, and what is the same here
//!
//! * A rule governs a Push(Put) as `put`, a Push(Del) as `delete` and a Request as `query`.
//!   Nothing else is rewritten: a Response is never governed (upstream's `reply` switch is never
//!   set, and its documentation says "replies qos cannot be overwritten"), and a declaration, an
//!   interest, a final and an OAM carry no QoS a rule may select.
//! * `key_exprs` absent governs every key; present, it governs the keys one of them INCLUDES, and
//!   a message whose key cannot be resolved on the face is not governed.
//! * Rules apply in the order they are written, each judged against the QoS the earlier ones left
//!   (upstream installs one interceptor per item, in order, so the second sees the first's
//!   rewrite).
//! * `payload_size` is an inclusive range whose bounds may each be left out. A Put is measured by
//!   its payload, a Query by the payload of its value, a Delete by nothing (zero).
//! * `reliability` in the QoS filter is the reliability of the frame the message rides.
//! * `zids`, `interfaces` and `link_protocols` narrow by the face, as the sibling interceptors'
//!   do ([`LinkSubject`] holds the one policy), and a face whose zid is not known is governed.
//!
//! # Where this deliberately differs
//!
//! **A priority increment is applied in both directions.** Upstream accepts `priority: <n>` with
//! `-7 <= n <= 7` and documents nothing about it; its code branches on `if 1 >= 0` where it
//! plainly means the sign of `n`, so a positive increment adds (saturating at `Background`) and a
//! negative one adds zero and changes nothing. Here a negative increment subtracts, clamped at
//! `Control`, which is the reading the range and the code's own else-branch give. A document that
//! states a negative increment therefore does something here and nothing on a stock node; the
//! alternative would be to port a branch that cannot be reached.
//!
//! # Not covered, and why it is not a gap in this interceptor
//!
//! Upstream installs no QoS overwrite on a multicast transport (`new_transport_multicast` and
//! `new_peer_multicast` answer none), and neither does this: a group's traffic is not rewritten
//! whatever `govern_multicast` says.

use wz_routing_graph::Zid;
use wz_session_core::declare_ext_qos::{
    read_push_qos, read_request_qos, set_push_qos, set_request_qos,
};
use wz_session_core::ext_view::query_value_payload_len;
use wz_session_core::keyexpr_match::keyexpr_includes_target;
use wz_session_core::link::{InterceptorLink, LinkSubject};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::put_payload::payload_len as put_payload_len;
use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::sample::QosLevel;

use wz_codecs::push::PushOwnedVariant;
use wz_codecs::request::RequestOwnedVariant;

use super::{Interceptor, InterceptorContext, InterceptorFlow, InterceptorKind};

/// Which message KIND a rule governs — zenoh `QosOverwriteMessage`
/// (`commons/zenoh-config/src/qos.rs` @ `pub enum QosOverwriteMessage`). Three, and not `DataMessage`'s four: a reply is not
/// a kind a rule can select.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosOverwriteMessage {
    /// A Push carrying a Put.
    Put,
    /// A Push carrying a Delete.
    Delete,
    /// A Request.
    Query,
}

impl QosOverwriteMessage {
    /// Every kind a rule can govern.
    pub const ALL: [QosOverwriteMessage; 3] = [
        QosOverwriteMessage::Put,
        QosOverwriteMessage::Delete,
        QosOverwriteMessage::Query,
    ];

    /// Upstream's wire spelling (`#[serde(rename_all = "snake_case")]`).
    ///
    /// Exhaustive on purpose: a fourth kind stops this compiling instead of quietly acquiring no
    /// spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            QosOverwriteMessage::Put => "put",
            QosOverwriteMessage::Delete => "delete",
            QosOverwriteMessage::Query => "query",
        }
    }

    /// The kind upstream spells `text`, searched through [`Self::ALL`] and [`Self::as_str`] so
    /// there is one table and the inverse cannot disagree with it.
    pub fn from_upstream_str(text: &str) -> Option<QosOverwriteMessage> {
        QosOverwriteMessage::ALL
            .iter()
            .copied()
            .find(|m| m.as_str() == text)
    }
}

/// How a rule sets the priority — zenoh `PriorityUpdateConf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityUpdate {
    /// Replace the priority with this one.
    Set(Priority),
    /// Move the priority by this many bands: positive toward `Background`, negative toward
    /// `Control`, clamped at both ends. See the module note on the direction.
    Shift(i8),
}

/// What a rule sets on the messages it selects — zenoh `QosOverwrites`. A field left `None`
/// leaves that part of the message's QoS as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QosOverwrites {
    /// The new priority, or the shift to apply to the one the message has.
    pub priority: Option<PriorityUpdate>,
    /// The new congestion control.
    pub congestion_control: Option<CongestionControl>,
    /// The new express flag.
    pub express: Option<bool>,
}

impl QosOverwrites {
    /// `qos` with this rule's settings applied.
    pub fn apply(&self, qos: QosLevel) -> QosLevel {
        let mut out = qos;
        if let Some(update) = self.priority {
            let priority = match update {
                PriorityUpdate::Set(priority) => priority,
                PriorityUpdate::Shift(by) => {
                    let band = i16::from(qos.priority().wire_byte()) + i16::from(by);
                    Priority::from_wire(band.clamp(0, 7) as u8)
                }
            };
            out = out.with_priority(priority);
        }
        if let Some(congestion) = self.congestion_control {
            out = out.with_congestion(congestion);
        }
        if let Some(express) = self.express {
            out = out.with_express(express);
        }
        out
    }
}

/// The QoS a message must already carry for a rule to select it — zenoh `QosFilter`. Every
/// field that is set must match; none set matches every message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QosFilter {
    /// The priority the message carries.
    pub priority: Option<Priority>,
    /// The congestion control the message carries.
    pub congestion_control: Option<CongestionControl>,
    /// The express flag the message carries.
    pub express: Option<bool>,
    /// The reliability of the frame the message rides: `true` for reliable.
    pub reliable: Option<bool>,
}

impl QosFilter {
    /// Whether a message carrying `qos` on a frame of the given reliability passes.
    pub fn matches(&self, qos: QosLevel, reliable: bool) -> bool {
        // `map_or(true, ..)`: `is_none_or` postdates the workspace MSRV.
        self.priority.map_or(true, |p| qos.priority() == p)
            && self
                .congestion_control
                .map_or(true, |c| qos.congestion() == c)
            && self.express.map_or(true, |e| qos.is_express() == e)
            && self.reliable.map_or(true, |r| reliable == r)
    }
}

/// An inclusive range of payload sizes whose bounds may each be left out — zenoh `ConfRange`
/// (`"a..b"`, `"a.."`, `"..b"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PayloadRange {
    /// The smallest size selected, or none.
    pub start: Option<u64>,
    /// The largest size selected, or none.
    pub end: Option<u64>,
}

impl PayloadRange {
    /// Whether a payload of `size` bytes is inside the range.
    pub fn contains(&self, size: u64) -> bool {
        self.start.map_or(true, |s| size >= s) && self.end.map_or(true, |e| size <= e)
    }
}

/// One `qos/network` item, as the interceptor holds it — zenoh `QosOverwriteItemConf` after the
/// document's spelling has become types.
#[derive(Debug, Clone)]
pub struct QosOverwriteRule {
    /// The peers the rule governs, by zid. EMPTY does not narrow (upstream's `None`; an empty
    /// list is refused by the reader).
    pub zids: Vec<Zid>,
    /// The NIC names the rule governs. EMPTY does not narrow.
    pub interfaces: Vec<String>,
    /// The link protocols the rule governs. EMPTY does not narrow.
    pub link_protocols: Vec<InterceptorLink>,
    /// The kinds of message the rule governs.
    pub messages: Vec<QosOverwriteMessage>,
    /// The keys the rule governs. EMPTY governs every key (upstream's `None`).
    pub key_exprs: Vec<String>,
    /// What the rule sets.
    pub overwrite: QosOverwrites,
    /// The flows the rule applies on. The document leaves it out to mean both, and the compile
    /// (`super::document`, under `zenoh-config`) writes both here, so this is always explicit.
    pub flows: Vec<InterceptorFlow>,
    /// The QoS a message must carry to be selected.
    pub filter: QosFilter,
    /// The payload sizes selected, or all.
    pub payload_size: Option<PayloadRange>,
}

impl QosOverwriteRule {
    /// Whether the face the message is on is one this rule governs. A zid that is not known
    /// governs, as a link that cannot describe itself does ([`LinkSubject`]); upstream skips the
    /// zid test when it cannot read the zid, and installs the rewrite.
    fn governs_face(&self, ctx: &dyn InterceptorContext) -> bool {
        let zid_ok =
            self.zids.is_empty() || ctx.subject().map_or(true, |zid| self.zids.contains(&zid));
        zid_ok
            && LinkSubject::opt_matches_protocols(ctx.link_subject(), &self.link_protocols)
            && LinkSubject::opt_matches_interfaces(ctx.link_subject(), &self.interfaces)
    }
}

/// The QoS overwrite for ONE flow: the rules that apply to it, in the order they were written.
/// Stateless, as upstream's is.
pub struct QosOverwriteInterceptor {
    rules: Vec<QosOverwriteRule>,
}

impl QosOverwriteInterceptor {
    /// The interceptor for the subset of `rules` that applies to `flow`, or `None` when none does
    /// (upstream installs nothing on a flow no item names).
    pub fn for_flow(rules: &[QosOverwriteRule], flow: InterceptorFlow) -> Option<Self> {
        let rules: Vec<QosOverwriteRule> = rules
            .iter()
            .filter(|r| r.flows.contains(&flow))
            .cloned()
            .collect();
        (!rules.is_empty()).then_some(Self { rules })
    }
}

/// The kind of `msg` as a rule sees it, and the size of the payload a `payload_size` range is
/// tested against; `None` for a message no rule can govern.
fn classify(msg: &NetworkMessage) -> Option<(QosOverwriteMessage, u64)> {
    match msg {
        NetworkMessage::Push(push) => match &push.body {
            PushOwnedVariant::CodecZenohMsgPut(put) => {
                Some((QosOverwriteMessage::Put, put_payload_len(put) as u64))
            }
            PushOwnedVariant::CodecZenohMsgDel(_) => Some((QosOverwriteMessage::Delete, 0)),
            _ => None,
        },
        // Every Request is a query to upstream (its `RequestBody` has the one arm); one that
        // carries a value is measured by it.
        NetworkMessage::Request(request) => {
            let size = match &request.body {
                RequestOwnedVariant::CodecZenohQuery(query) => query
                    .extensions
                    .as_ref()
                    .map_or(0, |exts| query_value_payload_len(exts)),
                _ => 0,
            };
            Some((QosOverwriteMessage::Query, size as u64))
        }
        _ => None,
    }
}

/// The QoS `msg` carries, or `None` for a message that carries none a rule may set.
pub fn message_qos(msg: &NetworkMessage) -> Option<QosLevel> {
    match msg {
        NetworkMessage::Push(push) => Some(read_push_qos(push)),
        NetworkMessage::Request(request) => Some(read_request_qos(request)),
        _ => None,
    }
}

/// Write `qos` into `msg`'s QoS extension. A message that carries none is left as it was.
pub fn apply_qos(msg: &mut NetworkMessage, qos: QosLevel) {
    match msg {
        NetworkMessage::Push(push) => set_push_qos(push, qos),
        NetworkMessage::Request(request) => set_request_qos(request, qos),
        _ => {}
    }
}

/// A copy of `msg` that [`apply_qos`] can rewrite, or `None` for a message it cannot. Only the two
/// kinds a rule governs are cloneable here; a forwarder holding a borrowed message clones it once
/// and only when a rule has changed its QoS.
pub fn clone_for_rewrite(msg: &NetworkMessage) -> Option<NetworkMessage> {
    match msg {
        NetworkMessage::Push(push) => Some(NetworkMessage::Push(push.clone())),
        NetworkMessage::Request(request) => Some(NetworkMessage::Request(request.clone())),
        _ => None,
    }
}

impl Interceptor for QosOverwriteInterceptor {
    fn kind(&self) -> InterceptorKind {
        InterceptorKind::QosOverwrite
    }

    // This interceptor never drops: it admits everything and rewrites through `overwrite_qos`.
    fn intercept(&self, _ctx: &dyn InterceptorContext, _msg: &NetworkMessage) -> bool {
        true
    }

    fn rewrites_qos(&self) -> bool {
        true
    }

    fn overwrite_qos(
        &self,
        ctx: &dyn InterceptorContext,
        msg: &NetworkMessage,
        qos: QosLevel,
        reliable: bool,
    ) -> QosLevel {
        let Some((kind, size)) = classify(msg) else {
            return qos;
        };
        // Resolved at most once, and only for a rule that names keys.
        let mut keyexpr: Option<Option<String>> = None;
        let mut qos = qos;
        for rule in &self.rules {
            if !rule.messages.contains(&kind) || !rule.governs_face(ctx) {
                continue;
            }
            if !rule.key_exprs.is_empty() {
                let key = keyexpr.get_or_insert_with(|| ctx.full_keyexpr(msg));
                let Some(key) = key else {
                    continue;
                };
                let chunks: Vec<&str> = key.split('/').collect();
                if !rule
                    .key_exprs
                    .iter()
                    .any(|ke| keyexpr_includes_target(ke, &chunks))
                {
                    continue;
                }
            }
            if !rule.filter.matches(qos, reliable) {
                continue;
            }
            if rule.payload_size.is_some_and(|range| !range.contains(size)) {
                continue;
            }
            qos = rule.overwrite.apply(qos);
        }
        qos
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::push_build::{build_push_del_literal, build_push_literal};
    use wz_session_core::request_build::build_request_query;

    /// The context of a face: who it is, what link it rides, and the key a message names.
    struct Face {
        zid: Option<Zid>,
        link: Option<LinkSubject>,
        key: Option<String>,
    }

    impl Face {
        fn keyed(key: &str) -> Self {
            Self {
                zid: None,
                link: None,
                key: Some(key.to_owned()),
            }
        }
    }

    impl InterceptorContext for Face {
        fn subject(&self) -> Option<Zid> {
            self.zid
        }
        fn full_keyexpr(&self, _msg: &NetworkMessage) -> Option<String> {
            self.key.clone()
        }
        fn link_subject(&self) -> Option<&LinkSubject> {
            self.link.as_ref()
        }
        fn username(&self) -> Option<String> {
            None
        }
    }

    fn rule(
        keys: &[&str],
        messages: &[QosOverwriteMessage],
        overwrite: QosOverwrites,
    ) -> QosOverwriteRule {
        QosOverwriteRule {
            zids: Vec::new(),
            interfaces: Vec::new(),
            link_protocols: Vec::new(),
            messages: messages.to_vec(),
            key_exprs: keys.iter().map(|k| (*k).to_owned()).collect(),
            overwrite,
            flows: InterceptorFlow::ALL.to_vec(),
            filter: QosFilter::default(),
            payload_size: None,
        }
    }

    fn real_time() -> QosOverwrites {
        QosOverwrites {
            priority: Some(PriorityUpdate::Set(Priority::RealTime)),
            congestion_control: Some(CongestionControl::Block),
            express: Some(true),
        }
    }

    fn put(key: &str, payload: &[u8]) -> NetworkMessage {
        NetworkMessage::Push(Box::new(
            build_push_literal(key, payload).expect("build put"),
        ))
    }

    fn run(
        rules: Vec<QosOverwriteRule>,
        face: &Face,
        msg: &NetworkMessage,
        reliable: bool,
    ) -> QosLevel {
        let chain = QosOverwriteInterceptor::for_flow(&rules, InterceptorFlow::Ingress)
            .expect("the rules apply to ingress");
        chain.overwrite_qos(
            face,
            msg,
            message_qos(msg).expect("a Push carries qos"),
            reliable,
        )
    }

    #[test]
    fn a_rule_sets_priority_congestion_and_express_of_the_keys_it_includes() {
        let rules = vec![rule(&["a/**"], &[QosOverwriteMessage::Put], real_time())];
        let got = run(
            rules.clone(),
            &Face::keyed("a/test"),
            &put("a/test", b"x"),
            true,
        );
        assert_eq!(got.priority(), Priority::RealTime);
        assert_eq!(got.congestion(), CongestionControl::Block);
        assert!(got.is_express());
        let other = run(rules, &Face::keyed("c/test"), &put("c/test", b"x"), true);
        assert_eq!(
            other,
            QosLevel::DEFAULT,
            "a key the rule does not include is untouched"
        );
    }

    #[test]
    fn a_field_the_rule_leaves_out_keeps_what_the_message_had() {
        let only_priority = QosOverwrites {
            priority: Some(PriorityUpdate::Set(Priority::InteractiveHigh)),
            ..QosOverwrites::default()
        };
        let before = QosLevel::from_parts(Priority::DataLow, CongestionControl::Drop, false);
        let after = only_priority.apply(before);
        assert_eq!(after.priority(), Priority::InteractiveHigh);
        assert_eq!(after.congestion(), CongestionControl::Drop);
        assert!(!after.is_express());
    }

    #[test]
    fn a_rule_governs_only_the_kinds_it_lists() {
        let rules = vec![rule(&["**"], &[QosOverwriteMessage::Delete], real_time())];
        let face = Face::keyed("b/test");
        let del = NetworkMessage::Push(Box::new(
            build_push_del_literal("b/test").expect("build del"),
        ));
        assert_eq!(
            run(rules.clone(), &face, &del, true).priority(),
            Priority::RealTime
        );
        assert_eq!(
            run(rules, &face, &put("b/test", b"x"), true),
            QosLevel::DEFAULT
        );
    }

    #[test]
    fn a_request_is_a_query_and_a_rule_for_it_rewrites_the_request() {
        let rules = vec![rule(
            &["a/test"],
            &[QosOverwriteMessage::Query],
            real_time(),
        )];
        let mut query = NetworkMessage::Request(Box::new(
            build_request_query(1, 0, Some("a/test")).expect("build query"),
        ));
        let face = Face::keyed("a/test");
        let qos = run(rules, &face, &query, true);
        assert_eq!(qos.priority(), Priority::RealTime);
        apply_qos(&mut query, qos);
        assert_eq!(
            message_qos(&query),
            Some(qos),
            "the Request carries the rewritten QoS"
        );
    }

    #[test]
    fn a_key_that_does_not_resolve_is_not_governed_when_the_rule_names_keys() {
        let rules = vec![rule(&["a/**"], &[QosOverwriteMessage::Put], real_time())];
        let unresolved = Face {
            zid: None,
            link: None,
            key: None,
        };
        assert_eq!(
            run(rules, &unresolved, &put("a/x", b"x"), true),
            QosLevel::DEFAULT
        );
        let unkeyed = vec![rule(&[], &[QosOverwriteMessage::Put], real_time())];
        assert_eq!(
            run(unkeyed, &unresolved, &put("a/x", b"x"), true).priority(),
            Priority::RealTime,
            "a rule that names no key governs every message"
        );
    }

    #[test]
    fn the_qos_filter_selects_on_what_the_message_carries_and_the_frame_reliability() {
        let mut selective = rule(&["**"], &[QosOverwriteMessage::Put], real_time());
        selective.filter = QosFilter {
            priority: Some(Priority::Data),
            congestion_control: Some(CongestionControl::Drop),
            express: Some(false),
            reliable: Some(true),
        };
        let face = Face::keyed("a/x");
        let msg = put("a/x", b"x");
        assert_eq!(
            run(vec![selective.clone()], &face, &msg, true).priority(),
            Priority::RealTime
        );
        assert_eq!(
            run(vec![selective.clone()], &face, &msg, false),
            QosLevel::DEFAULT,
            "a best-effort frame fails a reliable filter"
        );
        selective.filter.priority = Some(Priority::Background);
        assert_eq!(run(vec![selective], &face, &msg, true), QosLevel::DEFAULT);
    }

    #[test]
    fn the_payload_range_is_inclusive_and_each_bound_may_be_left_out() {
        let at_least_four = PayloadRange {
            start: Some(4),
            end: None,
        };
        assert!(!at_least_four.contains(3));
        assert!(at_least_four.contains(4));
        assert!(at_least_four.contains(u64::MAX));
        let up_to_four = PayloadRange {
            start: None,
            end: Some(4),
        };
        assert!(up_to_four.contains(0));
        assert!(up_to_four.contains(4));
        assert!(!up_to_four.contains(5));
        let mut ranged = rule(&["**"], &[QosOverwriteMessage::Put], real_time());
        ranged.payload_size = Some(PayloadRange {
            start: Some(2),
            end: Some(4),
        });
        let face = Face::keyed("a/x");
        for (payload, governed) in [
            (&b"x"[..], false),
            (b"xx", true),
            (b"xxxx", true),
            (b"xxxxx", false),
        ] {
            let got = run(vec![ranged.clone()], &face, &put("a/x", payload), true);
            assert_eq!(
                got.priority() == Priority::RealTime,
                governed,
                "a payload of {} bytes",
                payload.len()
            );
        }
    }

    #[test]
    fn rules_apply_in_order_and_each_sees_what_the_earlier_ones_left() {
        let first = rule(&["**"], &[QosOverwriteMessage::Put], real_time());
        let mut second = rule(
            &["**"],
            &[QosOverwriteMessage::Put],
            QosOverwrites {
                express: Some(false),
                ..QosOverwrites::default()
            },
        );
        // Selects only what the first rule made RealTime.
        second.filter.priority = Some(Priority::RealTime);
        let got = run(
            vec![first, second],
            &Face::keyed("a/x"),
            &put("a/x", b"x"),
            true,
        );
        assert_eq!(got.priority(), Priority::RealTime);
        assert!(
            !got.is_express(),
            "the second rule saw the first one's priority"
        );
    }

    #[test]
    fn a_priority_shift_moves_in_both_directions_and_clamps() {
        let at = |priority| QosLevel::from_parts(priority, CongestionControl::Drop, false);
        let shift = |by| QosOverwrites {
            priority: Some(PriorityUpdate::Shift(by)),
            ..QosOverwrites::default()
        };
        assert_eq!(
            shift(1).apply(at(Priority::Data)).priority(),
            Priority::DataLow
        );
        assert_eq!(
            shift(-2).apply(at(Priority::Data)).priority(),
            Priority::InteractiveLow
        );
        assert_eq!(
            shift(7).apply(at(Priority::DataLow)).priority(),
            Priority::Background
        );
        assert_eq!(
            shift(-7).apply(at(Priority::RealTime)).priority(),
            Priority::Control
        );
    }

    #[test]
    fn the_face_axes_narrow_the_rule() {
        let zid = Zid::from_slice(&[1, 2, 3]);
        let other = Zid::from_slice(&[9]);
        let mut by_zid = rule(&["**"], &[QosOverwriteMessage::Put], real_time());
        by_zid.zids = vec![zid];
        let face = |zid: Option<Zid>| Face {
            zid,
            link: None,
            key: Some("a/x".to_owned()),
        };
        let msg = put("a/x", b"x");
        assert_eq!(
            run(vec![by_zid.clone()], &face(Some(zid)), &msg, true).priority(),
            Priority::RealTime
        );
        assert_eq!(
            run(vec![by_zid.clone()], &face(Some(other)), &msg, true),
            QosLevel::DEFAULT
        );
        assert_eq!(
            run(vec![by_zid], &face(None), &msg, true).priority(),
            Priority::RealTime,
            "a face whose zid is not known is governed"
        );
        let mut by_nic = rule(&["**"], &[QosOverwriteMessage::Put], real_time());
        by_nic.interfaces = vec!["eth0".to_owned()];
        let on = |nic: &str| Face {
            zid: None,
            link: Some(LinkSubject {
                interfaces: Some(vec![nic.to_owned()]),
                ..LinkSubject::default()
            }),
            key: Some("a/x".to_owned()),
        };
        assert_eq!(
            run(vec![by_nic.clone()], &on("eth0"), &msg, true).priority(),
            Priority::RealTime
        );
        assert_eq!(
            run(vec![by_nic], &on("wlan0"), &msg, true),
            QosLevel::DEFAULT
        );
    }

    #[test]
    fn a_flow_no_rule_names_installs_nothing() {
        let mut egress_only = rule(&["**"], &[QosOverwriteMessage::Put], real_time());
        egress_only.flows = vec![InterceptorFlow::Egress];
        let rules = vec![egress_only];
        assert!(QosOverwriteInterceptor::for_flow(&rules, InterceptorFlow::Ingress).is_none());
        assert!(QosOverwriteInterceptor::for_flow(&rules, InterceptorFlow::Egress).is_some());
    }

    #[test]
    fn nothing_but_a_push_or_a_request_carries_a_qos_a_rule_may_set() {
        let declare = NetworkMessage::Declare(Box::new(
            wz_session_core::declare_build::build_declare_queryable(0, 0, Some("a/q"))
                .expect("build declare"),
        ));
        assert!(message_qos(&declare).is_none());
        assert!(clone_for_rewrite(&declare).is_none());
        assert!(clone_for_rewrite(&put("a/x", b"x")).is_some());
    }

    #[test]
    fn it_admits_everything() {
        let rules = vec![rule(&["**"], &[QosOverwriteMessage::Put], real_time())];
        let chain = QosOverwriteInterceptor::for_flow(&rules, InterceptorFlow::Ingress).unwrap();
        assert!(chain.intercept(&Face::keyed("a/x"), &put("a/x", b"x")));
    }
}
