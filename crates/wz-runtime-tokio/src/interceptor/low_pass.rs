// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The §5.16 low-pass (per-key message-size limit) interceptor — the wz mirror
//! of zenoh `net/routing/interceptor/low_pass.rs`, and the faithful realization
//! of the `access-quota` inventory feature.
//!
//! HONEST mapping note. The `access-quota` catalog entry reads "per-key quota
//! accounting", but zenoh has NO cumulative quota-accounting interceptor — only
//! `low_pass`, a per-key message-SIZE limit (a message whose payload plus
//! attachment exceeds the limit for its keyexpr is dropped). A cumulative
//! byte/message accounting quota would be an INVENTION, which the
//! port-don't-invent rule forbids; so "quota" is realized as zenoh's actual
//! per-key limit. The interceptor is STATELESS (a pure size comparison — no
//! clock, no per-keyexpr state, unlike the downsampler), and is the THIRD
//! interceptor kind on the composable chain beside the ACL enforcer and the
//! downsampler.
//!
//! # What a rule governs (R311y451)
//!
//! A rule carries the four axes zenoh's `LowPassFilterConf` carries and wz can
//! resolve: `key_exprs`, `size_limit`, the [`messages`](LowPassRule::messages)
//! set, and the [`flows`](LowPassRule::flows) set. Before R311y451 wz had only
//! the first two, which made three divergences from zenoh 1.5.0 that a foreign
//! peer could drive:
//!
//! 1. **Only a Push(Put) was sized.** zenoh sizes Query, Reply(Put),
//!    Reply(Del), Push(Put), Push(Del) and Err (`low_pass.rs:259-350`), keyed
//!    by a `LowPassFilterMessage` = { Put, Delete, Query, Reply }
//!    (`:500-516`) that the config selects per rule (`:113`). A Del carrying a
//!    large attachment passed wz.
//! 2. **The attachment bytes were not counted.** zenoh budgets
//!    `payload_size + attachment_size` (`:358-361`), so a small-payload /
//!    large-attachment message that zenoh drops was admitted by wz. This is
//!    what the cross-impl fixture witnesses: a real zenoh-pico
//!    `z_pub_attachment` Put whose payload alone fits the limit.
//! 3. **The FIRST matching rule decided.** zenoh takes the MINIMUM limit across
//!    every matching rule (`:364-391`, `min_by_key` within and across the
//!    per-subject trees), so wz could admit what zenoh drops whenever a looser
//!    rule was listed before a tighter one.
//!
//! # The SUBJECT axes (R311y453) — built, and stricter than upstream
//!
//! `interfaces` / `link_protocols` (zenoh `:102-112`, `:164-184`) were this
//! atom's last recorded residual and are now real
//! ([`link_protocols`](LowPassRule::link_protocols) /
//! [`interfaces`](LowPassRule::interfaces)), resolved once at link open by
//! [`crate::link_interfaces`] and matched through the shared
//! [`LinkSubject`](wz_session_core::link::LinkSubject) predicates the downsampler
//! and the ACL rule use — one policy, three interceptors, so they cannot drift.
//! The three ways this is deliberately better than upstream (no process-lifetime
//! interface cache; "could not determine" kept distinct from "no NIC";
//! one consistent quantifier and error policy across both axes) are set out in
//! the sibling downsampler's module note.
//!
//! # Deliberate omissions, with their reasons
//!
//! - **Rule `id` uniqueness validation** (zenoh `:60-70`). In zenoh's low-pass
//!   the `id` has NO other consumer — direct read of the module shows `lpf.id`
//!   read at `:63` and nowhere else (`:452-454` is `SubjectStore`'s unrelated
//!   counter). Porting it would add a field whose only function is to validate
//!   its own uniqueness, which is the option-atom-with-no-difference trap.
//! - **`compute_keyexpr_cache`** (zenoh `:402-409`) — a per-face memoization of
//!   the four per-kind limits, not a semantic. wz has no per-face keyexpr cache
//!   seam to hang it on; the limit lookup is a linear scan of the rule list.
//! - **Per-flow drop STATS** (zenoh `:417-428`, behind zenoh's `stats` feature).
//!   wz witnesses drops with the flow-agnostic
//!   `LinkstateForwarder::interceptor_dropped` counter.

use wz_codecs::ext_entry::ExtEntryOwned;
use wz_codecs::push::PushOwnedVariant;
use wz_codecs::reply::ReplyOwnedVariant;
use wz_codecs::request::RequestOwnedVariant;
use wz_codecs::response::ResponseOwnedVariant;
use wz_session_core::attachment::{
    decode_attachment_ext, ATTACHMENT_EXT_ID_PUSH, ATTACHMENT_EXT_ID_QUERY,
};
use wz_session_core::keyexpr_match::keyexpr_includes_target;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::query_value_ext::decode_query_value_ext;

use wz_session_core::link::{InterceptorLink, LinkSubject};

use super::{Interceptor, InterceptorContext, InterceptorFlow};

/// Which message KIND a low-pass rule sizes — the wz mirror of zenoh
/// `LowPassFilterMessage` (`zenoh-config/src/lib.rs:157-164`), the per-rule
/// `messages` selector. zenoh keeps one keyexpr tree per (subject, flow, kind),
/// so a rule listing only `Put` leaves a Del / Query / Reply on the same keyexpr
/// unlimited; wz mirrors that by matching the kind against the rule's set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LowPassMessage {
    /// A data Put — a `Push` (or a Request) carrying a `MsgPut` body.
    Put,
    /// A data Del — a `Push` (or a Request) carrying a `MsgDel` body.
    Delete,
    /// A query — a `Request` carrying a `Query` body.
    Query,
    /// A query reply — a `Response` carrying a `Reply` (Put or Del) or an `Err`
    /// body. zenoh maps all three onto the one `Reply` kind (`low_pass.rs:285`,
    /// `:302`, `:341`).
    Reply,
}

impl LowPassMessage {
    /// Every kind — what a "cap this keyexpr" deploy knob means, and what
    /// zenoh's required non-empty `messages` list would have to spell out to
    /// govern the whole message surface.
    pub const ALL: [LowPassMessage; 4] = [
        LowPassMessage::Put,
        LowPassMessage::Delete,
        LowPassMessage::Query,
        LowPassMessage::Reply,
    ];
}

/// A low-pass rule — a message of a governed [`kind`](LowPassRule::messages),
/// on a governed [`flow`](LowPassRule::flows), whose keyexpr one of
/// [`key_exprs`](Self::key_exprs) INCLUDES (`rule ⊇ msg`, the same directional
/// matcher the ACL uses and zenoh's `nodes_including`), is dropped when its
/// payload PLUS attachment exceeds [`max_payload_size`](Self::max_payload_size)
/// bytes. zenoh's `LowPassFilterConf` (`zenoh-config/src/lib.rs:147-155`).
#[derive(Debug, Clone)]
pub struct LowPassRule {
    /// The rule keyexprs (literals or `*`/`**` patterns); a message keyexpr they
    /// INCLUDE is governed by this rule's size limit.
    pub key_exprs: Vec<String>,
    /// The maximum admitted message size in bytes (payload + attachment); a
    /// larger one is dropped. zenoh's `size_limit`.
    pub max_payload_size: usize,
    /// Which message kinds this rule sizes. zenoh's `messages` is a REQUIRED
    /// non-empty list, so there is no "all kinds" default to inherit — a rule
    /// governing everything spells out [`LowPassMessage::ALL`].
    pub messages: Vec<LowPassMessage>,
    /// Which flows this rule applies to. zenoh's `flows` is optional and
    /// defaults to BOTH (`low_pass.rs:83-85`); wz makes the resolved set
    /// explicit on the rule so the per-flow interceptor can filter on it.
    pub flows: Vec<InterceptorFlow>,
    /// R311y453 — the LINK-PROTOCOL subject axis: the rule governs only a face
    /// whose transport speaks one of these. EMPTY does not narrow, which is
    /// zenoh's `link_protocols: None`. FAIL-CLOSED on an indeterminate subject.
    pub link_protocols: Vec<InterceptorLink>,
    /// R311y453 — the NIC-NAME subject axis: the rule governs only a face whose
    /// link sits on one of these interfaces. EMPTY does not narrow (zenoh's
    /// `interfaces: None`). FAIL-CLOSED on an indeterminate subject; a link
    /// RESOLVED to no NIC is a definite non-match.
    pub interfaces: Vec<String>,
}

impl LowPassRule {
    /// R311y453 — whether this rule's LINK subject axes admit `subject`. Both
    /// must pass; an axis left EMPTY does not narrow. Delegates to the same two
    /// [`LinkSubject`] matchers the ACL rule and the sibling interceptor use, so
    /// the three §5.16 filters cannot drift on the policy.
    pub fn governs_link(&self, subject: Option<&LinkSubject>) -> bool {
        LinkSubject::opt_matches_protocols(subject, &self.link_protocols)
            && LinkSubject::opt_matches_interfaces(subject, &self.interfaces)
    }
}

/// The low-pass interceptor for ONE flow — holds the rules that apply to that
/// flow; stateless (the decision is a pure `(size, kind, keyexpr)` comparison).
/// zenoh builds a separate ingress / egress `LowPassInterceptor` over the shared
/// rule state (`low_pass.rs:188-205`), which is why the flow is resolved once at
/// construction rather than per message.
pub struct LowPassInterceptor {
    rules: Vec<LowPassRule>,
}

impl LowPassInterceptor {
    /// The interceptor enforcing the subset of `rules` that applies to `flow`,
    /// or `None` when none does — the wz analogue of zenoh's
    /// `interface_enabled.<flow>.then(|| ...)` (`low_pass.rs:188-205`), which
    /// installs no interceptor on a flow no rule governs.
    pub fn for_flow(rules: &[LowPassRule], flow: InterceptorFlow) -> Option<Self> {
        let rules: Vec<LowPassRule> = rules
            .iter()
            .filter(|r| r.flows.contains(&flow))
            .cloned()
            .collect();
        (!rules.is_empty()).then_some(Self { rules })
    }

    /// The tightest limit governing `keyexpr` for `message`, or `None` when no
    /// rule governs it (unlimited). zenoh takes the MINIMUM over every matching
    /// node, within and across its per-subject trees (`low_pass.rs:364-391`),
    /// and maps "no match" to `usize::MAX`; the `Option` says the same thing
    /// without a magic ceiling.
    fn max_allowed_size(
        &self,
        message: LowPassMessage,
        keyexpr: &str,
        link: Option<&LinkSubject>,
    ) -> Option<usize> {
        let target_chunks: Vec<&str> = keyexpr.split('/').collect();
        self.rules
            .iter()
            .filter(|rule| rule.messages.contains(&message))
            // R311y453 — the LINK subject axes narrow which rules govern this face.
            .filter(|rule| rule.governs_link(link))
            .filter(|rule| {
                rule.key_exprs
                    .iter()
                    .any(|ke| keyexpr_includes_target(ke, &target_chunks))
            })
            .map(|rule| rule.max_payload_size)
            .min()
    }

    /// Whether to admit a `message` of `payload` + `attachment` bytes on
    /// `keyexpr` — the testable core (`intercept` classifies the message and
    /// calls it). Admits when no rule governs the (kind, keyexpr) pair, or the
    /// summed size fits the tightest governing limit. An addition that OVERFLOWS
    /// `usize` is dropped, mirroring zenoh's `Err(usize::MAX)` arm
    /// (`low_pass.rs:358-361`).
    fn admit_message(
        &self,
        message: LowPassMessage,
        payload: usize,
        attachment: usize,
        keyexpr: &str,
        link: Option<&LinkSubject>,
    ) -> bool {
        let Some(limit) = self.max_allowed_size(message, keyexpr, link) else {
            return true; // ungoverned (kind, keyexpr) — never size-limited
        };
        match payload.checked_add(attachment) {
            Some(size) => size <= limit,
            None => false,
        }
    }
}

/// The attachment byte count on an ext chain for `ext_id`, or 0 when the message
/// carries none — zenoh's `ext_attachment.map(|att| att.buffer.len())
/// .unwrap_or(0)`. wz carries the attachment on the generic ext chain rather
/// than in a named field, so the size comes from the
/// [`decode_attachment_ext`](wz_session_core::attachment::decode_attachment_ext)
/// SSOT (Push body id `0x03`, Query id `0x05`) instead of a struct read.
fn attachment_len(extensions: Option<&Vec<ExtEntryOwned>>, ext_id: u8) -> usize {
    extensions
        .and_then(|exts| decode_attachment_ext(exts, ext_id))
        .map_or(0, <[u8]>::len)
}

/// The query-body payload byte count — zenoh's
/// `query.ext_body.map(|body| body.payload.len()).unwrap_or(0)`
/// (`low_pass.rs:265-269`). wz carries the query VALUE as the `0x03` ENC_ZBUF
/// ext whose body is `encoding || payload`, so the PAYLOAD half comes from
/// [`decode_query_value_ext`] — the encoding bytes are not part of zenoh's
/// budget and are not counted here either.
fn query_value_len(extensions: Option<&Vec<ExtEntryOwned>>) -> usize {
    extensions
        .and_then(|exts| decode_query_value_ext(exts))
        .map_or(0, |(_, payload)| payload.len())
}

/// Classify `msg` into `(kind, payload bytes, attachment bytes)`, or `None` for
/// a kind low-pass does not size (which is then admitted) — the wz mirror of
/// zenoh's match over `NetworkBodyMut` (`low_pass.rs:259-350`). `ResponseFinal`,
/// `Interest`, `Declare` and `OAM` return early in zenoh (`:346-349`) and map to
/// `None` here.
///
/// DELIBERATE SUPERSET, and the reason: zenoh's `RequestBody` has only a `Query`
/// arm, so upstream cannot represent a Put / Del routed as a Request and has no
/// arm to size one. wz's codec CAN represent both, and the sibling ACL adapter
/// already governs them as `Put` / `Delete`
/// ([`acl_action`](super::access_control)). Sizing them here keeps the two §5.16
/// adapters symmetric on the same wire form and is strictly conservative (it can
/// only drop more); leaving them unsized would be an asymmetry, not fidelity.
fn message_size(msg: &NetworkMessage) -> Option<(LowPassMessage, usize, usize)> {
    match msg {
        NetworkMessage::Push(p) => match &p.body {
            PushOwnedVariant::CodecZenohMsgPut(put) => Some((
                LowPassMessage::Put,
                put.payload.as_slice().len(),
                attachment_len(put.extensions.as_ref(), ATTACHMENT_EXT_ID_PUSH),
            )),
            PushOwnedVariant::CodecZenohMsgDel(del) => Some((
                LowPassMessage::Delete,
                0,
                attachment_len(del.extensions.as_ref(), ATTACHMENT_EXT_ID_PUSH),
            )),
            _ => None,
        },
        NetworkMessage::Request(r) => match &r.body {
            RequestOwnedVariant::CodecZenohQuery(query) => Some((
                LowPassMessage::Query,
                query_value_len(query.extensions.as_ref()),
                attachment_len(query.extensions.as_ref(), ATTACHMENT_EXT_ID_QUERY),
            )),
            RequestOwnedVariant::CodecZenohMsgPut(put) => Some((
                LowPassMessage::Put,
                put.payload.as_slice().len(),
                attachment_len(put.extensions.as_ref(), ATTACHMENT_EXT_ID_PUSH),
            )),
            RequestOwnedVariant::CodecZenohMsgDel(del) => Some((
                LowPassMessage::Delete,
                0,
                attachment_len(del.extensions.as_ref(), ATTACHMENT_EXT_ID_PUSH),
            )),
            _ => None,
        },
        NetworkMessage::Response(r) => match &r.body {
            ResponseOwnedVariant::CodecZenohReply(reply) => match &reply.body {
                ReplyOwnedVariant::CodecZenohMsgPut(put) => Some((
                    LowPassMessage::Reply,
                    put.payload.as_slice().len(),
                    attachment_len(put.extensions.as_ref(), ATTACHMENT_EXT_ID_PUSH),
                )),
                ReplyOwnedVariant::CodecZenohMsgDel(del) => Some((
                    LowPassMessage::Reply,
                    0,
                    attachment_len(del.extensions.as_ref(), ATTACHMENT_EXT_ID_PUSH),
                )),
                _ => None,
            },
            // zenoh sizes an Err by its payload alone — the wire form carries no
            // attachment ext (`low_pass.rs:337-344` sets `attachment_size = 0`).
            ResponseOwnedVariant::CodecZenohErr(err) => {
                Some((LowPassMessage::Reply, err.payload.as_slice().len(), 0))
            }
            _ => None,
        },
        _ => None,
    }
}

impl Interceptor for LowPassInterceptor {
    fn intercept(&self, ctx: &dyn InterceptorContext, msg: &NetworkMessage) -> bool {
        // A kind low-pass does not size is admitted (zenoh's early-return arms).
        let Some((message, payload, attachment)) = message_size(msg) else {
            return true;
        };
        let Some(keyexpr) = ctx.full_keyexpr(msg) else {
            return true;
        };
        // Measure the ACTUAL buffer bytes (zenoh reads `put.payload.len()`), not
        // the producer-supplied `payload_len` wire field.
        self.admit_message(message, payload, attachment, &keyexpr, ctx.link_subject())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rule governing every kind on both flows — what the deploy knob builds.
    fn rule(key_exprs: &[&str], max_payload_size: usize) -> LowPassRule {
        LowPassRule {
            key_exprs: key_exprs.iter().map(|k| (*k).to_owned()).collect(),
            max_payload_size,
            messages: LowPassMessage::ALL.to_vec(),
            flows: vec![InterceptorFlow::Ingress, InterceptorFlow::Egress],
            link_protocols: Vec::new(),
            interfaces: Vec::new(),
        }
    }

    fn ingress(rules: Vec<LowPassRule>) -> LowPassInterceptor {
        LowPassInterceptor::for_flow(&rules, InterceptorFlow::Ingress)
            .expect("both-flow rules apply to ingress")
    }

    #[test]
    fn drops_a_put_whose_payload_exceeds_the_limit() {
        let lp = ingress(vec![rule(&["demo/**"], 16)]);
        let put = |size| lp.admit_message(LowPassMessage::Put, size, 0, "demo/data", None);
        assert!(put(0), "empty fits");
        assert!(put(16), "exactly the limit fits");
        assert!(!put(17), "one over the limit is dropped");
        assert!(!put(1024), "well over is dropped");
        // An ungoverned keyexpr is never size-limited.
        assert!(
            lp.admit_message(LowPassMessage::Put, 1 << 20, 0, "other/x", None),
            "no rule -> admitted"
        );
    }

    /// R311y451 — the ATTACHMENT is part of the budget (zenoh
    /// `low_pass.rs:358-361` sums payload + attachment). The pre-y451 code
    /// counted the payload alone, so a Put whose payload FITS but whose
    /// payload+attachment does not was admitted; this is the unit twin of the
    /// cross-impl `z_pub_attachment` leg, and it reds if the sum reverts to
    /// `payload` only.
    #[test]
    fn the_attachment_counts_toward_the_budget() {
        let lp = ingress(vec![rule(&["demo/**"], 16)]);
        assert!(
            lp.admit_message(LowPassMessage::Put, 8, 8, "demo/data", None),
            "8 payload + 8 attachment == the 16 limit -> admitted"
        );
        assert!(
            !lp.admit_message(LowPassMessage::Put, 8, 9, "demo/data", None),
            "the PAYLOAD alone fits (8 <= 16) — only the attachment pushes it over"
        );
        assert!(
            !lp.admit_message(LowPassMessage::Delete, 0, 17, "demo/data", None),
            "a Del carries no payload, so its attachment is the whole budget"
        );
    }

    /// An addition that overflows `usize` is a DROP, not an admit (zenoh's
    /// `checked_add` -> `Err(usize::MAX)` arm). A wrapping sum would wrap to a
    /// small number and admit.
    #[test]
    fn an_overflowing_size_is_dropped() {
        let lp = ingress(vec![rule(&["demo/**"], usize::MAX)]);
        assert!(
            !lp.admit_message(LowPassMessage::Put, usize::MAX, 1, "demo/data", None),
            "payload + attachment overflow -> dropped even at the MAX limit"
        );
    }

    /// R311y451 — the TIGHTEST matching rule decides, not the first listed
    /// (zenoh `low_pass.rs:364-391` takes the minimum). The pre-y451 code
    /// returned on the first match, so a looser rule listed first admitted what
    /// zenoh drops.
    #[test]
    fn the_tightest_matching_rule_decides_regardless_of_order() {
        // The LOOSER rule is listed FIRST — the order the old first-match scan
        // would have honoured.
        let loose_first = ingress(vec![rule(&["demo/**"], 64), rule(&["demo/small/**"], 4)]);
        assert!(
            !loose_first.admit_message(LowPassMessage::Put, 8, 0, "demo/small/x", None),
            "the tighter demo/small/** limit of 4 wins over the demo/** 64"
        );
        // Reversing the list must not change the verdict.
        let tight_first = ingress(vec![rule(&["demo/small/**"], 4), rule(&["demo/**"], 64)]);
        assert!(
            !tight_first.admit_message(LowPassMessage::Put, 8, 0, "demo/small/x", None),
            "order-independent: the minimum limit decides either way"
        );
        // A keyexpr only the looser rule governs keeps the looser limit.
        assert!(
            loose_first.admit_message(LowPassMessage::Put, 8, 0, "demo/big", None),
            "demo/big matches only demo/** -> its 64 limit admits 8 bytes"
        );
        assert!(
            !loose_first.admit_message(LowPassMessage::Put, 65, 0, "demo/big", None),
            "but not over that 64 limit"
        );
    }

    /// R311y451 — a rule's `messages` set scopes it to the kinds it lists; a
    /// kind outside the set is unlimited on the same keyexpr (zenoh keeps one
    /// keyexpr tree per kind, `low_pass.rs:491-517`).
    #[test]
    fn a_rule_governs_only_the_kinds_it_lists() {
        let put_only = ingress(vec![LowPassRule {
            key_exprs: vec!["demo/**".to_owned()],
            max_payload_size: 4,
            messages: vec![LowPassMessage::Put],
            flows: vec![InterceptorFlow::Ingress, InterceptorFlow::Egress],
            link_protocols: Vec::new(),
            interfaces: Vec::new(),
        }]);
        assert!(
            !put_only.admit_message(LowPassMessage::Put, 8, 0, "demo/x", None),
            "Put is governed -> 8 over the 4 limit is dropped"
        );
        for ungoverned in [
            LowPassMessage::Delete,
            LowPassMessage::Query,
            LowPassMessage::Reply,
        ] {
            assert!(
                put_only.admit_message(ungoverned, 1 << 20, 0, "demo/x", None),
                "{ungoverned:?} is not in the rule's messages set -> unlimited"
            );
        }
    }

    /// R311y451 — a rule's `flows` set scopes it to one direction, and a flow no
    /// rule governs installs NO interceptor at all (zenoh's
    /// `interface_enabled.<flow>.then(...)`).
    #[test]
    fn a_flow_no_rule_governs_installs_no_interceptor() {
        let ingress_only = vec![LowPassRule {
            key_exprs: vec!["demo/**".to_owned()],
            max_payload_size: 4,
            messages: LowPassMessage::ALL.to_vec(),
            flows: vec![InterceptorFlow::Ingress],
            link_protocols: Vec::new(),
            interfaces: Vec::new(),
        }];
        let on_ingress = LowPassInterceptor::for_flow(&ingress_only, InterceptorFlow::Ingress)
            .expect("the ingress-scoped rule applies to ingress");
        assert!(
            !on_ingress.admit_message(LowPassMessage::Put, 8, 0, "demo/x", None),
            "the ingress rule sizes an ingress Put"
        );
        assert!(
            LowPassInterceptor::for_flow(&ingress_only, InterceptorFlow::Egress).is_none(),
            "no rule governs egress -> no egress interceptor is installed"
        );
    }

    /// The `Reply` kind covers all three reply wire forms zenoh maps onto it —
    /// Reply(Put), Reply(Del) and Err — via the codec classification, not the
    /// size core. Bound to real built messages so a codec arm rename reds here.
    #[test]
    fn message_size_classifies_every_kind_zenoh_sizes() {
        use wz_session_core::push_build::{build_push_del_literal, build_push_literal};
        use wz_session_core::request_build::build_request_query;
        use wz_session_core::response_build::build_response_reply_literal;

        let put = NetworkMessage::Push(Box::new(
            build_push_literal("demo/x", b"1234").expect("build put"),
        ));
        assert_eq!(message_size(&put), Some((LowPassMessage::Put, 4, 0)));

        let del = NetworkMessage::Push(Box::new(
            build_push_del_literal("demo/x").expect("build del"),
        ));
        assert_eq!(message_size(&del), Some((LowPassMessage::Delete, 0, 0)));

        let query = NetworkMessage::Request(Box::new(
            build_request_query(1, 0, Some("demo/q")).expect("build query"),
        ));
        assert_eq!(message_size(&query), Some((LowPassMessage::Query, 0, 0)));

        let reply = NetworkMessage::Response(Box::new(
            build_response_reply_literal(1, "demo/q", b"abc").expect("build reply"),
        ));
        assert_eq!(message_size(&reply), Some((LowPassMessage::Reply, 3, 0)));

        // A kind low-pass does not size admits regardless of its bytes — zenoh
        // returns `Ok(())` for Declare / Interest / OAM / ResponseFinal
        // (`low_pass.rs:346-349`).
        let declare = NetworkMessage::Declare(Box::new(
            wz_session_core::declare_build::build_declare_queryable(0, 0, Some("demo/q"))
                .expect("build decl queryable"),
        ));
        assert_eq!(message_size(&declare), None);
    }

    /// The attachment SIZE is read off the real ext chain, not a struct field —
    /// so the count binds to the `0x03` Push-body attachment ext the wire
    /// actually carries (the same ext a pico `z_pub_attachment` emits, which the
    /// cross-impl leg of this round witnesses end to end).
    ///
    /// The ext is composed with the `encode_attachment_ext` SSOT rather than
    /// with `build_push_literal_with_meta`, because that builder's attachment
    /// arm is gated on `pubsub-attachment` (`push_build.rs:379`) — a feature
    /// low-pass deliberately does NOT require, since it must SIZE a foreign
    /// peer's attachment on a build that cannot EMIT one. Going through the
    /// builder here would have silently produced a chain-less Put and asserted
    /// nothing; it did exactly that before this note was written.
    #[test]
    fn a_real_push_attachment_ext_is_measured_from_the_wire_chain() {
        use wz_session_core::attachment::encode_attachment_ext;
        use wz_session_core::push_build::build_push_literal;

        let attachment = b"0123456789";
        let mut push = build_push_literal("demo/x", b"1234").expect("build put");
        let PushOwnedVariant::CodecZenohMsgPut(put) = &mut push.body else {
            panic!("build_push_literal emits a Put body");
        };
        put.extensions = Some(vec![encode_attachment_ext(
            ATTACHMENT_EXT_ID_PUSH,
            attachment,
        )
        .expect("encode attachment")]);
        put.header |= 0x80; // the Z chain bit, as `build_msg_put_with_meta` sets it

        let msg = NetworkMessage::Push(Box::new(push));
        let (kind, payload, measured) = message_size(&msg).expect("a Put is sized");
        assert_eq!(kind, LowPassMessage::Put);
        assert_eq!(payload, 4, "the payload half");
        assert_eq!(
            measured,
            attachment.len(),
            "the attachment half comes from the 0x03 ext, not a named field"
        );
    }
}
