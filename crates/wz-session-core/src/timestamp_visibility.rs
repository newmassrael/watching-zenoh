// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Who sees a sample's timestamp: the part of the `entity-timestamp-opt-in` policy that every
//! engine shares.
//!
//! # The decision
//!
//! A timestamp rides on a sample whether or not the entity that receives it cares. Upstream hands
//! it to every subscriber and every querier. An image that cares about the work a callback does
//! may want the opposite: the entity sees a timestamp only if it was declared to. That is a
//! decision of the declaration, so each entity states it, or takes what the snapshot of its
//! session says ([`crate::timestamp_visibility::exposed_by`]) when it states nothing, and the
//! rule is applied at one place per engine: the point where a sample or a reply is handed to the
//! entity's callback.
//!
//! # What hiding means
//!
//! [`crate::timestamp_visibility::HiddenTimestamp`] is a [`crate::sink::SampleView`] over another one that answers the same to every
//! question but the timestamp's, which it answers as a sample with none. It is a view and not a
//! copy: nothing is allocated, and the payload and every other field are the inner view's.
//!
//! # A time given to a publisher
//!
//! The other half of the policy is on the sending side: a caller gives a publisher one time
//! value and the publisher supplies its node's identity, so a caller cannot sign a sample as
//! another node. [`crate::timestamp_visibility::ntp64_from_unix_ms`] is the conversion for a caller whose clock counts
//! milliseconds.

use crate::sink::SampleView;

/// What an entity that states no choice about timestamps gets, by the `entity-timestamp-opt-in`
/// policy of `policy`, the snapshot of the session it is declared on: `true` (it takes part)
/// when the policy is off, which is upstream's behaviour, and `false` when taking part is opt-in.
pub const fn exposed_by(policy: &crate::policy::SessionPolicy) -> bool {
    !policy.entity_timestamp_opt_in()
}

/// What an entity's declaration says about seeing the timestamps it is handed: the choice it
/// made, or that it takes the `entity-timestamp-opt-in` value of the session it is declared on.
///
/// The second is the `Default`, so an options struct that derives `Default` states nothing of its
/// own and reads nothing from the build; the session resolves it from its own snapshot when the
/// entity is declared ([`Self::resolve`]), since the policy is bound per entity at its
/// declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExposeTimestamp {
    /// The declaration states nothing: the entity takes its session's value ([`exposed_by`]).
    #[default]
    OfSession,
    /// The declaration states it: `true` sees the timestamp, `false` sees none.
    Chosen(bool),
}

impl ExposeTimestamp {
    /// What the declaration states, or `None` when it leaves it to the session.
    pub const fn chosen(self) -> Option<bool> {
        match self {
            Self::OfSession => None,
            Self::Chosen(expose) => Some(expose),
        }
    }

    /// Whether the entity sees the timestamp, declared on a session whose snapshot is `policy`.
    pub const fn resolve(self, policy: &crate::policy::SessionPolicy) -> bool {
        match self {
            Self::OfSession => exposed_by(policy),
            Self::Chosen(expose) => expose,
        }
    }
}

/// What a publishing or answering entity's declaration says about stamping the messages it is
/// given a time for, as [`ExposeTimestamp`] says about seeing one: the choice it made, or that it
/// takes its session's value, which is the `Default` and which the session resolves when the
/// entity is declared ([`Self::resolve`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StampTimestamp {
    /// The declaration states nothing: the entity takes its session's value ([`exposed_by`]).
    #[default]
    OfSession,
    /// The declaration states it: `true` stamps, `false` refuses a stamped message.
    Chosen(bool),
}

impl StampTimestamp {
    /// What the declaration states, or `None` when it leaves it to the session.
    pub const fn chosen(self) -> Option<bool> {
        match self {
            Self::OfSession => None,
            Self::Chosen(stamp) => Some(stamp),
        }
    }

    /// Whether the entity stamps, declared on a session whose snapshot is `policy`.
    pub const fn resolve(self, policy: &crate::policy::SessionPolicy) -> bool {
        match self {
            Self::OfSession => exposed_by(policy),
            Self::Chosen(stamp) => stamp,
        }
    }
}

/// The NTP64 time word of a time given in milliseconds since the Unix epoch: seconds in the
/// high half, and the milliseconds' share of a second as a fraction of 2^32 in the low half,
/// which is what [`crate::sample::TimestampHint::time`] and the wire carry. A time that does
/// not fit in 32 bits of seconds wraps, as an NTP64 does.
pub const fn ntp64_from_unix_ms(unix_ms: u64) -> u64 {
    let secs = unix_ms / 1000;
    let frac_ms = unix_ms % 1000;
    // frac_ms < 1000, so frac_ms << 32 fits in 42 bits.
    ((secs & 0xFFFF_FFFF) << 32) | ((frac_ms << 32) / 1000)
}

/// A [`SampleView`] that shows no timestamp and is the inner view in every other way.
pub struct HiddenTimestamp<'a>(pub &'a dyn SampleView);

impl SampleView for HiddenTimestamp<'_> {
    fn keyexpr(&self) -> &str {
        self.0.keyexpr()
    }
    fn payload(&self) -> &[u8] {
        self.0.payload()
    }
    fn kind(&self) -> crate::sample_kind::SampleKind {
        self.0.kind()
    }
    fn reliability(&self) -> crate::reliability::Reliability {
        self.0.reliability()
    }
    #[cfg(feature = "storage-profile")]
    fn qos(&self) -> Option<crate::sample::QosLevel> {
        self.0.qos()
    }
    #[cfg(feature = "storage-profile")]
    fn attachment(&self) -> Option<&[u8]> {
        self.0.attachment()
    }
    #[cfg(feature = "alloc")]
    fn attachment_shared(&self) -> Option<&crate::link::RxBytes> {
        self.0.attachment_shared()
    }
    #[cfg(feature = "alloc")]
    fn timestamp(&self) -> Option<&crate::sample::TimestampHint> {
        None
    }
    #[cfg(feature = "alloc")]
    fn encoding(&self) -> Option<&crate::sample::EncodingHint> {
        self.0.encoding()
    }
    #[cfg(feature = "pubsub-ts-stack")]
    fn ts_stack(&self) -> Option<&crate::ts_stack::TsStack> {
        self.0.ts_stack()
    }
    #[cfg(feature = "pubsub-ts-stack")]
    fn routed(&self) -> bool {
        self.0.routed()
    }
    #[cfg(feature = "storage-profile")]
    fn source_info(&self) -> Option<&crate::sample::SourceInfo> {
        self.0.source_info()
    }
    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        None
    }
    fn encoding_parts(&self) -> Option<(u32, Option<&[u8]>)> {
        self.0.encoding_parts()
    }
    #[cfg(feature = "alloc")]
    fn payload_shared(&self) -> Option<&crate::link::RxBytes> {
        self.0.payload_shared()
    }
    #[cfg(feature = "alloc")]
    fn payload_shared_owned(&self) -> Option<crate::link::RxBytes> {
        self.0.payload_shared_owned()
    }
    fn keyexpr_unchanged(&self) -> bool {
        self.0.keyexpr_unchanged()
    }
    // A plain Put has no timestamp to hide, so the inner view's answer is also this one's; and a
    // sample with a timestamp is not plain, which is the conservative answer for the view that
    // hides it too (the caller then reads the fields one by one and finds none).
    fn is_plain_put(&self) -> bool {
        self.0.is_plain_put()
    }
    #[cfg(feature = "alloc")]
    fn plain_facts(&self) -> Option<crate::sink::PlainFacts> {
        self.0.plain_facts()
    }
}

/// A [`ReplyView`](crate::reply_sink::ReplyView) that shows no timestamp and is the inner view in
/// every other way: [`HiddenTimestamp`]'s counterpart for the reply a querier is handed.
pub struct HiddenReplyTimestamp<'a>(pub &'a dyn crate::reply_sink::ReplyView);

impl crate::reply_sink::ReplyView for HiddenReplyTimestamp<'_> {
    fn rid(&self) -> crate::wire_id::RequestId {
        self.0.rid()
    }
    fn keyexpr(&self) -> &str {
        self.0.keyexpr()
    }
    fn kind(&self) -> crate::reply_sink::ReplyKind {
        self.0.kind()
    }
    fn payload(&self) -> &[u8] {
        self.0.payload()
    }
    fn err_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.0.err_encoding()
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.0.attachment()
    }
    fn put_encoding(&self) -> Option<(u32, Option<&[u8]>)> {
        self.0.put_encoding()
    }
    #[cfg(feature = "storage-profile")]
    fn source_info(&self) -> Option<&crate::sample::SourceInfo> {
        self.0.source_info()
    }
    #[cfg(feature = "storage-profile")]
    fn timestamp_parts(&self) -> Option<crate::reply_stage::TimestampParts<'_>> {
        None
    }
    #[cfg(feature = "alloc")]
    fn timestamp(&self) -> Option<&crate::sample::TimestampHint> {
        None
    }
    #[cfg(feature = "alloc")]
    fn payload_shared(&self) -> Option<&crate::link::RxBytes> {
        self.0.payload_shared()
    }
    #[cfg(feature = "alloc")]
    fn attachment_shared(&self) -> Option<&crate::link::RxBytes> {
        self.0.attachment_shared()
    }
    // What is not the sample's timestamp stays as the inner view has it: the node that answered,
    // the quality of service, and the timestamp stack the Response carried.
    fn responder(&self) -> Option<(&[u8], u32)> {
        self.0.responder()
    }
    #[cfg(feature = "storage-profile")]
    fn qos(&self) -> Option<crate::sample::QosLevel> {
        self.0.qos()
    }
    #[cfg(feature = "pubsub-ts-stack")]
    fn ts_stack(&self) -> Option<&crate::ts_stack::TsStack> {
        self.0.ts_stack()
    }
    #[cfg(feature = "pubsub-ts-stack")]
    fn routed(&self) -> bool {
        self.0.routed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_in_milliseconds_becomes_its_ntp64_word() {
        assert_eq!(ntp64_from_unix_ms(0), 0);
        assert_eq!(ntp64_from_unix_ms(1000), 1 << 32);
        // 500 ms is half a second: half of 2^32.
        assert_eq!(ntp64_from_unix_ms(500), 1 << 31);
        assert_eq!(ntp64_from_unix_ms(2_500), (2 << 32) | (1 << 31));
        // 1 ms is the floor of 2^32 / 1000.
        assert_eq!(ntp64_from_unix_ms(1), (1u64 << 32) / 1000);
    }

    #[test]
    fn the_build_defaults_expose_as_their_policy_says() {
        let defaults = crate::policy::SessionPolicy::defaults();
        assert_eq!(exposed_by(&defaults), !defaults.entity_timestamp_opt_in());
    }

    /// An option that states nothing is the default and reads nothing until a session resolves
    /// it; one that states a choice keeps it whatever the session says.
    #[test]
    fn an_option_that_states_nothing_takes_the_session_value_and_a_choice_stays() {
        let defaults = crate::policy::SessionPolicy::defaults();
        assert_eq!(ExposeTimestamp::default(), ExposeTimestamp::OfSession);
        assert_eq!(StampTimestamp::default(), StampTimestamp::OfSession);
        assert_eq!(ExposeTimestamp::OfSession.chosen(), None);
        assert_eq!(StampTimestamp::OfSession.chosen(), None);
        assert_eq!(
            ExposeTimestamp::OfSession.resolve(&defaults),
            exposed_by(&defaults)
        );
        assert_eq!(
            StampTimestamp::OfSession.resolve(&defaults),
            exposed_by(&defaults)
        );
        for choice in [true, false] {
            assert_eq!(ExposeTimestamp::Chosen(choice).chosen(), Some(choice));
            assert_eq!(StampTimestamp::Chosen(choice).chosen(), Some(choice));
            assert_eq!(ExposeTimestamp::Chosen(choice).resolve(&defaults), choice);
            assert_eq!(StampTimestamp::Chosen(choice).resolve(&defaults), choice);
        }
    }

    /// The snapshot an entity is declared under decides, not the build: opt-in hides the
    /// timestamp from an entity that states nothing, and off shows it. A stated choice is the
    /// entity's under either.
    #[test]
    fn an_entity_is_exposed_by_the_snapshot_it_is_declared_under() {
        use crate::policy::{EntityTimestampOptIn, SessionPolicy};
        use crate::policy_binding::PolicyValue;
        if EntityTimestampOptIn::DOMAIN.is_singleton() {
            return;
        }
        let mut opt_in = SessionPolicy::defaults();
        opt_in
            .select_entity_timestamp_opt_in(EntityTimestampOptIn::On)
            .expect("the domain holds both values");
        let mut upstream = opt_in;
        upstream
            .select_entity_timestamp_opt_in(EntityTimestampOptIn::Off)
            .expect("the domain holds both values");
        assert!(!exposed_by(&opt_in));
        assert!(exposed_by(&upstream));
        assert!(!ExposeTimestamp::OfSession.resolve(&opt_in));
        assert!(ExposeTimestamp::OfSession.resolve(&upstream));
        assert!(!StampTimestamp::OfSession.resolve(&opt_in));
        assert!(StampTimestamp::OfSession.resolve(&upstream));
        assert!(ExposeTimestamp::Chosen(true).resolve(&opt_in));
        assert!(!StampTimestamp::Chosen(false).resolve(&upstream));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_hidden_view_shows_no_timestamp_and_everything_else_as_the_inner_view_does() {
        use crate::sample::{Sample, TimestampHint};
        let sample = Sample::new_put("home/a", b"payload".as_slice())
            .with_timestamp(TimestampHint::new(7, &[1u8, 2]).unwrap());
        assert_eq!(SampleView::timestamp(&sample).map(|t| t.time), Some(7));
        let hidden = HiddenTimestamp(&sample);
        assert!(SampleView::timestamp(&hidden).is_none());
        assert!(hidden.timestamp_parts().is_none());
        assert_eq!(hidden.keyexpr(), "home/a");
        assert_eq!(hidden.payload(), b"payload");
        assert_eq!(hidden.kind(), SampleView::kind(&sample));
        assert!(
            !hidden.is_plain_put(),
            "a stamped sample is not a plain put"
        );
    }

    /// The stack a message carries is not a timestamp of the sample, so hiding the timestamp
    /// leaves it, and the fact that the message was routed, as the inner view has them.
    #[cfg(feature = "pubsub-ts-stack")]
    #[test]
    fn a_hidden_view_shows_the_timestamp_stack_and_the_routing_of_the_inner_view() {
        use crate::{
            sample::Sample,
            ts_stack::{point, TsStack},
        };
        let mut stack = TsStack::new(point::SEND);
        stack.record(point::SEND, alloc::vec![1, 2], false);
        let sample = Sample::new_put("home/a", b"payload".as_slice())
            .with_ts_stack(stack.clone())
            .with_routed(true);
        let hidden = HiddenTimestamp(&sample);
        assert_eq!(hidden.ts_stack(), Some(&stack));
        assert!(hidden.routed());
    }

    /// Hiding the timestamp of a reply hides that and nothing else: the node that answered, the
    /// quality of service and the stack of the Response are the inner view's.
    #[cfg(feature = "pubsub-ts-stack")]
    #[test]
    fn a_hidden_reply_view_shows_what_is_not_the_timestamp_as_the_inner_view_has_it() {
        use crate::{
            reply::{InboundReply, InboundReplyBody, ReplyStamp},
            reply_sink::ReplyView,
            ts_stack::{point, TsStack},
        };
        let mut stack = TsStack::new(point::SEND);
        stack.record(point::SEND, alloc::vec![1, 2], false);
        let reply = InboundReply {
            rid: 1,
            keyexpr_literal: "a/b".into(),
            body: InboundReplyBody::Err {
                encoding: None,
                payload: alloc::vec![b'e'],
            },
            responder: Some((alloc::vec![0xAB], 4)),
            qos: Some(crate::sample::QosLevel::from_raw(0b0001_1010)),
            stamp: ReplyStamp {
                ts_stack: Some(stack.clone()),
                routed: true,
            },
        };
        let hidden = HiddenReplyTimestamp(&reply);
        assert_eq!(hidden.responder(), Some((&[0xAB][..], 4)));
        assert_eq!(
            hidden.qos(),
            Some(crate::sample::QosLevel::from_raw(0b0001_1010))
        );
        assert_eq!(hidden.ts_stack(), Some(&stack));
        assert!(hidden.routed());
        assert!(
            hidden.timestamp().is_none(),
            "the timestamp is what is hidden"
        );
    }
}
