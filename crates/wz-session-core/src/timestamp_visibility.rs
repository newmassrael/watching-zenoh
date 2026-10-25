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
//! decision of the declaration, so each entity states it ([`crate::timestamp_visibility::default_exposed`] is what an entity
//! that states nothing gets), and the rule is applied at one place per engine: the point where a
//! sample or a reply is handed to the entity's callback.
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

/// What an entity that states no choice about timestamps gets, by this build's policy: `true`
/// (it takes part) when the policy is off, which is upstream's behaviour, and `false` when the
/// build makes taking part opt-in.
pub const fn default_exposed() -> bool {
    !crate::policy::SessionPolicy::from_build().entity_timestamp_opt_in
}

/// An entity's choice about the timestamps it is handed, as a value whose `Default` is the
/// build's ([`default_exposed`]), so an options struct that derives `Default` holds the right
/// default without writing one by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExposeTimestamp(pub bool);

impl Default for ExposeTimestamp {
    fn default() -> Self {
        Self(default_exposed())
    }
}

/// A publisher's choice about stamping the messages it is given a time for, as
/// [`ExposeTimestamp`] is an entity's about seeing one: `Default` is the build's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StampTimestamp(pub bool);

impl Default for StampTimestamp {
    fn default() -> Self {
        Self(default_exposed())
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
    #[cfg(feature = "storage-profile")]
    fn source_info(&self) -> Option<&crate::sample::SourceInfo> {
        self.0.source_info()
    }
    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        None
    }
    fn encoding_parts(&self) -> Option<(u32, Option<&str>)> {
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
    fn rid(&self) -> u64 {
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
    fn err_encoding(&self) -> Option<(u32, Option<&str>)> {
        self.0.err_encoding()
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.0.attachment()
    }
    fn put_encoding(&self) -> Option<(u32, Option<&str>)> {
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
    fn the_default_follows_the_build_policy() {
        assert_eq!(
            default_exposed(),
            !crate::policy::SessionPolicy::from_build().entity_timestamp_opt_in
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_hidden_view_shows_no_timestamp_and_everything_else_as_the_inner_view_does() {
        use crate::sample::{Sample, TimestampHint};
        let sample =
            Sample::new_put("home/a", b"payload".as_slice()).with_timestamp(TimestampHint {
                time: 7,
                zid: [1u8, 2].as_slice().into(),
            });
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
}
