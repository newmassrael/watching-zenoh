// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R222 — application-layer `Sample` type for subscriber callbacks.
//!
//! Mirrors zenoh-pico's `z_sample_t` / `_z_sample_t` shape — the
//! decoded view of a Push that subscribers actually want to consume.
//! Before R222, `SubscriberRegistry::register` handed `&Push` to the
//! callback, leaving the caller to re-extract the resolved keyexpr
//! (id + suffix → literal lookup), to discriminate Put vs Del by
//! matching on `push.body`'s tagged-union arms, and to dig payload
//! bytes out of `PushVariant::CodecZenohMsgPut(MsgPut { payload, .. })`.
//! That call-site boilerplate was the same in every subscriber.
//!
//! `Sample` is the projection that does the work once in
//! `dispatch_push`:
//!
//! * [`Sample::keyexpr`] is the resolved literal string (peer
//!   keyexpr table lookup already applied).
//! * [`Sample::kind`] is [`SampleKind::Put`] for `MsgPut` bodies and
//!   [`SampleKind::Del`] for `MsgDel` bodies.
//! * [`Sample::payload`] is the data bytes from the Put body, or
//!   an empty `Vec<u8>` for Del (Del has no payload on the wire).
//!
//! The struct is `#[non_exhaustive]` so a future round can surface
//! additional projections (timestamp, encoding, qos, attachment,
//! source_info, reliability) without an API-breaking churn — callers
//! that read existing fields are unaffected.

/// Sample kind discriminant. Numeric values match zenoh-pico's
/// `z_sample_kind_t` (`vendor/zenoh-pico/include/zenoh-pico/api/constants.h`
/// lines 165-167) so any future wire-side extension that carries
/// the kind byte can serialize via `as u8` without translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SampleKind {
    /// The sample carries data — the publisher called Put. zenoh-pico:
    /// `Z_SAMPLE_KIND_PUT`.
    Put = 0,
    /// The sample marks a key deletion — the publisher called Delete.
    /// zenoh-pico: `Z_SAMPLE_KIND_DELETE`.
    Del = 1,
}

/// Application-layer view of a single inbound Push record.
///
/// Constructed by [`SubscriberRegistry::dispatch_push`](crate::pubsub::SubscriberRegistry::dispatch_push)
/// from the decoded `Push` + the registry's peer keyexpr table.
/// Handed to user-registered callbacks by reference.
///
/// The struct is intentionally `#[non_exhaustive]` — future rounds
/// can add fields (extensions surface like `timestamp`, `encoding`,
/// `attachment`, etc.) without breaking external callers that read
/// existing fields. External-crate construction is therefore only
/// possible via [`Sample::new_put`] / [`Sample::new_del`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Sample {
    /// Resolved keyexpr literal. The peer DECLARE table lookup +
    /// optional suffix concatenation has already been applied by
    /// the dispatcher, so callers see the same string a peer's
    /// `Declare(DeclKexpr)` carries on the wire.
    pub keyexpr: String,
    /// Whether this sample is data ([`SampleKind::Put`]) or a key
    /// deletion ([`SampleKind::Del`]).
    pub kind: SampleKind,
    /// Payload bytes for Put samples; empty `Vec<u8>` for Del
    /// (Del has no payload on the wire). Owned `Vec<u8>` rather
    /// than `&[u8]` to keep the callback's lifetime simple — the
    /// dispatcher allocates one Vec per dispatched Push, which is
    /// the same allocation cost as the prior `&Push`-callback
    /// design (where the callback would clone bytes out of
    /// `MsgPut.payload` itself).
    pub payload: Vec<u8>,
}

impl Sample {
    /// Construct a `Sample` carrying Put-kind data.
    pub fn new_put(keyexpr: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            keyexpr: keyexpr.into(),
            kind: SampleKind::Put,
            payload: payload.into(),
        }
    }

    /// Construct a `Sample` carrying Del-kind notification. Payload
    /// is always empty for Del.
    pub fn new_del(keyexpr: impl Into<String>) -> Self {
        Self {
            keyexpr: keyexpr.into(),
            kind: SampleKind::Del,
            payload: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_kind_numeric_repr_matches_zenoh_pico() {
        // zenoh-pico constants.h:
        //   Z_SAMPLE_KIND_PUT = 0
        //   Z_SAMPLE_KIND_DELETE = 1
        assert_eq!(SampleKind::Put as u8, 0);
        assert_eq!(SampleKind::Del as u8, 1);
    }

    #[test]
    fn new_put_carries_keyexpr_and_payload() {
        let sample = Sample::new_put("home/temp", b"23.5".to_vec());
        assert_eq!(sample.keyexpr, "home/temp");
        assert_eq!(sample.kind, SampleKind::Put);
        assert_eq!(sample.payload, b"23.5");
    }

    #[test]
    fn new_del_carries_empty_payload() {
        let sample = Sample::new_del("home/temp");
        assert_eq!(sample.keyexpr, "home/temp");
        assert_eq!(sample.kind, SampleKind::Del);
        assert!(sample.payload.is_empty());
    }

    #[test]
    fn sample_clone_preserves_kind_and_payload() {
        let original = Sample::new_put("topic/a", b"data".to_vec());
        let clone = original.clone();
        assert_eq!(clone.keyexpr, "topic/a");
        assert_eq!(clone.kind, SampleKind::Put);
        assert_eq!(clone.payload, b"data");
    }
}
