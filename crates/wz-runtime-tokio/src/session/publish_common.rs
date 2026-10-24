// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nb (Level B, B5b-2b tail — publish SSOT convergence) — the
//! TRANSPORT-AGNOSTIC publish value surface, split out of the
//! `transport-unicast`-gated [`publisher`](super::publisher) cluster.
//!
//! [`PublishOptions`], [`PublishError`], and the loopback Sample assembly
//! `build_loopback_sample` are the primitives the unified
//! [`Session::publish`](super::Session::publish) consumes on EVERY transport
//! (the remote leg builds a `NetworkMessage::Push` and routes it through the
//! transport-dispatch send seam
//! [`Session::send_network_message`](super::Session::send_network_message);
//! the loopback leg reads only the observer + deferred-fire queue). None of
//! the three names the unicast action bundle, so they are not unicast-coupled
//! — they were over-gated only because the literal `publish` previously lived
//! in the `transport-unicast` impl block. This module gives them their honest
//! (ungated) home so a multicast-only build reaches the same single `publish`
//! SSOT, replacing the prior multicast-specific `publish(k, v)` (R311mo/mp).
//!
//! The genuinely-unicast publish surface stays in
//! [`publisher`](super::publisher): the [`Publisher`](super::Publisher) /
//! [`PublisherAliased`](super::PublisherAliased) handles, the aliased
//! keyexpr-mapping path ([`Session::publish_aliased`](super::Session::publish_aliased)
//! / `publish_aliased_auto`), and [`PublishAliasError`](super::PublishAliasError)
//! — the aliased forms resolve the unicast outbound mapping table, which a
//! handshake-free multicast session has no analogue of.
//!
//! The VALUE types moved one layer further down, to
//! [`wz_session_core::publish_options`], and are re-exported here so every path
//! that named them keeps naming them: every field and every derivation of a
//! publish is a session-core type, and the pico C ABI over the cooperative
//! engine has to describe a publish without this engine
//! (`docs/capi-pico-on-coop-engine.md`). What stays is the loopback leg, which
//! is this engine's.

pub use wz_session_core::publish_options::{PlainPutParams, PublishError, PublishOptions};

// `build_loopback_sample` is the sole `Sample` / `SampleKind` consumer here, so
// the imports follow its `pubsub-allow-loop` gate (the loopback leg).
#[cfg(feature = "pubsub-allow-loop")]
use crate::sample::{Sample, SampleKind};

/// R232 — shared loopback Sample assembly for
/// [`Session::publish`](super::Session::publish) and
/// [`Session::publish_aliased`](super::Session::publish_aliased).
/// Constructs a Put or Del Sample on the
/// supplied keyexpr + payload, threads every metadata field the caller
/// attached to [`PublishOptions`] via `with_*` setters, and leaves the
/// Del-encoding slot empty (zenoh-pico `_z_msg_del_t` carries no
/// encoding so the loopback parity mirrors that wire constraint).
///
/// R311y308 — every metadata field flows through its feature gate, so an
/// un-composed field cannot reach the loopback Sample. The gates are the ones
/// [`PublishOptions::push_metadata`] applies for the wire leg, read through
/// that one bundle, so the two legs cannot gate a field differently.
/// R311y310 — the gates were named `loopback_*` here and in four §5.8
/// inventory reasons; no such symbol has ever existed, and the reasons had
/// copied the name from this comment. A citation that names a symbol is only
/// durable if the symbol was grepped.
///
/// Keeps the metadata-threading rules in one place so a future R232
/// follow-up that adjusts the propagation policy (e.g. validating QoS
/// bits or trimming an over-long attachment) only edits this function.
#[cfg(feature = "pubsub-allow-loop")]
pub(super) fn build_loopback_sample(
    keyexpr: &str,
    payload: &[u8],
    opts: &PublishOptions,
) -> Sample {
    let mut sample = match opts.kind {
        SampleKind::Put => Sample::new_put(keyexpr, payload.to_vec()),
        SampleKind::Del => Sample::new_del(keyexpr),
    };
    sample = sample.with_reliability(opts.reliability);
    let meta = opts.push_metadata();
    if let Some(ts) = meta.timestamp {
        sample = sample.with_timestamp(ts);
    }
    // Encoding is Put-only on the wire; mirror the constraint on
    // loopback so a caller mis-attaching encoding to a Del kind sees
    // the same "encoding=None" the wire path would project.
    if opts.kind == SampleKind::Put {
        if let Some(enc) = meta.encoding {
            sample = sample.with_encoding(enc);
        }
    }
    if let Some(si) = meta.source_info {
        sample = sample.with_source_info(si);
    }
    if let Some(att) = meta.attachment {
        sample = sample.with_attachment(att);
    }
    if let Some(qos) = meta.qos {
        sample = sample.with_qos(qos);
    }
    sample
}
