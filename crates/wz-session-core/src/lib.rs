// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz-session-core — runtime-agnostic Session + SessionLinkActions
//! + helper surface.
//!
//! R311di-1 lands the empty crate skeleton; the production surface
//! moves in incrementally from `wz-runtime-tokio::{session,
//! session_glue, observer, declare, pubsub, query, reply, sample,
//! locality, keyexpr_canon}` over subsequent sub-rounds (R311di-2+).
//! See `crates/wz-session-core/Cargo.toml` for the per-crate
//! rationale and the `wz-runtime-tokio` retained boundary (Lua
//! bindings + `SessionLinkActions::new` concrete TokioRuntime
//! constructor stay in the AP crate).

#![no_std]
#![cfg_attr(not(feature = "alloc"), allow(unused_extern_crates))]

#[cfg(feature = "alloc")]
extern crate alloc;

// R311ds — host-run unit tests use std (Arc + Mutex capture cells for
// the `Box<dyn FnMut + Send>` callback fan-out tests). The production
// artifact stays strictly `#![no_std]`: `#[cfg(test)]` code is never
// compiled into it (and the Layer G MCU cross-compile, which excludes
// test code, independently proves the no_std footing). Mirrors the
// established wz-codecs sibling-crate convention
// (`wz-codecs/src/lib.rs` `#[cfg(test)] extern crate std;`).
#[cfg(test)]
extern crate std;

#[cfg(feature = "alloc")]
pub mod keyexpr_canon;

/// R311dn / di-15-pre — keyexpr glob + intersection matchers
/// (zenoh `**` / `*` / `$*` DSL) lifted from
/// `wz-runtime-tokio::pubsub`. The two `pub fn` entry points
/// (`keyexpr_pattern_matches`, `keyexpr_intersect_patterns`) back
/// the future inherent `has_matching` methods on
/// `Remote{Subscriber,Queryable}Registry` (R311do / R311dp) once
/// those registries migrate into wz-session-core.
#[cfg(feature = "alloc")]
pub mod keyexpr_match;

/// R223 — zenoh-style locality filter (no_std + no_alloc; pure enum + helpers).
/// Mirrors zenoh-pico's `z_locality_t` and `_z_locality_allows_{local,remote}`.
/// Available unconditionally because the type carries no allocations.
pub mod locality;

/// Reliability hint shared by LinkDriver outbound + Sample inbound.
/// no_std + no_alloc clean (pure enum + helper); unconditional.
pub mod reliability;

/// Link-layer value types (TxFrame / RxFrame / LinkEvent / LostCause).
/// RxFrame carries Vec<u8> so the module is alloc-gated. The
/// LinkDriver trait + concrete TcpDriver/UdpDriver impls remain in
/// wz-runtime-tokio because they are tokio-specific.
#[cfg(feature = "alloc")]
pub mod link;

/// Inbound-parse error surface + ext-chain depth ceiling. Precursor
/// for the NetworkMessage / DriverLoopOutcome dispatch cluster.
/// no_std clean (core::fmt + core::error::Error); unconditional.
pub mod parse_error;

/// Lease-deadline check outcome (R77 helper surface). no_std +
/// no_alloc clean (pure enum); unconditional.
pub mod lease;

/// Query-side enums (ConsolidationMode + QueryTarget) shared by the
/// Request(Query) builder and the application-layer query API.
/// no_std + no_alloc clean (pure value types with wire_byte helpers).
pub mod query_mode;

/// Wire-encode-time metadata bundles (PushMetadata + QueryMetadata)
/// routed from session API through the codec layer. Uses Sample +
/// query_mode types; alloc-gated due to Vec<u8> attachment slots.
#[cfg(feature = "alloc")]
pub mod metadata;

/// Typed reject for the outbound DECLARE-side gate (R300). Uses
/// OutboundKeyexprError (alloc-bound) so the module is alloc-gated.
#[cfg(feature = "alloc")]
pub mod send_declare_error;

/// R222 / R225 — application-layer `Sample` type for subscriber callbacks.
/// Mirrors zenoh-pico's `_z_sample_t` projection. Carries alloc-bound
/// fields (Vec<u8> payload, String keyexpr) so gated on the `alloc`
/// feature. Re-exported from wz-runtime-tokio for `crate::sample::*`
/// callsite compatibility.
#[cfg(feature = "alloc")]
pub mod sample;

/// R74 / R311di-11 — `NetworkMessage` application-layer envelope batch
/// + `parse_frame_payload` dispatcher. Uses `Box<Request>` etc. so
/// gated on `alloc`. Body variants (Request / Push / Response /
/// ResponseFinal / Declare) are individually `codec-*`-gated per the
/// 3-stage feature-forwarding chain. The `Oam`, `Interest`, and
/// `Unknown` variants stay unconditional. Re-exported from
/// wz-runtime-tokio at `crate::session_glue::NetworkMessage` for
/// callsite compatibility with the query / declare / tests modules.
#[cfg(feature = "alloc")]
pub mod network_message;

/// R76 / R83 / R311di-12 — `DriverLoopOutcome` + `IterationEvent`
/// driver-loop observer surface. Wraps `Vec<NetworkMessage>` +
/// `Vec<ExtEntry>` (FramePayload variant) so alloc-gated.
/// Runtime-agnostic; the wz-runtime-tokio side keeps the concrete
/// `poll_and_dispatch_one` + `drive_session_until_terminal` loop
/// machinery that constructs these values.
#[cfg(feature = "alloc")]
pub mod driver_loop;

/// R310.5a / R311di-13 — `resolve_wireexpr` peer-keyexpr-table
/// lookup shared across the four remote-declaration registries.
/// Pure HashMap + Wireexpr projection; alloc-gated (returns
/// `Option<String>`).
#[cfg(feature = "alloc")]
pub mod wireexpr_resolve;

/// R311di-14+ — application-layer remote-declaration registries
/// (liveliness / subscriber / queryable / liveliness_subscriber).
/// Each sub-module gates on `codec-declare` because the inbound
/// dispatch consumes wz-codecs Declare variants. Alloc-gated for
/// the callback Box + Vec storage.
#[cfg(feature = "alloc")]
pub mod declare;

/// R311du — application-layer local subscriber registry
/// (`SubscriberRegistry` + `SubscriptionId`): the keyexpr callbacks the
/// application registers so an inbound `Push` fires them. The dispatch
/// arms gate on `codec-push` (they consume wz-codecs `Push` records);
/// the struct itself is alloc-gated for the callback `Box` + `Vec`
/// storage. Runtime-agnostic (`FnMut + Send`, no async), so the same
/// registry serves the tokio (AP) and lwIP (MCU) runtimes.
#[cfg(feature = "alloc")]
pub mod pubsub;

/// R311dv — Response-builder cluster (`build_response_{reply,err}_*`
/// + `ResponseReplyBuilder` / `ResponseErrBuilder`): pure value
/// construction of a `Response(Reply|Err)` wire record from a
/// request_id + keyexpr + payload. Lifted from
/// `wz-runtime-tokio::session_glue`; gated on `codec-response` because
/// without the Response codec there is no wire frame to build. The
/// precursor that lets `query.rs` (with its `codec-response`-gated
/// `QueryReply::into_response`) migrate into wz-session-core.
#[cfg(all(feature = "alloc", feature = "codec-response"))]
pub mod response_build;
