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

/// R311ec — QoS packed-byte value types (`Priority` +
/// `CongestionControl`): the two enum components of the zenoh-pico qos
/// packed byte not already covered by `reliability`. Pure no_std +
/// no_alloc (const wire helpers); unconditional. First DP3 leaf lifted
/// from `wz-runtime-tokio::session_glue` toward the runtime-agnostic
/// Session/actions split.
pub mod qos;

/// R311ed — session `CloseReason` discriminator (byte-valued enum
/// mirroring the session FSM's four close-reason mutators). Pure no_std
/// + no_alloc; unconditional. Second DP3 leaf lifted from
/// `wz-runtime-tokio::session_glue`; the Close codec encode stays in the
/// tokio crate next to the rest of the Close path.
pub mod close_reason;

/// R311ee — per-role ext-chain dispatch discriminator (`ExtChainRole`,
/// a four-variant `Copy` enum for the InitSyn/InitAck/OpenSyn/OpenAck
/// negotiation frames). Pure no_std + no_alloc; unconditional. DP3 leaf
/// lifted from `wz-runtime-tokio::session_glue`; the per-role slot
/// storage + encoder read path stay in the tokio crate (they hold an
/// `R::Mutex`).
pub mod ext_chain_role;

/// R311ef — script-action dispatch trace counters (`ActionTrace`, a bag
/// of `u32` counters + a `CloseReason` field, all `Copy`). Pure no_std +
/// no_alloc; unconditional. DP3 leaf lifted from
/// `wz-runtime-tokio::session_glue`; the live `R::Mutex<ActionTrace>`
/// slot + the `trace_snapshot` accessor stay in the tokio crate.
pub mod action_trace;

/// R311eg — peer-advertised InitSyn capability snapshot (`PeerInitCaps`,
/// three integer fields + a `from_init_syn` decoder). Pure no_std +
/// no_alloc; unconditional. DP3 leaf lifted from
/// `wz-runtime-tokio::session_glue`; the decoder's `transport-batching`
/// gate moves here (the live `R::Mutex<Option<PeerInitCaps>>` slot stays
/// in the tokio crate).
pub mod peer_init_caps;

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

/// R311eh — Request-builder cluster (`build_request_query` + the five
/// `build_request_query_with_*` layered variants + `RequestQueryBuilder`
/// + the two size-bound consts): pure value construction of a
/// `Request(Query)` wire record from a request_id + keyexpr + Query/
/// Request-layer settings. Lifted from `wz-runtime-tokio::session_glue`;
/// the mirror of the `response_build` move. Gated on
/// `all(alloc, codec-request)` — the builders allocate owned codec
/// buffers and there is no Request frame to build without the codec.
#[cfg(all(feature = "alloc", feature = "codec-request"))]
pub mod request_build;

/// R311dx — application-layer queryable registry (`QueryableRegistry`
/// + `QueryReply` / `ReplyBody` / `QueryResponder` / `QueryableId` /
/// `QueryableCallback`): routes inbound `Request(Query)` records to
/// user-registered on_query callbacks, accumulating Reply / Err
/// records into a caller-owned `Vec<QueryReply>`. Lifted from
/// `wz-runtime-tokio::query`. The codec-agnostic accumulator + handle
/// types are always-compiled (alloc-gated); the wire-dispatch entry
/// points (`dispatch_request` / `local_query` / `fire_matching_queryables`
/// / `extract_query_attachment`) gate on `codec-request` (the
/// `Request` / `Query` codec_group), and `QueryReply::into_response` /
/// `response_final_for` gate on `codec-response` / `codec-response-final`.
/// Runtime-agnostic (`FnMut + Send`, no async).
#[cfg(feature = "alloc")]
pub mod query;

/// R311dx — consumer-facing query callback wrappers (`QueryEvent` +
/// `ReplyEmitter`) lifted from `wz-runtime-tokio::query_event`. They
/// decouple the application callback signature from the wz-codecs wire
/// types; both are always-nameable (a `query-queryable`-OFF
/// `PhantomData` arm keeps the structs well-formed) so the type-ungated
/// `Session::declare_queryable{_aliased}` signatures compile in every
/// feature subset. Alloc-gated because `ReplyEmitter` borrows the
/// alloc-bound `crate::query::QueryResponder`.
#[cfg(feature = "alloc")]
pub mod query_event;

/// R311dy — application-layer reply registry (`ReplyRegistry` +
/// `InboundReply` / `InboundReplyBody` / `ReplyHandle` / `ReplyCallback`
/// / `FinalCallback`): the z_get-side mirror of `query`, routing inbound
/// `Response(Reply|Err)` + `ResponseFinal` records to per-rid callbacks.
/// Lifted from `wz-runtime-tokio::reply`. Unlike the queryable registry,
/// `ReplyRegistry` stays always-compiled (alloc-gated): its loopback
/// delivery (`deliver_local_reply` / `deliver_local_final`) + timeout
/// sweep (`sweep_timed_out`) are codec-agnostic, so only the wire
/// dispatch (`dispatch_response` / `resolve_wireexpr`) gates on
/// `codec-response` (and `dispatch_response_final` on
/// `codec-response-final`); the `From<QueryReply>` loopback bridge gates
/// on `query-queryable`. Mirrors the `SubscriberRegistry` shape.
#[cfg(feature = "alloc")]
pub mod reply;

/// R311dz-pre — `ResponseSink` IoC trait: the outbound-reply drain
/// abstraction the application-layer observer's `flush_pending` /
/// `dispatch` depend on, inverting their dependency on the concrete
/// tokio `SessionLinkActions<R, T>` so the observer can migrate here
/// without the tokio actions layer. `SessionLinkActions` impls it in
/// wz-runtime-tokio. Alloc-gated (the `send_response` method takes a
/// `wz_codecs::response::ResponseOwned`); the method set is empty in a
/// build with neither response codec so the trait is always-nameable.
#[cfg(feature = "alloc")]
pub mod response_sink;

/// R311dz — application-layer observer bundle (`ApplicationLayerObserver`):
/// combines the six per-domain registries (subscribers, queryables,
/// remote_subscribers, remote_queryables, liveliness,
/// liveliness_subscribers, replies) plus the queryable side's
/// pending-reply / pending-final staging buffers into one cohesive
/// struct so a production caller drives the whole dispatch graph with a
/// single [`observer::ApplicationLayerObserver::dispatch`] call per
/// `IterationEvent`. Migrated from `wz-runtime-tokio::observer`; the move
/// was unblocked by R311dz-pre's `ResponseSink` IoC trait (the drain's
/// only dependency on the tokio actions layer). Gated on `codec-declare`
/// because its `liveliness_subscribers` field's type lives under the
/// `codec-declare`-gated `declare` module; the `queryables` field
/// additionally gates on `query-queryable`. Runtime-agnostic so the same
/// bundle serves the tokio (AP) and lwIP (MCU) profiles.
#[cfg(all(feature = "alloc", feature = "codec-declare"))]
pub mod observer;
