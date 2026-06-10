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

/// R221 — zenoh keyexpr structural canonicalization mirror.
///
/// R311gb (Track 2 no-alloc gating) — un-gated from `alloc`: the
/// canon core ([`canonize_keyexpr`](keyexpr_canon::canonize_keyexpr) +
/// the per-chunk state machine) now backs its two output buffers onto
/// [`bounded::BoundedString`] / [`bounded::BoundedVec`], so registry
/// pattern canonicalization exists on the MCU no-heap profile. The
/// outbound zenoh-pico-safety gate
/// ([`check_outbound_keyexpr_pico_safe`](keyexpr_canon::check_outbound_keyexpr_pico_safe)
/// + [`OutboundKeyexprError`](keyexpr_canon::OutboundKeyexprError))
/// stays `alloc`-gated: it guards the outbound DECLARE *wire emit*
/// path, which is AP-retention per the Track 2 borrow boundary.
pub mod keyexpr_canon;

/// R311dn / di-15-pre — keyexpr glob + intersection matchers
/// (zenoh `**` / `*` / `$*` DSL) lifted from
/// `wz-runtime-tokio::pubsub`. The two `pub fn` entry points
/// (`keyexpr_pattern_matches`, `keyexpr_intersect_patterns`) back
/// the future inherent `has_matching` methods on
/// `Remote{Subscriber,Queryable}Registry` (R311do / R311dp) once
/// those registries migrate into wz-session-core.
///
/// R311fz — un-gated from `alloc`: the matcher now backs its one
/// indexed buffer onto `bounded::BoundedVec<&str, MAX_KEYEXPR_CHUNKS>`
/// (the `$*`-split paths became allocation-free peekable / head-tail
/// walks), so keyexpr matching exists on the MCU no-heap profile. The
/// alloc-gated callers (`pubsub` / `query` / `declare`) are unaffected.
pub mod keyexpr_match;

/// Capacity-generic backing store (`BoundedVec<T, N>`) for the
/// application-layer registries: `alloc::Vec` on the AP profile,
/// `heapless::Vec<T, N>` on the MCU no-heap profile (§2.3 / §2.4).
/// Unconditional — the type exists in every profile so registry code
/// names one backing-agnostic container regardless of the `alloc`
/// feature. First step of the session-core no-alloc gating: provides
/// the seam the 25 currently alloc-gated modules migrate onto.
pub mod bounded;

/// R311gb (Track 2 no-alloc gating) — deploy-declared capacity
/// constants: the SSOT for the bounded backing sizes (`N`) the
/// registries pin onto [`bounded::BoundedVec`] / [`bounded::BoundedString`].
/// Unconditional (plain `usize` consts). A registry field binds a
/// const directly (`BoundedVec<_, { caps::MAX_X }>`) — no `const N`
/// type parameter, since one machine per sidecar (§2.1) means no
/// per-instance capacity divergence. See the module docs for the
/// const-vs-type-parameter rationale.
pub mod caps;

/// W3 bounded owned-mirror adapters (`bounded_bytes` / `bounded_string`) for
/// the builders that copy caller data into SCE's no-alloc bounded codec
/// owned fields (SCE pin 7a94d084a). Public so the AP runtime
/// (`wz-runtime-tokio` `session_glue`) hand-assembling the same `*Owned`
/// wire mirrors reuses the single SSOT adapter rather than duplicating the
/// bound/error mapping.
pub mod codec_bound;

/// R311gb (Track 2) — shared `RegisterError` taxonomy for the bounded
/// application-layer registries (the SSOT for "a registration was
/// rejected at declared capacity"); replaces the per-registry error
/// enums the R311hd..hg fan-out minted.
pub mod registry_error;

/// R311gb — sample-delivery seam (`SampleView` accessor contract +
/// `SampleSink` DIP trait + the `alloc`-only `BoxedSink` closure
/// adapter). Unconditional — the traits exist in every profile so
/// the subscriber registry dispatches through one backing-agnostic seam
/// (model B: AP stores `BoxedSink` heap closures, MCU stores a
/// consumer-supplied closed `enum` of codegen'd Worker/statechart sinks,
/// §2.4 static-first dynamic-opt-in). The registry generic-over-`C:
/// SampleSink` rewrite landed (R311gb-2b); statechart injection is NOT a
/// `SampleSink` but a port-threading inbound adapter (see [`switchboard`],
/// R311gh).
pub mod sink;

/// R311gh — the switchboard: a zenoh-keyexpr -> SCXML-domain-event inbound
/// adapter (`EventInjector` DIP port over the SCE engine's
/// `raise_external_by_name` ingress + the AP dynamic `SwitchboardRegistry`).
/// The Anti-Corruption-Layer translation point: wz owns zenoh keyexpr
/// demux, then injects a *domain* event into the statechart so the SCXML
/// core stays decoupled from the vendor wire naming. Unlike a
/// [`sink::SampleSink`] the registry *threads* the [`switchboard::EventInjector`]
/// port through `dispatch` rather than storing an engine handle, so the
/// AP dynamic table and the MCU generated static `match` share one ingress
/// shape (R311gh gc-2 structure ratify, ledger Round 311gh; supersedes the
/// gc-1 `StatechartSink`-as-`SampleSink` adapter). The `EventInjector`
/// trait is unconditional + no-`alloc`; `SwitchboardRegistry` is
/// `alloc`-gated (AP dynamic). The engine-bridge `EventInjector` impl
/// (`wz-statechart-bridge`) and the build-time `external_ingress_events`
/// cross-check land in later sub-rounds (gc-2b / gc-3).
pub mod switchboard;

/// R311gb-3 — query-dispatch seam (`QueryView` inbound accessor contract
/// + `ReplyOut` outbound emit contract + `QuerySink` DIP trait + the
/// `alloc`-only `BoxedQuerySink` closure adapter). The request/response
/// sibling of [`sink`]: unconditional so the queryable registry can
/// dispatch a matched inbound query through one backing-agnostic seam
/// (model B: AP stores `BoxedQuerySink` heap closures, MCU stores a
/// consumer-supplied closed `enum`, §2.4 static-first dynamic-opt-in).
/// The queryable model-B seam: the registry is generic-over-`C: QuerySink`
/// (R311gb-3b), the reply accumulator `query::QueryResponder` impls
/// `ReplyOut` directly, and the dispatch builds a `BorrowedQuery` for the
/// inbound `QueryView` (R311gb-3b-cleanup retired the prior
/// `QueryEvent`/`ReplyEmitter` wrapper module).
pub mod query_sink;

/// R311gb-3c — reply-delivery seam (`ReplyKind` discriminant + `ReplyView`
/// accessor contract + `ReplySink` DIP trait with `on_reply` / `on_final`
/// + the `alloc`-only `BoxedReplySink` closure adapter). The response-plane
/// sibling of [`sink`]: unconditional so the reply registry can route a
/// pending z_get's inbound replies through one backing-agnostic seam
/// (model B: AP stores `BoxedReplySink` heap closures, MCU stores a
/// consumer-supplied closed `enum`, §2.4 static-first dynamic-opt-in).
/// First step of the reply model-B migration; the registry
/// generic-over-`C: ReplySink` rewrite + `impl ReplyView for InboundReply`
/// land in the apply sub-round.
pub mod reply_sink;

/// R311gb-3d — declare-event delivery seam (`DeclView` accessor contract
/// + `DeclSink` / `UndeclSink` DIP traits + the `alloc`-only
/// `BoxedDeclSink` / `BoxedUndeclSink` closure adapters). The
/// control-plane sibling of [`sink`]: unconditional so the peer-
/// declaration observer registries (subscriber / queryable /
/// liveliness-token) fan inbound `Declare(DeclX|UndeclX)` records through
/// one backing-agnostic seam (model B: AP stores `BoxedDeclSink` heap
/// closures, MCU stores consumer-supplied closed `enum`s). One shared
/// `DeclView` since the three peer-declaration wire records are field-
/// identical `(id, keyexpr)`; the matching undeclaration is a bare `u64`
/// scalar. First step of the declare model-B migration; the registry
/// generic-over-sink rewrites land in the apply sub-rounds.
pub mod decl_sink;

/// R223 — zenoh-style locality filter (no_std + no_alloc; pure enum + helpers).
/// Mirrors zenoh-pico's `z_locality_t` and `_z_locality_allows_{local,remote}`.
/// Available unconditionally because the type carries no allocations.
pub mod locality;

/// Reliability hint shared by LinkDriver outbound + Sample inbound.
/// no_std + no_alloc clean (pure enum + helper); unconditional.
pub mod reliability;

/// R311gb-2 — `SampleKind` discriminant (Put/Del), hoisted out of the
/// `alloc`-gated `sample` module so the no-alloc `sink::SampleView`
/// accessor contract can name it on every profile. Pure `Copy` enum;
/// unconditional. `sample` re-exports it for path compatibility.
pub mod sample_kind;

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

/// R311ep — scouting script-action dispatch trace counters (`ScoutTrace`,
/// four `u32` counters). Pure no_std + no_alloc; unconditional. The
/// scouting-side sibling of [`action_trace`]; the live
/// `R::Mutex<ScoutTrace>` slot stays in `wz-runtime-tokio::scouting_glue`.
pub mod scout_trace;

/// R311ep — per-deploy active-scouting parameters (`ScoutParams`:
/// version / what / zid). Pure owned value type; alloc-gated (Vec zid).
/// The scouting-side sibling of [`session_init_params`]; drives the
/// active-mode Scout frame emit (docs/scouting-fsm.md §2.4.1).
#[cfg(feature = "alloc")]
pub mod scout_params;

/// Round C — per-deploy multicast-transport JOIN parameters
/// (`MulticastParams`: version / whatami / zid / lease / join cadence).
/// Pure owned value type; alloc-gated (Vec zid), like [`scout_params`]. The
/// inputs the AP multicast drive loop (`wz-runtime-tokio::multicast_glue`)
/// packs into each periodic JOIN beacon (session-fsm §3.1/§3.2).
#[cfg(feature = "alloc")]
pub mod multicast_params;

/// R311eq — static scouting mode: `ScoutingMode` discriminator +
/// `synth_static_locators` (host-side locator synthesis from
/// `deploy.connect[]`, docs/scouting-fsm.md §2.4.3). Pure alloc value
/// transform, NOT gated on `scouting-active` — static mode is the FSM
/// bypass path used when the active FSM is compiled out.
///
/// R311if — gated on `scouting-static` so a deploy that does not use
/// `scouting.mode: static` elides the module entirely (§2.4.3 reason #2
/// codegen-elision). The two scouting modes are independent toggles:
/// `scouting-active` (the multicast FSM in wz-runtime-tokio) and
/// `scouting-static` (this host synthesis).
///
/// R311ih — no longer requires `alloc`: the synth builds onto the bounded
/// seam ([`scout_static::StaticLocators`]) so it composes on the no-alloc
/// MCU profile. The `alloc`-only surface (the `ScoutingMode` deploy-string
/// parser) is gated per-item inside the module.
#[cfg(feature = "scouting-static")]
pub mod scout_static;

/// R311er — mode-agnostic locator parsing (`proto/addr:port` ->
/// `ParsedLocator{Proto, SocketAddr}`, docs/scouting-fsm.md §1.2). The
/// single seam both scouting modes' locator strings (active discovered +
/// static synth) flow through before a link dial. Pure core::net + alloc;
/// distinct from wz-codecs::locator (the wire codec).
#[cfg(feature = "alloc")]
pub mod locator;

/// R311eg — peer-advertised InitSyn capability snapshot (`PeerInitCaps`,
/// three integer fields + a `from_init_syn` decoder). Pure no_std +
/// no_alloc; unconditional. DP3 leaf lifted from
/// `wz-runtime-tokio::session_glue`; the decoder's `transport-batching`
/// gate moves here (the live `R::Mutex<Option<PeerInitCaps>>` slot stays
/// in the tokio crate).
pub mod peer_init_caps;

/// R311ei — anti-amplification cookie signing key (`SigningKey` +
/// `SigningKeyTooShort`) + the HMAC-SHA256 cookie primitive
/// (`generate_cookie_hmac_sha256`). Pure crypto/value construction over
/// the RustCrypto hmac + sha2 stack; alloc-gated (the key is
/// `Zeroizing<Vec<u8>>`). DP3 leaf lifted from
/// `wz-runtime-tokio::session_glue`; the OS-entropy constructor stays
/// AP-only as a free fn in the tokio crate (getrandom has no MCU
/// backend, and the orphan rule forbids a cross-crate inherent method).
#[cfg(feature = "alloc")]
pub mod signing_key;

/// R311ej — per-deploy session handshake parameters (`SessionInitParams`:
/// version / whatami / zid / resolutions / lease / cookie + signing
/// key). Pure owned value type; alloc-gated (Vec zid/cookie + SigningKey).
/// DP3 leaf lifted from `wz-runtime-tokio::session_glue`; unblocked by
/// R311ei moving SigningKey here. No codec coupling — drives the session
/// FSM identically on the tokio (AP) and lwIP (MCU) runtimes.
#[cfg(feature = "alloc")]
pub mod session_init_params;

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

/// W3 — typed reject for the non-DECLARE outbound wire-emit actions
/// (push / request / interest). Alloc-free (only wraps `CodecError`),
/// so ungated — usable from the no-alloc MCU surface too.
pub mod send_wire_error;

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

/// Inbound transport-frame decode SSOT (`parse_inbound` + `InboundFrame`
/// + `decode_ext_chain`) and the FSM-event projection
/// (`inbound_to_fsm_event`). Hoisted from `wz-runtime-tokio::session_glue`
/// so both runtime profiles (tokio AP + lwIP MCU) decode through one
/// source — the MCU `#![no_std]` profile cannot depend on the tokio crate.
/// `InboundFrame` carries owned `Vec` buffers, so alloc-gated like
/// `network_message` / `driver_loop`; the no-alloc borrowed-decode variant
/// is a deferred follow-up. `inbound_to_fsm_event` is additionally gated on
/// `session-unicast` (it names the generated FSM event enum).
#[cfg(feature = "alloc")]
pub mod inbound;

/// Outbound `T_MID_FRAME` envelope encoders (`encode_frame_envelope` +
/// the `encode_frame_with_*` family) hoisted from
/// `wz-runtime-tokio::session_glue` so the session action layer shares
/// one outbound encode SSOT across the tokio (AP) and lwIP (MCU)
/// profiles. Owned `Vec` output, so alloc-gated like `inbound` /
/// `network_message`.
#[cfg(feature = "alloc")]
pub mod frame_encode;

/// Outbound transport-handshake / close frame encoders
/// (`encode_init` / `encode_open` / `encode_close`) hoisted from
/// `wz-runtime-tokio::session_glue` so the session action layer shares
/// one handshake encode SSOT across the tokio (AP) and lwIP (MCU)
/// profiles. Owned `Vec` output, so alloc-gated like `frame_encode`;
/// additionally gated on at least one handshake codec feature so the
/// module is absent (rather than empty) under a data-plane-only subset.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close"
    )
))]
pub mod handshake_encode;

/// Outbound pub/sub `Push` network-message builders (`build_push_*` +
/// the `_with_meta` family) hoisted from
/// `wz-runtime-tokio::session_glue` so both runtime profiles share one
/// Push-builder SSOT. Owned `Vec` output (alloc-gated) and `codec-push`
/// gated — the whole module is dead under a subset that does not compose
/// the pub/sub data plane.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub mod push_build;

/// Outbound DECLARE / UNDECLARE network-message builders
/// (`build_declare_*` / `build_undeclare_*` / `build_declare_final`)
/// hoisted from `wz-runtime-tokio::session_glue` so both runtime profiles
/// share one DECLARE-builder SSOT. Owned `Vec` output (alloc-gated) and
/// `codec-declare` gated. Distinct from the `declare` module (the
/// remote-declaration registries) — this is the outbound encode side.
#[cfg(all(feature = "alloc", feature = "codec-declare"))]
pub mod declare_build;

/// Outbound INTEREST network-message builders
/// (`build_interest_liveliness_subscriber` / `_get` / `build_interest_final`)
/// hoisted from `wz-runtime-tokio::session_glue`. `InterestOwned` output, so
/// alloc-gated; the builders carry no codec feature gate (mirroring the
/// ungated `frame_encode::encode_frame_with_interest`).
#[cfg(feature = "alloc")]
pub mod interest_build;

/// Outbound RESPONSE-FINAL network-message builder
/// (`build_response_final`). Separate from `response_build` because
/// `codec-response-final` is an independent feature from `codec-response`.
#[cfg(all(feature = "alloc", feature = "codec-response-final"))]
pub mod response_final_build;

/// R310.5a / R311di-13 — `resolve_wireexpr` peer-keyexpr-table
/// lookup shared across the four remote-declaration registries.
/// Pure HashMap + Wireexpr projection; alloc-gated (returns
/// `Option<String>`).
#[cfg(feature = "alloc")]
pub mod wireexpr_resolve;

/// R311di-14+ — application-layer remote-declaration registries
/// (liveliness / subscriber / queryable / liveliness_subscriber).
///
/// R311gb (Track 2 no-alloc gating) — un-gated from `alloc`: each
/// registry's control plane (the `BoundedVec` observer lists +
/// `on_*_declared_sink` installers + the no-heap fire entries
/// `dispatch_declared_borrowed` / `dispatch_undeclared`) compiles on the
/// MCU no-heap profile. The wire-dispatch entry points
/// (`dispatch_declare` / `dispatch_messages` consuming owned
/// `DeclareOwnedVariant` / `NetworkMessage`) and the peer-`declared`
/// membership table (`HashMap` + `has_matching`) stay
/// `all(codec-declare, alloc)` / `alloc`-gated per sub-module. The
/// `local_token` declarer-side responder + `liveliness_sample` /
/// `liveliness_subscriber` keep their `alloc` gates pending their own
/// Track 2 sub-round.
pub mod declare;

/// R311du — application-layer local subscriber registry
/// (`SubscriberRegistry` + `SubscriptionId`): the keyexpr callbacks the
/// application registers so an inbound `Push` fires them. The dispatch
/// arms gate on `codec-push` (they consume wz-codecs `Push` records).
/// Runtime-agnostic (`FnMut + Send`, no async), so the same registry
/// serves the tokio (AP) and lwIP (MCU) runtimes.
///
/// R311gb (Track 2 no-alloc gating) — un-gated from `alloc`: the
/// control plane (the `BoundedVec` subscriber table + `BoundedString`
/// patterns + `register` / `unregister` / matching) compiles on the
/// MCU no-heap profile. The wire-dispatch surface (`dispatch_push` /
/// `dispatch` / `local_publish` / `absorb_declare` consuming owned
/// `PushOwned` / `NetworkMessage` / `Sample`, plus the
/// `peer_keyexpr_table` / `own_zid` wire-state fields) stays
/// `alloc`-gated per the Track 2 borrow boundary — the no-heap fire
/// path (borrowed `SampleView` dispatch) lands in a later sub-round.
pub mod pubsub;

/// R311ek — shared `source_info` extension-body encoder
/// (`encode_source_info_ext_body` + the `pub(crate)` VLE primitive it
/// shares with `response_build`'s responder encoder). Alloc-only, no
/// codec-feature gate: the encoder is consumed by both the `codec-push`
/// body-extension path and the `codec-response` responder path, so it
/// must be reachable in a `codec-push`-only subset. Relocated out of the
/// `codec-response`-gated `response_build` module to close the
/// arbitrary-composition gap (north-star mechanism ①).
#[cfg(feature = "alloc")]
pub mod source_info_ext;

/// SSOT for the attachment extension wire shape. Gated on the
/// `attachment-bytes` catalog primitive that the `pubsub-attachment` /
/// `query-attachment` consumer features select; owns the one encode /
/// decode pair the Push / Query × encode / decode sites previously each
/// re-derived. Sibling of `source_info_ext`.
#[cfg(all(feature = "alloc", feature = "attachment-bytes"))]
pub mod attachment;

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
/// + `QueryReply` / `ReplyBody` / `QueryResponder` / `QueryableId`):
/// routes inbound `Request(Query)` records to user-registered on_query
/// sinks (R311gb-3b: the `QuerySink` seam), accumulating Reply / Err
/// records into a caller-owned `Vec<QueryReply>`. Lifted from
/// `wz-runtime-tokio::query`.
///
/// R311gb (Track 2 no-alloc gating) — un-gated from `alloc`: the
/// control plane (the `BoundedVec` queryable table + `BoundedString`
/// patterns + `register_sink` / `unregister` / matching) compiles on
/// the MCU no-heap profile, with the borrowed no-heap fire entry
/// (`dispatch_borrowed` via the `QueryView` / `ReplyOut` seam). The
/// reply-accumulator surface (`QueryReply` / `ReplyBody` /
/// `QueryResponder`, all holding owned `String` / `Vec<u8>`) is
/// `alloc`-gated, and the wire-dispatch entry points (`dispatch_request`
/// / `local_query` / `fire_matching_queryables` / `dispatch_messages` /
/// `extract_query_attachment`) gate on `all(codec-request, alloc)` (the
/// `Request` / `Query` codec_group consumes owned records into the
/// `alloc` accumulator), with `QueryReply::into_response` /
/// `response_final_for` further behind `codec-response` /
/// `codec-response-final`. Runtime-agnostic (`FnMut + Send`, no async).
pub mod query;

/// R311dy — application-layer reply registry (`ReplyRegistry` +
/// `InboundReply` / `InboundReplyBody` / `ReplyHandle`): the z_get-side
/// mirror of `query`, routing inbound `Response(Reply|Err)` +
/// `ResponseFinal` records to per-rid sinks (R311gb-3c: the `ReplySink`
/// seam). Lifted from `wz-runtime-tokio::reply`.
///
/// R311gb (Track 2 no-alloc gating) — un-gated from `alloc`: the control
/// plane (the `BoundedVec` pending table + `register_sink` / `unregister`
/// + rid correlation + the no-heap fire entries `dispatch_borrowed`
/// (on_reply via `ReplyView`) / `deliver_local_final` + the
/// `fire_final_for` / `sweep_timed_out` remove-then-fire) compiles on the
/// MCU no-heap profile. The owned retention form (`InboundReply` /
/// `InboundReplyBody`, holding `String` / `Vec<u8>`) + the `From<QueryReply>`
/// loopback bridge + `deliver_local_reply` are `alloc`-gated, and the wire
/// dispatch (`dispatch_response` / `dispatch_messages`) gates on
/// `all(codec-response, alloc)` (`dispatch_response_final` on
/// `all(codec-response-final, alloc)`). Mirrors the `SubscriberRegistry`
/// shape.
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
/// only dependency on the tokio actions layer). R311ek — gated on
/// `alloc` alone (was `all(alloc, codec-declare)`): the bundle holds the
/// always-compiled `subscribers` (pub/sub) + `replies` registries, so a
/// `codec-push`-only subset needs the observer to route Push samples —
/// gating the whole bundle on `codec-declare` made pub/sub-only
/// composition impossible. Every codec-coupled field
/// (`queryables`/`remote_*`/`liveliness`/`liveliness_subscribers`) is now
/// individually feature-gated, so the struct composes down to just the
/// always-compiled registries when no declare/query codec is selected.
/// Runtime-agnostic so the same bundle serves the tokio (AP) and lwIP
/// (MCU) profiles.
#[cfg(feature = "alloc")]
pub mod observer;

/// SCE-generated reassembly slot state machine. The emit comes from
/// `sources/network/reassembly_slot.scxml` via `build.rs` (codegen'd into
/// `$OUT_DIR/reassembly_slot_sm.rs` only under the `reassembly` feature).
/// Exposes the `ReassemblySlotState` / `ReassemblySlotEvent` enums, the
/// `ReassemblySlotActions` host trait, the `ReassemblySlotPolicy<A>`
/// policy, and the typed `ReassemblySlotInject` seam. Fully
/// script-engine-free (no `IScriptEngine`): every effect is a native
/// `<sce:action>` trait call and every guard is a typed `_event.data`
/// comparison, so the module compiles `#![no_std]`. The build script
/// strips the file-head `#![...]` inner attributes; the lint allows are
/// restored here as outer attributes on the wrapping module.
#[cfg(feature = "reassembly")]
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(unused_labels)]
#[allow(unreachable_patterns)]
#[allow(unreachable_code)]
#[allow(clippy::all)]
pub mod reassembly_slot {
    include!(concat!(env!("OUT_DIR"), "/reassembly_slot_sm.rs"));
}

/// R311im — the reassembly Router (dispatcher) that drives N
/// [`reassembly_slot`] FSM instances: the stateful SN-consecutiveness
/// classification, per-peer quota, staging buffers, and deadline sweep
/// that the engine-free slot FSM cannot own. See the module docs for the
/// division of labour with the slot FSM.
#[cfg(feature = "reassembly")]
pub mod reassembly_dispatch;

/// SCE-generated active scouting state machine (R311ik). The emit comes
/// from `sources/session/scouting.scxml` via `build.rs` (codegen'd into
/// `$OUT_DIR/scouting_sm.rs` only under the `scouting-active` feature).
/// Exposes the `ScoutingState` / `ScoutingEvent` enums, the
/// `ScoutingActions` host trait, and the `ScoutingPolicy<A>` policy.
/// Fully script-engine-free (no `IScriptEngine`) and self-timer-free (no
/// `<send delay>`): every effect is a native `<sce:action>` trait call
/// and the host drive loop (wz-runtime-tokio scouting_glue) owns the
/// scout deadline, so the module compiles `#![no_std]`. The build script
/// strips the file-head `#![...]` inner attributes; the lint allows are
/// restored here as outer attributes on the wrapping module.
#[cfg(feature = "scouting-active")]
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(unused_labels)]
#[allow(unreachable_patterns)]
#[allow(unreachable_code)]
#[allow(clippy::all)]
pub mod scouting {
    include!(concat!(env!("OUT_DIR"), "/scouting_sm.rs"));
}

/// SCE-generated unicast session state machine (R311il). The emit comes
/// from `sources/session/session_fsm_unicast.scxml` via `build.rs`
/// (codegen'd into `$OUT_DIR/session_fsm_unicast_sm.rs` only under the
/// `session-unicast` feature). Exposes the `SessionFsmUnicastState` /
/// `SessionFsmUnicastEvent` enums, the `SessionFsmUnicastActions` host
/// trait, and the `SessionFsmUnicastPolicy<A>` policy. Fully
/// script-engine-free (no `IScriptEngine`) and self-timer-free (no
/// `<send delay>`): every effect is a no-arg native `<sce:action>` trait
/// call and the host drive loop (wz-runtime-tokio session_glue) owns
/// every session deadline + pre-classifies the accept guards, so the
/// module compiles `#![no_std]`. The build script strips the file-head
/// `#![...]` inner attributes; the lint allows are restored here as outer
/// attributes on the wrapping module.
#[cfg(feature = "session-unicast")]
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(unused_labels)]
#[allow(unreachable_patterns)]
#[allow(unreachable_code)]
#[allow(clippy::all)]
pub mod session_fsm_unicast {
    include!(concat!(env!("OUT_DIR"), "/session_fsm_unicast_sm.rs"));
}

/// R311il — host-owned handshake deadline config ([`SessionTimeouts`]) +
/// the runtime-agnostic state -> deadline comparator
/// ([`session_timeouts::handshake_deadline_for`]) for the engine-free
/// unicast session FSM. The engine-free FSM arms no `<send delay>`
/// (NoOpHal); the host drive loop owns the clock and raises each timeout
/// transition when its spec-sourced (§2.5) deadline elapses. Sibling of
/// [`lease`] (the Established lease deadline); gated with
/// `session_fsm_unicast` since the comparator names its state/event enums.
#[cfg(feature = "session-unicast")]
pub mod session_timeouts;

/// chunk-5 — runtime-agnostic `SessionLinkActions` bundle + the
/// `SessionActionsBinding` newtype carrying the engine-free
/// [`session_fsm_unicast::SessionFsmUnicastActions`] trait impl (the 18
/// `<sce:action>` native operations + the accept-side admission guards).
/// Gated on `session-unicast` (the generated FSM trait the binding impls)
/// + `alloc` (the bundle owns `Vec` / `HashMap` / `String` staging slots).
/// The concrete `R = TokioRuntime` constructor (`new_session_actions`) and
/// the `Engine`-bound `new_session_engine` factory stay AP-side in
/// `wz-runtime-tokio::session_glue` (they name tokio / sce-rust-runtime types).
#[cfg(all(feature = "alloc", feature = "session-unicast"))]
pub mod session_actions;

/// A4 (session-reconnect) — re-dial + re-handshake support types: the
/// [`reconnect::CachedDeclaration`] declaration-cache entry (zenoh-pico
/// `_z_session_t._declaration_cache` parity), the
/// [`reconnect::ReplayDeclarationsError`] typed reject, and the
/// [`reconnect::SwappableLink`] transport-replacement seam. Gated like
/// [`session_actions`] (the cache types name `SendDeclareError` /
/// `SendWireError` and the swap seam names `SessionRuntime`'s link sink);
/// the cache STORAGE on the actions bundle additionally gates on the
/// `session-reconnect` feature — these types stay compiled so the
/// signature-stable `replay_declarations` / `declaration_cache_snapshot`
/// surface keeps its types across feature states (R311g1).
#[cfg(all(feature = "alloc", feature = "session-unicast"))]
pub mod reconnect;

/// Stage 3 — runtime-agnostic drive-loop dispatch core. `dispatch_link_event`
/// (the synchronous body of the AP `poll_and_dispatch_one`) + the const-generic
/// `report_outcome_reassembling` (reassembly-pool ingest) so the lwIP MCU sync
/// loop (Stage 4) and the tokio async loop share one dispatch SSOT. Gated like
/// [`session_actions`] (it names the FSM engine + the action bundle).
#[cfg(all(feature = "alloc", feature = "session-unicast"))]
pub mod drive;

/// SCE-generated multicast session-LEVEL state machine (Round A). The emit
/// comes from `sources/session/session_fsm_multicast.scxml` via `build.rs`
/// (codegen'd into `$OUT_DIR/session_fsm_multicast_sm.rs` only under the
/// `session-multicast` feature). Exposes the `SessionFsmMulticastState` /
/// `SessionFsmMulticastEvent` enums, the `SessionFsmMulticastActions` host
/// trait, and the `SessionFsmMulticastPolicy<A>` policy. Engine-free (no
/// `IScriptEngine`) and self-timer-free (no `<send delay>`): the §3.1
/// lifecycle (Idle/LinkOpening/Running/Stopped) with the §3.1 parallel
/// Running concerns elided to a leaf owned by the [`multicast_dispatch`]
/// Router. Handshake-free (§3.3), so a different shape from
/// [`session_fsm_unicast`]. The build script strips the file-head `#![...]`
/// inner attributes; the lint allows are restored here as outer attributes.
#[cfg(feature = "session-multicast")]
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(unused_labels)]
#[allow(unreachable_patterns)]
#[allow(unreachable_code)]
#[allow(clippy::all)]
pub mod session_fsm_multicast {
    include!(concat!(env!("OUT_DIR"), "/session_fsm_multicast_sm.rs"));
}

/// SCE-generated multicast per-peer membership state machine (Round A). The
/// emit comes from `sources/session/multicast_peer.scxml` via `build.rs`
/// (codegen'd into `$OUT_DIR/multicast_peer_sm.rs` only under the
/// `session-multicast` feature). Exposes the `MulticastPeerState` /
/// `MulticastPeerEvent` enums, the `MulticastPeerActions` host trait, and
/// the `MulticastPeerPolicy<A>` policy. Engine-free; the §3.2 membership
/// lifecycle (Free/Discovered/Active/Expired) driven one-instance-per-peer
/// by the [`multicast_dispatch`] Router — the same one-FSM-per-entity shape
/// [`reassembly_slot`] uses for fragment chains. The build script strips
/// the file-head `#![...]` inner attributes; the lint allows are restored
/// here as outer attributes.
#[cfg(feature = "session-multicast")]
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(unused_labels)]
#[allow(unreachable_patterns)]
#[allow(unreachable_code)]
#[allow(clippy::all)]
pub mod multicast_peer {
    include!(concat!(env!("OUT_DIR"), "/multicast_peer_sm.rs"));
}

/// Round A — the multicast Router (dispatcher) that drives the one
/// [`session_fsm_multicast`] session-level Engine plus a fixed bounded pool
/// of [`multicast_peer`] per-peer Engines (the §3.2 `multicast_peer_table`).
/// The handshake-free multicast sibling of [`reassembly_dispatch`]: it owns
/// everything the engine-free FSMs cannot — the per-peer last_seen + lease
/// arithmetic, the Join validation / classification, and the lease-sweep
/// clock — and exposes a no-I/O `ingest_*` / `sweep` surface. The transport
/// link socket + the host drive loop (the §3.1 JoinEmit / RxDispatch I/O)
/// land in later rounds. Gated on `session-multicast` (it names the two
/// generated FSM engines).
#[cfg(feature = "session-multicast")]
pub mod multicast_dispatch;
