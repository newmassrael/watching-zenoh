// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//
// R311y205 (transport-multilink IMPL-2b-iii) — the AP-only `transport-multilink`
// feature ALSO links std: the aggregation link set is a
// `std::sync::Mutex<Vec<R::Shared<LinkState>>>` (session_actions.rs). Unlike the
// runtime `R::Mutex<T>` GAT — whose `where T: Send` naming-bound is unprovable
// for the opaque `R::Shared<_>` element in generic-`R` code — `std::sync::Mutex<T>`
// carries no naming-bound, so the field is well-formed for every `R` while
// still being `Send + Sync` on the only runtime that ever enables this feature
// (the std `TokioRuntime`; `R::Shared = Arc`). The feature is rsa-gated (std) and
// AP-only, so it is NEVER built on a bare-metal target — every MCU / default
// build stays strictly `#![no_std]`, and the Layer G cross-compile (feature-off)
// proves it.
#[cfg(any(test, feature = "transport-multilink"))]
extern crate std;

// R311y211 (reconnect×multilink coherence slice-1) — the y205
// `transport-multilink` × `session-reconnect` `compile_error!` XOR is REMOVED.
// The single real hazard it guarded — `reset_for_reopen` (gated
// `session-reconnect`, session_actions.rs) zeroing the SHARED `SessionCore`
// `rx_sn` / `outbound_frame_sn`, which in a live aggregate would corrupt the
// surviving link's per-channel SN gate — is now a RUNTIME invariant inside
// `reset_for_reopen`: when `transport-multilink` is also compiled the shared-
// core reset is skipped while `live_link_count() > 0` (a survivor must keep
// its SN mid-stream). The coherent whole-collapse is a fresh-core rebuild (the
// accept loop drops the aggregate at `remaining == 0`, so the next dial is a
// fresh primary), and a partial loss survives via `del_link`, not a reset — so
// the two features compose. See `SessionLinkActions::reset_for_reopen`.

// R311lt — re-export the wz-codecs transport-MID constants so runtime crates
// that drive a loop's raw-byte MID classification (the AP `multicast_glue`
// loop, the MCU `wz-session-lwip::multicast_drive` loop) reach them through the
// session SSOT instead of taking a direct `wz-codecs` dependency.
pub use wz_codecs::wire_const;
// The node role type owned by the codec layer, re-exported here because the
// `SessionInitParams` / `MulticastParams` `whatami` fields are now this type —
// callers of those param bundles name the role from this crate's surface.
pub use wz_codecs::whatami::WhatAmI;

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

/// Ungated keyexpr non-wild-prefix SSOT (the `NonWildKeyExpr` newtype +
/// [`strip_nonwild_prefix`](keyexpr_prefix::strip_nonwild_prefix), the wz port
/// of zenoh `keyexpr::strip_nonwild_prefix`). The shared chunk-walk core behind
/// §5.24 storage strip-prefix ([`storage_strip_prefix`]) and §5.21
/// routing-namespace ([`namespace`]); both consumer features select
/// `keyexpr-prefix` so the core compiles exactly where a consumer needs it.
/// The borrowed core (`NonWildKeyExpr` + `strip_nonwild_prefix`) is no-alloc;
/// the owned `OwnedNonWildKeyExpr` namespace value is `alloc`-gated.
#[cfg(feature = "keyexpr-prefix")]
pub mod keyexpr_prefix;

/// §5.21 routing-namespace — the per-participant keyexpr namespace prefix/strip
/// decorator ([`namespace::apply_egress`] + the stateful
/// [`namespace::NamespaceIngress`]), the wz mirror of zenoh's
/// `net/routing/namespace.rs` `Namespace` / `ENamespace` `Primitives` pair.
#[cfg(feature = "routing-namespace")]
pub mod namespace;

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

/// W3 bounded owned-mirror adapters (`owned_bytes` / `owned_string`) for
/// the builders that copy caller data into SCE's no-alloc bounded codec
/// owned fields (SCE pin 7a94d084a). Public so the AP runtime
/// (`wz-runtime-tokio` `session_glue`) hand-assembling the same `*Owned`
/// wire mirrors reuses the single SSOT adapter rather than duplicating the
/// bound/error mapping.
pub mod codec_owned;

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

/// R311qc — the data-plane forwarding kernel (`routing-routes`): the
/// [`routing::RouteTable`] a router uses to forward a Put received on one peer
/// face to every other face that declared a matching subscriber. Sibling to
/// the `routing-router` accept-and-hold foundation; the table is generic over
/// the runtime/clock and wrapped single-task by the tokio forwarder. Gated on
/// `all(alloc, routing-routes)` (AP router); the kernel reuses the
/// [`wireexpr_resolve`] / [`keyexpr_match`] SSOTs the subscriber path uses.
#[cfg(all(feature = "alloc", feature = "routing-routes"))]
pub mod routing;

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

/// R311y442 — the zenoh SELECTOR-PARAMETER dialect (`;` list separator, `=`
/// field separator, the bare `_anyke` reply-keyexpr flag) as ONE definition for
/// every wz crate that reads or writes a selector. It lives here rather than
/// beside a consumer because a per-consumer copy is what let the `@adv` cache and
/// the `@adv` subscriber drift to `&` together while agreeing with each other,
/// and what left the same bug live in the REST bridge one crate away.
pub mod selector_params;

/// R311y833 — the requester-side reply-keyexpr contract
/// ([`reply_acceptance::ReplyKeyExpr`] + the acceptance policy a pending z_get
/// registers with). zenoh states it as a GUARANTEE of `get()` itself and both
/// upstreams enforce it in their reply dispatchers; wz enforced it only inside
/// the C ABI shim, so the native `Session::query` delivered replies keyed
/// outside the query. Lives here, beside [`selector_params`], because the
/// opt-out travels as the bare `_anyke` selector parameter — one value read by
/// the responder and by the requester's own gate.
pub mod reply_acceptance;

/// R223 — zenoh-style locality filter (no_std + no_alloc; pure enum + helpers).
/// Mirrors zenoh-pico's `z_locality_t` and `_z_locality_allows_{local,remote}`.
/// Available unconditionally because the type carries no allocations.
pub mod locality;

/// Reliability hint shared by LinkDriver outbound + Sample inbound.
/// no_std + no_alloc clean (pure enum + helper); unconditional.
pub mod reliability;

/// R311y819 — the §2.5 RNG plugin-tier PORT: the shape a profile's entropy
/// source has, so the per-handshake cookie / challenge nonces are drawn at
/// construction on the MCU profile too and not left as deploy constants.
/// Round 11 put RNG in the plugin tier for implementation multiplicity, so the
/// no_std core declares the seam rather than naming a source. Pure no_std +
/// no_alloc (one trait, one payload-free error); unconditional.
pub mod entropy;

/// A1a — modular sequence-number arithmetic (zenoh-pico
/// `transport/utils.c` mirror): the `seq_num_res` ring masks + the
/// half-window `precedes` ordering every RX SN gate shares. First
/// consumer is the multicast data plane's per-peer Frame admission.
/// Pure no_std + no_alloc; unconditional.
pub mod sn;

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

/// R311y435 — the handshake-negotiated capability SET (`SessionOffer`) plus the
/// EXCLUSIVE `TransportMode` choice. zenoh keeps qos and lowlatency as two
/// independent bools and bails at manager build when both are set
/// (`unicast/manager.rs:264`); wz encodes the same rule as one three-state field
/// so the conflict is unrepresentable rather than merely rejected. Pure no_std +
/// no_alloc value types; unconditional (the per-mode cargo features gate what
/// `SessionLinkActions::apply_offer` can STAGE, not what the caller can NAME).
pub mod transport_mode;

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

/// R311nt — transport-agnostic SERIAL-link framing, handshake, and
/// locator logic (the `Z_FEATURE_LINK_SERIAL` upper protocol). Mirrors
/// zenoh-pico serial_protocol.c + protocol/codec/serial.c, holding NO
/// I/O so it compiles on both the AP (tty) and MCU (UART HAL) profiles.
/// Consumes the R311ns serial framing codecs (serial_envelope / cobs /
/// crc32). Gated on `transport-link-serial` (forwards `codec-serial`).
#[cfg(feature = "transport-link-serial")]
pub mod serial_link;

/// R311y579 (G9) — the raweth (L2) link's FRAMING SSOT: the 16 / 20-byte
/// Ethernet header zenoh-pico's raweth transport puts a batch inside, its
/// source-MAC allow-list, and the `reth/` locator. Pure data, `no_std` +
/// alloc; the AF_PACKET socket that carries it lives in `wz-packet-socket`
/// (Round 1998 moved it out of wz-runtime-tokio, which never drove it and
/// charged every consumer a mandatory `tokio` to reach it).
#[cfg(feature = "transport-link-raweth")]
pub mod raweth_link;

/// R311eg — peer-advertised InitSyn capability snapshot (`PeerInitCaps`,
/// three integer fields + a `from_init_body` decoder). Pure no_std +
/// no_alloc; unconditional AND feature-independent (R311kl removed the
/// R311cb `transport-batching` gate over the batch_size honoring —
/// negotiation is core transport, pico parity). DP3 leaf lifted from
/// `wz-runtime-tokio::session_glue` (the live
/// `R::Mutex<Option<PeerInitCaps>>` slot stays in the tokio crate).
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

/// SSOT for the zenoh `iext` extension-header vocabulary (the spec-frozen
/// encoding-marker bits + the id-field accessor). Unconditional — these are
/// protocol constants shared by every ext codec; `ext_nodeid` (codec-gated)
/// re-exports from here so a gated-out consumer (the session-extauth auth
/// dispatch / codec) reaches them without re-deriving the bits. `pub` like the
/// sibling `wz_codecs::wire_const` wire vocabulary, so the spec constants are
/// not dead-code-flagged in feature configs that use only a subset.
pub mod ext_header;

/// The per-carrier extension NAME table — what an id means in the chain it was
/// read from. UNCONDITIONAL for the reason [`ext_header`] is: it reads only
/// header bytes, so an observer build that implements none of these
/// capabilities still names them.
pub mod ext_name;

/// R311y630 (§14.1) — the MANDATORY-extension admission rule: which decoded
/// extension chains a conforming PARTICIPANT must refuse, as distinct from
/// which ones a decoder can read.
///
/// UNCONDITIONAL for the same reason [`ext_header`] is, and one more: the rule
/// reads only extension HEADER bytes, so it needs neither a codec feature nor
/// the `alloc` storage profile, and every consumer — the participant seam, the
/// passive analyzer, the driving oracle — reaches one copy of it.
pub mod ext_admit;

/// SSOT for the transport-message extension CHAIN codec (the Z-flag-gated
/// `ExtEntry` list). Shared by `handshake_encode` (outbound), `inbound`
/// (inbound), and `auth_dispatch` (the Z_EXT_AUTH inner method chain).
///
/// The union of `codec-*` gates this once carried — grown twice (R311y605
/// JOIN, R311y607 SCOUT and HELLO, each found only by a feature-SUBSET build)
/// — collapsed when `parse_inbound` gained its UNCONDITIONAL arm:
/// transport OAM (`T_MID_OAM`) needs no generated body codec, only this chain
/// decoder and a VLE read, so every `alloc` build now has a consumer and there
/// is no longer a list to grow. `alloc` is the real dependency and always was:
/// the decoder returns an owned `Vec` of entries.
#[cfg(feature = "alloc")]
mod ext_chain;

/// Lease-deadline check outcome (R77 helper surface). no_std +
/// no_alloc clean (pure enum); unconditional.
pub mod lease;

/// R311y605 — the JOIN datagram DECODE, gated on `codec-join` alone.
///
/// Hoisted out of [`multicast_join`] (which needs `session-multicast` for its
/// encode + validate halves) when a second, non-participant consumer arrived:
/// the passive observer's [`inbound::parse_inbound`], which reported every JOIN
/// as `Unknown { mid: 0x07 }`. Re-exported from [`multicast_join`], so that
/// module remains the JOIN wire SSOT for a participant reader.
#[cfg(feature = "codec-join")]
pub mod join_decode;

/// R311y607 — the SCOUTING message namespace, which is NOT the transport one.
///
/// `S_MID_SCOUT` and `T_MID_INIT` are both `0x01`; `S_MID_HELLO` and
/// `T_MID_OPEN` are both `0x02`. Only the link that carried the bytes settles
/// which namespace applies, so a decoder handed the wrong one MISREADS rather
/// than failing — the observer read every multicast SCOUT as a confident
/// `InboundFrame::Init`. This module is the other dispatch, kept unreachable
/// from [`inbound`]'s so neither can silently absorb the other's MIDs.
///
/// `alloc`-gated for the owned bodies + ext chain, like [`inbound`]; the two
/// body codecs are gated individually so a HELLO-only reader carries one.
///
/// R311y608 — named `scouting_message` and not `scouting`, after pico's own
/// `_z_scouting_message_t` / `_z_scouting_message_decode`. `scouting` was
/// already taken by the SCE-generated active-scouting STATE MACHINE below, and
/// the two are different things one word apart: this is the wire decode, that
/// is the FSM that drives a scout. R311y607 took the shorter name and the
/// collision was invisible to every build it ran — the two modules sit behind
/// disjoint features (`codec-scout`/`codec-hello` vs `scouting-active`), so
/// only a build enabling BOTH sees them at once, and hosted Layer C1bf
/// (`wz-runtime-tokio --all-features`) was the first that did.
#[cfg(all(
    feature = "alloc",
    any(feature = "codec-scout", feature = "codec-hello")
))]
pub mod scouting_message;

/// R311y846 — the scouting RESPONDER decision: one datagram in, at most one
/// Hello out. The half of multicast scouting that makes wz DISCOVERABLE, which
/// no wz mode carried — active / passive / static (§1.4) are all initiator
/// paths, so a stock zenoh peer running its default
/// `scouting/multicast/listen: true` had to be told wz's endpoint instead of
/// finding it.
///
/// Needs BOTH codecs, unlike [`scouting_message`], which decodes whichever it
/// has: the responder reads a Scout and writes a Hello, so a build with one
/// half has no responder to offer rather than a partial one.
#[cfg(all(feature = "alloc", feature = "codec-scout", feature = "codec-hello"))]
pub mod scout_responder;

/// R2334 — the INITIATOR's counterpart to [`scout_responder`]: why a datagram
/// that reached a scouting window advanced nothing.
///
/// Gated identically, and for the identical reason — it reads a Scout (to tell
/// our own looped-back question from a stranger's) and is consulted by the loop
/// that is waiting for a Hello, so a build with one codec has no verdict to
/// give rather than half of one.
#[cfg(all(feature = "alloc", feature = "codec-scout", feature = "codec-hello"))]
pub mod scout_initiator;

/// R311ky — deferred callback firing (the F-6 structural fix): the
/// staging queue + per-listener take-call-restore cell that let
/// decl/matching/data callbacks run OUTSIDE the session observer mutex.
/// Pure Session-tier infra — its only consumer is wz-runtime-tokio (the
/// AP runtime), which enables `deferred-fire` unconditionally on its
/// wz-session-core dependency.
///
/// R311me — gated on `deferred-fire` ALONE. `alloc::sync::Arc` needs
/// `target_has_atomic = "ptr"` (absent on ARMv6-M), and `deferred-fire`
/// implies `alloc`, so making it the sole gate keeps the module off
/// every profile that does not run the AP deferral machinery. Before
/// R311me the gate also fired on the decl-sink / data-plane features
/// (`session-matching` / `declare-subscriber` / `declare-queryable` /
/// `liveliness-token` / `liveliness-subscriber` / `query-reply`), a
/// pre-R311lh artifact: those arms were how the AP Session-tier deferred
/// listeners (R311lb/lc/lg) reached the module before R311lh introduced
/// the explicit `deferred-fire` consumer feature. No wz-session-core
/// code instantiates a deferred type under those arms (only doc-links),
/// so post-R311lh they were dead weight — and one of them,
/// `liveliness-token`, dragged `alloc::sync::Arc` into the Arc-free MCU
/// multicast profile (the single-task loop drives registries inline and
/// stages its liveliness / queryable replies through the Rc-backed
/// `MulticastReplyQueue`, never the deferred seam), breaking the
/// thumbv6m M0 liveliness cross-build. Collapsing the gate restores that
/// M0 inline-fire reach with no AP change (wz-runtime-tokio still
/// enables `deferred-fire`).
#[cfg(feature = "deferred-fire")]
pub mod deferred_fire;

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

/// §5.19 — predefined Encoding constants + the MIME id<->str table, the wz mirror
/// of zenoh's high-level Encoding API (the convenience layer the encoding-* atoms
/// name, on top of the active `pubsub-encoding` wire field). FOUNDATIONAL
/// (always-on, no cfg toggle — encoding identity is a data value, not a
/// composable code path). Gated on `alloc` (it builds the `String`-bearing
/// [`sample::EncodingHint`]).
#[cfg(feature = "alloc")]
pub mod encoding;

/// zid <-> zenoh `ZenohId` Display hex — the SSOT recipe for rendering a
/// length-trimmed wire zid as the string zenoh prints (and parsing it back).
/// FOUNDATIONAL (always-on under `alloc`); `storage_replication` re-exports it,
/// and the admin space (§5.23) reads it without the storage gate. Gated on
/// `alloc` (it builds a `String`).
#[cfg(feature = "alloc")]
pub mod zid_hex;

/// R311y50 — the SSOT JSON string-literal escaper shared by the hand-rolled
/// (no `serde_json`) admin / config JSON emitters (`adminspace`, `config`).
/// `alloc`-only; ungated by any admin/routing cfg so every emitter reaches it.
#[cfg(feature = "alloc")]
pub mod json;

/// R311y842 — the READ direction of [`json`]: a hand-rolled JSON5 reader, so
/// the stock zenoh config an operator already holds is an INPUT to wz rather
/// than only ever an output of it. `alloc`-only, same as its emit twin.
#[cfg(feature = "alloc")]
pub mod json5;

/// §5.23 — admin space `local_data` view: the `@/<zid>/<whatami>/**` built-in
/// queryable keyexpr helpers + the `local_data` JSON body, the wz mirror of
/// zenoh `net/runtime/adminspace.rs`. Pure data-view (the queryable wiring lives
/// in wz-runtime-tokio); `alloc`-only / no_std-feasible.
#[cfg(feature = "adminspace-core")]
pub mod adminspace;

/// Shared slice-based VLE decoder (the `SceCursor::read_vle_u64` borrowed-slice
/// twin) — the SSOT for parsing a varint out of an already-buffered ext body.
/// `pub` for the `read_zbuf` / `write_zbuf` "one zenoh ZBuf" framing primitive,
/// consumed across the crate boundary by the AP-only pubkey auth method (the
/// VLE u64 helpers stay `pub(crate)`); the rest is crate-internal.
#[cfg(feature = "alloc")]
pub mod vle;

/// R311y68 — `ext-pubsub-serde-codec` (§5.25): the Zenoh Serialization
/// Format codec (`z_serialize` / `z_deserialize`), the leaf prerequisite
/// for the advanced pub/sub miss-detection heartbeat. Reuses the
/// [`vle`] VLE SSOT for its `VarInt` length prefix. The `= ["alloc"]`
/// feature implies `alloc`, so the gate subsumes the allocator need.
#[cfg(feature = "ext-pubsub-serde-codec")]
pub mod serde_codec;

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

/// R311y784 / R311y787 — the multicast departure observer surface
/// (`MulticastPeerId` / `MulticastPeerLost` / `MulticastPeerLostReason`).
/// Authored inside [`driver_loop`] and moved out of it: the types are
/// allocation-free, but their PRODUCER is `multicast_dispatch`, which
/// compiles on the no-alloc MCU profile where the alloc-gated `driver_loop`
/// does not exist — so the observer surface is UNGATED and `driver_loop`
/// re-exports it for the alloc-side consumers.
///
/// (`multicast_dispatch` is a code span, not an intra-doc link: it is
/// `session-multicast`-gated and absent from the default-feature rustdoc run
/// Layer C1bz measures.)
pub mod multicast_peer_lost;

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

/// Outbound transport-handshake / close / keepalive frame encoders
/// (`encode_init` / `encode_open` / `encode_close` /
/// `encode_keep_alive`) hoisted from
/// `wz-runtime-tokio::session_glue` so the session action layer shares
/// one transport-message encode SSOT across the tokio (AP) and lwIP
/// (MCU) profiles. Owned `Vec` output, so alloc-gated like
/// `frame_encode`; additionally gated on at least one t_msg emitter
/// feature so the module is absent (rather than empty) under a
/// data-plane-only subset (R311kx adds `transport-keepalive` to the
/// union — its `encode_keep_alive` is a const 1-byte header, no codec
/// body).
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-init-body",
        feature = "codec-open-body",
        feature = "codec-close",
        feature = "transport-keepalive"
    )
))]
pub mod handshake_encode;

/// R311y816 — the Open-body `initial_sn` derivation (zenoh `compute_sn`),
/// the ring origin an OpenSyn / OpenAck announces and the TX counter is
/// seeded from. Gated on `codec-open-body` alone: it is the Open body's own
/// field, it needs no allocator, and the `sha3` dependency rides the same
/// feature so a profile without the Open body (the multicast-only MCU
/// artifact the Layer Q footprint gate measures) links no Keccak.
#[cfg(feature = "codec-open-body")]
pub mod initial_sn;

/// Outbound pub/sub `Push` network-message builders (`build_push_*` +
/// the `_with_meta` family) hoisted from
/// `wz-runtime-tokio::session_glue` so both runtime profiles share one
/// Push-builder SSOT. Owned `Vec` output (alloc-gated) and `codec-push`
/// gated — the whole module is dead under a subset that does not compose
/// the pub/sub data plane.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub mod push_build;

/// Shared codec-agnostic `Wireexpr` constructors (`literal_wireexpr`) — the
/// SSOT a forwarder normalizes an aliased keyexpr through before it crosses a
/// link without the inbound alias table (c3c-3 B1). Relocated out of
/// `push_build` so the Request forward path reuses it without the Push codec;
/// `alloc`-gated only (owned-string output).
#[cfg(feature = "alloc")]
pub mod wireexpr_build;

/// Shared `ext_nodeid` routing-context chain codec (P4 routing) — the SSOT
/// for the `zextz64!(0x3, true)` NodeId extension Push and Declare both carry,
/// plus the per-entry chain `Z`-bit normalisation. `push_routing_context` /
/// `declare_routing_context` / `request_routing_context` / `push_build`
/// delegate here instead of each re-implementing the chain edits (R311ru
/// consolidation of the prior triplication).
///
/// R311y801 — gated on `alloc` ALONE. It used to additionally require one of
/// `codec-push` / `codec-declare` / `codec-request` / `codec-response`, which
/// named its callers rather than its needs: every type this module touches
/// (`ExtEntryOwned`, `ExtZint`, [`ext_header`]) is ungated. The narrower gate
/// became wrong when `interest_build` — which carries NO codec gate, mirroring
/// the ungated `frame_encode::encode_frame_with_interest` — started stamping
/// the `ext_qos` chain, so an `alloc`-only build reached a chain edit that did
/// not exist. Widening costs nothing: the items are `pub`, so no configuration
/// gains a dead-code finding.
#[cfg(feature = "alloc")]
pub mod ext_nodeid;

/// QueryableInfo (`complete` / `distance`) extension on a DeclareQueryable
/// (P4 routing, QueryTarget::BestMatching) — `read_queryable_info` /
/// `set_queryable_info` over the body's ext chain, a thin projection of the
/// shared [`ext_nodeid`] z64-chain SSOT. Gated on `alloc` + `codec-declare`
/// (the carrier codec).
#[cfg(all(feature = "alloc", feature = "codec-declare"))]
pub mod queryable_info;

/// Push routing-context source `node_id` (P4 routing, linkstate port step
/// c3c-1): `read_push_source` / `set_push_source` over the Push `ext_nodeid`
/// extension — the data-plane forward seam naming the spanning-tree root a
/// linkstate-peer floods a message along. `codec-push` gated (the data plane
/// the routing context rides) and owned `Vec` output (alloc-gated).
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub mod push_routing_context;

/// OAM carrier for the linkstate-peer topology exchange (P4 routing,
/// linkstate port step c1): `build_linkstate_oam` wraps a `LinkStateList`
/// as an `OAM_LINKSTATE` network message, `try_parse_linkstate_oam`
/// extracts one back. `codec-linkstate` gated (AP/full-node routing,
/// absent from the MCU footprint); owned `Vec` output (alloc-gated).
#[cfg(all(feature = "alloc", feature = "codec-linkstate"))]
pub mod linkstate_oam;

/// Outbound DECLARE / UNDECLARE network-message builders
/// (`build_declare_*` / `build_undeclare_*` / `build_declare_final`)
/// hoisted from `wz-runtime-tokio::session_glue` so both runtime profiles
/// share one DECLARE-builder SSOT. Owned `Vec` output (alloc-gated) and
/// `codec-declare` gated. Distinct from the `declare` module (the
/// remote-declaration registries) — this is the outbound encode side.
#[cfg(all(feature = "alloc", feature = "codec-declare"))]
pub mod declare_build;

/// Declare routing-context source `node_id` (P4 routing, linkstate port step
/// c3c-3 atom3a): `read_declare_source` / `set_declare_source` over the
/// Declare `ext_nodeid` extension — the control-plane forward seam naming the
/// spanning-tree root a linkstate-peer floods a SOURCED subscription
/// declaration along (the Declare twin of [`push_routing_context`]).
/// `codec-declare` gated (the declaration carrier the routing context rides)
/// and owned `Vec` output (alloc-gated).
#[cfg(all(feature = "alloc", feature = "codec-declare"))]
pub mod declare_routing_context;

/// Declare `ext_keyexpr` extension (P4 routing, c3c-3 debt A1 — subscription
/// lifecycle): `build_ext_keyexpr` / `read_ext_keyexpr` over the
/// `_z_decl_ext_keyexpr` keyexpr extension a SOURCED `UndeclareSubscriber`
/// carries — the keyexpr IS the sourced-subscription identity (`id == 0`), so a
/// transit linkstate peer resolves which interest to withdraw from this ext.
/// `codec-declare` gated and owned `Vec` output (alloc-gated).
#[cfg(all(feature = "alloc", feature = "codec-declare"))]
pub mod declare_ext_keyexpr;

/// Declare `ext_qos` extension (R311y801): `QOS_DECLARE` /
/// `read_declare_qos` / `set_declare_qos` over the `zextz64!(0x1, false)` QoS
/// extension zenoh stamps on the Declare ENVELOPE — `Priority::Control` plus
/// `CongestionControl::Block`, the class that keeps a declaration out of the
/// drop-on-congestion band. Every `declare_build` envelope carries it; the
/// module owns the value, the header byte and the omit-on-DEFAULT rule.
/// `alloc`-gated only — the Interest arm rides the SAME extension (upstream's
/// Interest codec compares against `declare::ext::QoSType`), and
/// `wz_codecs::interest` carries no codec feature gate; the `DeclareOwned`-typed
/// items inside are `codec-declare`-gated individually.
#[cfg(feature = "alloc")]
pub mod declare_ext_qos;

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

/// SSOT for the Query body VALUE extension wire shape (the querier's attached
/// `payload` + `encoding`, the "Q_B / Q_E" wire codec slots). Gated on the
/// `query-value` catalog primitive that the querier `RequestQueryBuilder::
/// query_value` (encode) and the queryable `query::extract_query_value`
/// (decode) select; owns the one encode / decode pair for the
/// `(0x3, ENC_ZBUF, ExtZbuf body = encoding || payload)` value ext. Sibling of
/// `source_info_ext` (0x01) and `attachment` (0x05) — the three Query body exts.
#[cfg(all(feature = "alloc", feature = "query-value"))]
pub mod query_value_ext;

/// SSOT for the Z_EXT_AUTH establishment extension wire shape. Gated on the
/// `session-extauth` catalog primitive (AP-only — zenoh-pico has no auth);
/// owns the one encode / decode pair for the `(0x3, ENC_ZBUF, ExtZbuf body)`
/// auth ext on the Init / Open carrier. Sibling of `attachment` (same ExtZbuf
/// shape, distinct carrier + ext id space). The method-agnostic dispatch and
/// the concrete methods (usrpwd / pubkey) are follow-on atoms consuming it.
#[cfg(feature = "session-extauth")]
pub mod extauth;

/// SSOT for the Z_EXT_LOWLATENCY establishment ext (`transport-lowlatency`) —
/// the wz mirror of zenoh `init::ext::LowLatency` / `open::ext::LowLatency`
/// (`zextunit!(0x5,false)`). The codec layer (the `0x5` unit ext + the peer-offer
/// projector); the per-session `is_lowlatency` runtime state, the offer/`&=`
/// negotiation, and the lean no-Frame tx / rx data path live in `session_actions`
/// / `drive`.
/// R311xr — SSOT for the zero-payload UNIT capability-ext mechanism (encode +
/// presence-detect) shared by the lowlatency / compression / shm establishment
/// negotiations; each per-capability module keeps its named id + wrapper and
/// delegates the identical mechanism here.
/// R311y578 — `reassembly` / `transport-fragmentation` joined the gate: the
/// Fragment chain-boundary markers ([`extfragment`], ids `0x2` / `0x3`) are
/// unit exts in the Fragment message's own id space and share the identical
/// encode + identity-detect mechanism, so they delegate here rather than
/// re-deriving the third copy of it.
#[cfg(any(
    feature = "transport-lowlatency",
    feature = "session-extcompression",
    feature = "transport-shm",
    feature = "transport-qos",
    feature = "reassembly",
    feature = "transport-fragmentation"
))]
pub mod unit_ext;

/// R311y578 — SSOT for the `T_MID_FRAGMENT` message's OWN ext id space: the
/// `0x2 First` chain-start marker and the `0x3 Drop` chain-abandon marker
/// (zenoh `fragment::ext::{First,Drop}`). The TX emit has carried `First`
/// since R311y206; this module is where the RX INTERPRETATION reads both,
/// and where the reassembly Router's chain-boundary rules anchor.
#[cfg(any(feature = "reassembly", feature = "transport-fragmentation"))]
pub mod extfragment;

/// R311y578 (G2) — the PASSIVE session-context tracker: the observer-side
/// counterpart to `session_actions`'s participant state. Folds BOTH sides'
/// Init offers (a participant computes only its own half), tracks the phase
/// that decides when the stream reframes to the lowlatency 4-byte prefix, and
/// de-frames each direction's byte stream into decoded transport messages.
/// No I/O: capture ingest is a layer above.
#[cfg(all(
    feature = "alloc",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-frame"
))]
pub mod passive;

// R311y752 (carry N12) — the container decoded messages are held in, moved down
// from `wz-capture::messages`. Gated exactly as `passive` above, because that is
// where `PassiveFrame` comes from and this module is a list of them plus the
// discard receipt and census that share its privacy boundary.
//
// DELIBERATELY UNDOCUMENTED ON THIS LINE, and the reason is R311y724's: an outer
// `///` on a `mod` declaration is concatenated with the module's own `//!` docs
// and the merged block then resolves its intra-doc links in THIS scope, so every
// link the module makes to its own items reds under C1bz's zero broken-link
// budget. The module's note is in its own file.
#[cfg(all(
    feature = "alloc",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-frame"
))]
pub mod passive_messages;

/// R311y579 (G3 + G6-serde) — the LEAF-SCALAR field walker: a dissection that
/// reports, per scalar, the byte span it was decoded from, in a wz-owned view
/// model that can carry `serde` derives the codegen'd mirrors cannot. Gated on
/// `dissect`, which selects the whole codec-* MID space on purpose: an observer
/// reads every message it sees and encodes none.
#[cfg(feature = "dissect")]
pub mod dissect;

/// R311y585 (A4) — the OBSERVER's per-direction key-expression tables.
///
/// A participant keeps one table per link (the peer's ids) because the other
/// number space is its own. An observer has neither and must rebuild both,
/// then pick between them with the wire expression's `M` bit. Gated with the
/// dissect surface, whose consumers are the ones that need a path rather than
/// a number.
#[cfg(all(feature = "dissect", feature = "codec-declare"))]
pub mod passive_keyexpr;

/// R311y578 — SSOT for the `0x7` PATCH establishment ext: the protocol patch
/// LEVEL wz announces (R121f1) and, newly, the peer's half plus the `min()`
/// negotiation over it. The negotiated level is the sole gate on the
/// [`extfragment`] chain-boundary rules (zenoh
/// `PatchType::has_fragmentation_markers`), so reading it is a precondition
/// for honouring the markers without refusing every patch-0 peer's chains.
pub mod extpatch;

#[cfg(feature = "transport-lowlatency")]
pub mod extlowlatency;

/// SSOT for the Z_EXT_QOS establishment ext (`transport-qos`) — the wz mirror
/// of zenoh `init::ext::QoS` (`zextunit!(0x1,false)`). The codec layer (the 0x1
/// unit ext + the peer-offer projector that also tolerates the z64 `QoSLink`
/// form a priority-configured zenohd sends); the per-session `is_qos` state, the
/// `&=` negotiation, the per-priority SN conduits, and the Frame ext_qos wire
/// live in `session_actions` / `drive` / `inbound` / `frame_encode`.
///
/// Under `session-extqos` (R311y506) the module also owns the z64 `QoSLink`
/// half — the packed priority-range + reliability body and the DIRECTIONAL
/// containment that negotiates it (acceptor: subset; initiator: superset).
#[cfg(feature = "transport-qos")]
pub mod extqos;

/// SSOT for the transport-level batch COMPRESSION wrap (`transport-compression`)
/// — the wz mirror of zenoh's per-batch lz4 codec (batch.rs). `compress_batch` /
/// `decompress_batch` wrap the `[BatchHeader][payload]` the link layer length-
/// frames, applied at the `send_wire` / `dispatch_link_event` seams.
#[cfg(feature = "transport-compression")]
pub mod compression;

/// R311y9 — per-session transport byte/message counters (`transport-stats`) —
/// the wz mirror of zenoh's `zenoh-transport` `stats` feature. Additive
/// instrumentation counting wire bytes + messages at the `send_wire` (TX) /
/// `dispatch_link_event` (RX) seams, with a public snapshot accessor. Off by
/// default; the adminspace consumer stays P4.
/// R311y810 — the MODULE is unconditional; only the counting half
/// (`stats::TransportStats`, the atomics and the `inc_*` seams) is gated.
/// `stats::TransportStatsReport` is a four-integer snapshot with no
/// feature-dependent behaviour, and a consumer that carries one in a struct
/// field must be able to name the type in EVERY feature combination — the same
/// reason `locator::AnyLocator`'s `Serial` / `Unixsock` variants are
/// unconditional while their backends are gated. Gating the type instead is how
/// a cfg-gated pub struct field appears, which is the C1bf hazard class.
/// (Code spans, not links: the counting half is gated and this doc is read in
/// the default-feature rustdoc Layer C1bz measures.)
pub mod stats;

/// SSOT for the Z_EXT_COMPRESSION establishment ext (`session-extcompression`) —
/// the wz mirror of zenoh `init::ext::Compression` (`zextunit!(0x6,false)`). The
/// codec layer (the 0x6 unit ext + the peer-offer projector); the per-session
/// `is_compression` state, the `&=` negotiation, and the lz4 data path live in
/// `session_actions` / `drive` / `compression`.
#[cfg(feature = "session-extcompression")]
pub mod extcompression;

/// SSOT for the scoped same-host SHM descriptor + the Put-body `ext_shm` 0x2
/// marker + the [`extshm::ShmResolver`] no_std/std seam (`transport-shm`) — the
/// wz mirror of zenoh's zero-copy SHM payload (a descriptor on the wire + an
/// mmap'd segment off /dev/shm). The std POSIX segment lives in
/// `wz-runtime-tokio::shm_provider` behind the resolver trait.
#[cfg(feature = "transport-shm")]
pub mod extshm;

/// The method-agnostic Z_EXT_AUTH dispatch kernel — the wz mirror of zenoh
/// `establishment/ext/auth/mod.rs` (`AuthFsm`'s OpenFsm + AcceptFsm). Mux/demux
/// of per-method sub-exts (keyed by method id) into / out of the auth ext
/// across the four establishment stages, consuming the `extauth` outer codec +
/// the `ext_chain` inner chain. Method state rides `&mut self` on the existing
/// messages (no new FSM state, OQ-W10/W2). Concrete methods (usrpwd / pubkey) +
/// the live handshake wiring are follow-on atoms.
#[cfg(feature = "session-extauth")]
pub mod auth_dispatch;

/// SSOT for the Z_EXT_MULTILINK establishment ext (`transport-multilink`) — the
/// wz mirror of zenoh `establishment/ext/multilink.rs`. The 0x4 ext is UN-wrapped
/// (NOT muxed through [`auth_dispatch`]): the single-method
/// [`extmultilink::MultiLinkDispatch`] drives ONE `AuthMethod` (the ephemeral
/// pubkey handshake, injected rsa-free from wz-runtime-tokio) across the four
/// establishment stages and maps each `AuthSubExt` DIRECTLY to a 0x4
/// `ExtEntryOwned` via the shared [`auth_dispatch::AuthSubExt::into_ext_entry`]
/// SSOT (zenoh's `.transmute()`, id 0x1 -> 0x4, NO inner method-id frame). Gated
/// on `transport-multilink` (which forwards `session-extauth`); the aggregation
/// core (`MultiLinkSink` + the add-link decision) is a follow-on atom.
#[cfg(feature = "transport-multilink")]
pub mod extmultilink;

/// The usrpwd auth method — the wz mirror of zenoh `establishment/ext/auth/
/// usrpwd.rs`. A username/password challenge-response [`auth_dispatch::AuthMethod`]
/// (HMAC-SHA3-256 over an InitAck nonce). Gated on `access-extauth-usrpwd` (the
/// first concrete §5.16 auth method; pulls `sha3`).
#[cfg(feature = "access-extauth-usrpwd")]
pub mod extauth_usrpwd;

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

/// Request routing-context source `node_id` (P4 routing, query-routing atom
/// 2a): `read_request_source` / `set_request_source` over the Request
/// `ext_nodeid` extension — the seam naming the spanning-tree root a
/// linkstate-peer relays a ROUTED Query (`Request`) along, toward the matching
/// queryables (the Request twin of [`push_routing_context`] /
/// [`declare_routing_context`]). `codec-request` gated (the Query carrier the
/// routing context rides) and owned `Vec` output (alloc-gated).
#[cfg(all(feature = "alloc", feature = "codec-request"))]
pub mod request_routing_context;

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

/// R311uw — the `storage-backend` atom (§5.11 storage, 1/4): the pluggable
/// [`storage_backend::StorageBackend`] seam + an in-memory backend
/// ([`storage_backend::MemoryStorage`]). A faithful mirror of zenoh's
/// `zenoh-backend-traits` `Storage` trait + the bundled `memory_backend`.
/// Gated on `storage-backend` (which implies `alloc`: the BTreeMap /
/// String / Vec backing + the `crate::sample` TimestampHint / EncodingHint
/// the `StoredData` embeds). Runtime-agnostic backend layer; the newer-wins
/// service decision + the wz-runtime-tokio StorageService driver are the
/// follow-up atoms.
#[cfg(feature = "storage-backend")]
pub mod storage_backend;

/// R311ux — the storage *service gate* (§5.11 storage, atom 2/4): the
/// newer-wins versioning decision + the query-match set
/// ([`storage_state::StorageState`]). The runtime-agnostic half of a
/// storage service — pure no_std, no Subscriber / Queryable / async — that
/// turns the dumb [`storage_backend::StorageBackend`] into a storage by
/// applying zenoh's `guard_cache_if_latest` newer-wins gate (older
/// Put/Delete -> Outdated; Delete leaves a tombstone timestamp) and
/// resolving a (wildcard) query into the matching stored entries via the
/// shared [`keyexpr_match::keyexpr_intersects_target`] scan. Same
/// `storage-backend` gate; the wz-runtime-tokio StorageService driver
/// (Subscriber + complete Queryable + select loop) wraps a `StorageState`
/// (atom 3).
#[cfg(feature = "storage-backend")]
pub mod storage_state;

/// R311y55 — the §5.24 storage *Volume* layer: the FACTORY
/// ([`storage_volume::Volume`]) above the §5.11 per-store
/// [`storage_backend::StorageBackend`], plus the [`storage_volume::Capability`] /
/// [`storage_volume::Persistence`] guarantees and the base in-memory
/// [`storage_volume::MemoryVolume`]. The wz mirror of zenoh
/// `zenoh-backend-traits` `Volume` + `MemoryBackend` — the keystone a storage
/// MANAGER drives to host N named storages. FOUNDATIONAL: always compiled under
/// `storage-backend` (no own cfg toggle); the toggleable manager atoms
/// (multi-storage-host / strip-prefix / GC) compose ON it once
/// `storage-mgr-config` lands.
#[cfg(feature = "storage-backend")]
pub mod storage_volume;

/// R311y56 — the §5.24 storage manager *config* data model
/// ([`storage_config::StorageConfig`] + [`storage_config::GarbageCollectionConfig`]):
/// the declarative description of one named storage (name / key_expr / volume_id /
/// complete / strip_prefix / GC) a storage MANAGER reads to create + drive it. The
/// wz mirror of zenoh `zenoh-backend-traits` `StorageConfig`. FOUNDATIONAL: the
/// typed model only; the behaviors that read each field (complete-flag /
/// strip-prefix / garbage-collection) + the consumer (multi-storage-host) are
/// their own atoms.
#[cfg(feature = "storage-backend")]
pub mod storage_config;

/// R311y57 — the §5.24 `storage-mgr-multi-storage-host` atom: the
/// [`storage_manager::StorageManager`] that hosts N named storages over a registry
/// of named [`storage_volume::Volume`]s, creating each backend from its
/// [`storage_config::StorageConfig`] via the volume (the wz mirror of zenoh's
/// plugin-storage-manager `spawn_storage`). The first cfg-ACTIVE storage-manager
/// atom (the data-model + volume keystones are FOUNDATIONAL); composes
/// `storage-backend`.
#[cfg(feature = "storage-mgr-multi-storage-host")]
pub mod storage_manager;

/// R311y58 — the §5.24 `storage-mgr-strip-prefix` atom: the
/// [`storage_strip_prefix::strip_prefix`] / [`storage_strip_prefix::restore_prefix`]
/// key transforms a storage manager applies so a storage holds keys RELATIVE to a
/// mount point (the wz mirror of zenoh's `strip_prefix` / `prefix`). Closes the
/// R311wt aligner strip_prefix gap at the LOGIC level; the live manager/backend
/// application (which needs a §5.11 backend Option-key change for the exact-match
/// none-key) is a documented follow-up.
#[cfg(feature = "storage-mgr-strip-prefix")]
pub mod storage_strip_prefix;

/// R311uz — the `storage-history` atom (§5.11 storage, 2/4): an in-memory
/// `History::All` backend ([`storage_history::HistoryStorage`]) that keeps
/// every version per key, the multi-version counterpart of
/// [`storage_backend::MemoryStorage`]. The newer-wins gate skips an `All`
/// backend (every version retained); a query replies all versions. Gated
/// on `storage-history` (which implies `storage-backend`).
#[cfg(feature = "storage-history")]
pub mod storage_history;

/// R311y104 — the NTP64 timestamp-word SSOT ([`ntp64::Ntp64`]): the
/// `(unix_secs << 32) | fraction` layout uhlc / zenoh `Timestamp` carry, with
/// the `2^32` fraction-per-second magnitude defined once. A pure-core helper
/// (always compiled) the storage-replication classification, the AP wall-clock
/// source, and the advanced-cache `_time` resolver all build on, so the
/// magnitude is no longer stated four ways.
pub mod ntp64;

/// Round 311vh — the storage-replication *primitives* atom (§5.11 storage,
/// replication 1/N): the [`storage_replication::Fingerprint`], the
/// time-bucket classification ([`storage_replication::IntervalIdx`] /
/// [`storage_replication::SubIntervalIdx`]), the
/// [`storage_replication::ReplicationConfig`] + its compatibility
/// fingerprint, and the [`storage_replication::event_fingerprint`] a
/// replica's Digest is assembled from. Pure no_std xxh3 logic — a faithful,
/// byte-exact mirror of zenoh's `zenoh-plugin-storage-manager`
/// `replication::{digest,classification,configuration,log}`. The Digest
/// assembly + diff + wire codec + the publish/subscribe driver are the
/// follow-up atoms. Gated on `storage-replication` (implies
/// `storage-backend`).
#[cfg(feature = "storage-replication")]
pub mod storage_replication;

/// Round 311wa — the shared no_std bincode-1.3 wire primitives (the single
/// LE-fixint cursor + length helpers + the multi-consumer widths) the wire
/// codecs build on, so the bincode-1.3 framing contract lives in one place.
/// Gated on `storage-replication` (the aligner feature implies it) OR
/// `ext-pubsub-group-membership` (R311y97 — the group-membership wire codec is
/// the third consumer of the same bincode-1.3 cursor; it is independent of the
/// storage codecs but reuses the framing SSOT).
#[cfg(any(
    feature = "storage-replication",
    feature = "ext-pubsub-group-membership"
))]
pub(crate) mod wire_bincode;

/// R311y97 — `ext-pubsub-group-membership` (§5.25): the no_std data model
/// ([`group_membership::Member`] / [`group_membership::MemberLiveliness`] /
/// [`group_membership::GroupNetEvent`]) + the bincode-1.3 wire codec for
/// zenoh-ext's group-membership protocol. A faithful, byte-exact mirror of
/// zenoh-ext `group.rs`'s `bincode::serialize` wire (the group event +
/// per-member reply messages), hand-rolled on the shared
/// [`wire_bincode`] cursor and pinned to the real `bincode` 1.3 by a
/// `#[cfg(test)]` oracle. The live [`Group`](../wz_runtime_tokio/group) +
/// its background tasks are the AP-only tokio half. INDEPENDENT of the
/// advanced-pubsub `@adv` family (its own wire + KE namespace).
#[cfg(feature = "ext-pubsub-group-membership")]
pub mod group_membership;

/// Round 311vr — the storage-aligner *event metadata* atom (§5.11 storage,
/// aligner 1/N): the [`storage_aligner::Action`] + [`storage_aligner::EventMetadata`]
/// a replica exchanges to pull the entries a
/// [`storage_replication::DigestDiff`] localised. The metadata's
/// [`fingerprint`](storage_aligner::EventMetadata::fingerprint) reuses the
/// [`storage_replication::event_fingerprint`] SSOT, so an event's identity
/// agrees between the digest and the aligner. Pure no_std logic — a faithful
/// mirror of zenoh's `zenoh-plugin-storage-manager` `replication::log`
/// metadata (all four `Action` variants round-trip on the wire as of R311wt
/// slice-1; wz does not yet PRODUCE or APPLY a wildcard event — slices 2/3). The
/// AlignmentQuery / AlignmentReply protocol + the answer / pull engines + the
/// aligner driver are the follow-up atoms. Gated on `storage-aligner`
/// (implies `storage-replication`).
#[cfg(feature = "storage-aligner")]
pub mod storage_aligner;

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
/// `sources/network/reassembly_slot.scxml`; R311y22b: COMMITTED at
/// `out/wz-session-core/reassembly_slot_sm.rs`, `include!`-ed from there
/// (regenerated by the `xtask` SSOT, no build script), compiled only under the
/// `reassembly` feature.
/// Exposes the `ReassemblySlotState` / `ReassemblySlotEvent` enums, the
/// `ReassemblySlotActions` host trait, the `ReassemblySlotPolicy<A>`
/// policy, and the typed `ReassemblySlotInject` seam. Fully
/// script-engine-free (no `IScriptEngine`): every effect is a native
/// `<sce:action>` trait call and every guard is a typed `_event.data`
/// comparison, so the module compiles `#![no_std]`. The xtask
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
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-session-core",
        "/reassembly_slot_sm.rs"
    ));
}

/// R311im — the reassembly Router (dispatcher) that drives N
/// [`reassembly_slot`] FSM instances: the stateful SN-consecutiveness
/// classification, per-peer quota, staging buffers, and deadline sweep
/// that the engine-free slot FSM cannot own. See the module docs for the
/// division of labour with the slot FSM.
/// R311y589 — the seam between the reassembly Router and the STORAGE its
/// chains accumulate into ([`chain_staging::ChainStaging`]), plus the default
/// on-demand-heap arena. Gated with the Router it serves: a build without
/// `reassembly` has no chains to stage.
#[cfg(feature = "reassembly")]
pub mod chain_staging;

/// R311y713 (§B7) — what a reassembly sweep gave up on, as a value.
///
/// UNGATED, unlike the Router it describes: the verbs that return it
/// (`PassiveSession::observe_at_counting` and friends) are ungated on the
/// R311y655 rule that a caller must not have to know which features this
/// binary carries, and a return type gated more narrowly than its function
/// breaks precisely the feature arm between the two — measured, on
/// `--features dissect` without `reassembly`.
pub mod chain_loss;

#[cfg(feature = "reassembly")]
pub mod reassembly_dispatch;

/// SCE-generated active scouting state machine (R311ik). The emit comes
/// from `sources/session/scouting.scxml`; R311y22b: COMMITTED at
/// `out/wz-session-core/scouting_sm.rs`, `include!`-ed from there (regenerated
/// by the `xtask` SSOT, no build script), compiled only under the
/// `scouting-active` feature.
/// Exposes the `ScoutingState` / `ScoutingEvent` enums, the
/// `ScoutingActions` host trait, and the `ScoutingPolicy<A>` policy.
/// Fully script-engine-free (no `IScriptEngine`) and self-timer-free (no
/// `<send delay>`): every effect is a native `<sce:action>` trait call
/// and the host drive loop (wz-runtime-tokio scouting_glue) owns the
/// scout deadline, so the module compiles `#![no_std]`. The xtask
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
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-session-core",
        "/scouting_sm.rs"
    ));
}

/// SCE-generated unicast session state machine (R311il). The emit comes
/// from `sources/session/session_fsm_unicast.scxml`; R311y22b: COMMITTED at
/// `out/wz-session-core/session_fsm_unicast_sm.rs`, `include!`-ed from there
/// (regenerated by the `xtask` SSOT, no build script), compiled only under the
/// `session-unicast` feature. Exposes the `SessionFsmUnicastState` /
/// `SessionFsmUnicastEvent` enums, the `SessionFsmUnicastActions` host
/// trait, and the `SessionFsmUnicastPolicy<A>` policy. Fully
/// script-engine-free (no `IScriptEngine`) and self-timer-free (no
/// `<send delay>`): every effect is a no-arg native `<sce:action>` trait
/// call and the host drive loop (wz-runtime-tokio session_glue) owns
/// every session deadline + pre-classifies the accept guards, so the
/// module compiles `#![no_std]`. The xtask strips the file-head
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
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-session-core",
        "/session_fsm_unicast_sm.rs"
    ));
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
/// comes from `sources/session/session_fsm_multicast.scxml`; R311y22b:
/// COMMITTED at `out/wz-session-core/session_fsm_multicast_sm.rs`, `include!`-ed
/// from there (regenerated by the `xtask` SSOT, no build script), compiled only
/// under the `session-multicast` feature. Exposes the `SessionFsmMulticastState` /
/// `SessionFsmMulticastEvent` enums, the `SessionFsmMulticastActions` host
/// trait, and the `SessionFsmMulticastPolicy<A>` policy. Engine-free (no
/// `IScriptEngine`) and self-timer-free (no `<send delay>`): the §3.1
/// lifecycle (Idle/LinkOpening/Running/Stopped) with the §3.1 parallel
/// Running concerns elided to a leaf owned by the [`multicast_dispatch`]
/// Router. Handshake-free (§3.3), so a different shape from
/// [`session_fsm_unicast`]. The xtask strips the file-head `#![...]`
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
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-session-core",
        "/session_fsm_multicast_sm.rs"
    ));
}

/// SCE-generated multicast per-peer membership state machine (Round A). The
/// emit comes from `sources/session/multicast_peer.scxml`; R311y22b: COMMITTED
/// at `out/wz-session-core/multicast_peer_sm.rs`, `include!`-ed from there
/// (regenerated by the `xtask` SSOT, no build script), compiled only under the
/// `session-multicast` feature. Exposes the `MulticastPeerState` /
/// `MulticastPeerEvent` enums, the `MulticastPeerActions` host trait, and
/// the `MulticastPeerPolicy<A>` policy. Engine-free; the §3.2 membership
/// lifecycle (Free/Discovered/Active/Expired) driven one-instance-per-peer
/// by the [`multicast_dispatch`] Router — the same one-FSM-per-entity shape
/// [`reassembly_slot`] uses for fragment chains. The xtask strips
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
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/wz-session-core",
        "/multicast_peer_sm.rs"
    ));
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

/// R311kt — the multicast JOIN datagram surface (encode the periodic TX
/// beacon, decode the RX classify view, validate the §3.2 rejection
/// rules), hoisted from `wz-runtime-tokio::multicast_glue` so both
/// runtime profiles share one JOIN wire SSOT (the multicast sibling of
/// [`handshake_encode`]). Pure functions: codecs + [`multicast_params`] +
/// [`sn`] only — the host drive loops own the socket + the clock.
#[cfg(all(
    feature = "session-multicast",
    feature = "codec-join",
    feature = "alloc"
))]
pub mod multicast_join;

/// R311lv — the shared multicast RX classify + dispatch SSOT consumed by both
/// the AP (`wz-runtime-tokio::multicast_glue`) and MCU
/// (`wz-session-lwip::multicast_drive`) drive loops, so the §3.1 RxDispatch
/// decision (transport MID -> [`multicast_dispatch`] method) has ONE home
/// rather than a copy per loop. Pure orchestration over [`multicast_dispatch`]
/// + [`multicast_join`] + the inbound / frame codecs; the loops own only the IO
/// + clock + their reassembly Router (the divergent tail
/// [`multicast_rx::MulticastRxNext`] hands back).
#[cfg(all(
    feature = "session-multicast",
    feature = "codec-join",
    feature = "codec-frame",
    feature = "codec-close",
    feature = "alloc"
))]
pub mod multicast_rx;

/// R311lx — the shared multicast TX emit SSOT consumed by both the AP
/// (`wz-runtime-tokio::multicast_glue`) and MCU
/// (`wz-session-lwip::multicast_drive`) drive loops, so the §3.1 TxData
/// decision ([`MulticastTxItem`](multicast_tx::MulticastTxItem) -> mint ->
/// `encode_frame_with_*` -> [`multicast_frame_or_fragments`](frame_encode::multicast_frame_or_fragments))
/// has ONE home rather than a copy per loop. The TX twin of [`multicast_rx`];
/// the loops own only the IO (how the next item is obtained, how each returned
/// datagram is sent). Needs codec-frame + alloc; the per-variant body codecs
/// (codec-push / codec-response / codec-response-final / liveliness-token) gate
/// the enum variants and the matching emit arms.
#[cfg(all(
    feature = "session-multicast",
    feature = "codec-frame",
    feature = "alloc"
))]
pub mod multicast_tx;

/// R311md — the shared observer-drain reply sink SSOT
/// ([`MulticastReplySink<Q>`](multicast_reply_sink::MulticastReplySink) +
/// [`MulticastReplyEnqueue`](multicast_reply_sink::MulticastReplyEnqueue)). The
/// "staged reply -> [`MulticastTxItem`](multicast_tx::MulticastTxItem)"
/// construction has ONE home, generic over the enqueue backing, so the AP and
/// MCU multicast loops contribute only a backing rather than a duplicated
/// `ResponseSink` / `DeclareReplySink` impl. The TX-staging sibling of
/// [`multicast_rx`] / [`multicast_tx`]. Same gate as `multicast_tx`.
#[cfg(all(
    feature = "session-multicast",
    feature = "codec-frame",
    feature = "alloc"
))]
pub mod multicast_reply_sink;
