// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Outbound INTEREST network-message builders.
//!
//! `build_interest_liveliness_subscriber` / `build_interest_liveliness_get`
//! construct the `InterestOwned` codec struct for the liveliness-token
//! subscribe (FUTURE) and one-shot GET (CURRENT) paths — both routed through
//! the shared `build_liveliness_token_interest` body-header SSOT —
//! and `build_interest_final` the matching terminator. Pure wz-codecs
//! constructors — no runtime / no FSM coupling; the transport-`Frame`
//! envelope is applied separately by `frame_encode::encode_frame_with_interest`.
//!
//! Hoisted from `wz-runtime-tokio::session_glue` so both runtime profiles
//! share one INTEREST-builder SSOT — the MCU `#![no_std]` profile cannot
//! depend on the tokio crate. `InterestOwned` output, so alloc-gated; the
//! builders carry no codec feature gate (mirroring the ungated
//! `frame_encode::encode_frame_with_interest`).

use sce_forge_runtime::codec::CodecError;
use wz_codecs::wire_const;

use wz_codecs::interest::InterestOwned;
use wz_codecs::interest_body::InterestBodyOwned;
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
use wz_codecs::wireexpr_local::WireexprLocalOwned;

/// R279 — build an `Interest` network-message that subscribes to the
/// peer's `DeclToken` / `UndeclToken` stream restricted to a specific
/// keyexpr. Mirrors zenoh-pico `_z_n_interest_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/network.c:452-486` invoked
/// from `_z_register_liveliness_subscriber` with
/// `flags = KEYEXPRS | TOKENS | RESTRICTED | FUTURE [| CURRENT]`
/// (`vendor/zenoh-pico/src/net/liveliness.c:169-198` via
/// `vendor/zenoh-pico/src/session/interest.c:204-209`).
///
/// Wire shape (composed by `Interest::encode` from the
/// `sources/codecs/interest.scxml` envelope + `interest_body.scxml`
/// inner body):
///
/// ```text
///   [outer header = N_MID_INTEREST (0x19)
///                    | (history ? 0x20 : 0)   // C = CURRENT
///                    | 0x40                    // F = FUTURE
///                    | (Z extensions = 0 here)]
///   VLE(interest_id)
///   [InterestBody.header = 0x01 (KE) | 0x08 (TO) | 0x10 (R)
///                          | (suffix.is_some() ? 0x20 : 0) // N
///                          | 0x40                           // M (Local)
///                          ]
///   wireexpr.encode  (id VLE + optional suffix_len VLE + suffix bytes)
/// ```
///
/// N/M bit positions on `InterestBody.header` (bits 5 and 6) coincide
/// with the C/F bit positions on the outer `Interest.header` — that
/// is intentional and matches zenoh-pico's `_Z_INTEREST_FLAG_COPY_MASK
/// = 0x9F` reorder at `vendor/zenoh-pico/src/protocol/codec/interest.c:37`:
/// the encoder hoists C/F to the outer header, clears them from the
/// body, and stores N/M (wireexpr codec flags) at the freed positions.
/// The two `header` bytes are distinct wire bytes so the apparent
/// overload causes no collision; the body carrier owns its own bit
/// layout per `interest_body.scxml::header` flags carrier definition.
///
/// `history = true` instructs the peer to immediately replay the
/// current matching `DeclToken` set (zenoh-pico's
/// `_z_liveliness_subscription_trigger_history` fires after the
/// register call); `history = false` only registers for future
/// events. The `FUTURE` (F) bit is always set — a wz liveliness
/// subscriber that does not want future events would
/// `Self::send_interest_final` immediately after the declare and
/// the peer would remove the interest before any future event
/// arrives, which is the wrong shape (use a one-shot Query path for
/// "current matching set only").
///
/// `keyexpr_mapping_id == 0` with `keyexpr_suffix = Some(s)` targets
/// a literal keyexpr. Pure-alias (mapping_id != 0, suffix=None) and
/// composite (mapping_id != 0, suffix=Some) forms emit via the
/// `Local` wireexpr arm; the `Nonlocal` arm (M=0) for keyexprs
/// rooted in the peer's mapping table is reserved for a future
/// `_nonlocal` companion builder mirroring the DECLARE pattern.
pub fn build_interest_liveliness_subscriber(
    interest_id: u64,
    history: bool,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<InterestOwned, CodecError> {
    // A liveliness subscriber always sets FUTURE (the subscription stays
    // live for subsequent peer declarations); CURRENT mirrors the
    // `history` replay request.
    let mut interest = build_liveliness_token_interest(
        interest_id,
        /*current=*/ history,
        /*future=*/ true,
        keyexpr_mapping_id,
        keyexpr_suffix,
    )?;
    // R311y801 — the `ext_qos` upstream stamps on THIS Interest and on no other
    // api-level one (`api/session.rs:1812`; the subscribers / queryables /
    // liveliness-get / Final interests are all left at DEFAULT and so write
    // nothing). Applied HERE rather than in the shared
    // `build_liveliness_token_interest` precisely because the GET arm shares
    // that body and must NOT carry it — the two builders differ in the C/F bits
    // and now in this, and folding it down would have made wz uniform where
    // upstream is not.
    crate::declare_ext_qos::set_interest_qos(&mut interest, crate::declare_ext_qos::QOS_DECLARE);
    Ok(interest)
}

/// Build a one-shot liveliness GET (snapshot) `Interest`: CURRENT set,
/// FUTURE clear, restricted to the attached keyexpr. The peer replies
/// with the currently-alive matching tokens (`interest_id`-tagged
/// `Declare(DeclToken)`) terminated by an `interest_id`-tagged
/// `Declare(DeclFinal)`, then — because FUTURE is clear — drops the
/// interest without streaming future events. Mirrors zenoh-pico's
/// `_z_liveliness_query` flags
/// (`KEYEXPRS | TOKENS | RESTRICTED | CURRENT`,
/// `vendor/zenoh-pico/src/net/liveliness.c:350-352`). Shares the
/// body-header flag composition with
/// [`build_interest_liveliness_subscriber`] via
/// [`build_liveliness_token_interest`] (one SSOT; the two differ only in
/// the outer C / F bits).
pub fn build_interest_liveliness_get(
    interest_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<InterestOwned, CodecError> {
    build_liveliness_token_interest(
        interest_id,
        /*current=*/ true,
        /*future=*/ false,
        keyexpr_mapping_id,
        keyexpr_suffix,
    )
}

/// WHICH DECLARATION KINDS an `Interest` asks the peer for — the `S`, `Q`
/// and `T` bits of the `InterestBody` header, and nothing else.
///
/// The kind bits are the ONLY part of that header a caller chooses. `KE`
/// (bit 0) and `R` (bit 4) are implied by wz always attaching a keyexpr, and
/// `N` / `M` are derived from the wireexpr the builder composes — deriving
/// them rather than accepting them is what zenoh does too, in
/// `Interest::options` (`zenoh-protocol/src/network/interest.rs:198-209`,
/// which adds `RESTRICTED` / `NAMED` / `MAPPING` from `wire_expr` after the
/// caller has supplied only the kinds). A caller that could set them
/// independently could emit `R=0, N=1`, which the protocol comment at
/// `interest.rs:131-136` forbids ("If R==0 then N should be set to 0").
///
/// Bit values are the wire's, shared by all three implementations:
/// `S=0x02`, `Q=0x04`, `T=0x08` — zenoh's `InterestOptions::SUBSCRIBERS`
/// / `QUERYABLES` / `TOKENS` (`interest.rs:248-251`), zenoh-pico's
/// `_Z_INTEREST_FLAG_*` and wz's own generated
/// `InterestBodyOwned::su` / `qu` / `to` accessors
/// (`out/wz-codecs/interest_body.rs`).
///
/// AGGREGATE (`A`, bit 7) is deliberately ABSENT from this type rather than
/// merely unused: it is not a kind (it asks for the matching kinds to be
/// answered as ONE reply, not for a fourth kind of declaration), and wz has
/// no aggregate reply staging — see the `liveliness-token` inventory atom,
/// whose aggregate residual records why the obvious implementation regresses
/// a paid-for MCU footprint fix. A `const AGGREGATE` here would read as
/// "supported".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InterestKinds(u8);

impl InterestKinds {
    /// Peer SUBSCRIBER declarations (`S`). zenoh emits this from
    /// `declare_publisher_inner` (`zenoh/src/api/session.rs:1373-1374`); a
    /// zenoh ROUTER propagates a subscriber declaration to a face ONLY if
    /// that face registered an interest carrying this bit
    /// (`hat/router/pubsub.rs:120-125`), which is why a wz face that never
    /// emits it sees an empty remote-subscriber set against zenohd.
    pub const SUBSCRIBERS: Self = Self(0x02);

    /// Peer QUERYABLE declarations (`Q`). zenoh emits this from
    /// `declare_querier_inner` (`api/session.rs:1431-1432`) and its router
    /// gates queryable propagation on it the same way
    /// (`hat/router/queries.rs:255-259`).
    pub const QUERYABLES: Self = Self(0x04);

    /// Peer liveliness TOKEN declarations (`T`) — the kind wz has always
    /// emitted, via [`build_interest_liveliness_subscriber`] /
    /// [`build_interest_liveliness_get`].
    pub const TOKENS: Self = Self(0x08);

    /// The raw `S|Q|T` bits, for composition into the body header.
    ///
    /// Deliberately no constructor from a raw `u8`: the only values this
    /// type may hold are unions of the three constants, and a `from_bits`
    /// would let a caller smuggle `R` / `N` / `M` / `A` into the kind
    /// position where they would silently overwrite the derived bits.
    pub const fn bits(self) -> u8 {
        self.0
    }
}

// THE EMPTY SET IS UNREPRESENTABLE, and that is the whole guard: this type
// has no `empty()`, no `Default`, and no `from_bits`, so the only values a
// caller can build are unions of the three constants above and every one of
// them has at least one kind bit. An Interest naming NO kind would be a leak
// with no observable effect — the peer registers an interest that can never
// match a declaration and only a Final clears it — and zenoh cannot express
// it either (each of its emit sites names a kind literally). Making it
// unconstructible is preferred over a runtime reject because there is no
// honest `CodecError` variant for it: the encoder would happily write the
// byte, so the refusal is a protocol judgement, not an encoding failure.

impl core::ops::BitOr for InterestKinds {
    type Output = Self;

    /// Union — `SUBSCRIBERS | QUERYABLES` is one Interest asking for both,
    /// exactly as zenoh's `InterestOptions` adds its flags together.
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// SSOT for the RESTRICTED `Interest` body-header flag composition
/// (`KE | <kinds> | R | N | M`) shared by every builder in this module. The
/// callers differ only in the kind bits and in the outer `Interest.header`
/// C (CURRENT) / F (FUTURE) bits, surfaced here as `kinds` / `current` /
/// `future`. Keeping one constructor is what stops the body-header bitset
/// drifting between the token, subscriber and queryable paths — the three
/// share every bit except the kind.
///
/// N/M bit positions on `InterestBody.header` (bits 5 and 6) coincide
/// with the C/F positions on the outer `Interest.header`; that is
/// intentional and matches zenoh-pico's `_Z_INTEREST_FLAG_COPY_MASK`
/// reorder (the two `header` bytes are distinct wire bytes, so no
/// collision). The inner body always sets KE (carries a keyexpr) and R
/// (restricted to the attached keyexpr); AG stays clear (wz stages no
/// aggregate reply — see [`InterestKinds`]).
///
/// `keyexpr_suffix.is_some()` is the ONLY source of N and the `Local`
/// wireexpr arm the only source of M, both derived here rather than passed:
/// see [`InterestKinds`] for why the protocol forbids the combinations a
/// caller-supplied form would allow.
fn build_restricted_interest(
    interest_id: u64,
    kinds: InterestKinds,
    current: bool,
    future: bool,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<InterestOwned, CodecError> {
    let suffix_len = keyexpr_suffix.map(|s| s.len() as u64);
    let suffix_string = keyexpr_suffix
        .map(crate::codec_owned::owned_string)
        .transpose()?;

    // Outer header: MID 0x19 | (current ? C) | (future ? F). Z stays
    // clear — wz emits no Interest-level extensions today; the
    // wz-codecs envelope leaves bit 7 free for a future ext-chain.
    let c_flag = if current { 0x20u8 } else { 0x00u8 };
    let f_flag = if future { 0x40u8 } else { 0x00u8 };

    let ke_flag = 0x01u8;
    let r_flag = 0x10u8;
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    let m_flag = 0x40u8; // Local arm (M=1)
    let body_header = ke_flag | kinds.bits() | r_flag | n_flag | m_flag;

    Ok(InterestOwned {
        header: wire_const::N_MID_INTEREST | c_flag | f_flag,
        interest_id,
        body: Some(InterestBodyOwned {
            header: body_header,
            keyexpr: Some(WireexprOwned {
                body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                    id: keyexpr_mapping_id,
                    suffix_len,
                    suffix: suffix_string,
                }),
            }),
        }),
        extensions: None,
    })
}

/// The liveliness-token arm of [`build_restricted_interest`] — kinds fixed
/// to [`InterestKinds::TOKENS`]. Kept as a named wrapper because the two
/// public liveliness builders differ only in C / F and share this kind
/// choice; inlining it would restate `TOKENS` at both.
fn build_liveliness_token_interest(
    interest_id: u64,
    current: bool,
    future: bool,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<InterestOwned, CodecError> {
    build_restricted_interest(
        interest_id,
        InterestKinds::TOKENS,
        current,
        future,
        keyexpr_mapping_id,
        keyexpr_suffix,
    )
}

/// Build an `Interest` asking the peer for its SUBSCRIBER declarations
/// matching `(keyexpr_mapping_id, keyexpr_suffix)` — the emit wz was missing
/// entirely until R311y771, and the reason a wz face peered with zenohd saw
/// an EMPTY remote-subscriber set no matter how many subscribers the far side
/// declared.
///
/// The gate is on the ROUTER, not on wz: `hat/router/pubsub.rs:120-125`
/// propagates a subscriber declaration to a destination face only if that
/// face's own `remote_interests` holds one with `options.subscribers()`
/// matching the resource. No interest, no declarations — silently, with no
/// error anywhere. The data plane is unaffected either way (a `Put` carries
/// its keyexpr inline), so what this restores is the DECLARATION plane:
/// `RemoteSubscriberRegistry`, and with it `get_matching_status` and the
/// matching listeners built on top of it.
///
/// zenoh emits the same message from `declare_publisher_inner` with
/// `options: KEYEXPRS + SUBSCRIBERS` and `mode: CurrentFuture`
/// (`zenoh/src/api/session.rs:1370-1377`); `RESTRICTED` / `NAMED` /
/// `MAPPING` are added by `Interest::options` from the attached
/// `wire_expr`, which is exactly what the shared header SSOT derives (the
/// private `build_restricted_interest`, named rather than linked: a public
/// doc linking a private item is a Layer C1bz finding).
///
/// `current` requests the peer's CURRENT matching set (replayed as
/// `interest_id`-tagged declarations terminated by a `DeclFinal`) and
/// `future` keeps the interest live for subsequent declare / undeclare
/// events; the pair spans the three non-Final modes of `InterestMode`
/// (`Current`, `Future`, `CurrentFuture`). Do NOT pass both clear to reach
/// a Final: the outer header would read as `Mode::Final` while a body is
/// still attached, and upstream neither writes it (`zenoh-codec/src/network/
/// interest.rs:69`) nor reads it (`:130`) in that mode, so the body bytes
/// would be parsed as the NEXT message. [`build_interest_final`] is the
/// Final, and it emits no body at all.
pub fn build_interest_subscribers(
    interest_id: u64,
    current: bool,
    future: bool,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<InterestOwned, CodecError> {
    build_restricted_interest(
        interest_id,
        InterestKinds::SUBSCRIBERS,
        current,
        future,
        keyexpr_mapping_id,
        keyexpr_suffix,
    )
}

/// Build an `Interest` asking the peer for its QUERYABLE declarations
/// matching `(keyexpr_mapping_id, keyexpr_suffix)` — the queryable-plane
/// twin of [`build_interest_subscribers`], gated by the router the same way
/// (`hat/router/queries.rs:255-259` requires `options.queryables()` on a
/// matching face interest before it propagates a queryable declaration).
///
/// zenoh emits it from `declare_querier_inner` with `options: KEYEXPRS +
/// QUERYABLES`, `mode: CurrentFuture` (`api/session.rs:1428-1435`).
///
/// What it feeds on the wz side is `RemoteQueryableRegistry` — the backing
/// of `Querier::get_matching_status` and the querier-scoped matching
/// listener.
pub fn build_interest_queryables(
    interest_id: u64,
    current: bool,
    future: bool,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<InterestOwned, CodecError> {
    build_restricted_interest(
        interest_id,
        InterestKinds::QUERYABLES,
        current,
        future,
        keyexpr_mapping_id,
        keyexpr_suffix,
    )
}

/// Build an `Interest` for an arbitrary UNION of declaration kinds — the
/// general form the three fixed-kind builders above specialise.
///
/// Public because the union is genuinely expressible upstream (zenoh's
/// `InterestOptions` is additive and its `ALL` constant is
/// `KEYEXPRS|SUBSCRIBERS|QUERYABLES|TOKENS`,
/// `zenoh-protocol/src/network/interest.rs:253-259`) and a caller that wants
/// both planes should send ONE Interest rather than two — two interests mean
/// two ids, two Finals, and two independent `DeclFinal` terminations to
/// correlate.
pub fn build_interest_kinds(
    interest_id: u64,
    kinds: InterestKinds,
    current: bool,
    future: bool,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<&str>,
) -> Result<InterestOwned, CodecError> {
    build_restricted_interest(
        interest_id,
        kinds,
        current,
        future,
        keyexpr_mapping_id,
        keyexpr_suffix,
    )
}

/// R279 — build an `Interest(Final)` network-message (C=0, F=0) that
/// terminates a previously emitted Interest. Mirrors zenoh-pico's
/// `_z_make_interest_final` at
/// `vendor/zenoh-pico/src/protocol/definitions/interest.c:27` and the
/// encoder-side path through `_z_n_interest_encode(.., is_final=true)`
/// at `vendor/zenoh-pico/src/protocol/codec/network.c:452-486` (the
/// `is_final` branch skips the inner body emit per interest.c:43-46).
///
/// Wire shape: `[N_MID_INTEREST (0x19), VLE(interest_id)]` — exactly
/// two bytes for `interest_id <= 0xFF`. No inner body (the
/// `_Z_INTEREST_NOT_FINAL_MASK` gate at interest.h:35 — C||F — is
/// clear), no extensions.
pub fn build_interest_final(interest_id: u64) -> InterestOwned {
    InterestOwned {
        header: wire_const::N_MID_INTEREST,
        interest_id,
        body: None,
        extensions: None,
    }
}

// The interest coverage tests assert against zenoh-pico DECLARE-context
// wire bytes, so they gate on `codec-declare` even though the builders
// themselves are codec-feature-agnostic.
#[cfg(all(test, feature = "codec-declare"))]
mod tests {
    use super::*;
    use alloc::vec;
    use wz_codecs_test_support::TestWire;

    /// R311y801 — the two bytes a liveliness-subscriber Interest now ends with:
    /// the `ext_qos` entry header (`id 0x01 | ENC_Z64`, terminal) and
    /// `QoSType::DECLARE` (Control | nodrop). Named once so the four vectors
    /// below say WHAT they gained rather than repeating a pair of magic bytes,
    /// and so a change to either value has to move this line.
    const QOS_EXT_TAIL: [u8; 2] = [
        crate::declare_ext_qos::QOS_EXT_HEADER,
        crate::declare_ext_qos::QOS_DECLARE.raw,
    ];

    /// R279 — `build_interest_liveliness_subscriber` produces an
    /// `Interest` envelope with the inner `InterestBody` carrier
    /// emitting `flags = KEYEXPRS | TOKENS | RESTRICTED | FUTURE
    /// [| CURRENT]` per zenoh-pico's
    /// `_z_register_liveliness_subscriber`
    /// (`vendor/zenoh-pico/src/net/liveliness.c:169-198` via
    /// `vendor/zenoh-pico/src/session/interest.c:204-209`). Four
    /// vectors lock the four semantic cases (literal-future,
    /// literal-current, alias, composite) so a future codegen
    /// regression on either the outer C/F gate, the body N/M
    /// derivation, or the wireexpr arm choice fires immediately.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn build_interest_liveliness_subscriber_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — literal keyexpr, history=false (FUTURE only).
        //   outer header = MID(0x19) | F(0x40) = 0x59
        //   VLE(interest_id=7) = 0x07
        //   body header = KE(0x01) | TO(0x08) | R(0x10) | N(0x20) | M(0x40) = 0x79
        //   wireexpr.id VLE(0) = 0x00
        //   suffix_len VLE(14) = 0x0E
        //   suffix bytes = "liveliness/dev"
        let future_only = build_interest_liveliness_subscriber(
            7,
            /*history=*/ false,
            /*mapping_id=*/ 0,
            Some("liveliness/dev"),
        )
        .unwrap();
        // R311y801 — all four vectors gained the outer `Z` bit and a TRAILING
        // two-byte `ext_qos` entry. Trailing, not leading: the Interest codec
        // writes its extensions AFTER the id / options / wire_expr
        // (`zenoh-codec/src/network/interest.rs:65-88`), the mirror image of
        // the Declare, where they precede the body.
        let future_only_wire = future_only.wire();
        let mut future_only_expected = vec![
            0xD9u8, // outer: MID | F | Z
            0x07,   // VLE(interest_id=7)
            0x79,   // body: KE | TO | R | N | M
            0x00,   // wireexpr.id VLE(0) literal sentinel
            0x0E,   // suffix_len VLE(14)
        ];
        future_only_expected.extend_from_slice(b"liveliness/dev");
        future_only_expected.extend_from_slice(&QOS_EXT_TAIL);
        assert_eq!(
            future_only_wire, future_only_expected,
            "future-only literal Interest wire bytes must match zenoh-pico reference",
        );

        // Case 2 — literal keyexpr, history=true (CURRENT + FUTURE).
        //   outer header = MID | C(0x20) | F(0x40) = 0x79
        //   VLE(3) = 0x03
        //   body header = KE | TO | R | N | M = 0x79
        //   wireexpr.id VLE(0) | suffix_len VLE(1) | "a"
        let current_future = build_interest_liveliness_subscriber(
            3,
            /*history=*/ true,
            /*mapping_id=*/ 0,
            Some("a"),
        )
        .unwrap();
        let current_future_wire = current_future.wire();
        let mut current_future_expected = vec![
            0xF9u8, // outer: MID | C | F | Z
            0x03,   // VLE(interest_id=3)
            0x79,   // body: KE | TO | R | N | M
            0x00,   // wireexpr.id VLE(0)
            0x01,   // suffix_len VLE(1)
        ];
        current_future_expected.extend_from_slice(b"a");
        current_future_expected.extend_from_slice(&QOS_EXT_TAIL);
        assert_eq!(
            current_future_wire, current_future_expected,
            "current+future literal Interest wire bytes must match zenoh-pico reference",
        );

        // Case 3 — pure alias (no suffix).
        //   outer header = MID | F = 0x59
        //   VLE(5) = 0x05
        //   body header = KE | TO | R | M (no N) = 0x59
        //   wireexpr.id VLE(11) = 0x0B  (no suffix bytes)
        let alias = build_interest_liveliness_subscriber(
            5, /*history=*/ false, /*mapping_id=*/ 11, None,
        )
        .unwrap();
        let alias_wire = alias.wire();
        assert_eq!(
            alias_wire,
            vec![0xD9u8, 0x05, 0x59, 0x0B, QOS_EXT_TAIL[0], QOS_EXT_TAIL[1]],
            "alias Interest wire bytes must match zenoh-pico reference",
        );

        // Case 4 — composite (alias + tail).
        //   body header = KE | TO | R | N | M = 0x79
        //   wireexpr.id VLE(11) | suffix_len VLE(5) | "/tail"
        let composite = build_interest_liveliness_subscriber(
            5,
            /*history=*/ false,
            /*mapping_id=*/ 11,
            Some("/tail"),
        )
        .unwrap();
        let composite_wire = composite.wire();
        let mut composite_expected = vec![0xD9u8, 0x05, 0x79, 0x0B, 0x05];
        composite_expected.extend_from_slice(b"/tail");
        composite_expected.extend_from_slice(&QOS_EXT_TAIL);
        assert_eq!(
            composite_wire, composite_expected,
            "composite alias Interest wire bytes must match zenoh-pico reference",
        );

        // Structural assertions on Case 1 — verify the InterestBody
        // is present and carries the expected wireexpr arm.
        match &future_only.body {
            Some(body) => {
                assert_eq!(
                    body.header, 0x79,
                    "InterestBody.header must carry KE | TO | R | N | M",
                );
                match &body.keyexpr {
                    Some(WireexprOwned {
                        body: WireexprOwnedVariant::WireexprLocal(w),
                    }) => {
                        assert_eq!(w.id, 0, "literal-keyexpr → wireexpr.id=0 sentinel");
                        assert_eq!(
                            w.suffix.as_deref(),
                            Some("liveliness/dev"),
                            "literal suffix must round-trip",
                        );
                    }
                    _ => panic!(
                        "build_interest_liveliness_subscriber must wrap the keyexpr in WireexprLocal",
                    ),
                }
            }
            None => panic!(
                "future-only/current+future Interest must carry an InterestBody (C||F is set)",
            ),
        }
    }

    /// liveliness-get — `build_interest_liveliness_get` produces a
    /// one-shot CURRENT snapshot `Interest`: outer C set, F CLEAR
    /// (`MID | C = 0x39`), distinguishing it from the subscriber's
    /// always-FUTURE Interest. The inner body carries the same
    /// `KE | TO | R | N | M` flags (shared SSOT via
    /// `build_liveliness_token_interest`). Mirrors zenoh-pico's
    /// `_z_liveliness_query` flags
    /// (`KEYEXPRS | TOKENS | RESTRICTED | CURRENT`,
    /// `vendor/zenoh-pico/src/net/liveliness.c:350-352`).
    #[cfg(feature = "codec-declare")]
    #[test]
    fn build_interest_liveliness_get_emits_current_only_wire_bytes() {
        // Literal keyexpr snapshot get.
        //   outer header = MID(0x19) | C(0x20) = 0x39   (NO FUTURE)
        //   VLE(interest_id=7) = 0x07
        //   body header = KE | TO | R | N | M = 0x79
        //   wireexpr.id VLE(0) | suffix_len VLE(14) | "liveliness/dev"
        let get =
            build_interest_liveliness_get(7, /*mapping_id=*/ 0, Some("liveliness/dev")).unwrap();
        let get_wire = get.wire();
        let mut expected = vec![
            0x39u8, // outer: MID | C  (F clear — one-shot snapshot)
            0x07,   // VLE(interest_id=7)
            0x79,   // body: KE | TO | R | N | M
            0x00,   // wireexpr.id VLE(0) literal sentinel
            0x0E,   // suffix_len VLE(14)
        ];
        expected.extend_from_slice(b"liveliness/dev");
        assert_eq!(
            get_wire, expected,
            "liveliness-get Interest must set CURRENT and clear FUTURE",
        );
        assert_eq!(
            get.header & 0x40,
            0,
            "FUTURE (F) bit MUST be clear — a get is one-shot, not an ongoing subscription",
        );
        assert_eq!(get.header & 0x20, 0x20, "CURRENT (C) bit must be set");
    }

    /// R279 — `build_interest_final` produces an `Interest` envelope
    /// in the C=0 F=0 Z=0 form. Mirror of zenoh-pico's
    /// `_z_make_interest_final` at
    /// `vendor/zenoh-pico/src/protocol/definitions/interest.c:27`. The
    /// wire reduces to `[N_MID_INTEREST, VLE(interest_id)]` — no inner
    /// body (the `_Z_INTEREST_NOT_FINAL_MASK` gate at interest.h:35 is
    /// clear so the body embed is suppressed) and no extensions.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn build_interest_final_emits_two_byte_marker() {
        let small = build_interest_final(7);
        let small_wire = small.wire();
        assert_eq!(
            small_wire,
            vec![wire_const::N_MID_INTEREST, 0x07],
            "InterestFinal small-id wire bytes must equal [N_MID_INTEREST, VLE(id)]",
        );
        assert!(
            small.body.is_none(),
            "InterestFinal must carry no inner body — C||F is clear",
        );
        assert!(
            small.extensions.is_none(),
            "InterestFinal must carry no extensions — Z stays clear in the wz emit path",
        );

        let large = build_interest_final(200);
        assert_eq!(
            large.wire(),
            vec![wire_const::N_MID_INTEREST, 0xC8, 0x01],
            "InterestFinal multi-byte VLE id wire bytes must match zenoh-pico reference",
        );
    }

    /// R311y771 THE DISCRIMINATOR for the subscriber plane. The one byte that
    /// decides whether a zenoh router will ever send this face a subscriber
    /// declaration is the body header's `S` bit, and it must be `S` — not
    /// `T`, which is what every wz Interest carried before this round.
    ///
    /// Expected body header = KE(0x01) | SU(0x02) | R(0x10) | N(0x20) |
    /// M(0x40) = `0x73`. Held against the TOKEN form's `0x79` in the same
    /// test so the two are a DIFFERENCE and not merely two constants: if the
    /// kind bit were dropped from the SSOT both would read `0x71` and each
    /// assertion alone would still look meaningful.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn a_subscribers_interest_sets_the_subscriber_bit_where_the_token_form_sets_the_token_bit() {
        let subs = build_interest_subscribers(
            7,
            /*current=*/ true,
            /*future=*/ true,
            /*mapping_id=*/ 0,
            Some("demo/**"),
        )
        .unwrap();
        let mut expected = vec![
            0x79u8, // outer: MID(0x19) | C(0x20) | F(0x40) -- CurrentFuture
            0x07,   // VLE(interest_id=7)
            0x73,   // body: KE | SU | R | N | M   <- SU(0x02), NOT TO(0x08)
            0x00,   // wireexpr.id VLE(0) literal sentinel
            0x07,   // suffix_len VLE(7)
        ];
        expected.extend_from_slice(b"demo/**");
        assert_eq!(
            subs.wire(),
            expected,
            "a SUBSCRIBERS Interest must carry S=1 in the body header",
        );

        // The same call shape on the token path differs in EXACTLY that byte.
        let tokens = build_interest_liveliness_subscriber(
            7,
            /*history=*/ true,
            /*mapping_id=*/ 0,
            Some("demo/**"),
        )
        .unwrap();
        let (subs_body, tok_body) = (
            subs.body.as_ref().expect("C||F set -> body present").header,
            tokens
                .body
                .as_ref()
                .expect("C||F set -> body present")
                .header,
        );
        assert_eq!(
            subs_body ^ tok_body,
            InterestKinds::SUBSCRIBERS.bits() | InterestKinds::TOKENS.bits(),
            "the two forms must differ in the KIND bits and nothing else -- a \
             difference anywhere else means the shared header SSOT drifted",
        );
        // R311y801 — compared MODULO the ext-chain `Z` bit, which the outer
        // header now also carries: the liveliness-token form stamps `ext_qos`
        // (upstream `api/session.rs:1812`) and the subscribers form does not
        // (`:1376`), so the raw bytes legitimately differ there. The claim this
        // line makes is about the MODE bits, and it is narrowed to say so
        // rather than widened to accept the difference.
        assert_eq!(
            subs.header & !crate::ext_nodeid::MESSAGE_FLAG_Z,
            tokens.header & !crate::ext_nodeid::MESSAGE_FLAG_Z,
            "the outer C/F header is a mode, not a kind, and must be identical",
        );
        assert_eq!(
            (subs.header ^ tokens.header) & crate::ext_nodeid::MESSAGE_FLAG_Z,
            crate::ext_nodeid::MESSAGE_FLAG_Z,
            "and the Z bit is exactly where they DO differ -- the token form \
             carries ext_qos, the subscribers form does not",
        );
    }

    /// The queryable plane, and the ANTI-VACUITY pair for the test above: `Q`
    /// is a THIRD distinct bit, so a builder that ignored its `kinds`
    /// argument and hardcoded one value cannot satisfy both tests.
    ///
    /// Expected body header = KE | QU(0x04) | R | N | M = `0x75`.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn a_queryables_interest_sets_only_the_queryable_bit() {
        let qabl = build_interest_queryables(
            9,
            /*current=*/ true,
            /*future=*/ true,
            /*mapping_id=*/ 0,
            Some("demo/**"),
        )
        .unwrap();
        let body = qabl.body.as_ref().expect("C||F set -> body present").header;
        assert_eq!(body, 0x75, "body must be KE | QU | R | N | M");
        assert_eq!(
            body & InterestKinds::SUBSCRIBERS.bits(),
            0,
            "S must be CLEAR -- a queryable interest that also asked for \
             subscribers would silently widen what the router forwards",
        );
        assert_eq!(body & InterestKinds::TOKENS.bits(), 0, "T must be CLEAR",);
    }

    /// The three kind constants are the THREE WIRE BITS the two upstreams
    /// agree on, pinned as a SET rather than one at a time: zenoh's
    /// `InterestOptions::SUBSCRIBERS` / `QUERYABLES` / `TOKENS`
    /// (`zenoh-protocol/src/network/interest.rs:249-251` = `1<<1`, `1<<2`,
    /// `1<<3`) and wz's own generated `InterestBodyOwned::su` / `qu` / `to`
    /// accessors, which is where a codegen change would land.
    ///
    /// Pinned through the GENERATED `su()` / `qu()` / `to()` READERS, not
    /// through the literals: a test that only compared `0x02 == 0x02` would
    /// pass even if the codec moved the bit, because both sides of that
    /// comparison are this file's. Here the classification comes from the
    /// codec and the bytes come from the builder, so a disagreement between
    /// them fails.
    ///
    /// All THREE readers are asserted on all THREE builders — the full
    /// 3x3 — because a one-sided check ("the subscriber form reads `su`")
    /// is satisfied by a builder that sets every bit.
    #[cfg(feature = "codec-declare")]
    fn kind_readers(msg: &InterestOwned) -> (bool, bool, bool) {
        let body = msg.body.as_ref().expect("C||F set -> body present");
        (body.su(), body.qu(), body.to())
    }

    #[cfg(feature = "codec-declare")]
    #[test]
    fn the_kind_constants_are_the_bits_the_generated_codec_reads() {
        assert_eq!(
            kind_readers(&build_interest_subscribers(1, true, true, 0, Some("a")).unwrap()),
            (true, false, false),
            "the SUBSCRIBERS builder must read as su-only through the codec",
        );
        assert_eq!(
            kind_readers(&build_interest_queryables(1, true, true, 0, Some("a")).unwrap()),
            (false, true, false),
            "the QUERYABLES builder must read as qu-only through the codec",
        );
        assert_eq!(
            kind_readers(&build_interest_liveliness_get(1, 0, Some("a")).unwrap()),
            (false, false, true),
            "the token builder must still read as to-only -- this round must \
             not have moved the kind it already had",
        );
        assert_eq!(
            kind_readers(
                &build_interest_kinds(
                    1,
                    InterestKinds::SUBSCRIBERS | InterestKinds::QUERYABLES,
                    true,
                    true,
                    0,
                    Some("a"),
                )
                .unwrap()
            ),
            (true, true, false),
            "a union must read as BOTH through the codec, not as one of them",
        );
    }

    /// A UNION is one Interest with two kind bits, not two Interests. Pinned
    /// because the union is the shape a caller wanting both planes should
    /// reach for (one id, one Final) and because `BitOr` is the only way to
    /// reach a multi-kind value at all.
    ///
    /// Expected body header = KE | SU | QU | R | N | M = `0x77`.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn a_union_of_kinds_rides_one_interest() {
        let both = build_interest_kinds(
            4,
            InterestKinds::SUBSCRIBERS | InterestKinds::QUERYABLES,
            /*current=*/ true,
            /*future=*/ true,
            /*mapping_id=*/ 0,
            Some("demo/**"),
        )
        .unwrap();
        let body = both.body.as_ref().expect("C||F set -> body present").header;
        assert_eq!(body, 0x77, "body must be KE | SU | QU | R | N | M");
        assert_eq!(
            body & InterestKinds::TOKENS.bits(),
            0,
            "a union that was never asked for tokens must not carry T",
        );
    }

    /// The MODE axis is independent of the kind axis, and all three non-Final
    /// modes are reachable on the new builders. Without this the C/F pair
    /// would be pinned only at the value both liveliness callers happen to
    /// use, and a builder that hardcoded `CurrentFuture` would pass every
    /// other test in this module.
    ///
    /// The body header is asserted CONSTANT across the three so the mode
    /// cannot be leaking into the kind byte.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn every_non_final_mode_is_reachable_without_touching_the_kind_byte() {
        let cases = [
            (true, true, 0x79u8),  // CurrentFuture: MID | C | F
            (true, false, 0x39u8), // Current:       MID | C
            (false, true, 0x59u8), // Future:        MID | F
        ];
        for (current, future, outer) in cases {
            let msg = build_interest_subscribers(1, current, future, 0, Some("a")).unwrap();
            assert_eq!(
                msg.header, outer,
                "outer header for (current={current}, future={future})",
            );
            assert_eq!(
                msg.body.as_ref().expect("C||F set -> body present").header,
                0x73,
                "the kind byte must not move with the mode",
            );
        }
    }

    /// N and M are DERIVED, never supplied — the alias / composite / literal
    /// axis behaves on the new builders exactly as it does on the token ones.
    /// This is the regression guard that the generalisation did not lose the
    /// wireexpr derivation while moving the kind bits out.
    #[cfg(feature = "codec-declare")]
    #[test]
    fn the_wireexpr_derivation_survives_the_kind_generalisation() {
        // Pure alias: no suffix -> N clear. body = KE | SU | R | M = 0x53.
        let alias = build_interest_subscribers(5, false, true, /*mapping_id=*/ 11, None).unwrap();
        assert_eq!(
            alias.wire(),
            vec![0x59u8, 0x05, 0x53, 0x0B],
            "alias form must clear N and carry the mapping id verbatim",
        );

        // Composite: alias + tail -> N set. body = KE | SU | R | N | M = 0x73.
        let composite =
            build_interest_subscribers(5, false, true, /*mapping_id=*/ 11, Some("/tail")).unwrap();
        let mut expected = vec![0x59u8, 0x05, 0x73, 0x0B, 0x05];
        expected.extend_from_slice(b"/tail");
        assert_eq!(composite.wire(), expected);
    }
}
