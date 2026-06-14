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
    build_liveliness_token_interest(
        interest_id,
        /*current=*/ history,
        /*future=*/ true,
        keyexpr_mapping_id,
        keyexpr_suffix,
    )
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

/// SSOT for the liveliness-token `Interest` body-header flag composition
/// (`KE | TO | R | N | M`) shared by the subscriber + get paths. The
/// only difference between the two is the outer `Interest.header` C
/// (CURRENT) / F (FUTURE) bits, surfaced here as the `current` / `future`
/// params. Keeping one constructor avoids the body-header bitset drifting
/// between the two callers.
///
/// N/M bit positions on `InterestBody.header` (bits 5 and 6) coincide
/// with the C/F positions on the outer `Interest.header`; that is
/// intentional and matches zenoh-pico's `_Z_INTEREST_FLAG_COPY_MASK`
/// reorder (the two `header` bytes are distinct wire bytes, so no
/// collision). The inner body sets KE (carries a keyexpr), TO (wants
/// token records), and R (restricted to the attached keyexpr); SU/QU/AG
/// stay clear (the liveliness-token path does not interest on peer
/// subscribers / queryables / aggregated keyexprs).
fn build_liveliness_token_interest(
    interest_id: u64,
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
    let to_flag = 0x08u8;
    let r_flag = 0x10u8;
    let n_flag = if keyexpr_suffix.is_some() {
        0x20u8
    } else {
        0x00u8
    };
    let m_flag = 0x40u8; // Local arm (M=1)
    let body_header = ke_flag | to_flag | r_flag | n_flag | m_flag;

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
        let future_only_wire = future_only.wire();
        let mut future_only_expected = vec![
            0x59u8, // outer: MID | F
            0x07,   // VLE(interest_id=7)
            0x79,   // body: KE | TO | R | N | M
            0x00,   // wireexpr.id VLE(0) literal sentinel
            0x0E,   // suffix_len VLE(14)
        ];
        future_only_expected.extend_from_slice(b"liveliness/dev");
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
            0x79u8, // outer: MID | C | F
            0x03,   // VLE(interest_id=3)
            0x79,   // body: KE | TO | R | N | M
            0x00,   // wireexpr.id VLE(0)
            0x01,   // suffix_len VLE(1)
        ];
        current_future_expected.extend_from_slice(b"a");
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
            vec![0x59u8, 0x05, 0x59, 0x0B],
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
        let mut composite_expected = vec![0x59u8, 0x05, 0x79, 0x0B, 0x05];
        composite_expected.extend_from_slice(b"/tail");
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
}
