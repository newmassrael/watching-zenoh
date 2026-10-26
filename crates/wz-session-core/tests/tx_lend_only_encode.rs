// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lend-only encoders write the bytes the heap encoders write
//! (fixed-memory step S4, ARCHITECTURE section 9.1).
//!
//! Under `tx-lend-only` a handshake message is encoded into a slot the link
//! lends, from the parameters where they lie and the codec's borrowed view of the
//! body, with its extension chain written straight after it and the accept cookie
//! minted into a stack array. None of that may change a byte on the wire, and the
//! wire is what a peer judges, so each encoder is held here against an ORACLE
//! WRITTEN IN THIS FILE from the codec's own `encode_to_vec` facade, the way the
//! heap encoders built a message before the `_into` forms existed: the header
//! byte, the body, and the chain with its continuation bit patched on every entry
//! but the last. A bug in the shared writer cannot also be in the oracle.
//!
//! A buffer too short for a message refuses it with `BufferOverflow` at every
//! length below the message's own, so a lent slot that does not hold a handshake
//! message is a refusal the sender can count, never a message cut short.
//!
//! Compiles empty without the lend-only profile and the three message codecs,
//! so no other leg of this crate's suite counts it.
#![cfg(all(
    feature = "tx-lend-only",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close"
))]

use sce_forge_runtime::codec::CodecError;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::init_body::InitBody;
use wz_codecs::open_body::OpenBody;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;
use wz_session_core::accept_cookie::{
    decode_accept_cookie, encode_accept_cookie, encode_accept_cookie_into, AcceptCookieState,
    AcceptCookieView, MultilinkAcceptState, ACCEPT_COOKIE_MAX_BYTES,
};
use wz_session_core::accept_state::NegotiatedExtensions;
use wz_session_core::handshake_encode::{
    encode_close, encode_close_into, encode_init, encode_init_into, encode_open, encode_open_into,
    InitCaps,
};
use wz_session_core::session_init_params::{
    cookie_bytes, zid_bytes, LinkRxConf, SessionInitParams, TxQueueConf,
};
use wz_session_core::signing_key::SigningKey;
use wz_session_core::tx_buf::{SliceTxBuf, TxBuf};

fn params(zid: &[u8], cookie: &[u8]) -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: zid_bytes(zid),
        seq_num_res: 2,
        req_id_res: 1,
        batch_size: 1472,
        lease_ms: 10_000,
        keep_alive: wz_session_core::session_init_params::KeepAliveConf::default(),
        initial_sn: 77,
        cookie: cookie_bytes(cookie),
        tx_queue: TxQueueConf::default(),
        link_rx: LinkRxConf::default(),
        cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect("key"),
    }
}

/// Three entries with different headers and bodies: the patch announcement (a
/// z64) and two units.
fn chain() -> Vec<ExtEntryOwned> {
    let unit = |header: u8| ExtEntryOwned {
        header,
        body: ExtEntryOwnedVariant::CodecZenohExtUnit(wz_codecs::ext_unit::ExtUnit {}),
    };
    vec![
        wz_session_core::extpatch::encode_patch_ext(),
        unit(0x05),
        unit(0x01),
    ]
}

/// The chain as the heap encoders built it: each entry's own encoding, the
/// continuation bit set on every entry but the last and clear on it.
fn oracle_chain(entries: &[ExtEntryOwned]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let mut bytes = entry.as_borrowed().encode_to_vec();
        if i + 1 == entries.len() {
            bytes[0] &= !0x80;
        } else {
            bytes[0] |= 0x80;
        }
        out.extend_from_slice(&bytes);
    }
    out
}

/// What an Init message is: the header, the body, the chain.
fn oracle_init(
    p: &SessionInitParams,
    caps: InitCaps,
    is_ack: bool,
    entries: &[ExtEntryOwned],
    cookie: Option<&[u8]>,
) -> Vec<u8> {
    let mut flags = wire_const::FLAG_T_INIT_S;
    if is_ack {
        flags |= wire_const::FLAG_T_INIT_A;
    }
    if !entries.is_empty() {
        flags |= wire_const::FLAG_T_Z;
    }
    let cookie = if is_ack { cookie } else { None };
    let body = InitBody {
        version: wire_const::PROTOCOL_VERSION,
        cbyte: p.whatami.to_wire() | (((p.zid.len() as u8 - 1) & 0x0F) << 4),
        zid: &p.zid,
        sn_res: Some((caps.seq_num_res & 0x03) | ((caps.req_id_res & 0x03) << 2)),
        batch_size: Some(caps.batch_size),
        cookie_len: cookie.map(|c| c.len() as u64),
        cookie,
    };
    let mut out = vec![flags | wire_const::T_MID_INIT];
    out.extend_from_slice(&body.encode_to_vec((flags >> 6) & 1, (flags >> 5) & 1));
    out.extend_from_slice(&oracle_chain(entries));
    out
}

/// What an Open message is: the header, the body, the chain.
fn oracle_open(
    p: &SessionInitParams,
    initial_sn: u64,
    is_ack: bool,
    cookie: Option<&[u8]>,
    entries: &[ExtEntryOwned],
) -> Vec<u8> {
    let (in_seconds, lease) = wz_session_core::lease::lease_to_wire(p.lease_ms);
    let mut flags = 0u8;
    if in_seconds {
        flags |= wire_const::FLAG_T_OPEN_T;
    }
    if is_ack {
        flags |= wire_const::FLAG_T_OPEN_A;
    }
    if !entries.is_empty() {
        flags |= wire_const::FLAG_T_Z;
    }
    let cookie: &[u8] = if is_ack {
        &[]
    } else {
        cookie.unwrap_or(&p.cookie)
    };
    let body = OpenBody {
        lease,
        initial_sn,
        cookie_len: (!is_ack).then_some(cookie.len() as u64),
        cookie: (!is_ack).then_some(cookie),
    };
    let mut out = vec![flags | wire_const::T_MID_OPEN];
    out.extend_from_slice(&body.encode_to_vec((flags >> 5) & 1));
    out.extend_from_slice(&oracle_chain(entries));
    out
}

/// A fixed buffer of `len` bytes and what writing `f` into it left: the bytes on
/// success, the refusal otherwise.
fn into_fixed(
    len: usize,
    f: impl FnOnce(&mut SliceTxBuf<'_>) -> Result<(), CodecError>,
) -> Result<Vec<u8>, CodecError> {
    let mut storage = vec![0u8; len];
    let mut buf = SliceTxBuf::new(&mut storage);
    f(&mut buf)?;
    Ok(buf.as_slice().to_vec())
}

/// Every buffer shorter than the message refuses it, and the one exactly its
/// length holds it.
fn assert_refuses_every_shorter_buffer(
    what: &str,
    expected: &[u8],
    write: impl Fn(&mut SliceTxBuf<'_>) -> Result<(), CodecError>,
) {
    assert_eq!(
        into_fixed(expected.len(), &write),
        Ok(expected.to_vec()),
        "{what}: a buffer exactly the message's length holds it"
    );
    for len in 0..expected.len() {
        assert_eq!(
            into_fixed(len, &write),
            Err(CodecError::BufferOverflow),
            "{what}: a {len}-byte buffer cannot hold a {}-byte message",
            expected.len()
        );
    }
}

#[test]
fn an_init_message_written_into_a_buffer_is_the_message_the_heap_encoder_builds() {
    let entries = chain();
    for (zid, cookie) in [
        (&[0xA1u8][..], &[][..]),
        (&[0xB2; 4][..], &[0x11; 16][..]),
        (&[0xC3; 16][..], &[0x22; 100][..]),
    ] {
        let p = params(zid, cookie);
        let caps = InitCaps::of(&p);
        for is_ack in [false, true] {
            for exts in [&entries[..], &entries[..1], &[][..]] {
                for override_cookie in [None, Some(&[0x33u8; 40][..])] {
                    let expected = oracle_init(
                        &p,
                        caps,
                        is_ack,
                        exts,
                        override_cookie.or(Some(p.cookie.as_slice())),
                    );
                    let what = format!(
                        "init zid {} bytes, ack {is_ack}, {} ext(s), override {}",
                        zid.len(),
                        exts.len(),
                        override_cookie.is_some()
                    );
                    assert_eq!(
                        encode_init(&p, is_ack, exts, override_cookie).expect("heap"),
                        expected,
                        "{what}: the heap encoder is the oracle"
                    );
                    assert_refuses_every_shorter_buffer(&what, &expected, |buf| {
                        encode_init_into(buf, &p, caps, is_ack, exts, override_cookie)
                    });
                }
            }
        }
    }
}

#[test]
fn an_ack_advertises_the_sizes_it_is_given_and_never_the_unset_sentinel() {
    let mut p = params(&[0xA1; 4], &[]);
    p.batch_size = 0;
    assert_eq!(
        InitCaps::of(&p).batch_size,
        65535,
        "the wire never carries the internal 0 = unset sentinel"
    );
    let capped = InitCaps {
        seq_num_res: 0,
        req_id_res: 3,
        batch_size: 512,
    };
    let expected = oracle_init(&p, capped, true, &[], Some(&[]));
    let written =
        into_fixed(64, |buf| encode_init_into(buf, &p, capped, true, &[], None)).expect("fits");
    assert_eq!(written, expected, "an InitAck capped to the peer's sizes");
}

#[test]
fn an_open_message_written_into_a_buffer_is_the_message_the_heap_encoder_builds() {
    let entries = chain();
    let echoed = [0x55u8; 50];
    for lease_ms in [10_000u64, 1_500] {
        let mut p = params(&[0xA1; 4], &[0x66; 8]);
        p.lease_ms = lease_ms;
        for is_ack in [false, true] {
            for exts in [&entries[..], &[][..]] {
                for cookie in [None, Some(&echoed[..])] {
                    let expected = oracle_open(&p, 1234, is_ack, cookie, exts);
                    let what = format!(
                        "open lease {lease_ms} ms, ack {is_ack}, {} ext(s), echo {}",
                        exts.len(),
                        cookie.is_some()
                    );
                    // The heap encoder reads the ring origin from the
                    // parameters, so it is given a copy that says 1234.
                    let mut heap = p.clone();
                    heap.initial_sn = 1234;
                    assert_eq!(
                        encode_open(&heap, is_ack, cookie, exts).expect("heap"),
                        expected,
                        "{what}: the heap encoder is the oracle"
                    );
                    assert_refuses_every_shorter_buffer(&what, &expected, |buf| {
                        encode_open_into(buf, &p, 1234, is_ack, cookie, exts)
                    });
                }
            }
        }
    }
}

#[test]
fn a_close_written_into_a_buffer_is_the_close_the_heap_encoder_builds() {
    for reason in [0u8, 1, 0x7f, 0xff] {
        for session in [false, true] {
            let expected = encode_close(reason, session);
            assert_eq!(expected.len(), 2, "a close is a header and a reason byte");
            assert_refuses_every_shorter_buffer(
                &format!("close reason {reason} session {session}"),
                &expected,
                |buf| encode_close_into(buf, reason, session),
            );
        }
    }
}

fn key() -> SigningKey {
    SigningKey::new(vec![9u8; 32]).expect("key")
}

fn cookie_state(zid_len: usize, multilink: Option<(u64, Vec<u8>)>) -> AcceptCookieState {
    AcceptCookieState {
        peer_zid: (1..=zid_len as u8).collect(),
        peer_whatami: 1,
        sn_res: 0x0A,
        batch_size: 1472,
        nonce: 0x0102_0304_0506_0708,
        negotiated: NegotiatedExtensions::default(),
        multilink: MultilinkAcceptState(multilink),
    }
}

fn view_of(state: &AcceptCookieState) -> AcceptCookieView<'_> {
    AcceptCookieView {
        peer_zid: &state.peer_zid,
        peer_whatami: state.peer_whatami,
        sn_res: state.sn_res,
        batch_size: state.batch_size,
        nonce: state.nonce,
        negotiated: state.negotiated,
        multilink: state.multilink.0.as_ref().map(|(c, k)| (*c, k.as_slice())),
    }
}

/// The cookie minted into a stack array is the cookie the owned form mints, for
/// every zid width the wire admits, and it verifies and decodes back to the state
/// that made it.
#[test]
fn a_cookie_minted_into_an_array_is_the_cookie_the_owned_form_mints() {
    let k = key();
    for zid_len in 1..=16usize {
        let state = cookie_state(zid_len, None);
        let owned = encode_accept_cookie(&k, &state).expect("owned");
        let mut array = [0u8; ACCEPT_COOKIE_MAX_BYTES];
        let minted = encode_accept_cookie_into(&k, &view_of(&state), &mut array)
            .expect("the widest cookie without a multilink key fits the array");
        assert_eq!(minted, owned.as_slice(), "zid {zid_len} bytes");
        assert_eq!(
            decode_accept_cookie(&k, minted).expect("verifies"),
            state,
            "zid {zid_len} bytes: what was minted decodes to what was asked"
        );
    }
}

/// The array is the width of the widest cookie without a multilink key, and the
/// generated `cookie` field caps at 128: the array must fit the field.
#[test]
fn the_cookie_array_fits_the_generated_field() {
    const {
        assert!(
            ACCEPT_COOKIE_MAX_BYTES <= 128,
            "the widest array cookie exceeds the 128 bytes the generated field caps at"
        )
    };
    let widest = cookie_state(16, None);
    let owned = encode_accept_cookie(&key(), &widest).expect("owned");
    assert_eq!(
        owned.len(),
        ACCEPT_COOKIE_MAX_BYTES,
        "the array constant is exactly the widest cookie without a key"
    );
}

/// A multilink key makes the cookie wider than the array on the widest zid: it is
/// refused (`None`, which the acceptor reads as "no cookie" and fails closed),
/// not truncated; a short one that does fit is the owned form's bytes.
#[test]
fn a_cookie_that_does_not_fit_the_array_is_refused_not_truncated() {
    let k = key();
    let wide = cookie_state(16, Some((7, vec![0xEE; 40])));
    let mut array = [0u8; ACCEPT_COOKIE_MAX_BYTES];
    assert!(
        encode_accept_cookie_into(&k, &view_of(&wide), &mut array).is_none(),
        "a 16-byte zid and a 40-byte key do not fit the widest-no-key array"
    );
    assert!(
        encode_accept_cookie(&k, &wide).is_some(),
        "the owned form takes it: the refusal is the array's, not the state's"
    );

    let narrow = cookie_state(1, Some((7, vec![0xEE; 4])));
    let owned = encode_accept_cookie(&k, &narrow).expect("owned");
    let mut array = [0u8; ACCEPT_COOKIE_MAX_BYTES];
    let minted =
        encode_accept_cookie_into(&k, &view_of(&narrow), &mut array).expect("a narrow one fits");
    assert_eq!(minted, owned.as_slice());
}

/// Nothing is minted for a zid the wire cannot carry, in either form.
#[test]
fn no_cookie_is_minted_for_a_zid_outside_one_to_sixteen() {
    let k = key();
    let mut array = [0u8; ACCEPT_COOKIE_MAX_BYTES];
    // A zid longer than sixteen bytes is not a value the fixed form can hold at
    // all (`session-slot` refuses it before a cookie is in question).
    let lens: &[usize] = if cfg!(feature = "session-slot") {
        &[0]
    } else {
        &[0, 17]
    };
    for &zid_len in lens {
        let state = AcceptCookieState {
            peer_zid: wz_session_core::session_init_params::session_bytes::<16>(&vec![1; zid_len])
                .expect("fits"),
            ..cookie_state(1, None)
        };
        assert!(
            encode_accept_cookie(&k, &state).is_none(),
            "owned, {zid_len}"
        );
        assert!(
            encode_accept_cookie_into(&k, &view_of(&state), &mut array).is_none(),
            "array, {zid_len}"
        );
    }
}
