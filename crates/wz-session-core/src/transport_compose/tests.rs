// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::*;
use crate::frame_encode::{begin_frame, frame_flags};
use crate::handshake_encode::{encode_close, encode_init, encode_open};
use crate::session_init_params::{SessionInitParams, TxQueueConf};
use alloc::vec;
use wz_codecs::whatami::WhatAmI;

fn params(zid: &[u8], batch_size: u16, lease_ms: u64) -> SessionInitParams {
    SessionInitParams {
        version: 0x05,
        whatami: WhatAmI::Peer,
        zid: zid.to_vec(),
        seq_num_res: 2,
        req_id_res: 1,
        batch_size,
        lease_ms,
        initial_sn: 0x1234,
        cookie: vec![0xC0, 0xC1, 0xC2],
        tx_queue: TxQueueConf::default(),
        cookie_signing_key: crate::signing_key::SigningKey::new(vec![0xAB; 32])
            .expect("32-byte test key"),
    }
}

/// The bytes the session TX path writes for the same fields are the bytes this
/// module writes: INIT, both roles, every zid length, with and without an
/// extension chain. The production encoder is the oracle here and not an
/// independent one -- the independent oracle is `wz-session-wire-fixtures`,
/// which the `wz-capture` tests compare against -- and what this holds is that
/// the two composers of one wire do not drift.
#[test]
fn compose_init_matches_the_session_encoder() {
    for zid_len in 1..=16usize {
        let zid: Vec<u8> = (0..zid_len as u8).map(|i| 0xA0 + i).collect();
        let p = params(&zid, 0x4000, 10_000);
        for ack in [false, true] {
            let chain = [ExtSpec {
                id: 7,
                mandatory: false,
                body: ExtBody::Z64(1),
            }];
            let session_chain = [ExtEntryOwned {
                header: 7 | (1 << 5),
                body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value: 1 }),
            }];
            for with_chain in [false, true] {
                let want =
                    encode_init(&p, ack, if with_chain { &session_chain } else { &[] }, None)
                        .expect("encodes");
                let spec = InitSpec {
                    role: if ack {
                        InitRole::Ack { cookie: &p.cookie }
                    } else {
                        InitRole::Syn
                    },
                    version: p.version,
                    whatami: 1,
                    zid: &zid,
                    size: Some(SizeParams {
                        frame_sn_code: p.seq_num_res,
                        request_id_code: p.req_id_res,
                        batch_size: p.batch_size,
                    }),
                    extensions: if with_chain { &chain } else { &[] },
                };
                assert_eq!(
                    compose_init(&spec).expect("composes"),
                    want,
                    "zid_len {zid_len} ack {ack} chain {with_chain}"
                );
            }
        }
    }
}

/// Where the two part is the point of this module: a batch size of zero is the
/// session's "unset" sentinel and is written as the default, and here it is the
/// value the caller said.
#[test]
fn compose_init_writes_a_zero_batch_size_the_session_encoder_replaces() {
    let zid = [0xB0, 0xB1, 0xB2, 0xB3];
    let p = params(&zid, 0, 10_000);
    let session = encode_init(&p, false, &[], None).expect("encodes");
    let spec = InitSpec {
        role: InitRole::Syn,
        version: 5,
        whatami: 1,
        zid: &zid,
        size: Some(SizeParams {
            frame_sn_code: p.seq_num_res,
            request_id_code: p.req_id_res,
            batch_size: 0,
        }),
        extensions: &[],
    };
    let composed = compose_init(&spec).expect("composes");
    // [header][version][cbyte][zid x4][sn_res][batch lo][batch hi]
    assert_eq!(&composed[8..10], &[0, 0], "the caller's zero is written");
    assert_ne!(
        &session[8..10],
        &[0, 0],
        "the session encoder substitutes its default for the sentinel"
    );
}

#[test]
fn compose_open_matches_the_session_encoder() {
    for lease_ms in [0u64, 1, 999, 1000, 1500, 10_000, 123_456_000] {
        let p = params(&[1, 2, 3, 4], 0x1000, lease_ms);
        for ack in [false, true] {
            let want = encode_open(&p, ack, None, &[]).expect("encodes");
            let spec = OpenSpec {
                role: if ack {
                    OpenRole::Ack
                } else {
                    OpenRole::Syn { cookie: &p.cookie }
                },
                lease_ms,
                lease_unit: None,
                initial_sn: p.initial_sn,
                extensions: &[],
            };
            assert_eq!(
                compose_open(&spec).expect("composes"),
                want,
                "{lease_ms} {ack}"
            );
        }
    }
}

/// A unit named by the caller is written as named; the derived one is the
/// session's. Ten seconds is the case that shows it: derived it travels as
/// `10` with `T` set, asked for in milliseconds it travels as `10000` with `T`
/// clear, and asked for in seconds when it is not whole it is refused.
#[test]
fn a_named_lease_unit_is_written_as_named() {
    let open = |lease_ms, lease_unit| {
        compose_open(&OpenSpec {
            role: OpenRole::Ack,
            lease_ms,
            lease_unit,
            initial_sn: 0,
            extensions: &[],
        })
    };
    let derived = open(10_000, None).expect("composes");
    assert_eq!(derived, [0x62, 10, 0]);
    assert_eq!(
        open(10_000, Some(LeaseUnit::Seconds)).expect("composes"),
        derived
    );
    // 10000 as a VLE is 0x90 0x4E.
    assert_eq!(
        open(10_000, Some(LeaseUnit::Milliseconds)).expect("composes"),
        [0x22, 0x90, 0x4E, 0]
    );
    assert_eq!(
        open(1_500, Some(LeaseUnit::Seconds)),
        Err(ComposeError::LeaseNotWholeSeconds { lease_ms: 1_500 })
    );
}

#[test]
fn compose_close_matches_the_session_encoder() {
    for reason in [0u8, 1, 7, 8, 255] {
        for session in [false, true] {
            assert_eq!(
                compose_close(reason, session),
                encode_close(reason, session)
            );
        }
    }
}

#[test]
fn compose_keep_alive_is_the_one_header_byte() {
    assert_eq!(compose_keep_alive(), [wire_const::T_MID_KEEP_ALIVE]);
}

/// Below the widest ring the codec and the TX path's hand-rolled VLE write the
/// same bytes, for every width, with and without the QoS extension.
#[test]
fn build_frame_wire_matches_begin_frame_below_the_widest_ring() {
    let payload = [0xDE, 0xAD, 0xBE, 0xEF];
    for width in 1..=VLE_MAX_WIDTH {
        let (min, max) = vle_range(width).expect("a width");
        // The ring never reaches 2^63 (`sn::mask_from_res(3)`).
        let top = max.min(crate::sn::mask_from_res(3));
        for sn in [min, top] {
            for reliable in [false, true] {
                for priority in [None, Some(Priority::DataHigh)] {
                    let mut want = Vec::new();
                    begin_frame(&mut want, sn, frame_flags(reliable), priority)
                        .expect("a Vec grows, so its sink is infallible");
                    want.extend_from_slice(&payload);
                    assert_eq!(
                        build_frame_wire(sn, &payload, reliable, priority),
                        want,
                        "sn {sn} reliable {reliable} priority {priority:?}"
                    );
                }
            }
        }
    }
}

/// And above it they part: the codec ends a VLE at nine bytes with the last
/// carrying eight bits, the hand-rolled loop writes a tenth. The session cannot
/// reach the value; a caller that sets `sn` can.
#[test]
fn build_frame_wire_writes_the_codecs_nine_byte_vle_for_the_top_bucket() {
    let sn = 1u64 << 63;
    let built = build_frame_wire(sn, &[], true, None);
    assert_eq!(built.len(), 1 + 9, "header and a nine-byte VLE");
    let mut tx = Vec::new();
    begin_frame(&mut tx, sn, wire_const::FLAG_T_FRAME_R, None)
        .expect("a Vec grows, so its sink is infallible");
    assert_eq!(tx.len(), 1 + 10, "the TX path's loop writes a tenth byte");
    // The reader reads what the codec wrote.
    let mut cursor = sce_forge_runtime::codec::SceCursor::new(&built[1..]);
    assert_eq!(cursor.read_vle_u64().expect("reads"), sn);
    assert_eq!(cursor.remaining(), 0);
}

#[test]
fn vle_ranges_are_the_codecs_buckets() {
    let mut previous_max: Option<u64> = None;
    for width in 1..=VLE_MAX_WIDTH {
        let (min, max) = vle_range(width).expect("a width");
        assert_eq!(vle_width(min), width, "min of {width}");
        assert_eq!(vle_width(max), width, "max of {width}");
        match previous_max {
            None => assert_eq!(min, 0),
            Some(p) => assert_eq!(min, p + 1, "buckets tile"),
        }
        if width < VLE_MAX_WIDTH {
            assert_eq!(vle_width(max + 1), width + 1, "one past {width}");
        }
        previous_max = Some(max);
    }
    assert_eq!(previous_max, Some(u64::MAX));
    assert_eq!(vle_range(1), Some((0, 127)));
    assert_eq!(vle_range(2), Some((128, 16_383)));
    assert_eq!(vle_range(9), Some((1u64 << 56, u64::MAX)));
    assert_eq!(vle_range(0), None);
    assert_eq!(vle_range(10), None);
}

#[test]
fn the_ring_of_each_resolution_fills_its_widest_vle() {
    // 8 / 16 / 32 / 64 bit resolution: 1 / 2 / 4 / 9 bytes at the ring's top.
    let widths: Vec<usize> = (0..4u8).map(|c| vle_width(sn_ring_max(c))).collect();
    assert_eq!(widths, [1, 2, 4, 9]);
}

#[test]
fn frame_unit_writes_the_prefix_of_each_framing() {
    let body = [1u8, 2, 3];
    assert_eq!(frame_unit(Framing::Datagram, &body).unwrap(), body);
    assert_eq!(
        frame_unit(Framing::TcpStream, &body).unwrap(),
        [3, 0, 1, 2, 3]
    );
    assert_eq!(
        frame_unit(Framing::LowLatencyStream, &body).unwrap(),
        [3, 0, 0, 0, 1, 2, 3]
    );
    let big = vec![0u8; 65_536];
    assert_eq!(
        frame_unit(Framing::TcpStream, &big),
        Err(ComposeError::UnitTooLong {
            len: 65_536,
            max: 65_535
        })
    );
    assert_eq!(
        frame_unit(Framing::LowLatencyStream, &big).unwrap().len(),
        65_540
    );
    assert_eq!(frame_unit(Framing::Datagram, &big).unwrap().len(), 65_536);
}

#[test]
fn every_value_that_does_not_fit_its_field_is_refused() {
    let init = |zid: &[u8], whatami: u8, size: Option<SizeParams>| {
        compose_init(&InitSpec {
            role: InitRole::Syn,
            version: 5,
            whatami,
            zid,
            size,
            extensions: &[],
        })
    };
    assert_eq!(init(&[], 1, None), Err(ComposeError::ZidLength(0)));
    assert_eq!(init(&[0; 17], 1, None), Err(ComposeError::ZidLength(17)));
    assert!(init(&[0; 16], 1, None).is_ok());
    assert_eq!(init(&[1], 4, None), Err(ComposeError::WhatAmI(4)));
    assert!(init(&[1], 3, None).is_ok(), "the reserved code is writable");
    let size = |f, r| {
        Some(SizeParams {
            frame_sn_code: f,
            request_id_code: r,
            batch_size: 1,
        })
    };
    assert_eq!(
        init(&[1], 1, size(4, 0)),
        Err(ComposeError::ResolutionCode(4))
    );
    assert_eq!(
        init(&[1], 1, size(0, 9)),
        Err(ComposeError::ResolutionCode(9))
    );
    let too_many = [ExtSpec {
        id: 1,
        mandatory: false,
        body: ExtBody::Unit,
    }; MAX_EXT_CHAIN_DEPTH + 1];
    assert_eq!(
        compose_open(&OpenSpec {
            role: OpenRole::Ack,
            lease_ms: 0,
            lease_unit: None,
            initial_sn: 0,
            extensions: &too_many
        }),
        Err(ComposeError::ExtensionChain {
            entries: MAX_EXT_CHAIN_DEPTH + 1
        })
    );
    let bad_id = [ExtSpec {
        id: 16,
        mandatory: false,
        body: ExtBody::Unit,
    }];
    assert_eq!(
        compose_open(&OpenSpec {
            role: OpenRole::Ack,
            lease_ms: 0,
            lease_unit: None,
            initial_sn: 0,
            extensions: &bad_id
        }),
        Err(ComposeError::ExtensionId { index: 0, id: 16 })
    );
    assert_eq!(
        compose_frame(&FrameSpec {
            reliable: true,
            sn: 0,
            priority: Some(8),
            payload: &[]
        }),
        Err(ComposeError::Priority(8))
    );
}

#[test]
fn an_extension_header_follows_from_its_body_and_place() {
    let chain = [
        ExtSpec {
            id: 1,
            mandatory: true,
            body: ExtBody::Unit,
        },
        ExtSpec {
            id: 7,
            mandatory: false,
            body: ExtBody::Z64(300),
        },
        ExtSpec {
            id: 3,
            mandatory: false,
            body: ExtBody::ZBuf(&[0xAA, 0xBB]),
        },
    ];
    let wire = compose_open(&OpenSpec {
        role: OpenRole::Ack,
        lease_ms: 0,
        lease_unit: None,
        initial_sn: 0,
        extensions: &chain,
    })
    .expect("composes");
    // [hdr][lease][sn] then: unit M id 1 + Z; z64 id 7 + Z (300 = 0xAC 0x02);
    // zbuf id 3 (last): length 2 and the two bytes.
    assert_eq!(
        wire,
        [
            wire_const::FLAG_T_OPEN_A
                | wire_const::FLAG_T_OPEN_T
                | wire_const::FLAG_T_Z
                | wire_const::T_MID_OPEN,
            0,
            0,
            0x81 | 0x10,
            0x87 | 0x20,
            0xAC,
            0x02,
            0x43,
            0x02,
            0xAA,
            0xBB
        ]
    );
}
