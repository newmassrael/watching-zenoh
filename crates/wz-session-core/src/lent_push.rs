// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A literal-keyexpr `Put` as the codec's BORROWED `Push`, composed over the
//! caller's own `&str` and `&[u8]` with nothing built on a heap.
//!
//! [`crate::push_build::build_push_literal`] makes the codec's OWNED mirror of the
//! message (a copy of the keyexpr and a copy of the payload), which exists to be
//! encoded and dropped: the borrowed view is what owns `encode`
//! (`try_as_borrowed`), and a send that has the text and the bytes in hand needs
//! nothing in between. The unicast lend-only send has composed it this way since
//! fixed-memory step S4 (`send_push_literal_qos`); the multicast TX of a build with
//! no allocator (`multicast_tx::MulticastTxPut`) is the second caller, and
//! the composition is here so that the two cannot disagree about a byte.
//!
//! The bytes are `build_push_literal`'s: the header is the Push MID with the `N`
//! flag (the `M` flag derives from the `WireexprLocal` arm at encode time), the
//! keyexpr is `id == 0` with the suffix inline, there is no extension, and the body
//! is the bare Put header, no optional field, then the payload.

#[cfg(feature = "pubsub-qos")]
use sce_forge_runtime::heapless::Vec as HeaplessVec;
#[cfg(feature = "pubsub-qos")]
use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
#[cfg(feature = "pubsub-qos")]
use wz_codecs::ext_zint::ExtZint;
use wz_codecs::msg_put::MsgPut;
use wz_codecs::push::{Push, PushVariant};
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;

/// The `N` flag of the Push header: a keyexpr suffix rides inline.
const FLAG_PUSH_N: u8 = 0x20;

/// The `M` flag of the Push header: the id is in the sender's mapping.
const FLAG_PUSH_M: u8 = 0x40;

/// A Put's header with no timestamp, no encoding and no extension: the payload
/// follows its length.
const PUT_HEADER: u8 = 0x01;

/// The `Push` that carries `value` to the literal keyexpr `keyexpr_suffix`,
/// borrowing both for `'a`.
pub fn literal_put<'a>(keyexpr_suffix: &'a str, value: &'a [u8]) -> Push<'a> {
    Push {
        header: wz_codecs::wire_const::N_MID_PUSH | FLAG_PUSH_N,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(keyexpr_suffix.len() as u64),
                suffix: Some(keyexpr_suffix),
            }),
        },
        extensions: None,
        body: PushVariant::CodecZenohMsgPut(MsgPut {
            header: PUT_HEADER,
            payload_len: Some(value.len() as u64),
            payload: Some(value),
            ..MsgPut::default()
        }),
    }
}

/// [`literal_put`] carrying `qos` on the Push's outer extension chain, exactly where
/// [`crate::push_build::build_push_literal_with_meta`] puts it: one ext, id `0x01`, a
/// `ZINT` body, and the Push header's `Z` bit. The DEFAULT byte rides no extension, so a
/// plain publish stays wire-identical to the metadata-stripped baseline (pico's
/// `has_qos_ext = msg->_qos._val != _Z_N_QOS_DEFAULT._val`), and a build without
/// `pubsub-qos` carries none, as the owned builder does.
///
/// The chain is a fixed-capacity vector on the stack, so a Put with QoS is composed over the
/// caller's own text and bytes with nothing built on a heap; the owned builder costs three
/// allocations and a copy of each input per message, to be encoded once and dropped.
pub fn literal_put_with_qos<'a>(
    keyexpr_suffix: &'a str,
    value: &'a [u8],
    qos: crate::sample::QosLevel,
) -> Push<'a> {
    put_with_qos(0, Some(keyexpr_suffix), value, qos)
}

/// The same Put on a keyexpr the sender declared: `mapping_id`, then `suffix` when the key
/// is the declaration with something appended
/// ([`crate::push_build::build_push_aliased_with_meta`]'s bytes). With no suffix the Push
/// header's `N` flag is clear and the wire carries the id alone, which is what makes an
/// aliased publish cheaper to send and to read than the literal key it stands for.
///
/// `mapping_id` is not zero: that id is the literal key's.
pub fn aliased_put_with_qos<'a>(
    mapping_id: u64,
    suffix: Option<&'a str>,
    value: &'a [u8],
    qos: crate::sample::QosLevel,
) -> Push<'a> {
    debug_assert!(mapping_id != 0, "id 0 is the literal key, not an alias");
    put_with_qos(mapping_id, suffix, value, qos)
}

/// The one composition behind [`literal_put_with_qos`] and [`aliased_put_with_qos`]: a Put on
/// `(mapping_id, suffix)`, the `N` flag set exactly when a suffix rides.
pub fn put_with_qos<'a>(
    mapping_id: u64,
    suffix: Option<&'a str>,
    value: &'a [u8],
    qos: crate::sample::QosLevel,
) -> Push<'a> {
    // Mutated only when the QoS extension can ride (`pubsub-qos`).
    #[allow(unused_mut)]
    let mut push = Push {
        header: wz_codecs::wire_const::N_MID_PUSH | if suffix.is_some() { FLAG_PUSH_N } else { 0 },
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len: suffix.map(|text| text.len() as u64),
                suffix,
            }),
        },
        extensions: None,
        body: PushVariant::CodecZenohMsgPut(MsgPut {
            header: PUT_HEADER,
            payload_len: Some(value.len() as u64),
            payload: Some(value),
            ..MsgPut::default()
        }),
    };
    #[cfg(feature = "pubsub-qos")]
    if qos != crate::sample::QosLevel::DEFAULT {
        let mut chain: HeaplessVec<ExtEntry<'a>, 8> = HeaplessVec::new();
        // One extension: no `Z` bit on it, which only says another follows.
        let _ = chain.push(ExtEntry {
            // ENC_ZINT(0x20) | id_qos(0x01); no `M`, qos is informational.
            header: 0x20 | 0x01,
            body: ExtEntryVariant::CodecZenohExtZint(ExtZint {
                value: u64::from(qos.raw),
            }),
        });
        push.extensions = Some(chain);
        // The Push header says an outer chain follows.
        push.header |= 0x80;
    }
    #[cfg(not(feature = "pubsub-qos"))]
    let _ = qos;
    push
}

/// The bytes of [`put_with_qos`] written straight into `sink`, without composing the codec's
/// `Push` and walking its variants to encode it: the Push header, the key (the id, and a suffix
/// with its length), the QoS extension when it rides, the Put header, the payload's length and
/// the payload. A stream of equal messages sends this one shape, and the generic encoder's
/// walk over a message of any shape was most of what encoding it cost. The two are the same
/// bytes for every input (see the equality test), so the shape stays the codec's and this is
/// only a faster way to write it.
pub fn write_plain_put<S: sce_forge_runtime::codec::SceSink>(
    sink: &mut S,
    mapping_id: u64,
    suffix: Option<&str>,
    value: &[u8],
    qos: crate::sample::QosLevel,
) -> Result<(), sce_forge_runtime::codec::CodecError> {
    // The QoS extension rides when `pubsub-qos` is built and the byte is not the default one.
    #[cfg(feature = "pubsub-qos")]
    let with_qos = qos != crate::sample::QosLevel::DEFAULT;
    #[cfg(not(feature = "pubsub-qos"))]
    let with_qos = {
        let _ = qos;
        false
    };
    let header = wz_codecs::wire_const::N_MID_PUSH
        | if suffix.is_some() { FLAG_PUSH_N } else { 0 }
        // `M`: the id is in the sender's space, which the codec derives from its
        // `WireexprLocal` arm at encode time.
        | FLAG_PUSH_M
        // The header says an outer extension chain follows.
        | if with_qos { 0x80 } else { 0 };
    sink.write_u8(header)?;
    sink.write_vle_u64(mapping_id)?;
    if let Some(text) = suffix {
        sink.write_vle_u64(text.len() as u64)?;
        sink.write_bytes(text.as_bytes())?;
    }
    #[cfg(feature = "pubsub-qos")]
    if with_qos {
        // ENC_ZINT(0x20) | id_qos(0x01), no `Z`: the only extension of the chain.
        sink.write_u8(0x21)?;
        sink.write_vle_u64(u64::from(qos.raw))?;
    }
    sink.write_u8(PUT_HEADER)?;
    sink.write_vle_u64(value.len() as u64)?;
    sink.write_bytes(value)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::push_build::build_push_literal;

    /// The direct writer and the codec's encoder write the same bytes: for a literal key and
    /// for an id, with and without a suffix, for the default QoS byte and for others, and for
    /// payloads whose lengths take one, two and three VLE bytes.
    #[test]
    fn the_direct_writer_is_the_codecs_bytes() {
        let mut compared = 0usize;
        for id in [0u64, 1, 127, 128, 300, 16_384, 65_535] {
            for suffix in [
                None,
                Some("a"),
                Some("test/thr"),
                Some("a/much/longer/key/x"),
            ] {
                if id == 0 && suffix.is_none() {
                    continue;
                }
                for raw in [0x05u8, 0x1a, 0x00, 0xff] {
                    let qos = crate::sample::QosLevel::from_raw(raw);
                    for payload in [
                        &b""[..],
                        &b"x"[..],
                        &[7u8; 127][..],
                        &[9u8; 300][..],
                        &[1u8; 20_000][..],
                    ] {
                        let mut want = alloc::vec::Vec::new();
                        put_with_qos(id, suffix, payload, qos)
                            .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut want))
                            .expect("a Vec grows");
                        let mut got = alloc::vec::Vec::new();
                        write_plain_put(
                            &mut sce_forge_runtime::codec::VecSink::new(&mut got),
                            id,
                            suffix,
                            payload,
                            qos,
                        )
                        .expect("a Vec grows");
                        assert_eq!(
                            got,
                            want,
                            "id {id} suffix {suffix:?} qos {raw:#04x} {} payload bytes",
                            payload.len()
                        );
                        compared += 1;
                    }
                }
            }
        }
        assert!(compared > 500, "{compared}");
    }

    /// The borrowed composition and the owned builder it replaces put the same bytes on
    /// the wire, for the keyexprs and payloads a Put can carry, the empty ones included.
    #[test]
    fn the_borrowed_put_is_the_owned_builders_bytes() {
        let keyexprs = [
            "a",
            "demo/mc",
            "a/very/long/keyexpr/that/needs/more/than/a/byte",
        ];
        let payloads: [&[u8]; 4] = [b"", b"x", b"hello", &[7u8; 300]];
        let mut compared = 0usize;
        for keyexpr in keyexprs {
            for payload in payloads {
                let owned = build_push_literal(keyexpr, payload).expect("a literal Put builds");
                let mut want = alloc::vec::Vec::new();
                owned
                    .try_as_borrowed()
                    .expect("the owned Put has a view")
                    .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut want))
                    .expect("a Vec grows");
                let mut got = alloc::vec::Vec::new();
                literal_put(keyexpr, payload)
                    .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut got))
                    .expect("a Vec grows");
                assert_eq!(
                    got,
                    want,
                    "keyexpr {keyexpr:?}, {} payload bytes",
                    payload.len()
                );
                compared += 1;
            }
        }
        assert_eq!(compared, keyexprs.len() * payloads.len());
    }

    /// With QoS the borrowed composition and the owned metadata builder put the same bytes
    /// on the wire: the DEFAULT byte rides no extension, and every other byte rides the
    /// outer chain with the Push header's `Z` bit, across the priorities, the congestion
    /// controls and the express bit a publisher sets.
    #[test]
    fn the_borrowed_put_with_qos_is_the_owned_builders_bytes() {
        use crate::metadata::PushMetadata;
        use crate::push_build::build_push_literal_with_meta;
        use crate::sample::QosLevel;

        let mut qos_bytes: alloc::vec::Vec<u8> = (0..=0x1f).collect();
        qos_bytes.push(QosLevel::DEFAULT.raw);
        let payloads: [&[u8]; 3] = [b"", b"x", &[9u8; 700]];
        let mut compared = 0usize;
        let mut with_extension = 0usize;
        for raw in qos_bytes {
            let qos = QosLevel::from_raw(raw);
            for payload in payloads {
                let meta = PushMetadata {
                    qos: Some(qos),
                    ..PushMetadata::default()
                };
                let owned = build_push_literal_with_meta("demo/qos/key", payload, &meta)
                    .expect("a literal Put with QoS builds");
                let mut want = alloc::vec::Vec::new();
                owned
                    .try_as_borrowed()
                    .expect("the owned Put has a view")
                    .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut want))
                    .expect("a Vec grows");
                let mut got = alloc::vec::Vec::new();
                literal_put_with_qos("demo/qos/key", payload, qos)
                    .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut got))
                    .expect("a Vec grows");
                assert_eq!(
                    got,
                    want,
                    "qos byte {raw:#04x}, {} payload bytes",
                    payload.len()
                );
                if owned.extensions.is_some() {
                    with_extension += 1;
                }
                compared += 1;
            }
        }
        assert!(compared > 0);
        // The control: the extension really rides for the non-default bytes, so the
        // equality above is not two empty chains agreeing.
        #[cfg(feature = "pubsub-qos")]
        assert!(
            with_extension > 0 && with_extension < compared,
            "some bytes carry an extension and the DEFAULT one does not: {with_extension} of {compared}"
        );
        #[cfg(not(feature = "pubsub-qos"))]
        assert_eq!(with_extension, 0);
    }

    /// An aliased Put, with and without a suffix and with and without QoS, is the owned
    /// aliased builder's bytes: the `N` flag rides exactly when a suffix does, and the id is
    /// written as the key.
    #[test]
    fn the_borrowed_aliased_put_is_the_owned_builders_bytes() {
        use crate::metadata::PushMetadata;
        use crate::push_build::build_push_aliased_with_meta;
        use crate::sample::QosLevel;

        let mut compared = 0usize;
        for id in [1u64, 7, 127, 128, 300, 65_535] {
            for suffix in [None, Some("tail"), Some("a/longer/suffix/than/one")] {
                for raw in [QosLevel::DEFAULT.raw, 0x11, 0x1a] {
                    for payload in [&b""[..], &b"x"[..], &[5u8; 400][..]] {
                        let qos = QosLevel::from_raw(raw);
                        let meta = PushMetadata {
                            qos: Some(qos),
                            ..PushMetadata::default()
                        };
                        let owned = build_push_aliased_with_meta(id, suffix, payload, &meta)
                            .expect("an aliased Put builds");
                        let mut want = alloc::vec::Vec::new();
                        owned
                            .try_as_borrowed()
                            .expect("the owned Put has a view")
                            .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut want))
                            .expect("a Vec grows");
                        let mut got = alloc::vec::Vec::new();
                        aliased_put_with_qos(id, suffix, payload, qos)
                            .encode(&mut sce_forge_runtime::codec::VecSink::new(&mut got))
                            .expect("a Vec grows");
                        assert_eq!(
                            got,
                            want,
                            "id {id}, suffix {suffix:?}, qos {raw:#04x}, {} payload bytes",
                            payload.len()
                        );
                        compared += 1;
                    }
                }
            }
        }
        assert_eq!(compared, 6 * 3 * 3 * 3);
    }
}
