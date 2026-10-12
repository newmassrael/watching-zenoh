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

use wz_codecs::msg_put::MsgPut;
use wz_codecs::push::{Push, PushVariant};
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;

/// The `N` flag of the Push header: a keyexpr suffix rides inline.
const FLAG_PUSH_N: u8 = 0x20;

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

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::push_build::build_push_literal;

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
}
