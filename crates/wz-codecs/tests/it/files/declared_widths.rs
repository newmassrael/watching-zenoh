// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A key expression's scope is an `ExprId`, sixteen bits, and a request id is a
//! `RequestId`, thirty-two bits, and upstream reads both bounded: a VLE that
//! says more is refused, not truncated
//! (`commons/zenoh-codec/src/core/wire_expr.rs` @ `let zodec = Zenoh080Bounded::<ExprId>::new();`,
//! `commons/zenoh-codec/src/network/request.rs` @ `let id: RequestId = bodec.read(&mut *reader)?;`,
//! `commons/zenoh-codec/src/network/response.rs` @ `let rid: RequestId = bodec.read(&mut *reader)?;`;
//! the widths `commons/zenoh-protocol/src/core/wire_expr.rs` @ `pub type ExprId = u16;` and
//! `commons/zenoh-protocol/src/network/request.rs` @ `pub type RequestId = u32;`).
//!
//! Each field is read at the widest value its type holds, the control, and one
//! past it, which must be refused: without the control a refusal could come
//! from a frame that is wrong for another reason.

#![cfg(all(
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final"
))]

use sce_forge_runtime::codec::CodecError;
use wz_codecs::lent::{Push, Request, Response, ResponseFinal};
use wz_codecs::SceCursor;

/// `value` as a zenoh VLE.
fn vle(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while value >= 0x80 {
        out.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

/// A Push whose key expression has the scope `scope` and no suffix, carrying a
/// Put with an empty payload.
fn push_with_scope(scope: u64) -> Vec<u8> {
    let mut frame = vec![0x1D];
    frame.extend(vle(scope));
    // Put: header, then the payload's VLE length 0.
    frame.extend([0x01, 0x00]);
    frame
}

/// A Request of id `rid` on scope 0, carrying a Query with nothing set.
fn request_with_id(rid: u64) -> Vec<u8> {
    let mut frame = vec![0x1C];
    frame.extend(vle(rid));
    frame.extend([0x00, 0x03]);
    frame
}

/// A Response to request `rid` on scope 0, carrying a Reply of a Put with an
/// empty payload.
fn response_with_id(rid: u64) -> Vec<u8> {
    let mut frame = vec![0x1B];
    frame.extend(vle(rid));
    frame.extend([0x00, 0x04, 0x01, 0x00]);
    frame
}

/// A ResponseFinal to request `rid`.
fn response_final_with_id(rid: u64) -> Vec<u8> {
    let mut frame = vec![0x1A];
    frame.extend(vle(rid));
    frame
}

#[test]
fn a_scope_is_read_up_to_sixteen_bits_and_refused_past_them() {
    let at = push_with_scope(u64::from(u16::MAX));
    assert!(
        Push::decode(&mut SceCursor::new(&at)).is_ok(),
        "the widest scope an ExprId holds is read"
    );
    let past = push_with_scope(u64::from(u16::MAX) + 1);
    assert_eq!(
        Push::decode(&mut SceCursor::new(&past)).err(),
        Some(CodecError::VleWidthOverflow),
        "a scope past an ExprId is refused, as upstream's bounded read refuses it"
    );
}

#[test]
fn a_request_id_is_read_up_to_thirty_two_bits_and_refused_past_them() {
    let at = request_with_id(u64::from(u32::MAX));
    let read = Request::decode(&mut SceCursor::new(&at)).expect("the widest RequestId is read");
    assert_eq!(read.rid, u32::MAX);
    let past = request_with_id(u64::from(u32::MAX) + 1);
    assert_eq!(
        Request::decode(&mut SceCursor::new(&past)).err(),
        Some(CodecError::VleWidthOverflow)
    );
}

#[test]
fn a_response_names_its_request_by_the_same_thirty_two_bits() {
    let at = response_with_id(u64::from(u32::MAX));
    let read = Response::decode(&mut SceCursor::new(&at)).expect("the widest RequestId is read");
    assert_eq!(read.request_id, u32::MAX);
    let past = response_with_id(u64::from(u32::MAX) + 1);
    assert_eq!(
        Response::decode(&mut SceCursor::new(&past)).err(),
        Some(CodecError::VleWidthOverflow)
    );

    let at = response_final_with_id(u64::from(u32::MAX));
    let read =
        ResponseFinal::decode(&mut SceCursor::new(&at)).expect("the widest RequestId is read");
    assert_eq!(read.request_id, u32::MAX);
    let past = response_final_with_id(u64::from(u32::MAX) + 1);
    assert_eq!(
        ResponseFinal::decode(&mut SceCursor::new(&past)).err(),
        Some(CodecError::VleWidthOverflow)
    );
}
