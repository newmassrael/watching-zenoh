// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The records of a Frame read with the lent codec of each network message, each held to its
//! round trip: what the targets that read a peer's records where they lie share.
//!
//! The round trip of a value `v` decoded from the wire is held as: the bytes `encode(v)` decode
//! again, wholly, to a value that reads as `v` and encodes to the same bytes. It is not held as
//! byte identity with the wire, which may spell a value in more than one way (a variable-length
//! integer with leading zero groups).

use wz_codecs::wire_const::{
    N_MID_DECLARE, N_MID_INTEREST, N_MID_OAM, N_MID_PUSH, N_MID_REQUEST, N_MID_RESPONSE,
    N_MID_RESPONSE_FINAL,
};
use wz_codecs::SceCursor;

/// Walk `payload`'s records with the lent codecs, each held to its round trip, and hand `each`
/// where each record began and how many bytes it took. The walk ends at the first byte that
/// names no network message (a transport message, which ends a Frame's records) and at the first
/// record its codec refuses.
pub fn lent_records(payload: &[u8], mut each: impl FnMut(usize, usize)) {
    let mut cursor = SceCursor::new(payload);
    while cursor.remaining() > 0 {
        let at = payload.len() - cursor.remaining();
        match lent_record(&mut cursor) {
            Some(len) => each(at, len),
            None => break,
        }
    }
}

/// The record at the front of `cursor`, read with the lent codec its id names and held to its
/// round trip: how many bytes it took, or `None` for an id that names no network message and
/// for a record its codec refuses.
fn lent_record(cursor: &mut SceCursor<'_>) -> Option<usize> {
    match cursor.peek_slice(1).ok()?[0] & 0x1F {
        N_MID_PUSH => push(cursor),
        N_MID_REQUEST => request(cursor),
        N_MID_RESPONSE => response(cursor),
        N_MID_RESPONSE_FINAL => response_final(cursor),
        N_MID_DECLARE => declare(cursor),
        N_MID_INTEREST => interest(cursor),
        N_MID_OAM => oam(cursor),
        _ => None,
    }
}

/// One function per lent codec: a lent value is invariant in the lifetime of the bytes it was
/// read from, so the value read again from its own encoding is another type, and the two are
/// compared by what they render.
macro_rules! round_trip {
    ($($name:ident => $codec:ident),* $(,)?) => {$(
        fn $name(cursor: &mut SceCursor<'_>) -> Option<usize> {
            let before = cursor.remaining();
            let value = wz_codecs::lent::$codec::decode(cursor).ok()?;
            let read = before - cursor.remaining();
            let first = value.encode_to_vec();
            let mut again = SceCursor::new(&first);
            let second = wz_codecs::lent::$codec::decode(&mut again)
                .expect(concat!("a ", stringify!($codec), " the codec encoded decodes again"));
            assert_eq!(
                again.remaining(),
                0,
                concat!("a ", stringify!($codec), " decodes from all of its own encoding")
            );
            assert_eq!(
                format!("{value:?}"),
                format!("{second:?}"),
                concat!("a ", stringify!($codec), " reads back as the value it was encoded from")
            );
            assert_eq!(
                second.encode_to_vec(),
                first,
                concat!("a ", stringify!($codec), " encodes the same bytes the second time")
            );
            Some(read)
        }
    )*};
}

round_trip! {
    push => Push,
    request => Request,
    response => Response,
    response_final => ResponseFinal,
    declare => Declare,
    interest => Interest,
    oam => Oam,
}
