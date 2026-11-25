// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pull of a frame's records on the form that lends every kind
//! ([`RecordForm::LentControl`](super::RecordForm::LentControl)): each record's body is read
//! where it lies as soon as its kind is read, and handed over.

use super::*;

/// The records of `payload`, a frame's, each read where it lies as soon as its kind is read, judged
/// by the owned rule, and handed to `each`, until `each` takes no more, a transport message begins,
/// a record does not decode, or the payload ends: how far the pull read, and whether `each` ended
/// it with a record still unread. A transport message begins where the last record ends and is the
/// batch's to read.
///
/// Every consumer reads every body it is handed, and a record's end is known only once its body is
/// read, so the body is read in the step that reads its kind: one cursor goes through the payload
/// once, with no record handed out unread to be passed over by the next step.
pub(super) fn hand_records<'f>(
    payload: &'f [u8],
    each: &mut dyn EachRecord<'f>,
) -> Result<(usize, bool), crate::parse_error::InboundParseError> {
    let mut cursor = SceCursor::new(payload);
    while let Some(mid) = record_at(&cursor) {
        if !lend_next(mid, &mut cursor, each)? {
            let read = payload.len().saturating_sub(cursor.remaining());
            return Ok((read, record_at(&cursor).is_some()));
        }
    }
    Ok((payload.len().saturating_sub(cursor.remaining()), false))
}

/// The id of the record at `cursor`; `None` at the end of the payload, and where a transport
/// message begins.
fn record_at(cursor: &SceCursor<'_>) -> Option<u8> {
    let mid = cursor.peek_u8().ok()? & 0x1F;
    (!is_transport_mid(mid)).then_some(mid)
}

/// The record at `cursor`, whose id is `mid`, read past and handed to `each`; what `each` said of
/// taking another. A MID this build has no decoder for takes the rest of the payload as one skipped
/// record, as the owned walk's `Unknown` does: its length is unknowable.
fn lend_next<'f>(
    mid: u8,
    cursor: &mut SceCursor<'f>,
    each: &mut dyn EachRecord<'f>,
) -> Result<bool, crate::parse_error::InboundParseError> {
    match mid {
        // What the build reads off the wire (`rx-push`, `rx-response`, `rx-control`): a kind it
        // did not ask for is a MID with no decoder here, and ends the pull of its frame.
        #[cfg(all(feature = "codec-push", feature = "rx-push"))]
        wire_const::N_MID_PUSH => lend_body::<PushBody>(cursor, each),
        #[cfg(feature = "codec-request")]
        wire_const::N_MID_REQUEST => lend_body::<RequestBody>(cursor, each),
        #[cfg(all(feature = "codec-response", feature = "rx-response"))]
        wire_const::N_MID_RESPONSE => lend_body::<ResponseBody>(cursor, each),
        #[cfg(all(feature = "codec-response-final", feature = "rx-response"))]
        wire_const::N_MID_RESPONSE_FINAL => lend_body::<ResponseFinalBody>(cursor, each),
        #[cfg(all(feature = "codec-declare", feature = "rx-control"))]
        wire_const::N_MID_DECLARE => lend_body::<DeclareBody>(cursor, each),
        #[cfg(feature = "rx-control")]
        wire_const::N_MID_INTEREST => lend_body::<InterestBody>(cursor, each),
        // Read and judged, and handed over as itself only where the counters read its band
        // ([`OamBody`]).
        #[cfg(feature = "rx-control")]
        wire_const::N_MID_OAM => lend_body::<OamBody>(cursor, each),
        _ => {
            cursor
                .advance(cursor.remaining())
                .map_err(crate::parse_error::InboundParseError::Codec)?;
            each.take_record(WalkedRecord::Skipped)
        }
    }
}

/// The body of the record at `cursor`, of the kind `B`, read where the payload lies and handed to
/// `each`. Out of line and one per kind, so the frame holds the one body only while its record is
/// handed over.
#[cfg(any(
    all(feature = "codec-push", feature = "rx-push"),
    feature = "codec-request",
    all(feature = "codec-response", feature = "rx-response"),
    all(feature = "codec-response-final", feature = "rx-response"),
    feature = "rx-control"
))]
#[inline(never)]
fn lend_body<'f, B: RecordBody<'f>>(
    cursor: &mut SceCursor<'f>,
    each: &mut dyn EachRecord<'f>,
) -> Result<bool, crate::parse_error::InboundParseError> {
    let mut body = B::View::default();
    B::read(cursor, &mut body)?;
    each.take_record(B::walked(&body))
}

/// How the body of one kind of record is read, and how the walk hands it over.
#[cfg(any(
    all(feature = "codec-push", feature = "rx-push"),
    feature = "codec-request",
    all(feature = "codec-response", feature = "rx-response"),
    all(feature = "codec-response-final", feature = "rx-response"),
    feature = "rx-control"
))]
trait RecordBody<'f> {
    /// The body as the codec reads it where the payload lies.
    type View: Default;
    /// Read the body at `cursor` into `view` and judge it by the owned rule.
    fn read(
        cursor: &mut SceCursor<'f>,
        view: &mut Self::View,
    ) -> Result<(), crate::parse_error::InboundParseError>;
    /// The body as the walk hands it over, lent for the call.
    fn walked<'v>(view: &'v Self::View) -> WalkedRecord<'v, 'f>
    where
        'f: 'v;
}

/// The body of a Push record.
#[cfg(all(feature = "codec-push", feature = "rx-push"))]
enum PushBody {}

#[cfg(all(feature = "codec-push", feature = "rx-push"))]
impl<'f> RecordBody<'f> for PushBody {
    type View = PushRead<'f>;
    fn read(
        cursor: &mut SceCursor<'f>,
        view: &mut Self::View,
    ) -> Result<(), crate::parse_error::InboundParseError> {
        read_push(cursor, view)
    }
    fn walked<'v>(view: &'v Self::View) -> WalkedRecord<'v, 'f>
    where
        'f: 'v,
    {
        WalkedRecord::Push(view)
    }
}

/// The body of a Request record.
#[cfg(feature = "codec-request")]
enum RequestBody {}

#[cfg(feature = "codec-request")]
impl<'f> RecordBody<'f> for RequestBody {
    type View = wz_codecs::request::RequestView<'f>;
    fn read(
        cursor: &mut SceCursor<'f>,
        view: &mut Self::View,
    ) -> Result<(), crate::parse_error::InboundParseError> {
        read_request(cursor, view)
    }
    fn walked<'v>(view: &'v Self::View) -> WalkedRecord<'v, 'f>
    where
        'f: 'v,
    {
        WalkedRecord::Request(view)
    }
}

/// The body of a Response record.
#[cfg(all(feature = "codec-response", feature = "rx-response"))]
enum ResponseBody {}

#[cfg(all(feature = "codec-response", feature = "rx-response"))]
impl<'f> RecordBody<'f> for ResponseBody {
    type View = wz_codecs::response::ResponseView<'f>;
    fn read(
        cursor: &mut SceCursor<'f>,
        view: &mut Self::View,
    ) -> Result<(), crate::parse_error::InboundParseError> {
        read_response(cursor, view)
    }
    fn walked<'v>(view: &'v Self::View) -> WalkedRecord<'v, 'f>
    where
        'f: 'v,
    {
        WalkedRecord::Response(view)
    }
}

/// The body of a ResponseFinal record.
#[cfg(all(feature = "codec-response-final", feature = "rx-response"))]
enum ResponseFinalBody {}

#[cfg(all(feature = "codec-response-final", feature = "rx-response"))]
impl<'f> RecordBody<'f> for ResponseFinalBody {
    type View = wz_codecs::lent::ResponseFinal<'f>;
    fn read(
        cursor: &mut SceCursor<'f>,
        view: &mut Self::View,
    ) -> Result<(), crate::parse_error::InboundParseError> {
        read_response_final(cursor, view)
    }
    fn walked<'v>(view: &'v Self::View) -> WalkedRecord<'v, 'f>
    where
        'f: 'v,
    {
        WalkedRecord::ResponseFinal(view)
    }
}

/// The body of a Declare record.
#[cfg(all(feature = "codec-declare", feature = "rx-control"))]
enum DeclareBody {}

#[cfg(all(feature = "codec-declare", feature = "rx-control"))]
impl<'f> RecordBody<'f> for DeclareBody {
    type View = wz_codecs::lent::Declare<'f>;
    fn read(
        cursor: &mut SceCursor<'f>,
        view: &mut Self::View,
    ) -> Result<(), crate::parse_error::InboundParseError> {
        read_declare(cursor, view)
    }
    fn walked<'v>(view: &'v Self::View) -> WalkedRecord<'v, 'f>
    where
        'f: 'v,
    {
        WalkedRecord::Declare(view)
    }
}

/// The body of an Interest record.
#[cfg(feature = "rx-control")]
enum InterestBody {}

#[cfg(feature = "rx-control")]
impl<'f> RecordBody<'f> for InterestBody {
    type View = wz_codecs::lent::Interest<'f>;
    fn read(
        cursor: &mut SceCursor<'f>,
        view: &mut Self::View,
    ) -> Result<(), crate::parse_error::InboundParseError> {
        read_interest(cursor, view)
    }
    fn walked<'v>(view: &'v Self::View) -> WalkedRecord<'v, 'f>
    where
        'f: 'v,
    {
        WalkedRecord::Interest(view)
    }
}

/// The body of an Oam record.
#[cfg(feature = "rx-control")]
enum OamBody {}

#[cfg(feature = "rx-control")]
impl<'f> RecordBody<'f> for OamBody {
    type View = wz_codecs::lent::Oam<'f>;
    fn read(
        cursor: &mut SceCursor<'f>,
        view: &mut Self::View,
    ) -> Result<(), crate::parse_error::InboundParseError> {
        read_oam(cursor, view)
    }
    #[cfg(all(feature = "transport-stats", feature = "alloc"))]
    fn walked<'v>(view: &'v Self::View) -> WalkedRecord<'v, 'f>
    where
        'f: 'v,
    {
        WalkedRecord::Oam(view)
    }
    // Only a build with the counters hands an Oam over as itself; any other hands it over as a
    // skipped record ([`WalkedRecord::Skipped`]).
    #[cfg(not(all(feature = "transport-stats", feature = "alloc")))]
    fn walked<'v>(_view: &'v Self::View) -> WalkedRecord<'v, 'f>
    where
        'f: 'v,
    {
        WalkedRecord::Skipped
    }
}
