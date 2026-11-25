// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pull of a frame's records on the form that lends every kind
//! ([`RecordForm::LentControl`](super::RecordForm::LentControl)): a record is handed out as its
//! kind and where it lies, and its body is read where it lies only when its consumer asks.

use super::*;

/// The records of a frame's payload, pulled one at a time where the payload lies
/// ([`RecordForm::LentControl`]): each pull hands out the record at the cursor as a small view (its
/// kind and where it lies), and the record's body is read only when its consumer asks for it
/// ([`Pulled::read`]), into a binding of the consumer's own frame. A record whose body no consumer
/// read is read by the next pull, to find where the one after it begins, and is judged by the owned
/// rule all the same. The pull ends before a transport message, which begins where the last record
/// ends and is the batch's to read ([`Self::consumed`] says where), after a record that does not
/// decode, and at the end of the payload. The codec's pull of a frame's messages has the same shape
/// (a small view enum by value, the body read in place), so the reader it generates can take this
/// one's place.
///
/// Pulled through a shared borrow (`&Records` is the iterator), so a view that was handed out can
/// say where its record ends once its body is read.
pub(super) struct Records<'f> {
    payload: &'f [u8],
    /// Where the record handed out last begins while [`Self::unread`] holds its id; otherwise
    /// where the next record begins.
    at: core::cell::Cell<usize>,
    /// The id of the record handed out last whose body no consumer has read.
    unread: core::cell::Cell<Option<u8>>,
    /// A record failed to decode: what follows it has no known start.
    failed: core::cell::Cell<bool>,
}

impl<'f> Records<'f> {
    /// The records of `payload`, a frame's.
    pub(super) fn new(payload: &'f [u8]) -> Self {
        Self {
            payload,
            at: core::cell::Cell::new(0),
            unread: core::cell::Cell::new(None),
            failed: core::cell::Cell::new(false),
        }
    }

    /// How many bytes of the payload the records read so far took. A record handed out whose
    /// body was not read yet is not counted: where it ends is not known.
    pub(super) fn consumed(&self) -> usize {
        self.at.get()
    }

    /// Whether a record lies past the ones read so far: the payload goes on, no transport message
    /// begins there, and no record before failed to decode. Asked once the record handed out last
    /// was read ([`Self::pass_unread`]).
    pub(super) fn holds_record(&self) -> bool {
        !self.failed.get()
            && self
                .payload
                .get(self.at.get())
                .is_some_and(|header| !is_transport_mid(header & 0x1F))
    }

    /// Read the body of the record handed out last if no consumer read it, to learn where it ends;
    /// it is judged as a body its consumer reads is judged.
    pub(super) fn pass_unread(&self) -> Result<(), crate::parse_error::InboundParseError> {
        let Some(mid) = self.unread.get() else {
            return Ok(());
        };
        match mid {
            #[cfg(all(feature = "codec-push", feature = "rx-push"))]
            wire_const::N_MID_PUSH => pass_body::<PushBody>(self),
            #[cfg(feature = "codec-request")]
            wire_const::N_MID_REQUEST => pass_body::<RequestBody>(self),
            #[cfg(all(feature = "codec-response", feature = "rx-response"))]
            wire_const::N_MID_RESPONSE => pass_body::<ResponseBody>(self),
            #[cfg(all(feature = "codec-response-final", feature = "rx-response"))]
            wire_const::N_MID_RESPONSE_FINAL => pass_body::<ResponseFinalBody>(self),
            #[cfg(all(feature = "codec-declare", feature = "rx-control"))]
            wire_const::N_MID_DECLARE => pass_body::<DeclareBody>(self),
            #[cfg(feature = "rx-control")]
            wire_const::N_MID_INTEREST => pass_body::<InterestBody>(self),
            #[cfg(feature = "rx-control")]
            wire_const::N_MID_OAM => pass_body::<OamBody>(self),
            // Only the ids above are handed out unread; any other ends the pull as an unknown MID
            // does.
            _ => {
                self.unread.set(None);
                self.at.set(self.payload.len());
                Ok(())
            }
        }
    }

    /// The view of the record at the cursor, whose id is `mid`. A MID this build has no decoder for
    /// takes the rest of the payload as one skipped record, as the owned walk's `Unknown` does: its
    /// length is unknowable.
    fn hand_out(&self, mid: u8) -> RecordView<'_, 'f> {
        match mid {
            // What the build reads off the wire (`rx-push`, `rx-response`, `rx-control`): a kind
            // it did not ask for is a MID with no decoder here, and ends the pull of its frame.
            #[cfg(all(feature = "codec-push", feature = "rx-push"))]
            wire_const::N_MID_PUSH => RecordView::Push(self.unread_at(mid)),
            #[cfg(feature = "codec-request")]
            wire_const::N_MID_REQUEST => RecordView::Request(self.unread_at(mid)),
            #[cfg(all(feature = "codec-response", feature = "rx-response"))]
            wire_const::N_MID_RESPONSE => RecordView::Response(self.unread_at(mid)),
            #[cfg(all(feature = "codec-response-final", feature = "rx-response"))]
            wire_const::N_MID_RESPONSE_FINAL => RecordView::ResponseFinal(self.unread_at(mid)),
            #[cfg(all(feature = "codec-declare", feature = "rx-control"))]
            wire_const::N_MID_DECLARE => RecordView::Declare(self.unread_at(mid)),
            #[cfg(feature = "rx-control")]
            wire_const::N_MID_INTEREST => RecordView::Interest(self.unread_at(mid)),
            // The counters read an Oam's band (`RecordClass`); nothing else reads it.
            #[cfg(all(feature = "rx-control", feature = "transport-stats", feature = "alloc"))]
            wire_const::N_MID_OAM => RecordView::Oam(self.unread_at(mid)),
            #[cfg(all(
                feature = "rx-control",
                not(all(feature = "transport-stats", feature = "alloc"))
            ))]
            wire_const::N_MID_OAM => {
                self.unread.set(Some(mid));
                RecordView::Skipped(core::marker::PhantomData)
            }
            _ => {
                self.at.set(self.payload.len());
                RecordView::Skipped(core::marker::PhantomData)
            }
        }
    }

    /// The record at the cursor, whose id is `mid`, handed out with its body unread.
    #[cfg(any(
        all(feature = "codec-push", feature = "rx-push"),
        feature = "codec-request",
        all(feature = "codec-response", feature = "rx-response"),
        all(feature = "codec-response-final", feature = "rx-response"),
        feature = "rx-control"
    ))]
    fn unread_at<B>(&self, mid: u8) -> Pulled<'_, 'f, B> {
        self.unread.set(Some(mid));
        Pulled {
            records: self,
            at: self.at.get(),
            body: core::marker::PhantomData,
        }
    }

    /// The body of the record at `at`, read into `view`. When it is the record handed out last
    /// and not read before, the pull learns where it ends, or that nothing after it can be read.
    #[cfg(any(
        all(feature = "codec-push", feature = "rx-push"),
        feature = "codec-request",
        all(feature = "codec-response", feature = "rx-response"),
        all(feature = "codec-response-final", feature = "rx-response"),
        feature = "rx-control"
    ))]
    fn read_body<B: RecordBody<'f>>(
        &self,
        at: usize,
        view: &mut B::View,
    ) -> Result<(), crate::parse_error::InboundParseError> {
        let mut cursor = SceCursor::new(self.payload.get(at..).unwrap_or_default());
        let read = B::read(&mut cursor, view);
        if self.unread.get().is_some() && self.at.get() == at {
            self.unread.set(None);
            match read {
                Ok(()) => self
                    .at
                    .set(self.payload.len().saturating_sub(cursor.remaining())),
                Err(_) => self.failed.set(true),
            }
        }
        read
    }
}

impl<'r, 'f> Iterator for &'r Records<'f> {
    type Item = Result<RecordView<'r, 'f>, crate::parse_error::InboundParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let records = *self;
        if let Err(stop) = records.pass_unread() {
            return Some(Err(stop));
        }
        if !records.holds_record() {
            return None;
        }
        let header = *records.payload.get(records.at.get())?;
        Some(Ok(records.hand_out(header & 0x1F)))
    }
}

/// One record [`Records`] pulled: its kind, and the record where it lies, whose body is read when
/// its consumer asks for it. A few words whatever the kind, so the view moves by value and holds no
/// decoded body across its consumer's call.
pub(super) enum RecordView<'r, 'f> {
    /// A Push.
    #[cfg(all(feature = "codec-push", feature = "rx-push"))]
    Push(Pulled<'r, 'f, PushBody>),
    /// A Request.
    #[cfg(feature = "codec-request")]
    Request(Pulled<'r, 'f, RequestBody>),
    /// A Response.
    #[cfg(all(feature = "codec-response", feature = "rx-response"))]
    Response(Pulled<'r, 'f, ResponseBody>),
    /// A ResponseFinal.
    #[cfg(all(feature = "codec-response-final", feature = "rx-response"))]
    ResponseFinal(Pulled<'r, 'f, ResponseFinalBody>),
    /// A Declare.
    #[cfg(all(feature = "codec-declare", feature = "rx-control"))]
    Declare(Pulled<'r, 'f, DeclareBody>),
    /// An Interest.
    #[cfg(feature = "rx-control")]
    Interest(Pulled<'r, 'f, InterestBody>),
    /// An Oam, kept for the transport counters, which read its band.
    #[cfg(all(feature = "rx-control", feature = "transport-stats", feature = "alloc"))]
    Oam(Pulled<'r, 'f, OamBody>),
    /// A record no consumer reads further: an Oam in a build without the counters, or the tail of
    /// a payload that opens with a MID this build has no decoder for.
    Skipped(core::marker::PhantomData<&'r Records<'f>>),
}

/// A record [`Records`] handed out, of the kind `B`, whose body is not read until its consumer
/// asks for it.
#[cfg(any(
    all(feature = "codec-push", feature = "rx-push"),
    feature = "codec-request",
    all(feature = "codec-response", feature = "rx-response"),
    all(feature = "codec-response-final", feature = "rx-response"),
    feature = "rx-control"
))]
pub(super) struct Pulled<'r, 'f, B> {
    records: &'r Records<'f>,
    /// Where the record begins in the payload.
    at: usize,
    body: core::marker::PhantomData<B>,
}

#[cfg(any(
    all(feature = "codec-push", feature = "rx-push"),
    feature = "codec-request",
    all(feature = "codec-response", feature = "rx-response"),
    all(feature = "codec-response-final", feature = "rx-response"),
    feature = "rx-control"
))]
impl<'f, B: RecordBody<'f>> Pulled<'_, 'f, B> {
    /// Read the record's body into `view`, a binding of the caller's frame, and judge it by the
    /// owned rule; the refusal or the decode error of its kind when it is not admitted.
    pub(super) fn read(
        &self,
        view: &mut B::View,
    ) -> Result<(), crate::parse_error::InboundParseError> {
        self.records.read_body::<B>(self.at, view)
    }
}

/// How the body of one kind of record is read, and how the walk hands it over.
#[cfg(any(
    all(feature = "codec-push", feature = "rx-push"),
    feature = "codec-request",
    all(feature = "codec-response", feature = "rx-response"),
    all(feature = "codec-response-final", feature = "rx-response"),
    feature = "rx-control"
))]
pub(super) trait RecordBody<'f> {
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
pub(super) enum PushBody {}

#[cfg(all(feature = "codec-push", feature = "rx-push"))]
impl<'f> RecordBody<'f> for PushBody {
    type View = wz_codecs::push::PushView<'f>;
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
pub(super) enum RequestBody {}

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
pub(super) enum ResponseBody {}

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
pub(super) enum ResponseFinalBody {}

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
pub(super) enum DeclareBody {}

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
pub(super) enum InterestBody {}

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
pub(super) enum OamBody {}

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
    // skipped record ([`RecordView::Skipped`]).
    #[cfg(not(all(feature = "transport-stats", feature = "alloc")))]
    fn walked<'v>(_view: &'v Self::View) -> WalkedRecord<'v, 'f>
    where
        'f: 'v,
    {
        WalkedRecord::Skipped
    }
}

/// The body of the record handed out last, of kind `B`, read and dropped. Out of line and one per
/// kind, so the frame holds the one body only while it is read.
#[cfg(any(
    all(feature = "codec-push", feature = "rx-push"),
    feature = "codec-request",
    all(feature = "codec-response", feature = "rx-response"),
    all(feature = "codec-response-final", feature = "rx-response"),
    feature = "rx-control"
))]
#[inline(never)]
fn pass_body<'f, B: RecordBody<'f>>(
    records: &Records<'f>,
) -> Result<(), crate::parse_error::InboundParseError> {
    let mut body = B::View::default();
    records.read_body::<B>(records.at.get(), &mut body)
}
