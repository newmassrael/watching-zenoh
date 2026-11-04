// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE ROW PLANE: what a selector says about the messages no census plane
//! judges, so every row of a document is judged.
//!
//! # What the census planes leave
//!
//! The payload plane judges a `Push` and a `Response` as records and the
//! exchange plane a `Request` and the `ResponseFinal` that closes it. Every
//! other message was never asked: a `Declare`, an `Interest`, a network `Oam`,
//! a `ResponseFinal` whose request the capture does not hold, and every
//! transport message that carries no batch (`Init`, `Open`, `Close`,
//! `KeepAlive`, `Join`, a `Fragment`, a transport `Oam`). Their rows read
//! `unjudged` under every selector, so `msg == Declare` or
//! `decl_subscriber.keyexpr.suffix contains "x"` had nothing to answer them.
//!
//! This plane judges each of them as a ROW THAT CARRIES NO RECORD
//! ([`crate::filter::RecordView::kind`] is `None`): its own facts (`dir`,
//! `zid`, `time`, `elapsed`, `offset`, its row facts and the paths into its
//! own tree) answer as a record's do, and every term about a record is the
//! decided answer a field the row does not carry gives.
//!
//! # One walk per capture, before any document is rendered
//!
//! Judged here, beside the census planes, and NOT by a document renderer
//! while it writes a row: the field document and the selection document must
//! say the same word for one row, and only the first holds the capture's bytes.
//! The tree of a row with no batch, and the `Frame` around a batch's records,
//! are walked from the bytes this crate can read of the message
//! (`CaptureOrder::held_message_bytes`): a stream flow's retained stream, and a
//! datagram list's own unit bytes, which it reads its rows again from. Where
//! neither holds them (trimmed, or a container this call was not lent) a path
//! term over the transport message is undecided, in every document alike.
//!
//! # A message the session could not decode
//!
//! Its row still shows the tree the field walker reads from its bytes, under
//! the name its MID gives it, so a selector reads the same: its row facts, its
//! name, and the paths into that tree. What it carried is not known where its
//! MID is one that carries records (a `Frame`, a `Fragment`), so every record
//! term over it is undecided there; any other transport message carries none.
//!
//! # What stays unjudged
//!
//! A row whose message did not decode and whose bytes the capture does not
//! keep carries nothing a term can read, not even what it is: it stays
//! `unjudged`.
//!
//! # The part of a batch past where its walk stopped
//!
//! It may hold the record the selector asks for, so it adds one record to its
//! row, judged as a record that was not read standing in the frame's transport
//! message ([`crate::field_path::Envelope::Remainder`]): the row's facts and the
//! paths through that message are decided, and every term about the record,
//! its name (`msg`) included, is undecided.

use alloc::collections::BTreeMap;

use crate::filter::{Content, Filter, MessageNames, Record, RecordView, Truth};
use crate::payload::{RowKey, RowVerdict};
use wz_session_core::dissect::MessageName;
use wz_session_core::network_message::{BatchParse, NetworkMessage};
use wz_session_core::passive::{Carried, PassiveFrame};

/// The verdicts of the rows (and the records in them) no census plane judged.
#[derive(Debug, Default, Clone)]
pub(crate) struct RowPlane {
    rows: BTreeMap<RowKey, RowVerdict>,
}

impl RowPlane {
    /// Judge every message of `d` the census planes leave, against `filter`
    /// (already read against the capture's zids). `exchanges` is the exchange
    /// plane's walk over the same selector: a `ResponseFinal` it paired with a
    /// request is that plane's to judge.
    pub(crate) fn of(
        d: &crate::Dissection,
        filter: &Filter,
        grouping: &crate::node::SessionGrouping,
        exchanges: &crate::exchange::ExchangeTable,
    ) -> Self {
        let mut plane = Self::default();
        let origin = d.capture_origin_ms();
        let order = d.message_frames_in_capture_order();
        for (flow, list, packet, row) in order.iter() {
            let frame: &PassiveFrame = &row;
            // The transport message's bytes, where the capture keeps them and a
            // path term reads them: a row with no batch is that message, and a
            // batch's records stand inside it. A message the session could not
            // decode is named from them whatever the selector reads.
            let held = (filter.reads_tree() || frame.frame.is_err())
                .then(|| order.held_message_bytes(d, list, &row))
                .flatten();
            let ctx = grouping
                .context(list)
                .placed(flow, Some(packet))
                .holding(held.as_deref());
            let key = RowKey::of(list, &row);
            let base = Base {
                filter,
                ctx,
                frame,
                origin,
            };
            match &frame.carried {
                Carried::Batch(batch) => plane.batch(&base, key, batch, exchanges),
                #[cfg(feature = "reassembly")]
                Carried::Reassembled { batch, .. } => plane.batch(&base, key, batch, exchanges),
                // A frame that carried no batch IS its row's message, read from
                // the bytes the capture keeps of it; a datagram's are the
                // caller's.
                _ => plane.whole(&base, key, held.as_deref()),
            }
        }
        plane
    }

    /// The verdicts this plane recorded for one row.
    pub(crate) fn row_verdict(&self, key: &RowKey) -> Option<&RowVerdict> {
        self.rows.get(key)
    }

    /// Every record of a batch no census plane judges, and the walk's stop.
    fn batch(
        &mut self,
        base: &Base<'_>,
        key: RowKey,
        batch: &BatchParse,
        exchanges: &crate::exchange::ExchangeTable,
    ) {
        let envelope = crate::field_path::envelope_for(base.filter, base.frame, base.ctx);
        for (record, (message, span)) in batch.records().enumerate() {
            if judged_by_a_census_plane(message, exchanges, &key, record) {
                continue;
            }
            // A MID no codec knows is where the session's walk stopped: its
            // bytes are the batch's unread remainder, judged once, below.
            if matches!(message, NetworkMessage::Unknown { .. }) {
                continue;
            }
            let names = MessageNames::of(base.frame, Some(message.name()));
            let tree = crate::field_path::RecordAt::new(span, envelope.as_ref()).tree(base.frame);
            // A close the exchange plane could not pair answers its record
            // terms as the request it closes, which the capture does not hold:
            // they are undecided, never `no`. Every other message here is a
            // row with no record.
            //
            // Its `dir` is the requester's all the same, which is the one record
            // fact it can name: a close travels back to the end that asked, as
            // the exchange plane reads a paired close's direction.
            let (record, direction) = match message {
                NetworkMessage::ResponseFinal(_) => (Record::Unread, base.frame.direction.peer()),
                _ => (Record::None, base.frame.direction),
            };
            let truth = base.judge(
                record,
                direction,
                &names,
                tree.as_ref(),
                crate::agg::record_unit_offset(base.frame, span),
                Remainder::Read,
            );
            self.rows.entry(key).or_default().record(truth);
        }
        if crate::field_path::has_an_unread_remainder(envelope.as_ref(), batch) {
            // The part past the stop may hold the record a selector asks
            // about. It stands in the frame's transport message all the same,
            // so it is judged as a record that was not read, inside that
            // message: a term about the message is decided there, and a term
            // about the record, its name included, is not.
            let tree = envelope
                .as_ref()
                .and_then(|e| crate::field_path::remainder_tree(base.frame, e, batch));
            let truth = base.judge(
                Record::Unread,
                base.frame.direction,
                &MessageNames::of(base.frame, None),
                tree.as_ref(),
                None,
                Remainder::Unread,
            );
            self.rows.entry(key).or_default().record(truth);
        } else if batch.records().next().is_none() {
            // A batch read to its end that held no record (a `Frame` of
            // extensions alone, an empty `Fragment` body): the row is its
            // transport message and carries no record, as a row with no batch.
            let tree = envelope
                .as_ref()
                .and_then(crate::field_path::empty_batch_tree);
            let truth = base.judge(
                Record::None,
                base.frame.direction,
                &MessageNames::of(base.frame, None),
                tree.as_ref(),
                None,
                Remainder::Read,
            );
            self.rows.entry(key).or_default().record(truth);
        }
    }

    /// A row that is one message and no batch.
    fn whole(&mut self, base: &Base<'_>, key: RowKey, bytes: Option<&[u8]>) {
        let (names, record) = match &base.frame.frame {
            Ok(_) => (MessageNames::of(base.frame, None), Record::None),
            // A message the session could not decode is read as the field
            // document reads it: walked from the bytes the capture keeps of it,
            // and named by its MID. What it carried is not known where its MID
            // is one that carries records, so a record term over it is
            // undecided there; any other transport message carries none.
            // The MID is the header's low five bits, as every reader of a
            // transport header takes it.
            Err(_) => match bytes
                .and_then(|b| b.first())
                .and_then(|b| MessageName::of_transport(b & 0x1f))
            {
                Some(message) => (
                    MessageNames::one(message.name()),
                    if carries_records(message) {
                        Record::Unread
                    } else {
                        Record::None
                    },
                ),
                // Without its bytes nothing is known of it, not even what it
                // is, and the row stays unjudged.
                None => return,
            },
        };
        let tree = if base.filter.reads_tree() {
            bytes
                .and_then(|b| wz_session_core::dissect::dissect_transport_message(b, 0).ok())
                .map(crate::field_path::RecordTree::transport)
        } else {
            None
        };
        // Where the message began in its framing unit; a message decompressed
        // out of an lz4 body has no such place on the wire.
        let offset = base
            .frame
            .decompressed
            .is_none()
            .then_some(base.frame.unit_offset as u64);
        let truth = base.judge(
            record,
            base.frame.direction,
            &names,
            tree.as_ref(),
            offset,
            Remainder::Read,
        );
        self.rows.entry(key).or_default().record(truth);
    }
}

/// Whether what is judged is the unread part of a batch, whose messages no
/// reader named ([`crate::filter::RowFacts::unread_remainder`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Remainder {
    /// A message that was read, whose names are all known.
    Read,
    /// The part of a batch past where its walk stopped.
    Unread,
}

/// Whether a transport message of this kind carries network records: a
/// `Frame` its batch, a `Fragment` a piece of one.
fn carries_records(message: MessageName) -> bool {
    matches!(message, MessageName::Frame | MessageName::Fragment)
}

/// Whether a census plane judges this record: the payload plane every record
/// it classifies as traffic, the exchange plane a request and the close it
/// paired with one.
fn judged_by_a_census_plane(
    message: &NetworkMessage,
    exchanges: &crate::exchange::ExchangeTable,
    key: &RowKey,
    record: usize,
) -> bool {
    match message {
        NetworkMessage::ResponseFinal(_) => exchanges.closing(key, record).is_some(),
        _ => crate::agg::classify(message).is_some(),
    }
}

/// What every judgement of one frame shares.
struct Base<'a> {
    filter: &'a Filter,
    ctx: crate::node::ListContext<'a>,
    frame: &'a PassiveFrame,
    origin: Option<u64>,
}

impl Base<'_> {
    /// Judge one record-less message of this frame.
    ///
    /// `direction` is the RECORD's (`dir`, `zid`); the row facts are always the
    /// frame's own, so `src` is the end that sent this row.
    fn judge(
        &self,
        record: Record,
        direction: wz_session_core::passive::Direction,
        names: &MessageNames,
        tree: Option<&crate::field_path::RecordTree>,
        unit_offset: Option<u64>,
        remainder: Remainder,
    ) -> Truth {
        let row = self
            .ctx
            .row_facts(names.as_slice(), self.frame.direction)
            .map(|facts| match remainder {
                Remainder::Read => facts,
                Remainder::Unread => facts.with_an_unread_remainder(),
            });
        self.filter.matches(&RecordView {
            direction,
            keyexpr: None,
            kind: record,
            payload_bytes: None,
            value: Content::Unavailable,
            observed_at_ms: self.frame.observed_at_ms,
            elapsed_ms: crate::agg::elapsed_since(self.origin, self.frame.observed_at_ms),
            unit_offset,
            source_delay_ms: None,
            outcome: None,
            zid: self.ctx.zid(direction),
            tree,
            row,
        })
    }
}
