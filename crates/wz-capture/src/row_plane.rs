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
//! The tree of a row with no batch is walked from the bytes this crate keeps,
//! which a stream flow keeps and a datagram flow does not (the caller holds the
//! packet), so a path term over a datagram flow's transport message is
//! undecided in every document alike.
//!
//! # What stays unjudged
//!
//! A row whose message did not decode carries nothing a term can read, and a
//! row this plane cannot tell holds no record is not one it may call empty: it
//! stays `unjudged`. A batch whose walk stopped part way adds one UNDECIDED
//! record to its row: the bytes after the stop may hold the record the
//! selector asks for.

use alloc::collections::BTreeMap;

use crate::filter::{Content, Filter, MessageNames, Record, RecordView, Truth};
use crate::payload::{RowKey, RowVerdict};
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
        for (flow, list, packet, row) in d.message_frames_in_capture_order() {
            let frame: &PassiveFrame = &row;
            let ctx = grouping.context(list).placed(flow, Some(packet));
            let key = RowKey::of(list, frame);
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
                _ => {
                    // A frame that carried no batch IS its row's message. The
                    // bytes of a stream flow's message are kept; a datagram
                    // flow's are the caller's.
                    let bytes = d
                        .flows()
                        .get(list)
                        .filter(|f| f.flow == flow)
                        .and_then(|f| f.message_bytes(&row).ok());
                    plane.whole(&base, key, bytes.as_deref());
                }
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
        for (record, (message, span)) in batch.records().enumerate() {
            if judged_by_a_census_plane(message, exchanges, &key, record) {
                continue;
            }
            let names = MessageNames::of(base.frame, Some(message.name()));
            let tree = if base.filter.reads_tree() {
                crate::field_path::record_tree(base.frame, span)
            } else {
                None
            };
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
            );
            self.rows.entry(key).or_default().record(truth);
        }
        if batch.halt.is_some() {
            self.rows.entry(key).or_default().record(Truth::Unknown);
        }
    }

    /// A row that is one message and no batch.
    fn whole(&mut self, base: &Base<'_>, key: RowKey, bytes: Option<&[u8]>) {
        // A message that did not decode is not one this plane may call empty.
        if base.frame.frame.is_err() {
            return;
        }
        let names = MessageNames::of(base.frame, None);
        let tree = if base.filter.reads_tree() {
            bytes.and_then(|b| wz_session_core::dissect::dissect_transport_message(b, 0).ok())
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
            Record::None,
            base.frame.direction,
            &names,
            tree.as_ref(),
            offset,
        );
        self.rows.entry(key).or_default().record(truth);
    }
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
        tree: Option<&crate::field_path::TreeNode>,
        unit_offset: Option<u64>,
    ) -> Truth {
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
            row: self.ctx.row_facts(names.as_slice(), self.frame.direction),
        })
    }
}
