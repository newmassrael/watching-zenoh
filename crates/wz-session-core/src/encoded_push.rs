// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A Push a router received, encoded once for its fan-out to leaf sessions.
//!
//! A client is a leaf: it is sent a Put under its key as a literal and naming no routing source
//! ([`LeafPush`]). The router made that message by copying the Put it received, re-keying the copy
//! and resetting its source ([`crate::push_build::reliteralize_push`],
//! [`crate::push_routing_context::set_push_source`]), once for every fan-out of an aliased Put or of
//! one that names a source. [`LeafPush::encode`] makes the same bytes without the copy: the received
//! Put is framed by the writer the session's own send uses, behind a literal head, and its own head
//! and routing source are then taken out of the bytes in place. Only the router reaches this
//! module, so a build without a fan-out links nothing of it and keeps the one Push writer it had.
//!
//! A Push is written header, key expression, extensions, body (`PushWire::encode_source` in
//! `out/wz-codecs/push.rs`), and only the header's `N` and `M` flags and the key expression depend
//! on the key form a destination is sent. So the encoding is kept split where the key expression
//! ends ([`EncodedPush`]): a session frames the head of its key form ([`PushHead`]) followed by the
//! extensions and body every session shares ([`SplicedPush`]), and what the send decides before it
//! builds a frame (the QoS, whether the payload is shared memory, the class the network counters
//! charge) is read off the Put once, when it is encoded, not by each session from a message.

use alloc::vec::Vec;

use sce_forge_runtime::codec::{CodecError, SceSink, VecSink};
use wz_codecs::ext_entry::ExtEntryWire;
use wz_codecs::wireexpr::{WireexprSource, WireexprVariantSource, WireexprWire};
use wz_codecs::wireexpr_local::{WireexprLocalParts, WireexprLocalWire};

use crate::ext_header::{ext_eid, EXT_FLAG_Z};
use crate::ext_nodeid::NODEID_EXT_HEADER;
use crate::sample::QosLevel;
use crate::wire::PushOwned;
use crate::wireexpr_resolve::id_and_suffix;

/// The `N` flag of the Push header: the key expression carries a suffix.
const FLAG_PUSH_N: u8 = 0x20;
/// The `M` flag of the Push header: the key expression's id is in the sender's mapping.
const FLAG_PUSH_M: u8 = 0x40;
/// The `Z` flag of the Push header: an extension chain follows the key expression.
const FLAG_PUSH_Z: u8 = 0x80;

/// A Push a router received, as it is delivered to a leaf: under its key as a literal, and naming
/// no routing source. The message [`Self::to_push`] makes, and the bytes [`Self::encode`] writes
/// without making it.
#[derive(Debug, Clone, Copy)]
pub struct LeafPush<'a> {
    received: &'a PushOwned,
    key: LeafKey<'a>,
    keyexpr: &'a str,
}

/// The key expression a leaf is sent.
#[derive(Debug, Clone, Copy)]
enum LeafKey<'a> {
    /// The received Push's own, already a literal, kept as it came as `reliteralize_push` keeps it.
    Own,
    /// The key the router resolved, as a literal.
    Literal(WireexprLocalParts<'a>),
}

impl<'a> LeafPush<'a> {
    /// `received` as it is delivered to a leaf under `keyexpr`, the key the router resolved it to.
    /// A Push whose key is already a literal keeps it, and `keyexpr` is not read for its bytes.
    /// `LengthOutOfRange` for a key past the protocol's `u16` length, which no literal carries.
    pub fn new(received: &'a PushOwned, keyexpr: &'a str) -> Result<Self, CodecError> {
        let (key, keyexpr) = match id_and_suffix(&received.keyexpr.body) {
            (0, own) => (LeafKey::Own, own.unwrap_or_default()),
            _ => (
                LeafKey::Literal(WireexprLocalParts {
                    id: 0,
                    suffix: Some(crate::codec_owned::sent_suffix(keyexpr)?),
                }),
                keyexpr,
            ),
        };
        Ok(Self {
            received,
            key,
            keyexpr,
        })
    }

    /// The Push as the router received it.
    pub fn received(&self) -> &'a PushOwned {
        self.received
    }

    /// Whether the received Push is already what a leaf is sent: a literal that names no source.
    pub fn is_as_received(&self) -> bool {
        matches!(self.key, LeafKey::Own)
            && !crate::push_routing_context::push_names_a_source(self.received)
    }

    /// The message a leaf is sent, made as a copy of the received Push: re-keyed and its source
    /// reset.
    pub fn to_push(&self) -> Result<PushOwned, CodecError> {
        let mut push = crate::push_build::reliteralize_push(self.received, self.keyexpr)?;
        crate::push_routing_context::set_push_source(&mut push, 0)?;
        Ok(push)
    }

    /// The bytes [`Self::to_push`]'s message encodes to, made without making the message.
    ///
    /// The received Push is encoded by the writer a session frames its own Push with
    /// (`frame_encode::push_body`), into the buffer the bytes are kept in, behind the head a literal
    /// key needs; its own head and its routing source are then taken out in place. The Push's
    /// writer is generic over the source it reads, so writing the leaf's message from a source of
    /// its own would link a second writer into every router, and routing the session's own send
    /// through that source would grow every build that sends a Push, which have no fan-out. The
    /// layout this edits is the one the writer has (`PushWire::write_source` in
    /// `out/wz-codecs/push.rs`): header, key expression, the extension entries in order, each
    /// with its chain flag set but the last's, then the body.
    pub fn encode(&self) -> EncodedPush {
        let push = self.received;
        let chain: &[crate::wire::parts::ExtEntryOwned] = push
            .extensions
            .as_deref()
            .map_or(&[], |chain| chain.as_slice());
        let kept = chain
            .iter()
            .filter(|entry| !names_the_source(entry.header))
            .count();
        let chained = if kept > 0 { FLAG_PUSH_Z } else { 0 };
        let received_head = WireexprWire::measure(&push.keyexpr).len().saturating_add(1);
        let literal_head = match &self.key {
            LeafKey::Own => 0,
            LeafKey::Literal(local) => WireexprLocalWire::measure(local).len().saturating_add(1),
        };
        let mut bytes = Vec::with_capacity(
            literal_head.saturating_add(crate::frame_encode::push_capacity_hint(push)),
        );
        if let LeafKey::Literal(local) = &self.key {
            // A literal is in the sender's mapping and carries its key as a suffix.
            bytes.push(
                (push.header & !(FLAG_PUSH_N | FLAG_PUSH_M | FLAG_PUSH_Z))
                    | FLAG_PUSH_N
                    | FLAG_PUSH_M
                    | chained,
            );
            match WireexprLocalWire::encode_source(local, &mut VecSink::new(&mut bytes)) {
                Ok(()) => {}
                Err(never) => match never {},
            }
        }
        {
            let mut sink = crate::tx_buf::TxSink::new(&mut bytes);
            crate::frame_encode::push_body(push)(&mut sink)
                .expect("a Vec grows, so its sink is infallible");
        }
        let tail_at = match self.key {
            LeafKey::Own => {
                // The received header, which the body's writer wrote first.
                if let Some(header) = bytes.first_mut() {
                    *header = (*header & !FLAG_PUSH_Z) | chained;
                }
                received_head
            }
            LeafKey::Literal(_) => literal_head,
        };
        // The extensions and the body move up over the received head and the entries left out.
        // Every offset below is inside the bytes just written: the entries move down, never up.
        let mut from = literal_head.saturating_add(received_head);
        let mut to = tail_at;
        let mut left = kept;
        for entry in chain {
            let len = ExtEntryWire::measure(entry).len();
            if !names_the_source(entry.header) {
                bytes.copy_within(from..from.saturating_add(len), to);
                left = left.saturating_sub(1);
                if let Some(header) = bytes.get_mut(to) {
                    *header = if left > 0 {
                        *header | EXT_FLAG_Z
                    } else {
                        *header & !EXT_FLAG_Z
                    };
                }
                to = to.saturating_add(len);
            }
            from = from.saturating_add(len);
        }
        let end = bytes.len();
        bytes.copy_within(from..end, to);
        bytes.truncate(to.saturating_add(end.saturating_sub(from)));
        #[cfg(feature = "transport-stats")]
        let keyexpr_at = tail_at.saturating_sub(self.keyexpr.len())..tail_at;
        #[cfg(feature = "transport-stats")]
        debug_assert_eq!(
            bytes.get(keyexpr_at.clone()),
            Some(self.keyexpr.as_bytes()),
            "a literal key expression ends with its key"
        );
        EncodedPush {
            bytes,
            tail_at,
            qos: crate::declare_ext_qos::read_push_qos(push),
            #[cfg(feature = "session-extshm")]
            shared_memory: carries_shared_memory(push),
            #[cfg(feature = "transport-stats")]
            class: crate::network_message::push_stats_class_under(push, self.keyexpr),
            #[cfg(feature = "transport-stats")]
            keyexpr_at,
        }
    }
}

/// Whether `push`'s payload is held in shared memory, whose slices are mapped for each peer inside
/// the transaction its message is built in, so that no two sessions can be sent the same bytes.
#[cfg(feature = "session-extshm")]
fn carries_shared_memory(push: &PushOwned) -> bool {
    match &push.body {
        crate::wire::PushOwnedVariant::CodecZenohMsgPut(put) => {
            !crate::put_payload::shm_descriptors(put).is_empty()
        }
        _ => false,
    }
}

/// Whether `header` is the routing source's, by the extension's identity, as
/// [`crate::ext_nodeid::set_source`] tells the entry it takes out.
fn names_the_source(header: u8) -> bool {
    ext_eid(header) == ext_eid(NODEID_EXT_HEADER)
}

/// A Push encoded once for every session of a fan-out, kept split where its key expression ends:
/// the header and key expression of the key form it was encoded under, then the extensions and the
/// body every key form shares. With it, what a session decides before it builds the frame, read
/// off the Push when it was encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedPush {
    bytes: Vec<u8>,
    tail_at: usize,
    qos: QosLevel,
    #[cfg(feature = "session-extshm")]
    shared_memory: bool,
    #[cfg(feature = "transport-stats")]
    class: crate::stats::NetworkStatsClass,
    /// Where the key's text is in `bytes`: the end of the literal key expression's suffix.
    #[cfg(feature = "transport-stats")]
    keyexpr_at: core::ops::Range<usize>,
}

impl EncodedPush {
    /// The whole Push, under the key form it was encoded under.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The extensions and the body, which every key form shares.
    pub fn tail(&self) -> &[u8] {
        // `tail_at` is where the encoder put the end of the head.
        self.bytes.get(self.tail_at..).unwrap_or_default()
    }

    /// The Push under the key form it was encoded under.
    pub fn spliced(&self) -> SplicedPush<'_> {
        SplicedPush {
            head: self.bytes.get(..self.tail_at).unwrap_or_default(),
            encoded: self,
        }
    }

    /// The header and key expression of the same Push under `key`, another key form of the same
    /// key (an id the destination's mapping holds, with or without a suffix): the header's `N` and
    /// `M` flags follow `key`, and the rest of it is the encoded Push's.
    pub fn head_for<K: WireexprSource + ?Sized>(&self, key: &K) -> PushHead {
        let n = WireexprWire::input_n(key);
        let m = matches!(
            WireexprSource::body(key),
            WireexprVariantSource::WireexprLocal(_)
        );
        // An encoded Push starts with its header.
        let header = (self.bytes.first().copied().unwrap_or_default()
            & !(FLAG_PUSH_N | FLAG_PUSH_M))
            | if n { FLAG_PUSH_N } else { 0 }
            | if m { FLAG_PUSH_M } else { 0 };
        let mut bytes = Vec::with_capacity(WireexprWire::measure(key).len().saturating_add(1));
        bytes.push(header);
        match WireexprWire::encode_source(key, &mut VecSink::new(&mut bytes)) {
            Ok(()) => {}
            Err(never) => match never {},
        }
        PushHead { bytes }
    }

    /// The Push under the key form `head` was made for by [`Self::head_for`].
    pub fn spliced_under<'e>(&'e self, head: &'e PushHead) -> SplicedPush<'e> {
        SplicedPush {
            head: &head.bytes,
            encoded: self,
        }
    }

    /// The Push's QoS, whose congestion control decides whether a send may be dropped.
    pub fn qos(&self) -> QosLevel {
        self.qos
    }

    /// Whether the Push's payload is held in shared memory, which a session maps for its own peer
    /// and so cannot be sent as shared bytes.
    #[cfg(feature = "session-extshm")]
    pub fn carries_shared_memory(&self) -> bool {
        self.shared_memory
    }

    /// The class the network counters charge the Push to, before a session matches it against its
    /// own `stats/filters`.
    #[cfg(feature = "transport-stats")]
    pub fn stats_class(&self) -> crate::stats::NetworkStatsClass {
        self.class
    }

    /// The key the Push is sent under, which a session's `stats/filters` are matched against.
    #[cfg(feature = "transport-stats")]
    pub fn keyexpr(&self) -> Option<&str> {
        core::str::from_utf8(self.bytes.get(self.keyexpr_at.clone())?).ok()
    }
}

/// The header and key expression of an [`EncodedPush`] under one key form
/// ([`EncodedPush::head_for`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushHead {
    bytes: Vec<u8>,
}

/// A Push as a session frames it: the head of the key form it is sent under, then the extensions
/// and the body it shares with every other session of the fan-out.
#[derive(Debug, Clone, Copy)]
pub struct SplicedPush<'e> {
    head: &'e [u8],
    encoded: &'e EncodedPush,
}

impl SplicedPush<'_> {
    /// What the send reads of the Push besides its bytes.
    pub fn encoded(&self) -> &EncodedPush {
        self.encoded
    }

    /// The bytes the Push is framed as.
    pub fn encoded_len(&self) -> usize {
        self.head.len().saturating_add(self.encoded.tail().len())
    }

    /// Write the Push into `sink`: its head, then what it shares.
    pub fn write<K: SceSink>(&self, sink: &mut K) -> Result<(), K::Error> {
        sink.write_bytes(self.head)?;
        sink.write_bytes(self.encoded.tail())
    }

    /// The bytes the Push is framed as, in a vector of their own.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        match self.write(&mut VecSink::new(&mut bytes)) {
            Ok(()) => {}
            Err(never) => match never {},
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext_header::EXT_ENC_ZBUF;
    use crate::push_build::{
        build_push_aliased, build_push_del_aliased, build_push_literal, reliteralize_push,
        set_push_timestamp,
    };
    use crate::push_routing_context::{push_names_a_source, set_push_source};
    use crate::wire::parts::{ExtEntryOwned, ExtEntryOwnedVariant, ExtZbufOwned};
    use alloc::string::String;
    use alloc::vec;
    use wz_codecs::ext_zint::ExtZint;

    const KEY: &str = "demo/leaf";
    const PAYLOAD: &[u8] = b"fan-out-payload";

    /// The routing source a Put names when it comes from a node of the mesh.
    fn source_entry() -> ExtEntryOwned {
        ExtEntryOwned {
            header: NODEID_EXT_HEADER,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value: 7 }),
        }
    }

    /// A QoS that blocks, as `set_push_qos` writes it.
    fn qos_entry() -> ExtEntryOwned {
        let mut scratch = build_push_literal(KEY, b"").expect("a literal push");
        crate::declare_ext_qos::set_push_qos(
            &mut scratch,
            QosLevel::DEFAULT.with_congestion(crate::qos::CongestionControl::Block),
        )
        .expect("a qos");
        scratch.extensions.as_deref().expect("a chain of the qos")[0].clone()
    }

    /// The Push timestamp extension (id 2, a ZBuf), which a router carries as it came.
    fn timestamp_entry() -> ExtEntryOwned {
        let value: &[u8] = &[0x81, 0x01, 0x03, 0xAA, 0xBB, 0xCC];
        ExtEntryOwned {
            header: 0x02 | EXT_ENC_ZBUF,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: value.len() as u64,
                value: crate::codec_owned::owned_bytes(value).expect("a short value"),
            }),
        }
    }

    /// `push` with `chain` as its extension chain, in that order.
    fn with_chain(mut push: PushOwned, chain: Vec<ExtEntryOwned>) -> PushOwned {
        crate::held_list::edit_chain(&mut push.extensions, |list| *list = Some(chain))
            .expect("a message's chain has no bound");
        push
    }

    /// The Puts a router fans out to leaves, each with the key a leaf is sent it under: a literal,
    /// an alias with no suffix, an alias with a suffix, and a Del under an alias; each with no
    /// extension, with each of a routing source, a QoS and a timestamp, and with them together
    /// in different orders, and a Put with a timestamp in its body too.
    fn received_puts() -> Vec<(String, PushOwned, &'static str)> {
        let sources: Vec<(&str, PushOwned, &'static str)> = vec![
            (
                "literal",
                build_push_literal(KEY, PAYLOAD).expect("a literal push"),
                KEY,
            ),
            (
                "alias",
                build_push_aliased(5, None, PAYLOAD).expect("an aliased push"),
                KEY,
            ),
            (
                "alias with suffix",
                build_push_aliased(5, Some("/x"), PAYLOAD).expect("an aliased push"),
                "demo/leaf/x",
            ),
            (
                "del under an alias",
                build_push_del_aliased(5, None).expect("an aliased del"),
                KEY,
            ),
        ];
        let chains: Vec<(&str, Vec<ExtEntryOwned>)> = vec![
            ("no extension", vec![]),
            ("source", vec![source_entry()]),
            ("qos", vec![qos_entry()]),
            ("timestamp", vec![timestamp_entry()]),
            (
                "qos, source, timestamp",
                vec![qos_entry(), source_entry(), timestamp_entry()],
            ),
            ("source, qos", vec![source_entry(), qos_entry()]),
            ("timestamp, source", vec![timestamp_entry(), source_entry()]),
        ];
        let mut cases = Vec::new();
        for (source, push, key) in &sources {
            for (chain, entries) in &chains {
                let case = alloc::format!("{source}, {chain}");
                cases.push((case, with_chain(push.clone(), entries.clone()), *key));
            }
        }
        let mut stamped = with_chain(
            build_push_aliased(5, None, PAYLOAD).expect("an aliased push"),
            vec![source_entry(), qos_entry()],
        );
        // A build without `pubsub-timestamp` leaves the body as it is, and the case is the one before.
        let _ = set_push_timestamp(
            &mut stamped,
            &crate::sample::TimestampHint {
                time: 0x0123_4567,
                zid: vec![0xAA, 0xBB],
            },
        )
        .expect("a timestamp fits");
        cases.push((String::from("alias, body timestamp"), stamped, KEY));
        cases
    }

    /// What a leaf is sent: the received Push copied, re-keyed and its source reset.
    fn leaf_message(received: &PushOwned, keyexpr: &str) -> PushOwned {
        let mut push = reliteralize_push(received, keyexpr).expect("re-keyed");
        set_push_source(&mut push, 0).expect("the source taken out");
        push
    }

    /// The bytes written from a received Push are the encoding of the message a leaf is sent,
    /// whatever key it named and whatever extensions it carried, and the spliced frame (the head
    /// followed by what is shared) is the same bytes. Turned red by a writer that keeps the
    /// routing source, keeps the received key, leaves a header flag of the received key form, or
    /// splits the head anywhere but where the key expression ends.
    #[test]
    fn a_leaf_push_encodes_to_the_message_a_leaf_is_sent() {
        for (case, received, keyexpr) in received_puts() {
            let leaf = LeafPush::new(&received, keyexpr).expect("a literal key");
            let message = leaf_message(&received, keyexpr);
            assert!(!push_names_a_source(&message), "{case}");
            assert_eq!(
                leaf.to_push().expect("the message"),
                message,
                "{case}: the message made"
            );
            let full = message.encode_to_vec();
            let encoded = leaf.encode();
            assert_eq!(encoded.as_bytes(), &full[..], "{case}: the whole encoding");
            let spliced = encoded.spliced();
            assert_eq!(spliced.to_vec(), full, "{case}: the spliced frame");
            assert_eq!(spliced.encoded_len(), full.len(), "{case}");
            assert!(
                full.ends_with(encoded.tail()),
                "{case}: the shared part is the end of the message"
            );
            let head_len = full.len() - encoded.tail().len();
            assert_eq!(
                head_len,
                1 + WireexprWire::measure(&message.keyexpr).len(),
                "{case}: the head is the header and the key expression"
            );
        }
    }

    /// What the send decides before it frames the bytes is read off the received Push when it is
    /// encoded, and is what the message a leaf is sent would give it. Turned red by a QoS, a
    /// class or a key read from anything but the Put the bytes are of.
    #[test]
    fn a_leaf_push_carries_what_the_send_decides_by() {
        for (case, received, keyexpr) in received_puts() {
            let message = leaf_message(&received, keyexpr);
            let encoded = LeafPush::new(&received, keyexpr)
                .expect("a literal key")
                .encode();
            assert_eq!(
                encoded.qos(),
                crate::declare_ext_qos::read_push_qos(&message),
                "{case}"
            );
            #[cfg(feature = "session-extshm")]
            assert!(!encoded.carries_shared_memory(), "{case}");
            #[cfg(feature = "transport-stats")]
            {
                assert_eq!(
                    encoded.stats_class(),
                    crate::network_message::push_stats_class(&message, |_| None),
                    "{case}"
                );
                assert_eq!(encoded.keyexpr(), Some(keyexpr), "{case}");
            }
        }
    }

    /// The same Push under another key form a destination's mapping holds is the encoded tail
    /// behind the head of that form: a literal, an id, and an id with a suffix. Turned red by a
    /// head whose `N` or `M` flag does not follow its key form, or one that drops a flag of the
    /// header it was made from.
    #[test]
    fn a_head_of_another_key_form_splices_into_that_forms_message() {
        let forms = [
            (
                "literal",
                build_push_literal(KEY, b"").expect("a literal").keyexpr,
            ),
            (
                "id",
                build_push_aliased(9, None, b"").expect("an id").keyexpr,
            ),
            (
                "id with suffix",
                build_push_aliased(9, Some("/x"), b"")
                    .expect("an id with a suffix")
                    .keyexpr,
            ),
        ];
        for (case, received, keyexpr) in received_puts() {
            let message = leaf_message(&received, keyexpr);
            let encoded = LeafPush::new(&received, keyexpr)
                .expect("a literal key")
                .encode();
            for (form, key) in &forms {
                let mut under = message.clone();
                under.keyexpr = key.clone();
                let head = encoded.head_for(key);
                assert_eq!(
                    encoded.spliced_under(&head).to_vec(),
                    under.encode_to_vec(),
                    "{case}, under {form}"
                );
            }
        }
    }

    /// A Push under an id of the receiver's mapping is re-keyed as one under the sender's: the head
    /// that is cut out is the received one, whatever its length and its `M` flag, and a literal
    /// in that arm keeps its own head. Turned red by an encoding that cuts the head by the length
    /// of the key it writes, or that takes the received `M` flag for the literal's.
    #[test]
    fn a_receiver_mapped_push_is_re_keyed_from_its_own_head() {
        let nonlocal = |id: u16, suffix: &str| {
            let mut push = build_push_aliased(5, Some("/x"), PAYLOAD).expect("an aliased push");
            push.keyexpr = crate::wire::parts::WireexprOwned {
                body: crate::wire::parts::WireexprOwnedVariant::WireexprNonlocal(
                    crate::wire::parts::WireexprNonlocalOwned {
                        id,
                        suffix_len: Some(suffix.len() as u64),
                        suffix: Some(crate::wire::wire_string(suffix).expect("a short suffix")),
                    },
                ),
            };
            push
        };
        let cases = [
            ("receiver-mapped id", nonlocal(5, "/x"), "demo/leaf/x"),
            ("receiver-mapped literal", nonlocal(0, KEY), KEY),
        ];
        for (case, push, keyexpr) in cases {
            for (chain, entries) in [
                ("no extension", vec![]),
                ("qos, source", vec![qos_entry(), source_entry()]),
            ] {
                let received = with_chain(push.clone(), entries);
                let encoded = LeafPush::new(&received, keyexpr)
                    .expect("a literal key")
                    .encode();
                assert_eq!(
                    encoded.as_bytes(),
                    &leaf_message(&received, keyexpr).encode_to_vec()[..],
                    "{case}, {chain}"
                );
            }
        }
    }

    /// A received literal that names no source is already what a leaf is sent, and its key is its
    /// own whatever key it is given; a literal that names a source and any aliased Put are not.
    /// Turned red by a literal re-keyed to the key it is handed, or a Put that names a source
    /// taken as it came.
    #[test]
    fn only_a_literal_that_names_no_source_is_sent_as_it_came() {
        let literal = build_push_literal(KEY, PAYLOAD).expect("a literal push");
        let leaf = LeafPush::new(&literal, "ignored/key").expect("its own key");
        assert!(leaf.is_as_received());
        assert_eq!(leaf.encode().as_bytes(), &literal.encode_to_vec()[..]);
        let sourced = with_chain(literal.clone(), vec![source_entry()]);
        assert!(!LeafPush::new(&sourced, KEY)
            .expect("its own key")
            .is_as_received());
        let aliased = build_push_aliased(5, None, PAYLOAD).expect("an aliased push");
        assert!(!LeafPush::new(&aliased, KEY)
            .expect("a literal key")
            .is_as_received());
    }

    /// A key past the protocol's `u16` length is refused for a Put that must be re-keyed to it,
    /// as the copy that re-keys it refuses it; a literal keeps its own key and is not refused.
    /// Turned red by a leaf Push that writes a key no literal carries.
    #[test]
    fn a_key_no_literal_carries_is_refused() {
        let long = "k".repeat(usize::from(u16::MAX) + 1);
        let aliased = build_push_aliased(5, None, PAYLOAD).expect("an aliased push");
        assert_eq!(
            LeafPush::new(&aliased, &long).err(),
            Some(CodecError::LengthOutOfRange)
        );
        assert!(
            reliteralize_push(&aliased, &long).is_err(),
            "the copy agrees"
        );
        let literal = build_push_literal(KEY, PAYLOAD).expect("a literal push");
        assert!(LeafPush::new(&literal, &long).is_ok());
    }
}
