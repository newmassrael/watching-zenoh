// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.2 -- a Push delivered where its frame lies.
//!
//! The fixed-memory MCU profile's receive path (`drive::dispatch_datagram`,
//! `wz-runtime-coop`'s `rx-in-place`) decodes a Push record over the datagram
//! the link lends and hands it over as
//! [`IterationEvent::InPlace`](crate::driver_loop::IterationEvent::InPlace)
//! instead of projecting it into
//! a boxed owned message. This module is the subscriber side of that: the
//! keyexpr is resolved without a `String`
//! ([`resolve_wireexpr_view`]), the payload, attachment and every
//! extension are read where they lie, and the subscribers are handed a
//! [`SampleView`] over those bytes ([`LentSample`]) through the same matcher
//! and the same sinks the owned path uses. A subscriber's contract was already
//! a view borrowed for the call ([`SampleSink::deliver`]), so no subscriber
//! changes; one that keeps the sample copies it
//! ([`Sample::from_view`](crate::sample::Sample::from_view)).
//!
//! What it delivers is what [`SubscriberRegistry::dispatch_push`] delivers for
//! the owned projection of the same record, field for field: the keyexpr by
//! the same resolution rule, the kind, the payload, the reliability, and under
//! the same features the QoS, attachment, source info, timestamp and encoding,
//! with the same self-echo rule. The two timestamp and encoding hints own heap
//! fields (a zid vector, a schema string), so they are built only when a
//! subscriber asks for them, once per delivery.
//!
//! Two kinds of Put are not represented lent and take the owned projection
//! instead, counted in [`InPlaceFallbacks`]: a Put whose payload is a list of
//! slices (joined or resolved into a buffer of its own by
//! `put_payload::collect_wire_payload`), and a Put whose resolved keyexpr is
//! longer than [`crate::wireexpr_resolve::KeyexprBuf`], which only
//! the fixed bounded backing refuses. Each is still delivered, as the copying
//! path delivers it.

#[cfg(feature = "alloc")]
use core::cell::OnceCell;

use wz_codecs::encoding::Encoding;
use wz_codecs::push::{Push, PushVariant};
use wz_codecs::timestamp::Timestamp;

use super::{fire_into, SubscriberPeer, SubscriberTable};
use crate::bounded::Storage;
use crate::driver_loop::InPlaceRecord;
use crate::reliability::Reliability;
#[cfg(feature = "alloc")]
use crate::sample::{EncodingHint, TimestampHint};
use crate::sample::{QosLevel, SourceInfo};
use crate::sample_kind::SampleKind;
use crate::sink::{SampleSink, SampleView};
use crate::wireexpr_resolve::{resolve_wireexpr_view, KeyexprBuf, KeyexprPastBound};

/// The sample a Push read in place is delivered as: every field a range of the
/// frame or a value read off it, valid for the delivery call.
struct LentSample<'s> {
    keyexpr: &'s str,
    payload: &'s [u8],
    kind: SampleKind,
    reliability: Reliability,
    qos: Option<QosLevel>,
    attachment: Option<&'s [u8]>,
    source_info: Option<SourceInfo>,
    timestamp: Option<&'s Timestamp<'s>>,
    #[cfg(feature = "alloc")]
    timestamp_hint: OnceCell<TimestampHint>,
    encoding: Option<&'s Encoding<'s>>,
    #[cfg(feature = "alloc")]
    encoding_hint: OnceCell<EncodingHint>,
}

impl SampleView for LentSample<'_> {
    fn keyexpr(&self) -> &str {
        self.keyexpr
    }
    fn payload(&self) -> &[u8] {
        self.payload
    }
    fn kind(&self) -> SampleKind {
        self.kind
    }
    fn reliability(&self) -> Reliability {
        self.reliability
    }
    fn qos(&self) -> Option<QosLevel> {
        self.qos
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.attachment
    }
    #[cfg(feature = "alloc")]
    fn timestamp(&self) -> Option<&TimestampHint> {
        let ts = self.timestamp?;
        Some(
            self.timestamp_hint
                .get_or_init(|| TimestampHint::from_view(ts)),
        )
    }
    #[cfg(feature = "alloc")]
    fn encoding(&self) -> Option<&EncodingHint> {
        let encoding = self.encoding?;
        Some(
            self.encoding_hint
                .get_or_init(|| EncodingHint::from_view(encoding)),
        )
    }
    // The parts are the wire's own fields, read where they lie: nothing is built to
    // answer, so this is the accessor a build with no allocator has.
    fn timestamp_parts(&self) -> Option<(u64, &[u8])> {
        self.timestamp.map(|ts| (ts.time, ts.zid))
    }
    fn encoding_parts(&self) -> Option<(u32, Option<&str>)> {
        self.encoding
            .map(|encoding| (encoding.packed_id, encoding.schema))
    }
    fn source_info(&self) -> Option<&SourceInfo> {
        self.source_info.as_ref()
    }
    // `attachment_shared` and `payload_shared` keep their `None` defaults: the
    // bytes are the link's, lent for the call, and a subscriber that keeps them
    // copies them, as it does a `BorrowedSample`.
}

/// The body-level fields of a Put or a Del read in place, before the keyexpr is
/// known: what `dispatch_push`'s body match projects, on the lent form.
struct LentBody<'s> {
    kind: SampleKind,
    payload: &'s [u8],
    timestamp: Option<&'s Timestamp<'s>>,
    encoding: Option<&'s Encoding<'s>>,
    attachment: Option<&'s [u8]>,
    source_info: Option<SourceInfo>,
}

/// Why a Push read in place is delivered through its owned projection instead.
enum Fallback {
    /// Its payload is a list of slices. Only a Put has one.
    #[cfg(feature = "pubsub-put")]
    Sliced,
    /// Its keyexpr does not fit the bounded buffer.
    KeyexprPastBound,
}

/// The body of `push` as a lent sample delivers it, `Ok(None)` for a body the
/// owned path drops too (an unknown body tag, or a kind this build does not
/// deliver), and the fallback for a Put whose payload is sliced.
fn lent_body<'s>(push: &'s Push<'s>) -> Result<Option<LentBody<'s>>, Fallback> {
    match &push.body {
        #[cfg(feature = "pubsub-put")]
        PushVariant::CodecZenohMsgPut(put) => {
            if put.slices.is_some() {
                return Err(Fallback::Sliced);
            }
            let exts: &[wz_codecs::ext_entry::ExtEntry<'s>] =
                put.extensions.as_deref().unwrap_or(&[]);
            #[cfg(not(any(feature = "pubsub-attachment", feature = "pubsub-source-info")))]
            let _ = exts;
            Ok(Some(LentBody {
                kind: SampleKind::Put,
                // A Put with neither layout populated is an empty inline payload,
                // as `put_payload::layout` reads it.
                payload: put.payload.unwrap_or(&[]),
                #[cfg(feature = "pubsub-timestamp")]
                timestamp: put.timestamp.as_ref(),
                #[cfg(not(feature = "pubsub-timestamp"))]
                timestamp: None,
                #[cfg(feature = "pubsub-encoding")]
                encoding: put.encoding.as_ref(),
                #[cfg(not(feature = "pubsub-encoding"))]
                encoding: None,
                #[cfg(feature = "pubsub-attachment")]
                attachment: crate::attachment::decode_attachment_ext(
                    exts,
                    crate::attachment::ATTACHMENT_EXT_ID_PUSH,
                ),
                #[cfg(not(feature = "pubsub-attachment"))]
                attachment: None,
                #[cfg(feature = "pubsub-source-info")]
                source_info: crate::sample::extract_source_info(exts),
                #[cfg(not(feature = "pubsub-source-info"))]
                source_info: None,
            }))
        }
        #[cfg(feature = "pubsub-delete")]
        PushVariant::CodecZenohMsgDel(del) => {
            let exts: &[wz_codecs::ext_entry::ExtEntry<'s>] =
                del.extensions.as_deref().unwrap_or(&[]);
            #[cfg(not(any(feature = "pubsub-attachment", feature = "pubsub-source-info")))]
            let _ = exts;
            Ok(Some(LentBody {
                kind: SampleKind::Del,
                payload: &[],
                #[cfg(feature = "pubsub-timestamp")]
                timestamp: del.timestamp.as_ref(),
                #[cfg(not(feature = "pubsub-timestamp"))]
                timestamp: None,
                // Encoding is Put-only on the wire.
                encoding: None,
                #[cfg(feature = "pubsub-attachment")]
                attachment: crate::attachment::decode_attachment_ext(
                    exts,
                    crate::attachment::ATTACHMENT_EXT_ID_DEL,
                ),
                #[cfg(not(feature = "pubsub-attachment"))]
                attachment: None,
                #[cfg(feature = "pubsub-source-info")]
                source_info: crate::sample::extract_source_info(exts),
                #[cfg(not(feature = "pubsub-source-info"))]
                source_info: None,
            }))
        }
        // An unknown body tag is neither a confirmed Put nor a confirmed Del,
        // and a kind this build does not deliver is dropped, as the owned path
        // drops both.
        _ => Ok(None),
    }
}

impl<C: SampleSink, P: Storage> SubscriberTable<C, P> {
    /// Deliver a Push the in-place receive path lent: the subscriber side of
    /// [`IterationEvent::InPlace`](crate::driver_loop::IterationEvent::InPlace).
    /// See the module docs for what it delivers and what it hands to the owned
    /// projection.
    ///
    /// `peer` is the sending peer's side: whose aliases the keyexpr resolves
    /// through and whose zid names a self-echo.
    pub(super) fn dispatch_in_place(
        &mut self,
        peer: &SubscriberPeer<P>,
        record: &InPlaceRecord<'_>,
    ) {
        // A lent Request or Response is the queryables' or the pending gets'.
        let Some(push) = record.push() else {
            return;
        };
        let reliability = Reliability::from_reliable_bool(record.reliable());
        match self.deliver_lent(peer, push, reliability) {
            Ok(()) => {}
            #[cfg(feature = "pubsub-put")]
            Err(Fallback::Sliced) => {
                self.in_place_fallbacks.sliced = self.in_place_fallbacks.sliced.saturating_add(1);
                #[cfg(feature = "alloc")]
                self.dispatch_owned_projection(peer, push, reliability);
            }
            Err(Fallback::KeyexprPastBound) => {
                self.in_place_fallbacks.keyexpr_past_bound =
                    self.in_place_fallbacks.keyexpr_past_bound.saturating_add(1);
                #[cfg(feature = "alloc")]
                self.dispatch_owned_projection(peer, push, reliability);
            }
        }
    }

    /// The lent delivery itself: nothing on the heap for a Put whose keyexpr
    /// fits, short of a timestamp or encoding hint a subscriber asks for.
    fn deliver_lent(
        &mut self,
        peer: &SubscriberPeer<P>,
        push: &Push<'_>,
        reliability: Reliability,
    ) -> Result<(), Fallback> {
        let Some(body) = lent_body(push)? else {
            return Ok(());
        };
        // The keyexpr may be the peer table's own literal, so the table stays
        // borrowed through the delivery; the subscribers are a field of their
        // own (`fire_into`). A composed keyexpr lies in `composed`, in this
        // frame: fixed on the fixed backing, an empty string until written on
        // the growable one.
        let spaces = peer.mapping_spaces();
        let mut composed = KeyexprBuf::new();
        let keyexpr = match resolve_wireexpr_view(&push.keyexpr.body, spaces, &mut composed) {
            Ok(Some(keyexpr)) => keyexpr,
            // The empty keyexpr, or an id the space does not hold: dropped, as
            // the owned path drops it. A sliced Put never reaches here, so
            // there are no shared-memory slices to settle.
            Ok(None) => return Ok(()),
            Err(KeyexprPastBound) => return Err(Fallback::KeyexprPastBound),
        };
        let outer: &[wz_codecs::ext_entry::ExtEntry<'_>] =
            push.extensions.as_deref().unwrap_or(&[]);
        #[cfg(feature = "pubsub-qos")]
        let qos = crate::sample::extract_qos_in(outer);
        #[cfg(not(feature = "pubsub-qos"))]
        let qos: Option<QosLevel> = {
            let _ = outer;
            None
        };
        let sample = LentSample {
            keyexpr,
            payload: body.payload,
            kind: body.kind,
            reliability,
            qos,
            attachment: body.attachment,
            source_info: body.source_info,
            timestamp: body.timestamp,
            #[cfg(feature = "alloc")]
            timestamp_hint: OnceCell::new(),
            encoding: body.encoding,
            #[cfg(feature = "alloc")]
            encoding_hint: OnceCell::new(),
        };
        // R231 -- the self-echo rule of `dispatch_push`, on the same fields: a
        // wire-arrived sample whose source names this session is not fired.
        if let (Some(own), Some(info)) = (peer.own_zid(), sample.source_info.as_ref()) {
            let prefix = info.zid_prefix();
            if !prefix.is_empty() && prefix == own {
                return Ok(());
            }
        }
        fire_into(&mut self.subscribers, &sample, true);
        Ok(())
    }

    /// The fallback: the owned projection of `push`, delivered by the path the
    /// copying receive takes ([`Self::dispatch_push`]), so a Put the lent form
    /// cannot represent is delivered exactly as it always was.
    #[cfg(feature = "alloc")]
    fn dispatch_owned_projection(
        &mut self,
        peer: &SubscriberPeer<P>,
        push: &Push<'_>,
        reliability: Reliability,
    ) {
        // The wire profile is unbounded (`Heap`, or the AP's shared frame
        // ranges), so this projection cannot refuse a decoded Push. It
        // consumes its view; the clone is of the view, not of the bytes.
        if let Ok(owned) = push.clone().try_into_owned_in::<crate::wire::WireStorage>() {
            self.dispatch_push(peer, &owned, reliability, true);
        }
    }
}

#[cfg(all(feature = "alloc", feature = "pubsub-put"))]
impl<C: SampleSink, P: Storage> SubscriberTable<C, P> {
    /// Deliver the plain `Put`s of one frame
    /// ([`DriverLoopOutcome::FramePlainPuts`](crate::driver_loop::DriverLoopOutcome::FramePlainPuts)),
    /// in the order they lie in it: what [`Self::dispatch_push`] delivers for the owned
    /// projection of each, without building one. A plain Put has no timestamp, no
    /// encoding, no attachment and no source, so none of those is read and the self-echo
    /// rule, which needs a source, has nothing to test.
    ///
    /// A key the peer never declared (or the empty key) is dropped, as the owned path
    /// drops it, and one record's key never affects another's.
    pub(super) fn dispatch_plain_puts(
        &mut self,
        peer: &SubscriberPeer<P>,
        reliable: bool,
        frame: &crate::link::RxBytes,
        puts: &[crate::plain_push::PlainPut],
    ) {
        let reliability = Reliability::from_reliable_bool(reliable);
        let spaces = peer.mapping_spaces();
        // The text of the suffix just read, which the next record of a stream repeats: its
        // bytes are compared with the last ones instead of being checked as UTF-8 again.
        let mut last_suffix: Option<(&[u8], &str)> = None;
        let frame_bytes = frame.as_slice();
        // The key of the record just delivered, kept as text. The reader says when a record
        // names the same key as the one before it ([`PlainPut::repeats_key`]), and then that
        // text is the key: it is not composed again, and the sample is marked as repeating so
        // that the match against the subscribers and a sink's list of keys are not redone
        // either. `current_is_set` is false until a record has been delivered, and after one
        // that was dropped, so a repeat never rests on a key that was not.
        let mut current = alloc::string::String::new();
        let mut current_is_set = false;
        for put in puts {
            let repeats = put.repeats_key && current_is_set;
            if !repeats {
                current_is_set = false;
                let suffix = match put.suffix {
                    Some((from, to)) => {
                        let bytes = &frame_bytes[from as usize..to as usize];
                        match last_suffix {
                            Some((held, text)) if held == bytes => Some(text),
                            _ => match core::str::from_utf8(bytes) {
                                Ok(text) => {
                                    last_suffix = Some((bytes, text));
                                    Some(text)
                                }
                                // The reader validated it; a frame that changed under it is
                                // dropped.
                                Err(_) => continue,
                            },
                        }
                    }
                    None => None,
                };
                let mut composed = KeyexprBuf::new();
                let keyexpr = match crate::wireexpr_resolve::resolve_plain_parts(
                    put.sender_mapping,
                    put.id,
                    suffix,
                    spaces,
                    &mut composed,
                ) {
                    Ok(Some(keyexpr)) => keyexpr,
                    // Undeclared id or empty key; the growable backing never answers past-bound.
                    Ok(None) | Err(KeyexprPastBound) => continue,
                };
                current.clear();
                current.push_str(keyexpr);
                current_is_set = true;
            }
            #[cfg(feature = "pubsub-qos")]
            let qos = put.qos.map(QosLevel::from_raw);
            #[cfg(not(feature = "pubsub-qos"))]
            let qos: Option<QosLevel> = None;
            let mut sample =
                crate::sink::PlainSample::new(&current, frame, put.payload, reliability, qos);
            if repeats {
                sample = sample.repeating_the_previous_key();
            }
            self.fire_plain_to_subscribers(&sample, true);
        }
        // The frame is done with this table: a sink that gathered its samples hands over.
        for subscriber in self.subscribers.iter_mut() {
            subscriber.sink.end_plain_frame();
        }
    }
}

// The lent delivery against the owned one on the same record: every field a
// subscriber can read through `SampleView` must be the same, the fallbacks must
// deliver what the copying path delivers and be counted, and the self-echo rule
// must hold on both. The allocation count of the path is the lwIP harness's
// (`wz-session-lwip/tests/rx_frame_allocations.rs`), which runs it end to end.
#[cfg(all(test, feature = "pubsub-put"))]
mod tests {
    use super::*;
    use crate::driver_loop::IterationEvent;
    use crate::locality::Locality;
    use crate::network_message::NetworkMessage;
    use crate::pubsub::InPlaceFallbacks;
    use crate::sink::BoxedSink;
    use alloc::boxed::Box;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use sce_forge_runtime::codec::SceCursor;
    use std::sync::{Arc, Mutex};

    /// The registry over the AP's closure sink, which records what it is handed.
    type SubscriberRegistry = crate::pubsub::SubscriberRegistry<BoxedSink>;

    /// Everything a subscriber can read through the view, as owned values.
    #[derive(Debug, Clone, PartialEq)]
    struct Seen {
        keyexpr: String,
        payload: Vec<u8>,
        kind: SampleKind,
        reliability: Reliability,
        qos: Option<QosLevel>,
        attachment: Option<Vec<u8>>,
        timestamp: Option<TimestampHint>,
        encoding: Option<EncodingHint>,
        source_info: Option<SourceInfo>,
    }

    fn recording(pattern: &str) -> (SubscriberRegistry, Arc<Mutex<Vec<Seen>>>) {
        let mut registry = SubscriberRegistry::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let into = seen.clone();
        registry
            .register_sink(
                pattern,
                Locality::Any,
                BoxedSink::new(move |s: &dyn SampleView| {
                    into.lock().unwrap().push(Seen {
                        keyexpr: s.keyexpr().to_string(),
                        payload: s.payload().to_vec(),
                        kind: s.kind(),
                        reliability: s.reliability(),
                        qos: s.qos(),
                        attachment: s.attachment().map(<[u8]>::to_vec),
                        timestamp: s.timestamp().cloned(),
                        encoding: s.encoding().cloned(),
                        source_info: s.source_info().cloned(),
                    });
                }),
            )
            .expect("register");
        (registry, seen)
    }

    /// The wire bytes of `push`, as a peer sends them.
    fn wire_of(push: &crate::wire::PushOwned) -> Vec<u8> {
        push.try_as_borrowed().expect("a view").encode_to_vec()
    }

    /// `push` delivered lent (the in-place path) and owned (the copying path)
    /// to two registries prepared alike: what each subscriber saw, and the
    /// lent registry's fallbacks.
    fn both_ways(
        push: &Push<'_>,
        pattern: &str,
        prepare: impl Fn(&mut SubscriberRegistry),
    ) -> (Vec<Seen>, Vec<Seen>, InPlaceFallbacks) {
        let (mut lent, lent_seen) = recording(pattern);
        prepare(&mut lent);
        let record = InPlaceRecord::push_of_frame(push, false, 7, crate::qos::Priority::DEFAULT);
        lent.dispatch_iteration_event(IterationEvent::InPlace(record));

        let (mut owned, owned_seen) = recording(pattern);
        prepare(&mut owned);
        let message = NetworkMessage::Push(Box::new(
            push.clone()
                .try_into_owned_in::<crate::wire::WireStorage>()
                .expect("an owned projection"),
        ));
        owned.dispatch(&message, Reliability::BestEffort);

        let lent_seen = lent_seen.lock().unwrap().clone();
        let owned_seen = owned_seen.lock().unwrap().clone();
        (lent_seen, owned_seen, lent.in_place_fallbacks())
    }

    fn meta() -> crate::metadata::PushMetadata {
        crate::metadata::PushMetadata {
            timestamp: Some(TimestampHint {
                time: 0x0102_0304_0506_0708,
                zid: alloc::vec![0xa1, 0xa2, 0xa3],
            }),
            encoding: Some(EncodingHint {
                packed_id: 0x0b,
                schema: Some("schema/x".to_string()),
            }),
            source_info: Some(SourceInfo::new(&[0x51, 0x52, 0x53, 0x54], 9, 41)),
            attachment: Some(alloc::vec![1, 2, 3, 4, 5]),
            qos: Some(QosLevel::from_raw(0x05)),
        }
    }

    #[test]
    fn a_literal_put_with_every_field_is_delivered_lent_as_the_owned_path_delivers_it() {
        let built = crate::push_build::build_push_literal_with_meta("demo/a", b"payload", &meta())
            .expect("build");
        let wire = wire_of(&built);
        let push = Push::decode(&mut SceCursor::new(&wire)).expect("decode");
        let (lent, owned, fallbacks) = both_ways(&push, "demo/*", |_| {});
        assert_eq!(owned.len(), 1, "the owned path delivers it");
        assert_eq!(
            lent, owned,
            "the lent delivery is the owned one, field for field"
        );
        assert_eq!(lent[0].reliability, Reliability::BestEffort);
        assert_eq!(fallbacks, InPlaceFallbacks::default(), "nothing fell back");
    }

    #[cfg(feature = "pubsub-delete")]
    #[test]
    fn a_del_is_delivered_lent_as_the_owned_path_delivers_it() {
        let built =
            crate::push_build::build_push_del_literal_with_meta("demo/a", &meta()).expect("build");
        let wire = wire_of(&built);
        let push = Push::decode(&mut SceCursor::new(&wire)).expect("decode");
        let (lent, owned, _) = both_ways(&push, "demo/a", |_| {});
        assert_eq!(owned.len(), 1);
        assert_eq!(lent, owned);
        assert_eq!(lent[0].kind, SampleKind::Del);
    }

    /// An `M=1` alias is the peer's literal, lent from its table when there is
    /// no suffix and composed when there is one; an id the peer never declared
    /// is dropped on both paths.
    #[test]
    fn a_peer_alias_resolves_as_the_owned_path_resolves_it() {
        let peer = |r: &mut SubscriberRegistry| {
            let literal = crate::id_map::key_text("demo/a").expect("fits");
            let _ = crate::id_map::IdMap::bind(&mut r.peer.naming.aliases, 5, literal);
        };
        for suffix in [None, Some("/b")] {
            let built = crate::push_build::build_push_aliased(5, suffix, b"v").expect("build");
            let wire = wire_of(&built);
            let push = Push::decode(&mut SceCursor::new(&wire)).expect("decode");
            let (lent, owned, fallbacks) = both_ways(&push, "demo/**", peer);
            assert_eq!(owned.len(), 1, "suffix {suffix:?}");
            assert_eq!(lent, owned, "suffix {suffix:?}");
            assert_eq!(fallbacks, InPlaceFallbacks::default());
        }
        let built = crate::push_build::build_push_aliased(6, None, b"v").expect("build");
        let wire = wire_of(&built);
        let push = Push::decode(&mut SceCursor::new(&wire)).expect("decode");
        let (lent, owned, _) = both_ways(&push, "**", peer);
        assert_eq!(
            (lent.len(), owned.len()),
            (0, 0),
            "an undeclared id is dropped"
        );
    }

    /// An `M=0` alias names OUR space, which the lent path reads into its
    /// buffer through `OwnMappingSpace::append_own_mapping`.
    #[test]
    fn an_own_space_alias_resolves_as_the_owned_path_resolves_it() {
        let wire = own_space_wire();
        let push = own_space_push(&wire);
        let (lent, owned, _) = both_ways(&push, "mine/*", with_own_space);
        assert_eq!(owned.len(), 1);
        assert_eq!(lent, owned);
        assert_eq!(lent[0].keyexpr, "mine/x");
    }

    /// The anti-vacuity twin of the witness above: the same frame, with no own
    /// space installed (only the peer's space, and nothing declared there), is
    /// delivered by neither path, so the witness measures the install and not a
    /// fixture that resolves either way.
    #[test]
    fn without_an_own_space_the_lent_path_refuses_the_same_alias() {
        let wire = own_space_wire();
        let push = own_space_push(&wire);
        let (lent, owned, _) = both_ways(&push, "**", |_| {});
        assert_eq!((lent.len(), owned.len()), (0, 0));
    }

    /// The wire of an aliased Put (id 3, suffix `x`), before it is read as an
    /// `M=0` alias.
    fn own_space_wire() -> Vec<u8> {
        let built = crate::push_build::build_push_aliased(3, Some("x"), b"v").expect("build");
        wire_of(&built)
    }

    /// `wire` decoded, its keyexpr rewritten from the peer-space form the
    /// builder writes to the `M=0` form that names OUR space.
    fn own_space_push(wire: &[u8]) -> Push<'_> {
        let mut push = Push::decode(&mut SceCursor::new(wire)).expect("decode");
        let wz_codecs::wireexpr::WireexprVariant::WireexprLocal(local) = &push.keyexpr.body else {
            panic!("the builder writes the peer-space form");
        };
        push.keyexpr.body = wz_codecs::wireexpr::WireexprVariant::WireexprNonlocal(
            wz_codecs::wireexpr_nonlocal::WireexprNonlocal {
                id: local.id,
                suffix_len: local.suffix_len,
                suffix: local.suffix,
            },
        );
        push
    }

    /// Install our space: id 3 is `mine/`.
    fn with_own_space(r: &mut SubscriberRegistry) {
        let mut table = hashbrown::HashMap::new();
        table.insert(3u64, "mine/".to_string());
        let space: crate::wireexpr_resolve::SharedOwnMappingSpace = Arc::new(table);
        r.set_own_mapping_space(space);
    }

    /// A sliced Put is not delivered lent: it takes the owned projection, which
    /// joins its plain slices, and is counted.
    #[test]
    fn a_sliced_put_takes_the_owned_projection_and_is_counted() {
        let built = crate::push_build::build_push_literal("demo/s", b"").expect("build");
        let wire = wire_of(&built);
        let mut push = Push::decode(&mut SceCursor::new(&wire)).expect("decode");
        let PushVariant::CodecZenohMsgPut(put) = &mut push.body else {
            panic!("a Put");
        };
        let mut slices = sce_forge_runtime::heapless::Vec::new();
        for bytes in [&b"ab"[..], &b"cd"[..]] {
            let _ = slices.push(wz_codecs::zbuf_slice::ZbufSlice {
                kind: u32::from(crate::put_payload::SLICE_KIND_RAW),
                len: bytes.len() as u64,
                bytes,
            });
        }
        put.payload = None;
        put.payload_len = None;
        put.slice_count = Some(2);
        put.slices = Some(slices);
        let (lent, owned, fallbacks) = both_ways(&push, "demo/s", |_| {});
        assert_eq!(lent, owned);
        // Without the shared-memory transport the owned projection joins the
        // plain slices. With it, a list of slices goes through the un-swap, which
        // refuses it (and counts it) on a session that negotiated no shared
        // memory, as this one has not: dropped on both paths alike.
        #[cfg(not(feature = "transport-shm"))]
        {
            assert_eq!(owned.len(), 1);
            assert_eq!(lent[0].payload, b"abcd");
        }
        #[cfg(feature = "transport-shm")]
        assert!(
            owned.is_empty(),
            "an unnegotiated list of slices is dropped"
        );
        assert_eq!(
            fallbacks,
            InPlaceFallbacks {
                sliced: 1,
                ..InPlaceFallbacks::default()
            }
        );
    }

    /// A keyexpr past the bounded buffer: refused by the fixed backing, which
    /// counts it and delivers it through the owned projection; composed in a
    /// growable string on the growable backing, which never refuses.
    #[test]
    fn a_keyexpr_past_the_bound_is_counted_and_still_delivered() {
        // The alias fits the table's text; the alias and the message's suffix
        // together do not fit the buffer a keyexpr is composed in.
        let long_base = "a".repeat(crate::caps::MAX_KEYEXPR_BYTES - 2);
        let base = alloc::format!("{long_base}/");
        let peer = |r: &mut SubscriberRegistry| {
            let literal = crate::id_map::key_text(&base).expect("the alias fits the table");
            let _ = crate::id_map::IdMap::bind(&mut r.peer.naming.aliases, 9, literal);
        };
        let built = crate::push_build::build_push_aliased(9, Some("tail"), b"v").expect("build");
        let wire = wire_of(&built);
        let push = Push::decode(&mut SceCursor::new(&wire)).expect("decode");
        let (lent, owned, fallbacks) = both_ways(&push, "**", peer);
        assert_eq!(owned.len(), 1);
        assert_eq!(lent, owned);
        let refused = u32::from(crate::bounded::ENFORCES_CAPACITY);
        assert_eq!(
            fallbacks,
            InPlaceFallbacks {
                keyexpr_past_bound: refused,
                ..InPlaceFallbacks::default()
            }
        );
    }

    /// A sample whose source names this session is not fired, lent or owned.
    #[cfg(feature = "pubsub-source-info")]
    #[test]
    fn a_self_echo_is_suppressed_on_both_paths() {
        let built = crate::push_build::build_push_literal_with_meta("demo/a", b"p", &meta())
            .expect("build");
        let wire = wire_of(&built);
        let push = Push::decode(&mut SceCursor::new(&wire)).expect("decode");
        let own = |r: &mut SubscriberRegistry| {
            assert!(r.set_own_zid(alloc::vec![0x51, 0x52, 0x53, 0x54]));
        };
        let (lent, owned, _) = both_ways(&push, "demo/a", own);
        assert_eq!((lent.len(), owned.len()), (0, 0));
    }

    /// A hint that owns heap is built only when a subscriber asks for it.
    #[test]
    fn the_timestamp_and_encoding_hints_are_built_only_when_asked() {
        let ts = Timestamp {
            time: 1,
            zid_len: 1,
            zid: &[7],
        };
        let sample = LentSample {
            keyexpr: "k",
            payload: &[],
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
            qos: None,
            attachment: None,
            source_info: None,
            timestamp: Some(&ts),
            timestamp_hint: OnceCell::new(),
            encoding: None,
            encoding_hint: OnceCell::new(),
        };
        assert!(
            sample.timestamp_hint.get().is_none(),
            "not built before asked"
        );
        assert_eq!(sample.timestamp().map(|t| t.time), Some(1));
        assert!(sample.timestamp_hint.get().is_some(), "built once asked");
        assert!(sample.encoding().is_none());
    }
}
