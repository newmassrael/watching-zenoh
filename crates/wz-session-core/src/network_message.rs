// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R74 / R311di-11 — Application-layer envelope batch inside a
//! `Frame.payload` carrier.
//!
//! `Frame.payload` models `Vec<NetworkMessage>` per
//! `docs/wire-spec-subset.md` §4 (the Established-session payload
//! carrier; zenoh-pico maps it to `_z_network_message_t`). Each
//! record starts with a header byte where bits 0..4 carry the network
//! MID and bits 5..7 carry per-MID flags + the shared Z bit. The full
//! network-MID set is 7 wide (PUSH 0x1D, REQUEST 0x1C, RESPONSE 0x1B,
//! RESPONSE_FINAL 0x1A, DECLARE 0x1E, INTEREST 0x19, OAM 0x1F per
//! `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h:33-39`).
//!
//! Each variant body (Request / Push / Response / ResponseFinal /
//! Declare) is cfg-gated on the matching `codec-*` feature so a
//! handshake-only deploy that turns off body codecs elides the unused
//! decode paths from the runtime. `Oam`, `Interest`, and `Unknown`
//! remain unconditional because the underlying codec modules are
//! always present in wz-codecs (no `codec-oam` / `codec-interest`
//! feature exists).

#[cfg(any(
    feature = "codec-request",
    feature = "codec-push",
    feature = "codec-response",
    feature = "codec-declare",
))]
use alloc::boxed::Box;
use alloc::vec::Vec;

#[cfg(feature = "codec-frame")]
use sce_forge_runtime::codec::{CodecError, SceCursor};

// Only the lifetime-free `*Owned` mirrors are imported at module level —
// they are what `NetworkMessage` stores. The borrowed `Foo<'a>` decode
// views are referenced by fully-qualified path inside the codec-frame
// gated `parse_frame_payload` (their only use), so no borrowed import
// needs cfg-gating against the body-codec feature matrix.
#[cfg(feature = "codec-declare")]
use wz_codecs::declare::DeclareOwned;
use wz_codecs::interest::InterestOwned;
use wz_codecs::oam::OamOwned;
#[cfg(feature = "codec-push")]
use wz_codecs::push::PushOwned;
#[cfg(feature = "codec-request")]
use wz_codecs::request::RequestOwned;
#[cfg(feature = "codec-response")]
use wz_codecs::response::ResponseOwned;
#[cfg(feature = "codec-response-final")]
use wz_codecs::response_final::ResponseFinalOwned;

/// R311dl — re-export the wire-spec MID constants from the
/// wz-codecs single-source-of-truth home. Callsite references
/// (`wire_const::N_MID_REQUEST` etc.) below keep their existing
/// shape; the constants themselves are defined in
/// [`wz_codecs::wire_const`].
#[cfg(feature = "codec-frame")]
use wz_codecs::wire_const;

/// R74 — one application-layer message inside a `Frame.payload` batch.
///
/// See the module docstring for the wire-shape rationale and per-
/// variant cfg gating policy. `#[derive(Debug)]` derives transitively
/// over wz-codecs codec structs — those carry the category-uniform
/// `Debug + Clone + PartialEq` derive set per
/// `sce-build::forge::rust_derive_policy::RustDeriveCategory::CodecStruct`
/// SSOT (SCE 14ff5e36d).
#[derive(Debug)]
pub enum NetworkMessage {
    /// Network MID `_Z_MID_N_REQUEST` (0x1C). Carries a query / put /
    /// del wrapped in a Wireexpr + request-id envelope with response
    /// correlation. Decoded via `wz_codecs::request::Request`. The
    /// `Box` keeps the enum variant size small — `Request` carries
    /// `Wireexpr` + a `RequestVariant` whose arms hold MsgPut / MsgDel
    /// / Query structs, making the inline form much larger than the
    /// `Unknown` variant.
    #[cfg(feature = "codec-request")]
    Request(Box<RequestOwned>),
    /// R90 — Network MID `_Z_MID_N_PUSH` (0x1D). Pub/sub data
    /// carrier wrapping a put / del inner body — same envelope
    /// shape as `Request` minus the rid field. The `Box` mirrors
    /// the `Request` variant's size-balancing rationale.
    #[cfg(feature = "codec-push")]
    Push(Box<PushOwned>),
    /// R91 — Network MID `_Z_MID_N_RESPONSE_FINAL` (0x1A). Pure
    /// correlation marker that closes a Request's reply stream;
    /// payload is header + request_id VLE only (no embed, no
    /// inner body). Inlined (no `Box`) because the struct is
    /// small — just three integer fields plus an optional ext
    /// vec.
    #[cfg(feature = "codec-response-final")]
    ResponseFinal(ResponseFinalOwned),
    /// R92 — Network MID `_Z_MID_N_OAM` (0x1F). Diagnostic /
    /// control-plane envelope; header (mid+enc+Z) + VLE id +
    /// optional ext-chain + body variant on `header.enc` (UNIT
    /// / ZINT / ZBUF inner codec). The body variant arms hold
    /// `ExtUnit` / `ExtZint` / `ExtZbuf` — small enough to inline
    /// like `ResponseFinal`.
    Oam(OamOwned),
    /// R93/R94 — Network MID `_Z_MID_N_INTEREST` (0x19).
    /// Declarations discovery / liveliness subscriber registration
    /// envelope; header (mid+C+F+Z) + VLE interest_id + (C||F)-gated
    /// inner body + Z-gated ext-chain. R94 closed the body via the
    /// interest_body sub-codec (body_flags byte + R-gated wireexpr).
    /// Inlined (no `Box`) because the struct is small — header byte
    /// + u64 + optional body + optional ext vec.
    Interest(InterestOwned),
    /// R97 — Network MID `_Z_MID_N_RESPONSE` (0x1B). Query reply
    /// carrier wrapping a reply (0x04) or err (0x05) inner body
    /// dispatched via peek-byte on the inner MID bit-range. Same
    /// envelope shape as `Request` minus the body kind set. The
    /// `Box` keeps the enum variant size small — `Response`
    /// carries `Wireexpr` + `ResponseVariant` whose arms hold
    /// Reply / Err structs, making the inline form larger than
    /// the `Unknown` variant (mirrors the Request sizing
    /// rationale).
    #[cfg(feature = "codec-response")]
    Response(Box<ResponseOwned>),
    /// R110/R115 — Network MID `_Z_MID_N_DECLARE` (0x1E). Declarations
    /// envelope wrapping one of the nine sub-MID inner bodies
    /// (DECL_KEXPR / DECL_SUBSCRIBER / DECL_QUERYABLE / DECL_TOKEN /
    /// UNDECL_KEXPR / UNDECL_SUBSCRIBER / UNDECL_QUERYABLE /
    /// UNDECL_TOKEN / DECL_FINAL) dispatched via peek-byte on the
    /// inner header MID. R110a-e closed the wz-side authoring chain
    /// and the byte-equiv Layer 3 wire-interop vs zenoh-pico
    /// `_z_declare_encode`; R115 wires the inbound dispatch so a
    /// peer-emitted DECLARE record surfaces here. The `Box` mirrors
    /// the `Request`/`Push`/`Response` sizing rationale — `Declare`
    /// carries an optional interest_id + ext vec + the inner
    /// `DeclareVariant` whose arms hold the nine sub-body structs,
    /// making the inline form much larger than `Unknown`.
    #[cfg(feature = "codec-declare")]
    Declare(Box<DeclareOwned>),
    /// Header byte's MID falls outside the
    /// {REQUEST, PUSH, RESPONSE_FINAL, OAM, INTEREST, RESPONSE, DECLARE}
    /// subset wz-codecs has authored envelope coverage for. `body`
    /// carries the rest of the payload bytes (header byte included)
    /// verbatim so a future per-MID decoder can re-parse without
    /// losing data; the parse stops here to avoid mis-cursor-advancing
    /// across an unknown body length.
    Unknown { mid: u8, body: Vec<u8> },
}

/// R74 — decode a `Frame.payload` byte slice into the in-order batch
/// of network messages it carries.
///
/// Loop shape: peek the cursor's next byte, mask to `mid = byte & 0x1F`,
/// dispatch to the matching envelope decoder. On `N_MID_REQUEST` calls
/// `Request::decode` which re-reads the header byte itself (peek-byte
/// primitive per RFC §5.B Y3 atomic 2b-ii) so no double-consumption.
/// On any other MID, absorbs the remaining bytes as `Unknown { mid,
/// body }` and terminates the batch loop — see
/// [`NetworkMessage::Unknown`] for the rationale.
///
/// An empty `bytes` slice returns `Ok(vec![])` (an empty batch is a
/// valid Frame.payload — the transport envelope is fine, no
/// application-layer records).
///
/// Codec errors propagate as `CodecError`. The caller is responsible
/// for deciding whether to surface them as a transport-FSM
/// `FramingError` (current `poll_and_dispatch_one` behavior, since the
/// transport envelope already parsed but the application-layer batch
/// is malformed) or to log and continue with the partially-decoded
/// batch.
///
/// R311g — gated on `codec-frame`. The only caller is the
/// `InboundFrame::Frame` arm in `poll_and_dispatch_one` (also
/// codec-frame-gated), so a codec-frame-OFF build never reaches a
/// caller; cfg-gating the definition itself elides ~80 lines of
/// dispatch + the `NetworkMessage` decoders for every body codec
/// without leaving an orphan public symbol. Individual match arms
/// inside this function carry their own per-body cfg
/// (`N_MID_PUSH` under `codec-push`, etc.).
#[cfg(feature = "codec-frame")]
pub fn parse_frame_payload(bytes: &[u8]) -> Result<Vec<NetworkMessage>, CodecError> {
    let mut messages = Vec::new();
    let mut cursor = SceCursor::new(bytes);
    while cursor.remaining() > 0 {
        // R311y578 — the per-MID dispatch moved to `decode_one_record`, the
        // SSOT this strict walk and the best-effort walk share. Behaviour
        // here is unchanged: `Ok(None)` (no envelope decoder for the MID)
        // absorbs the tail as `Unknown` and terminates, a codec error
        // propagates and fails the whole batch.
        if !decode_one_record(&mut cursor, &mut messages)? {
            {
                let mid = cursor.peek_slice(1)?[0] & 0x1F;
                let rem = cursor.remaining();
                let body = cursor.peek_slice(rem)?.to_vec();
                cursor.advance(rem)?;
                messages.push(NetworkMessage::Unknown { mid, body });
                break;
            }
        }
    }
    Ok(messages)
}

/// R311y578 — why a batch parse stopped short of the payload's end.
///
/// A batch is a run of self-delimiting records with no per-record length
/// prefix, so the ONLY way to find record N+1 is to have fully decoded
/// record N. Once that fails there is nothing to resynchronise against:
/// halting is correct, and the deliverable is saying WHERE and WHY.
#[cfg(feature = "codec-frame")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchHalt {
    /// A network MID this build has no envelope decoder for. Its body
    /// length is unknowable, so the remaining bytes were absorbed into a
    /// trailing [`NetworkMessage::Unknown`] and the walk stopped. Not
    /// necessarily corruption: it is also what a peer speaking a MID
    /// outside this build's `codec-*` selection looks like.
    UnknownMid {
        /// The masked MID (`header & 0x1F`).
        mid: u8,
        /// Byte offset of that header within the payload.
        offset: usize,
    },
    /// A record's decoder failed. Everything before `offset` decoded
    /// cleanly and is in [`BatchParse::messages`]; from `offset` on the
    /// payload is unparsed.
    ///
    /// [`sce_forge_runtime::codec::CodecError::NeedMoreBytes`] here is the
    /// ordinary shape of a TRUNCATED capture (a snaplen cut, a flow whose
    /// tail was never captured), which is why the error value is carried
    /// rather than flattened to a bool.
    CodecError {
        /// Byte offset of the failing record's header within the payload.
        offset: usize,
        /// The decoder's own error.
        error: CodecError,
    },
}

/// R311y578 — the outcome of a BEST-EFFORT batch parse.
///
/// [`parse_frame_payload`] is the PARTICIPANT contract: a record it cannot
/// decode is a framing error on a session it owns, so the whole batch
/// fails and the transport tears down. That is the right answer when an
/// unparsable frame means the two ends have lost sync.
///
/// An OBSERVER owns nothing. Its batch may contain a MID this build was
/// not compiled with, a record from a protocol revision it predates, or a
/// tail the capture truncated — and in every one of those cases the
/// records it COULD read are still real, still in order, and still worth
/// more than the `Err` that discards them.
#[cfg(feature = "codec-frame")]
#[derive(Debug)]
pub struct BatchParse {
    /// Every record decoded before the walk stopped, in wire order.
    pub messages: Vec<NetworkMessage>,
    /// `None` when the whole payload decoded; otherwise where and why the
    /// walk stopped.
    pub halt: Option<BatchHalt>,
    /// Bytes from the halt offset to the end of the payload — `0` when
    /// the walk consumed everything. Carried separately from `offset`
    /// because a consumer reporting "N bytes unparsed" should not have to
    /// hold the payload to compute it.
    pub unparsed_bytes: usize,
}

#[cfg(feature = "codec-frame")]
impl BatchParse {
    /// `true` when the entire payload decoded with no halt — the shape a
    /// participant's strict parse also accepts.
    pub fn is_complete(&self) -> bool {
        self.halt.is_none()
    }
}

/// R311y578 — decode a `Frame.payload` BEST-EFFORT: keep every record that
/// decodes and report where the walk stopped, instead of failing the whole
/// batch.
///
/// The record loop is [`parse_frame_payload`]'s, deliberately: the two
/// contracts differ only in what they do at the seam where a record cannot
/// be decoded, and duplicating the seven-arm MID dispatch to express that
/// would put the codec selection in two places that could drift. This
/// function owns the loop and the halt bookkeeping; the strict entry point
/// stays byte-for-byte the caller-visible contract it always was.
///
/// Never returns `Err`. An empty payload is `messages = []`, `halt = None`
/// — a valid empty batch, exactly as in the strict parse.
#[cfg(feature = "codec-frame")]
pub fn parse_frame_payload_best_effort(bytes: &[u8]) -> BatchParse {
    let total = bytes.len();
    let mut messages = Vec::new();
    let mut cursor = SceCursor::new(bytes);
    let mut halt = None;
    while cursor.remaining() > 0 {
        // The offset is recomputed per record rather than tracked, so it
        // cannot drift from the cursor the decoders actually advance.
        let offset = total - cursor.remaining();
        match decode_one_record(&mut cursor, &mut messages) {
            Ok(true) => {}
            Ok(false) => {
                // An unknown MID: absorb the rest verbatim (the strict
                // parse's own behaviour) and stop, since the record's
                // length is unknowable and there is nothing to resync on.
                let mid = bytes[offset] & 0x1F;
                let rem = cursor.remaining();
                let body = bytes[offset..].to_vec();
                // `advance` past a slice the cursor already reports as
                // remaining cannot fail; the outcome is checked anyway so
                // a future cursor change cannot silently desync the walk.
                if cursor.advance(rem).is_err() {
                    halt = Some(BatchHalt::CodecError {
                        offset,
                        error: CodecError::NeedMoreBytes,
                    });
                    break;
                }
                messages.push(NetworkMessage::Unknown { mid, body });
                halt = Some(BatchHalt::UnknownMid { mid, offset });
                break;
            }
            Err(error) => {
                halt = Some(BatchHalt::CodecError { offset, error });
                break;
            }
        }
    }
    let unparsed_bytes = match halt {
        Some(BatchHalt::UnknownMid { offset, .. }) | Some(BatchHalt::CodecError { offset, .. }) => {
            total - offset
        }
        None => 0,
    };
    BatchParse {
        messages,
        halt,
        unparsed_bytes,
    }
}

/// Decode ONE record at the cursor and PUSH it onto `out`. `Ok(false)` means
/// the MID has no envelope decoder in this build — the caller decides whether
/// that is a terminating `Unknown` absorb (both parsers) or something else.
///
/// The single MID-dispatch SSOT: adding a `codec-*` feature adds an arm
/// here and both the strict and the best-effort walk gain it together.
///
/// R311y580 — pushes through `out` rather than returning
/// `Option<NetworkMessage>` by value, and that is a FOOTPRINT decision with a
/// measured number behind it. `NetworkMessage` is a wide enum (its largest
/// variants are boxed precisely because of that); returning one through an
/// extra `Option` layer, out of a function, and into a `Vec::push` gave the
/// thumbv7m multicast artifact +748 B in `parse_frame_payload` alone at
/// `opt-level=s` — the whole of Layer Q's +868 regression, per-symbol ELF
/// diff of `e8af0d92` against `8fd6c25c`. The SSOT the extraction bought is
/// worth keeping; the extra move was not, and the out-param keeps both.
#[cfg(feature = "codec-frame")]
fn decode_one_record(
    cursor: &mut SceCursor<'_>,
    out: &mut Vec<NetworkMessage>,
) -> Result<bool, CodecError> {
    let header = cursor.peek_slice(1)?[0];
    let mid = header & 0x1F;
    match mid {
        #[cfg(feature = "codec-request")]
        wire_const::N_MID_REQUEST => {
            let req = wz_codecs::request::Request::decode(cursor)?;
            crate::ext_chain::check_request(&req)?;
            out.push(NetworkMessage::Request(Box::new(req.try_into_owned()?)));
        }
        #[cfg(feature = "codec-push")]
        wire_const::N_MID_PUSH => {
            let push = wz_codecs::push::Push::decode(cursor)?;
            crate::ext_chain::check_push(&push)?;
            out.push(NetworkMessage::Push(Box::new(push.try_into_owned()?)));
        }
        #[cfg(feature = "codec-response-final")]
        wire_const::N_MID_RESPONSE_FINAL => {
            let rf = wz_codecs::response_final::ResponseFinal::decode(cursor)?;
            crate::ext_chain::check_chain(rf.extensions.as_ref())?;
            out.push(NetworkMessage::ResponseFinal(rf.try_into_owned()?));
        }
        wire_const::N_MID_OAM => {
            let oam = wz_codecs::oam::Oam::decode(cursor)?;
            crate::ext_chain::check_chain(oam.extensions.as_ref())?;
            out.push(NetworkMessage::Oam(oam.try_into_owned()?));
        }
        wire_const::N_MID_INTEREST => {
            let interest = wz_codecs::interest::Interest::decode(cursor)?;
            crate::ext_chain::check_chain(interest.extensions.as_ref())?;
            out.push(NetworkMessage::Interest(interest.try_into_owned()?));
        }
        #[cfg(feature = "codec-response")]
        wire_const::N_MID_RESPONSE => {
            let resp = wz_codecs::response::Response::decode(cursor)?;
            crate::ext_chain::check_response(&resp)?;
            out.push(NetworkMessage::Response(Box::new(resp.try_into_owned()?)));
        }
        #[cfg(feature = "codec-declare")]
        wire_const::N_MID_DECLARE => {
            let decl = wz_codecs::declare::Declare::decode(cursor)?;
            crate::ext_chain::check_declare(&decl)?;
            out.push(NetworkMessage::Declare(Box::new(decl.try_into_owned()?)));
        }
        _ => return Ok(false),
    }
    Ok(true)
}

// ── R311y582 — A1: a chain that never terminated must not reach a consumer.
//    The check lives in `crate::ext_chain`; these are its firing legs. A rule
//    that is merely PRESENT proves nothing, so each leg damages one thing and
//    is paired with the control that leaves it green. ──
#[cfg(all(test, feature = "codec-frame", feature = "codec-push"))]
mod chain_saturation_tests {
    use super::*;

    /// A `Push` whose keyexpr is a bare id and whose body is a `MsgPut`
    /// carrying `ext_count` unit extensions and a three-byte payload.
    ///
    /// The terminating extension's id is 3 on purpose: its header byte is
    /// then `0x03`, a plausible VLE that the codec will read as `payload_len`
    /// if the chain saturates — so an unguarded parse SUCCEEDS with the wrong
    /// answer instead of failing. A fixture whose overflow byte was
    /// implausible would prove only that the codec noticed a truncated read.
    fn push_with_put_exts(ext_count: usize) -> Vec<u8> {
        let mut wire = alloc::vec![wire_const::N_MID_PUSH, 0x01];
        // MsgPut header: MID 0x01 plus Z, since the chain is present.
        wire.push(0x01 | 0x80);
        for i in 1..ext_count {
            wire.push(0x80 | (i as u8));
        }
        wire.push(0x03);
        wire.extend_from_slice(&[0x03, 0xAA, 0xBB, 0xCC]);
        wire
    }

    /// THE CONTROL. Four extensions is exactly the cap, and the chain
    /// terminates on its own, so nothing is refused and the payload is the
    /// one on the wire. Without this leg the reject below could be produced
    /// by a check that fires on every chain.
    #[test]
    fn a_chain_that_terminates_at_the_cap_is_accepted_with_the_right_payload() {
        let wire = push_with_put_exts(crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH);
        let msgs = parse_frame_payload(&wire).expect("a terminated chain must parse");
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            NetworkMessage::Push(p) => match &p.body {
                wz_codecs::push::PushOwnedVariant::CodecZenohMsgPut(put) => {
                    assert_eq!(put.payload.as_ref(), &[0xAAu8, 0xBB, 0xCC]);
                    assert_eq!(
                        put.extensions.as_ref().map_or(0, |e| e.len()),
                        crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH
                    );
                }
                other => panic!("expected a Put body, got {other:?}"),
            },
            other => panic!("expected a Push, got {other:?}"),
        }
    }

    /// THE FIRING LEG. One more extension than the cap, and the generated
    /// decode would return `Ok` with a payload of `[0x03, 0xAA, 0xBB]`. The
    /// seam refuses instead — and refuses on the NESTED chain, which is the
    /// one that costs a payload; the `Push`'s own chain is absent here.
    #[test]
    fn a_chain_past_the_cap_is_refused_at_the_dispatch_seam() {
        let wire = push_with_put_exts(crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH + 1);
        assert_eq!(
            parse_frame_payload(&wire).unwrap_err(),
            CodecError::TlvChainOverflow,
            "the dispatch accepted a message whose inner chain never terminated"
        );
    }

    /// An observer keeps what it read and reports where it stopped, rather
    /// than losing the batch — G4's contract, which A1 must not undo. The
    /// leading clean record survives; the saturated one does not become a
    /// decoded message.
    #[test]
    fn the_best_effort_walk_halts_on_it_without_losing_the_earlier_record() {
        let mut wire = wz_codecs::oam::Oam {
            id: 7,
            ..Default::default()
        }
        .encode_to_vec();
        wire.extend_from_slice(&push_with_put_exts(
            crate::ext_chain::NETWORK_EXT_CHAIN_DEPTH + 1,
        ));

        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(best.messages.len(), 1, "the clean OAM record is kept");
        assert!(
            !best.is_complete(),
            "the saturated record must halt the walk"
        );
        assert!(best
            .messages
            .iter()
            .all(|m| !matches!(m, NetworkMessage::Push(_))));
    }
}

// ── R311y578 — G4: the batch parse is best-effort for an OBSERVER while
//    staying strict for a PARTICIPANT. The fixtures are OAM records
//    (`N_MID_OAM = 0x1F`), whose codec is ungated in wz-codecs, so the
//    contract is pinned in every build that has `codec-frame` at all
//    rather than only in the lanes that select a body codec. ──
#[cfg(all(test, feature = "codec-frame"))]
mod best_effort_batch_tests {
    use super::*;
    use alloc::vec;

    /// One encoded OAM record. `Oam::default()`'s header carries its own
    /// wire MID (`0x1F`), so the fixture is a real record through the real
    /// encoder rather than a hand-typed byte string.
    fn oam_record(id: u64) -> Vec<u8> {
        wz_codecs::oam::Oam {
            id,
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn oam_ids(messages: &[NetworkMessage]) -> Vec<u64> {
        messages
            .iter()
            .filter_map(|m| match m {
                NetworkMessage::Oam(o) => Some(o.id),
                _ => None,
            })
            .collect()
    }

    /// A clean batch: both parsers agree, and the best-effort one reports
    /// no halt. Without this the halt assertions below could be satisfied
    /// by a parser that always halts.
    #[test]
    fn a_clean_batch_parses_identically_under_both_contracts() {
        let mut wire = oam_record(7);
        wire.extend_from_slice(&oam_record(8));

        let strict = parse_frame_payload(&wire).expect("clean batch");
        let best = parse_frame_payload_best_effort(&wire);

        assert_eq!(oam_ids(&strict), vec![7, 8]);
        assert_eq!(oam_ids(&best.messages), vec![7, 8]);
        assert!(best.is_complete(), "no halt on a clean batch");
        assert_eq!(best.halt, None);
        assert_eq!(best.unparsed_bytes, 0);
    }

    /// An empty payload is a valid EMPTY batch under both contracts — not
    /// a halt. A dissector that reported "unparsed" here would flag every
    /// keepalive-shaped frame.
    #[test]
    fn an_empty_payload_is_a_complete_empty_batch() {
        let best = parse_frame_payload_best_effort(&[]);
        assert!(best.messages.is_empty());
        assert!(best.is_complete());
        assert_eq!(best.unparsed_bytes, 0);
    }

    /// THE CASE G4 EXISTS FOR. A truncated trailing record makes the
    /// strict parse discard the whole batch — correct for a participant,
    /// for which a half-record means the two ends lost sync. An observer
    /// reading a capture whose tail was cut still has the earlier records,
    /// and they are exactly as real as they were.
    ///
    /// The two arms run over the SAME bytes, so the difference is the
    /// contract and nothing else.
    #[test]
    fn a_truncated_tail_loses_the_whole_batch_strictly_and_keeps_the_prefix_best_effort() {
        let first = oam_record(7);
        let second = oam_record(8);
        let mut wire = first.clone();
        // Keep only the second record's header byte: enough to dispatch on
        // the MID, not enough to decode the body.
        wire.push(second[0]);

        // Participant: everything is lost.
        assert!(
            parse_frame_payload(&wire).is_err(),
            "the strict contract fails the whole batch on a truncated record"
        );

        // Observer: the readable prefix survives, with a typed marker for
        // where the payload stopped being readable.
        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(
            oam_ids(&best.messages),
            vec![7],
            "the record that DID decode is kept"
        );
        assert!(!best.is_complete());
        match best.halt {
            Some(BatchHalt::CodecError { offset, error }) => {
                assert_eq!(
                    offset,
                    first.len(),
                    "the halt points at the failing record's own header, not at the \
                     cursor's high-water mark"
                );
                assert_eq!(
                    error,
                    CodecError::NeedMoreBytes,
                    "a truncated capture is NeedMoreBytes, which is why the error \
                     value is carried rather than flattened to a bool"
                );
            }
            other => panic!("expected a CodecError halt, got {other:?}"),
        }
        assert_eq!(best.unparsed_bytes, 1, "the lone header byte is unparsed");
    }

    /// An unknown MID mid-batch: both contracts absorb the tail as
    /// `Unknown` and stop (its length is unknowable, so there is nothing
    /// to resynchronise on), but only the best-effort one says WHERE.
    ///
    /// `0x00` is outside the seven-wide network MID set on purpose — the
    /// authored catalog covers all seven, so a meaningful Unknown fixture
    /// has to be synthetic.
    #[test]
    fn an_unknown_mid_halts_with_its_offset_under_both_contracts() {
        let first = oam_record(7);
        let mut wire = first.clone();
        wire.extend_from_slice(&[0x00, 0xAB, 0xCD]);

        let strict = parse_frame_payload(&wire).expect("unknown MID absorbs, not errors");
        assert_eq!(oam_ids(&strict), vec![7]);
        assert!(matches!(
            strict.last(),
            Some(NetworkMessage::Unknown { mid: 0x00, .. })
        ));

        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(oam_ids(&best.messages), vec![7]);
        match best.messages.last() {
            Some(NetworkMessage::Unknown { mid, body }) => {
                assert_eq!(*mid, 0x00);
                assert_eq!(
                    body.as_slice(),
                    &[0x00, 0xAB, 0xCD],
                    "the absorbed body starts AT the unknown header, not after it"
                );
            }
            other => panic!("expected a trailing Unknown, got {other:?}"),
        }
        assert_eq!(
            best.halt,
            Some(BatchHalt::UnknownMid {
                mid: 0x00,
                offset: first.len()
            })
        );
        assert_eq!(best.unparsed_bytes, 3);
    }

    /// The two walks share ONE per-MID dispatch (`decode_one_record`), so
    /// a build's codec selection cannot differ between them. Asserted over
    /// a batch of every record kind this build decodes: the strict and
    /// best-effort message sequences must be identical whenever the strict
    /// parse succeeds at all.
    #[test]
    fn both_walks_decode_the_same_records() {
        let mut wire = Vec::new();
        for id in 0..4u64 {
            wire.extend_from_slice(&oam_record(id));
        }
        let strict = parse_frame_payload(&wire).expect("clean batch");
        let best = parse_frame_payload_best_effort(&wire);
        assert_eq!(oam_ids(&strict), oam_ids(&best.messages));
        assert_eq!(strict.len(), best.messages.len());
        assert!(best.is_complete());
    }
}
