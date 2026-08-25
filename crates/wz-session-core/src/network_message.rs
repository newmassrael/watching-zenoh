// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
    /// R311y641 (§1.1n) — `(offset, len)` within this payload for each entry of
    /// [`Self::messages`], same index, same order.
    ///
    /// THE WALK ALREADY COMPUTED THIS AND KEPT IT ONLY FOR FAILURES. `offset`
    /// is recomputed from the cursor on every iteration and, until this round,
    /// was carried into [`BatchHalt`] and discarded for every record that
    /// SUCCEEDED. So a batch reported where it stopped and never where anything
    /// in it was, and a consumer holding a record could not point at the bytes
    /// it came from.
    ///
    /// A parallel `Vec` rather than a field on `NetworkMessage`, because the
    /// span is a fact about this PARSE and not about the message: the same
    /// message re-encoded elsewhere sits at a different offset, and putting it
    /// on the value would let a copy carry a coordinate that no longer refers to
    /// anything. Pushed in lockstep in the ONE loop below, with
    /// [`Self::span_of`] as the sanctioned paired read.
    pub spans: Vec<(usize, usize)>,
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

    /// R311y641 (§1.1n) — `(offset, len)` of the `i`th message within the
    /// payload this batch was parsed from.
    ///
    /// `None` only when `i` is out of range. The two vectors are pushed
    /// together in `parse_frame_payload_best_effort` and a lookup that fell
    /// through would mean they had desynced, which is the one failure a
    /// parallel vector can have — so it answers `None` rather than indexing.
    pub fn span_of(&self, i: usize) -> Option<(usize, usize)> {
        self.spans.get(i).copied()
    }

    /// Every record with the bytes it came from, in wire order.
    pub fn records(&self) -> impl Iterator<Item = (&NetworkMessage, Option<(usize, usize)>)> {
        self.messages
            .iter()
            .enumerate()
            .map(|(i, m)| (m, self.span_of(i)))
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
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut cursor = SceCursor::new(bytes);
    let mut halt = None;
    while cursor.remaining() > 0 {
        // The offset is recomputed per record rather than tracked, so it
        // cannot drift from the cursor the decoders actually advance.
        let offset = total - cursor.remaining();
        // R311y641 — how many records this step appends is the decoder's
        // business, not this loop's, so the spans are filled by DELTA rather
        // than by assuming one. A step that pushed two would otherwise leave the
        // vectors one apart for the rest of the walk.
        let before = messages.len();
        match decode_one_record(&mut cursor, &mut messages) {
            Ok(true) => {
                let len = (total - cursor.remaining()) - offset;
                spans.resize(before, (0, 0));
                for _ in before..messages.len() {
                    spans.push((offset, len));
                }
            }
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
                // The absorbed remainder IS this record's extent: the strict
                // parse treats an unknown MID as consuming the rest, so the
                // span says so rather than leaving the one record a reader most
                // wants to locate without a coordinate.
                spans.push((offset, rem));
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
    // Every path that appends a message appends its span, so this holds by
    // construction; it is asserted because a parallel vector's one failure mode
    // is silent and a later arm could reintroduce it.
    debug_assert_eq!(messages.len(), spans.len());
    BatchParse {
        messages,
        spans,
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
            out.push(NetworkMessage::Request(Box::new(req.try_into_owned()?)));
        }
        #[cfg(feature = "codec-push")]
        wire_const::N_MID_PUSH => {
            let push = wz_codecs::push::Push::decode(cursor)?;
            out.push(NetworkMessage::Push(Box::new(push.try_into_owned()?)));
        }
        #[cfg(feature = "codec-response-final")]
        wire_const::N_MID_RESPONSE_FINAL => {
            let rf = wz_codecs::response_final::ResponseFinal::decode(cursor)?;
            out.push(NetworkMessage::ResponseFinal(rf.try_into_owned()?));
        }
        wire_const::N_MID_OAM => {
            let oam = wz_codecs::oam::Oam::decode(cursor)?;
            out.push(NetworkMessage::Oam(oam.try_into_owned()?));
        }
        wire_const::N_MID_INTEREST => {
            let interest = wz_codecs::interest::Interest::decode(cursor)?;
            out.push(NetworkMessage::Interest(interest.try_into_owned()?));
        }
        #[cfg(feature = "codec-response")]
        wire_const::N_MID_RESPONSE => {
            let resp = wz_codecs::response::Response::decode(cursor)?;
            out.push(NetworkMessage::Response(Box::new(resp.try_into_owned()?)));
        }
        #[cfg(feature = "codec-declare")]
        wire_const::N_MID_DECLARE => {
            let decl = wz_codecs::declare::Declare::decode(cursor)?;
            out.push(NetworkMessage::Declare(Box::new(decl.try_into_owned()?)));
        }
        _ => return Ok(false),
    }
    Ok(true)
}

// ── R311y582 — A1: a chain that never terminated must not reach a consumer.
//    A rule that is merely PRESENT proves nothing, so each leg damages one
//    thing and is paired with the control that leaves it green.
//
//    R311y589 — the check no longer lives in `crate::ext_chain`: SCE landed
//    `on-overflow="reject"` on the entry-flag path (`ec3b032984`) and the
//    GENERATED decode refuses now, so wz's compensating seam was deleted. These
//    tests were deliberately NOT deleted with it. They assert the CONTRACT —
//    what a wz participant must never act on — and the contract outlives
//    whichever layer enforces it; that they still pass with the seam gone is
//    the measurement that the codec took the work over, rather than an
//    inspection of the emit. ──
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

// ── R311y804 — the Z-flagged DECLARATION-BODY ext chain, and why every
//    assertion below is about the SECOND record.
//
//    Each declaration body carries a `Z` bit at header bit 7 meaning "an
//    extension chain follows", and both upstreams consume it unconditionally:
//    zenoh loops `extension::skip` / `skip_all` per body
//    (zenoh-codec/src/network/declare.rs — :319 DeclareKeyExpr, :377
//    UndeclareKeyExpr, :452 DeclareSubscriber, :826 DeclareToken, :255 Final),
//    and pico calls `_z_msg_ext_skip_non_mandatories` / `_z_msg_ext_decode_iter`
//    at the same five sites (src/protocol/codec/declarations.c:181-191,
//    :192-200, :259-267, :301-309, :314-321). wz consumed it on the four bodies
//    that carry an ext of their OWN (the queryable info, the sourced
//    `ext_keyexpr`) and on none of these five.
//
//    A test that only asserts the Z-flagged record itself decodes proves
//    NOTHING — the old decoder returned `Ok` too, having simply stopped early.
//    What the unconsumed bytes cost is the REST OF THE BATCH: a batch is a run
//    of self-delimiting records with no per-record length prefix (see
//    `BatchHalt`'s header above), so record N+1 is found only by having fully
//    decoded record N. Each test therefore puts a second, ordinary
//    `Declare(UndeclKexpr id = 42)` after the Z-flagged one and asserts THAT
//    survives. Before this round every one of them read the ext header byte
//    `0x21` as a network MID (`0x21 & 0x1F == 0x01`, which is no N_MID),
//    absorbed the remainder as `Unknown`, and lost the second record.
//
//    The fixtures are hand-assembled bytes on purpose: wz's own builders write
//    Z=0 on all five bodies, as do both upstreams' 1.5.0 writers, so an
//    encode-then-decode round trip could not reach the arm under test. These
//    bytes are what a peer with one extension more than this revision knows
//    about puts on the wire. ──
#[cfg(all(test, feature = "codec-frame", feature = "codec-declare"))]
mod declare_body_ext_chain_tests {
    use super::*;

    /// A terminal ZINT extension: id 1, `enc = ZINT` (`0b01 << 5`), no `M`, no
    /// `Z` — so the chain ends here — carrying VLE(42).
    const TERMINAL_ZINT_EXT: [u8; 2] = [0x21, 0x2A];

    /// The mapping id of the record every test appends AFTER the Z-flagged one.
    const SENTINEL_ID: u64 = 42;

    /// That record: a plain `Declare(UndeclKexpr)`, two bytes of body, no flags,
    /// nothing shared with the record before it — so decoding it back out with
    /// the right id is not something a desynchronised cursor produces.
    fn sentinel_record() -> Vec<u8> {
        alloc::vec![wire_const::N_MID_DECLARE, 0x01, SENTINEL_ID as u8]
    }

    /// `[Declare(<z_flagged_body>), Declare(UndeclKexpr 42)]`.
    fn batch_after(z_flagged_body: &[u8]) -> Vec<u8> {
        let mut wire = alloc::vec![wire_const::N_MID_DECLARE];
        wire.extend_from_slice(z_flagged_body);
        wire.extend_from_slice(&sentinel_record());
        wire
    }

    /// The shared assertion: two records came back, and the SECOND is the
    /// sentinel with its id intact.
    fn assert_sentinel_survived(wire: &[u8], what: &str) -> Vec<NetworkMessage> {
        let msgs = parse_frame_payload(wire)
            .unwrap_or_else(|e| panic!("{what}: the batch must parse, got {e:?}"));
        assert_eq!(
            msgs.len(),
            2,
            "{what}: the Z-flagged body swallowed the record after it"
        );
        match &msgs[1] {
            NetworkMessage::Declare(d) => match &d.body {
                wz_codecs::declare::DeclareOwnedVariant::CodecZenohUndeclKexpr(u) => {
                    assert_eq!(
                        u.id, SENTINEL_ID,
                        "{what}: the second record decoded at the wrong offset"
                    );
                }
                other => panic!("{what}: expected the sentinel UndeclKexpr, got {other:?}"),
            },
            other => panic!("{what}: expected a Declare, got {other:?}"),
        }
        msgs
    }

    /// DeclSubscriber, and the one fixture with a MULTI-entry chain: the first
    /// entry sets its own `Z` (0x80) so the loop must run twice. A decoder that
    /// consumed exactly one entry fails here while passing every single-entry
    /// sibling below.
    #[test]
    fn a_z_flagged_decl_subscriber_does_not_swallow_the_next_record() {
        let body = alloc::vec![
            0x02 | 0x80, // DeclSubscriber MID 0x02 | Z
            0x07,        // subscriber id
            0x00,        // wireexpr mapping id (N=0, so no suffix)
            0xA1,        // ext id 1, ZINT, Z set -> one more follows
            0x2A,        // VLE(42)
            0x22,        // ext id 2, ZINT, terminal
            0x07,        // VLE(7)
        ];
        let msgs = assert_sentinel_survived(&batch_after(&body), "decl_subscriber");
        match &msgs[0] {
            NetworkMessage::Declare(d) => match &d.body {
                wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclSubscriber(s) => {
                    assert_eq!(
                        s.extensions.as_ref().map_or(0, |e| e.len()),
                        2,
                        "both chain entries must be held, not skipped"
                    );
                }
                other => panic!("expected a DeclSubscriber, got {other:?}"),
            },
            other => panic!("expected a Declare, got {other:?}"),
        }
    }

    #[test]
    fn a_z_flagged_decl_token_does_not_swallow_the_next_record() {
        let mut body = alloc::vec![
            0x06 | 0x80, // DeclToken MID 0x06 | Z
            0x09,        // token id
            0x00,        // wireexpr mapping id (N=0)
        ];
        body.extend_from_slice(&TERMINAL_ZINT_EXT);
        assert_sentinel_survived(&batch_after(&body), "decl_token");
    }

    /// DeclKexpr is the sharper of the two bodies that did not model bit 7 at
    /// all — the flag was absent from `decl_kexpr.scxml`, so there was no `z()`
    /// accessor to have ignored.
    #[test]
    // R311y806 — the `<MID> | 0x80` spelling is what makes this group of hand-
    // assembled fixtures readable: each names its declaration MID and then sets
    // bit 7. DeclKexpr's MID is 0x00, so clippy reads the OR as an identity and
    // asks for a bare `0x80` — which would leave this the one fixture in the
    // group that does not say which body it is. The lint is right about the
    // arithmetic and wrong about the intent, so it is silenced HERE rather than
    // the byte being collapsed. R311y804 shipped this and the `--all-features`
    // clippy lane (C1bf) reddened on it hosted.
    #[allow(clippy::identity_op)]
    fn a_z_flagged_decl_kexpr_does_not_swallow_the_next_record() {
        let mut body = alloc::vec![
            0x00 | 0x80, // DeclKexpr MID 0x00 | Z (N=0)
            0x03,        // mapping id
            0x00,        // wireexpr mapping id
        ];
        body.extend_from_slice(&TERMINAL_ZINT_EXT);
        assert_sentinel_survived(&batch_after(&body), "decl_kexpr");
    }

    /// UndeclKexpr had the `Z` flag declared with no chain behind it, which is
    /// the shape that reads as deliberate and is not: its three Undecl_*
    /// siblings all consume a chain because their SOURCED form rides one, and
    /// this body has no ext of its own to have prompted the same work.
    #[test]
    fn a_z_flagged_undecl_kexpr_does_not_swallow_the_next_record() {
        let mut body = alloc::vec![
            0x01 | 0x80, // UndeclKexpr MID 0x01 | Z
            0x05,        // mapping id
        ];
        body.extend_from_slice(&TERMINAL_ZINT_EXT);
        assert_sentinel_survived(&batch_after(&body), "undecl_kexpr");
    }

    #[test]
    fn a_z_flagged_decl_final_does_not_swallow_the_next_record() {
        let mut body = alloc::vec![0x1A | 0x80]; // DeclFinal MID 0x1A | Z
        body.extend_from_slice(&TERMINAL_ZINT_EXT);
        assert_sentinel_survived(&batch_after(&body), "decl_final");
    }

    /// An UNKNOWN declaration MID with a chain, decoded through the `DeclFinal`
    /// catch-all arm. wz ABSORBS an unknown declaration where both upstreams
    /// reject the whole message, so wz is the implementation for which
    /// consuming the chain changes an outcome rather than tidying one.
    #[test]
    fn an_unknown_declaration_kind_with_a_chain_does_not_swallow_the_next_record() {
        // MID 0x0B is in no `declare::id::*` upstream and no wz arm.
        let mut body = alloc::vec![0x0B | 0x80];
        body.extend_from_slice(&TERMINAL_ZINT_EXT);
        assert_sentinel_survived(&batch_after(&body), "unknown declaration kind");
    }

    /// wz HOLDS the chain where both upstreams DISCARD it (zenoh's `skip`,
    /// pico's `skip_non_mandatories`), so a decoded body re-encodes to the bytes
    /// it came from. That is a superset of upstream behaviour, and it separates
    /// "the chain is consumed" from "the chain is modelled" — a skip-only
    /// decoder passes every test above and fails this one.
    #[test]
    fn a_decoded_z_flagged_body_re_encodes_to_the_bytes_it_came_from() {
        use sce_forge_runtime::codec::SceCursor;
        let wire = alloc::vec![
            wire_const::N_MID_DECLARE,
            0x02 | 0x80, // DeclSubscriber | Z
            0x07,
            0x00,
            0x21,
            0x2A,
        ];
        let mut cursor = SceCursor::new(&wire);
        let decoded = wz_codecs::declare::Declare::decode(&mut cursor).expect("decode");
        assert_eq!(
            cursor.remaining(),
            0,
            "the decode left the extension bytes on the cursor"
        );
        assert_eq!(decoded.encode_to_vec(), wire);
    }
}
