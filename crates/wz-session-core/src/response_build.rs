// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Response-builder cluster — runtime-agnostic wire-record construction
//! for the queryable reply path. The minimal one-shot helpers
//! (`build_response_{reply,err}_{literal,aliased}`) plus the fluent
//! [`ResponseReplyBuilder`] / [`ResponseErrBuilder`] compose a
//! `Response(Reply|Err)` network message from a `request_id`, a keyexpr
//! (literal or peer-aliased), and a payload — mirroring zenoh-pico's
//! `_z_response_encode -> _z_{reply,err}_encode` chain.
//!
//! R311dv — lifted verbatim from `wz-runtime-tokio::session_glue`.
//! The cluster is pure value construction over `wz_codecs` records (no
//! `async`, no `LinkDriver`, no tokio), so it belongs in the no_std
//! core where both the tokio (AP) and lwIP (MCU) runtimes can reach it.
//! `wz-runtime-tokio::session_glue` re-exports the public surface so
//! `crate::session_glue::{build_response_*, Response*Builder}` callers
//! (the `query.rs` `into_response` path + the session_glue regression
//! tests) resolve unchanged. The whole module gates on `codec-response`
//! — without the Response codec there is no wire frame to build.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use wz_codecs::encoding::Encoding;
use wz_codecs::err::Err;
use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
use wz_codecs::ext_zbuf::ExtZbuf;
use wz_codecs::msg_del::MsgDel;
use wz_codecs::msg_put::MsgPut;
use wz_codecs::reply::{Reply, ReplyVariant};
use wz_codecs::response::{Response, ResponseVariant};
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;

use crate::query_mode::ConsolidationMode;

/// R121j-3 — build a `Response(Reply(MsgPut))` network-message in
/// the minimal AP MVP shape (no Response-level exts, no Reply-level
/// consolidation, no Reply-level exts, no MsgPut timestamp /
/// encoding / exts). The wire is the queryable's data response to
/// an earlier `Request(Query)` keyed by `request_id`.
///
/// Mirrors the zenoh-pico encoder chain
/// `_z_response_encode -> _z_reply_encode -> _z_push_body_encode ->
/// _z_msg_put_encode`
/// (vendor/zenoh-pico/src/protocol/codec/network.c:241-304 +
/// vendor/zenoh-pico/src/protocol/codec/message.c:507-543 +
/// the put-encode at message.c:259-310).
///
/// Wire shape (literal-keyexpr case — `id=0 + suffix`):
///
/// ```text
///   [Response.header = _Z_MID_N_RESPONSE(0x1B)
///                       | _Z_FLAG_N_RESPONSE_N(0x20)         // suffix present
///                       | _Z_FLAG_N_RESPONSE_M(0x40)         // wireexpr Local arm (codegen-derived)
///                       | Z(0x00)]                           // no Response exts
///   VLE(request_id)
///   wireexpr Local: VLE(id=0), VLE(suffix.len()), suffix bytes
///   [Reply.header = _Z_MID_Z_REPLY(0x04)]                    // no C, no Z
///   [MsgPut.header = _Z_MID_Z_PUT(0x01)]                     // no T, no E, no Z
///   VLE(payload.len())
///   payload bytes
/// ```
///
/// `keyexpr_suffix` is required (no `Option<&str>`): the literal
/// shape's whole point is to carry the keyexpr inline, so an
/// empty / None literal would be a bug. For aliased-keyexpr replies
/// (publisher sent the matching Query through a mapped id), use
/// [`build_response_reply_aliased`].
///
/// Future R121j-3 sub-helpers (audit-traced carry):
/// `_with_consolidation(mode)` sets Reply.header.C(0x20) + 1-byte
/// consolidation; `_with_responder(zid, eid)` sets Response.header.Z
/// and emits the Responder ext (ext_id=0x03 ZBUF, zid+eid encoding
/// per network.c:281-291); `_with_reply_del(...)` swaps the MsgPut
/// arm for a MsgDel arm (delete instead of put as the reply payload).
#[cfg(feature = "codec-response")]
pub fn build_response_reply_literal(
    request_id: u64,
    keyexpr_suffix: &str,
    payload: &[u8],
) -> Response {
    assert!(
        !keyexpr_suffix.is_empty(),
        "build_response_reply_literal requires a non-empty keyexpr suffix; \
         the literal shape's purpose is to carry the keyexpr inline",
    );
    let suffix_string = keyexpr_suffix.to_string();
    let suffix_len = Some(suffix_string.len() as u64);
    Response {
        // MID 0x1B | N 0x20 (suffix present) | M codegen-derived
        // (Local arm sets 0x40). Z stays clear (no Response exts).
        header: 0x1B | 0x20,
        request_id,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len,
                suffix: Some(suffix_string),
            }),
        },
        extensions: None,
        body: ResponseVariant::CodecZenohReply(Reply {
            // MID 0x04 only; no C (consolidation), no Z (Reply exts).
            header: 0x04,
            consolidation: None,
            extensions: None,
            body: ReplyVariant::CodecZenohMsgPut(MsgPut {
                // MID 0x01 only; no T/E/Z gates.
                header: 0x01,
                timestamp: None,
                encoding: None,
                extensions: None,
                payload_len: payload.len() as u64,
                payload: payload.to_vec(),
            }),
        }),
    }
}

/// R121j-3 — build a `Response(Reply(MsgPut))` for a peer-declared
/// keyexpr mapping (aliased path). Mirror of
/// [`build_response_reply_literal`] for the case where the original
/// `Request(Query)` keyexpr resolved via a `Declare(DeclKexpr)`
/// previously sent in this session. The queryable replies referencing
/// the same mapping_id so the requester's wireexpr table resolves
/// the response to the original query keyexpr.
///
/// Convention matches the DECLARE / Request builders:
///   - `(N, None)`: pure alias — Reply targets peer's mapping for `N`.
///   - `(N, Some(s))`: compound — alias `N`'s prefix + suffix `s`.
///
/// Panics on `mapping_id == 0` — id=0 is the literal-keyexpr sentinel;
/// for literal replies use [`build_response_reply_literal`].
#[cfg(feature = "codec-response")]
pub fn build_response_reply_aliased(
    request_id: u64,
    mapping_id: u64,
    suffix: Option<&str>,
    payload: &[u8],
) -> Response {
    assert!(
        mapping_id != 0,
        "build_response_reply_aliased requires a non-zero mapping id; \
         use build_response_reply_literal for the literal keyexpr case",
    );
    let suffix_string = suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Response {
        header: 0x1B | n_flag,
        request_id,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: ResponseVariant::CodecZenohReply(Reply {
            header: 0x04,
            consolidation: None,
            extensions: None,
            body: ReplyVariant::CodecZenohMsgPut(MsgPut {
                header: 0x01,
                timestamp: None,
                encoding: None,
                extensions: None,
                payload_len: payload.len() as u64,
                payload: payload.to_vec(),
            }),
        }),
    }
}

/// R121j-4 — build a `Response(Err)` network-message in the minimal
/// AP MVP shape (no Response-level exts, no Err encoding, no Err
/// exts). The wire is the queryable's error response to a Query that
/// it could not service — mirror of [`build_response_reply_literal`]
/// with the inner body arm swapped from `Reply` (MID 0x04) to `Err`
/// (MID 0x05). Same Response envelope shape: a peer expecting either
/// a Reply or Err discriminates on the inner MID byte after the
/// Response header / rid / wireexpr / Z-gated exts.
///
/// Mirrors zenoh-pico `_z_response_encode -> _z_err_encode` chain
/// (vendor/zenoh-pico/src/protocol/codec/network.c:241-304 +
/// vendor/zenoh-pico/src/protocol/codec/message.c:545+).
///
/// Wire shape (literal-keyexpr case — `id=0 + suffix`):
///
/// ```text
///   [Response.header = _Z_MID_N_RESPONSE(0x1B)
///                       | _Z_FLAG_N_RESPONSE_N(0x20)
///                       | _Z_FLAG_N_RESPONSE_M(0x40)
///                       | Z(0x00)]
///   VLE(request_id)
///   wireexpr Local: VLE(id=0), VLE(suffix.len()), suffix bytes
///   [Err.header = _Z_MID_Z_ERR(0x05)]            // no E, no Z
///   VLE(payload.len())
///   payload bytes
/// ```
///
/// `payload` is the error message body. zenoh-pico's `_z_err_encode`
/// at message.c:545+ writes `[Err.header | E | Z]` then the
/// E-gated Encoding sub-codec, then the Z-gated extension chain
/// (source_info / attachment), then always-present payload_len + bytes.
/// The minimal helper here emits only the always-present pair — no
/// encoding hint, no source-info, no attachment.
#[cfg(feature = "codec-response")]
pub fn build_response_err_literal(
    request_id: u64,
    keyexpr_suffix: &str,
    payload: &[u8],
) -> Response {
    assert!(
        !keyexpr_suffix.is_empty(),
        "build_response_err_literal requires a non-empty keyexpr suffix; \
         the literal shape's purpose is to carry the keyexpr inline",
    );
    let suffix_string = keyexpr_suffix.to_string();
    let suffix_len = Some(suffix_string.len() as u64);
    Response {
        header: 0x1B | 0x20, // MID | N (M codegen-derived from Local)
        request_id,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len,
                suffix: Some(suffix_string),
            }),
        },
        extensions: None,
        body: ResponseVariant::CodecZenohErr(Err {
            // MID 0x05 only; no E (encoding), no Z (exts).
            header: 0x05,
            encoding: None,
            extensions: None,
            payload_len: payload.len() as u64,
            payload: payload.to_vec(),
        }),
    }
}

/// R121j-4 — build a `Response(Err)` for a peer-declared keyexpr
/// mapping (aliased path). Mirror of [`build_response_err_literal`]
/// for the aliased case — same convention as the other DECLARE /
/// Request / Reply aliased builders ((N,None) pure alias /
/// (N,Some) compound). Panics on mapping_id=0.
#[cfg(feature = "codec-response")]
pub fn build_response_err_aliased(
    request_id: u64,
    mapping_id: u64,
    suffix: Option<&str>,
    payload: &[u8],
) -> Response {
    assert!(
        mapping_id != 0,
        "build_response_err_aliased requires a non-zero mapping id; \
         use build_response_err_literal for the literal keyexpr case",
    );
    let suffix_string = suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    Response {
        header: 0x1B | n_flag,
        request_id,
        keyexpr: Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: ResponseVariant::CodecZenohErr(Err {
            header: 0x05,
            encoding: None,
            extensions: None,
            payload_len: payload.len() as u64,
            payload: payload.to_vec(),
        }),
    }
}

/// R121j-2b — fluent builder for `Response(Reply)` that composes the
/// Reply-layer + Response-layer options on top of the minimal-shape
/// baseline provided by [`build_response_reply_literal`] /
/// [`build_response_reply_aliased`]. Mirror of `RequestQueryBuilder`
/// on the Response side.
///
/// Keyexpr convention (matches the rest of the wz builder family):
///   - `(0, Some(s))`: literal — Reply carries inline keyexpr suffix `s`.
///   - `(N, None)`: pure alias — Reply targets peer's mapping for `N`.
///   - `(N, Some(s))`: compound — alias `N`'s prefix + suffix `s`.
///
/// Reply-layer setters today: `consolidation` (R121j-3a), `reply_del`
/// body-arm swap (R121j-3d), and `responder` envelope-level ext
/// (R121j-3c). R121j-3b (Reply-body source_info as a Reply-LEVEL ext)
/// is wire-absent per zenoh-pico `_z_reply_encode` at
/// `src/protocol/codec/message.c:507-519` (no extensions chain on the
/// Reply body); the carry was retracted in Round 121j-4-retract.
#[cfg(feature = "codec-response")]
pub struct ResponseReplyBuilder {
    request_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<String>,
    payload: Vec<u8>,
    // Reply-body-arm selector. Default false = MsgPut (the put-data
    // reply); .reply_del() flips to MsgDel (the delete-keyexpr reply).
    // Payload is unused when body_kind_del is true — the MsgDel body
    // carries no payload, just an optional timestamp + ext chain.
    body_kind_del: bool,
    // Reply-layer settings.
    consolidation: Option<ConsolidationMode>,
    // R121j-3c: Response-ENVELOPE-level responder ext (ext_id 0x03 ZBUF).
    // Tuple = (zid bytes 1..=16, eid). Distinct from R121j-4b Err.source_info
    // (Err-body-level): responder sits on the outer Response.extensions
    // chain, applies symmetrically to Reply and Err bodies, and is keyed
    // by zenoh-pico ext_id 0x03 per network.c:281-291. The Reply/Err inner
    // body is unaffected; envelope-level Z(0x80) on Response.header
    // signals chain presence.
    responder: Option<(Vec<u8>, u32)>,
}

#[cfg(feature = "codec-response")]
impl ResponseReplyBuilder {
    /// Begin a builder rooted in the same baseline contract as
    /// [`build_response_reply_literal`] / [`build_response_reply_aliased`]:
    /// minimal Response(Reply) envelope with the keyexpr arm
    /// (literal id=0 + Some, alias id=N + None, compound id=N + Some).
    pub fn new(
        request_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
        payload: &[u8],
    ) -> Self {
        Self {
            request_id,
            keyexpr_mapping_id,
            keyexpr_suffix: keyexpr_suffix.map(str::to_string),
            payload: payload.to_vec(),
            body_kind_del: false,
            consolidation: None,
            responder: None,
        }
    }

    /// Set the Reply-body consolidation mode. Subsequent calls
    /// overwrite (last-wins). Mirror of
    /// `RequestQueryBuilder::consolidation` — same
    /// [`ConsolidationMode`] enum, same wire-byte contract, applied to
    /// `Reply.header._Z_FLAG_Z_R_C(0x20)` + 1-byte consolidation.
    pub fn consolidation(mut self, mode: ConsolidationMode) -> Self {
        self.consolidation = Some(mode);
        self
    }

    /// Swap the inner Reply body arm from `MsgPut` (the default
    /// put-data reply) to `MsgDel` (the delete-keyexpr reply). The
    /// payload supplied to [`Self::new`] is dropped on the MsgDel
    /// path — `MsgDel` carries no payload, only an optional
    /// timestamp + ext chain.
    ///
    /// Mirrors zenoh-pico's `_z_reply_encode` dispatch on the inner
    /// MID byte: `_Z_MID_Z_PUT(0x01)` vs `_Z_MID_Z_DEL(0x02)`. The
    /// outer Response envelope (header / rid / wireexpr) is identical
    /// between the two arms; only the body inner MID + body shape
    /// differs.
    pub fn reply_del(mut self) -> Self {
        self.body_kind_del = true;
        self
    }

    /// R121j-3c — attach a `responder` extension to the outer Response
    /// envelope. `zid` is the responder's ZenohId (1..=16 raw bytes,
    /// packed as `(zid_len - 1) << 4` in the leading byte per
    /// zenoh-pico's `_z_response_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c:281-291`).
    /// `eid` is the responder's entity-id (z-int).
    ///
    /// **Envelope-level vs body-level**: the responder ext sits on
    /// `Response.extensions` (alongside future qos / timestamp exts —
    /// network.c emit order is qos → tstamp → responder), NOT on the
    /// Reply body's own extensions chain. The Reply body has no
    /// extensions surface (see `_z_reply_encode` message.c:507-519);
    /// envelope-level identification of the responding queryable is
    /// the wire-level shape regardless of Reply vs Err inner body.
    ///
    /// Today this lands as the sole entry in `Response.extensions`
    /// (no Z chain-continuation bit). When future envelope exts (qos,
    /// tstamp) land, the chain-plumb step mirrors
    /// `RequestQueryBuilder::build` at
    /// session_glue.rs:2772-2782.
    ///
    /// Panics if `zid.len()` is outside `1..=16`.
    pub fn responder(mut self, zid: &[u8], eid: u32) -> Self {
        assert!(
            (1..=16).contains(&zid.len()),
            "ResponseReplyBuilder::responder requires zid length 1..=16 \
             (zenoh-pico ZenohId wire constraint, transport.h:31-37)"
        );
        self.responder = Some((zid.to_vec(), eid));
        self
    }

    /// Materialise the Response. Constructs the baseline envelope via
    /// the existing literal-or-aliased builder, then applies the
    /// Reply-layer settings. Panics on `(mapping_id=0, suffix=None)`
    /// because the literal path requires an inline keyexpr suffix.
    pub fn build(self) -> Response {
        let mut response = if self.keyexpr_mapping_id == 0 {
            let suffix = self.keyexpr_suffix.as_deref().unwrap_or_else(|| {
                panic!(
                    "ResponseReplyBuilder literal path (mapping_id=0) requires \
                     a non-empty keyexpr_suffix; use mapping_id != 0 for aliased",
                )
            });
            build_response_reply_literal(self.request_id, suffix, &self.payload)
        } else {
            build_response_reply_aliased(
                self.request_id,
                self.keyexpr_mapping_id,
                self.keyexpr_suffix.as_deref(),
                &self.payload,
            )
        };

        if let ResponseVariant::CodecZenohReply(ref mut reply) = response.body {
            if self.body_kind_del {
                // Swap MsgPut arm for MsgDel arm. The MsgPut allocated
                // by build_response_reply_literal/aliased gets dropped
                // here — the perf cost is one wasted MsgPut struct per
                // del-reply build, acceptable for the additive shape
                // of this round. A future refactor can split the
                // baseline helpers to expose envelope-only construction
                // without the put body, but the present additive
                // shape keeps the one-shot helpers unchanged.
                reply.body = ReplyVariant::CodecZenohMsgDel(MsgDel {
                    header: 0x02, // _Z_MID_Z_DEL
                    timestamp: None,
                    extensions: None,
                });
            }
            if let Some(mode) = self.consolidation {
                reply.header |= 0x20; // _Z_FLAG_Z_R_C
                reply.consolidation = Some(mode.wire_byte());
            }
        } else {
            unreachable!(
                "build_response_reply_* must produce a CodecZenohReply body — \
                 the layered builder relies on this invariant"
            );
        }

        // Envelope-level extension (Response.extensions). Today the
        // only ext we expose is responder (R121j-3c); future qos /
        // tstamp setters layer in here with the same Vec<ExtEntry>
        // chain-plumb idiom used in RequestQueryBuilder.build.
        if let Some((zid, eid)) = self.responder {
            let value = encode_responder_ext_body(&zid, eid);
            response.header |= 0x80; // _Z_FLAG_Z_Z on Response envelope
            response.extensions = Some(vec![ExtEntry {
                // ENC_ZBUF(0x40) | id_responder(0x03). No M flag and no
                // Z chain-continuation (sole envelope ext today).
                header: 0x40 | 0x03,
                body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                    value_len: value.len() as u64,
                    value,
                }),
            }]);
        }

        response
    }
}

/// R121j-2b — fluent builder for `Response(Err)` that composes the
/// Err-layer options on top of the minimal-shape baseline provided by
/// [`build_response_err_literal`] / [`build_response_err_aliased`].
/// Mirror of [`ResponseReplyBuilder`] for the Err inner-body arm.
///
/// Err-layer setters today: `encoding(id, schema)` (R121j-4a),
/// `source_info(zid, eid, sn)` (R121j-4b), and the envelope-level
/// `responder(zid, eid)` (R121j-3c, applied symmetrically with
/// [`ResponseReplyBuilder::responder`]). R121j-4c (Err.attachment) is
/// wire-absent per zenoh-pico `_z_err_encode` at
/// `src/protocol/codec/message.c:545-573` (only `encoding` flag-driven
/// inline encode + source_info ext are emitted); the carry was
/// retracted in Round 121j-4-retract.
#[cfg(feature = "codec-response")]
pub struct ResponseErrBuilder {
    request_id: u64,
    keyexpr_mapping_id: u64,
    keyexpr_suffix: Option<String>,
    payload: Vec<u8>,
    // Err-layer settings. Tuple = (id, optional schema). packed_id =
    // (id << 1) | has_schema computed at build() time.
    encoding: Option<(u32, Option<String>)>,
    // R121j-4b: Err-body source_info ext (ext_id 0x01 ZBUF). Tuple =
    // (zid bytes 1..=16, eid, sn). zid owned to outlive the builder;
    // wire body packed at build() time via
    // [`encode_source_info_ext_body`] and wrapped in an ExtZbuf entry.
    source_info: Option<(Vec<u8>, u32, u32)>,
    // R121j-3c: Response-ENVELOPE-level responder ext (ext_id 0x03 ZBUF).
    // Identical shape and emit-site to [`ResponseReplyBuilder::responder`]
    // — Response envelope ext applies symmetrically to Reply and Err
    // inner bodies (zenoh-pico network.c:281-291 has one encoder branch
    // that fires for both _Z_RESPONSE_BODY_REPLY and _Z_RESPONSE_BODY_ERR).
    responder: Option<(Vec<u8>, u32)>,
}

#[cfg(feature = "codec-response")]
impl ResponseErrBuilder {
    /// Begin a builder rooted in the same baseline contract as
    /// [`build_response_err_literal`] / [`build_response_err_aliased`]:
    /// minimal Response(Err) envelope with the keyexpr arm
    /// (literal id=0 + Some, alias id=N + None, compound id=N + Some).
    pub fn new(
        request_id: u64,
        keyexpr_mapping_id: u64,
        keyexpr_suffix: Option<&str>,
        payload: &[u8],
    ) -> Self {
        Self {
            request_id,
            keyexpr_mapping_id,
            keyexpr_suffix: keyexpr_suffix.map(str::to_string),
            payload: payload.to_vec(),
            encoding: None,
            source_info: None,
            responder: None,
        }
    }

    /// Set the Err encoding hint. `id` is the zenoh-pico content-type
    /// prefix (e.g. 4 = application/json — see
    /// `vendor/zenoh-pico/include/zenoh-pico/api/constants.h`);
    /// `schema` is the optional schema fragment appended after the
    /// prefix. The wire `packed_id = (id << 1) | has_schema_bit`
    /// composition follows zenoh-pico's `_z_encoding_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/core.c` — the LSB carries
    /// the schema-present discriminator so the decoder can parse the
    /// optional suffix conditionally.
    pub fn encoding(mut self, id: u32, schema: Option<&str>) -> Self {
        self.encoding = Some((id, schema.map(str::to_string)));
        self
    }

    /// R121j-4b — set the Err-body `source_info` extension. `zid` is the
    /// peer's ZenohId (1..=16 raw bytes; `(zid_len - 1) << 4` packs the
    /// length into the leading ext byte per zenoh-pico's
    /// `_z_source_info_encode_ext` at
    /// `vendor/zenoh-pico/src/protocol/codec/message.c:243-254`). `eid`
    /// is the peer's entity-id; `sn` is the per-source sequence number
    /// that scopes Reply ordering on the requester side.
    ///
    /// The ext lands as the sole entry in `Err.extensions` because
    /// zenoh-pico's `_z_err_encode` (`message.c:545-573`) emits
    /// source_info as the only ext-chain element with header
    /// `_Z_MSG_EXT_ENC_ZBUF | 0x01` and no Z chain-continuation bit.
    /// When future Err-level exts land they will plumb the chain bits
    /// through a `Vec<ExtEntry>` build mirroring
    /// `RequestQueryBuilder::build`.
    ///
    /// Panics if `zid.len()` is outside `1..=16`.
    pub fn source_info(mut self, zid: &[u8], eid: u32, sn: u32) -> Self {
        assert!(
            (1..=16).contains(&zid.len()),
            "ResponseErrBuilder::source_info requires zid length 1..=16 \
             (zenoh-pico ZenohId wire constraint, transport.h:31-37)"
        );
        self.source_info = Some((zid.to_vec(), eid, sn));
        self
    }

    /// R121j-3c — attach a `responder` extension to the outer Response
    /// envelope. Mirror of [`ResponseReplyBuilder::responder`]: same
    /// wire bytes, same emit site (`Response.extensions`), same
    /// `_Z_FLAG_Z_Z(0x80)` envelope-level header bit. Provided on
    /// ErrBuilder because zenoh-pico's `_z_response_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c:281-291` runs
    /// the same responder-ext branch for Reply and Err inner bodies;
    /// the wire is symmetric.
    ///
    /// Panics if `zid.len()` is outside `1..=16`.
    pub fn responder(mut self, zid: &[u8], eid: u32) -> Self {
        assert!(
            (1..=16).contains(&zid.len()),
            "ResponseErrBuilder::responder requires zid length 1..=16 \
             (zenoh-pico ZenohId wire constraint, transport.h:31-37)"
        );
        self.responder = Some((zid.to_vec(), eid));
        self
    }

    /// Materialise the Response. Constructs the baseline envelope via
    /// the existing literal-or-aliased builder, then applies the
    /// Err-layer settings. Panics on `(mapping_id=0, suffix=None)`
    /// because the literal path requires an inline keyexpr suffix.
    pub fn build(self) -> Response {
        let mut response = if self.keyexpr_mapping_id == 0 {
            let suffix = self.keyexpr_suffix.as_deref().unwrap_or_else(|| {
                panic!(
                    "ResponseErrBuilder literal path (mapping_id=0) requires \
                     a non-empty keyexpr_suffix; use mapping_id != 0 for aliased",
                )
            });
            build_response_err_literal(self.request_id, suffix, &self.payload)
        } else {
            build_response_err_aliased(
                self.request_id,
                self.keyexpr_mapping_id,
                self.keyexpr_suffix.as_deref(),
                &self.payload,
            )
        };

        if let ResponseVariant::CodecZenohErr(ref mut err) = response.body {
            if let Some((id, schema)) = self.encoding {
                err.header |= 0x40; // _Z_FLAG_Z_E (Err encoding present)
                let has_schema = schema.is_some();
                let packed = (id << 1) | if has_schema { 1 } else { 0 };
                err.encoding = Some(Encoding {
                    packed_id: packed,
                    schema_len: schema.as_ref().map(|s| s.len() as u64),
                    schema,
                });
            }
            if let Some((zid, eid, sn)) = self.source_info {
                let value = encode_source_info_ext_body(&zid, eid, sn);
                // _Z_FLAG_Z_Z(0x80) signals ext-chain presence to the
                // peer's `_z_err_decode` (message.c:594-595).
                err.header |= 0x80;
                err.extensions = Some(vec![ExtEntry {
                    // ENC_ZBUF(0x40) | id_source_info(0x01). No M flag
                    // (informational hint) and no Z chain-continuation
                    // (single entry today; the chain-plumb step lands
                    // once a second Err ext exists, mirroring
                    // RequestQueryBuilder.build at
                    // session_glue.rs:2772-2782).
                    header: 0x40 | 0x01,
                    body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                        value_len: value.len() as u64,
                        value,
                    }),
                }]);
            }
        } else {
            unreachable!(
                "build_response_err_* must produce a CodecZenohErr body — \
                 the layered builder relies on this invariant"
            );
        }

        // Envelope-level extension (Response.extensions). Mirror of the
        // same step in [`ResponseReplyBuilder::build`] — the responder
        // ext is shared between Reply and Err envelopes.
        if let Some((zid, eid)) = self.responder {
            let value = encode_responder_ext_body(&zid, eid);
            response.header |= 0x80; // _Z_FLAG_Z_Z on Response envelope
            response.extensions = Some(vec![ExtEntry {
                header: 0x40 | 0x03,
                body: ExtEntryVariant::CodecZenohExtZbuf(ExtZbuf {
                    value_len: value.len() as u64,
                    value,
                }),
            }]);
        }

        response
    }
}

/// R121j-4b — encode the value bytes of a `source_info` extension per
/// zenoh-pico's `_z_source_info_encode_ext` at
/// `vendor/zenoh-pico/src/protocol/codec/message.c:243-254`.
///
/// Wire layout (the bytes this fn returns; the surrounding ExtZbuf
/// codec prepends its own `VLE(value_len)` length prefix that maps to
/// zenoh-pico's leading `zsize(ext_size)`):
///
///   [byte 0]            `((zid_len - 1) << 4)` — high nibble carries
///                        `zid_len - 1` (1..=16 valid, encoded 0..=15).
///   [byte 1..1+zid_len] raw zid bytes (caller's MSB-first id slice).
///   [VLE u64]            `eid`.
///   [VLE u64]            `sn`.
///
/// Panics if `zid.len()` is outside `1..=16` (the caller's setter
/// guards this; the inner assertion is defence-in-depth).
#[cfg(feature = "codec-response")]
pub fn encode_source_info_ext_body(zid: &[u8], eid: u32, sn: u32) -> Vec<u8> {
    assert!(
        (1..=16).contains(&zid.len()),
        "source_info zid length must be 1..=16 (zenoh-pico ZenohId wire constraint)"
    );
    // Capacity = 1 leading byte + zid + VLE(u32) worst-case (5 bytes) ×2.
    let mut out = Vec::with_capacity(1 + zid.len() + 5 + 5);
    out.push(((zid.len() as u8) - 1) << 4);
    out.extend_from_slice(zid);
    encode_vle_u64_into(&mut out, eid as u64);
    encode_vle_u64_into(&mut out, sn as u64);
    out
}

/// R121j-4b — base-128 VLE u64 emit into a `Vec<u8>`. Mirrors the
/// inline loop in `encode_frame_envelope` and zenoh-pico's
/// `_z_zsize_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/core.c`. Free-function shape
/// because source_info ext-body construction happens before any
/// `SceSink` is in scope — the ext body lives inside `ExtZbuf.value`
/// and the surrounding codec sink only sees the already-built `Vec`.
#[cfg(feature = "codec-response")]
fn encode_vle_u64_into(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7F) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// R121j-3c — encode the value bytes of a `responder` extension per
/// zenoh-pico's `_z_response_encode` at
/// `vendor/zenoh-pico/src/protocol/codec/network.c:281-291`.
///
/// Wire layout (the bytes this fn returns; the surrounding ExtZbuf
/// codec prepends its own `VLE(value_len)` length prefix that maps to
/// zenoh-pico's leading `zsize(ext_size)`):
///
///   [byte 0]            `((zid_len - 1) << 4)` — high nibble carries
///                        `zid_len - 1` (1..=16 valid, encoded 0..=15).
///   [byte 1..1+zid_len] raw zid bytes.
///   [VLE u64]            `eid`.
///
/// Distinct from [`encode_source_info_ext_body`] in that no `sn`
/// trailer is emitted — responder identifies the entity, source_info
/// identifies the entity + per-source sequence position.
///
/// Panics if `zid.len()` is outside `1..=16` (the caller's setter
/// guards this; the inner assertion is defence-in-depth).
#[cfg(feature = "codec-response")]
pub fn encode_responder_ext_body(zid: &[u8], eid: u32) -> Vec<u8> {
    assert!(
        (1..=16).contains(&zid.len()),
        "responder zid length must be 1..=16 (zenoh-pico ZenohId wire constraint)"
    );
    // Capacity = 1 leading byte + zid + VLE(u32) worst-case (5 bytes).
    let mut out = Vec::with_capacity(1 + zid.len() + 5);
    out.push(((zid.len() as u8) - 1) << 4);
    out.extend_from_slice(zid);
    encode_vle_u64_into(&mut out, eid as u64);
    out
}
