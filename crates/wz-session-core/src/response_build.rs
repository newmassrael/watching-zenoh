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

use wz_codecs::encoding::EncodingOwned;
use wz_codecs::err::ErrOwned;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_zbuf::ExtZbufOwned;
use wz_codecs::msg_del::MsgDelOwned;
use wz_codecs::msg_put::MsgPutOwned;
use wz_codecs::reply::{ReplyOwned, ReplyOwnedVariant};
use wz_codecs::response::{ResponseOwned, ResponseOwnedVariant};
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
use wz_codecs::wireexpr_local::WireexprLocalOwned;

use crate::query_mode::ConsolidationMode;
// R311ek — the source_info ext encoder + the shared VLE primitive moved
// to the codec-feature-agnostic `source_info_ext` module so the
// `codec-push` body-extension path can reach the encoder too; the
// responder encoder below keeps borrowing the VLE helper from there.
use crate::source_info_ext::{encode_source_info_ext_body, encode_vle_u64_into};

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
) -> ResponseOwned {
    assert!(
        !keyexpr_suffix.is_empty(),
        "build_response_reply_literal requires a non-empty keyexpr suffix; \
         the literal shape's purpose is to carry the keyexpr inline",
    );
    let suffix_string = keyexpr_suffix.to_string();
    let suffix_len = Some(suffix_string.len() as u64);
    ResponseOwned {
        // MID 0x1B | N 0x20 (suffix present) | M codegen-derived
        // (Local arm sets 0x40). Z stays clear (no Response exts).
        header: 0x1B | 0x20,
        request_id,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: 0,
                suffix_len,
                suffix: Some(suffix_string),
            }),
        },
        extensions: None,
        body: ResponseOwnedVariant::CodecZenohReply(ReplyOwned {
            // MID 0x04 only; no C (consolidation), no Z (Reply exts).
            header: 0x04,
            consolidation: None,
            extensions: None,
            body: ReplyOwnedVariant::CodecZenohMsgPut(MsgPutOwned {
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
) -> ResponseOwned {
    assert!(
        mapping_id != 0,
        "build_response_reply_aliased requires a non-zero mapping id; \
         use build_response_reply_literal for the literal keyexpr case",
    );
    let suffix_string = suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    ResponseOwned {
        header: 0x1B | n_flag,
        request_id,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: ResponseOwnedVariant::CodecZenohReply(ReplyOwned {
            header: 0x04,
            consolidation: None,
            extensions: None,
            body: ReplyOwnedVariant::CodecZenohMsgPut(MsgPutOwned {
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
) -> ResponseOwned {
    assert!(
        !keyexpr_suffix.is_empty(),
        "build_response_err_literal requires a non-empty keyexpr suffix; \
         the literal shape's purpose is to carry the keyexpr inline",
    );
    let suffix_string = keyexpr_suffix.to_string();
    let suffix_len = Some(suffix_string.len() as u64);
    ResponseOwned {
        header: 0x1B | 0x20, // MID | N (M codegen-derived from Local)
        request_id,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: 0,
                suffix_len,
                suffix: Some(suffix_string),
            }),
        },
        extensions: None,
        body: ResponseOwnedVariant::CodecZenohErr(ErrOwned {
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
) -> ResponseOwned {
    assert!(
        mapping_id != 0,
        "build_response_err_aliased requires a non-zero mapping id; \
         use build_response_err_literal for the literal keyexpr case",
    );
    let suffix_string = suffix.map(str::to_string);
    let suffix_len = suffix_string.as_ref().map(|s| s.len() as u64);
    let n_flag = if suffix.is_some() { 0x20u8 } else { 0x00u8 };
    ResponseOwned {
        header: 0x1B | n_flag,
        request_id,
        keyexpr: WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id: mapping_id,
                suffix_len,
                suffix: suffix_string,
            }),
        },
        extensions: None,
        body: ResponseOwnedVariant::CodecZenohErr(ErrOwned {
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
    pub fn build(self) -> ResponseOwned {
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

        if let ResponseOwnedVariant::CodecZenohReply(ref mut reply) = response.body {
            if self.body_kind_del {
                // Swap MsgPut arm for MsgDel arm. The MsgPut allocated
                // by build_response_reply_literal/aliased gets dropped
                // here — the perf cost is one wasted MsgPut struct per
                // del-reply build, acceptable for the additive shape
                // of this round. A future refactor can split the
                // baseline helpers to expose envelope-only construction
                // without the put body, but the present additive
                // shape keeps the one-shot helpers unchanged.
                reply.body = ReplyOwnedVariant::CodecZenohMsgDel(MsgDelOwned {
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
            response.extensions = Some(vec![ExtEntryOwned {
                // ENC_ZBUF(0x40) | id_responder(0x03). No M flag and no
                // Z chain-continuation (sole envelope ext today).
                header: 0x40 | 0x03,
                body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
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
    pub fn build(self) -> ResponseOwned {
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

        if let ResponseOwnedVariant::CodecZenohErr(ref mut err) = response.body {
            if let Some((id, schema)) = self.encoding {
                err.header |= 0x40; // _Z_FLAG_Z_E (Err encoding present)
                let has_schema = schema.is_some();
                let packed = (id << 1) | if has_schema { 1 } else { 0 };
                err.encoding = Some(EncodingOwned {
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
                err.extensions = Some(vec![ExtEntryOwned {
                    // ENC_ZBUF(0x40) | id_source_info(0x01). No M flag
                    // (informational hint) and no Z chain-continuation
                    // (single entry today; the chain-plumb step lands
                    // once a second Err ext exists, mirroring
                    // RequestQueryBuilder.build at
                    // session_glue.rs:2772-2782).
                    header: 0x40 | 0x01,
                    body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
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
            response.extensions = Some(vec![ExtEntryOwned {
                header: 0x40 | 0x03,
                body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
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

// R311fs — the byte-stable Response reply/err builder regression
// tests, relocated from wz-runtime-tokio::session_glue to their SSOT
// home now that the production code lives here (R311dv). The builders
// are re-exported by session_glue, so the runtime crate kept duplicate
// copies after the move; this is the dedup. TestWire mirrors the
// session_glue owned->wire projection.
#[cfg(all(test, feature = "codec-response"))]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    trait TestWire {
        fn wire(&self) -> Vec<u8>;
    }
    impl TestWire for ResponseOwned {
        fn wire(&self) -> Vec<u8> {
            self.try_as_borrowed()
                .expect("test: <=N exts by construction")
                .encode_to_vec()
        }
    }

    /// R121j-3 — Wire-byte regression gate for
    /// `build_response_reply_literal`. The minimal Response(Reply(MsgPut))
    /// chain wire shape after the inner `_z_msg_put_encode` arm — no
    /// Response-level exts, no Reply-level consolidation/exts, no
    /// MsgPut timestamp/encoding/exts. Two vectors lock the alias
    /// rid + small payload and the multi-byte VLE boundary (rid=200).
    #[cfg(feature = "codec-response")]
    #[test]
    fn build_response_reply_literal_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — small request_id (42), literal keyexpr "demo/test",
        // payload "hello-reply".
        //   Response.header = MID(0x1B) | N(0x20) | M(0x40 codegen) = 0x7B
        //   VLE(rid=42) = 0x2A
        //   wireexpr Local: id=0 → 0x00, suffix_len(9) → 0x09, "demo/test"
        //   Reply.header = 0x04
        //   MsgPut.header = 0x01
        //   MsgPut.payload_len(11) → 0x0B
        //   payload "hello-reply"
        let small = build_response_reply_literal(42, "demo/test", b"hello-reply");
        let small_wire = small.wire();
        let mut small_expected = vec![
            0x7B, // Response: MID | N | M
            0x2A, // VLE(rid=42)
            0x00, // wireexpr.id VLE(0) literal sentinel
            0x09, // wireexpr.suffix_len VLE(9)
        ];
        small_expected.extend_from_slice(b"demo/test");
        small_expected.push(0x04); // Reply.header MID only
        small_expected.push(0x01); // MsgPut.header MID only
        small_expected.push(0x0B); // payload_len VLE(11)
        small_expected.extend_from_slice(b"hello-reply");
        assert_eq!(
            small_wire, small_expected,
            "Response(Reply(MsgPut)) literal wire bytes must match \
             zenoh-pico reference chain (network.c:241-304 + \
             message.c:507-543 + message.c:259-310)",
        );

        // Case 2 — multi-byte VLE boundary on rid (200 = 0xC8 0x01).
        let large = build_response_reply_literal(200, "k", b"v");
        let large_wire = large.wire();
        let large_expected = vec![
            0x7B, 0xC8, // VLE(200) low + cont
            0x01, // VLE(200) high
            0x00, // wireexpr id=0 literal
            0x01, // suffix_len(1)
            b'k', 0x04, // Reply.header
            0x01, // MsgPut.header
            0x01, // payload_len(1)
            b'v',
        ];
        assert_eq!(
            large_wire, large_expected,
            "Response(Reply) multi-byte VLE rid wire bytes must match \
             zenoh-pico reference",
        );

        // Inner-arm sanity.
        match &small.body {
            ResponseOwnedVariant::CodecZenohReply(reply) => {
                assert_eq!(reply.header, 0x04, "Reply.header MID only");
                assert!(reply.consolidation.is_none());
                assert!(reply.extensions.is_none());
                match &reply.body {
                    ReplyOwnedVariant::CodecZenohMsgPut(put) => {
                        assert_eq!(put.header, 0x01);
                        assert_eq!(put.payload_len, 11);
                        assert_eq!(put.payload.as_slice(), b"hello-reply");
                    }
                    _ => panic!("Reply.body must be CodecZenohMsgPut"),
                }
            }
            _ => panic!("Response.body must be CodecZenohReply"),
        }
    }

    #[cfg(feature = "codec-response")]
    #[test]
    #[should_panic(expected = "build_response_reply_literal requires a non-empty keyexpr suffix")]
    fn build_response_reply_literal_rejects_empty_suffix() {
        let _ = build_response_reply_literal(42, "", b"v");
    }

    /// R121j-3 — Wire-byte regression gate for
    /// `build_response_reply_aliased`. Three vectors lock the
    /// aliased / composite / aliased-large-VLE shapes.
    #[cfg(feature = "codec-response")]
    #[test]
    fn build_response_reply_aliased_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — pure alias (rid=42, mapping_id=7, no suffix,
        // payload "v"). Wire:
        //   Response.header = MID(0x1B) | M(0x40, no N) = 0x5B
        //   VLE(rid=42) = 0x2A
        //   wireexpr Local: id=7 → 0x07 (no suffix; N flag clear)
        //   Reply.header = 0x04
        //   MsgPut.header = 0x01
        //   payload_len(1) → 0x01
        //   payload "v"
        let alias = build_response_reply_aliased(42, 7, None, b"v");
        let alias_wire = alias.wire();
        assert_eq!(
            alias_wire,
            vec![
                0x5B, // Response: MID | M (no N)
                0x2A, 0x07, // wireexpr.id VLE(7)
                0x04, // Reply.header
                0x01, // MsgPut.header
                0x01, // payload_len(1)
                b'v',
            ],
            "Response(Reply) aliased no-suffix wire bytes must match \
             zenoh-pico reference",
        );

        // Case 2 — composite (rid=42, mapping_id=7, suffix "tail",
        // payload "data"). Wire:
        //   Response.header = MID | N | M = 0x7B
        //   wireexpr Local: id=7 + suffix_len(4) + "tail"
        let composite = build_response_reply_aliased(42, 7, Some("tail"), b"data");
        let composite_wire = composite.wire();
        let mut composite_expected = vec![
            0x7B, 0x2A, 0x07, // wireexpr.id
            0x04, // suffix_len(4)
        ];
        composite_expected.extend_from_slice(b"tail");
        composite_expected.push(0x04); // Reply.header
        composite_expected.push(0x01); // MsgPut.header
        composite_expected.push(0x04); // payload_len(4)
        composite_expected.extend_from_slice(b"data");
        assert_eq!(
            composite_wire, composite_expected,
            "Response(Reply) composite alias wire bytes must match \
             zenoh-pico reference",
        );

        // Case 3 — multi-byte VLE alias (mapping_id=200).
        let large = build_response_reply_aliased(42, 200, None, b"x");
        let large_wire = large.wire();
        assert_eq!(
            large_wire,
            vec![
                0x5B, 0x2A, 0xC8, 0x01, // wireexpr.id VLE(200)
                0x04, 0x01, 0x01, b'x',
            ],
            "Response(Reply) multi-byte VLE alias wire bytes must match \
             zenoh-pico reference",
        );
    }

    #[cfg(feature = "codec-response")]
    #[test]
    #[should_panic(expected = "build_response_reply_aliased requires a non-zero mapping id")]
    fn build_response_reply_aliased_rejects_zero_mapping_id() {
        let _ = build_response_reply_aliased(42, 0, Some("any"), b"v");
    }

    /// R121j-4 — Wire-byte regression gate for
    /// `build_response_err_literal`. Mirror of the Reply byte-compare
    /// with the inner body MID swap (0x04 → 0x05) and structural diff
    /// (Err has no payload prefix beyond payload_len; Reply wraps a
    /// MsgPut which itself has a MID byte before payload_len).
    /// Two vectors lock the small rid + literal keyexpr and the
    /// multi-byte VLE boundary.
    #[cfg(feature = "codec-response")]
    #[test]
    fn build_response_err_literal_emits_zenoh_pico_compatible_wire_bytes() {
        // Case 1 — rid=42, literal "k", payload "fail".
        //   Response.header = MID(0x1B) | N(0x20) | M(0x40) = 0x7B
        //   VLE(rid=42) = 0x2A
        //   wireexpr Local: id=0, suffix_len(1), "k"
        //   Err.header = 0x05
        //   payload_len(4) = 0x04
        //   "fail"
        let small = build_response_err_literal(42, "k", b"fail");
        let small_wire = small.wire();
        let mut small_expected = vec![
            0x7B, 0x2A, 0x00, // wireexpr id=0
            0x01, // suffix_len(1)
            b'k', 0x05, // Err.header (no MsgPut layer above this!)
            0x04, // payload_len(4)
        ];
        small_expected.extend_from_slice(b"fail");
        assert_eq!(
            small_wire, small_expected,
            "Response(Err) literal wire bytes must match zenoh-pico \
             reference (network.c:241-304 + message.c:545+)",
        );

        // Case 2 — multi-byte VLE rid (200).
        let large = build_response_err_literal(200, "x", b"e");
        let large_wire = large.wire();
        assert_eq!(
            large_wire,
            vec![
                0x7B, 0xC8, 0x01, // VLE(rid=200)
                0x00, // wireexpr id=0 literal
                0x01, // suffix_len(1)
                b'x', 0x05, // Err.header
                0x01, // payload_len(1)
                b'e',
            ],
            "Response(Err) multi-byte VLE rid wire bytes must match \
             zenoh-pico reference",
        );

        // Inner-arm sanity.
        match &small.body {
            ResponseOwnedVariant::CodecZenohErr(err) => {
                assert_eq!(err.header, 0x05, "Err.header MID only");
                assert!(err.encoding.is_none());
                assert!(err.extensions.is_none());
                assert_eq!(err.payload_len, 4);
                assert_eq!(err.payload.as_slice(), b"fail");
            }
            _ => panic!("Response.body must be CodecZenohErr"),
        }
    }

    #[cfg(feature = "codec-response")]
    #[test]
    #[should_panic(expected = "build_response_err_literal requires a non-empty keyexpr suffix")]
    fn build_response_err_literal_rejects_empty_suffix() {
        let _ = build_response_err_literal(42, "", b"v");
    }

    /// R121j-4 — Wire-byte regression gate for
    /// `build_response_err_aliased`. Mirror of the Reply aliased
    /// byte-compare with inner body MID swap.
    #[cfg(feature = "codec-response")]
    #[test]
    fn build_response_err_aliased_emits_zenoh_pico_compatible_wire_bytes() {
        // Pure alias: rid=42, mapping_id=7, no suffix, payload "e".
        let alias = build_response_err_aliased(42, 7, None, b"e");
        let alias_wire = alias.wire();
        assert_eq!(
            alias_wire,
            vec![
                0x5B, // Response: MID | M (no N)
                0x2A, // VLE(rid=42)
                0x07, // wireexpr.id VLE(7)
                0x05, // Err.header
                0x01, // payload_len(1)
                b'e',
            ],
            "Response(Err) aliased no-suffix wire bytes must match \
             zenoh-pico reference",
        );

        // Composite: rid=42, mapping_id=7, suffix "tail", payload "data".
        let composite = build_response_err_aliased(42, 7, Some("tail"), b"data");
        let composite_wire = composite.wire();
        let mut composite_expected = vec![
            0x7B, // Response: MID | N | M
            0x2A, 0x07, 0x04, // suffix_len(4)
        ];
        composite_expected.extend_from_slice(b"tail");
        composite_expected.push(0x05); // Err.header
        composite_expected.push(0x04); // payload_len(4)
        composite_expected.extend_from_slice(b"data");
        assert_eq!(
            composite_wire, composite_expected,
            "Response(Err) composite alias wire bytes must match \
             zenoh-pico reference",
        );
    }

    #[cfg(feature = "codec-response")]
    #[test]
    #[should_panic(expected = "build_response_err_aliased requires a non-zero mapping id")]
    fn build_response_err_aliased_rejects_zero_mapping_id() {
        let _ = build_response_err_aliased(42, 0, Some("any"), b"v");
    }

    /// R121j-2b — ResponseReplyBuilder with no setters must emit the
    /// exact same wire bytes as the baseline aliased helper. The
    /// builder is a strictly additive surface; it cannot silently
    /// change the minimal-shape output.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_reply_builder_no_setters_matches_aliased_baseline() {
        let direct = build_response_reply_aliased(42, 7, None, b"hello").wire();
        let built = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .build()
            .wire();
        assert_eq!(
            direct, built,
            "ReplyBuilder.new+build must match build_response_reply_aliased byte-for-byte"
        );
    }

    /// R121j-2b — ResponseReplyBuilder.consolidation sets the
    /// `_Z_FLAG_Z_R_C(0x20)` bit on `Reply.header` and emits the 1-byte
    /// consolidation immediately after the header. Mirrors zenoh-pico
    /// `_z_reply_encode` at vendor/zenoh-pico/src/protocol/codec/message.c.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_reply_builder_consolidation_sets_r_c_flag_and_byte() {
        let baseline = build_response_reply_aliased(42, 7, None, b"hello").wire();
        let with_c = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .consolidation(ConsolidationMode::Latest)
            .build()
            .wire();
        // The C-bit-set wire differs from baseline only in the Reply.header
        // byte (R_C bit) and a freshly inserted consolidation byte (0x02 =
        // Latest) directly after it.
        assert_ne!(
            baseline, with_c,
            "consolidation setter must alter the wire bytes"
        );
        // Locate Reply.header in the encoded Response. The encoded layout
        // up through Reply.header is:
        //   Response.header(1) + VLE(rid) + wireexpr + Reply.header(1)
        // For (rid=42, mapping_id=7, suffix=None) the prefix is small and
        // we can pin the locations explicitly: Response.header at offset
        // 0, VLE(42)=1 byte at offset 1, wireexpr(id=7,no suffix)=1 byte
        // VLE(7) at offset 2, Reply.header at offset 3.
        assert_eq!(
            baseline[3] & 0x20,
            0,
            "baseline Reply.header must have R_C clear"
        );
        assert_eq!(
            with_c[3] & 0x20,
            0x20,
            "consolidation builder must set R_C(0x20) on Reply.header"
        );
        assert_eq!(
            with_c[4],
            ConsolidationMode::Latest.wire_byte(),
            "consolidation byte must follow Reply.header carrying the wire-byte mapping"
        );
    }

    /// R121j-2b — ResponseErrBuilder with no setters must emit the
    /// exact same wire bytes as the baseline aliased helper.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_err_builder_no_setters_matches_aliased_baseline() {
        let direct = build_response_err_aliased(42, 7, None, b"oops").wire();
        let built = ResponseErrBuilder::new(42, 7, None, b"oops").build().wire();
        assert_eq!(
            direct, built,
            "ErrBuilder.new+build must match build_response_err_aliased byte-for-byte"
        );
    }

    /// R121j-2b — ResponseErrBuilder.encoding without schema sets the
    /// `_Z_FLAG_Z_E(0x40)` bit on `Err.header` and emits packed_id =
    /// (id << 1) | 0 with no schema_len / schema bytes.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_err_builder_encoding_no_schema_packs_id_left_shift_one() {
        let with_enc = ResponseErrBuilder::new(42, 7, None, b"oops")
            .encoding(4, None) // 4 = application/json prefix
            .build()
            .wire();
        // Layout up through Err.header:
        //   Response.header(1) + VLE(42)(1) + VLE(7)(1) + Err.header(1) at offset 3
        assert_eq!(
            with_enc[3] & 0x40,
            0x40,
            "encoding builder must set E(0x40) on Err.header"
        );
        // Next byte is VLE(packed_id) where packed_id = 4<<1 = 8.
        // VLE(8) = single byte 0x08.
        assert_eq!(
            with_enc[4], 0x08,
            "no-schema packed_id = (id << 1) | 0; for id=4 this is 0x08"
        );
    }

    /// R121j-2b — ResponseErrBuilder.encoding with schema sets E,
    /// packs LSB=1, and emits the VLE schema_len + schema bytes.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_err_builder_encoding_with_schema_sets_lsb_and_emits_suffix() {
        let with_enc = ResponseErrBuilder::new(42, 7, None, b"oops")
            .encoding(4, Some("schema_v1"))
            .build()
            .wire();
        assert_eq!(
            with_enc[3] & 0x40,
            0x40,
            "schema-bearing encoding still sets E on Err.header"
        );
        // packed_id = (4 << 1) | 1 = 9 → VLE single byte 0x09
        assert_eq!(
            with_enc[4], 0x09,
            "with-schema packed_id = (id << 1) | 1; for id=4 this is 0x09"
        );
        // VLE(schema_len = 9) = single byte 0x09, then "schema_v1" bytes
        assert_eq!(
            with_enc[5], 0x09,
            "schema_len VLE follows packed_id; 'schema_v1' length = 9"
        );
        assert_eq!(
            &with_enc[6..6 + 9],
            b"schema_v1",
            "schema bytes follow schema_len"
        );
    }

    /// R121j-2b — ResponseReplyBuilder literal path requires a
    /// non-empty keyexpr_suffix; (mapping_id=0, suffix=None) panics
    /// with the builder's diagnostic message at build() time.
    #[cfg(feature = "codec-response")]
    #[test]
    #[should_panic(
        expected = "ResponseReplyBuilder literal path (mapping_id=0) requires a non-empty keyexpr_suffix"
    )]
    fn response_reply_builder_literal_rejects_none_suffix() {
        let _ = ResponseReplyBuilder::new(42, 0, None, b"hello").build();
    }

    /// R121j-2b — ResponseErrBuilder literal path requires a
    /// non-empty keyexpr_suffix.
    #[cfg(feature = "codec-response")]
    #[test]
    #[should_panic(
        expected = "ResponseErrBuilder literal path (mapping_id=0) requires a non-empty keyexpr_suffix"
    )]
    fn response_err_builder_literal_rejects_none_suffix() {
        let _ = ResponseErrBuilder::new(42, 0, None, b"oops").build();
    }

    /// R121j-4b — ResponseErrBuilder.source_info sets `Err.header.Z(0x80)`
    /// and emits a single `ExtZbuf` ext entry with header
    /// `ENC_ZBUF(0x40) | id_source_info(0x01) = 0x41`. The value body is
    /// `[(zid_len-1)<<4, zid..., VLE(eid), VLE(sn)]` per zenoh-pico
    /// `_z_source_info_encode_ext` at `vendor/zenoh-pico/src/protocol/
    /// codec/message.c:243-254`.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_err_builder_source_info_emits_zbuf_ext_entry() {
        let wire = ResponseErrBuilder::new(42, 7, None, b"oops")
            .source_info(&[0xAA; 4], 11, 17)
            .build()
            .wire();
        // Layout up through Err.header: Response.header(1) + VLE(42)(1)
        // + VLE(7)(1) + Err.header(1) at offset 3. The source_info
        // setter must set Z(0x80) and leave E(0x40) clear (no encoding
        // in this test).
        assert_eq!(
            wire[3] & 0x80,
            0x80,
            "source_info builder must set Z(0x80) on Err.header"
        );
        assert_eq!(
            wire[3] & 0x40,
            0x00,
            "source_info-only builder must leave E(0x40) clear on Err.header"
        );
        // ExtEntry.header at offset 4: ENC_ZBUF(0x40) | id_source_info(0x01).
        // No Z chain-continuation bit because this is the sole entry.
        assert_eq!(
            wire[4], 0x41,
            "source_info ext header = ENC_ZBUF(0x40) | id_source_info(0x01); no Z chain bit on the sole entry"
        );
        // ExtZbuf value_len VLE at offset 5: leading byte(1) + zid(4)
        // + VLE(eid=11)(1) + VLE(sn=17)(1) = 7 bytes.
        assert_eq!(
            wire[5], 0x07,
            "ExtZbuf value_len = 1 leading + 4 zid + 1 VLE(eid) + 1 VLE(sn) = 7"
        );
        // value[0] = (4-1) << 4 = 0x30 at offset 6.
        assert_eq!(
            wire[6], 0x30,
            "leading byte = (zid_len-1) << 4 = 0x30 for zid_len=4"
        );
        // value[1..5] = zid bytes [0xAA; 4] at offsets 7..11.
        assert_eq!(
            &wire[7..11],
            &[0xAA; 4],
            "zid bytes follow the leading byte"
        );
        // value[5] = VLE(eid=11) at offset 11.
        assert_eq!(wire[11], 0x0B, "VLE(eid=11) = single byte 0x0B");
        // value[6] = VLE(sn=17) at offset 12.
        assert_eq!(wire[12], 0x11, "VLE(sn=17) = single byte 0x11");
        // Payload tail: VLE(payload_len=4) at offset 13, then "oops".
        assert_eq!(wire[13], 0x04, "VLE(payload_len=4) follows the ext chain");
        assert_eq!(
            &wire[14..18],
            b"oops",
            "payload bytes follow the length prefix"
        );
    }

    /// R121j-4b — `source_info` and `encoding` compose: both Err.header
    /// bits (E + Z) set, the encoded `Encoding` field sits between the
    /// header and the ext chain (Err::encode order at
    /// `wz-codecs/.../out/err.rs:171-200`).
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_err_builder_source_info_composes_with_encoding() {
        let wire = ResponseErrBuilder::new(42, 7, None, b"oops")
            .encoding(4, None)
            .source_info(&[0xBB; 1], 1, 2)
            .build()
            .wire();
        // Err.header at offset 3: E(0x40) | Z(0x80) = 0xC0.
        assert_eq!(
            wire[3] & 0xC0,
            0xC0,
            "compose path must set both E(0x40) and Z(0x80) on Err.header"
        );
        // Encoding at offset 4: packed_id = (4<<1)|0 = 8 → VLE 0x08.
        // (Schema absent so no schema_len / schema bytes follow.)
        assert_eq!(
            wire[4], 0x08,
            "encoding packed_id = (id << 1) | 0; for id=4 this is 0x08"
        );
        // ExtEntry.header at offset 5: 0x41.
        assert_eq!(
            wire[5], 0x41,
            "ext header follows encoding when both are set"
        );
        // VLE(value_len=4) at offset 6 (1 leading + 1 zid + 1 VLE(eid) + 1 VLE(sn)).
        assert_eq!(
            wire[6], 0x04,
            "value_len = 1 + 1 + 1 + 1 = 4 for 1-byte zid"
        );
        // value[0] = (1-1)<<4 = 0x00 at offset 7.
        assert_eq!(wire[7], 0x00, "leading byte = 0x00 for zid_len=1");
        assert_eq!(wire[8], 0xBB, "zid byte");
        assert_eq!(wire[9], 0x01, "VLE(eid=1)");
        assert_eq!(wire[10], 0x02, "VLE(sn=2)");
        // VLE(payload_len=4) + "oops".
        assert_eq!(wire[11], 0x04, "payload_len VLE follows the ext body");
        assert_eq!(&wire[12..16], b"oops");
    }

    /// R121j-4b — source_info rejects zid lengths outside the
    /// zenoh-pico ZenohId wire constraint (1..=16, transport.h:31-37).
    #[cfg(feature = "codec-response")]
    #[test]
    #[should_panic(expected = "ResponseErrBuilder::source_info requires zid length 1..=16")]
    fn response_err_builder_source_info_rejects_zid_too_long() {
        let _ = ResponseErrBuilder::new(42, 7, None, b"oops").source_info(&[0; 17], 0, 0);
    }

    /// R121j-4b — empty zid is also rejected (lower bound of 1..=16).
    #[cfg(feature = "codec-response")]
    #[test]
    #[should_panic(expected = "ResponseErrBuilder::source_info requires zid length 1..=16")]
    fn response_err_builder_source_info_rejects_empty_zid() {
        let _ = ResponseErrBuilder::new(42, 7, None, b"oops").source_info(&[], 0, 0);
    }

    /// R121j-3c — ResponseReplyBuilder.responder sets
    /// `Response.header.Z(0x80)` (envelope-level), prepends a single
    /// `ExtZbuf` envelope ext (header `ENC_ZBUF(0x40) | id_responder(0x03)
    /// = 0x43`) carrying `[(zid_len-1)<<4, zid..., VLE(eid)]` per
    /// zenoh-pico `_z_response_encode` at
    /// `vendor/zenoh-pico/src/protocol/codec/network.c:281-291`. The
    /// Reply inner body is unaffected — envelope ext is orthogonal to
    /// body bits.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_reply_builder_responder_emits_envelope_zbuf_ext_entry() {
        let baseline = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .build()
            .wire();
        let wire = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .responder(&[0xAA; 4], 11)
            .build()
            .wire();
        // Envelope: Response.header(1) + VLE(42)(1) + VLE(7)(1) = 3-byte
        // prefix; responder ext lands at offset 3 (no keyexpr suffix in
        // the aliased mapping_id=7 + None path).
        assert_eq!(
            wire[0],
            baseline[0] | 0x80,
            "responder must set Z(0x80) on Response.header; other base bits preserved"
        );
        assert_eq!(
            wire[3], 0x43,
            "envelope ext header = ENC_ZBUF(0x40) | id_responder(0x03); no Z chain bit on sole entry"
        );
        assert_eq!(
            wire[4], 0x06,
            "ExtZbuf value_len = 1 leading + 4 zid + 1 VLE(eid) = 6"
        );
        assert_eq!(wire[5], 0x30, "leading byte = (4-1) << 4 for zid_len=4");
        assert_eq!(&wire[6..10], &[0xAA; 4], "raw zid bytes");
        assert_eq!(wire[10], 0x0B, "VLE(eid=11)");
        // Inner Reply.header was at offset 3 in baseline; the envelope
        // ext adds 8 bytes (1 header + 1 value_len + 6 value), so
        // Reply.header is now at offset 11 with the same byte value.
        assert_eq!(
            wire[11], baseline[3],
            "inner Reply.header preserved at the offset shifted by the envelope ext (8 bytes)"
        );
        assert_eq!(
            wire.len(),
            baseline.len() + 8,
            "wire length grows by exactly the envelope ext size (1+1+6=8 bytes)"
        );
    }

    /// R121j-3c — responder (envelope-level) composes with consolidation
    /// (Reply-body-level): the bits land on different bytes — Z on
    /// Response.header, C on Reply.header — so the two setters are
    /// orthogonal and may be applied in either order with the same
    /// wire result.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_reply_builder_responder_composes_with_consolidation() {
        let wire = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .responder(&[0xBB; 1], 1)
            .consolidation(ConsolidationMode::Latest)
            .build()
            .wire();
        // Envelope Z set on Response.header at offset 0.
        assert_eq!(
            wire[0] & 0x80,
            0x80,
            "envelope-level Z(0x80) on Response.header"
        );
        // Envelope ext: header(0x43) + VLE(value_len = 1+1+1 = 3) + body(3)
        // at offsets 3..8. Body = [0x00, 0xBB, 0x01].
        assert_eq!(wire[3], 0x43);
        assert_eq!(
            wire[4], 0x03,
            "value_len = 1 leading + 1 zid + 1 VLE(eid) = 3"
        );
        assert_eq!(wire[5], 0x00, "leading byte = 0x00 for zid_len=1");
        assert_eq!(wire[6], 0xBB);
        assert_eq!(wire[7], 0x01, "VLE(eid=1)");
        // Inner Reply.header at offset 8 with consolidation C(0x20) bit
        // set; consolidation byte (LatestSamePeer = 0x02 wire byte) at
        // offset 9.
        assert_eq!(
            wire[8] & 0x20,
            0x20,
            "Reply.header.C(0x20) set by consolidation; orthogonal to envelope-level Z"
        );
        assert_eq!(
            wire[9],
            ConsolidationMode::Latest.wire_byte(),
            "consolidation byte follows Reply.header"
        );
    }

    /// R121j-3c — ResponseErrBuilder.responder mirrors the Reply path:
    /// envelope-level Z(0x80) + single ExtEntry on Response.extensions.
    /// The Err inner body (header.E / header.Z for source_info) is
    /// independent of the envelope ext.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_err_builder_responder_emits_envelope_zbuf_ext_entry() {
        let baseline = ResponseErrBuilder::new(42, 7, None, b"oops").build().wire();
        let wire = ResponseErrBuilder::new(42, 7, None, b"oops")
            .responder(&[0xCC; 2], 5)
            .build()
            .wire();
        assert_eq!(
            wire[0],
            baseline[0] | 0x80,
            "responder must set Z(0x80) on Response.header for Err path too"
        );
        assert_eq!(
            wire[3], 0x43,
            "same envelope ext header for both Reply and Err paths"
        );
        assert_eq!(
            wire[4], 0x04,
            "value_len = 1 leading + 2 zid + 1 VLE(eid) = 4"
        );
        assert_eq!(wire[5], 0x10, "leading byte = (2-1) << 4 for zid_len=2");
        assert_eq!(&wire[6..8], &[0xCC, 0xCC]);
        assert_eq!(wire[8], 0x05, "VLE(eid=5)");
        // Inner Err.header preserved (was at offset 3 in baseline, now
        // shifted by envelope ext size = 1 + 1 + 4 = 6 bytes).
        assert_eq!(
            wire[9], baseline[3],
            "inner Err.header preserved at offset shifted by envelope ext (6 bytes)"
        );
        assert_eq!(wire.len(), baseline.len() + 6);
    }

    /// R121j-3c — Err.responder (envelope) + Err.source_info (Err body)
    /// compose: envelope-level Z lands on Response.header, body-level
    /// Z lands on Err.header. Separate bytes, separate ext chains.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_err_builder_responder_composes_with_source_info() {
        let wire = ResponseErrBuilder::new(42, 7, None, b"oops")
            .responder(&[0xDD; 1], 9)
            .source_info(&[0xEE; 1], 3, 4)
            .build()
            .wire();
        // Envelope Z on Response.header.
        assert_eq!(
            wire[0] & 0x80,
            0x80,
            "envelope Z(0x80) on Response.header for responder"
        );
        // Envelope ext: 0x43 + VLE(3) + [0x00, 0xDD, 0x09] at offsets 3..8.
        assert_eq!(wire[3], 0x43);
        assert_eq!(wire[4], 0x03, "envelope responder value_len = 3");
        assert_eq!(&wire[5..8], &[0x00, 0xDD, 0x09]);
        // Err.header at offset 8 with Z(0x80) set by source_info.
        // E(0x40) clear because no encoding.
        assert_eq!(
            wire[8] & 0x80,
            0x80,
            "Err.header.Z(0x80) set by source_info; orthogonal to envelope Z"
        );
        assert_eq!(
            wire[8] & 0x40,
            0x00,
            "Err.header.E(0x40) clear (no encoding)"
        );
        // Err body ext: 0x41 + VLE(value_len = 1+1+1+1 = 4) + body(4)
        // at offsets 9..14.
        assert_eq!(wire[9], 0x41, "Err body ext header = source_info (0x41)");
        assert_eq!(wire[10], 0x04, "source_info value_len = 4");
        assert_eq!(&wire[11..15], &[0x00, 0xEE, 0x03, 0x04]);
    }

    /// R121j-3c — responder rejects zid lengths outside 1..=16 on
    /// both Reply and Err builders (zenoh-pico ZenohId wire constraint,
    /// transport.h:31-37).
    #[cfg(feature = "codec-response")]
    #[test]
    #[should_panic(expected = "ResponseReplyBuilder::responder requires zid length 1..=16")]
    fn response_reply_builder_responder_rejects_zid_too_long() {
        let _ = ResponseReplyBuilder::new(42, 7, None, b"hello").responder(&[0; 17], 0);
    }

    /// R121j-3c — ResponseErrBuilder.responder shares the same wire
    /// constraint.
    #[cfg(feature = "codec-response")]
    #[test]
    #[should_panic(expected = "ResponseErrBuilder::responder requires zid length 1..=16")]
    fn response_err_builder_responder_rejects_empty_zid() {
        let _ = ResponseErrBuilder::new(42, 7, None, b"oops").responder(&[], 0);
    }

    /// R121j-3c — direct check on the helper that builds the
    /// responder ext-body bytes. Distinct from source_info in that no
    /// `sn` trailer is emitted.
    #[cfg(feature = "codec-response")]
    #[test]
    fn encode_responder_ext_body_matches_zenoh_pico_layout() {
        // zid_len=3 → leading byte = (3-1)<<4 = 0x20
        let bytes = encode_responder_ext_body(&[0xCA, 0xFE, 0xBA], 0x4000);
        assert_eq!(
            bytes[0], 0x20,
            "leading byte packs zid_len-1 in high nibble"
        );
        assert_eq!(
            &bytes[1..4],
            &[0xCA, 0xFE, 0xBA],
            "raw zid follows the leading byte"
        );
        // VLE(16384) = 0x80 0x80 0x01
        assert_eq!(
            &bytes[4..7],
            &[0x80, 0x80, 0x01],
            "VLE(eid=16384) = 0x80 0x80 0x01"
        );
        assert_eq!(bytes.len(), 7, "total = 1 leading + 3 zid + 3 VLE(eid) = 7");
    }

    /// R121j-3d — ResponseReplyBuilder.reply_del() swaps the inner
    /// ReplyVariant arm from CodecZenohMsgPut to CodecZenohMsgDel.
    /// Wire-level effect: inner MID byte flips from 0x01 (Put) to
    /// 0x02 (Del); the payload bytes the constructor received are
    /// dropped (MsgDel has no payload).
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_reply_builder_reply_del_swaps_inner_arm_to_msgdel() {
        let put_wire = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .build()
            .wire();
        let del_wire = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .reply_del()
            .build()
            .wire();
        // Layout up through Reply.header: Response.header(1) + VLE(42)(1) +
        // VLE(7)(1) + Reply.header(1) at offset 3. Inner MID at offset 4.
        assert_eq!(put_wire[4], 0x01, "Put path inner MID = _Z_MID_Z_PUT(0x01)");
        assert_eq!(del_wire[4], 0x02, "Del path inner MID = _Z_MID_Z_DEL(0x02)");
        // The Del wire is shorter than Put because MsgPut emits VLE(payload_len)
        // + payload bytes (1 + 5 = 6 bytes for b"hello") while MsgDel emits
        // nothing after its header. Specifically del_wire ends right after
        // the Reply.header for MsgDel (no Reply exts, no MsgDel exts).
        assert!(
            del_wire.len() < put_wire.len(),
            "Del wire must be strictly shorter than Put wire (no payload)",
        );
        // Pinpoint: Put adds VLE(5) + 5 payload bytes = 6 bytes after the
        // inner MID byte. Del adds nothing. So Put length - Del length == 6.
        assert_eq!(
            put_wire.len() - del_wire.len(),
            6,
            "Del path must drop exactly VLE(5)+5 = 6 payload bytes from the Put baseline",
        );
    }

    /// R121j-3d — reply_del() composes with consolidation. The
    /// Reply.header.C bit must still be set when MsgDel + consolidation
    /// are combined; the consolidation byte sits between Reply.header
    /// and the MsgDel inner MID, not between Put header and payload.
    #[cfg(feature = "codec-response")]
    #[test]
    fn response_reply_builder_reply_del_composes_with_consolidation() {
        let wire = ResponseReplyBuilder::new(42, 7, None, b"hello")
            .reply_del()
            .consolidation(ConsolidationMode::Latest)
            .build()
            .wire();
        // Reply.header at offset 3 must carry R_C(0x20).
        assert_eq!(
            wire[3] & 0x20,
            0x20,
            "consolidation must set R_C(0x20) on Reply.header even on Del path"
        );
        // Consolidation byte at offset 4 (between Reply.header and MsgDel).
        assert_eq!(
            wire[4],
            ConsolidationMode::Latest.wire_byte(),
            "consolidation byte follows Reply.header"
        );
        // MsgDel inner MID at offset 5.
        assert_eq!(wire[5], 0x02, "MsgDel inner MID follows consolidation byte");
    }
}
