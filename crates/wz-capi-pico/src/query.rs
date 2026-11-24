// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The queryable (responder) half of the pico query plane: `z_closure_query`,
//! `z_declare_queryable` / `z_declare_background_queryable` /
//! `z_undeclare_queryable`, the loaned-query accessors, and
//! `z_query_reply` / `_del` / `_err`.
//!
//! A C queryable is recorded in the session's registry as a SECOND SSOT
//! alongside the subscription one (the `faces` module) and replayed onto every
//! face, so one C declaration answers queries from every connected peer — the
//! responder-side mirror of the subscriber fan-out. Per-face request-id
//! independence (each face's wz session allocates its own request ids) makes
//! cross-face rid collision unrepresentable rather than merely untested.
//!
//! ## The owned query
//!
//! The owned-query family (`z_query_clone` / `z_query_take_from_loaned` / the
//! `z_owned_query_t` ownership set) is exported, with the query's accessors
//! (`z_query_encoding`, `z_query_source_info`, `z_query_accepts_replies`) and
//! `z_queryable_id`. pico's channel handlers
//! (`include/zenoh-pico/api/handlers.h`, e.g. `z_fifo_channel_query_new`) are
//! `static inline`: they compile into the USER's object file and their bodies
//! call `z_query_take_from_loaned` / `z_query_move` / `z_query_drop`, so a
//! program that keeps a query and answers it later links against these.
//!
//! What lets a kept query answer after its callback is the engine's
//! [`HeldQuery`] (R2953, open-debt item 836): it answers on the query's own
//! route and holds the `ResponseFinal` until the copy is let go, as pico's
//! `_z_query_clear` does. The family was withheld until that seam existed,
//! because exporting it without one would have made every channel-based
//! queryable link and then silently fail to answer; the owned query is now
//! deferred through the held query and does not depend on the callback's
//! `ReplyOut`, which is lent to a query only for its callback's own call.
//!
//! ## Replies
//!
//! `z_query_reply` hands its reply to the responder of the dispatch the query
//! arrived in while the C callback runs, read where the caller holds it: no
//! copy of the caller's key and no list of replies is kept for later. wz's own
//! responder stages what it is handed, and the `Response`s leave the session
//! after the handler returns. The responder is lent to
//! the marshal for the callback's call alone (`QueryMarshal::answer_with`),
//! the one place a lifetime is erased, and taken back before the borrow ends.

use alloc::sync::Arc;
use core::cell::Cell;
use core::ffi::c_void;
use core::ptr::NonNull;

use wz_capi_port::{HeldQuery, QblId, QueryCallback, QueryHolder, QueryableSink};
use wz_session_core::query_sink::{QueryView, ReplyMeta, ReplyOut};
use wz_session_core::reply_acceptance::ReplyKeyExpr;

use crate::abi::{
    handle_ref, impl_handle_ownership7, z_loaned_bytes_t, z_loaned_keyexpr_t, z_moved_bytes_t,
    z_view_string_t,
};
use crate::ffi::{guarded, CClosure as FfiClosure};
use crate::keyexpr::{declared_of, keyexpr_str, DeclaredKeyexpr};
use crate::prelude::*;
use crate::result::{
    ZResult, Z_ERR_INVALID, Z_ERR_KEYEXPR_NOT_MATCH, Z_ERR_NULL, Z_ERR_SESSION_CLOSED, Z_OK,
};
use crate::session::{session_handle, z_loaned_session_t, Engine};

// The enum-typed option fields (`z_congestion_control_t`, `z_priority_t`) are in
// `crate::qos`. Both are documented "Deprecated: ignored, taken from query" on the
// reply options (`~/zenoh-pico/include/zenoh-pico/api/types.h:318-321`), so the reply
// options below carry them for layout only.
use crate::qos::{
    z_congestion_control_t, z_priority_t, Z_CONGESTION_CONTROL_BLOCK, Z_PRIORITY_DEFAULT,
};
use crate::reply_keyexpr::{
    parameters_has_anyke, reply_keyexpr_is_covered, z_reply_keyexpr_t, Z_REPLY_KEYEXPR_ANY,
    Z_REPLY_KEYEXPR_MATCHING_QUERY,
};

// --- opaque loaned query ---------------------------------------------------

/// Opaque loaned query (pico `z_loaned_query_t`). The C callback only holds a
/// pointer to it and passes it back to the accessors / `z_query_reply`, so this
/// stays opaque rather than reproducing pico's concrete `_z_query_t` layout —
/// the same model `z_loaned_sample_t` uses.
#[repr(C)]
pub struct z_loaned_query_t {
    _opaque: [u8; 0],
}

/// R311y562 — the value metadata a staged reply carries, in the wz hint types
/// the [`ReplyOut`] seam takes.
///
/// Read off the caller's options struct at `z_query_reply` / `z_query_reply_del`
/// time, because the options are BORROWED for the duration of that call only:
/// the `z_timestamp_t*` and `z_source_info_t*` a C program passes routinely
/// point at its own stack. Projecting to owned hints at read time keeps them
/// whatever the responder does with the reply after the call.
#[derive(Default)]
struct ReplyMetaOwned {
    encoding: Option<wz_session_core::sample::EncodingHint>,
    timestamp: Option<wz_session_core::sample::TimestampHint>,
    source_info: Option<wz_session_core::sample::SourceInfo>,
    /// The `is_express` its options carried, `false` when there were none. pico
    /// builds every reply's QoS from THIS flag and the query's own congestion
    /// control and priority (`vendor/zenoh-pico/src/net/primitives.c` @
    /// `_z_n_qos_create(is_express, _z_n_qos_get_congestion_control(query->_qos), _z_n_qos_get_priority(query->_qos));`),
    /// so it replaces the query's express bit rather than inheriting it.
    express: bool,
}

impl ReplyMetaOwned {
    /// Borrow the owned hints back into the seam's borrowed view, with the QoS
    /// pico gives the reply: the query's `query_qos` and this reply's express bit.
    fn view<'a>(
        &'a self,
        attachment: Option<&'a [u8]>,
        query_qos: wz_session_core::sample::QosLevel,
    ) -> ReplyMeta<'a> {
        ReplyMeta::new()
            .with_encoding(self.encoding.as_ref())
            .with_timestamp(self.timestamp.as_ref())
            .with_source_info(self.source_info.as_ref())
            .with_attachment(attachment)
            .with_qos(Some(query_qos.with_express(self.express)))
    }
}

/// One reply the C callback asked for, on its way to the responder of the query: the dispatch's,
/// while the callback runs, or the held query's, for a query kept past it ([`QueryMarshal::reply`]).
/// Its key is the caller's, read where the caller holds it for the one call.
enum PendingReply<'k> {
    /// `z_query_reply` — a Put-form reply under an explicit keyexpr.
    Put {
        keyexpr: &'k str,
        payload: crate::bytes::ByteBuf,
        attachment: Option<crate::bytes::ByteBuf>,
        meta: ReplyMetaOwned,
    },
    /// `z_query_reply_del` — a Del-form reply under an explicit keyexpr.
    Del {
        keyexpr: &'k str,
        meta: ReplyMetaOwned,
    },
    /// `z_query_reply_err` — an Err-form reply, with the encoding the options
    /// carried: pico sends it with the error (`vendor/zenoh-pico/src/api/api.c` @
    /// `_z_encoding_from_moved(opts.encoding));`).
    Err {
        payload: crate::bytes::ByteBuf,
        encoding: Option<wz_session_core::sample::EncodingHint>,
    },
}

/// Emit one reply of an ESCAPED query NOW, on the query's own route.
///
/// `z_query_take_from_loaned` lets a C program answer a query from its own
/// thread, arbitrarily later than the dispatch that delivered it — which is the
/// whole point of `z_queryable_channel.c`. Two things must survive that escape:
/// the ability to EMIT a reply, and the `ResponseFinal` that must not go out
/// until the escaped query is dropped (pico's `_z_query_clear`,
/// `src/net/query.c:54-61`).
///
/// R2953 (open-debt item 836) — both are the engine's [`HeldQuery`], which
/// answers on the query's own route (the wire, or this session's own pending
/// GET for a query it asked of itself) and releases the Final on drop. This ABI
/// only formats the reply, through the same [`flush_one`] the dispatch's
/// responder is handed replies by. Until R2953 it carried its own wire-only responder.
fn emit_held(
    held: &dyn HeldQuery,
    reply: PendingReply<'_>,
    query_qos: wz_session_core::sample::QosLevel,
) {
    let mut reply = Some(reply);
    held.reply(&mut |out| {
        if let Some(reply) = reply.take() {
            let mut out = out;
            flush_one(&mut out, reply, query_qos);
        }
    });
}

/// Route ONE reply into a [`ReplyOut`]. Shared by the dispatch's responder and the deferred emit
/// so the two cannot answer differently.
///
/// `query_qos` is the QoS of the query being answered: a reply takes its
/// congestion control and priority from it and its express bit from its own
/// options ([`ReplyMetaOwned::express`]).
fn flush_one(
    out: &mut &mut dyn ReplyOut,
    reply: PendingReply<'_>,
    query_qos: wz_session_core::sample::QosLevel,
) {
    match reply {
        // R311y562 — ONE seam carries all four metadata arms now
        // ([`ReplyMeta`]). The previous shape had to pick between
        // `reply_keyed_attached` (attachment, no timestamp) and `reply_keyed`
        // (neither), because no arm carried an attachment ALONGSIDE a timestamp
        // and source_info — so a `z_query_reply` whose options set both lost
        // one of them no matter which branch it took.
        PendingReply::Put {
            keyexpr,
            payload,
            attachment,
            meta,
        } => admitted_at_the_abi(out.reply_keyed_meta(
            keyexpr,
            &payload,
            meta.view(attachment.as_ref().map(|a| a.as_slice()), query_qos),
        )),
        // The Del arm passes no attachment: a Del body encodes none
        // (`has_attachment = _is_put && ..`, `message.c:263`), which is why
        // `z_query_reply_del` takes-and-drops the caller's — as pico does.
        PendingReply::Del { keyexpr, meta } => {
            admitted_at_the_abi(out.reply_keyed_del_meta(keyexpr, meta.view(None, query_qos)))
        }
        PendingReply::Err { payload, encoding } => {
            // UNPACKED. `EncodingHint::packed_id` is the wire word
            // `(id << 1) | has_schema`, while `ReplyOut::reply_err` documents its
            // `encoding_id` as the content-type prefix and packs it itself, so the
            // packed word would be shifted twice and put a different content type
            // on the wire. The zenoh-c ABI's Err arm does the same projection.
            let (id, schema) = match encoding.as_ref() {
                Some(hint) => (Some(hint.packed_id >> 1), hint.schema.as_deref()),
                None => (None, None),
            };
            out.reply_err(id, schema, &payload)
        }
    }
}

/// The core responder's verdict on a reply this ABI already ADMITTED.
///
/// `z_query_reply` / `z_query_reply_del` apply [`reply_keyexpr_is_covered`]
/// before a reply is handed on and return `_Z_ERR_KEYEXPR_NOT_MATCH` to the C
/// program there, as pico's `_z_send_reply` does. The core responder applies
/// the intersection again when it stages the reply, reading `_anyke` in zenoh's dialect where
/// this ABI reads it in both (`abi_reads_anyke`), so an admission here is an
/// admission there; a refusal there means the two gates disagree, a wz
/// defect with no C caller left to tell — so a debug build stops on it rather
/// than dropping the reply unseen.
fn admitted_at_the_abi(staged: Result<(), wz_session_core::query_sink::ReplyError>) {
    debug_assert_eq!(
        staged,
        Ok(()),
        "the core reply gate refused a reply z_query_reply had admitted"
    );
}

/// The `_anyke` this ABI answers with: pico's reading, where the core responder
/// that stages the reply reads the same flag.
///
/// The two readings agree on every UTF-8 list
/// (`the_abi_admits_no_reply_the_core_responder_would_refuse` measures it). They
/// part on a list that is not UTF-8, where pico's byte scan still finds a
/// `;`-bounded `_anyke` and the core reads the guarantee
/// ([`ReplyKeyExpr::from_parameter_bytes`]). Admitting there would hand the C
/// program `Z_OK` for a reply the responder then refuses, so the ABI reads what both
/// read.
fn abi_reads_anyke(parameters: &[u8]) -> bool {
    parameters_has_anyke(parameters)
        && ReplyKeyExpr::from_parameter_bytes(Some(parameters)) == ReplyKeyExpr::Any
}

/// A text a query's marshal reads: where the view holds it, for the one call the marshal is handed
/// to ([`QueryMarshal::new`]), or a copy of the marshal's own, for a query kept past it
/// ([`QueryMarshal::deep_copy_deferred`]).
enum QueryText<T: ?Sized> {
    /// The view's, which outlives the marshal that reads it.
    Lent(*const T),
    /// The marshal's own.
    Owned(Box<T>),
}

impl<T: ?Sized> QueryText<T> {
    fn get(&self) -> &T {
        match self {
            // SAFETY: a lent text outlives the marshal that holds it (`QueryMarshal::new`).
            Self::Lent(text) => unsafe { &**text },
            Self::Owned(text) => text,
        }
    }
}

/// The owned marshal behind a borrowed `z_loaned_query_t` during one callback.
///
/// Reads the query's keyexpr, parameters and value where the wz [`QueryView`] holds them for the
/// call, caches the loaned views the accessors hand back, and hands each reply the callback asks
/// for to the dispatch's responder as it is asked for ([`Self::answer_with`]).
pub(crate) struct QueryMarshal {
    keyexpr: QueryText<str>,
    parameters: QueryText<[u8]>,
    /// pico's `_anyke`: whether this query accepts replies under ANY key rather
    /// than only keys it covers. Derived from `parameters` at marshal time (see
    /// [`parameters_has_anyke`]) — the same derivation pico does, and the gate
    /// `z_query_reply` consults.
    anyke: bool,
    /// R311y559 — the query's `(zid, eid, sn)` source triple, in the pico ABI
    /// shape `z_query_source_info` hands back a POINTER to. Stored rather than
    /// synthesised per call for the same reason every cached view here is: the
    /// accessor returns a pointer, and a stack temporary would dangle.
    source_info: Option<crate::pubsub::z_source_info_t>,
    /// The query's ENCODING, if it carried one. Unlike the payload this stays
    /// an `Option`, because `z_query_encoding` hands back a POINTER and pico
    /// distinguishes "no encoding" from "the default encoding". Held in the
    /// marshal and pointed at by `loaned_encoding` once [`Self::bind`] runs, so
    /// it is let go of with the marshal and costs no allocation of its own.
    encoding: Option<crate::encoding::EncodingState>,
    /// The query's value payload, EMPTY when the query carried no value ext.
    ///
    /// There is deliberately no `has_payload` companion. pico's
    /// `z_query_payload` is `return &..->_value.payload` — it hands back a
    /// pointer unconditionally and lets an empty payload speak for itself
    /// (`vendor/zenoh-pico/src/api/api.c:476`), and the same is true of
    /// `z_query_attachment` (:472). Carrying a presence flag here invites the
    /// accessor to return NULL for absence, which is the one thing a pico
    /// program cannot survive; see the accessors' own docstrings.
    payload: crate::bytes::ByteBuf,
    /// The query's attachment, EMPTY when absent. Same no-presence-flag rule as
    /// [`Self::payload`].
    attachment: crate::bytes::ByteBuf,
    loaned_keyexpr: z_loaned_keyexpr_t,
    loaned_payload: z_loaned_bytes_t,
    loaned_attachment: z_loaned_bytes_t,
    loaned_encoding: crate::encoding::z_loaned_encoding_t,
    /// The request id this query answers — the correlator a DEFERRED reply and
    /// the terminator both need, and the one piece of the query that is not
    /// reachable through any accessor.
    rid: wz_session_core::wire_id::RequestId,
    /// R2594 — the query's QoS, which a DEFERRED reply inherits. Like `rid` it
    /// has no pico accessor; it is carried only so the escaped responder can
    /// seed its replies from it.
    qos: wz_session_core::sample::QosLevel,
    /// What the FACE's queries are held through ([`QueryHolder`]), on a marshal the
    /// dispatch built and on every copy escaped from it. `None` on one built outside
    /// a dispatch (a test fixture), which is exactly the case that cannot be escaped —
    /// see [`clone_query_marshal`].
    ///
    /// It also says whether the session has been closed: a reply on a query whose
    /// session has been closed answers `_Z_ERR_SESSION_CLOSED`, as pico's
    /// `z_query_reply*` do before anything else (`vendor/zenoh-pico/src/api/api.c`,
    /// `_z_session_weak_upgrade_if_open`). Only an ESCAPED query can meet a closed
    /// session: a callback's own query cannot outlive the session it runs on.
    holder: Option<Arc<dyn QueryHolder>>,
    /// R2953 — whether the session asked this query of itself: the half of
    /// the query's route the rid alone does not name ([`HeldQuery`]).
    is_local: bool,
    /// Present only on an ESCAPED marshal: the query held past its dispatch,
    /// which a reply issued long after it goes through. `None` means this
    /// marshal is the ordinary borrowed one, whose replies go to the dispatch's
    /// responder while the callback runs ([`Self::answer_with`]). Each escape is its own hold (pushing the same
    /// query into two channels is legal), released on its own drop; an escaped
    /// marshal is the end of the chain and is not escaped again.
    deferred: Option<Box<dyn HeldQuery>>,
    /// The dispatch's responder, while the callback this marshal is handed to runs
    /// ([`Self::answer_with`]), and none otherwise.
    ///
    /// A `Cell` because the accessors receive `*const z_loaned_query_t`. The soundness anchor is
    /// pico's callback contract, and it is the ONLY anchor: one query's callback — and any
    /// `z_query_reply` on its loaned query — runs on the session's single read task, inside the
    /// dispatch that lent the responder, so the responder is used by nothing else while it is set.
    /// This marshal is valid for exactly the duration of one `call`, the same scope pico gives its
    /// own `z_loaned_query_t`; using the pointer after the callback returns, or from another
    /// thread, is undefined behaviour, in pico too, whose loaned query is only escapable via
    /// `z_query_take_from_loaned`.
    responder: Cell<Option<NonNull<dyn ReplyOut>>>,
}

impl QueryMarshal {
    /// Build the marshal for one inbound query, with its cached views still
    /// UNBOUND — [`Self::bind`] must run once the value has reached its final
    /// address. Splitting the two is load-bearing; see `bind`. Its payload and attachment are
    /// read where the view holds them, as a subscriber's sample's are; an escaped copy copies them
    /// ([`clone_query_marshal`]).
    ///
    /// # Safety
    /// The marshal is dropped before the borrow of `view` ends.
    unsafe fn new(view: &dyn QueryView) -> Self {
        // Read where the view holds them, as the payload is: the marshal is dropped before the
        // view's borrow ends, and an escaped copy keeps copies of its own.
        let parameters = view.parameters().unwrap_or_default();
        Self {
            keyexpr: QueryText::Lent(view.keyexpr() as *const str),
            anyke: abi_reads_anyke(parameters),
            parameters: QueryText::Lent(parameters as *const [u8]),
            // Absence collapses to EMPTY here, not to a flag: the accessors
            // must hand C a pointer either way (see the field docs).
            payload: view
                .payload()
                .map(|payload| crate::bytes::ByteBuf::lent(payload))
                .unwrap_or_default(),
            attachment: view
                .attachment()
                .map(|attachment| crate::bytes::ByteBuf::lent(attachment))
                .unwrap_or_default(),
            // Read where the view holds it, as the payload is: the marshal is dropped before the
            // view's borrow ends, and an escaped copy keeps a copy of its own.
            encoding: view.encoding().map(|hint| {
                crate::encoding::EncodingState::lent(hint.packed_id, hint.schema.as_deref())
            }),
            // R311y559 — carried through the SAME projection the sample plane
            // uses, so a `(zid, eid, sn)` read off a query and one read off a
            // sample cannot render differently.
            source_info: view.source_info().map(crate::pubsub::source_info_of),
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(core::ptr::null(), 0),
            loaned_payload: z_loaned_bytes_t {
                handle: core::ptr::null_mut(),
                _pad: [core::ptr::null_mut(); 3],
            },
            loaned_attachment: z_loaned_bytes_t {
                handle: core::ptr::null_mut(),
                _pad: [core::ptr::null_mut(); 3],
            },
            loaned_encoding: crate::encoding::z_loaned_encoding_t::unbound(),
            rid: view.rid(),
            qos: view.qos(),
            holder: None,
            is_local: view.is_local(),
            deferred: None,
            responder: Cell::new(None),
        }
    }

    /// Bind what the FACE's queries are held through, so this marshal can be
    /// escaped. Called only by the dispatch; a marshal without it is un-escapable
    /// by construction.
    fn with_holder(mut self, holder: Arc<dyn QueryHolder>) -> Self {
        self.holder = Some(holder);
        self
    }

    /// Whether the session this query arrived on has been closed.
    fn session_closed(&self) -> bool {
        self.holder
            .as_ref()
            .is_some_and(|holder| holder.session_closed())
    }

    /// An INDEPENDENT copy bound to a DEFERRED responder — what
    /// `z_query_take_from_loaned` hands back.
    ///
    /// The copy owns everything the accessors read, so it stays valid for as
    /// long as the C program keeps it; the cached views stay UNBOUND until
    /// [`Self::bind`] runs at the copy's final address (see
    /// [`crate::pubsub::SampleMarshal::deep_copy`]). It holds no responder of
    /// the dispatch: its replies go through `held`. `payload` and `attachment` are the copy's own, made before the
    /// hold is taken, so that no room for them holds nothing open.
    fn deep_copy_deferred(
        &self,
        held: Box<dyn HeldQuery>,
        payload: crate::bytes::ByteBuf,
        attachment: crate::bytes::ByteBuf,
        encoding: Option<crate::encoding::EncodingState>,
    ) -> Self {
        Self {
            keyexpr: QueryText::Owned(Box::from(self.keyexpr.get())),
            parameters: QueryText::Owned(Box::from(self.parameters.get())),
            anyke: self.anyke,
            encoding,
            source_info: self.source_info,
            payload,
            attachment,
            loaned_keyexpr: z_loaned_keyexpr_t::borrowed(core::ptr::null(), 0),
            loaned_payload: z_loaned_bytes_t {
                handle: core::ptr::null_mut(),
                _pad: [core::ptr::null_mut(); 3],
            },
            loaned_attachment: z_loaned_bytes_t {
                handle: core::ptr::null_mut(),
                _pad: [core::ptr::null_mut(); 3],
            },
            loaned_encoding: crate::encoding::z_loaned_encoding_t::unbound(),
            rid: self.rid,
            qos: self.qos,
            // The COPY is the escaped end of the chain: it carries the held query,
            // which is what makes it un-escapable ([`clone_query_marshal`]), and
            // the holder only to say whether its session has since been closed.
            holder: self.holder.clone(),
            is_local: self.is_local,
            deferred: Some(held),
            responder: Cell::new(None),
        }
    }

    /// Point the cached views at this marshal's own fields.
    ///
    /// MUST run only once the marshal sits at its FINAL address, and must not
    /// be folded back into [`Self::new`]. `loaned_payload.handle` /
    /// `loaned_attachment.handle` store the address of the `ByteBuf` STRUCT
    /// (that is what [`crate::abi::handle_ref`] reconstructs a `&ByteBuf` from),
    /// and a struct field's address moves with the struct. `new` returns `Self` by
    /// value, so binding inside it would record `new`'s frame and hand C a
    /// pointer into a dead frame the moment the value is moved out — return-
    /// value optimisation is not a language guarantee and does not save it.
    ///
    /// `loaned_keyexpr._start` would in fact survive (`String::as_ptr` is the
    /// HEAP buffer, which a move does not relocate — the same distinction
    /// [`crate::bytes`] documents), and that asymmetry is exactly what made an
    /// earlier binding-inside-`new` pass its test: the test read only the
    /// keyexpr. Both are bound here so the rule is uniform rather than
    /// per-field reasoning.
    ///
    /// Sibling shapes in this crate, for orientation: `SampleMarshal`
    /// (`pubsub.rs`) is built in the callback frame and never moved;
    /// [`QueryableState`] binds after its `Box::new`. Both reach the same
    /// invariant — bind at the final address.
    fn bind(&mut self) {
        self.loaned_keyexpr =
            z_loaned_keyexpr_t::borrowed(self.keyexpr.get().as_ptr(), self.keyexpr.get().len());
        self.loaned_payload.handle = &self.payload as *const crate::bytes::ByteBuf as *mut c_void;
        self.loaned_attachment.handle =
            &self.attachment as *const crate::bytes::ByteBuf as *mut c_void;
        if let Some(encoding) = self.encoding.as_ref() {
            self.loaned_encoding.handle =
                encoding as *const crate::encoding::EncodingState as *mut c_void;
        }
    }

    /// Run `call` with this marshal answering through `out`, the responder of the dispatch the
    /// query arrived in: each reply the callback asks for goes to it as it is asked for, read where
    /// the caller holds it, with nothing kept for later. The responder is let go of before this
    /// returns, inside its borrow.
    fn answer_with(&self, out: &mut dyn ReplyOut, call: impl FnOnce(&Self)) {
        let lent = NonNull::from(out);
        // SAFETY: only the lifetime is erased. The borrow of `out` ends only after the Cell is
        // emptied below, and the pointer is read only from the Cell, so it is never used past it.
        let lent = unsafe {
            core::mem::transmute::<NonNull<dyn ReplyOut + '_>, NonNull<dyn ReplyOut>>(lent)
        };
        self.responder.set(Some(lent));
        call(self);
        self.responder.set(None);
    }

    /// Hand a reply the C callback asked for to the query's responder: the held query's for an
    /// ESCAPED query, whose callback returned long ago, and the dispatch's while the callback
    /// runs. A marshal that has neither, built outside a dispatch, has no route to answer.
    ///
    /// # Safety
    /// Caller must be inside the callback that owns this marshal (the pico
    /// single-threaded-callback contract), so nothing else uses the responder.
    unsafe fn reply(&self, reply: PendingReply<'_>) -> ZResult {
        if let Some(held) = self.deferred.as_deref() {
            emit_held(held, reply, self.qos);
            return Z_OK;
        }
        let Some(mut lent) = self.responder.get() else {
            return crate::result::Z_ERR_GENERIC;
        };
        // SAFETY: the caller's: the responder is set only while the callback runs, inside its
        // borrow, and nothing else uses it then (`Self::answer_with`).
        let mut out: &mut dyn ReplyOut = unsafe { lent.as_mut() };
        flush_one(&mut out, reply, self.qos);
        Z_OK
    }
}

/// R2953 — the marshal IS the query the dispatch handed the callback, so it is
/// what an escape holds ([`QueryHolder::hold_query`]). Only what the hold
/// reads is answered from the marshal's own fields; an empty payload or
/// attachment reads as absent, as the view it was built from would.
impl QueryView for QueryMarshal {
    fn keyexpr(&self) -> &str {
        self.keyexpr.get()
    }
    fn parameters(&self) -> Option<&[u8]> {
        Some(self.parameters.get())
    }
    fn attachment(&self) -> Option<&[u8]> {
        (!self.attachment.is_empty()).then_some(self.attachment.as_slice())
    }
    fn payload(&self) -> Option<&[u8]> {
        (!self.payload.is_empty()).then_some(self.payload.as_slice())
    }
    fn rid(&self) -> wz_session_core::wire_id::RequestId {
        self.rid
    }
    fn is_local(&self) -> bool {
        self.is_local
    }
    fn qos(&self) -> wz_session_core::sample::QosLevel {
        self.qos
    }
}

/// Read the marshal behind a loaned query, or `None` if the pointer is null or
/// the marshal is spent (its callback already returned).
///
/// # Safety
/// `query` must be null or a pointer this crate handed to a query callback.
unsafe fn query_marshal<'a>(query: *const z_loaned_query_t) -> Option<&'a QueryMarshal> {
    if query.is_null() {
        return None;
    }
    Some(&*(query as *const QueryMarshal))
}

// --- C closure types -------------------------------------------------------

/// pico `z_closure_query_callback_t`: `void call(z_loaned_query_t*, void*)`.
pub type z_closure_query_callback_t =
    Option<unsafe extern "C" fn(*const z_loaned_query_t, *mut c_void)>;

/// Owned query closure (pico `z_owned_closure_query_t`, 24 B:
/// `{ context, call, drop }` in that field order —
/// `~/zenoh-pico/include/zenoh-pico/api/types.h:730-740`).
#[repr(C)]
pub struct z_owned_closure_query_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_query_callback_t,
    pub(crate) drop: crate::pubsub::z_closure_drop_callback_t,
}

/// Loaned query closure (pico `z_loaned_closure_query_t`), same layout.
#[repr(C)]
pub struct z_loaned_closure_query_t {
    pub(crate) context: *mut c_void,
    pub(crate) call: z_closure_query_callback_t,
    pub(crate) drop: crate::pubsub::z_closure_drop_callback_t,
}

/// Moved query closure (pico `z_moved_closure_query_t`).
#[repr(C)]
pub struct z_moved_closure_query_t {
    pub(crate) _this: z_owned_closure_query_t,
}

impl z_owned_closure_query_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            context: core::ptr::null_mut(),
            call: None,
            drop: None,
        }
    }
}

/// The Rust-side wrapper one C queryable's per-face callbacks share — the
/// queryable plane's instantiation of the shared [`crate::ffi::CClosure`]
/// mechanism. Its `Drop` invokes the C `drop(context)` exactly once, when the
/// last face's callback and the registry's SSOT entry have both released it.
pub(crate) type CQueryClosure = FfiClosure<z_closure_query_callback_t>;

// SAFETY: the responder plane's own argument, written here rather than granted
// by a blanket impl on the generic (see `crate::ffi::CClosure`).
//
// Sharing one queryable's `CQueryClosure` across a per-face callback needs
// `Sync` (so `Arc<CQueryClosure>`, and each callback, is `Send`). Sharing
// `&CQueryClosure` is sound because the closure is two C pointers Rust only
// reads, and WHO calls `call` is pico's contract, kept in each arm:
//
// - Without `local-queryable` every queryable is `Locality::Remote`, which the
//   queryable's own declaration makes MECHANICAL rather than a promise: a Remote
//   queryable is unreachable from `Session::query`'s in-process fan (gated on the
//   queryable registry's locality), so no `z_get` on the C thread, whatever
//   locality IT chooses, can run this handler there. The handler fires from the
//   drive task's inbound dispatch alone, as pico's default build fires it from
//   its read task alone.
// - With `local-queryable` a queryable whose `allowed_origin` admits it answers
//   the session's own get inside `z_get`, on the calling thread, while the drive
//   task may be answering a peer's query with it at once. pico does exactly that:
//   `_z_session_deliver_query_locally` runs on the thread that called `z_get`,
//   and the queryable callback runs outside the session lock. A program built
//   with that switch is written for it.
//
// `drop` runs only when the last `Arc` is released, which cannot overlap a live
// `call` (a running callback holds a reference).
unsafe impl Sync for CQueryClosure {}

/// Build the wz-side queryable handler for ONE face from a shared C closure.
///
/// Marshals the wz [`QueryView`] into a borrowed `z_loaned_query_t`, invokes the
/// C `call`, each reply it asks for handed to the wz
/// [`ReplyOut`]. The marshal (and so the borrowed keyexpr / payload) is valid
/// only for the duration of that call — pico's contract, which is why the C side
/// must copy anything it keeps.
pub(crate) fn make_queryable_callback(
    closure: Arc<CQueryClosure>,
    holder: Arc<dyn QueryHolder>,
) -> impl FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static {
    move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
        let call = match closure.call {
            Some(f) => f,
            None => return,
        };
        // SAFETY: the marshal is dropped at the end of this call, inside the borrow of `view`.
        let mut marshal = unsafe { QueryMarshal::new(view) }.with_holder(holder.clone());
        // Bind AFTER the move out of `new` — the marshal is at its final
        // address only here. See `QueryMarshal::bind`.
        marshal.bind();
        // Each reply the callback asks for goes to `out` as it is asked for.
        marshal.answer_with(out, |marshal| {
            let query_ptr = marshal as *const QueryMarshal as *const z_loaned_query_t;
            // SAFETY: `call` is the C callback; `marshal` outlives the call and the
            // borrowed query is valid only for its duration (pico contract).
            // `context` travels with the drive dispatch. A panic unwinding OUT of
            // the C callback across this `extern "C"` boundary is UB and would tear
            // down the drive thread, so it is caught here — the drive loop survives
            // a misbehaving callback.
            let ctx = closure.context.0;
            let _in_callback = crate::ffi::InCallback::enter();
            let _ = crate::ffi::catch(|| unsafe {
                call(query_ptr, ctx);
            });
        });
    }
}

/// Release a boxed [`QueryMarshal`].
///
/// Dropping it drops its [`HeldQuery`], which is what emits the
/// `ResponseFinal` — pico's `_z_query_clear` contract.
///
/// # Safety
/// `handle` must be a live `QueryMarshal` handle.
unsafe fn free_query_marshal(handle: *mut c_void) {
    crate::object_slot::release(handle.cast::<QueryMarshal>());
}

/// Escape a borrowed query into an owned one bound to a deferred responder.
///
/// # Safety
/// `src` must be null or a pointer this crate handed to a query callback.
unsafe fn clone_query_marshal(src: *const z_loaned_query_t) -> Result<*mut c_void, ZResult> {
    let Some(marshal) = query_marshal(src) else {
        return Err(crate::result::Z_ERR_GENERIC);
    };
    // Only a marshal the DISPATCH built can be escaped: the session it must
    // reply through comes from there. A marshal with no holder is one this
    // crate built outside a dispatch (a unit-test fixture), and escaping it
    // would produce an owned query with no way to answer — reported as a
    // failure rather than silently handed back. An escaped copy is the end of
    // the chain and is not escaped again.
    if marshal.deferred.is_some() {
        return Err(crate::result::Z_ERR_GENERIC);
    }
    let Some(holder) = marshal.holder.as_ref() else {
        return Err(crate::result::Z_ERR_GENERIC);
    };
    // The place is taken before the hold, so a full pool refuses the escape and holds nothing
    // open.
    let Some(slot) = crate::object_slot::Slot::take(crate::object_slot::Kind::Query) else {
        return Err(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY);
    };
    // The bytes the view lent are copied before the hold, so no room for them holds nothing open.
    let (payload, attachment) = match (marshal.payload.try_clone(), marshal.attachment.try_clone())
    {
        (Ok(payload), Ok(attachment)) => (payload, attachment),
        (Err(no_room), _) | (_, Err(no_room)) => return Err(no_room.code()),
    };
    // The encoding's schema is kept in a slot of the pool of encodings before the hold too.
    let encoding = match marshal
        .encoding
        .as_ref()
        .map(crate::encoding::EncodingState::kept)
        .transpose()
    {
        Ok(encoding) => encoding,
        Err(no_room) => return Err(no_room.code()),
    };
    // R2953 — the hold is taken HERE, inside the C callback: the handler job
    // every terminator job of its drain batch runs after, which is what makes
    // the hold visible to the job it must suppress. One hold per escape.
    let held = holder.hold_query(marshal);
    let owned = slot.fill(marshal.deep_copy_deferred(held, payload, attachment, encoding));
    (*owned).bind();
    Ok(owned.cast::<c_void>())
}

crate::abi::impl_boxed_element!(
    z_owned_query_t,
    z_moved_query_t,
    z_loaned_query_t,
    16,
    free_query_marshal,
    clone_query_marshal,
    z_internal_query_null,
    z_internal_query_check,
    z_query_loan,
    z_query_loan_mut,
    z_query_move,
    z_query_take,
    z_query_drop,
    z_query_take_from_loaned
);

// --- closure_query exports -------------------------------------------------

/// Build an owned query closure from a callback + drop + context (pico
/// `z_closure_query`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_query(
    closure: *mut z_owned_closure_query_t,
    call: z_closure_query_callback_t,
    drop: crate::pubsub::z_closure_drop_callback_t,
    context: *mut c_void,
) -> ZResult {
    guarded(|| {
        if closure.is_null() {
            return Z_ERR_NULL;
        }
        *closure = z_owned_closure_query_t {
            context,
            call,
            drop,
        };
        Z_OK
    })
}

/// Invoke a query closure directly (pico `z_closure_query_call`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_call(
    closure: *const z_loaned_closure_query_t,
    query: *mut z_loaned_query_t,
) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        if let Some(call) = (*closure).call {
            call(query, (*closure).context);
        }
        Z_OK
    });
}

/// Zero an owned query closure (pico `z_internal_closure_query_null`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_query_null(closure: *mut z_owned_closure_query_t) {
    if !closure.is_null() {
        *closure = z_owned_closure_query_t::null_value();
    }
}

/// `true` iff the closure holds a callback (pico
/// `z_internal_closure_query_check`).
#[no_mangle]
pub unsafe extern "C" fn z_internal_closure_query_check(
    closure: *const z_owned_closure_query_t,
) -> bool {
    crate::ffi::guard_val(false, || !closure.is_null() && (*closure).call.is_some())
}

/// Borrow an owned query closure (pico `z_closure_query_loan`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_loan(
    closure: *const z_owned_closure_query_t,
) -> *const z_loaned_closure_query_t {
    closure as *const z_loaned_closure_query_t
}

/// Move-cast an owned query closure (pico `z_closure_query_move`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_move(
    closure: *mut z_owned_closure_query_t,
) -> *mut z_moved_closure_query_t {
    closure as *mut z_moved_closure_query_t
}

/// Take an owned query closure out of `src` into `dst` (pico
/// `z_closure_query_take`).
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_take(
    dst: *mut z_owned_closure_query_t,
    src: *mut z_moved_closure_query_t,
) {
    if dst.is_null() || src.is_null() {
        return;
    }
    (*dst).context = (*src)._this.context;
    (*dst).call = (*src)._this.call;
    (*dst).drop = (*src)._this.drop;
    (*src)._this = z_owned_closure_query_t::null_value();
}

/// Drop an owned query closure that was never declared (pico
/// `z_closure_query_drop`): run the C `drop(context)` and null the struct.
#[no_mangle]
pub unsafe extern "C" fn z_closure_query_drop(closure: *mut z_moved_closure_query_t) {
    let _ = guarded(|| {
        if closure.is_null() {
            return Z_OK;
        }
        let owned = &mut (*closure)._this;
        if let Some(dropfn) = owned.drop {
            dropfn(owned.context);
        }
        *owned = z_owned_closure_query_t::null_value();
        Z_OK
    });
}

// --- queryable options -----------------------------------------------------

/// Queryable options (pico `z_queryable_options_t`).
///
/// `{ bool complete; }` — the `allowed_origin` field exists only under
/// `Z_FEATURE_LOCAL_QUERYABLE`, which pico defaults to **0**
/// (`~/zenoh-pico/CMakeLists.txt:353`), so the default-config layout is this
/// one. Mirroring pico's api.c feature gates rather than its header is the rule
/// here: the header declares fields/ops unconditionally, the gates decide what a
/// default build actually has.
///
/// With `local-queryable` the struct gains `allowed_origin` after `complete`
/// (`#if Z_FEATURE_LOCAL_QUERYABLE == 1` upstream), 8 B with its alignment.
#[repr(C)]
pub struct z_queryable_options_t {
    pub complete: bool,
    #[cfg(feature = "local-queryable")]
    pub allowed_origin: crate::locality::z_locality_t,
}

crate::locality::locality_option_field!(z_queryable_options_t, allowed_origin, "local-queryable");

/// Fill default queryable options (pico `z_queryable_options_default`):
/// `complete = false`, the incomplete default, and with `local-queryable` an
/// `allowed_origin` of `Z_LOCALITY_ANY`.
#[no_mangle]
pub unsafe extern "C" fn z_queryable_options_default(options: *mut z_queryable_options_t) {
    if !options.is_null() {
        (*options).complete = false;
        #[cfg(feature = "local-queryable")]
        {
            (*options).allowed_origin = crate::locality::Z_LOCALITY_ANY;
        }
    }
}

/// Reply options (pico `z_query_reply_options_t`, `api/types.h:327-337`).
/// `congestion_control` / `priority` are carried for layout only — pico
/// documents both "Deprecated: ignored, taken from query" (`api/types.h:318-321`).
///
/// R311y562 — `encoding` and `timestamp` are TYPED and READ now, and
/// `source_info` exists at all. All three were carried as opaque `*mut c_void`
/// (source_info was simply absent) with two stated reasons, and BOTH had
/// expired: the encoding said "no exported `z_encoding_*` to build one with"
/// while [`crate::encoding::z_encoding_from_str`] and its family have been
/// exported since R311y529, and the timestamp said "the timestamp family is a
/// follow-up round" while `z_timestamp_t` / `z_timestamp_new` landed at
/// R311y557. This is the same class R311y561 named — a residual is a claim with
/// a date on it — recurring in the file next door.
#[repr(C)]
pub struct z_query_reply_options_t {
    /// `z_moved_encoding_t*` — the value encoding, CONSUMED (pico
    /// `z_encoding_drop(opts.encoding)`, `src/api/api.c:2152`).
    pub encoding: *mut crate::encoding::z_moved_encoding_t,
    pub congestion_control: z_congestion_control_t,
    pub priority: z_priority_t,
    /// `z_timestamp_t*` — borrowed, not moved: pico reads through it into
    /// `_z_send_reply` and never drops it.
    pub timestamp: *mut crate::pubsub::z_timestamp_t,
    pub is_express: bool,
    pub attachment: *mut z_moved_bytes_t,
    /// `z_source_info_t*` — the `(zid, eid, sn)` the reply is stamped with.
    /// Unstable-gated upstream (`#ifdef Z_FEATURE_UNSTABLE_API`), and here with
    /// `unstable-api` (so is `z_put_options_t`'s).
    #[cfg(feature = "unstable-api")]
    pub source_info: *mut crate::pubsub::z_source_info_t,
}

crate::option_fields::unstable_option_fields!(z_query_reply_options_t {
    source_info: *mut crate::pubsub::z_source_info_t = core::ptr::null_mut(),
});

/// The upstream layout this struct must match, measured against the vendored
/// header with `Z_FEATURE_UNSTABLE_API` on: 48 B, `source_info` last at
/// offset 40; without it, 40 B and 32 B for the two reply structs.
///
/// R311y562 — the FIRST ABI layout guard on this crate's reply options. Adding
/// `source_info` moves this struct from 40 B to 48 B, and nothing else in the
/// tree would have caught getting that wrong: a C caller passing the upstream
/// struct into a wz build with a short one writes past the end of wz's view and
/// reads garbage for every field after the mismatch, silently.
///
/// The numbers are the LP64 header's (the crate root says how a 32-bit image is pinned).
#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(core::mem::size_of::<z_query_reply_err_options_t>() == 8);
    // By OFFSET, not only by size — see `crate::get::z_get_options_t`, where the
    // same feature-conditional tail displaced a field and a size check would
    // have read that as a harmless omission. Here the unstable field IS last,
    // so nothing moves; pinning it anyway is what keeps that a measured fact
    // rather than an assumption about upstream's field order, which is exactly
    // what was wrong next door.
    assert!(core::mem::offset_of!(z_query_reply_options_t, timestamp) == 16);
    assert!(core::mem::offset_of!(z_query_reply_options_t, attachment) == 32);
    assert!(core::mem::offset_of!(z_query_reply_del_options_t, timestamp) == 8);
    assert!(core::mem::offset_of!(z_query_reply_del_options_t, attachment) == 24);
};

#[cfg(all(feature = "unstable-api", target_pointer_width = "64"))]
const _: () = {
    assert!(core::mem::size_of::<z_query_reply_options_t>() == 48);
    assert!(core::mem::size_of::<z_query_reply_del_options_t>() == 40);
    assert!(core::mem::offset_of!(z_query_reply_options_t, source_info) == 40);
    assert!(core::mem::offset_of!(z_query_reply_del_options_t, source_info) == 32);
};

#[cfg(all(not(feature = "unstable-api"), target_pointer_width = "64"))]
const _: () = {
    assert!(core::mem::size_of::<z_query_reply_options_t>() == 40);
    assert!(core::mem::size_of::<z_query_reply_del_options_t>() == 32);
};

/// Fill default reply options (pico `z_query_reply_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_options_default(options: *mut z_query_reply_options_t) {
    if options.is_null() {
        return;
    }
    (*options).encoding = core::ptr::null_mut();
    (*options).congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    (*options).priority = Z_PRIORITY_DEFAULT;
    (*options).timestamp = core::ptr::null_mut();
    (*options).is_express = false;
    (*options).attachment = core::ptr::null_mut();
    #[cfg(feature = "unstable-api")]
    {
        (*options).source_info = core::ptr::null_mut();
    }
}

/// Del-reply options (pico `z_query_reply_del_options_t`,
/// `api/types.h:352-361`) — the reply options without the encoding (a Del
/// carries no payload to encode).
///
/// The `attachment` is accepted and dropped, and that is UPSTREAM PARITY rather
/// than a wz gap: `_z_push_body_encode` computes `has_attachment` as
/// `pshb->_is_put && _z_bytes_check(..)` (`src/protocol/codec/message.c:263`),
/// so pico's own `z_query_reply_del` — which passes `opts.attachment` into
/// `_z_send_reply` with `Z_SAMPLE_KIND_DELETE` (`src/api/api.c:2208-2212`) —
/// encodes a Del body that carries no attachment ext either. Both libraries
/// take the value, free it, and put nothing on the wire.
#[repr(C)]
pub struct z_query_reply_del_options_t {
    pub congestion_control: z_congestion_control_t,
    pub priority: z_priority_t,
    /// `z_timestamp_t*` — READ (R311y562). A Del body DOES carry a timestamp:
    /// `_z_push_body_encode` sets `_Z_FLAG_Z_D_T` on the Del arm exactly as it
    /// sets `_Z_FLAG_Z_P_T` on the Put arm (`message.c:269-281`).
    pub timestamp: *mut crate::pubsub::z_timestamp_t,
    pub is_express: bool,
    pub attachment: *mut z_moved_bytes_t,
    /// `z_source_info_t*` — READ (R311y562). `has_source_info` is computed off
    /// the shared push-body `_commons`, BEFORE the `_is_put` split
    /// (`message.c:259-261`), so a Del reply carries its source identity.
    #[cfg(feature = "unstable-api")]
    pub source_info: *mut crate::pubsub::z_source_info_t,
}

crate::option_fields::unstable_option_fields!(z_query_reply_del_options_t {
    source_info: *mut crate::pubsub::z_source_info_t = core::ptr::null_mut(),
});

/// Fill default del-reply options (pico `z_query_reply_del_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_del_options_default(
    options: *mut z_query_reply_del_options_t,
) {
    if options.is_null() {
        return;
    }
    (*options).congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    (*options).priority = Z_PRIORITY_DEFAULT;
    (*options).timestamp = core::ptr::null_mut();
    (*options).is_express = false;
    (*options).attachment = core::ptr::null_mut();
    #[cfg(feature = "unstable-api")]
    {
        (*options).source_info = core::ptr::null_mut();
    }
}

/// Err-reply options (pico `z_query_reply_err_options_t`) — `{ encoding }`.
#[repr(C)]
pub struct z_query_reply_err_options_t {
    /// `z_moved_encoding_t*` — opaque; see [`z_query_reply_options_t::encoding`].
    pub encoding: *mut c_void,
}

/// Fill default err-reply options (pico `z_query_reply_err_options_default`).
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_err_options_default(
    options: *mut z_query_reply_err_options_t,
) {
    if !options.is_null() {
        (*options).encoding = core::ptr::null_mut();
    }
}

// --- queryable handle ------------------------------------------------------

/// Behind a `z_owned_queryable_t` handle: the C queryable's id in the session's
/// responder SSOT. Dropping it retracts the declaration — removing it from the
/// SSOT (so no future face replays it) and dropping every live face's wz
/// queryable, which emits each wire undeclare and releases the last closure
/// reference (→ the C `drop(context)`).
pub(crate) struct QueryableState {
    engine: Arc<Engine>,
    id: QblId,
    /// R2959 — the queryable's key with the non-wild-prefix declaration pico
    /// makes for it; dropped after the queryable, so the retraction follows.
    key: DeclaredKeyexpr,
    /// Cached loan of `key`, so `z_queryable_keyexpr` hands back a borrow of
    /// stable storage rather than of a temporary.
    loaned_keyexpr: z_loaned_keyexpr_t,
    /// Opens when the queryable's closure has run its `drop(context)`; the undeclare waits on it
    /// so it returns only when no query is still being answered (pico's `_z_sync_group_wait`).
    released: Arc<crate::ffi::ReleaseLatch>,
}

impl Drop for QueryableState {
    fn drop(&mut self) {
        self.engine.undeclare_queryable(self.id);
        self.released.wait();
    }
}

/// Owned queryable (pico `z_owned_queryable_t`). Handle model, as publisher /
/// subscriber (see [`crate::abi`]).
#[repr(C)]
pub struct z_owned_queryable_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Loaned queryable (pico `z_loaned_queryable_t`).
#[repr(C)]
pub struct z_loaned_queryable_t {
    pub(crate) handle: *mut c_void,
    pub(crate) _pad: [*mut c_void; 3],
}

/// Moved queryable (pico `z_moved_queryable_t`).
#[repr(C)]
pub struct z_moved_queryable_t {
    pub(crate) _this: z_owned_queryable_t,
}

impl z_owned_queryable_t {
    #[inline]
    fn null_value() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            _pad: [core::ptr::null_mut(); 3],
        }
    }
}

/// # Safety
/// `h` must be a live `QueryableState` handle.
unsafe fn free_queryable(h: *mut c_void) {
    crate::object_slot::release_entity(h as *mut QueryableState);
}

impl_handle_ownership7!(
    z_owned_queryable_t,
    z_loaned_queryable_t,
    z_moved_queryable_t,
    free_queryable,
    z_internal_queryable_null,
    z_internal_queryable_check,
    z_queryable_loan,
    z_queryable_loan_mut,
    z_queryable_move,
    z_queryable_take,
    z_queryable_drop
);

// --- declare / undeclare ---------------------------------------------------

/// Shared body of `z_declare_queryable` / `z_declare_background_queryable`:
/// consume the moved closure, validate, and record the SSOT entry.
///
/// Returns the queryable id on success. The moved closure is consumed on EVERY
/// path (pico's contract): `CQueryClosure` owns the C `drop(context)` from the
/// moment it is built, so an early error drops it and frees the context.
unsafe fn declare_queryable_inner(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_query_t,
    options: *const z_queryable_options_t,
) -> Result<
    (
        Arc<Engine>,
        QblId,
        DeclaredKeyexpr,
        Arc<crate::ffi::ReleaseLatch>,
    ),
    ZResult,
> {
    if callback.is_null() {
        return Err(Z_ERR_NULL);
    }
    let owned = &mut (*callback)._this;
    let cclosure = CQueryClosure::new(owned.context, owned.call, owned.drop);
    *owned = z_owned_closure_query_t::null_value();
    let released = cclosure.release_latch();

    // A closed session takes no declaration; the closure consumed above runs its drop.
    let handle = crate::session::open_session_handle(zs)?;
    // A non-canonical / pico-unsafe keyexpr is refused UP FRONT — the same
    // outbound gate `z_declare_subscriber` applies, and for the same reason:
    // the registry declares best-effort per face, so a per-face reject would
    // be swallowed and the call would report `Z_OK` for a dead SSOT entry.
    let ke = crate::keyexpr::outbound_keyexpr(keyexpr)?.to_owned();
    let (complete, allowed_origin) = if options.is_null() {
        (false, crate::locality::default_locality!("local-queryable"))
    } else {
        ((*options).complete, (*options).allowed_origin())
    };
    let session = crate::write_filter::PicoSession::of(handle);
    let (id, key) = declare_queryable_on(
        &session,
        ke,
        declared_of(keyexpr),
        complete,
        allowed_origin,
        {
            // R311y498 — see the pubsub/liveliness twins: the shim mints, the
            // engine calls the factory per face, the C drop(context) is unmoved.
            let closure = Arc::new(cclosure);
            Arc::new(move |holder: Arc<dyn QueryHolder>| {
                Box::new(make_queryable_callback(closure.clone(), holder)) as QueryCallback
            })
        },
    )?;
    Ok((session.engine, id, key, released))
}

/// Declare a queryable the way pico's `z_declare_queryable` does, for whatever
/// answers it: the key's declaration, then the queryable announced on it.
///
/// R311y554 — `allowed_origin` is the caller's with `local-queryable` and
/// `Locality::Remote` without it: `Z_FEATURE_LOCAL_QUERYABLE` defaults to 0
/// upstream, so a default pico build has no local queryable at all and its
/// `z_queryable_options_t` carries no `allowed_origin` field.
/// R2959 — pico declares the queryable's NON-WILD PREFIX and announces the
/// queryable ON that declaration, the wild tail as suffix
/// (`vendor/zenoh-pico/src/net/primitives.c` @
/// `_z_wireexpr_t wire_expr = _z_declared_keyexpr_alias_to_wire(&q._key, _Z_RC_IN_VAL(zn));`)
/// — unlike the subscriber, which announces on the caller's key. Measured:
/// `DeclKexpr = demo/kd/qbl` then `DeclQueryable on K + "/*/x"`.
///
/// Shared by the C entry points, whose answerer is a C closure, and by a
/// composite whose answerer is its own (an advanced publisher's cache): what
/// reaches a peer is decided here once, and the sink is the only thing that
/// differs.
pub(crate) fn declare_queryable_on(
    session: &crate::write_filter::PicoSession,
    keyexpr: String,
    existing: Option<&DeclaredKeyexpr>,
    complete: bool,
    allowed_origin: wz_session_core::locality::Locality,
    sink: QueryableSink,
) -> Result<(QblId, DeclaredKeyexpr), ZResult> {
    let key = DeclaredKeyexpr::declare_non_wild_prefix(&session.engine, &keyexpr, existing)?;
    let id = session
        .engine
        .declare_queryable_on_wire(
            &keyexpr,
            key.wire(Arc::as_ref(&session.engine)),
            complete,
            allowed_origin,
            // A peer or router-hat session retracts the queryable naming its key
            // (`_z_undeclare_queryable`) — the announced one, for a queryable.
            key.retraction_naming_in(session.mode, Arc::as_ref(&session.engine)),
            sink,
        )
        .map_err(|refused| crate::result::refusal_code(refused, crate::result::Door::Entity))?;
    Ok((id, key))
}

/// A pico queryable with no C handle around it, retracted when dropped: the
/// declaration and its key, for a composite that answers with something other
/// than a C closure (an advanced publisher's cache, the admin space).
#[cfg(any(feature = "advanced", feature = "admin-space"))]
pub(crate) struct PlainQueryable {
    engine: Arc<Engine>,
    id: QblId,
    /// Dropped after the queryable, so the retraction follows.
    _key: DeclaredKeyexpr,
}

#[cfg(any(feature = "advanced", feature = "admin-space"))]
impl PlainQueryable {
    /// Declare a queryable on `keyexpr` answered by `sink`.
    pub(crate) fn declare(
        session: &crate::write_filter::PicoSession,
        keyexpr: &str,
        existing: Option<&DeclaredKeyexpr>,
        complete: bool,
        sink: QueryableSink,
    ) -> Result<Self, ZResult> {
        // Declared as pico declares its own (`z_declare_queryable` with NULL options):
        // the default origin.
        let (id, key) = declare_queryable_on(
            session,
            keyexpr.to_owned(),
            existing,
            complete,
            crate::locality::default_locality!("local-queryable"),
            sink,
        )?;
        Ok(Self {
            engine: session.engine.clone(),
            id,
            _key: key,
        })
    }
}

#[cfg(any(feature = "advanced", feature = "admin-space"))]
impl Drop for PlainQueryable {
    fn drop(&mut self) {
        self.engine.undeclare_queryable(self.id);
    }
}

/// Declare a queryable (pico `z_declare_queryable`). Consumes the moved
/// closure.
#[no_mangle]
pub unsafe extern "C" fn z_declare_queryable(
    zs: *const z_loaned_session_t,
    queryable: *mut z_owned_queryable_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_query_t,
    options: *const z_queryable_options_t,
) -> ZResult {
    guarded(|| {
        if queryable.is_null() {
            return Z_ERR_NULL;
        }
        if callback.is_null() {
            return Z_ERR_NULL;
        }
        // The queryable's place is taken from its session before it is declared, so a session
        // with no place left refuses the declaration and declares nothing; a session that is not
        // open is refused as the declaration refuses it. The closure is consumed as on every
        // refusal.
        let handle = match crate::session::open_session_handle(zs) {
            Ok(handle) => handle,
            Err(code) => {
                z_closure_query_drop(callback);
                return code;
            }
        };
        let Some(slot) = crate::object_slot::Slot::take_entity(
            &crate::session::engine_of(handle),
            crate::object_slot::Kind::Queryable,
        ) else {
            z_closure_query_drop(callback);
            return crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
        };
        match declare_queryable_inner(zs, keyexpr, callback, options) {
            Ok((engine, id, key, released)) => {
                let state = slot.fill(QueryableState {
                    engine,
                    id,
                    key,
                    loaned_keyexpr: z_loaned_keyexpr_t::borrowed(core::ptr::null(), 0),
                    released,
                });
                // Point the cached view at the placed keyexpr's final address.
                (*state).loaned_keyexpr = (*state).key.loaned();
                *queryable = z_owned_queryable_t {
                    handle: state as *mut c_void,
                    _pad: [core::ptr::null_mut(); 3],
                };
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// Declare a background queryable (pico `z_declare_background_queryable`): the
/// declaration lives until the session is closed or dropped, with no handle
/// handed back.
///
/// The declaration is simply never retracted by a handle drop — the engine
/// holds it (and so the C closure) until the session is closed or dropped,
/// which is exactly pico's "until the corresponding session is closed or
/// dropped" contract.
#[no_mangle]
pub unsafe extern "C" fn z_declare_background_queryable(
    zs: *const z_loaned_session_t,
    keyexpr: *const z_loaned_keyexpr_t,
    callback: *mut z_moved_closure_query_t,
    options: *const z_queryable_options_t,
) -> ZResult {
    guarded(
        || match declare_queryable_inner(zs, keyexpr, callback, options) {
            Ok((_, _, _, released)) => {
                // No handle will undeclare it, so the session's close waits for it.
                if let Some(handle) = session_handle(zs) {
                    handle.keep_background(released);
                }
                Z_OK
            }
            Err(code) => code,
        },
    )
}

/// Undeclare a queryable (pico `z_undeclare_queryable`): drops every face's wz
/// queryable (undeclare on the wire) and the callback (→ C `drop(context)`).
#[no_mangle]
pub unsafe extern "C" fn z_undeclare_queryable(queryable: *mut z_moved_queryable_t) -> ZResult {
    guarded(|| {
        if queryable.is_null() {
            return Z_OK;
        }
        let handle = (*queryable)._this.handle;
        if !handle.is_null() {
            crate::object_slot::release_entity(handle as *mut QueryableState);
            (*queryable)._this = z_owned_queryable_t::null_value();
        }
        Z_OK
    })
}

/// Borrow a queryable's keyexpr (pico `z_queryable_keyexpr`).
#[no_mangle]
pub unsafe extern "C" fn z_queryable_keyexpr(
    queryable: *const z_loaned_queryable_t,
) -> *const z_loaned_keyexpr_t {
    match handle_ref::<z_loaned_queryable_t, QueryableState>(queryable) {
        Some(state) => &state.loaned_keyexpr as *const z_loaned_keyexpr_t,
        None => core::ptr::null(),
    }
}

// --- loaned-query accessors ------------------------------------------------

/// Borrow the query's keyexpr (pico `z_query_keyexpr`).
#[no_mangle]
pub unsafe extern "C" fn z_query_keyexpr(
    query: *const z_loaned_query_t,
) -> *const z_loaned_keyexpr_t {
    match query_marshal(query) {
        Some(marshal) => &marshal.loaned_keyexpr as *const z_loaned_keyexpr_t,
        None => core::ptr::null(),
    }
}

/// Write the query's selector parameters into `parameters` as a view string
/// (pico `z_query_parameters`). A query with no parameters segment yields an
/// empty (not null) view, matching pico.
#[no_mangle]
pub unsafe extern "C" fn z_query_parameters(
    query: *const z_loaned_query_t,
    parameters: *mut z_view_string_t,
) {
    let _ = guarded(|| {
        if parameters.is_null() {
            return Z_OK;
        }
        let (start, len) = match query_marshal(query) {
            Some(marshal) => (
                marshal.parameters.get().as_ptr(),
                marshal.parameters.get().len(),
            ),
            None => (core::ptr::null(), 0),
        };
        (*parameters) = z_view_string_t {
            _start: start,
            _len: len,
            _pad: [0; 2],
        };
        Z_OK
    });
}

/// Borrow the query's value payload (pico `z_query_payload`). A payload-less
/// query yields a valid pointer to an EMPTY payload, never null; null is
/// reserved for an invalid `query` pointer.
///
/// This is pico's contract, read off its implementation:
/// `z_query_payload` is `return &_Z_RC_IN_VAL(query)->_value.payload`
/// (`vendor/zenoh-pico/src/api/api.c:476`) — an unconditional address-of, with
/// no presence check anywhere. The neighbouring `z_query_source_info` (:478-481)
/// DOES do `_z_source_info_check(info) ? info : NULL`, so pico's own getters are
/// asymmetric on purpose, and reading the shape off the wrong sibling is how
/// this diverged.
///
/// The divergence was not cosmetic. Real pico programs call this getter
/// unconditionally — `examples/unix/c11/z_queryable.c` does
/// `z_bytes_to_string(z_query_payload(query), &payload_string)` and only THEN
/// tests `z_string_len(...) > 0`. Returning null made `z_bytes_to_string` fail,
/// which leaves the caller's stack-allocated `z_owned_string_t` UNINITIALIZED,
/// and the very next line loans it: the upstream queryable example aborted on
/// a garbage handle the moment a real `z_get` reached it. An absent payload is
/// an empty payload, and the C side must be able to say so without a crash.
#[no_mangle]
pub unsafe extern "C" fn z_query_payload(
    query: *const z_loaned_query_t,
) -> *const z_loaned_bytes_t {
    match query_marshal(query) {
        Some(marshal) => &marshal.loaned_payload as *const z_loaned_bytes_t,
        None => core::ptr::null(),
    }
}

/// Which replies this query accepts (pico `z_query_accepts_replies`,
/// `src/api/api.c:469`): `_anyke ? ANY : MATCHING_QUERY`.
///
/// This is the accessor for the very flag [`z_query_reply`] gates on, so a C
/// queryable can ask the same question the library asks before it rejects a
/// reply with [`Z_ERR_KEYEXPR_NOT_MATCH`]. A null / spent query reports
/// `MATCHING_QUERY`, the conservative answer (pico would dereference and
/// crash).
#[no_mangle]
pub unsafe extern "C" fn z_query_accepts_replies(
    query: *const z_loaned_query_t,
) -> z_reply_keyexpr_t {
    crate::ffi::guard_val(Z_REPLY_KEYEXPR_MATCHING_QUERY, || {
        match query_marshal(query) {
            Some(marshal) if marshal.anyke => Z_REPLY_KEYEXPR_ANY,
            _ => Z_REPLY_KEYEXPR_MATCHING_QUERY,
        }
    })
}

/// Borrow the query's attachment (pico `z_query_attachment`). An attachment-less
/// query yields a valid pointer to an EMPTY attachment, never null; null is
/// reserved for an invalid `query` pointer.
///
/// Same contract and same reasoning as [`z_query_payload`]: pico's getter is
/// `return &_Z_RC_IN_VAL(query)->_attachment` with no presence check
/// (`vendor/zenoh-pico/src/api/api.c:472`). Fixed together with its sibling
/// rather than only the one a running example happened to crash on — the two
/// had the identical shape, so a caller that reads the attachment
/// unconditionally would have hit the identical uninitialized-owned-struct
/// abort.
#[no_mangle]
pub unsafe extern "C" fn z_query_attachment(
    query: *const z_loaned_query_t,
) -> *const z_loaned_bytes_t {
    match query_marshal(query) {
        Some(marshal) => &marshal.loaned_attachment as *const z_loaned_bytes_t,
        None => core::ptr::null(),
    }
}

// --- z_query_reply family --------------------------------------------------

/// Reply to a query (pico `z_query_reply`). Consumes the moved payload AND the
/// moved `options->attachment`.
///
/// Enforces zenoh's `reply ⊆ query` contract exactly as pico does — see
/// `reply_keyexpr_is_covered`. The reply goes to the query's responder as it is asked
/// for (see the module doc).
///
/// R311y562 — of `options`, `attachment`, `encoding`, `timestamp` AND
/// `source_info` are all honoured now. `congestion_control` / `priority` are
/// documented ignored by pico itself: a reply takes both from the query.
/// `is_express` is READ, and it is the reply's express bit: pico builds the
/// reply's QoS from it and the query's congestion control and priority
/// (`vendor/zenoh-pico/src/net/primitives.c` @ `_z_n_qos_create(is_express,`).
/// It stood here as a NAMED DIVERGENCE ("wz's [`ReplyOut`] has no express arm on
/// any reply form"), which stopped being true when [`ReplyMeta::with_qos`] landed
/// for the advanced cache's replies, and nothing struck the sentence.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply(
    query: *const z_loaned_query_t,
    keyexpr: *const z_loaned_keyexpr_t,
    payload: *mut z_moved_bytes_t,
    options: *const z_query_reply_options_t,
) -> ZResult {
    guarded(|| {
        // Consume BOTH moved arguments FIRST so they are freed on every path
        // (pico's "z_move consumes on all paths" contract). The attachment is a
        // moved `z_bytes` like the payload, and `z_bytes_*` IS exported — so a C
        // program can build one, and failing to take it here would leak it.
        let buf = crate::pubsub::take_moved_bytes(payload);
        // The moved `encoding` is consumed on every path alongside the
        // attachment, matching pico's unconditional `z_encoding_drop(opts.encoding)`
        // (`src/api/api.c:2152`) — an early return that skipped it would leak the
        // caller's owned encoding.
        let (attachment, meta) = if options.is_null() {
            (Ok(None), ReplyMetaOwned::default())
        } else {
            let attachment = crate::pubsub::take_moved_bytes((*options).attachment);
            let meta = ReplyMetaOwned {
                encoding: crate::encoding::take_moved_encoding_copy(
                    (*options).encoding as *mut c_void,
                ),
                timestamp: crate::pubsub::timestamp_hint_of((*options).timestamp),
                source_info: crate::pubsub::source_info_hint_of((*options).source_info()),
                express: (*options).is_express,
            };
            (attachment, meta)
        };
        // A payload or an attachment moved out of a callback's sample is copied; with no room for
        // the copy the reply is refused, every moved argument consumed all the same.
        let (buf, attachment) = match (buf, attachment) {
            (Ok(Some(buf)), Ok(attachment)) => (buf, attachment),
            (Ok(None), _) => return Z_ERR_NULL,
            (Err(no_room), _) | (_, Err(no_room)) => return no_room.code(),
        };
        let marshal = match query_marshal(query) {
            Some(m) => m,
            None => return Z_ERR_INVALID,
        };
        // pico refuses a reply on a closed session before reading anything else; the moved
        // arguments above are consumed first all the same, so none of them leaks.
        if marshal.session_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        // pico dereferences `keyexpr` unconditionally (`_z_send_reply` passes it
        // straight into `_z_declared_keyexpr_intersects`), so a null there is a
        // caller bug that SEGFAULTS pico. Report it instead of inventing a
        // fallback: silently substituting the query's own key would hide the bug
        // and claim a pico semantic that does not exist.
        let Some(ke) = keyexpr_str(keyexpr) else {
            return Z_ERR_NULL;
        };
        if !reply_keyexpr_is_covered(marshal.keyexpr.get(), ke, marshal.anyke) {
            return Z_ERR_KEYEXPR_NOT_MATCH;
        }
        marshal.reply(PendingReply::Put {
            keyexpr: ke,
            payload: buf,
            attachment,
            meta,
        })
    })
}

/// Reply to a query with a Del (pico `z_query_reply_del`). Consumes the moved
/// `options->attachment`.
///
/// Takes an arbitrary reply keyexpr, as pico's does, and enforces the same
/// `reply ⊆ query` rule as [`z_query_reply`]. An earlier cut of this round
/// accepted only a keyexpr STRING-EQUAL to the query's and rejected the rest as
/// a "named divergence" — that was wrong twice over: string equality against a
/// query key that is routinely a PATTERN rejects the ordinary wildcard case, and
/// the seam it claimed to be blocked on ([`ReplyOut::reply_keyed_del`]) was a
/// ten-line addition to the Put arm's existing keyed family, not a missing
/// concept. It was a cost-deferral wearing a divergence's clothes; the seam is
/// now built, so there is nothing to diverge about.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_del(
    query: *const z_loaned_query_t,
    keyexpr: *const z_loaned_keyexpr_t,
    options: *const z_query_reply_del_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved attachment on every path (see `z_query_reply`).
        // A Del reply carries no attachment ON THE WIRE, so this is a
        // take-and-drop: the C side's contract is still honoured (its `z_bytes`
        // is freed and its source nulled) and nothing leaks.
        //
        // R311y562 — this is UPSTREAM PARITY, not a wz gap, and the earlier note
        // calling it "the same named gap as the Put arm's `is_express`" was
        // wrong about what it was looking at. `_z_push_body_encode` computes
        // `has_attachment` as `pshb->_is_put && _z_bytes_check(..)`
        // (`vendor/zenoh-pico/src/protocol/codec/message.c:263`), so pico's own
        // `z_query_reply_del` — which does pass `opts.attachment` down into
        // `_z_send_reply` (`src/api/api.c:2208-2212`) — emits a Del body with no
        // attachment ext either. Carrying it further would build a field the
        // codec discards.
        //
        // The `timestamp` and `source_info` DO ride a Del and are read.
        let meta = if options.is_null() {
            ReplyMetaOwned::default()
        } else {
            crate::pubsub::drop_moved_bytes((*options).attachment);
            ReplyMetaOwned {
                encoding: None,
                timestamp: crate::pubsub::timestamp_hint_of((*options).timestamp),
                source_info: crate::pubsub::source_info_hint_of((*options).source_info()),
                express: (*options).is_express,
            }
        };
        let marshal = match query_marshal(query) {
            Some(m) => m,
            None => return Z_ERR_INVALID,
        };
        // pico refuses a reply on a closed session before reading anything else; the moved
        // arguments above are consumed first all the same, so none of them leaks.
        if marshal.session_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        // Null is a caller bug that segfaults pico — reported, not substituted
        // (see `z_query_reply`).
        let Some(ke) = keyexpr_str(keyexpr) else {
            return Z_ERR_NULL;
        };
        if !reply_keyexpr_is_covered(marshal.keyexpr.get(), ke, marshal.anyke) {
            return Z_ERR_KEYEXPR_NOT_MATCH;
        }
        marshal.reply(PendingReply::Del { keyexpr: ke, meta })
    })
}

/// Reply to a query with an error (pico `z_query_reply_err`). Consumes the
/// moved payload and the options' moved encoding, which goes out with the error.
#[no_mangle]
pub unsafe extern "C" fn z_query_reply_err(
    query: *const z_loaned_query_t,
    payload: *mut z_moved_bytes_t,
    options: *const z_query_reply_err_options_t,
) -> ZResult {
    guarded(|| {
        // Consume the moved payload and encoding FIRST (pico consume-on-all-paths
        // contract), before any early return can skip them.
        let buf = crate::pubsub::take_moved_bytes(payload);
        let encoding = if options.is_null() {
            None
        } else {
            crate::encoding::take_moved_encoding_copy((*options).encoding)
        };
        let buf = match buf {
            Ok(Some(buf)) => buf,
            Ok(None) => return Z_ERR_NULL,
            Err(no_room) => return no_room.code(),
        };
        let marshal = match query_marshal(query) {
            Some(m) => m,
            None => return Z_ERR_INVALID,
        };
        // pico refuses a reply on a closed session before reading anything else; the moved
        // arguments above are consumed first all the same, so none of them leaks.
        if marshal.session_closed() {
            return Z_ERR_SESSION_CLOSED;
        }
        marshal.reply(PendingReply::Err {
            payload: buf,
            encoding,
        })
    })
}

/// The query's ENCODING, or NULL when it carried none (pico
/// `z_query_encoding`).
///
/// NULL is reachable and meaningful: pico's `_z_query_t` holds the encoding of
/// the query's VALUE, and a query with no value has none. `z_queryable_attachment.c`
/// reads it only after checking the payload, which is the same guard.
#[no_mangle]
pub unsafe extern "C" fn z_query_encoding(
    query: *const z_loaned_query_t,
) -> *const crate::encoding::z_loaned_encoding_t {
    if query.is_null() {
        return core::ptr::null();
    }
    let marshal = &*(query as *const QueryMarshal);
    if marshal.encoding.is_none() {
        return core::ptr::null();
    }
    &marshal.loaned_encoding as *const crate::encoding::z_loaned_encoding_t
}

/// The `(zid, eid)` identity behind a loaned queryable, for
/// [`crate::session::z_queryable_id`] (R311y559).
///
/// The projection into the ABI struct lives in ONE place (`entity_id_of`), so
/// this hands back the raw pair rather than the struct — which is also what
/// keeps `QueryableState` private to this module.
///
/// # Safety
/// `queryable` must be null or a live loaned queryable.
#[cfg(feature = "unstable-api")]
pub(crate) unsafe fn queryable_identity(
    queryable: *const z_loaned_queryable_t,
) -> Option<([u8; 16], QblId)> {
    handle_ref::<z_loaned_queryable_t, QueryableState>(queryable)
        .map(|state| (state.engine.zid(), state.id))
}

/// Borrow a query's source info, or NULL when it carried none (pico
/// `z_query_source_info`).
///
/// R311y559 — a symbol the census found missing. NULL for absent is the
/// contract, not an error path, exactly as on
/// [`crate::pubsub::z_sample_source_info`].
///
/// # Safety
/// `query` must be null or a live loaned query.
#[no_mangle]
pub unsafe extern "C" fn z_query_source_info(
    query: *const z_loaned_query_t,
) -> *const crate::pubsub::z_source_info_t {
    crate::ffi::guard_val(core::ptr::null(), || match query_marshal(query) {
        Some(marshal) => match marshal.source_info.as_ref() {
            Some(info) => info as *const crate::pubsub::z_source_info_t,
            None => core::ptr::null(),
        },
        None => core::ptr::null(),
    })
}

/// Deep-copy a query into an owned one (pico `z_query_clone`).
///
/// Routed through the SAME `clone_query_marshal` `z_query_take_from_loaned`
/// uses, so the two cannot diverge; the only difference is that this leaves the
/// source intact. Both are ESCAPES: the copy carries a deferred responder and
/// holds the `ResponseFinal` open until it is dropped, which is what makes "the
/// query is answered when the C side drops it" true for a clone too.
///
/// # Safety
/// `dst` must be valid and writable; `this_` must be null or a live loaned
/// query.
#[no_mangle]
pub unsafe extern "C" fn z_query_clone(
    dst: *mut z_owned_query_t,
    this_: *const z_loaned_query_t,
) -> ZResult {
    guarded(|| {
        if dst.is_null() {
            return Z_ERR_NULL;
        }
        *dst = z_owned_query_t::null_value();
        if this_.is_null() {
            return Z_ERR_NULL;
        }
        match clone_query_marshal(this_) {
            Ok(handle) => {
                (*dst).handle = handle;
                Z_OK
            }
            Err(code) => code,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `QueryView` carrying a value payload + an attachment.
    struct FakeQuery {
        keyexpr: String,
        payload: Vec<u8>,
        attachment: Vec<u8>,
    }

    impl QueryView for FakeQuery {
        fn keyexpr(&self) -> &str {
            &self.keyexpr
        }
        fn parameters(&self) -> Option<&[u8]> {
            None
        }
        fn attachment(&self) -> Option<&[u8]> {
            Some(&self.attachment)
        }
        fn payload(&self) -> Option<&[u8]> {
            Some(&self.payload)
        }
        fn rid(&self) -> wz_session_core::wire_id::RequestId {
            7
        }
        fn qos(&self) -> wz_session_core::sample::QosLevel {
            wz_session_core::sample::QosLevel::DEFAULT
        }
    }

    /// The cached views must point at THIS marshal's own fields — the address
    /// invariant `bind` exists to establish.
    ///
    /// Regression gate for the bug an earlier cut shipped: `QueryMarshal::new`
    /// bound `loaned_payload.handle` to `&self.payload` — the address of the
    /// `Vec` STRUCT — and then returned `Self` BY VALUE, so the handle pointed
    /// into `new`'s dead frame and `z_query_payload` handed C a `Vec`
    /// reconstructed from freed stack. `loaned_keyexpr` hid it (`String::as_ptr`
    /// is the heap buffer, which a move does not relocate) and the wire test
    /// reads only the keyexpr, so the suite stayed green over UB.
    ///
    /// This asserts the ADDRESS, not the bytes, and that distinction is the
    /// whole point: reading a dangling handle is UB that routinely *appears* to
    /// work — a read-back assertion was tried first and passed even with the bug
    /// deliberately restored, because the dead frame still held the old `Vec`.
    /// The address invariant is deterministic and fails the instant `bind` runs
    /// anywhere but the final location.
    /// pico's `_anyke` is a SELECTOR PARAMETER, not a wire field, and the
    /// boundary rules are what make it a parse rather than a substring search.
    /// Ported from `~/zenoh-pico/src/utils/query_params.c:46-70`.
    #[test]
    fn anyke_parses_with_picos_parameter_boundary_rules() {
        assert!(parameters_has_anyke(b"_anyke"));
        assert!(parameters_has_anyke(b"a=1;_anyke"));
        assert!(parameters_has_anyke(b"_anyke;a=1"));
        assert!(parameters_has_anyke(b"a=1;_anyke;b=2"));
        assert!(!parameters_has_anyke(b""));
        assert!(!parameters_has_anyke(b"a=1"));
        // The boundary rules earn their keep here: each of these CONTAINS
        // "_anyke" and must NOT be read as the flag.
        assert!(!parameters_has_anyke(b"no_anyke"));
        assert!(!parameters_has_anyke(b"_anykey=1"));
        assert!(!parameters_has_anyke(b"a=1;xx_anyke_yy;b=2"));
        // ...but a real flag AFTER a decoy is still found (the scan continues).
        assert!(parameters_has_anyke(b"_anykey=1;_anyke"));
    }

    /// The `reply ⊆ query` gate is an INTERSECTION, so a wildcard query admits
    /// concrete replies — the ordinary case for a wildcard queryable, and the
    /// one an earlier string-equality cut of this round rejected.
    #[test]
    fn reply_coverage_is_intersection_not_string_equality() {
        // The case string equality got wrong: query is a PATTERN, reply concrete.
        assert!(reply_keyexpr_is_covered("a/**", "a/b", false));
        assert!(reply_keyexpr_is_covered("a/*", "a/b", false));
        assert!(reply_keyexpr_is_covered("a/b", "a/b", false));
        // Genuinely disjoint replies are rejected...
        assert!(!reply_keyexpr_is_covered("a/**", "z/b", false));
        assert!(!reply_keyexpr_is_covered("a/b", "a/c", false));
        // ...unless the querier said it accepts any key (`_anyke`), which is
        // exactly pico's `!query->_anyke && !intersects` short-circuit.
        assert!(reply_keyexpr_is_covered("a/**", "z/b", true));
        assert!(reply_keyexpr_is_covered("a/b", "a/c", true));
    }

    /// A query whose only content is its selector parameters.
    struct ParamsQuery {
        parameters: Vec<u8>,
    }

    impl QueryView for ParamsQuery {
        fn keyexpr(&self) -> &str {
            "a/b"
        }
        fn parameters(&self) -> Option<&[u8]> {
            Some(&self.parameters)
        }
        fn attachment(&self) -> Option<&[u8]> {
            None
        }
        fn payload(&self) -> Option<&[u8]> {
            None
        }
        fn rid(&self) -> wz_session_core::wire_id::RequestId {
            7
        }
        fn qos(&self) -> wz_session_core::sample::QosLevel {
            wz_session_core::sample::QosLevel::DEFAULT
        }
    }

    /// The core responder's gate behind `z_query_reply` is never the one that
    /// refuses: whatever `_anyke` the ABI reads, the responder built from the
    /// same parameters reads too, so no reply the ABI answered `Z_OK` for is
    /// refused when the responder stages it.
    ///
    /// Measured over every list of one to three segments drawn from the shapes
    /// on which pico's byte scan and zenoh's key split could part (a valued
    /// flag, a prefix, a suffix, an `&` list, an empty segment), with and
    /// without a trailing `;`. On those UTF-8 lists the ABI keeps pico's own
    /// answer. The list that is not UTF-8 is where pico's scan finds the flag
    /// and the core does not, and there the ABI reads no flag.
    #[test]
    fn the_abi_admits_no_reply_the_core_responder_would_refuse() {
        let segments: [&[u8]; 10] = [
            b"_anyke",
            b"_anyke=",
            b"_anyke=true",
            b"x_anyke",
            b"_anykex",
            b"a=1",
            b"",
            b"_anyke&b=2",
            b"b=2&_anyke",
            b"_max=5",
        ];
        let mut lists: Vec<Vec<u8>> = Vec::new();
        for a in segments {
            lists.push(a.to_vec());
            for b in segments {
                lists.push([a, b].join(&b';'));
                for c in segments {
                    lists.push([a, b, c].join(&b';'));
                }
            }
        }
        let trailing: Vec<Vec<u8>> = lists
            .iter()
            .map(|l| [l.as_slice(), b";".as_slice()].concat())
            .collect();
        lists.extend(trailing);

        let mut flagged = 0usize;
        for list in &lists {
            let query = ParamsQuery {
                parameters: list.clone(),
            };
            // SAFETY: the marshal is dropped before `query`.
            let marshal = unsafe { QueryMarshal::new(&query) };
            let shown = String::from_utf8_lossy(list);
            assert_eq!(
                marshal.anyke,
                parameters_has_anyke(list),
                "the ABI keeps pico's reading of the UTF-8 list {shown:?}"
            );
            if marshal.anyke {
                flagged += 1;
                assert_eq!(
                    ReplyKeyExpr::from_parameter_bytes(Some(list.as_slice())),
                    ReplyKeyExpr::Any,
                    "the core responder refuses what the ABI admitted under {shown:?}"
                );
            }
        }
        assert!(
            flagged > 0 && flagged < lists.len(),
            "the corpus holds both answers: {flagged} of {}",
            lists.len()
        );

        let not_text = b"\xff;_anyke".to_vec();
        assert!(
            parameters_has_anyke(&not_text),
            "pico's scan finds the flag"
        );
        assert_eq!(
            ReplyKeyExpr::from_parameter_bytes(Some(not_text.as_slice())),
            ReplyKeyExpr::MatchingQuery,
            "the core reads the guarantee"
        );
        let query = ParamsQuery {
            parameters: not_text,
        };
        // SAFETY: the marshal is dropped before `query`.
        let marshal = unsafe { QueryMarshal::new(&query) };
        assert!(
            !marshal.anyke,
            "so the ABI reads no flag and refuses the reply itself"
        );
    }

    #[test]
    fn bind_points_the_cached_views_at_this_marshals_own_fields() {
        let view = FakeQuery {
            keyexpr: "demo/q".to_owned(),
            payload: b"value-payload".to_vec(),
            attachment: b"att".to_vec(),
        };
        // Exactly the shape `make_queryable_callback` uses: construct, move out
        // of `new`, then bind at the final address.
        // SAFETY: the marshal is dropped before `view`.
        let mut marshal = unsafe { QueryMarshal::new(&view) };
        marshal.bind();

        assert_eq!(
            marshal.loaned_payload.handle as usize,
            &marshal.payload as *const crate::bytes::ByteBuf as usize,
            "the cached payload view must address THIS marshal's Vec, not a moved-from copy's"
        );
        assert_eq!(
            marshal.loaned_attachment.handle as usize,
            &marshal.attachment as *const crate::bytes::ByteBuf as usize,
            "the cached attachment view must address THIS marshal's Vec"
        );
        assert_eq!(
            marshal.loaned_keyexpr._start as usize,
            view.keyexpr.as_ptr() as usize,
            "the cached keyexpr view must address the key where the view holds it, uncopied"
        );

        // The accessors built on those views resolve to the query's bytes.
        let query = &marshal as *const QueryMarshal as *const z_loaned_query_t;
        unsafe {
            // Read as the type the handle IS. This used to say `Vec<u8>` and
            // passed only because `ByteBuf`'s first field was one — a type pun
            // that R2964's storage change turned into an empty read.
            let buf = handle_ref::<z_loaned_bytes_t, crate::bytes::ByteBuf>(z_query_payload(query))
                .expect("the cached payload view must resolve");
            assert_eq!(buf.as_slice(), b"value-payload");
            let buf =
                handle_ref::<z_loaned_bytes_t, crate::bytes::ByteBuf>(z_query_attachment(query))
                    .expect("the cached attachment view must resolve");
            assert_eq!(buf.as_slice(), b"att");
            assert_eq!(
                crate::keyexpr::keyexpr_str(z_query_keyexpr(query)),
                Some("demo/q")
            );
        }
    }

    /// A [`ReplyOut`] that records the QoS each staged reply was given.
    #[derive(Default)]
    struct QosTap {
        seen: Vec<Option<wz_session_core::sample::QosLevel>>,
    }

    impl ReplyOut for QosTap {
        fn reply(&mut self, _payload: &[u8]) {}
        fn reply_del(&mut self) {}
        fn reply_err(&mut self, _id: Option<u32>, _schema: Option<&[u8]>, _payload: &[u8]) {}
        fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
        fn reply_keyed_meta(
            &mut self,
            _keyexpr: &str,
            _payload: &[u8],
            meta: ReplyMeta<'_>,
        ) -> Result<(), wz_session_core::query_sink::ReplyError> {
            self.seen.push(meta.qos);
            Ok(())
        }
        fn reply_keyed_del_meta(
            &mut self,
            _keyexpr: &str,
            meta: ReplyMeta<'_>,
        ) -> Result<(), wz_session_core::query_sink::ReplyError> {
            self.seen.push(meta.qos);
            Ok(())
        }
    }

    /// A reply's QoS is the query's congestion control and priority with the
    /// express bit of the reply's OWN options, and the options' bit REPLACES the
    /// query's: a reply made with default options is not express even when the
    /// query was (`vendor/zenoh-pico/src/net/primitives.c` @
    /// `_z_n_qos_create(is_express,`). Both reply forms, both directions of the
    /// bit.
    #[test]
    fn a_reply_takes_the_express_bit_of_its_options_and_the_rest_of_the_queries_qos() {
        use wz_session_core::qos::{CongestionControl, Priority};
        use wz_session_core::sample::QosLevel;
        let query_qos = QosLevel::from_parts(Priority::RealTime, CongestionControl::Block, false);
        let put = |express| PendingReply::Put {
            keyexpr: "a/b",
            payload: crate::bytes::ByteBuf::copy_of(&[1u8]).expect("room for a byte"),
            attachment: None,
            meta: ReplyMetaOwned {
                express,
                ..ReplyMetaOwned::default()
            },
        };
        let del = |express| PendingReply::Del {
            keyexpr: "a/b",
            meta: ReplyMetaOwned {
                express,
                ..ReplyMetaOwned::default()
            },
        };
        let mut tap = QosTap::default();
        {
            let mut out: &mut dyn ReplyOut = &mut tap;
            flush_one(&mut out, put(true), query_qos);
            flush_one(&mut out, del(true), query_qos);
            flush_one(&mut out, put(false), query_qos.with_express(true));
            flush_one(&mut out, del(false), query_qos.with_express(true));
        }
        let expressed = query_qos.with_express(true);
        assert_eq!(
            tap.seen,
            vec![
                Some(expressed),
                Some(expressed),
                Some(query_qos),
                Some(query_qos)
            ],
            "the express bit is the options', over the query's priority and congestion control"
        );
    }

    /// The C entry points READ `is_express`: the same three replies, made through
    /// `z_query_reply` and `z_query_reply_del` with real options structs (and one
    /// with none), reach the responder with the QoS pico gives them. The test
    /// above holds the flush; this one holds the two functions that feed it.
    #[test]
    fn the_reply_entry_points_read_is_express_from_their_options() {
        let view = FakeQuery {
            keyexpr: "demo/q".to_owned(),
            payload: Vec::new(),
            attachment: Vec::new(),
        };
        // SAFETY: the marshal is dropped before `view`.
        let mut marshal = unsafe { QueryMarshal::new(&view) };
        marshal.bind();
        let mut tap = QosTap::default();
        marshal.answer_with(&mut tap, |marshal| unsafe {
            let query = marshal as *const QueryMarshal as *const z_loaned_query_t;
            let mut ke: crate::abi::z_view_keyexpr_t = core::mem::zeroed();
            assert_eq!(
                crate::keyexpr::z_view_keyexpr_from_str(&mut ke, c"demo/q".as_ptr()),
                Z_OK
            );
            let ke = crate::keyexpr::z_view_keyexpr_loan(&ke);
            let mut payload = core::mem::zeroed();
            assert_eq!(
                crate::bytes::z_bytes_copy_from_str(&mut payload, c"p".as_ptr()),
                Z_OK
            );
            let mut put: z_query_reply_options_t = core::mem::zeroed();
            z_query_reply_options_default(&mut put);
            put.is_express = true;
            assert_eq!(
                z_query_reply(query, ke, crate::bytes::z_bytes_move(&mut payload), &put),
                Z_OK
            );
            let mut del: z_query_reply_del_options_t = core::mem::zeroed();
            z_query_reply_del_options_default(&mut del);
            del.is_express = true;
            assert_eq!(z_query_reply_del(query, ke, &del), Z_OK);
            // And one made with NO options at all.
            assert_eq!(
                crate::bytes::z_bytes_copy_from_str(&mut payload, c"q".as_ptr()),
                Z_OK
            );
            assert_eq!(
                z_query_reply(
                    query,
                    ke,
                    crate::bytes::z_bytes_move(&mut payload),
                    core::ptr::null()
                ),
                Z_OK
            );
        });
        let plain = wz_session_core::sample::QosLevel::DEFAULT;
        assert_eq!(
            tap.seen,
            vec![
                Some(plain.with_express(true)),
                Some(plain.with_express(true)),
                Some(plain)
            ],
            "a reply made with is_express set is express, and one made with no options is not"
        );
    }

    /// A query whose value carries an encoding with a schema.
    struct EncodedQuery {
        encoding: wz_session_core::sample::EncodingHint,
    }

    impl QueryView for EncodedQuery {
        fn keyexpr(&self) -> &str {
            "demo/encoded"
        }
        fn parameters(&self) -> Option<&[u8]> {
            None
        }
        fn attachment(&self) -> Option<&[u8]> {
            None
        }
        fn payload(&self) -> Option<&[u8]> {
            Some(b"x")
        }
        fn encoding(&self) -> Option<&wz_session_core::sample::EncodingHint> {
            Some(&self.encoding)
        }
        fn rid(&self) -> wz_session_core::wire_id::RequestId {
            7
        }
        fn qos(&self) -> wz_session_core::sample::QosLevel {
            wz_session_core::sample::QosLevel::DEFAULT
        }
    }

    /// A hold that answers nothing: the kept copy below is never replied on.
    struct NoHold;

    impl HeldQuery for NoHold {
        fn reply(&self, _answer: &mut dyn FnMut(&mut dyn ReplyOut)) {}

        fn session_closed(&self) -> bool {
            false
        }
    }

    /// A query's payload and attachment are read where the view holds them, with nothing copied
    /// for the callback, and a query kept past it holds copies of its own.
    #[test]
    fn a_query_reads_its_bytes_in_place_and_a_kept_one_copies_them() {
        let view = FakeQuery {
            keyexpr: "demo/q".to_owned(),
            payload: b"in place".to_vec(),
            attachment: b"att".to_vec(),
        };
        // SAFETY: the marshal is dropped before `view`.
        let marshal = unsafe { QueryMarshal::new(&view) };
        assert_eq!(marshal.payload.as_slice().as_ptr(), view.payload.as_ptr());
        assert_eq!(
            marshal.attachment.as_slice().as_ptr(),
            view.attachment.as_ptr()
        );
        let payload = marshal.payload.try_clone().expect("room for the copy");
        let attachment = marshal.attachment.try_clone().expect("room for the copy");
        let encoding = marshal
            .encoding
            .as_ref()
            .map(crate::encoding::EncodingState::kept)
            .transpose()
            .expect("room for the copy");
        let kept = marshal.deep_copy_deferred(Box::new(NoHold), payload, attachment, encoding);
        drop(marshal);
        assert_ne!(kept.payload.as_slice().as_ptr(), view.payload.as_ptr());
        assert_eq!(kept.payload.as_slice(), b"in place");
        assert_eq!(kept.attachment.as_slice(), b"att");
    }

    /// The encoding a query carried is held in its marshal: the loaned encoding
    /// `z_query_encoding` hands out points inside the marshal, so the query's encoding took no
    /// allocation of its own and goes with the marshal, and it reads what the view carried. A
    /// query kept past its callback holds an encoding of its own, which reads the same once the
    /// marshal it was copied from is gone; a query that carried none hands out none.
    #[test]
    fn a_querys_encoding_is_held_in_its_marshal() {
        let view = EncodedQuery {
            encoding: wz_session_core::sample::EncodingHint {
                packed_id: 7,
                schema: Some(b"utf8".to_vec()),
            },
        };
        // SAFETY: the marshal is dropped before `view`.
        let mut marshal = unsafe { QueryMarshal::new(&view) };
        marshal.bind();
        let query = &marshal as *const QueryMarshal as *const z_loaned_query_t;
        // SAFETY: a query this crate marshalled and bound.
        let loaned = unsafe { z_query_encoding(query) };
        assert!(!loaned.is_null(), "the query carried an encoding");
        // SAFETY: the loaned encoding the accessor handed out, of the live marshal.
        let handle = unsafe { (*loaned).handle } as usize;
        let start = &marshal as *const QueryMarshal as usize;
        assert!(
            (start..start + core::mem::size_of::<QueryMarshal>()).contains(&handle),
            "the encoding lies in the marshal, not in a box of its own"
        );
        // SAFETY: as above.
        let hint = unsafe { crate::encoding::encoding_view(loaned) }.expect("bound");
        assert_eq!((hint.packed_id, hint.schema), (7, Some(&b"utf8"[..])));

        let held: Box<dyn HeldQuery> = Box::new(NoHold);
        let payload = marshal.payload.try_clone().expect("room for the copy");
        let attachment = marshal.attachment.try_clone().expect("room for the copy");
        let encoding = marshal
            .encoding
            .as_ref()
            .map(crate::encoding::EncodingState::kept)
            .transpose()
            .expect("room for the copy");
        let mut kept = marshal.deep_copy_deferred(held, payload, attachment, encoding);
        drop(marshal);
        kept.bind();
        let kept_query = &kept as *const QueryMarshal as *const z_loaned_query_t;
        // SAFETY: the kept copy, bound at its final address.
        let kept_loaned = unsafe { z_query_encoding(kept_query) };
        // SAFETY: the loaned encoding of the live copy.
        let kept_hint = unsafe { crate::encoding::encoding_view(kept_loaned) }.expect("kept");
        assert_eq!(
            (kept_hint.packed_id, kept_hint.schema),
            (7, Some(&b"utf8"[..]))
        );

        let plain = FakeQuery {
            keyexpr: "demo/plain".to_owned(),
            payload: Vec::new(),
            attachment: Vec::new(),
        };
        // SAFETY: the marshal is dropped before `plain`.
        let mut none = unsafe { QueryMarshal::new(&plain) };
        none.bind();
        let none_query = &none as *const QueryMarshal as *const z_loaned_query_t;
        // SAFETY: a query this crate marshalled and bound.
        let carried = unsafe { z_query_encoding(none_query) };
        assert!(carried.is_null(), "no encoding carried, none handed out");
    }

    /// A loaned query answered outside the callback it was handed to has no responder: the reply
    /// is refused with a generic failure and nothing is answered. Turned red by a responder left
    /// lent past the callback.
    #[test]
    fn a_reply_outside_the_callback_is_refused() {
        let view = FakeQuery {
            keyexpr: "demo/q".to_owned(),
            payload: Vec::new(),
            attachment: Vec::new(),
        };
        // SAFETY: the marshal is dropped before `view`.
        let mut marshal = unsafe { QueryMarshal::new(&view) };
        marshal.bind();
        let mut tap = QosTap::default();
        marshal.answer_with(&mut tap, |_| {});
        let query = &marshal as *const QueryMarshal as *const z_loaned_query_t;
        // SAFETY: a query this crate marshalled and bound, and live keys and payloads.
        unsafe {
            let mut ke: crate::abi::z_view_keyexpr_t = core::mem::zeroed();
            assert_eq!(
                crate::keyexpr::z_view_keyexpr_from_str(&mut ke, c"demo/q".as_ptr()),
                Z_OK
            );
            let mut payload = core::mem::zeroed();
            assert_eq!(
                crate::bytes::z_bytes_copy_from_str(&mut payload, c"late".as_ptr()),
                Z_OK
            );
            assert_eq!(
                z_query_reply(
                    query,
                    crate::keyexpr::z_view_keyexpr_loan(&ke),
                    crate::bytes::z_bytes_move(&mut payload),
                    core::ptr::null()
                ),
                crate::result::Z_ERR_GENERIC
            );
        }
        assert!(tap.seen.is_empty(), "nothing reached the responder");
    }

    /// What a kept query's replies reach: the replies' keys, in order.
    #[derive(Default)]
    struct Kept {
        keys: std::sync::Mutex<Vec<String>>,
    }

    /// A hold that records each reply's key into `Kept`.
    struct KeptHold(Arc<Kept>);

    impl HeldQuery for KeptHold {
        fn reply(&self, answer: &mut dyn FnMut(&mut dyn ReplyOut)) {
            let mut out = KeyTap(self.0.clone());
            answer(&mut out);
        }

        fn session_closed(&self) -> bool {
            false
        }
    }

    /// A responder that records the key of each keyed reply.
    struct KeyTap(Arc<Kept>);

    impl ReplyOut for KeyTap {
        fn reply(&mut self, _payload: &[u8]) {}
        fn reply_del(&mut self) {}
        fn reply_err(&mut self, _id: Option<u32>, _schema: Option<&[u8]>, _payload: &[u8]) {}
        fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
        fn reply_keyed_meta(
            &mut self,
            keyexpr: &str,
            _payload: &[u8],
            _meta: ReplyMeta<'_>,
        ) -> Result<(), wz_session_core::query_sink::ReplyError> {
            self.0
                .keys
                .lock()
                .expect("a held lock")
                .push(keyexpr.to_owned());
            Ok(())
        }
        fn reply_keyed_del_meta(
            &mut self,
            _keyexpr: &str,
            _meta: ReplyMeta<'_>,
        ) -> Result<(), wz_session_core::query_sink::ReplyError> {
            Ok(())
        }
    }

    /// What a dispatch's queries are held through, here a hold that records into `Kept`.
    struct KeptHolder(Arc<Kept>);

    impl QueryHolder for KeptHolder {
        fn hold_query(&self, _view: &dyn QueryView) -> Box<dyn HeldQuery> {
            Box::new(KeptHold(self.0.clone()))
        }
        fn session_closed(&self) -> bool {
            false
        }
    }

    /// A query cloned inside its callback is answered after the callback returned, as pico lets a
    /// program answer one it kept: the reply goes through the hold, not the dispatch's responder,
    /// which is no longer lent. Turned red by a kept query that answers through the responder.
    #[test]
    fn a_query_cloned_in_its_callback_answers_after_it() {
        let view = FakeQuery {
            keyexpr: "demo/kept".to_owned(),
            payload: Vec::new(),
            attachment: Vec::new(),
        };
        let kept = Arc::new(Kept::default());
        // SAFETY: the marshal is dropped before `view`.
        let mut marshal =
            unsafe { QueryMarshal::new(&view) }.with_holder(Arc::new(KeptHolder(kept.clone())));
        marshal.bind();
        let mut owned = z_owned_query_t::null_value();
        let mut tap = QosTap::default();
        marshal.answer_with(&mut tap, |marshal| {
            let query = marshal as *const QueryMarshal as *const z_loaned_query_t;
            // SAFETY: the callback's own loaned query, and a live destination.
            assert_eq!(unsafe { z_query_clone(&mut owned, query) }, Z_OK);
        });
        drop(marshal);
        // SAFETY: the kept query is live, and the keys and payloads are this frame's.
        unsafe {
            let mut ke: crate::abi::z_view_keyexpr_t = core::mem::zeroed();
            assert_eq!(
                crate::keyexpr::z_view_keyexpr_from_str(&mut ke, c"demo/kept".as_ptr()),
                Z_OK
            );
            let mut payload = core::mem::zeroed();
            assert_eq!(
                crate::bytes::z_bytes_copy_from_str(&mut payload, c"later".as_ptr()),
                Z_OK
            );
            assert_eq!(
                z_query_reply(
                    z_query_loan(&owned),
                    crate::keyexpr::z_view_keyexpr_loan(&ke),
                    crate::bytes::z_bytes_move(&mut payload),
                    core::ptr::null()
                ),
                Z_OK
            );
            z_query_drop(z_query_move(&mut owned));
        }
        assert!(tap.seen.is_empty(), "the dispatch's responder is not used");
        assert_eq!(
            *kept.keys.lock().expect("a held lock"),
            vec!["demo/kept".to_owned()]
        );
    }
}
