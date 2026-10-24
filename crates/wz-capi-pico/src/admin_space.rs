// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! zenoh-pico's admin space (`Z_FEATURE_ADMIN_SPACE`): `zp_start_admin_space`,
//! `zp_stop_admin_space` and the documents they serve.
//!
//! ## The key space is pico's, not the wz runtime's
//!
//! The wz runtime has an admin space of its own (`adminspace-core`), and it
//! answers zenoh's layout, `@/<zid>/<whatami>/**`. A program that links this
//! ABI was written against pico's, which is a different tree, so this module
//! serves that one: a single queryable on `@/<zid>/pico/**`
//! (`vendor/zenoh-pico/src/api/admin_space.c` @
//! `// ke = _Z_KEYEXPR_AT / ZID / _Z_KEYEXPR_PICO / Z_KEYEXPR_STARSTAR`),
//! declared as pico's `z_declare_queryable` with no options declares it
//! (incomplete, answering remote queries only), and answering, for every key of
//! the table below that intersects the query, in this order:
//!
//! | key under `@/<zid>/` | document |
//! |---|---|
//! | `pico` | `{"session":SESSION}` |
//! | `pico/session` | `SESSION` = `{"zid","whatami","transports":[TRANSPORT]}` |
//! | `pico/session/transports` | `[TRANSPORT]` |
//! | `pico/session/transports/0` | `TRANSPORT` = `{"type","link","peers"}` |
//! | `pico/session/transports/0/peers` | `[PEER, ...]` |
//! | `pico/session/transports/0/peers/<peer zid>` | `PEER` = `{"zid","whatami"}` |
//!
//! (`vendor/zenoh-pico/src/api/admin_space.c` @
//! `static const _ze_admin_space_endpoint_t _ze_admin_space_pico_endpoints[] = {`).
//! Every reply is `application/json`, written without whitespace and escaped as
//! pico's encoder escapes (`vendor/zenoh-pico/src/utils/json_encoder.c` @
//! `static z_result_t _z_json_encoder_write_escaped_string(`), and every zid is
//! spelled as `z_id_to_string` spells it. A document pico cannot encode (a role
//! outside the three) is not sent, and neither is any document that contains it.
//!
//! ## The connectivity half is not served, because nothing can ask for it
//!
//! With `Z_FEATURE_CONNECTIVITY` pico's start also declares a queryable on
//! `@/<zid>/session/**` and publishes each transport and link event under the
//! same prefix, both `Z_LOCALITY_SESSION_LOCAL`. A session-local queryable is
//! never declared on the wire (`vendor/zenoh-pico/src/net/primitives.c` @
//! `if (_z_locality_allows_remote(allowed_origin)) {`), and the session's own
//! get reaches it only through the local delivery that
//! `Z_FEATURE_LOCAL_QUERYABLE` compiles in (`#if Z_FEATURE_LOCAL_QUERYABLE == 1`
//! in `_z_query`), as the events reach a subscriber only through
//! `Z_FEATURE_LOCAL_SUBSCRIBER`. Both switches are 0 in this ABI, as in
//! upstream's default, so in the configuration this ABI reproduces that half has
//! no observer and is left out; it becomes observable with the local arms
//! (open-debt item 914), and has to be served then.
//!
//! ## Where a wz session differs from the pico session the documents describe
//!
//! - pico has ONE transport and its peers; a wz session is a registry of faces.
//!   The transport's peers are the faces, and its link is the locator the
//!   session was opened on: the listen locator when there is one, as pico opens
//!   its transport there first.
//! - The link's `metadata` and `config` are always `{}`. pico parses the `?` and
//!   `#` parts of an endpoint into integer-keyed maps whose keys are each link
//!   type's own; an endpoint carrying neither (every plain `tcp/`, `udp/` and
//!   `tls/` locator) reports `{}` in pico too.
//! - A link kind pico does not have (QUIC, unixpipe, ...) reports its protocol
//!   name as its `type`, where pico could not encode the document at all.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use wz_capi_core::faces::{FaceSnapshot, QueryableSink, SharedSession};
use wz_runtime_tokio::session::TokioQueryHolder;
use wz_runtime_tokio::session_glue::LinkKind;
use wz_session_core::keyexpr_match::keyexpr_intersects_text;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::sample::EncodingHint;
use wz_session_core::WhatAmI;

use crate::ffi::guarded;
use crate::link_properties::pico_link_properties;
use crate::query::PlainQueryable;
use crate::result::{ZResult, Z_ERR_NULL, Z_OK};
use crate::session::{session_handle, tokio_session, z_loaned_session_t, PicoSessionHandle};
use crate::write_filter::PicoSession;
use crate::zid::zid_hex;

// ===========================================================================
// the per-session slot
// ===========================================================================

/// One session's admin space: the locator its documents report as the
/// transport's link, and the queryable while it runs (pico's
/// `_admin_space_queryable_id`).
pub(crate) struct AdminSpaceSlot {
    transport_endpoint: Option<String>,
    running: Mutex<Option<PlainQueryable>>,
}

impl AdminSpaceSlot {
    /// A stopped admin space whose transport is `transport_endpoint`.
    pub(crate) fn new(transport_endpoint: Option<String>) -> Self {
        Self {
            transport_endpoint,
            running: Mutex::new(None),
        }
    }

    fn running(&self) -> MutexGuard<'_, Option<PlainQueryable>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The session behind `zs` and its tokio engine, whose session the admin
/// space's queryable is declared on: `Err(Z_ERR_NULL)` for a null or spent
/// handle.
unsafe fn slot_of<'a>(
    zs: *const z_loaned_session_t,
) -> Result<(&'a PicoSessionHandle, &'a wz_capi_core::drive::SessionState), ZResult> {
    tokio_session(zs).ok_or(Z_ERR_NULL)
}

/// Start the session's admin space (pico `zp_start_admin_space`).
///
/// Idempotent, as pico's is: a start while it runs returns `0` and declares
/// nothing more. A declaration the session refuses returns its error and leaves
/// the admin space stopped.
#[no_mangle]
pub unsafe extern "C" fn zp_start_admin_space(zs: *mut z_loaned_session_t) -> ZResult {
    guarded(|| {
        let (handle, state) = match slot_of(zs) {
            Ok(found) => found,
            Err(code) => return code,
        };
        let ext = &handle.ext;
        // Held across the declaration, as pico holds its admin-space mutex, so
        // two starts at once declare one queryable.
        let mut running = ext.admin_space.running();
        if running.is_some() {
            return Z_OK;
        }
        let identity = Identity {
            zid: zid_string(&state.zid()),
            mode: ext.mode,
            link: ext
                .admin_space
                .transport_endpoint
                .as_deref()
                .and_then(TransportLink::parse),
        };
        let key = format!("@/{}/pico/**", identity.zid);
        let answerer = Arc::new(Answerer {
            // Weak, as pico's query context is: the queryable lives in the
            // session, and a strong reference would keep the session alive
            // through its own declaration.
            session: Arc::downgrade(&state.shared),
            identity,
        });
        let sink: QueryableSink = Arc::new(move |_face: &TokioQueryHolder| {
            let answerer = Arc::clone(&answerer);
            Box::new(move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                answerer.answer(query, out)
            }) as Box<_>
        });
        match PlainQueryable::declare(&PicoSession::of(handle), &key, None, false, sink) {
            Ok(queryable) => {
                *running = Some(queryable);
                Z_OK
            }
            Err(code) => code,
        }
    })
}

/// Stop the session's admin space (pico `zp_stop_admin_space`): its queryable
/// is undeclared. Idempotent, as pico's is: a stop while it is stopped returns
/// `0`.
#[no_mangle]
pub unsafe extern "C" fn zp_stop_admin_space(zs: *mut z_loaned_session_t) -> ZResult {
    guarded(|| {
        let Some(handle) = session_handle(zs) else {
            return Z_ERR_NULL;
        };
        // Taken out under the lock and undeclared after it is released.
        let stopped = handle.ext.admin_space.running().take();
        drop(stopped);
        Z_OK
    })
}

// ===========================================================================
// the answerer
// ===========================================================================

/// What the documents say about the session itself, fixed at the start.
struct Identity {
    /// The session's zid as `z_id_to_string` spells it.
    zid: String,
    /// The session's own role.
    mode: WhatAmI,
    /// The transport's link, or `None` when the session has no locator to
    /// report, in which case no document that contains the transport is sent.
    link: Option<TransportLink>,
}

/// The two parts of a locator pico's link document reports.
#[derive(Debug, PartialEq, Eq)]
struct TransportLink {
    protocol: String,
    address: String,
}

impl TransportLink {
    /// `<protocol>/<address>[?metadata][#config]`, as pico splits an endpoint.
    fn parse(endpoint: &str) -> Option<Self> {
        let end = endpoint.find(['?', '#']).unwrap_or(endpoint.len());
        let (protocol, address) = endpoint[..end].split_once('/')?;
        if protocol.is_empty() || address.is_empty() {
            return None;
        }
        Some(Self {
            protocol: protocol.to_owned(),
            address: address.to_owned(),
        })
    }
}

/// The queryable's handler, shared by every face it is declared on.
struct Answerer {
    session: Weak<SharedSession>,
    identity: Identity,
}

impl Answerer {
    fn answer(&self, query: &dyn QueryView, out: &mut dyn ReplyOut) {
        // A session that is gone answers nothing, as pico drops the query of a
        // closed session.
        let Some(shared) = self.session.upgrade() else {
            return;
        };
        let faces = shared.face_snapshots();
        for (key, body) in replies(&self.identity, &faces, query.keyexpr()) {
            // Every key intersects the query, so a refusal is a full reply
            // stage, which pico logs and moves past to the next reply.
            let _ = out.reply_keyed_encoded(
                &key,
                body.as_bytes(),
                Some(&EncodingHint::APPLICATION_JSON),
            );
        }
    }
}

/// Every `(key, document)` pico answers a query on `query` with, in pico's
/// order.
fn replies(identity: &Identity, faces: &[FaceSnapshot], query: &str) -> Vec<(String, String)> {
    let base = format!("@/{}/pico", identity.zid);
    let mut out = Vec::new();
    answer(&mut out, query, base.clone(), || {
        Some(format!("{{\"session\":{}}}", session_doc(identity, faces)?))
    });
    answer(&mut out, query, format!("{base}/session"), || {
        session_doc(identity, faces)
    });
    answer(
        &mut out,
        query,
        format!("{base}/session/transports"),
        || Some(format!("[{}]", transport_doc(identity, faces)?)),
    );
    answer(
        &mut out,
        query,
        format!("{base}/session/transports/0"),
        || transport_doc(identity, faces),
    );
    answer(
        &mut out,
        query,
        format!("{base}/session/transports/0/peers"),
        || peers_doc(faces),
    );
    for face in faces {
        let key = format!(
            "{base}/session/transports/0/peers/{}",
            zid_string(&face.zid)
        );
        answer(&mut out, query, key, || peer_doc(face));
    }
    out
}

/// Push `(key, document)` when `key` intersects `query` and the document can be
/// written. `document` runs only for a key the query reaches, so a narrow query
/// pays for the documents it asked for and no others.
fn answer(
    out: &mut Vec<(String, String)>,
    query: &str,
    key: String,
    document: impl FnOnce() -> Option<String>,
) {
    if !keyexpr_intersects_text(query, &key) {
        return;
    }
    if let Some(body) = document() {
        out.push((key, body));
    }
}

/// `{"zid":..,"whatami":..,"transports":[TRANSPORT]}`.
fn session_doc(identity: &Identity, faces: &[FaceSnapshot]) -> Option<String> {
    let mut doc = String::from("{\"zid\":");
    push_json_str(&mut doc, &identity.zid);
    doc.push_str(",\"whatami\":");
    push_json_str(&mut doc, identity.mode.to_str());
    doc.push_str(",\"transports\":[");
    doc.push_str(&transport_doc(identity, faces)?);
    doc.push_str("]}");
    Some(doc)
}

/// `{"type":"unicast","link":LINK,"peers":[PEER, ...]}`: the C surface
/// establishes unicast transports only.
fn transport_doc(identity: &Identity, faces: &[FaceSnapshot]) -> Option<String> {
    let link = identity.link.as_ref()?;
    Some(format!(
        "{{\"type\":\"unicast\",\"link\":{},\"peers\":{}}}",
        link_doc(link),
        peers_doc(faces)?
    ))
}

/// pico's link document (`_ze_admin_space_encode_link`), with the flow and
/// reliability pico's link of that kind reports.
fn link_doc(link: &TransportLink) -> String {
    let (_, is_streamed, is_reliable) = pico_link_properties(link_kind(&link.protocol), 0);
    let mut doc = String::from("{\"type\":");
    push_json_str(&mut doc, &link.protocol);
    doc.push_str(",\"endpoint\":{\"locator\":{\"metadata\":{},\"protocol\":");
    push_json_str(&mut doc, &link.protocol);
    doc.push_str(",\"address\":");
    push_json_str(&mut doc, &link.address);
    doc.push_str("},\"config\":{}},\"capabilities\":{\"transport\":\"unicast\",\"flow\":");
    doc.push_str(if is_streamed {
        "\"stream\""
    } else {
        "\"datagram\""
    });
    doc.push_str(",\"is_reliable\":");
    doc.push_str(if is_reliable { "true" } else { "false" });
    doc.push_str("}}");
    doc
}

/// The link kind a locator's protocol names, for the flags pico's link of that
/// kind reports; `None` for a protocol no wz link has.
fn link_kind(protocol: &str) -> Option<LinkKind> {
    match protocol {
        "tcp" => Some(LinkKind::Tcp),
        "udp" => Some(LinkKind::Udp),
        "tls" => Some(LinkKind::Tls),
        "ws" => Some(LinkKind::Ws),
        "serial" => Some(LinkKind::Serial),
        "quic" => Some(LinkKind::Quic),
        "unixpipe" => Some(LinkKind::Unixpipe),
        "unixsock-stream" => Some(LinkKind::UnixsockStream),
        "vsock" => Some(LinkKind::Vsock),
        _ => None,
    }
}

/// `[PEER, ...]`, one per established face.
fn peers_doc(faces: &[FaceSnapshot]) -> Option<String> {
    let mut doc = String::from("[");
    for (i, face) in faces.iter().enumerate() {
        if i > 0 {
            doc.push(',');
        }
        doc.push_str(&peer_doc(face)?);
    }
    doc.push(']');
    Some(doc)
}

/// `{"zid":..,"whatami":..}`; `None` for a role outside the three, which pico's
/// encoder refuses.
fn peer_doc(face: &FaceSnapshot) -> Option<String> {
    let whatami = WhatAmI::from_wire(face.whatami)?;
    let mut doc = String::from("{\"zid\":");
    push_json_str(&mut doc, &zid_string(&face.zid));
    doc.push_str(",\"whatami\":");
    push_json_str(&mut doc, whatami.to_str());
    doc.push('}');
    Some(doc)
}

/// A zid as `z_id_to_string` spells it.
fn zid_string(zid: &[u8; 16]) -> String {
    zid_hex(zid).iter().map(|&b| char::from(b)).collect()
}

/// `value` as a JSON string, escaped exactly as pico's encoder escapes: the two
/// mandatory escapes, the five short forms, `\u00xx` for any other control
/// byte, and everything else verbatim.
fn push_json_str(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZID: &str = "0123456789abcdef0123456789abcdef";

    fn identity(link: Option<&str>) -> Identity {
        Identity {
            zid: ZID.to_owned(),
            mode: WhatAmI::Peer,
            link: link.and_then(TransportLink::parse),
        }
    }

    /// A face whose zid is `first` followed by zeros, of wire role `whatami`.
    fn face(first: u8, whatami: u8) -> FaceSnapshot {
        let mut zid = [0u8; 16];
        zid[0] = first;
        FaceSnapshot {
            zid,
            whatami,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
            links: Vec::new(),
        }
    }

    fn keys(replies: &[(String, String)]) -> Vec<&str> {
        replies.iter().map(|(k, _)| k.as_str()).collect()
    }

    #[test]
    fn the_whole_tree_answers_in_picos_order() {
        let faces = [face(0x0a, 2)];
        let got = replies(
            &identity(Some("tcp/127.0.0.1:7447")),
            &faces,
            &format!("@/{ZID}/pico/**"),
        );
        let expected = [
            format!("@/{ZID}/pico"),
            format!("@/{ZID}/pico/session"),
            format!("@/{ZID}/pico/session/transports"),
            format!("@/{ZID}/pico/session/transports/0"),
            format!("@/{ZID}/pico/session/transports/0/peers"),
            format!("@/{ZID}/pico/session/transports/0/peers/0000000000000000000000000000000a"),
        ];
        assert_eq!(
            keys(&got),
            expected.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_root_document_is_picos_byte_for_byte() {
        let faces = [face(0x0a, 2)];
        let got = replies(
            &identity(Some("tcp/127.0.0.1:7447")),
            &faces,
            &format!("@/{ZID}/pico"),
        );
        // pico renders the zid byte-reversed: 0x0a first is "...0a" last.
        let peer_zid = "0000000000000000000000000000000a";
        let expected = format!(
            "{{\"session\":{{\"zid\":\"{ZID}\",\"whatami\":\"peer\",\"transports\":[{{\"type\":\"unicast\",\
             \"link\":{{\"type\":\"tcp\",\"endpoint\":{{\"locator\":{{\"metadata\":{{}},\"protocol\":\"tcp\",\
             \"address\":\"127.0.0.1:7447\"}},\"config\":{{}}}},\"capabilities\":{{\"transport\":\"unicast\",\
             \"flow\":\"stream\",\"is_reliable\":true}}}},\"peers\":[{{\"zid\":\"{peer_zid}\",\
             \"whatami\":\"client\"}}]}}]}}}}"
        );
        assert_eq!(got.len(), 1, "only the exact key intersects an exact query");
        assert_eq!(got[0].1, expected);
    }

    #[test]
    fn an_exact_query_reaches_only_its_own_key() {
        let got = replies(
            &identity(Some("tcp/127.0.0.1:7447")),
            &[face(1, 1)],
            &format!("@/{ZID}/pico/session/transports/0/peers"),
        );
        let expected = format!("@/{ZID}/pico/session/transports/0/peers");
        assert_eq!(keys(&got), [expected.as_str()]);
        assert_eq!(
            got[0].1,
            "[{\"zid\":\"00000000000000000000000000000001\",\"whatami\":\"peer\"}]"
        );
    }

    #[test]
    fn another_sessions_key_space_is_not_answered() {
        let got = replies(
            &identity(Some("tcp/127.0.0.1:7447")),
            &[face(1, 1)],
            "@/ffffffffffffffffffffffffffffffff/pico/**",
        );
        assert!(got.is_empty(), "{got:?}");
        let got = replies(
            &identity(Some("tcp/127.0.0.1:7447")),
            &[],
            &format!("@/{ZID}/session/**"),
        );
        assert!(
            got.is_empty(),
            "the connectivity half is not served: {got:?}"
        );
    }

    #[test]
    fn a_role_pico_cannot_encode_drops_every_document_that_holds_it() {
        // 0b11 is the reserved wire role.
        let faces = [face(1, 1), face(2, 3)];
        let got = replies(
            &identity(Some("tcp/127.0.0.1:7447")),
            &faces,
            &format!("@/{ZID}/pico/**"),
        );
        let good = format!(
            "@/{ZID}/pico/session/transports/0/peers/{}",
            zid_string(&faces[0].zid)
        );
        assert_eq!(keys(&got), [good.as_str()]);
    }

    #[test]
    fn without_a_transport_link_only_the_peer_documents_answer() {
        let faces = [face(1, 0)];
        let got = replies(&identity(None), &faces, &format!("@/{ZID}/pico/**"));
        let peers = format!("@/{ZID}/pico/session/transports/0/peers");
        let peer = format!("{peers}/{}", zid_string(&faces[0].zid));
        assert_eq!(keys(&got), [peers.as_str(), peer.as_str()]);
        assert_eq!(
            got[1].1,
            "{\"zid\":\"00000000000000000000000000000001\",\"whatami\":\"router\"}"
        );
    }

    #[test]
    fn an_endpoint_splits_as_picos_does() {
        assert_eq!(
            TransportLink::parse("udp/10.0.0.1:7447?iface=lo#rel=1"),
            Some(TransportLink {
                protocol: "udp".to_owned(),
                address: "10.0.0.1:7447".to_owned(),
            })
        );
        assert_eq!(TransportLink::parse("no-separator"), None);
        assert_eq!(TransportLink::parse("/127.0.0.1:7447"), None);
        assert_eq!(TransportLink::parse("tcp/"), None);
    }

    #[test]
    fn a_link_reports_the_flags_of_picos_link_of_that_kind() {
        let udp = link_doc(&TransportLink::parse("udp/10.0.0.1:7447").unwrap());
        assert!(
            udp.contains("\"flow\":\"datagram\",\"is_reliable\":false"),
            "{udp}"
        );
        let ws = link_doc(&TransportLink::parse("ws/10.0.0.1:7447").unwrap());
        assert!(
            ws.contains("\"flow\":\"datagram\",\"is_reliable\":true"),
            "{ws}"
        );
        let quic = link_doc(&TransportLink::parse("quic/10.0.0.1:7447").unwrap());
        assert!(quic.starts_with("{\"type\":\"quic\""), "{quic}");
    }

    #[test]
    fn strings_are_escaped_as_picos_encoder_escapes() {
        let mut out = String::new();
        push_json_str(&mut out, "a\"b\\c\u{08}\u{0c}\n\r\t\u{01}\u{1f}\u{7f}é");
        assert_eq!(out, "\"a\\\"b\\\\c\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}é\"");
    }

    #[test]
    fn a_null_session_is_refused_by_both_doors() {
        unsafe {
            assert_eq!(zp_start_admin_space(std::ptr::null_mut()), Z_ERR_NULL);
            assert_eq!(zp_stop_admin_space(std::ptr::null_mut()), Z_ERR_NULL);
        }
    }
}
