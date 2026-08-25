// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Request dispatch: map a parsed HTTP request onto a wz `Session` operation.
//!
//! `GET`/`POST` -> [`TokioSession::query`] (JSON reply array, or raw first
//! reply with `?_raw`); `PUT`/`PATCH` -> [`TokioSession::publish`] Put;
//! `DELETE` -> [`TokioSession::publish`] Del; `OPTIONS` -> a CORS preflight
//! answer. The URL path becomes the keyexpr via [`path_to_keyexpr`] (zenoh
//! `path_to_key_expr` parity: strip the leading `/`, resolve the `@/local`
//! admin alias, canonicalise — an invalid keyexpr is `400`).

use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};

use wz_runtime_tokio::reply_sink::{ReplyKind, ReplyView};
use wz_runtime_tokio::session::{PublishOptions, QueryOptions, TokioSession};
use wz_runtime_tokio::session_glue::ConsolidationMode;
use wz_session_core::encoding::encoding_from_mime;
use wz_session_core::sample::{EncodingHint, TimestampHint};

use wz_session_core::keyexpr_canon::canonize_keyexpr;
use wz_session_core::selector_params::has_param;
use wz_session_core::zid_hex::zid_to_zenoh_hex;

use crate::http::{Method, Request, Response};

/// The raw-response selector flag (zenoh REST plugin `RAW_KEY`,
/// zenoh-plugin-rest/src/lib.rs:62).
const RAW_KEY: &str = "_raw";
/// The time-range selector key (zenoh `ZenohParameters::TIME_RANGE_KEY`,
/// zenoh/src/api/selector.rs:145).
const TIME_KEY: &str = "_time";
use crate::{json, QUERY_TIMEOUT_MS};

/// One collected reply, copied out of the borrowed `&dyn ReplyView` inside the
/// callback (the view does not outlive the call).
struct ReplyRow {
    key: String,
    kind: ReplyKind,
    payload: Vec<u8>,
    /// The reply's decoded encoding hint, if any. R311y501 — the WHOLE hint,
    /// where this used to keep only the packed id and drop the schema string.
    /// Dropping it was two divergences at once: the rendered `encoding` lost
    /// its `;schema` suffix (zenoh emits `application/json;charset=utf-8`), and
    /// the schema-vs-no-schema split is what selects zenoh's `value` branch.
    encoding: Option<EncodingHint>,
    /// R311y501 — the reply's inline body timestamp, if it carried one.
    timestamp: Option<TimestampHint>,
}

impl ReplyRow {
    /// The MIME rendering, through the SAME SSOT the SSE path uses (an absent
    /// hint renders zenoh's `zenoh/bytes` default, not the empty string).
    fn encoding_mime(&self) -> String {
        json::mime_or_default(self.encoding.as_ref())
    }

    /// `(id, has_schema)` — what selects the `value` rendering branch.
    fn encoding_id(&self) -> Option<(u16, bool)> {
        self.encoding.as_ref().map(|e| (e.id(), e.schema.is_some()))
    }
}

/// The result of dispatching a request: either a complete buffered response,
/// or (feature `rest-sse-subscribe`) a keyexpr to stream as Server-Sent Events.
pub enum Outcome {
    Response(Response),
    /// A `GET` with `Accept: text/event-stream` — the caller streams
    /// `declare_subscriber(keyexpr)` samples as SSE events over the connection.
    #[cfg(feature = "rest-sse-subscribe")]
    Sse(String),
}

/// Does this request ask for an SSE stream (`Accept: text/event-stream`)?
fn is_event_stream(req: &Request) -> bool {
    req.headers
        .get("accept")
        .is_some_and(|a| a.contains("text/event-stream"))
}

/// R311y501 — does this request ask for the HTML rendering?
///
/// Upstream reads the FIRST media type of `Accept` and compares it for equality
/// with `text/html` (`plugin-rest/src/lib.rs:362-376`: split on `;`, then on
/// `,`, take `[0]`), so `Accept: text/html, application/json` is HTML while
/// `application/json, text/html` is JSON. A `contains` test — which is what
/// [`is_event_stream`] can afford, `text/event-stream` never being a secondary
/// preference in practice — would get that backwards.
/// Takes the header VALUE rather than the `Request` so the preference-order
/// rule is directly unit-testable (`Headers` has no cross-module constructor,
/// and a test-only one would be a worse trade than this signature).
fn wants_html(accept: Option<&str>) -> bool {
    accept.is_some_and(|a| {
        a.split(';')
            .next()
            .unwrap_or_default()
            .split(',')
            .next()
            .unwrap_or_default()
            .trim()
            == "text/html"
    })
}

/// Escape a value for HTML text content.
///
/// A DELIBERATE, DOCUMENTED divergence from the reference, which interpolates
/// the keyexpr and the payload into its `<dt>`/`<dd>` RAW
/// (`plugin-rest/src/lib.rs:185-191`). Reproducing that would make any client
/// that can publish a sample able to inject script into any browser that later
/// GETs the key as HTML — a stored-XSS vector, in a surface whose whole purpose
/// is to be opened in a browser. wz is a superset of the reference, not a mirror
/// of its defects, so the escaping stays and the divergence is named here rather
/// than discovered later. The escaped set is the standard five.
fn html_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Dispatch one parsed request to a session op and build the outcome.
pub async fn dispatch(session: &TokioSession, zid: &[u8], req: Request) -> Outcome {
    match req.method {
        Method::Options => Outcome::Response(Response::options()),
        Method::Get | Method::Post if is_event_stream(&req) => sse_outcome(zid, &req),
        Method::Get | Method::Post => Outcome::Response(handle_query(session, zid, &req).await),
        Method::Put | Method::Patch => Outcome::Response(handle_write(session, zid, &req, false)),
        Method::Delete => Outcome::Response(handle_write(session, zid, &req, true)),
        Method::Head => Outcome::Response(Response::empty(405, "Method Not Allowed")),
    }
}

/// SSE dispatch (feature-on): resolve the keyexpr and hand it to the streamer.
#[cfg(feature = "rest-sse-subscribe")]
fn sse_outcome(zid: &[u8], req: &Request) -> Outcome {
    match path_to_keyexpr(split_target(&req.target).0, zid) {
        Ok(ke) => Outcome::Sse(ke),
        Err(()) => Outcome::Response(Response::text(400, "Bad Request", "invalid keyexpr")),
    }
}

/// SSE dispatch (feature-off): report `501` rather than silently mis-answering
/// the `Accept: text/event-stream` request as a one-shot JSON query.
#[cfg(not(feature = "rest-sse-subscribe"))]
fn sse_outcome(_zid: &[u8], _req: &Request) -> Outcome {
    Outcome::Response(Response::text(
        501,
        "Not Implemented",
        "SSE (text/event-stream) not enabled in this build",
    ))
}

async fn handle_query(session: &TokioSession, zid: &[u8], req: &Request) -> Response {
    let (path, query) = split_target(&req.target);
    let ke = match path_to_keyexpr(path, zid) {
        Ok(k) => k,
        Err(()) => return Response::text(400, "Bad Request", "invalid keyexpr"),
    };
    // R311y442 review (REVIEWER 1, finding 1) — the selector parameter list is
    // `;`-separated, not `&`-separated. Upstream's REST plugin reads it as
    // `Parameters::from(url.query())` then `contains_key(RAW_KEY)`
    // (zenoh-plugin-rest/src/lib.rs:435-442), i.e. the same dialect every other
    // zenoh selector uses; `;` is a legal RFC 3986 query sub-delim, so a
    // conformant `?_raw;_time=[now(-10s)..]` arrives here intact and the `&`
    // reading saw ONE parameter named `_raw;_time=[now(-10s)..]` — both knobs
    // silently wrong. Worse, :148 forwards the query string VERBATIM as the
    // outgoing zenoh parameters, so wz's local reading and the downstream
    // queryable's reading disagreed about the very same bytes.
    let raw = has_param(query, RAW_KEY);

    let rows: Arc<Mutex<Vec<ReplyRow>>> = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = oneshot::channel::<()>();
    let mut tx = Some(tx);
    let rows_cb = Arc::clone(&rows);

    let on_reply = move |rv: &dyn ReplyView| {
        let kind = rv.kind();
        let encoding = match kind {
            ReplyKind::Err => rv.err_encoding(),
            _ => rv.put_encoding(),
        }
        .map(|(packed_id, schema)| EncodingHint {
            packed_id,
            schema: schema.map(str::to_string),
        });
        rows_cb.lock().unwrap().push(ReplyRow {
            key: rv.keyexpr().to_string(),
            kind,
            payload: rv.payload().to_vec(),
            encoding,
            timestamp: rv.timestamp().cloned(),
        });
    };
    let on_final = move |_rid: u64| {
        if let Some(tx) = tx.take() {
            let _ = tx.send(());
        }
    };

    // Consolidation mirrors zenoh's REST plugin: a time-range selector
    // (`_time=...`) disables consolidation (each historical sample is kept),
    // otherwise Latest.
    // Presence, not a prefix match: upstream asks `parameters.time_range().is_some()`
    // (lib.rs:437), and a valueless `_time` is a key with an empty value rather
    // than an absent key.
    let has_time = has_param(query, TIME_KEY);
    let consolidation = if has_time {
        ConsolidationMode::None
    } else {
        ConsolidationMode::Latest
    };
    let mut opts = QueryOptions::get()
        .with_timeout_ms(QUERY_TIMEOUT_MS)
        .with_consolidation(consolidation);
    if !query.is_empty() {
        opts = opts.with_parameters(query.as_bytes().to_vec());
    }
    // R311y501 — forward the request BODY as the query's VALUE, with its
    // Content-Type as the encoding. Upstream does exactly this
    // (`plugin-rest/src/lib.rs:448-453`: a non-empty body becomes
    // `.payload(body).encoding(content_type)`), and its absence here was a
    // named residual — a `GET`/`POST` carrying a body reached the queryable
    // stripped, so a value-driven queryable could not be addressed through wz's
    // bridge at all. An ABSENT Content-Type takes zenoh's `Encoding::default()`
    // (`zenoh/bytes`) — spelled out rather than routed through
    // `encoding_from_mime("")`, which does NOT yield that: an unknown MIME falls
    // to the custom-id arm and the empty string would become a custom encoding
    // carrying an empty schema.
    if !req.body.is_empty() {
        let encoding = match req.headers.get("content-type") {
            Some(ct) => encoding_from_mime(ct),
            None => EncodingHint::ZENOH_BYTES,
        };
        opts = opts.with_payload(req.body.clone()).with_encoding(encoding);
    }

    // `Session::query` returns an inert rid token (`ReplyHandle` is a `Copy`
    // u64 with no Drop) — nothing to hold. Replies + the terminal final are
    // delivered to the callbacks by the caller's drive loop; a query that
    // never receives a wire final is reaped at its query-timeout deadline by
    // serve's sweep task (Session::sweep_expired_queries), which also fires
    // `on_final` so the wait below completes.
    if session.query(&ke, opts, on_reply, on_final).is_err() {
        return Response::text(500, "Internal Server Error", "query failed");
    }

    // Wait for on_final, bounded a little past the query's own deadline so the
    // query timeout wins the race and terminates a silent-queryable GET.
    let _ = timeout(Duration::from_millis(QUERY_TIMEOUT_MS as u64 + 500), rx).await;

    let rows = rows.lock().unwrap();
    if raw {
        match rows.first() {
            // R311y501 — the Content-Type is the sample's encoding, exactly as
            // upstream's `to_raw_response` takes it (an absent hint is already
            // `zenoh/bytes` via `mime_or_default`, so the former
            // `application/octet-stream` empty-string fallback is unreachable
            // and gone rather than left as dead cover).
            Some(r) => Response::raw(r.encoding_mime(), r.payload.clone()),
            None => Response::empty(200, "OK"),
        }
    } else if wants_html(req.headers.get("accept")) {
        // R311y501 — the `Accept: text/html` rendering, a named residual
        // ("wz having zero text/html handling, where upstream renders a
        // definition list"). Upstream's shape, `to_html` / `sample_to_html`
        // (`plugin-rest/src/lib.rs:185-217`): one `<dt>key</dt>\n<dd>value</dd>`
        // per reply, joined by a newline, wrapped in `<dl>`.
        let mut items = Vec::with_capacity(rows.len());
        for r in rows.iter() {
            let key = if matches!(r.kind, ReplyKind::Err) {
                "ERROR"
            } else {
                r.key.as_str()
            };
            items.push(format!(
                "<dt>{}</dt>\n<dd>{}</dd>\n",
                html_escape(key),
                html_escape(&String::from_utf8_lossy(&r.payload))
            ));
        }
        Response::raw(
            "text/html".to_string(),
            format!("<dl>\n{}\n</dl>\n", items.join("\n")).into_bytes(),
        )
    } else {
        let mut items = Vec::with_capacity(rows.len());
        for r in rows.iter() {
            let key = if matches!(r.kind, ReplyKind::Err) {
                "ERROR"
            } else {
                r.key.as_str()
            };
            let value = json::payload_to_json(&r.payload, r.encoding_id());
            let timestamp = json::timestamp_json(r.timestamp.as_ref());
            items.push(json::sample_object(
                key,
                &value,
                &r.encoding_mime(),
                &timestamp,
            ));
        }
        Response::json(format!("[{}]", items.join(",")).into_bytes())
    }
}

fn handle_write(session: &TokioSession, zid: &[u8], req: &Request, is_delete: bool) -> Response {
    let (path, _query) = split_target(&req.target);
    let ke = match path_to_keyexpr(path, zid) {
        Ok(k) => k,
        Err(()) => return Response::text(400, "Bad Request", "invalid keyexpr"),
    };

    let result = if is_delete {
        session.publish(&ke, &[], PublishOptions::del())
    } else {
        // Content-Type -> encoding; an absent header uses the default encoding
        // (zenoh's `unwrap_or_default()`), NOT a forced octet-stream.
        let opts = match req.headers.get("content-type") {
            Some(ct) => PublishOptions::put().with_encoding(encoding_from_mime(ct)),
            None => PublishOptions::put(),
        };
        session.publish(&ke, &req.body, opts)
    };

    match result {
        Ok(_) => Response::empty(200, "OK"),
        Err(_) => Response::text(500, "Internal Server Error", "publish failed"),
    }
}

/// Split a request-target into `(path, query)` at the first `?`.
fn split_target(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    }
}

/// Map a URL path to a canonical keyexpr (zenoh `path_to_key_expr` parity).
/// Strips the leading `/`, resolves the `@/local` admin alias to `@/<zid-hex>`,
/// then canonicalises; an invalid keyexpr yields `Err(())` (-> `400`).
fn path_to_keyexpr(path: &str, zid: &[u8]) -> Result<String, ()> {
    let p = path.strip_prefix('/').unwrap_or(path);
    // `@/local` -> `@/<zid>` where <zid> is the SSOT zenoh zid rendering
    // (LE-bytes -> u128 -> BE hex, one leading zero stripped), the SAME form
    // the adminspace registers its `@/<zid>/<whatami>` root under
    // (`AdminLocalData::peer_zid_hex`); a naive per-byte hex would miss it.
    let raw = if p == "@/local" {
        format!("@/{}", zid_to_zenoh_hex(zid))
    } else if let Some(suffix) = p.strip_prefix("@/local/") {
        format!("@/{}/{}", zid_to_zenoh_hex(zid), suffix)
    } else {
        p.to_string()
    };
    match canonize_keyexpr(&raw) {
        Ok(canon) => Ok(canon.as_str().to_string()),
        Err(_) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream reads the FIRST media type of `Accept`, so preference ORDER
    /// decides — a `contains` test would call the second row HTML too.
    #[test]
    fn wants_html_reads_the_first_accepted_media_type() {
        assert!(wants_html(Some("text/html")));
        assert!(wants_html(Some("text/html, application/json")));
        assert!(wants_html(Some("text/html;charset=utf-8")));
        assert!(wants_html(Some(" text/html ")));
        // Order decides: HTML as a SECOND preference is not the chosen type.
        assert!(!wants_html(Some("application/json, text/html")));
        assert!(!wants_html(Some("application/json")));
        assert!(!wants_html(None));
    }

    /// wz ESCAPES where the reference interpolates raw — the documented,
    /// deliberate divergence. A payload that would inject script must not.
    #[test]
    fn html_escape_neutralises_injection() {
        assert_eq!(
            html_escape("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a & b \"q\""), "a &amp; b &quot;q&quot;");
        assert_eq!(html_escape("plain"), "plain");
    }

    #[test]
    fn split_target_splits_on_question() {
        assert_eq!(split_target("/a/b"), ("/a/b", ""));
        assert_eq!(split_target("/a/b?_raw"), ("/a/b", "_raw"));
        assert_eq!(split_target("/a?x=1&y=2"), ("/a", "x=1&y=2"));
    }

    #[test]
    fn path_to_keyexpr_strips_and_canonicalises() {
        assert_eq!(path_to_keyexpr("/demo/key", &[]).unwrap(), "demo/key");
        // Collapsing leading slash + a trailing slash is a non-canonical form
        // canonize_keyexpr rejects (empty chunk).
        assert!(path_to_keyexpr("/demo//key", &[]).is_err());
    }

    #[test]
    fn path_to_keyexpr_resolves_local_alias() {
        // @/local resolves via the SSOT zenoh zid rendering (LE -> u128 -> BE
        // hex, leading zero stripped): [0x01,0x02,0xab] -> u128 0xab0201 ->
        // "ab0201" (the form the adminspace registers under), NOT a naive
        // per-byte "0102ab".
        let zid = [0x01u8, 0x02, 0xab];
        assert_eq!(path_to_keyexpr("/@/local", &zid).unwrap(), "@/ab0201");
        assert_eq!(
            path_to_keyexpr("/@/local/status", &zid).unwrap(),
            "@/ab0201/status"
        );
    }
}
