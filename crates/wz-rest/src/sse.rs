// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Server-Sent Events streaming (feature `rest-sse-subscribe`) — the SSE half
//! of the REST bridge, the compile-time-composed mirror of zenoh's REST plugin
//! `text/event-stream` path (`plugins/zenoh-plugin-rest/src/lib.rs:373`).
//!
//! A `GET` with `Accept: text/event-stream` becomes a `declare_subscriber` on
//! the request keyexpr; each received sample is streamed to the HTTP client as
//! an SSE event (`event: <PUT|DELETE>\ndata: <json-sample>\n\n`) until the
//! client disconnects, at which point the [`Subscriber`] handle drops and
//! undeclares. The subscriber callback fires on the session drive loop and
//! hands each sample to this task through a BOUNDED channel ([`CHANNEL_CAP`]
//! — R311y501 corrects this line, which said "unbounded" and contradicted the
//! code it documents ever since the bound was added); a periodic SSE
//! comment (`:\n\n`) keeps an idle stream alive AND detects a vanished client
//! (the write errors) so the subscriber is torn down promptly.
//!
//! [`Subscriber`]: wz_runtime_tokio::session::TokioSession::declare_subscriber

use std::io;

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::{interval, timeout, Duration};

use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::session::{SubscribeOptions, TokioSession};
use wz_session_core::sample::TimestampHint;
use wz_session_core::sink::SampleView;

use crate::http::Response;
use crate::{json, WRITE_TIMEOUT};

/// Idle keepalive cadence — an SSE comment written on this interval both keeps
/// intermediaries from closing an idle stream and probes for a vanished client.
const KEEPALIVE: Duration = Duration::from_secs(15);

/// Bound on the buffered-sample queue between the subscriber callback (which
/// runs on the drive loop and is never back-pressured) and the socket-writing
/// task. A slow-but-progressing consumer would grow an UNBOUNDED channel
/// without limit (its per-write timeout never fires); a bounded channel caps
/// the server memory a slow reader can pin. On overflow the newest sample is
/// dropped — SSE is best-effort (a reconnecting `EventSource` has no replay
/// anyway).
const CHANNEL_CAP: usize = 1024;

/// The SSE response head: `200`, `text/event-stream`, no `Content-Length` (the
/// body is open-ended, delimited by connection close), CORS.
const SSE_HEADERS: &[u8] = b"HTTP/1.1 200 OK\r\n\
Content-Type: text/event-stream\r\n\
Cache-Control: no-cache\r\n\
Access-Control-Allow-Origin: *\r\n\
Connection: close\r\n\r\n";

/// One received sample, copied out of the borrowed `&dyn SampleView` inside the
/// subscriber callback (the view does not outlive the call).
struct SseSample {
    kind: SampleKind,
    key: String,
    payload: Vec<u8>,
    encoding: String,
    /// The decoded encoding as `(id, has_schema)` — what selects zenoh's
    /// `value` rendering branch. Carried ALONGSIDE the MIME string rather than
    /// re-derived from it: `encoding_to_mime` is lossy for the base-vs-schema
    /// split (`"application/json;charset=utf-8"` and a custom-id encoding whose
    /// whole MIME is the schema both render as one string), and that split is
    /// exactly what decides embed-vs-base64.
    encoding_id: Option<(u16, bool)>,
    /// Inline body timestamp, if the sample carried one.
    timestamp: Option<TimestampHint>,
}

/// Stream `declare_subscriber(keyexpr)` samples to `wr` as SSE events until the
/// client disconnects. The subscriber is undeclared when this returns.
pub async fn stream<W: AsyncWriteExt + Unpin>(session: &TokioSession, keyexpr: String, wr: &mut W) {
    let (tx, mut rx) = mpsc::channel::<SseSample>(CHANNEL_CAP);
    let _subscriber = match session.declare_subscriber(
        keyexpr,
        SubscribeOptions::default(),
        move |sample: &dyn SampleView| {
            let encoding = json::mime_or_default(sample.encoding());
            let encoding_id = sample.encoding().map(|e| (e.id(), e.schema.is_some()));
            let timestamp = sample.timestamp().cloned();
            // Non-blocking bounded send: a full queue (slow client) or a closed
            // receiver (client gone, this task returned) drops the sample — the
            // callback runs on the drive loop and must not block it, and SSE is
            // best-effort. The subscriber teardown follows on the closed case.
            let _ = tx.try_send(SseSample {
                kind: sample.kind(),
                key: sample.keyexpr().to_string(),
                payload: sample.payload().to_vec(),
                encoding,
                encoding_id,
                timestamp,
            });
        },
    ) {
        Ok(subscriber) => subscriber,
        Err(_) => {
            let bytes = Response::text(500, "Internal Server Error", "subscribe failed").encode();
            let _ = wr.write_all(&bytes).await;
            return;
        }
    };

    // Open the event stream; if the client is already gone, drop (undeclare).
    if write_all_timed(wr, SSE_HEADERS).await.is_err() {
        return;
    }

    let mut keepalive = interval(KEEPALIVE);
    keepalive.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            received = rx.recv() => match received {
                Some(sample) => {
                    if write_all_timed(wr, format_event(&sample).as_bytes())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                // The sender cannot drop while `_subscriber` is held; treat a
                // closed channel as a clean end.
                None => break,
            },
            _ = keepalive.tick() => {
                // SSE comment keepalive — doubles as the disconnect probe.
                if write_all_timed(wr, b":\n\n").await.is_err() {
                    break;
                }
            }
        }
    }
    // `_subscriber` drops here -> UndeclareSubscriber on the wire.
}

/// Format one sample as an SSE event: `event: <PUT|DELETE>\ndata: <json>\n\n`
/// (the `data` is one `JSONSample` object, mirroring zenoh's per-sample SSE
/// payload). The compact JSON is single-line, so one `data:` line suffices.
fn format_event(sample: &SseSample) -> String {
    let name = match sample.kind {
        SampleKind::Put => "PUT",
        SampleKind::Del => "DELETE",
    };
    let value = json::payload_to_json(&sample.payload, sample.encoding_id);
    let timestamp = json::timestamp_json(sample.timestamp.as_ref());
    let object = json::sample_object(&sample.key, &value, &sample.encoding, &timestamp);
    format!("event: {name}\ndata: {object}\n\n")
}

/// Write all bytes under [`WRITE_TIMEOUT`] + flush; a timeout or socket error
/// (client gone) is surfaced as `Err` so the stream loop tears the subscriber
/// down.
async fn write_all_timed<W: AsyncWriteExt + Unpin>(wr: &mut W, bytes: &[u8]) -> io::Result<()> {
    match timeout(WRITE_TIMEOUT, async {
        wr.write_all(bytes).await?;
        wr.flush().await
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "sse write timeout")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_event_shape() {
        let sample = SseSample {
            kind: SampleKind::Put,
            key: "demo/k".to_string(),
            payload: b"v".to_vec(),
            encoding: "text/plain".to_string(),
            encoding_id: Some((4, false)),
            timestamp: None,
        };
        assert_eq!(
            format_event(&sample),
            "event: PUT\ndata: {\"key\":\"demo/k\",\"value\":\"v\",\"encoding\":\"text/plain\",\"timestamp\":null}\n\n"
        );
    }

    #[test]
    fn format_event_delete_empty_payload_is_null() {
        let sample = SseSample {
            kind: SampleKind::Del,
            key: "demo/k".to_string(),
            payload: Vec::new(),
            // An unencoded sample renders zenoh's default, NOT the empty
            // string — measured against a real zenohd DELETE event.
            encoding: json::mime_or_default(None),
            encoding_id: None,
            timestamp: None,
        };
        assert_eq!(
            format_event(&sample),
            "event: DELETE\ndata: {\"key\":\"demo/k\",\"value\":null,\"encoding\":\"zenoh/bytes\",\"timestamp\":null}\n\n"
        );
    }

    /// A stamped JSON sample renders BOTH the embedded value and the zenoh
    /// `<ntp64>/<zid-hex>` timestamp — and the event stays ONE `data:` line
    /// even though the source payload was pretty-printed across newlines.
    #[test]
    fn format_event_embeds_json_and_stamps() {
        let sample = SseSample {
            kind: SampleKind::Put,
            key: "demo/k".to_string(),
            payload: b"{\n  \"a\": 1\n}".to_vec(),
            encoding: "application/json".to_string(),
            encoding_id: Some((5, false)),
            timestamp: Some(TimestampHint {
                time: 42,
                zid: vec![0x1a, 0x2b, 0x3c],
            }),
        };
        let event = format_event(&sample);
        assert_eq!(
            event,
            "event: PUT\ndata: {\"key\":\"demo/k\",\"value\":{\"a\":1},\"encoding\":\"application/json\",\"timestamp\":\"42/3c2b1a\"}\n\n"
        );
        // Exactly two newlines beyond the event/data split: the SSE terminator.
        assert_eq!(event.matches('\n').count(), 3);
    }
}
