// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! # wz-rest — the §5.26 REST -> zenoh bridge (`rest-http-bridge`)
//!
//! A light, HAND-ROLLED HTTP/1.1 server (ZERO external HTTP dependency) that
//! bridges HTTP clients to a wz [`TokioSession`]:
//!
//! | HTTP                         | wz Session op                         |
//! |------------------------------|---------------------------------------|
//! | `GET`/`POST` `/key/expr`     | [`query`] -> JSON reply array         |
//! | `GET .. ?_raw`               | [`query`] -> first reply, raw bytes   |
//! | `PUT`/`PATCH` `/key` + body  | [`publish`] Put (Content-Type -> enc) |
//! | `DELETE` `/key`              | [`publish`] Del                       |
//!
//! It is the compile-time-composed superset of zenoh's `zenoh-plugin-rest`
//! (which is a dlopen `.so` plugin over `tide`): no plugin host-trait, ABI
//! gate, or lifecycle FSM — the whole bridge is gated behind the
//! `rest-http-bridge` cargo feature and, being std/AP-only, lives in its own
//! crate so no_std/MCU builds never pull it.
//!
//! ## SECURITY — read before deploying
//!
//! **A loopback bind is a network-exposure boundary, NOT authentication.**
//! [`serve`] performs NO authentication and NO access control; it exposes the
//! whole keyspace to whoever can reach the socket. Even bound to `127.0.0.1`:
//!
//! - **Any local process** (on a shared / multi-user host, that includes other
//!   users — loopback is not per-user isolated) can read, put, and delete the
//!   entire keyspace without credentials.
//! - Responses carry `Access-Control-Allow-Origin: *` and the `Host` header is
//!   not validated, so **any web page the user visits** can issue `GET`/`POST`
//!   (query) requests to `127.0.0.1:<port>` cross-origin and read the JSON
//!   response body — keyspace exfiltration with no DNS-rebinding needed.
//! - The SSE stream (feature `rest-sse-subscribe`) amplifies that into a
//!   PERSISTENT live tap: an `EventSource` from any origin keeps receiving the
//!   keyspace in real time for as long as the tab stays open, not just a
//!   one-shot snapshot. [`serve`] also imposes no cap on concurrent
//!   connections/subscribers, so long-lived streams accumulate server
//!   resources.
//!
//! Run this only as a local development / debugging convenience, on a trusted
//! single-user host, where the keyspace is not treated as confidential. For a
//! network-exposed or access-controlled deployment, front it with a reverse
//! proxy that adds TLS + authentication, or do not use it.
//!
//! ## Deployment invariant
//!
//! [`serve`] drives [`query`]/[`publish`] on a *clone* of the caller's
//! [`TokioSession`]; wire replies to a `GET` are delivered only while the
//! caller's session drive loop AND its deadline-sweep task run concurrently
//! over the SAME session. Spawn `serve` alongside them (see the crate's
//! integration test for the canonical wiring). A `GET` whose queryable answers
//! remotely relies on `query-timeout` (bounded by [`QUERY_TIMEOUT_MS`]) to
//! terminate; a co-located queryable answers synchronously via loopback.
//!
//! [`query`]: wz_runtime_tokio::session::TokioSession::query
//! [`publish`]: wz_runtime_tokio::session::TokioSession::publish
//! [`TokioSession`]: wz_runtime_tokio::session::TokioSession

use std::io;
use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Duration};

use wz_runtime_tokio::runtime_pool::WzRuntime;
use wz_runtime_tokio::session::TokioSession;

mod bridge;
mod http;
mod json;
#[cfg(feature = "rest-sse-subscribe")]
mod sse;

/// Default GET query timeout (ms). A `GET` whose queryable never answers is
/// bounded to this so the HTTP connection cannot hang forever; the HTTP-side
/// wait is a little longer so the query's own `on_final` wins the race.
pub const QUERY_TIMEOUT_MS: u32 = 10_000;

/// Per-connection read timeout. A client that opens a connection and stalls
/// (never completing the request head or body) is dropped after this, so a
/// slow/broken/hostile local client cannot pin a task + fd forever.
const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Write timeout for the response (best-effort; a wedged client must not pin
/// the handler task on the write side either).
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// How often [`serve_on`]'s sweep task reaps expired pending queries. Well
/// under [`QUERY_TIMEOUT_MS`] so a timed-out `GET` is reaped (and its `on_final`
/// fired) within roughly this margin of its deadline.
const SWEEP_CADENCE: Duration = Duration::from_secs(1);

/// Aborts a spawned task on drop — used so [`serve_on`]'s background sweep task
/// stops when the accept loop returns.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serve the REST bridge on `addr`, bridging every accepted HTTP connection to
/// `session`. Runs until the listener errors (e.g. cancelled by dropping the
/// future). `zid` is the node's own routing zid, used only to resolve the
/// `@/local` admin alias to `@/<zid-hex>` (zenoh `path_to_key_expr` parity);
/// pass the same bytes handed to `Session::set_own_zid`.
///
/// SECURITY: see the crate-level docs. Prefer a `127.0.0.1` `addr`; binding a
/// routable interface exposes an unauthenticated keyspace gateway.
pub async fn serve(session: TokioSession, zid: Vec<u8>, addr: SocketAddr) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_on(listener, session, zid).await
}

/// Like [`serve`], but drives an already-bound listener. Useful when the caller
/// needs the concrete bound address first (e.g. a test binding `127.0.0.1:0`
/// and reading [`TcpListener::local_addr`] before serving).
pub async fn serve_on(
    listener: TcpListener,
    session: TokioSession,
    zid: Vec<u8>,
) -> io::Result<()> {
    // Reap expired pending queries so a GET whose wire ResponseFinal never
    // arrives cannot leak its pending entry (the session drive loop no longer
    // ticks the reply sweep). Safe alongside any caller-side sweep (idempotent).
    // Aborted when this accept loop returns.
    let sweep_session = session.clone();
    // APPLICATION — a periodic sweep over retained query state, zenoh's own
    // classification for that shape (`ZRuntime::Application.spawn(gc_task(..))`,
    // `zenoh-ext/src/advanced_subscriber.rs`
    // @ `ZRuntime::Application.spawn(gc_task(`). Upstream's REST plugin names
    // no subsystem at all — it reaches for a plugin-local runtime instead
    // (`plugins/zenoh-plugin-rest/src/lib.rs`
    // @ `fn spawn_runtime<F>(task: F)`) — so there is no upstream
    // choice here to be faithful to, only wz's own tiers to place it in.
    let _sweep = AbortOnDrop(WzRuntime::Application.spawn(async move {
        loop {
            sleep(SWEEP_CADENCE).await;
            sweep_session.sweep_expired_queries();
        }
    }));

    loop {
        let (stream, _peer) = listener.accept().await?;
        let session = session.clone();
        let zid = zid.clone();
        // ACCEPTOR — this is the per-connection child of an accept loop, and an
        // accept loop is what zenoh puts on that subsystem
        // (`io/zenoh-link-commons/src/listener.rs`
        // @ `ZRuntime::Acceptor.spawn(task)`).
        WzRuntime::Acceptor.spawn(async move {
            handle_connection(session, zid, stream).await;
        });
    }
}

/// Handle one accepted connection: read+parse one request under a timeout,
/// dispatch it, write one response, close (no keep-alive — `Connection: close`).
async fn handle_connection(session: TokioSession, zid: Vec<u8>, mut stream: TcpStream) {
    let (mut rd, mut wr) = stream.split();

    let outcome = match timeout(READ_TIMEOUT, http::read_request(&mut rd)).await {
        // Timed out waiting for a complete request head/body.
        Err(_) => bridge::Outcome::Response(http::Response::text(
            408,
            "Request Timeout",
            "request read timed out",
        )),
        // Clean connection close before any request — nothing to answer.
        Ok(Err(http::ParseError::Empty)) => return,
        // Malformed request -> the mapped HTTP status.
        Ok(Err(http::ParseError::Status(code, reason))) => {
            bridge::Outcome::Response(http::Response::text(code, reason, reason))
        }
        // A well-formed request -> dispatch to the bridge.
        Ok(Ok(request)) => bridge::dispatch(&session, &zid, request).await,
    };

    match outcome {
        bridge::Outcome::Response(response) => {
            let bytes = response.encode();
            let _ = timeout(WRITE_TIMEOUT, async {
                let _ = wr.write_all(&bytes).await;
                let _ = wr.flush().await;
            })
            .await;
        }
        // An SSE stream takes over the connection: declare the subscriber and
        // stream its samples until the client disconnects (then undeclare).
        #[cfg(feature = "rest-sse-subscribe")]
        bridge::Outcome::Sse(keyexpr) => {
            sse::stream(&session, keyexpr, &mut wr).await;
        }
    }
}
