// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Minimal z_get-initiator facade-subset e2e consumer binary.
//!
//! Pins EXACTLY the z_get-initiator ("zget-reply-only") coherent facade
//! subset (see this crate's `Cargo.toml`) and ISSUES a query that a
//! foreign zenoh-pico `z_queryable` answers: the acceptor opens the
//! session, then emits one or more `Session::query` GETs; the inbound
//! Response(Reply) + terminating ResponseFinal route through the shared
//! harness's drive loop (observer -> ReplyRegistry -> on_reply /
//! on_final) and fire this binary's reply / final callbacks.
//!
//! Direction is wz = REQUESTER (the getter consumes the reply chain) —
//! the exact MIRROR of wz-e2e-queryable, where wz is the answerer that
//! produces the reply chain. Together the two binaries cover the
//! query/reply plane in BOTH wire directions against a foreign peer.
//! Deliberately uses ONLY the getter surface (`Session::query` +
//! `InboundReply`) so the source compiles under the pinned subset with
//! zero `#[cfg]`. The acceptor scaffolding (bind / accept / open / drive
//! / teardown) lives in [`wz_e2e_harness`]; this binary is its CLI + the
//! query-burst setup closure.
//!
//! ## R311fm composability finding (see Cargo.toml)
//!
//! This binary surfaced a feature-graph coupling bug: the named
//! "zget-reply-only" BUILD subset (codec-response, codec-response-final,
//! query-get, query-reply) type-checked but DECODED NO reply, because
//! the inbound `Response(Reply)` Put-body arm in wz-session-core
//! `reply.rs` was gated only on the pub/sub publisher marker
//! `pubsub-put`. A pure getter has no reason to pin a publisher feature,
//! so the arm collapsed to `_ => return` and every reply was silently
//! dropped (on_final still fired from the separate codec-response-final
//! path). R311fm splits the gate so `query-reply` enables its own
//! reply-body decode — the getter plane is now independently composable
//! and this binary pins the build subset verbatim with no pubsub feature.
//!
//! ## Why a burst rather than a single GET
//!
//! The harness runs this setup the instant the session is Established.
//! A foreign `z_queryable` that DIALED in has completed the handshake by
//! then but may not have registered its local queryable yet, and the
//! zget-reply-only subset carries NO declare observer (it does not learn
//! when the peer's queryable appears). So the first GET can race the
//! peer's declare and reach a queryable-less peer that silently drops
//! it. A small spaced burst — stopped on the first reply via a shared
//! flag — makes the round-trip robust without a declare observer, the
//! same robustness rationale as wz-e2e-pubsub's publish burst.

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use wz::runtime_core::TimeSource;
use wz::runtime_tokio::reply::InboundReplyBody;
use wz::runtime_tokio::session::QueryOptions;
use wz_e2e_harness::{run_acceptor_e2e, run_main, AbortOnDrop};

const BINARY: &str = "wz-e2e-zget";

/// Upper bound on GETs emitted; the burst loop breaks early on the first
/// reply (the shared `got_reply` flag), so this only caps the
/// peer-not-ready-yet retry window.
const QUERY_BURST: usize = 16;
/// Spacing between burst GETs; gives the foreign queryable time to
/// register between retries while keeping the whole window well inside
/// the integration test's reply-wait.
const BURST_INTERVAL_MS: u64 = 150;

fn main() -> ExitCode {
    let Some(args) = CliArgs::parse(std::env::args().skip(1)) else {
        eprintln!("usage: wz-e2e-zget --listen <ADDR> --query <KEY>");
        return ExitCode::FAILURE;
    };
    let CliArgs { listen, query_key } = args;

    run_main(
        BINARY,
        run_acceptor_e2e(BINARY, listen, move |opened| {
            // Emit the GET burst. A pure getter registers no reactive
            // queryable; each GET registers a pending-reply entry whose
            // on_reply / on_final callbacks fire from the harness's drive
            // loop when the inbound Reply / Final arrives. The burst runs
            // as a background task returned wrapped in AbortOnDrop so the
            // harness stops it at teardown. Session + clock are
            // cloned/copied into the task (the harness keeps its own
            // clones alive across the loop).
            let session = opened.session.clone();
            let clock = opened.clock;
            let got_reply = Arc::new(AtomicBool::new(false));
            let got_reply_task = got_reply.clone();
            let getter = tokio::spawn(async move {
                for idx in 0..QUERY_BURST {
                    if got_reply_task.load(Ordering::SeqCst) {
                        break;
                    }
                    let got_reply_cb = got_reply_task.clone();
                    let query_result = session.query(
                        &query_key,
                        QueryOptions::get(),
                        move |reply| {
                            got_reply_cb.store(true, Ordering::SeqCst);
                            // Mirror wz-ap-demo's REPLY RECEIVED line so the
                            // e2e test can assert the resolved keyexpr literal
                            // + the responder's payload both surfaced through
                            // the wire dispatch (Response -> ReplyRegistry ->
                            // on_reply) under the zget-reply-only subset.
                            let body_text = match &reply.body {
                                InboundReplyBody::Put { payload } => {
                                    format!("Put payload={:?}", String::from_utf8_lossy(payload))
                                }
                                InboundReplyBody::Del => "Del".to_string(),
                                InboundReplyBody::Err { encoding, payload } => format!(
                                    "Err encoding={encoding:?} payload={:?}",
                                    String::from_utf8_lossy(payload)
                                ),
                            };
                            log::info!(
                                "{BINARY}: ZGET REPLY RECEIVED rid={} keyexpr='{}' body={}",
                                reply.rid,
                                reply.keyexpr_literal,
                                body_text
                            );
                        },
                        move |rid| {
                            log::info!("{BINARY}: ZGET FINAL RECEIVED rid={rid}");
                        },
                    );
                    match query_result {
                        Ok(_handle) => {
                            log::info!("{BINARY}: GET ISSUED idx={idx} keyexpr='{query_key}'")
                        }
                        Err(e) => {
                            log::error!("{BINARY}: query failed: {e:?}");
                            break;
                        }
                    }
                    clock.sleep(BURST_INTERVAL_MS).await;
                }
            });
            Ok::<_, std::io::Error>(AbortOnDrop(getter))
        }),
    )
}

/// Parsed `--listen / --query` pair. Both are mandatory; this binary has
/// exactly one mode.
struct CliArgs {
    listen: String,
    query_key: String,
}

impl CliArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Option<Self> {
        let mut listen = None;
        let mut query_key = None;
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--listen" => listen = args.next(),
                "--query" => query_key = args.next(),
                _ => return None,
            }
        }
        Some(Self {
            listen: listen?,
            query_key: query_key?,
        })
    }
}
