// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Minimal declare-observer facade-subset e2e consumer binary.
//!
//! Pins EXACTLY the `declare-observer` coherent facade subset (see this
//! crate's `Cargo.toml`) and OBSERVES a foreign zenoh-pico `z_sub`
//! client's proactive subscriber declaration: the acceptor opens the
//! session, registers a remote-subscriber-declared callback on the
//! shared observer, and waits; when z_sub (client mode) emits its
//! `Declare(DeclSubscriber)` the instant the session is Established, the
//! inbound frame routes through the shared harness's drive loop
//! (observer -> RemoteSubscriberRegistry -> on_subscriber_declared) and
//! fires this binary's callback.
//!
//! Direction is wz = OBSERVER (passive sink), zenoh-pico `z_sub` = active
//! DECLARER. This is the inbound-declare MIRROR of the outbound declare
//! planes (wz-e2e-pubsub publishes, wz-e2e-queryable answers): here wz
//! emits NOTHING on the wire — it only decodes the peer's declaration.
//! The remote-subscriber dispatch in wz-session-core
//! `declare/subscriber.rs` fires the callback unconditionally on any
//! inbound `DeclSubscriber` whose keyexpr resolves; it is NOT gated on a
//! prior outbound declare-interest (the asymmetry vs the
//! liveliness-subscriber plane, which DOES emit an Interest first). So
//! the setup closure registers the callback and returns — no outbound
//! traffic, no RAII handle to hold.
//!
//! Deliberately uses ONLY the remote-subscriber observer surface
//! (`session.observer()` + `RemoteSubscriberRegistry::
//! on_subscriber_declared`) so the source compiles under the pinned
//! subset with zero `#[cfg]`. The acceptor scaffolding (bind / accept /
//! open / drive / teardown) lives in [`wz_e2e_harness`]; this binary is
//! its CLI + the observer-registration setup closure.
//!
//! ## Why the witness is on the wz side
//!
//! Like wz-e2e-liveliness (wz=subscriber), the proof line is wz's own
//! callback log, not the foreign CLI's stdout. That sidesteps the
//! shared-tempfile-FD capture race the burst-and-exit foreign-CLI tests
//! (z_get) must design around: the integration test gates on this
//! binary's `REMOTE SUBSCRIBER DECLARED` stderr line, captured from a
//! single long-running process.

use std::process::ExitCode;

use wz_e2e_harness::{run_acceptor_e2e, run_main};

const BINARY: &str = "wz-e2e-declare-observer";

fn main() -> ExitCode {
    let Some(args) = CliArgs::parse(std::env::args().skip(1)) else {
        eprintln!("usage: wz-e2e-declare-observer --listen <ADDR> --observe <KEY>");
        return ExitCode::FAILURE;
    };
    let CliArgs {
        listen,
        observe_key,
    } = args;

    run_main(
        BINARY,
        run_acceptor_e2e(BINARY, listen, move |opened| {
            // Register one remote-subscriber-declared callback on the
            // SAME observer Arc the harness drive loop dispatches inbound
            // frames into (Session stores observer.clone(); the drive
            // loop fans every IterationEvent through it). A pure observer
            // emits nothing on the wire — it just waits for the peer's
            // proactive Declare(DeclSubscriber). The callback's `decl`
            // (the decoded record) and `resolved` (the keyexpr literal
            // resolved through the peer keyexpr table) types are inferred
            // from the registry signature, so no codec import is needed.
            //
            // The observer handle is a std::sync::Mutex on the tokio
            // profile (see Session::observer doc); lock().unwrap() is the
            // documented AP-profile registration pattern.
            let observe_for_callback = observe_key.clone();
            opened
                .session
                .observer()
                .lock()
                .expect("observer mutex poisoned")
                .remote_subscribers
                .on_subscriber_declared(move |decl, resolved| {
                    log::info!(
                        "{BINARY}: REMOTE SUBSCRIBER DECLARED observe='{}' \
                         keyexpr='{}' sub_id={}",
                        observe_for_callback,
                        resolved,
                        decl.id,
                    );
                });
            // No RAII handle / wire-emitting Drop: a pure observer holds
            // nothing across the drive loop. The unit hold is dropped
            // first at teardown (a no-op) exactly like a declare handle.
            Ok::<_, std::io::Error>(())
        }),
    )
}

/// Parsed `--listen / --observe` pair. Both are mandatory; this binary
/// has exactly one mode. `--observe` is logged for witness legibility
/// (the binary observes whatever the peer declares regardless of this
/// value — a remote-subscriber observer does not filter by keyexpr).
struct CliArgs {
    listen: String,
    observe_key: String,
}

impl CliArgs {
    fn parse(mut args: impl Iterator<Item = String>) -> Option<Self> {
        let mut listen = None;
        let mut observe_key = None;
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--listen" => listen = args.next(),
                "--observe" => observe_key = args.next(),
                _ => return None,
            }
        }
        Some(Self {
            listen: listen?,
            observe_key: observe_key?,
        })
    }
}
