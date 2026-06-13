// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311mo (Level B) — isolated multicast-only runtime tests for the tokio
//! profile's `Session` API.
//!
//! `wz-runtime-tokio`'s own `cargo test` cannot reach the multicast-only
//! `Session` API ([`Session::new_multicast`] / the multicast
//! `Session::publish`, both gated `not(transport-unicast)`): its
//! `wz-runtime-tokio-test-support` dev-dependency depends on `wz-runtime-tokio`
//! with `transport-unicast`, so `cargo test`'s feature unification forces
//! `transport-unicast` ON and the multicast-only items are `cfg`'d out. This
//! crate pulls `wz-runtime-tokio` with ONLY `transport-multicast,codec-push`
//! (no test-support, no unicast) as a dev-dependency, so — built ISOLATED via
//! `cargo test -p` (Layer C1s; excluded from the C1/C2 `--workspace`
//! unification, the same feature-leak hazard the wz-mcu-* crates carry) — the
//! multicast `Session` surface is reachable and runtime-testable.
//!
//! The library is intentionally empty; the proof lives in the test module.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wz_runtime_tokio::multicast_glue::MulticastTxItem;
    use wz_runtime_tokio::observer::ApplicationLayerObserver;
    use wz_runtime_tokio::runtime_impl::TokioTime;
    use wz_runtime_tokio::session::Session;

    /// A multicast `Session::publish` builds a `MulticastTxItem::Push` (Put)
    /// and enqueues exactly one onto the TX seam the drive loop drains — the
    /// multicast analogue of the unicast publish wire leg, proving the unified
    /// `Session` API reaches the multicast transport (the Level B north star).
    /// The drive-loop framing of that queued item is covered separately by
    /// `wz_runtime_tokio::multicast_glue`'s
    /// `drive_loop_frames_queued_push` test; this asserts the new B3 wiring —
    /// `publish` builds the right item and enqueues it onto the session's
    /// transport sender.
    #[test]
    fn multicast_session_publish_enqueues_one_put_push() {
        // The Session owns the sender; the drive loop would drain the receiver.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MulticastTxItem>();
        let session: Session = Session::new_multicast(
            Arc::new(wz_runtime_tokio::sync::Mutex::new(
                ApplicationLayerObserver::new(),
            )),
            Arc::new(TokioTime::new()),
            tx,
        );

        session
            .publish("demo/mc", b"hello-multicast")
            .expect("multicast Put builds within codec capacity");

        let item = rx.try_recv().expect("publish enqueued one tx item");
        assert!(
            matches!(item, MulticastTxItem::Push { .. }),
            "the enqueued multicast item is a Put Push"
        );
        assert!(
            rx.try_recv().is_err(),
            "publish enqueued exactly one item (no duplicate)"
        );
    }
}
