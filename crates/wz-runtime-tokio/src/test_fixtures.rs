// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Crate-local fixtures for `wz-runtime-tokio`'s OWN unit tests.
//!
//! These live INSIDE the crate (compiled under `#[cfg(test)]`) rather
//! than in the `wz-runtime-tokio-test-support` sibling on purpose. The
//! sibling depends on `wz-runtime-tokio`, so a unit test that sourced
//! its `SessionLinkActions` / `RecordingLinkDriver` from the sibling
//! would receive the dev-dependency cycle's SECOND `wz-runtime-tokio`
//! copy — a distinct type that cannot be handed to the crate-local
//! `Session::new` and exposes no `pub(crate)` / private API here (see
//! the `feedback-test-support-dev-dep-cycle` note). Built locally,
//! these produce the same crate version the unit tests compile against,
//! so `build_session`, the `reconstruct_outbound_keyexpr` shape table,
//! and the wire-byte send guards all converge onto ONE fixture with no
//! per-test exceptions.
//!
//! `fixture_session_init_params` deliberately stays in the sibling: the
//! integration tests (`tests/*.rs`) consume it, and it returns a
//! `wz-session-core` type (`SessionInitParams`) that is SHARED across
//! both `wz-runtime-tokio` copies in the graph — so importing it across
//! the boundary here is sound (unlike a `wz-runtime-tokio`-defined type
//! such as `SessionLinkActions`). The recording driver + actions
//! builders are the ONLY surface that must be crate-local.

use std::sync::{Arc, Mutex};

use wz_runtime_tokio_test_support::fixture_session_init_params;

use crate::observer::ApplicationLayerObserver;
use crate::runtime_impl::TokioTime;
use crate::session_glue::{
    new_session_actions, BoxedLinkDriver, SessionInitParams, SessionLinkActions,
};
use crate::Reliability;

/// Test [`BoxedLinkDriver`] that records every outbound frame so a
/// behavioural guard can assert the emitted wire bytes / reliability
/// channel, or the *no-emit* half of a typed-reject contract
/// (`frame_count() == 0` — "no wire bytes leave on Err").
pub(crate) struct RecordingLinkDriver {
    frames: Mutex<Vec<(Vec<u8>, Reliability)>>,
}

impl RecordingLinkDriver {
    /// Number of frames observed via `send_blocking` so far.
    pub(crate) fn frame_count(&self) -> usize {
        self.frames
            .lock()
            .expect("recording driver mutex poisoned")
            .len()
    }

    /// Wire bytes of the `idx`-th recorded frame (panics if absent), so
    /// a wire-byte assertion can compare against an independently encoded
    /// expectation without reaching into the driver's private storage.
    pub(crate) fn frame_bytes(&self, idx: usize) -> Vec<u8> {
        self.frames.lock().expect("recording driver mutex poisoned")[idx]
            .0
            .clone()
    }

    /// Reliability channel the `idx`-th recorded frame was emitted on
    /// (panics if absent) — pins the action layer's reliable/best-effort
    /// channel pick (e.g. Close + Reply are reliable-only).
    pub(crate) fn frame_reliability(&self, idx: usize) -> Reliability {
        self.frames.lock().expect("recording driver mutex poisoned")[idx].1
    }

    /// Discard all recorded frames — lets a test ignore set-up emits (e.g. a
    /// register-time bootstrap flood) so a later `frame_count()` counts only
    /// the frames the operation under test produced. Gated like its sole
    /// consumer (`linkstate_forward`'s tests) so the no-`routing-peer`
    /// deny-warnings lane does not see it as dead code.
    #[cfg(feature = "routing-peer")]
    pub(crate) fn reset(&self) {
        self.frames
            .lock()
            .expect("recording driver mutex poisoned")
            .clear();
    }
}

impl BoxedLinkDriver for RecordingLinkDriver {
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) {
        self.frames
            .lock()
            .expect("recording driver mutex poisoned")
            .push((bytes.to_vec(), reliability));
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

/// Build a [`SessionLinkActions`] backed by a fresh [`RecordingLinkDriver`]
/// and the deterministic [`fixture_session_init_params`]. Returns both
/// handles so a caller can drive a signature-stable emit method and then
/// assert on the emitted frames (count / bytes / reliability).
pub(crate) fn recording_actions() -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
    recording_actions_with_params(fixture_session_init_params())
}

/// [`recording_actions`] variant that accepts caller-supplied
/// [`SessionInitParams`]. Use when a wire-byte assertion depends on a
/// specific field — typically `initial_sn`, which seeds
/// `next_outbound_frame_sn` and therefore the SN byte of every emitted
/// Frame. Build the params from [`fixture_session_init_params`] and
/// override only the asserted field so the rest stays on the SSOT.
pub(crate) fn recording_actions_with_params(
    params: SessionInitParams,
) -> (Arc<SessionLinkActions>, Arc<RecordingLinkDriver>) {
    let driver = recording_driver();
    let actions = new_session_actions(driver.clone(), params, TokioTime::new());
    (actions, driver)
}

/// A4 — a bare [`RecordingLinkDriver`] handle, for tests that wire the
/// recorder BEHIND another [`BoxedLinkDriver`] layer (the `SwappableLink`
/// transport-replacement seam) instead of using it as the actions driver
/// directly.
pub(crate) fn recording_driver() -> Arc<RecordingLinkDriver> {
    Arc::new(RecordingLinkDriver {
        frames: Mutex::new(Vec::new()),
    })
}

/// R2290 (open-debt item 626) — a link driver that answers ONE question per
/// emitted frame: was the session's observer mutex LOCKABLE at the instant
/// those bytes left?
///
/// A handle's teardown emits its wire retraction and then retires its local
/// registry entry. Between those two the registry still holds an entity the
/// peer has already been told is gone, and the drive thread's
/// `drain_declare_replies` reads exactly those registries — under this same
/// mutex — to answer a peer's Interest. So the pair has to be ONE transition,
/// and "the retract was emitted while this thread held the observer mutex" is
/// the property that says so. A same-thread `try_lock` on a `std::sync::Mutex`
/// reports `WouldBlock`, which is what makes `false` here mean "held" rather
/// than "contended".
///
/// Deliberately a link driver rather than a probe wired into one handle: the
/// retract reaches the wire the same way on every plane (subscriber, token,
/// queryable), so ONE probe covers the population instead of one per handle.
pub(crate) struct ObserverProbeLinkDriver {
    /// The observer to probe, installed AFTER the session exists (a driver is
    /// built before the session it belongs to). `None` = not yet armed, and an
    /// unarmed frame records nothing, which is how set-up emits are kept out
    /// of the population.
    armed: Mutex<Option<Arc<Mutex<ApplicationLayerObserver>>>>,
    /// One entry per frame emitted while armed: `true` = the observer mutex
    /// was free, i.e. the emit was NOT inside the acquisition.
    lockable: Mutex<Vec<bool>>,
}

impl ObserverProbeLinkDriver {
    /// Start probing against `observer`. Call after the set-up emits so the
    /// recorded population is exactly the frames under test.
    pub(crate) fn arm(&self, observer: Arc<Mutex<ApplicationLayerObserver>>) {
        *self.armed.lock().expect("probe arm mutex poisoned") = Some(observer);
    }

    /// One flag per frame emitted since [`Self::arm`], in emit order.
    pub(crate) fn lockable_flags(&self) -> Vec<bool> {
        self.lockable
            .lock()
            .expect("probe log mutex poisoned")
            .clone()
    }
}

impl BoxedLinkDriver for ObserverProbeLinkDriver {
    fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) {
        let armed = self.armed.lock().expect("probe arm mutex poisoned");
        if let Some(observer) = armed.as_ref() {
            // `try_lock`'s guard is dropped at the end of this statement, so
            // the probe never holds the observer past the measurement.
            let lockable = observer.try_lock().is_ok();
            self.lockable
                .lock()
                .expect("probe log mutex poisoned")
                .push(lockable);
        }
    }
    fn open_blocking(&self) {}
    fn close_blocking(&self) {}
}

/// [`recording_actions`] twin backed by an [`ObserverProbeLinkDriver`].
pub(crate) fn probing_actions() -> (Arc<SessionLinkActions>, Arc<ObserverProbeLinkDriver>) {
    let driver = Arc::new(ObserverProbeLinkDriver {
        armed: Mutex::new(None),
        lockable: Mutex::new(Vec::new()),
    });
    let actions = new_session_actions(
        driver.clone(),
        fixture_session_init_params(),
        TokioTime::new(),
    );
    (actions, driver)
}

/// A4 — [`recording_actions`] variant that accepts the caller's driver
/// (e.g. a `SwappableLink` wrapping a [`RecordingLinkDriver`]) so a test
/// can interpose on the link seam while keeping the deterministic
/// [`fixture_session_init_params`]. Gated like its sole consumer
/// (`session_glue::reconnect_tx_tests`) so the C1j deny-warnings subset
/// lane (no `session-reconnect`) does not see it as dead code.
#[cfg(feature = "session-reconnect")]
pub(crate) fn recording_actions_with_driver(
    driver: Arc<dyn BoxedLinkDriver + Send + Sync>,
) -> Arc<SessionLinkActions> {
    new_session_actions(driver, fixture_session_init_params(), TokioTime::new())
}

/// R311y767 (carry N71) — refuse a forwarder that puts an ALIAS OF ITS OWN on a
/// face, by reading the bytes that face actually received.
///
/// ## The premise this binds
///
/// Every forwarder in this tree resolves an inbound keyexpr against the SOURCE
/// FACE's alias table alone, with no own-id space on the other side of the `M`
/// bit. R311y739 gave the four INBOUND planes the pair (pubsub, reply,
/// switchboard, liveliness all take `impl Into<MappingSpaces>`) and left the
/// forwarders peer-only. The consequence is a silent one: an `M=0` alias, one
/// naming an id the FORWARDER declared, resolves against nothing and is dropped
/// indistinguishably from a peer naming an id it never declared. That is correct
/// exactly while the forwarder declares no alias of its own — a premise, not an
/// oversight, and R311y766 turned it into a test for the switchboard kernel.
/// This is that test's shared form, so the two remaining forwarders do not each
/// grow their own copy of the classification.
///
/// ## Why it reuses `resolve_governed_keyexpr` instead of matching records
///
/// A hand-written match over `NetworkMessage` would have to know that
/// `DeclareSubscriber` / `Queryable` / `Token` carry the keyexpr INLINE while the
/// three undeclares carry it in an optional `ext_wire_expr` extension — and it
/// would silently miss an alias hiding in that extension the first time it got
/// the split wrong. `resolve_governed_keyexpr` is already this tree's SSOT for
/// exactly that question, documented as a one-place edit when a new governed kind
/// appears, so a new kind reaches this guard for free.
///
/// ## The classification, which is the whole trick
///
/// Each emitted record is resolved TWICE — against an EMPTY table and against
/// the source face's real one:
///
/// * `(Some, _)` — a literal. Resolvable with no table at all, so any peer
///   decodes it. This is the case that must hold, and it is counted.
/// * `(None, Some(k))` — AN ALIAS THE FORWARDER PASSED THROUGH. Unresolvable
///   without a table, resolvable with the source's, so the destination is being
///   handed an id only the SOURCE ever declared. The failure.
/// * `(None, None)` — the record carries no governed keyexpr (`Oam`, a
///   `ResponseFinal`, a Final `Interest`, an id-only undeclare). Ignored.
///
/// The `(None, Some)` split is why the source's table is a parameter rather than
/// this asserting on `None`: `None` alone cannot tell an alias from a record that
/// never had a keyexpr, and treating the second as a failure would red every
/// linkstate `Oam`.
///
/// ## It RETURNS the literals it saw
///
/// `literals > 0` is only an anti-vacuity floor, and a floor cannot tell a guard
/// that inspected all four of a scenario's planes from one that inspected a
/// single plane and shrugged at the rest. The caller pins the SET, which is this
/// workspace's standing rule for coverage claims — a count would keep passing
/// while a plane quietly stopped emitting.
#[cfg(feature = "routing-peer")]
pub(crate) fn assert_emits_no_alias_of_its_own(
    sink: &RecordingLinkDriver,
    source_aliases: &hashbrown::HashMap<u64, String>,
    what: &str,
) -> Vec<String> {
    use wz_session_core::inbound::{parse_inbound, InboundFrame};
    use wz_session_core::network_message::parse_frame_payload;

    let empty: hashbrown::HashMap<u64, String> = hashbrown::HashMap::new();
    let mut literals: Vec<String> = Vec::new();
    let mut passed_through: Vec<String> = Vec::new();
    for idx in 0..sink.frame_count() {
        let bytes = sink.frame_bytes(idx);
        // The forwarder's OWN bytes, so a parse failure is a defect and not a
        // shape this guard may skip past.
        let parsed = parse_inbound(&bytes).expect("the forwarder's own frame parses");
        let InboundFrame::Frame { payload, .. } = parsed else {
            continue;
        };
        let records = parse_frame_payload(&payload).expect("the forwarder's own batch parses");
        for record in records {
            let as_literal = crate::linkstate_forward::resolve_governed_keyexpr(&record, &empty);
            let via_source =
                crate::linkstate_forward::resolve_governed_keyexpr(&record, source_aliases);
            match (as_literal, via_source) {
                (Some(k), _) => literals.push(k),
                (None, Some(k)) => passed_through.push(k),
                (None, None) => {}
            }
        }
    }
    assert!(
        passed_through.is_empty(),
        "{what} emitted {} keyexpr(s) that only the SOURCE face's alias table \
         can resolve: {passed_through:?}. The destination never declared those \
         ids. Every resolve site in this forwarder consults the source face's \
         peer table alone, so a peer answering such an alias with M=0 would be \
         dropped -- that is carry N39/N71, and this is the day it stopped being \
         latent. Give the face an own-id space and resolve through \
         MappingSpaces, as the four inbound planes have since R311y739",
        passed_through.len()
    );
    assert!(
        !literals.is_empty(),
        "{what} emitted no keyexpr-carrying record at all, so the assertion \
         above graded nothing"
    );
    literals.sort();
    literals
}
