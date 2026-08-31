// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2221 (open-debt item 568) — the two HANDSHAKE-NEGOTIATED axes that had no
//! GENUINE witness: the frame-SN ring (`seq_num_res`) and the protocol PATCH
//! level, measured as NEGOTIATED VALUES against a real `zenohd`.
//!
//! ## The gap this closes, stated exactly
//!
//! `scripts/lib/negotiated_axis_witness_gate.py` asks whether every negotiated
//! axis is asserted SOMEWHERE. Its own docstring says so — "every
//! HANDSHAKE-NEGOTIATED axis is asserted somewhere" — and it carries no
//! `genuine` / `foreign` / `zenohd` condition. The consuming surface read the
//! gate, agreed with it, and filed the narrower claim it does not answer: for
//! these two axes every assertion in the tree stood on a wire THIS TREE WROTE
//! (`craft_initack_wire` + `QueueDriver`,
//! `wz-runtime-tokio/tests/session_fsm_driver_loop.rs`). An encoder and a
//! decoder in one tree that are wrong together pass every such assertion.
//!
//! So the claim was never "there is no genuine witness" — there are 82 zenohd
//! files beside this one — but "no genuine witness measures THESE AXES AS
//! NEGOTIATED VALUES". That is what these four tests do.
//!
//! ## The axes are SPLIT, and the file says which is which
//!
//! They are separate `#[test]`s over separate helpers on purpose. Folded into
//! one leg, the weaker axis passes behind the stronger one and the roll-up
//! cannot tell which half was measured.
//!
//! ## AXIS 1 — `seq_num_res`, and the trap that makes a green mean nothing
//!
//! `Resolution` is `min()`ed by both peers
//! (`io/zenoh-transport/src/unicast/establishment/accept.rs:198-213` at zenoh
//! 1.5.0), so the SMALLER advertisement wins. Advertise the small value from
//! WZ and the negotiated ring equals wz's own advertisement — which an
//! implementation that ignored zenohd's InitAck entirely also produces. The
//! assertion would then be green over a population of zero.
//!
//! The value therefore lives on the ROUTER, through
//! `transport/link/tx/sequence_number_resolution`
//! (`DEFAULT_CONFIG.json5:590`; the spellings are
//! `commons/zenoh-protocol/src/core/resolution.rs:32-35`). The negotiated ring
//! is then a number that exists ONLY on zenohd's side of the wire until its
//! InitAck carries it back, and wz's default advertisement (`seq_num_res: 2`,
//! `wz-runtime-tokio-test-support`) is the value it must ABANDON.
//!
//! ### What is asserted, and why it is the wire and not the session
//!
//! Two readings, one per claim:
//!
//! * `negotiated_sn_mask()` — what wz DECIDED the ring is;
//! * the SN of the first `T_MID_FRAME` batch wz put on the link, read by the
//!   relay's own parser ([`CountingRelay::dialer_to_acceptor_frame_sns`]),
//!   which holds none of wz's session state.
//!
//! The second is what makes this "the negotiated value is APPLIED" rather than
//! "read". `SessionLinkActions::open_params` derives the ring ORIGIN from the
//! negotiated mask —
//! `derive_initial_sn(own_zid, peer_zid, negotiated_sn_mask())`,
//! `wz-session-core/src/session_actions.rs:2146-2149` — and seeds the TX
//! counter with it, so the first SN on the wire is a pure function of the
//! negotiated ring and the two identities. The leg recomputes that function
//! itself and compares.
//!
//! ### The control that is INSIDE the assertion
//!
//! Each arm also asserts that the same derivation over the OTHER arm's mask
//! yields a DIFFERENT number. That is the leg saying, in the leg, that the
//! reading it just made could have come out differently — so a wz that ignored
//! the InitAck's resolution is a red here and not a coincidence.
//!
//! ### What the wire assertion does NOT prove, said before someone assumes it
//!
//! Its oracle is `derive_initial_sn`, the PRODUCTION function, so a defect in
//! that function moves both sides and is invisible here. What it binds is
//! WHICH MASK is fed to it — which is exactly this axis and not the hash's
//! correctness (`wz-session-core/src/initial_sn.rs` owns that).
//!
//! ## MEASURED — four mutations, and which arm each one reddens
//!
//! Not predicted. Each was applied to this tree, run against a real zenohd,
//! and reverted; the point of listing all four is that they are ORTHOGONAL —
//! no mutation reddens an arm whose claim it does not touch.
//!
//! | mutation | red |
//! |---|---|
//! | `negotiated_sn_mask` drops the peer's `min` | the 16bit arm ALONE. zenohd then refuses wz's frames outright and the session dies — a genuine router is the one that objects |
//! | `negotiate_patch_against_peer` uses its own level | the NO_PATCH arm ALONE, at `left: 1 / right: 0` |
//! | the ring origin derived on wz's OWN advertised ring | the 16bit arm ALONE, through DELIVERY: the OpenSyn announces one ring and the mint walks another, and zenohd's half-window drops every frame |
//! | the ring origin derived on a THIRD ring (`res 0`) | BOTH SN arms, at the WIRE assertion ALONE — `negotiated_sn_mask()` stays correct and only the bytes are wrong. This is the one that shows the wire half is separately load-bearing |
//!
//! The patch arms stay green under both SN mutations and the SN arms under the
//! patch one, which is what says the two axes are measured separately rather
//! than one behind the other.
//!
//! ### Why `16bit` and not `8bit`, measured rather than chosen
//!
//! wz's ring masks follow zenoh-PICO — `_z_sn_max`: `0x00 -> U8_MAX >> 1`,
//! `0x01 -> U16_MAX >> 2`, `0x02 -> U32_MAX >> 4`
//! (`vendor/zenoh-pico/src/transport/utils.c:24-40`, mirrored at
//! `wz-session-core/src/sn.rs:33-40`) — while zenoh-full's `Bits::mask()` is
//! `u8::MAX` / `u16::MAX` / `u32::MAX`
//! (`commons/zenoh-protocol/src/core/resolution.rs:46-52`). wz's ring is a
//! strict SUBSET of zenoh's at every code, so every SN wz emits is legal to
//! zenohd — until wz WRAPS, at which point zenohd's half-window rejects the
//! step back. This leg therefore stays well inside the ring and never crosses
//! it. The divergence itself is out of this item's scope and is filed
//! separately; naming it here is what stops the next reader from reaching for
//! `8bit` and reading a harness limit as a wz defect.
//!
//! ## AXIS 2 — `patch`, and the handle the register said was not there
//!
//! The register expected a verdict here: every genuine implementation
//! announces the SAME level, so `min()` is a fixed point and the negotiated
//! value equals wz's own default. That half is TRUE and measured — zenoh
//! `PatchType::CURRENT = 1`
//! (`commons/zenoh-protocol/src/transport/mod.rs:322-323`), zenoh-pico
//! `_Z_CURRENT_PATCH 0x01`
//! (`include/zenoh-pico/protocol/definitions/transport.h:101`), wz
//! `CURRENT_PATCH = 1` (`wz-session-core/src/extpatch.rs`).
//!
//! What does NOT follow is that the axis cannot be measured. zenohd's acceptor
//! answers `min(PatchType::CURRENT, what the InitSyn carried)`
//! (`unicast/establishment/ext/patch.rs:~193`), so the level on a genuine
//! InitAck is a function of what WZ announced. Announce
//! [`wz_session_core::extpatch::NO_PATCH`] and a stock zenohd genuinely
//! answers 0. Both peers stay genuine, no byte on the wire is rewritten, and
//! the two arms read 1 and 0 through the same accessor.
//!
//! That is a real discriminator: an implementation that took its own
//! `CURRENT_PATCH` instead of the peer's announcement reads 1 on BOTH arms and
//! reds on the second. The handle is `set_ext_chain(ExtChainRole::InitSyn, ..)`
//! reached through `initiate_and_open_session_with_staging`, which exposes the
//! staging seam `initiator_open_offering` already had.
//!
//! ## Opt-in
//!
//! `#[ignore]`, run-ci Layer Z. The test NAMES carry `zenohd` because Layer E's
//! skip filter is a name substring (`--skip zenohd`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, spawn_counting_relay, spawn_subscribed_zsub,
    spawn_zenohd_sn_resolution_on_ephemeral_tcp, wz_ap_demo_binary, zenoh_pico_cli_binary,
    CountingRelay, RelayFault,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    initiate_and_open_session_with_staging, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::ext_chain_role::ExtChainRole;
use wz_session_core::extpatch::{encode_patch_ext_at, CURRENT_PATCH, NO_PATCH};
use wz_session_core::initial_sn::derive_initial_sn;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::sn::mask_from_res;
use wz_session_core::transport_mode::SessionOffer;

const ITER_CAP: usize = 4096;
const PUBLISH_KEYEXPR: &str = "demo/negotiated-axes";
const SUB_KEYEXPR: &str = "demo/**";
/// The transport MID the relay counts. Its SN reading is independent of this
/// (`T_MID_FRAME_LOCAL`), but a counted MID must still be a bare 5-bit id.
const T_MID_FRAME: u8 = 0x05;
/// `Bits::U16` — zenoh's spelling of the ring wz must ADOPT from the router.
const NON_DEFAULT_RESOLUTION: &str = "16bit";
/// The wire code `NON_DEFAULT_RESOLUTION` decodes to
/// (`resolution.rs:24-28` — `U16 = 0b01`).
const NON_DEFAULT_RES_CODE: u8 = 1;
/// `Bits::U32` — the zenoh DEFAULT, and the code wz itself advertises. Passed
/// EXPLICITLY on the twin arm so the two arms differ in one string and not in
/// which spawn helper they called.
const DEFAULT_RESOLUTION: &str = "32bit";
/// The wire code `DEFAULT_RESOLUTION` decodes to (`U32 = 0b10`).
const DEFAULT_RES_CODE: u8 = 2;
/// Frames to put on the link. Far above 1 (so the ring CONTAINMENT claim has a
/// population) and far below the smaller ring's 16384 (so neither arm wraps —
/// see the module docs on why a wrap would be a harness failure and not a wz
/// one).
const FRAMES: usize = 24;

/// What one arm of a pair observed.
struct ArmOutcome {
    /// wz's own decision.
    negotiated_mask: u64,
    /// The negotiated protocol patch level, and whether the merge ran at all.
    negotiated_patch: u8,
    patch_was_negotiated: bool,
    /// The two identities the ring origin is derived from. Carried out of the
    /// arm rather than re-fetched by the caller so the recomputation runs on
    /// the SAME values the session used — a second source for `own_zid` is a
    /// second thing that can drift from the params the dial actually sent.
    own_zid: Vec<u8>,
    peer_zid: Vec<u8>,
    /// Frame sequence numbers the RELAY read off wz's half of the wire.
    frame_sns: Vec<u64>,
    /// Did the router route wz's sample to a third implementation.
    delivery: Result<(), String>,
}

/// What one arm sets up, and what it must therefore read back.
///
/// Grouped because the four are one description of an arm, and because a pair
/// then differs in exactly ONE field — which is what makes each twin a twin by
/// construction rather than by parallel maintenance of two copies.
struct Arm {
    /// zenoh's spelling of the ROUTER's ring (`resolution.rs:32-35`).
    resolution: &'static str,
    /// The wire code that spelling decodes to (`resolution.rs:24-28`).
    res_code: u8,
    /// The protocol patch level wz announces on its InitSyn.
    advertised_patch: u8,
    /// The level a genuine zenohd must therefore answer with — its acceptor
    /// returns `min(PatchType::CURRENT, what the InitSyn carried)`.
    expected_patch: u8,
}

/// Drive one arm: a zenohd whose SN ring is `arm.resolution`, a pico `z_sub`
/// client of it, and a wz publisher dialling THROUGH a relay that records what
/// wz put on the wire.
///
/// # Why the SESSION-STATE assertions are here and not in the `#[test]`
///
/// They read an accessor off a session that does not outlive this function, so
/// asserting on a value carried out in [`ArmOutcome`] would put the READ and
/// the ASSERTION in different functions. That is not only a style point: it is
/// what `negotiated_axis_witness_gate.py` looks for — an accessor call inside
/// an assertion's argument list, or one binding hop away inside the same `fn` —
/// and a value laundered through a struct field is invisible to it. Measured:
/// the first draft of this file did exactly that and the axes still read
/// SYNTHETIC-ONLY with these tests passing.
///
/// The `#[test]`s keep everything the arm cannot claim: the WIRE readings, and
/// every statement about the PAIR.
async fn dial_zenohd(arm: &Arm) -> ArmOutcome {
    let Arm {
        resolution,
        res_code,
        advertised_patch,
        expected_patch,
    } = *arm;
    // The demo is not the subject here — this leg opens its own in-process
    // session — but `spawn_zenohd_*` spawns it as the handshake-readiness probe
    // and a stale one makes that probe fail to detect a router that IS ready.
    // Asserted rather than exempted: the exemption branch offers "raise the
    // carried number and say why", and R2200's finding is that repaying is the
    // right side of that fork. A named freshness failure beats a ten-second
    // readiness timeout whose message points at zenohd.
    assert_demo_binary_newer_than_sources(&wz_ap_demo_binary());
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (mut zenohd, zenohd_port) = spawn_zenohd_sn_resolution_on_ephemeral_tcp(resolution, || {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let relay: CountingRelay = spawn_counting_relay(zenohd_port, T_MID_FRAME, RelayFault::None);

    // pico subscribes to zenohd DIRECTLY: it is the far-side witness, and
    // routing it through the relay would only add a failure mode.
    let (mut z_sub_child, mut z_sub_stdout_reader) = spawn_subscribed_zsub(
        &z_sub,
        SUB_KEYEXPR,
        &format!("tcp/127.0.0.1:{zenohd_port}"),
        "zenohd",
        || tempfile::tempfile().expect("tempfile for z_sub stdout"),
    );

    // The zenohd-STRICT open shape (version 0x09 / real batch_size / res 2).
    // `seq_num_res` is left at 2 in BOTH arms: the whole point is that the
    // number wz ends up on comes from the ROUTER.
    let params = zenohd_interop_session_init_params();
    let own_zid = params.zid.clone();
    let stream = TcpStream::connect(("127.0.0.1", relay.port()))
        .await
        .expect("wz dials the sn-recording relay");
    let opened = initiate_and_open_session_with_staging(
        DialedLink::Tcp(stream),
        params,
        SessionOffer::universal(),
        |actions| {
            // Staged before the first wire byte, so this IS what the InitSyn
            // announces. `advertised_patch` is the only thing the patch pair
            // varies.
            actions.set_ext_chain(
                ExtChainRole::InitSyn,
                vec![encode_patch_ext_at(advertised_patch)],
            );
            Ok(())
        },
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await;

    let mut opened = match opened {
        Ok(opened) => opened,
        Err(e) => {
            let _ = z_sub_child.child_mut().kill();
            let _ = z_sub_child.child_mut().wait();
            let _ = zenohd.child_mut().kill();
            let _ = zenohd.child_mut().wait();
            panic!(
                "wz did not reach Established against a zenohd at \
                 sequence_number_resolution={resolution} (advertised patch \
                 {advertised_patch}): {e:?}"
            );
        }
    };

    // AXIS 1, wz's DECISION. The number lives only in zenohd's config until its
    // InitAck carries it back, so this is the axis and not a restatement of
    // what wz advertised. `ChildGuard` kills on drop, so a panic here still
    // reaps the router and the subscriber.
    assert_eq!(
        opened.actions.negotiated_sn_mask(),
        mask_from_res(res_code),
        "wz did not settle on the ring a genuine zenohd negotiated at \
         sequence_number_resolution={resolution} (wire code {res_code}). wz \
         advertised code 2, so this reading can only come from the InitAck."
    );

    // AXIS 2, and the same discipline. `patch_was_negotiated` separates "wz
    // merged a peer announcement" from "wz defaulted": the slot starts `None`
    // and the accessor would report NO_PATCH for a session that saw no Init.
    assert!(
        opened.actions.patch_was_negotiated(),
        "wz never merged a peer patch announcement (advertised \
         {advertised_patch})"
    );
    assert_eq!(
        opened.actions.negotiated_patch(),
        expected_patch,
        "wz announced patch {advertised_patch}; a genuine zenohd answers \
         min(CURRENT, {advertised_patch}) = {expected_patch} and wz must settle \
         there. Reading its own level instead means the peer's announcement was \
         not read."
    );

    let negotiated_mask = opened.actions.negotiated_sn_mask();
    let negotiated_patch = opened.actions.negotiated_patch();
    let patch_was_negotiated = opened.actions.patch_was_negotiated();
    let peer_zid = opened
        .actions
        .peer_zid()
        .expect("an Established session knows the peer zid");

    let publisher = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    let timeouts = SessionTimeouts::spec_defaults();
    let mut observer = ApplicationLayerObserver::new();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
    );

    let payload = format!("negotiated-axes-{resolution}");
    let received_witness = ">> [Subscriber] Received";
    let scenario = async {
        // The route still has to propagate through zenohd, so the Put is
        // republished on a cadence; every Put is byte-identical, so one landing
        // after the route installs suffices. The loop also SUPPLIES the frame
        // population the ring-containment claim is made over.
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut arrived = false;
        loop {
            publisher
                .publish(PUBLISH_KEYEXPR, payload.as_bytes(), PublishOptions::put())
                .expect("publish builds and routes through the send seam");
            tokio::time::sleep(Duration::from_millis(60)).await;
            if !arrived {
                let captured = read_stdout(&mut z_sub_stdout_reader);
                arrived = captured.contains(received_witness) && captured.contains(&payload);
            }
            // Both conditions, deliberately: the delivery witness alone would
            // leave the SN list too short to say anything about the ring, and a
            // frame count alone would not say the router accepted them.
            if arrived && relay.dialer_to_acceptor_frame_sns().len() >= FRAMES {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let captured = read_stdout(&mut z_sub_stdout_reader);
                return Err(format!(
                    "within 15s: delivered={arrived}, frames on wire={} (wanted \
                     {FRAMES}).\n--- captured z_sub stdout ---\n{captured}",
                    relay.dialer_to_acceptor_frame_sns().len()
                ));
            }
        }
    };

    let delivery = tokio::select! {
        _ = drive => Err(
            "wz drive loop reached a terminal state before the arm completed".to_string()
        ),
        r = scenario => r,
    };
    let frame_sns = relay.dialer_to_acceptor_frame_sns();

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    // Reported rather than asserted here: an arm is data, and every assertion
    // belongs in the `#[test]` that owns the claim.
    eprintln!(
        "arm resolution={resolution} advertised_patch={advertised_patch}: \
         mask=0x{negotiated_mask:X} patch={negotiated_patch} \
         patch_negotiated={patch_was_negotiated} frames={} first_sn={:?}",
        frame_sns.len(),
        frame_sns.first()
    );

    ArmOutcome {
        negotiated_mask,
        negotiated_patch,
        patch_was_negotiated,
        own_zid,
        peer_zid,
        frame_sns,
        delivery,
    }
}

/// Read whatever the child has written so far without consuming the handle.
fn read_stdout(handle: &mut std::fs::File) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let mut buf = String::new();
    let _ = handle.seek(SeekFrom::Start(0));
    let _ = handle.read_to_string(&mut buf);
    buf
}

/// Both arms of the SN pair assert the same three things about their own ring;
/// only the expected code differs. Shared so a claim cannot be made on one arm
/// and quietly dropped on the other.
fn assert_ring(arm: &ArmOutcome, res_code: u8, other_res_code: u8, what: &str) {
    let expected_mask = mask_from_res(res_code);
    let other_mask = mask_from_res(other_res_code);

    arm.delivery
        .as_ref()
        .unwrap_or_else(|e| panic!("{what}: the arm did not complete — {e}"));

    // 1. wz's DECISION is asserted inside the arm, beside the accessor read —
    //    see `dial_zenohd`'s docs for why the read and the assertion may not be
    //    separated. Restated here as a `debug` would be: the mask carried out
    //    is the one that was checked.
    assert_eq!(
        arm.negotiated_mask, expected_mask,
        "{what}: the mask carried out of the arm is not the one the arm checked"
    );

    // 2. The DERIVATION's discriminating power, asserted before it is used. A
    //    ring origin that happened to be equal under both masks would make
    //    assertion 3 pass for the wrong reason, and this is where that is
    //    caught rather than assumed away.
    let expected_first = derive_initial_sn(&arm.own_zid, &arm.peer_zid, expected_mask);
    let counterfactual = derive_initial_sn(&arm.own_zid, &arm.peer_zid, other_mask);
    assert_ne!(
        expected_first, counterfactual,
        "{what}: the ring origin is the SAME under both masks for this zid pair, \
         so assertion 3 below could not tell them apart. Nothing is wrong with \
         wz; this run cannot measure the axis and must not report that it did."
    );

    // 3. The negotiated ring APPLIED, read off the wire by a parser holding
    //    none of wz's session state. `open_params` seeds the TX counter with
    //    `derive_initial_sn(own, peer, negotiated_sn_mask())`, so the first
    //    frame SN is that function — computed here from the two identities and
    //    the mask the ROUTER chose.
    let first = *arm.frame_sns.first().unwrap_or_else(|| {
        panic!("{what}: the relay recorded no T_MID_FRAME batch from wz at all")
    });
    assert_eq!(
        first, expected_first,
        "{what}: wz's first frame SN on the wire is {first}, but the ring \
         zenohd negotiated puts its origin at {expected_first}. It matches the \
         un-negotiated {other_res_code}-code ring's origin ({counterfactual}) \
         when wz ignores the InitAck's resolution."
    );

    // 4. CONTAINMENT, over every frame and not only the first: the ring is not
    //    merely where the counter started.
    assert!(
        arm.frame_sns.len() >= FRAMES,
        "{what}: only {} frame(s) recorded; the containment claim below needs a \
         population",
        arm.frame_sns.len()
    );
    let over = arm
        .frame_sns
        .iter()
        .filter(|sn| **sn > expected_mask)
        .count();
    assert_eq!(
        over,
        0,
        "{what}: {over} of {} frame SNs sit ABOVE the negotiated ring \
         (mask 0x{expected_mask:X}); wz minted them on a wider ring than the \
         handshake agreed to.",
        arm.frame_sns.len()
    );
    // No wrap, which is what keeps assertion 4 a claim about the ring rather
    // than about the counter: a wrapped run would satisfy it trivially and, per
    // the module docs, would be a harness failure.
    let descents = arm.frame_sns.windows(2).filter(|w| w[1] <= w[0]).count();
    assert_eq!(
        descents, 0,
        "{what}: the SN sequence stepped backwards {descents} time(s). This leg \
         must stay inside the ring — see the module docs on the wz/zenoh mask \
         divergence — so a wrap here invalidates the reading rather than \
         reporting on wz."
    );
}

// wz-proves: codec-init-body zenohd->wz
// wz-proves: codec-frame wz->zenohd
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_adopts_the_sn_resolution_a_genuine_zenohd_negotiated() {
    let arm = dial_zenohd(&Arm {
        resolution: NON_DEFAULT_RESOLUTION,
        res_code: NON_DEFAULT_RES_CODE,
        advertised_patch: CURRENT_PATCH,
        expected_patch: CURRENT_PATCH,
    })
    .await;
    assert_ring(
        &arm,
        NON_DEFAULT_RES_CODE,
        DEFAULT_RES_CODE,
        "the 16bit router",
    );
    // The abandonment, said out loud: wz advertised code 2 and is on code 1.
    assert_ne!(
        arm.negotiated_mask,
        mask_from_res(DEFAULT_RES_CODE),
        "wz stayed on its OWN advertised ring against a router that negotiated a \
         narrower one"
    );
}

// wz-proves: none -- the CALIBRATION twin of the leg above. Its expected ring is
// also wz's own advertisement, so an implementation that ignored the InitAck's
// resolution passes it; that is exactly what makes it the calibration and not a
// proof. It witnesses that the SAME reading comes out differently when the
// router's config is the only thing changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_keeps_the_default_sn_resolution_against_a_stock_ring_zenohd() {
    let arm = dial_zenohd(&Arm {
        resolution: DEFAULT_RESOLUTION,
        res_code: DEFAULT_RES_CODE,
        advertised_patch: CURRENT_PATCH,
        expected_patch: CURRENT_PATCH,
    })
    .await;
    assert_ring(
        &arm,
        DEFAULT_RES_CODE,
        NON_DEFAULT_RES_CODE,
        "the stock 32bit router",
    );
}

// wz-proves: codec-init-body zenohd->wz
// wz-proves: session-unicast-open wz->zenohd
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_takes_the_patch_level_a_genuine_zenohd_announced() {
    let arm = dial_zenohd(&Arm {
        resolution: DEFAULT_RESOLUTION,
        res_code: DEFAULT_RES_CODE,
        advertised_patch: CURRENT_PATCH,
        expected_patch: CURRENT_PATCH,
    })
    .await;
    arm.delivery
        .as_ref()
        .unwrap_or_else(|e| panic!("the CURRENT-patch arm did not complete — {e}"));

    // The merge RAN. Without it the slot is `None` and the accessor reports
    // NO_PATCH, so this separates "wz read an Init" from "wz defaulted".
    assert!(
        arm.patch_was_negotiated,
        "wz never merged a peer patch announcement; `negotiated_patch()` would \
         report NO_PATCH for a session that had seen no Init at all"
    );
    assert_eq!(
        arm.negotiated_patch, CURRENT_PATCH,
        "a stock zenohd answers min(PatchType::CURRENT, our announcement) and we \
         announced CURRENT, so the negotiated level must be CURRENT"
    );
}

// wz-proves: codec-init-body zenohd->wz
// wz-proves: session-unicast-open wz->zenohd
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd router + zenoh-pico z_sub); set WZ_ZENOHD_BIN, run via Layer Z / --ignored"]
async fn wz_takes_the_lowered_patch_level_a_genuine_zenohd_answered() {
    // The DISCRIMINATOR of the pair. wz announces NO_PATCH, so a stock zenohd's
    // `min(CURRENT, 0)` genuinely answers 0 — both peers stock, no byte
    // rewritten. An implementation that took its own CURRENT_PATCH instead of
    // the peer's announcement reads 1 here and reds.
    let arm = dial_zenohd(&Arm {
        resolution: DEFAULT_RESOLUTION,
        res_code: DEFAULT_RES_CODE,
        advertised_patch: NO_PATCH,
        expected_patch: NO_PATCH,
    })
    .await;
    arm.delivery
        .as_ref()
        .unwrap_or_else(|e| panic!("the NO_PATCH arm did not complete — {e}"));

    assert!(
        arm.patch_was_negotiated,
        "wz never merged a peer patch announcement on the lowered arm"
    );
    assert_eq!(
        arm.negotiated_patch, NO_PATCH,
        "wz announced NO_PATCH, so a genuine zenohd's InitAck carries \
         min(CURRENT, 0) = 0 and wz must settle there. Reading CURRENT means wz \
         used its own level in place of the one the router sent."
    );
    assert_ne!(
        arm.negotiated_patch, CURRENT_PATCH,
        "the two patch arms must not read the same level, or neither measures \
         the axis"
    );
}
