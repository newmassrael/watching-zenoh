// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311hl — Track 2 no-alloc gating RUNTIME proof.
//!
//! A Cortex-M binary with **no `#[global_allocator]`** that drives every
//! `wz-session-core` application-layer registry's no-heap fire entry on a
//! (QEMU-emulated) MCU. See `Cargo.toml` for why the missing allocator is
//! the proof: a `#![no_std]` binary without one fails to link if any
//! reachable path references `alloc`, so a clean link + a successful run
//! is a whole-program guarantee that these registry paths are heap-free
//! AND execute correctly on real M-class silicon.
//!
//! The seven fire paths exercised (one per registry, subscriber covers
//! both declare + undeclare):
//!
//!   1. `pubsub::SubscriberRegistry::dispatch_borrowed`           (SampleSink)
//!   2. `query::QueryableRegistry::dispatch_borrowed`             (QuerySink + ReplyOut)
//!   3. `reply::ReplyRegistry::dispatch_borrowed`                 (ReplySink)
//!   4. `declare::subscriber::RemoteSubscriberRegistry`
//!      `::dispatch_declared_borrowed` + `::dispatch_undeclared` (DeclSink / UndeclSink)
//!   5. `declare::liveliness_subscriber::LivelinessSubscriberRegistry`
//!      `::dispatch_sample_borrowed`                            (LivelinessSampleSink)
//!
//! R311ho adds a sixth stage that proves the no-heap *emit* (not just the
//! inbound fire): `declare::local_token::LocalTokenRegistry`
//! `::respond_to_interest_borrowed` stages borrowed `DeclResponseItem`s,
//! and this probe — playing the MCU `ResponseSink` — encodes each into a
//! stack buffer through SCE's `SliceSink` (`encode<S: SceSink>`). A clean
//! no-allocator link + a non-zero encode position is the whole-program
//! proof that outbound wire construction is heap-free, closing the
//! Decision 2 no-heap-emit extension (R311hm/hn).
//!
//! ⓓ adds a seventh stage that closes the loop with the switchboard
//! generator: the `xtask` codegen SSOT runs `sce-codegen --no-std` +
//! wz-switchboard-codegen over the `thermostat` triad (a primitive-only
//! statechart + EventSchema + codec) and COMMITS the output under
//! `out/mcu-noheap-probe/` (R311y22c; gated by the Layer B2 regen-diff lane),
//! and `main` feeds a FOREIGN wire sample through the generated
//! `dispatch_switchboard` — keyexpr match -> `SceCursor` codec decode -> typed
//! `_event.data` inject via the `ThermostatInject::raise_temp_reading` seam ->
//! native `celsius_centi > 3000` guard -> `Engine<ThermostatPolicy>`
//! idle->hot. Every link is heap-free (the `--no-std` engine is heapless-
//! backed, the payload is a `Copy` u16, the codec's alloc facade compiles
//! out), so a clean no-allocator link + the observed transitions prove the
//! single-SCXML-source -> MCU no-heap *value* path end to end. This stage is
//! gated to the mps2-class cores (M3/M4/M7); the engine's working set exceeds
//! the microbit / M0's 16 KB RAM (the registry stages 1-6 still run there).
//!
//! Each registry is instantiated over a consumer-supplied concrete
//! (non-`Box`) sink — the closed-type shape an MCU consumer (a generated
//! switchboard `enum` or a hand-written app) supplies — and each sink
//! tallies its deliveries into a `static` `AtomicU32`. `main` asserts the
//! returned fired-count + the observed tally for each, then exits with
//! `SYS_EXIT` PASS=0 / FAIL=1 so the Layer Q lane gates on it.

#![no_std]
#![no_main]

// NB: deliberately NO `extern crate alloc;` and NO `#[global_allocator]`.
// The whole point is that nothing here links the allocator.

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;
use portable_atomic::{AtomicU32, Ordering};

use wz_session_core::decl_sink::{BorrowedDecl, DeclSink, DeclView, UndeclSink};
use wz_session_core::declare::liveliness_sample::{
    LivelinessSample, LivelinessSampleKind, LivelinessSampleSink,
};
use wz_session_core::declare::liveliness_subscriber::LivelinessSubscriberRegistry;
use wz_session_core::declare::subscriber::RemoteSubscriberRegistry;
use wz_session_core::locality::Locality;
use wz_session_core::pubsub::SubscriberRegistry;
use wz_session_core::query::QueryableRegistry;
use wz_session_core::query_sink::{BorrowedQuery, QuerySink, QueryView, ReplyOut};
use wz_session_core::reliability::Reliability;
use wz_session_core::reply::ReplyRegistry;
use wz_session_core::reply_sink::{BorrowedReply, ReplyKind, ReplySink, ReplyView};
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::sink::{BorrowedSample, SampleSink, SampleView};

// R311ho — declarer-side liveliness-token no-heap EMIT proof. The
// registry stages borrowed `DeclResponseItem`s; this probe encodes each
// into a stack buffer via SCE's `SliceSink` (no allocator).
use wz_session_core::bounded::BoundedVec;
use wz_session_core::caps;
use wz_session_core::declare::local_token::{
    build_final_reply, build_token_reply, DeclResponseItem, LocalTokenRegistry,
};

// The full `Declare` envelope is the real emitted unit; the probe encodes
// it (not just the inner leaf) so the no-heap proof covers the outer
// header + interest_id routing exactly as the AP sink emits.
use wz_codecs::declare::Declare;

use sce_forge_runtime::codec::SliceSink;

// ── (ⓓ) generated switchboard value path ────────────────────────────────
//
// The `xtask` codegen SSOT ran `sce-codegen --no-std` over the thermostat triad
// + wz-switchboard-codegen over wz-switchboard.yaml and COMMITTED the output
// under out/mcu-noheap-probe/ (R311y22c). The three generated artifacts are
// `include!`d here from there (build.rs no longer runs codegen):
//   - `thermostat` — the SCXML state machine (Engine<ThermostatPolicy> + the
//     ThermostatInject::raise_temp_reading typed seam, allocator-free under
//     --no-std);
//   - `temp_reading_codec` — the wire codec whose `SceCursor` decode reads the
//     big-endian uint16 `celsius_centi` (the alloc-gated VecSink facade is
//     compiled out — this crate has no `alloc` feature);
//   - the crate-root `dispatch_switchboard` — the closed keyexpr -> typed
//     inject dispatch.
// The machine + codec carry `#![allow(...)]` inner attributes that the xtask
// strips for the mid-module `include!`; they are restored here as outer
// attributes on the wrapping module (mirrors wz-switchboard-example).
//
// The whole switchboard machinery (both modules + the dispatch + the stage-7
// driver in `main`) is gated to `target_has_atomic = "32"` — the mps2-class
// cores (Cortex-M3/M4/M7). The generated `Engine<ThermostatPolicy>` working
// set exceeds the microbit / Cortex-M0's 16 KB RAM (see the stage-7 comment in
// `main`); gating the includes out there also keeps the M0 build free of
// unused-item warnings. The registry stages 1-6 stay unconditional.

#[cfg(target_has_atomic = "32")]
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(unused_labels)]
#[allow(unreachable_patterns)]
#[allow(unreachable_code)]
#[allow(unused_assignments)]
#[allow(clippy::all)]
mod thermostat {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/mcu-noheap-probe",
        "/thermostat_sm.rs"
    ));
}

#[cfg(target_has_atomic = "32")]
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(clippy::all)]
mod temp_reading_codec {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../out/mcu-noheap-probe",
        "/temp_reading_codec.rs"
    ));
}

// `use thermostat::ThermostatInject;` + `pub fn dispatch_switchboard(target,
// payload, engine)`. Included at CRATE ROOT (not in a module) so its
// `thermostat::` / `temp_reading_codec::` references resolve to the sibling
// modules above (mirrors wz-switchboard-example/src/lib.rs).
#[cfg(target_has_atomic = "32")]
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../out/mcu-noheap-probe",
    "/dispatch_switchboard.rs"
));

static SAMPLE_HITS: AtomicU32 = AtomicU32::new(0);
static QUERY_HITS: AtomicU32 = AtomicU32::new(0);
static REPLY_HITS: AtomicU32 = AtomicU32::new(0);
static DECL_HITS: AtomicU32 = AtomicU32::new(0);
static UNDECL_HITS: AtomicU32 = AtomicU32::new(0);
static LIVE_HITS: AtomicU32 = AtomicU32::new(0);
static EMIT_HITS: AtomicU32 = AtomicU32::new(0);
#[cfg(target_has_atomic = "32")]
static INJECT_HITS: AtomicU32 = AtomicU32::new(0);

// ── Concrete (non-`Box`) consumer sinks — the closed-type MCU shape. ──

struct SampleCounter(&'static AtomicU32);
impl SampleSink for SampleCounter {
    fn deliver(&mut self, _sample: &dyn SampleView) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct QueryCounter(&'static AtomicU32);
impl QuerySink for QueryCounter {
    fn handle(&mut self, _query: &dyn QueryView, out: &mut dyn ReplyOut) {
        self.0.fetch_add(1, Ordering::SeqCst);
        // Emit a reply through the seam's output contract — the borrowed
        // payload is consumed by `NoopReplyOut` with no allocation.
        out.reply(b"ok");
    }
}

/// A `ReplyOut` that drops everything — the query no-heap path hands the
/// sink an `&mut dyn ReplyOut`; an MCU consumer routes it to a Worker /
/// statechart, but the proof only needs it to be allocation-free.
struct NoopReplyOut;
impl ReplyOut for NoopReplyOut {
    fn reply(&mut self, _payload: &[u8]) {}
    fn reply_del(&mut self) {}
    fn reply_err(&mut self, _encoding_id: Option<u32>, _schema: Option<&str>, _payload: &[u8]) {}
    fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
    fn clear_responder(&mut self) {}
    fn responder(&self) -> Option<(&[u8], u32)> {
        None
    }
}

struct ReplyCounter(&'static AtomicU32);
impl ReplySink for ReplyCounter {
    fn on_reply(&mut self, _reply: &dyn ReplyView) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn on_final(&mut self, _rid: u64) {}
}

struct DeclCounter(&'static AtomicU32);
impl DeclSink for DeclCounter {
    fn on_declared(&mut self, _decl: &dyn DeclView) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct UndeclCounter(&'static AtomicU32);
impl UndeclSink for UndeclCounter {
    fn on_undeclared(&mut self, _id: u64) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct LiveCounter(&'static AtomicU32);
impl LivelinessSampleSink for LiveCounter {
    fn on_sample(&mut self, _sample: LivelinessSample<'_>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Abort the run with a FAIL exit code + a semihost message naming the
/// stage. Returns only on success so `main` reads as a straight-line
/// sequence of checks.
fn require(stage: &str, ok: bool) {
    if !ok {
        hprintln!("R311ho FAIL: {} no-heap path did not succeed", stage);
        debug::exit(debug::EXIT_FAILURE);
    }
}

#[entry]
fn main() -> ! {
    // Each stage is scoped in its own block so its registry (a
    // `BoundedVec` over `BoundedString<MAX_KEYEXPR_BYTES>` backings — a
    // few KB each) is dropped before the next stage allocates, bounding
    // peak stack to the largest single stage. Without this the six
    // registries coexist and overflow a small MCU's RAM (the microbit /
    // Cortex-M0 16 KB had hardfaulted).
    {
        // 1. pub/sub — SubscriberRegistry no-heap fire.
        let mut subs: SubscriberRegistry<SampleCounter> = SubscriberRegistry::with_sink_backing();
        require(
            "pubsub register",
            subs.register_sink("home/temp", Locality::Any, SampleCounter(&SAMPLE_HITS))
                .is_ok(),
        );
        let sample_fired = subs.dispatch_borrowed(
            &BorrowedSample {
                keyexpr: "home/temp",
                payload: b"21.5",
                kind: SampleKind::Put,
                reliability: Reliability::BestEffort,
            },
            /* is_remote = */ true,
        );
        require(
            "pubsub",
            sample_fired == 1 && SAMPLE_HITS.load(Ordering::SeqCst) == 1,
        );
    }

    {
        // 2. query — QueryableRegistry no-heap fire (shared `&mut dyn ReplyOut`).
        let mut qs: QueryableRegistry<QueryCounter> = QueryableRegistry::with_sink_backing();
        require(
            "query register",
            qs.register_sink("svc/**", Locality::Any, QueryCounter(&QUERY_HITS))
                .is_ok(),
        );
        let mut out = NoopReplyOut;
        let query_fired = qs.dispatch_borrowed(
            &BorrowedQuery {
                keyexpr: "svc/a",
                parameters: None,
                attachment: None,
                // R311y248 — the query VALUE ext payload. Un-gated (the
                // `encoding` sibling is alloc-gated and absent on this no-alloc
                // probe, like `source_info`), so it must be set even here.
                payload: None,
                rid: 1,
                // `false` for wire dispatch (this is a remote query — `is_remote
                // = true` below); the query-source-info round added this field
                // to BorrowedQuery after this probe last named the struct.
                is_local: false,
            },
            &mut out,
            /* is_remote = */ true,
        );
        require(
            "query",
            query_fired == 1 && QUERY_HITS.load(Ordering::SeqCst) == 1,
        );
    }

    {
        // 3. reply — ReplyRegistry no-heap fire (rid correlation).
        let mut rr: ReplyRegistry<ReplyCounter> = ReplyRegistry::with_sink_backing();
        require(
            "reply register",
            rr.register_sink(7, 1, None, ReplyCounter(&REPLY_HITS))
                .is_ok(),
        );
        let reply_fired = rr.dispatch_borrowed(&BorrowedReply {
            rid: 7,
            keyexpr: "svc/a",
            kind: ReplyKind::Put,
            payload: b"v",
            err_encoding: None,
            // A8b — no value side-bands on this no-heap probe reply.
            attachment: None,
            put_encoding: None,
        });
        require(
            "reply",
            reply_fired == 1 && REPLY_HITS.load(Ordering::SeqCst) == 1,
        );
    }

    {
        // 4. declare observers — RemoteSubscriberRegistry decl + undecl fire.
        let mut rsub: RemoteSubscriberRegistry<DeclCounter, UndeclCounter> =
            RemoteSubscriberRegistry::with_sink_backing();
        require(
            "declare register",
            rsub.on_subscriber_declared_sink(DeclCounter(&DECL_HITS))
                .is_ok()
                && rsub
                    .on_subscriber_undeclared_sink(UndeclCounter(&UNDECL_HITS))
                    .is_ok(),
        );
        let decl_fired = rsub.dispatch_declared_borrowed(&BorrowedDecl {
            id: 3,
            keyexpr: "peer/sub",
        });
        let undecl_fired = rsub.dispatch_undeclared(3);
        require(
            "declare",
            decl_fired == 1
                && undecl_fired == 1
                && DECL_HITS.load(Ordering::SeqCst) == 1
                && UNDECL_HITS.load(Ordering::SeqCst) == 1,
        );
    }

    {
        // 5. liveliness subscriber — slot-table no-heap fire.
        let mut ls: LivelinessSubscriberRegistry<LiveCounter> =
            LivelinessSubscriberRegistry::with_sink_backing();
        require(
            "liveliness register",
            ls.register(1, "live/**", false, LiveCounter(&LIVE_HITS))
                .unwrap_or(false),
        );
        let live_fired = ls.dispatch_sample_borrowed(LivelinessSampleKind::Put, "live/dev/3", 9);
        require(
            "liveliness",
            live_fired == 1 && LIVE_HITS.load(Ordering::SeqCst) == 1,
        );
    }

    {
        // 6. local token declarer — R311ho no-heap interest response + EMIT.
        // The registry stages a borrowed interest-response (one `DeclToken`
        // per matching held token, then a terminating `DeclFinal`); this probe
        // plays the MCU `ResponseSink` and encodes each staged item into a
        // stack buffer through SCE's `SliceSink` — the wire emit with zero
        // global allocator (B's thesis: outbound emit, not just inbound fire,
        // is heap-free). A clean link + a non-zero encode position proves it.
        let mut lt = LocalTokenRegistry::new();
        require(
            "local-token register",
            lt.register(1, "group1/dev").unwrap_or(false),
        );
        let mut pending: BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }> =
            BoundedVec::new();
        let staged = lt.respond_to_interest_borrowed(Some("group1/**"), 42, &mut pending);
        require("local-token stage", staged == 1);
        let mut emitted: u32 = 0;
        for item in pending {
            // Build the full borrowed `Declare` envelope through the
            // single-source reply builders and encode it into a stack
            // `SliceSink` — the exact wire the MCU `ResponseSink` emits,
            // with zero global allocator.
            match item {
                DeclResponseItem::Token {
                    token_id,
                    interest_id,
                } => {
                    // Resolve the keyexpr from the registry (SSOT) — the
                    // staged item is id-only, mirroring the observer drain.
                    let keyexpr = match lt.keyexpr_for(token_id) {
                        Some(ke) => ke,
                        None => continue,
                    };
                    let decl = build_token_reply(token_id, keyexpr, interest_id);
                    let mut buf = [0u8; Declare::MAX_ENCODED_BYTES];
                    let mut sink = SliceSink::new(&mut buf);
                    require(
                        "local-token emit token",
                        decl.encode(&mut sink).is_ok() && sink.position() > 0,
                    );
                    emitted += 1;
                }
                DeclResponseItem::Final { interest_id } => {
                    let decl = build_final_reply(interest_id);
                    let mut buf = [0u8; Declare::MAX_ENCODED_BYTES];
                    let mut sink = SliceSink::new(&mut buf);
                    require(
                        "local-token emit final",
                        decl.encode(&mut sink).is_ok() && sink.position() > 0,
                    );
                    emitted += 1;
                }
            }
        }
        EMIT_HITS.store(emitted, Ordering::SeqCst);
        // 1 matching DeclToken + 1 terminating DeclFinal.
        require("local-token emit", EMIT_HITS.load(Ordering::SeqCst) == 2);
    }

    // Stage 7 is gated to the mps2-class cores (Cortex-M3/M4/M7). The
    // generated SCXML `Engine<ThermostatPolicy>` working set + the microstep
    // step() frames exceed the microbit / Cortex-M0's 16 KB RAM — running it
    // there underflows the stack ~80 KB past the RAM base (observed
    // SP=0x1ffce0d0 < 0x20000000 -> HardFault Lockup). The mps2 machines have
    // megabytes of RAM and host it comfortably. `target_has_atomic = "32"` is
    // the established repo discriminator for the M0-vs-rest split (mirrors
    // mcu-qemu-demo's sync-only fork); here it is a proxy for "has enough RAM
    // for the engine", not an atomics requirement (the registry stages 1-6
    // below remain unconditional and DO run on M0, proving the no-heap control
    // plane + emit there). The single-source -> MCU no-heap *value* path is
    // proven on M3/M4/M7.
    #[cfg(target_has_atomic = "32")]
    {
        // 7. switchboard wire-decode -> typed inject (ⓓ). The convergence of
        // the two tracks: a FOREIGN wire sample drives a generated SCE
        // statechart with ZERO global allocator. The xtask codegen SSOT ran
        // `sce-codegen --no-std` + wz-switchboard-codegen over the thermostat
        // triad (committed under out/mcu-noheap-probe/); here a `home/<x>/temp`
        // sample's wire bytes are decoded by the
        // generated codec (`SceCursor`, no VecSink) into the typed
        // `ThermostatTempReadingPayload { celsius_centi: u16 }` and injected
        // into a real `Engine<ThermostatPolicy>` via the generated dispatch's
        // `raise_temp_reading` seam. The native uint16 guard
        // (`celsius_centi > 3000`) then fires idle -> hot. Every link is
        // heap-free: the codec decode, the `Copy` payload, the inject seam, and
        // the heapless-backed Engine — so a clean no-allocator link + the
        // observed transitions prove the single-source -> MCU no-heap value
        // path end to end.
        use sce_rust_runtime::Engine;
        use thermostat::{ThermostatPolicy, ThermostatState};

        let mut engine = Engine::new(ThermostatPolicy::new());
        engine.initialize();
        require(
            "switchboard init",
            engine.get_current_state() == ThermostatState::Idle,
        );

        // 3500 centidegrees = 35.00 C, big-endian uint16 = [0x0D, 0xAC] —
        // above the 30.00 C (3000) native guard threshold. Hand-laid on the
        // stack (no allocator); a real publisher would encode the same bytes.
        let hot_wire = [0x0Du8, 0xACu8];
        let injected = dispatch_switchboard("home/livingroom/temp", &hot_wire, &mut engine);
        engine.step();
        require(
            "switchboard inject hot",
            injected == 1 && engine.get_current_state() == ThermostatState::Hot,
        );

        // The reset row is a SIGNAL binding (no codec): an empty _event.data
        // injected via `raise_external_by_name` returns hot -> idle.
        let reset_fired = dispatch_switchboard("home/livingroom/reset", &[], &mut engine);
        engine.step();
        require(
            "switchboard reset",
            reset_fired == 1 && engine.get_current_state() == ThermostatState::Idle,
        );

        // Discriminating check: a 2000-centidegree (20.00 C) reading is decoded
        // and injected (row fires) but MUST miss the `> 3000` guard, proving the
        // decoded value actually reaches the guard rather than the transition
        // firing unconditionally. 2000 = 0x07D0 big-endian = [0x07, 0xD0].
        let cold_wire = [0x07u8, 0xD0u8];
        let cold_fired = dispatch_switchboard("home/livingroom/temp", &cold_wire, &mut engine);
        engine.step();
        require(
            "switchboard inject cold",
            cold_fired == 1 && engine.get_current_state() == ThermostatState::Idle,
        );

        INJECT_HITS.store(1, Ordering::SeqCst);
    }
    #[cfg(target_has_atomic = "32")]
    require(
        "switchboard inject tally",
        INJECT_HITS.load(Ordering::SeqCst) == 1,
    );

    // The PASS banner reflects what actually ran on this target: the mps2
    // cores add the stage-7 switchboard inject proof; the M0 keeps the
    // registry + emit proof (stage 7 gated out for RAM — see above).
    #[cfg(target_has_atomic = "32")]
    hprintln!(
        "PASS: 7 registry no-heap fire paths + declarer-side SliceSink emit + generated switchboard wire-decode->typed-inject (Engine<ThermostatPolicy>) executed with zero global allocator"
    );
    #[cfg(not(target_has_atomic = "32"))]
    hprintln!(
        "PASS: 7 registry no-heap fire paths + declarer-side SliceSink emit executed with zero global allocator (switchboard inject stage gated off: engine working set exceeds this core's 16 KB RAM)"
    );
    debug::exit(debug::EXIT_SUCCESS);

    // `debug::exit` terminates QEMU; this loop only satisfies the `-> !`
    // signature for the (unreached) case where the semihost host does not
    // honour SYS_EXIT. `wfi` parks the core instead of spinning.
    loop {
        cortex_m::asm::wfi();
    }
}
