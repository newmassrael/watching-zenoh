// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Layer 3 wire-interop fixture — keyexpr canonicalization mirror.
//!
//! Cross-validation gate for the R221 claim that
//! `wz_runtime_tokio::keyexpr_canon::canonize_keyexpr` is functionally
//! equivalent to zenoh-pico's `_z_keyexpr_canonize`
//! (`vendor/zenoh-pico/src/session/keyexpr.c:313-433`). The wz module
//! doc-comment (`crates/wz-runtime-tokio/src/keyexpr_canon.rs:64-65`)
//! asserts the variant-name 1:1 mapping; this fixture closes the
//! empirical loop by calling **both** implementations on the same
//! input and asserting:
//!
//!   * success-side — the rewritten canonical strings are byte-equal
//!     **within the agreed subspace** (inputs that do not trigger
//!     any of the three known pico canon bugs documented below)
//!   * failure-side — single-violation inputs map to the same status
//!     code (`KeyexprCanonError` ↔ `zp_keyexpr_canon_status_t`)
//!   * divergence — three **wz/pico canon divergences** are surfaced
//!     and pinned by dedicated tests (`canon_known_pico_anomaly_*`)
//!     so a future round that upgrades pico or upstreams a fix
//!     trips the lock and forces a revisit
//!
//! ## Known wz/pico canon divergences (R299 findings)
//!
//! Both divergences live in pico's main-canonize rewrite loop, not in
//! the per-chunk validation pass (`__zp_canon_prefix`). The wz code is
//! the spec-correct reference; pico's outputs are surfaced as the
//! actual upstream behaviour for wire-interop honesty.
//!
//! 1. **`**` followed by `*`-shape chunk** — pico's `case 1: reader[0]
//!    == '*'` branch writes `*` unconditionally without consulting
//!    `in_big_wild`, then defers `in_big_wild` to the NEXT non-`*`
//!    chunk (which gets `**` re-emitted before its body). Wz drops
//!    the post-`**` `*` per the spec. Example: input `**/*` →
//!    wz=`**`, pico=`*/**`.
//!
//! 2. **Initial `$*` rewrite + any later chunk containing `*`** —
//!    pico's main-rewrite char-walk uses `c < end` instead of `c <
//!    chunk_end` so the per-chunk byte scan reads PAST the chunk
//!    boundary and flags a STARS_IN_CHUNK error from the next chunk's
//!    `*`. Wz processes chunks independently and accepts the input.
//!    Example: input `$*/a/*` → wz=Ok(`*/a/*`), pico=Err(-5).
//!
//! 3. **`**` + SINGLE-BYTE chunk(s) + `*` or `**`** — pico's
//!    `__zp_canon_prefix` case-1 branch (length-1 chunk that is NOT
//!    `*` while `in_big_wild=true`) takes the
//!    `else { advance; continue; }` path which SKIPS the post-walk
//!    `in_big_wild = false` reset. A subsequent `*`-shape chunk then
//!    re-enters with `in_big_wild` still true and returns
//!    `SINGLE_STAR_AFTER_DOUBLE_STAR` with
//!    `*len = (chunk_start_of_star - start) - 3` — a position that
//!    is NOT the start of a 2-byte chunk ending in `*` (it lands on
//!    the `/` between the literal and the `*`). Main canonize then
//!    fails the `chunk_end - reader == 2` precondition and triggers
//!    `assert(false)` at `keyexpr.c:340`, aborting the process via
//!    SIGABRT. Wz handles the same input cleanly.
//!    Example: input `**/c/*` → wz=Ok(`**/c/*`) (identity — the
//!    `**` only absorbs an IMMEDIATELY following `*`-shape chunk,
//!    not one separated by a literal), pico=SIGABRT.
//!
//!    R311y544 — "SINGLE-BYTE" is load-bearing and this paragraph used
//!    to say "literal chunk". Only `case 1:` reaches the reset-skipping
//!    branch, so a chunk of length >= 2 that is not `**` falls through
//!    to the char-walk and CLOSES the window (`keyexpr.c:206`).
//!    Measured, not read: `canon_pico_abort_family_is_single_byte_chunks_only_measured`
//!    runs the real canonizer in a subprocess and pins `**/ab/*` as
//!    healthy next to `**/a/*` as an abort. The paragraph below said
//!    this case "cannot be cross-validated at runtime"; that is true
//!    only IN-PROCESS, and the subprocess probe is the whole fix.
//!
//! Both bugs #1/#2 produce wrong outputs (wire-interop divergence);
//! bug #3 ABORTS the process (denial-of-service risk if a wz peer
//! sends such a keyexpr to a pico client). All three are surfaced
//! here for production wire-interop visibility; the fix decision
//! (track pico's buggy output in wz, add an inbound normalization
//! shim, or upstream a patch to zenoh-pico) is deferred to a future
//! round.

use std::os::raw::c_char;

use proptest::prelude::*;
// R311y544 — the outbound gate under differential test lives in
// wz-session-core; the canon it wraps is re-exported through
// wz-runtime-tokio, which is where the rest of this fixture reaches it.
use wz_runtime_tokio::keyexpr_canon::{canonize_keyexpr, KeyexprCanonError};
use wz_session_core::keyexpr_canon::{check_outbound_keyexpr_pico_safe, OutboundKeyexprError};

/// Invoke zenoh-pico's `_z_keyexpr_canonize` against a writable copy
/// of `input`. Returns the canonical rewritten string on SUCCESS, or
/// the negative status code on a grammar violation.
///
/// `*len` carries the canonical-input byte length and never grows
/// (singleify shrinks; lone-`$*` → `*` shrinks by 1; drop-after-`**`
/// shrinks by 3; verbatim passthrough is same-length), so the result
/// always fits the input range and the truncate-on-success step scopes
/// the returned string to it.
///
/// The buffer MUST be NUL-terminated even though `*len` is supplied:
/// `_z_keyexpr_canonize` scans chunk boundaries with `strchr`
/// (`keyexpr.c:326`) and `_z_str_startswith` (`string.c`), both of
/// which read to a NUL terminator irrespective of `*len`. A buffer of
/// exactly `input.len()` bytes makes those reads run past its end (UB —
/// a rare SIGSEGV when the allocation abuts an unmapped page, which
/// surfaced as a flaky Layer C1 segfault under the parallel `cargo
/// test`; valgrind flags it deterministically as "Invalid read of size
/// 1" at `keyexpr.c:326` / `string.c:145`). The trailing NUL bounds
/// every internal scan; `len` excludes it, and canon's shrink-only
/// contract means the NUL slot is never written.
fn zenoh_pico_canonize(input: &str) -> Result<String, i32> {
    let mut buf: Vec<u8> = Vec::with_capacity(input.len() + 1);
    buf.extend_from_slice(input.as_bytes());
    buf.push(0);
    let mut len: usize = input.len();
    let status = unsafe {
        zenoh_pico_sys::_z_keyexpr_canonize(buf.as_mut_ptr() as *mut c_char, &mut len as *mut usize)
    };
    if status == 0 {
        buf.truncate(len);
        Ok(String::from_utf8(buf).expect("canonize output is valid UTF-8 when input is"))
    } else {
        Err(status as i32)
    }
}

/// Map wz `KeyexprCanonError` → pico `zp_keyexpr_canon_status_t`
/// numeric value, per the 1:1 mapping recorded in the wz module
/// doc-comment.
fn wz_error_to_pico_status(err: &KeyexprCanonError) -> i32 {
    match err {
        KeyexprCanonError::EmptyChunk => -4,
        KeyexprCanonError::StarsInChunk => -5,
        KeyexprCanonError::DollarAfterDollarOrStar => -6,
        KeyexprCanonError::ContainsSharpOrQmark => -7,
        KeyexprCanonError::ContainsUnboundDollar => -8,
        // R311gb — `ExceedsCapacity` is a wz-side no-alloc-only variant
        // (no zenoh-pico mirror) returned only when the bounded canon
        // buffer overflows on the MCU backing. This cross-validation
        // runs on the host alloc backing, where it is never produced.
        KeyexprCanonError::ExceedsCapacity => {
            unreachable!("ExceedsCapacity is unreachable on the host alloc backing")
        }
    }
}

/// Assert wz and zenoh-pico agree on `input` — same canonical output
/// on success, same status code on failure. Use only for inputs that
/// do NOT trigger one of the documented pico canon bugs; divergent
/// inputs live in `canon_known_pico_anomaly_*`.
#[track_caller]
fn assert_agree(input: &str) {
    let wz_result = canonize_keyexpr(input);
    let pico_result = zenoh_pico_canonize(input);
    match (&wz_result, &pico_result) {
        (Ok(wz_out), Ok(pico_out)) => {
            // R311gb — wz canon now returns `BoundedString`; compare by
            // string content against pico's `String`.
            assert_eq!(
                wz_out.as_str(),
                pico_out.as_str(),
                "canonize output mismatch: `{}` → wz=`{}`, pico=`{}`",
                input,
                wz_out,
                pico_out,
            );
        }
        (Err(wz_err), Err(pico_status)) => {
            let expected = wz_error_to_pico_status(wz_err);
            assert_eq!(
                expected, *pico_status,
                "canonize status mismatch: `{}` → wz={:?} (→ {}), pico={}",
                input, wz_err, expected, pico_status,
            );
        }
        (Ok(wz_out), Err(pico_status)) => {
            panic!(
                "canonize accept/reject divergence: `{}` → wz=Ok(`{}`), pico=Err({})",
                input, wz_out, pico_status,
            );
        }
        (Err(wz_err), Ok(pico_out)) => {
            panic!(
                "canonize accept/reject divergence: `{}` → wz=Err({:?}), pico=Ok(`{}`)",
                input, wz_err, pico_out,
            );
        }
    }
}

// ── R311y544 — the SUBPROCESS abort probe ──────────────────────
//
// `canon_known_pico_anomaly_double_star_literal_star_aborts` below says
// "We CANNOT cross-validate this case at runtime — pico aborts the
// entire process, which would also kill the test binary", and then
// documents the pico side ANALYTICALLY. That is true of an in-process
// call and false of the claim: a subprocess can carry the abort. The
// harness below re-execs THIS test binary against a single input and
// reports which of the three outcomes pico actually produced, so the
// bug-#3 family membership is a measurement rather than a reading.
//
// It matters because `check_outbound_keyexpr_pico_safe`'s doc asserts
// the trigger fires on multi-char literals too ("Empirically … `**/foo/*`,
// `**/abc/*/def`") and cites this fixture as the evidence — a fixture
// that never called pico on them.

/// The env var carrying the probe input to the re-exec'd child.
const PICO_CANON_PROBE_ENV: &str = "WZ_PICO_CANON_PROBE_INPUT";

/// Exit code the child uses for "pico's canonize returned SUCCESS".
const PICO_PROBE_EXIT_OK: i32 = 10;
/// Exit code the child uses for "pico's canonize returned a status code".
const PICO_PROBE_EXIT_ERR: i32 = 11;
/// Separates libtest's own `--nocapture` banner from the child's payload.
/// The child runs INSIDE a test body, so libtest has already written
/// "\nrunning 1 test\n" to the same stdout by the time the payload lands.
const PICO_PROBE_MARKER: &str = "<<<WZ-PICO-CANON-PROBE>>>";

/// What a real `_z_keyexpr_canonize` did with one input, observed from
/// outside the process so that an `assert(false)` is data rather than a
/// dead test binary.
#[derive(Debug, PartialEq, Eq)]
enum PicoCanonOutcome {
    /// Returned `Z_KEYEXPR_CANON_SUCCESS` with this canonical output.
    Success(String),
    /// Returned a negative `zp_keyexpr_canon_status_t`.
    Status(i32),
    /// Died on a signal — `assert(false)` raises `SIGABRT` (6).
    Signal(i32),
}

/// The child half of the probe: called by the re-exec'd binary when
/// [`PICO_CANON_PROBE_ENV`] is set. Never returns.
fn pico_canon_probe_child(input: &str) -> ! {
    use std::io::Write as _;
    match zenoh_pico_canonize(input) {
        Ok(out) => {
            print!("{PICO_PROBE_MARKER}{out}");
            std::io::stdout().flush().ok();
            std::process::exit(PICO_PROBE_EXIT_OK);
        }
        Err(status) => {
            print!("{PICO_PROBE_MARKER}{status}");
            std::io::stdout().flush().ok();
            std::process::exit(PICO_PROBE_EXIT_ERR);
        }
    }
}

/// Run pico's `_z_keyexpr_canonize` on `input` inside a fresh process
/// and report the outcome.
///
/// The child is this same test binary re-exec'd with the probe env var
/// set; the `#[test]` that observes the var short-circuits into
/// [`pico_canon_probe_child`] before libtest can start, so no test body
/// runs there and the process is free to abort.
fn probe_pico_canon(input: &str) -> PicoCanonOutcome {
    use std::os::unix::process::ExitStatusExt as _;

    let exe = std::env::current_exe().expect("test binary path");
    let out = std::process::Command::new(exe)
        // Name the child test EXACTLY so libtest does not fan out into
        // the rest of this file inside the child.
        .args([
            "--exact",
            "pico_canon_subprocess_probe_entry",
            "--nocapture",
        ])
        .env(PICO_CANON_PROBE_ENV, input)
        .output()
        .expect("re-exec the test binary as a canon probe");

    let raw = String::from_utf8_lossy(&out.stdout).to_string();
    // Everything after the marker is the child's payload; everything
    // before it is libtest's `--nocapture` banner.
    let payload = raw
        .split_once(PICO_PROBE_MARKER)
        .map(|(_, tail)| tail.to_string());
    match (out.status.code(), out.status.signal()) {
        (Some(PICO_PROBE_EXIT_OK), _) => {
            PicoCanonOutcome::Success(payload.expect("the OK child writes the marker"))
        }
        (Some(PICO_PROBE_EXIT_ERR), _) => PicoCanonOutcome::Status(
            payload
                .expect("the ERR child writes the marker")
                .trim()
                .parse()
                .expect("the child prints the raw status code"),
        ),
        (_, Some(sig)) => PicoCanonOutcome::Signal(sig),
        (code, _) => panic!(
            "canon probe child for `{input}` exited {code:?} without reaching either \
             probe exit; stdout=`{raw}`, stderr=`{}`",
            String::from_utf8_lossy(&out.stderr),
        ),
    }
}

/// The re-exec target. In the PARENT (no env var) this is a self-test of
/// the harness: it asserts that the probe can carry each of the three
/// outcomes, which is what makes a `Success` verdict elsewhere in this
/// file mean something. Without it a probe that silently reported
/// `Success` for everything would pass every abort test
/// (`feedback_a_vacuous_proof_passes_on_absence`).
// wz-proves: none -- harness self-test; calibrates `probe_pico_canon` on all
// three outcomes so the tests that USE it are not vacuous. It witnesses no atom
// of its own; the atoms are witnessed by its callers.
#[test]
fn pico_canon_subprocess_probe_entry() {
    if let Ok(input) = std::env::var(PICO_CANON_PROBE_ENV) {
        pico_canon_probe_child(&input);
    }

    // Outcome 1 — a plain canonical input round-trips through the child.
    assert_eq!(
        probe_pico_canon("home/temp"),
        PicoCanonOutcome::Success("home/temp".to_string()),
    );
    // Outcome 2 — a grammar violation comes back as its status code
    // (`Z_KEYEXPR_CANON_EMPTY_CHUNK` = -4) rather than as a signal.
    assert_eq!(probe_pico_canon("a//b"), PicoCanonOutcome::Status(-4));
    // Outcome 3 — the probe can OBSERVE an abort. `**/c/*` is the R299
    // bug-#3 witness; if pico is ever fixed this flips and the
    // divergence lock below is what forces the revisit.
    assert_eq!(
        probe_pico_canon("**/c/*"),
        PicoCanonOutcome::Signal(libc::SIGABRT),
        "the probe must be able to carry a SIGABRT, or every abort \
         assertion in this file is vacuous",
    );
}

/// Capture both implementations' output without panicking on
/// mismatch, so the divergence-locking tests can assert against
/// the SPECIFIC byte-different outputs each side produces.
fn capture_both(input: &str) -> (Result<String, KeyexprCanonError>, Result<String, i32>) {
    // R311gb — wz canon now returns a `BoundedString` (no-alloc core);
    // stringify for byte-parity comparison against pico's `String`.
    (
        canonize_keyexpr(input).map(|c| c.as_str().to_string()),
        zenoh_pico_canonize(input),
    )
}

// ── Handcrafted corpus — agreed subspace ───────────────────────

// wz-proves: keyexpr-canon codec-parity partial
#[test]
fn canon_identity_on_already_canonical_input() {
    // No-op path: input survives byte-for-byte through both
    // implementations. Pure literals, single `*`, double `**` (alone
    // or at end), intra-chunk `$*` DSL chunks.
    assert_agree("home/temp");
    assert_agree("sensors/room1/temp");
    assert_agree("home/*/temp");
    assert_agree("home/**");
    assert_agree("**/temp");
    assert_agree("home/**/temp");
    assert_agree("home/$*foo$*");
    assert_agree("a");
    assert_agree("a/b/c/d/e");
}

// wz-proves: keyexpr-canon codec-parity partial
#[test]
fn canon_singleify_collapses_dollar_star_runs_in_dsl_chunks() {
    // `$*$*` and longer runs collapse to a single `$*` in chunks
    // that ALSO carry literal anchors — these don't hit pico bug #2
    // because the rewrite chunk stays a Mixed DSL chunk (no `$*`-
    // alone lift, no later chunks with `*`).
    assert_agree("home/foo$*$*bar");
    assert_agree("home/$*$*foo");
    assert_agree("home/foo$*$*$*bar");
}

// wz-proves: keyexpr-canon codec-parity partial
#[test]
fn canon_lone_dollar_star_alone() {
    // Lone `$*` chunk lifts to `*`. Standalone or as a trailing
    // chunk with no further chunks containing `*` — avoids pico
    // bug #2 (char-walk overrun).
    assert_agree("$*");
    assert_agree("a/$*");
    assert_agree("home/temp/$*");
    assert_agree("a/b/c/$*");
}

// wz-proves: keyexpr-canon codec-parity partial
#[test]
fn canon_drops_double_star_after_double_star() {
    // `**/**` collapses to one `**`. Both sides handle this
    // consistently — the rewrite occurs before the post-`**`
    // walker, so bug #1's `in_big_wild` deferral path never fires
    // for `**` chunks themselves.
    assert_agree("home/**/**/temp");
    assert_agree("**/**");
    assert_agree("**/**/**");
    assert_agree("a/**/**/**/b");
}

// wz-proves: keyexpr-canon codec-parity partial
#[test]
fn canon_rejects_invalid_grammar_single_violation() {
    // Each input has EXACTLY ONE grammar violation so wz's chunk-
    // walk and pico's byte-walk hit the same first error — pinning
    // the 1:1 KeyexprCanonError ↔ zp_keyexpr_canon_status_t map.
    // Multi-violation inputs (e.g. `$*/#bad/`) hit different first
    // errors and are not in scope for the status-code lock.
    assert_agree("home//temp"); // EmptyChunk
    assert_agree("home/foo#bar"); // ContainsSharpOrQmark
    assert_agree("home/foo?bar"); // ContainsSharpOrQmark
    assert_agree("home/foo$"); // ContainsUnboundDollar
    assert_agree("home/foo$bar"); // ContainsUnboundDollar
    assert_agree("home/foo*bar"); // StarsInChunk
    assert_agree("home/***"); // StarsInChunk
    assert_agree("home/$$"); // DollarAfterDollarOrStar
    assert_agree("home/foo$*$"); // DollarAfterDollarOrStar
}

// ── The star-after-double-star run: a CLOSED divergence ────────

/// R311y564 — these five inputs were pinned here as "Pico bug #1", a
/// deliberate divergence in which wz DROPPED a `*` that followed a `**` and
/// pico re-ordered it. The pin recorded pico's answers correctly. What it got
/// wrong was which side was right: the same probe run against the real
/// `libzenohc.so` — a third implementation, and zenoh's reference one — gives
/// pico's answer, not wz's, on every case.
///
/// The two forms are not two spellings of one keyexpr. `a/**/b` matches `a/b`;
/// `a/**/*/b` requires at least one chunk between them. So wz was WIDENING
/// every keyexpr of this shape — on the wire and in both C ABIs — and a pinned
/// divergence is exactly what kept it invisible: the assertion passed every run
/// while asserting the defect.
///
/// The cases now assert AGREEMENT, which is why they moved out of the
/// divergence section. `**/$*`-shaped inputs are included deliberately: that is
/// the one sub-case where zenoh-c and pico themselves disagree, and wz's
/// default dialect is pico's, so agreement here is the stronger claim.
// wz-proves: keyexpr-canon codec-parity partial
#[test]
fn canon_agrees_with_pico_on_a_star_after_a_double_star() {
    assert_agree("**/*");
    assert_agree("home/**/*/temp");
    assert_agree("**/$*/temp");
    assert_agree("**/$*");
    assert_agree("**/$*$*/temp");
    assert_agree("a/**/*/*/b");
}

// wz-proves: none -- pico SIGABRTs on these inputs; no foreign call, wz-side only
#[test]
fn canon_known_pico_anomaly_double_star_literal_star_aborts() {
    // Pico bug #3: `**` + literal + `*` triggers SIGABRT via
    // `assert(false)` at keyexpr.c:340 — `__zp_canon_prefix`'s
    // case-1 else-continue path skips the in_big_wild reset, so
    // a subsequent `*` returns SINGLE_STAR_AFTER_DOUBLE_STAR with
    // a `*len` value pointing at the `/` between the literal and
    // the `*` (not at a 2-byte `**` chunk as the main rewrite
    // requires).
    //
    // We CANNOT cross-validate this case at runtime — pico aborts
    // the entire process, which would also kill the test binary.
    // So we only verify wz's behaviour (identity on these inputs —
    // `**` only absorbs an IMMEDIATELY following `*`-shape chunk,
    // not one separated by a literal) and document the pico side
    // analytically. The proptest strategy filters this pattern out
    // (no `**` followed anywhere later by a `*`-shape chunk) so
    // random fuzz does not trip the assert and abort the binary.
    // R311gb — wz canon returns `BoundedString`; assert the unwrapped
    // value against the expected literal (`BoundedString: PartialEq<&str>`).
    assert_eq!(canonize_keyexpr("**/c/*").unwrap(), "**/c/*");
    assert_eq!(canonize_keyexpr("**/foo/*").unwrap(), "**/foo/*");
    assert_eq!(canonize_keyexpr("**/abc/*/def").unwrap(), "**/abc/*/def");
    assert_eq!(canonize_keyexpr("**/a/b/*").unwrap(), "**/a/b/*");
}

// wz-proves: keyexpr-canon codec-parity partial
#[test]
fn canon_pico_abort_family_is_single_byte_chunks_only_measured() {
    // R311y544 — the MEASUREMENT the test above says cannot be taken.
    // It can; it just needs a subprocess. See `probe_pico_canon`.
    //
    // The claim under test is the one `check_outbound_keyexpr_pico_safe`
    // rests its gate on: "the trigger fires on multi-char literals as
    // well (`**/foo/*`, `**/abc/*/def`), not only the documented
    // single-char case", cited to the fixture above — which never called
    // pico on them. pico's `__zp_canon_prefix` reaches the
    // reset-skipping `else { advance; continue; }` ONLY from
    // `case 1:` (`keyexpr.c:130-138`), i.e. only for a chunk of length
    // ONE. A chunk of length >= 2 that is not `**` falls through to the
    // char-walk and executes `in_big_wild = false` (`keyexpr.c:206`),
    // closing the window.
    //
    // Each row is (input, what a real `_z_keyexpr_canonize` does).
    let cases: &[(&str, PicoCanonOutcome)] = &[
        // ── the window OPENS on single-byte chunks and aborts ──
        ("**/c/*", PicoCanonOutcome::Signal(libc::SIGABRT)),
        ("**/a/b/*", PicoCanonOutcome::Signal(libc::SIGABRT)),
        // …and the closer may be `**` as well as `*`, via
        // DOUBLE_STAR_AFTER_DOUBLE_STAR taking the same rewrite path.
        ("**/c/**", PicoCanonOutcome::Signal(libc::SIGABRT)),
        // ── a chunk of length >= 2 CLOSES the window: no abort ──
        // These two are the exact strings the gate's doc calls
        // empirical aborts. They are not.
        (
            "**/foo/*",
            PicoCanonOutcome::Success("**/foo/*".to_string()),
        ),
        (
            "**/abc/*/def",
            PicoCanonOutcome::Success("**/abc/*/def".to_string()),
        ),
        // The BOUNDARY of the new rule: length 2 is already enough to
        // reach the char-walk and reset `in_big_wild`. One byte fewer
        // (`**/a/*`) aborts.
        ("**/ab/*", PicoCanonOutcome::Success("**/ab/*".to_string())),
        ("**/a/*", PicoCanonOutcome::Signal(libc::SIGABRT)),
        // An opened window can be CLOSED again by a later long chunk,
        // so "did a single-byte chunk ever appear" is not the rule —
        // "is one still open at the closer" is.
        (
            "**/a/foo/*",
            PicoCanonOutcome::Success("**/a/foo/*".to_string()),
        ),
        // ── no intervening chunk at all: the rewrite is well-formed,
        //    so this is bug #1 (wrong output), not bug #3 (abort) ──
        ("**/*", PicoCanonOutcome::Success("*/**".to_string())),
        ("**/**", PicoCanonOutcome::Success("**".to_string())),
        // ── a `$*` closer takes the LONE_DOLLAR_STAR branch, whose
        //    `*len` points AT the `$*` chunk, so it does not abort ──
        ("**/c/$*", PicoCanonOutcome::Success("**/c/*".to_string())),
    ];

    for (input, expected) in cases {
        assert_eq!(
            &probe_pico_canon(input),
            expected,
            "pico's real canon outcome for `{input}` changed — upstream may \
             have fixed or widened R299 bug #3; the outbound gate \
             (`check_outbound_keyexpr_pico_safe`) is calibrated against \
             exactly this table and must be re-derived",
        );
    }
}

// wz-proves: keyexpr-canon codec-parity partial
#[test]
fn outbound_pico_safe_gate_rejects_exactly_what_pico_aborts_on() {
    // R311y544 — the gate is a CLAIM about a foreign process, so prove
    // it against that process rather than against its own doc comment.
    //
    // Enumerate every keyexpr over a chunk alphabet chosen to cover
    // each branch of pico's `__zp_canon_prefix` switch — a length-1
    // literal (`case 1`, the only reset-skipping path), a length-2
    // literal (the boundary), a longer literal, `*`, `**` and `$*` —
    // then require, for each, that
    //
    //     check_outbound_keyexpr_pico_safe(ke).is_err()
    //         <=> a real `_z_keyexpr_canonize(ke)` dies on a signal.
    //
    // Both directions matter. `=>` is the safety property the gate
    // exists for. `<=` is the one R311y543 lacked: an over-broad gate
    // silently disabled the advanced subscriber's whole recovery plane
    // for the commonest base keyexpr in the world.
    const CHUNKS: &[&str] = &["a", "ab", "foo", "*", "**", "$*", "$*$*", "x$*y"];

    // Every string any wz-side unit test asserts a verdict for, so the
    // unit tests are backed by this measurement rather than by a reading
    // of pico's source.
    const UNIT_TEST_STRINGS: &[&str] = &[
        "**/c/*",
        "**/foo/*",
        "**/abc/*/def",
        "**/a/b/*",
        "**/c/**",
        "**/c/$*",
        "**/c/$*$*",
        "**/foo$*bar",
        "**/foo$*bar/temp",
        "**/foo$*bar/*",
        "**/a/**",
        "**/a/**/b",
        "**/a/**/b/*",
        "**/*",
        "**/**",
        "**/$*",
        "**/$*/temp",
        "home/**/*/temp",
    ];

    let mut corpus: Vec<String> = UNIT_TEST_STRINGS.iter().map(|s| s.to_string()).collect();
    for a in CHUNKS {
        for b in CHUNKS {
            corpus.push(format!("{a}/{b}"));
            for c in CHUNKS {
                corpus.push(format!("{a}/{b}/{c}"));
            }
        }
    }
    // The @adv-shaped tail, which is the whole reason this gate is
    // being re-derived: a `**`-tailed base plus the derived namespace.
    for a in CHUNKS {
        for b in CHUNKS {
            corpus.push(format!("{a}/**/@adv/pub/{b}"));
            corpus.push(format!("{a}/{b}/**/@adv/pub/**"));
        }
    }

    let mut checked = 0usize;
    let mut rejected = 0usize;
    let mut aborting = 0usize;
    for ke in &corpus {
        // Inputs the grammar itself refuses are out of scope: the gate
        // reports NotCanonical for them and never reaches the bug walk.
        let verdict = check_outbound_keyexpr_pico_safe(ke);
        if matches!(verdict, Err(OutboundKeyexprError::NotCanonical(_))) {
            continue;
        }
        checked += 1;
        let gate_rejects = verdict.is_err();
        let outcome = probe_pico_canon(ke);
        let pico_aborts = matches!(outcome, PicoCanonOutcome::Signal(_));
        if gate_rejects {
            rejected += 1;
        }
        if pico_aborts {
            aborting += 1;
        }
        assert_eq!(
            gate_rejects,
            pico_aborts,
            "`{ke}`: check_outbound_keyexpr_pico_safe says {}, a real \
             zenoh-pico says {outcome:?}",
            if gate_rejects { "REFUSE" } else { "allow" },
        );
    }

    // Guard against a vacuous pass: the corpus must actually exercise
    // both verdicts, or the equality above holds for free.
    assert!(
        checked > 200,
        "corpus collapsed to {checked} canonical inputs",
    );
    assert!(aborting > 0, "no input in the corpus aborts a real pico");
    assert_eq!(
        rejected, aborting,
        "the two counters are the same quantity measured from each side",
    );
}

// wz-proves: keyexpr-canon codec-parity partial
#[test]
fn canon_derived_adv_keyexprs_do_not_abort_pico() {
    // R311y544 — the consequence half of the exclusion, measured.
    //
    // wz's advanced subscriber derives three `@adv` channels from its
    // base keyexpr, and for a `**`-tailed base all three were refused by
    // `check_outbound_keyexpr_pico_safe` on the grounds that they would
    // SIGABRT a real zenoh-pico peer. They do not, and they structurally
    // cannot: the chunk immediately following the base's trailing `**`
    // is always `@adv`, four bytes, which closes pico's window.
    //
    // Upstream's own `z_advanced_sub.c` defaults to `demo/example/**`,
    // so these are the COMMON derived forms, not edge cases.
    let derived: &[&str] = &[
        // heartbeat / late-publisher detection subscriber
        "demo/example/**/@adv/pub/**",
        "**/@adv/pub/**",
        "a/**/@adv/pub/**",
        // startup history GET
        "demo/example/**/@adv/**",
        // sample-driven recovery GET (`<zid>` hex, `<eid>` decimal —
        // the single-digit eid is deliberate: it is a length-1 chunk,
        // and the point is that it lands AFTER the window has closed)
        "demo/example/**/@adv/*/a0b1c2d3e4f5/1/**",
    ];
    for ke in derived {
        assert_eq!(
            probe_pico_canon(ke),
            PicoCanonOutcome::Success((*ke).to_string()),
            "`{ke}` is a keyexpr wz's advanced subscriber must be able to \
             put on the wire; a real zenoh-pico canonizes it to itself",
        );
    }
}

// wz-proves: none -- pins a wz/pico DIVERGENCE (wz Ok vs pico Err)
#[test]
fn canon_known_pico_anomaly_dsl_rewrite_chunk_walk_overrun() {
    // Pico bug #2: the main-canonize char-walk uses `c < end`
    // instead of `c < chunk_end`, so any `*` in a LATER chunk
    // trips STARS_IN_CHUNK on the FIRST post-rewrite chunk's
    // validation pass. Triggers when:
    //
    //   (a) canon_prefix returns a rewrite code (LONE_DOLLAR_STAR
    //       or one of the *_AFTER_DOUBLE_STAR variants — i.e. the
    //       input has a `$*` chunk OR `**` adjacency near the
    //       start), AND
    //   (b) a LATER chunk (after at least one non-`*` chunk that
    //       falls through case 1 / default to the char-walk)
    //       contains any `*`.
    //
    // Wz processes chunks independently and accepts. Pinning the
    // Err(-5) outputs locks the bug.
    let cases: &[(&str, &str, i32)] = &[
        ("$*/a/*", "*/a/*", -5),
        ("$*$*/a/*", "*/a/*", -5),
        ("$*/a/b/*", "*/a/b/*", -5),
    ];
    for (input, wz_expected, pico_expected_status) in cases {
        let (wz, pico) = capture_both(input);
        assert_eq!(
            wz.as_deref(),
            Ok(*wz_expected),
            "wz canon shape changed for `{}`",
            input,
        );
        assert_eq!(
            pico,
            Err(*pico_expected_status),
            "pico canon shape changed for `{}` (upstream may have fixed bug #2 — \
             revisit the R299 divergence carry)",
            input,
        );
    }
}

// ── R299b property fuzz layer ───────────────────────────────────
//
// Random canonical keyexpr generator + property assertion that
// wz/pico agree on byte-equal output. The strategy is constrained
// to the AGREED subspace:
//
//   * inputs are pre-canonical (avoid singleify and rewrite paths
//     that trigger pico bug #2 char-walk overrun)
//   * `**` chunks are never followed by `*`-shape chunks (avoid
//     pico bug #1 in_big_wild deferral)
//
// The handcrafted corpus above + the divergence-lock tests pin the
// behaviour outside this subspace; the property exists to surface
// any THIRD divergence that random fuzz turns up.

/// Single character drawn from the bounded `[a, b, c]` alphabet.
fn alpha_char_strategy() -> impl Strategy<Value = char> {
    prop::sample::select(vec!['a', 'b', 'c'])
}

/// Bounded-length literal string `[a-c]{min..=max}`.
fn lit_strategy(min: usize, max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(alpha_char_strategy(), min..=max)
        .prop_map(|chars| chars.into_iter().collect())
}

/// Pre-canonical `$*`-DSL chunk: chunks with a single `$*` run
/// flanked by literal anchors (lead OR trail must be non-empty so
/// the chunk is NOT a lone `$*` — that lifts to `*` and triggers
/// the rewrite path).
fn dsl_chunk_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // lead $* trail — at least one of lead/trail non-empty
        (lit_strategy(1, 2), lit_strategy(0, 2))
            .prop_map(|(lead, trail)| format!("{}$*{}", lead, trail)),
        (lit_strategy(0, 2), lit_strategy(1, 2))
            .prop_map(|(lead, trail)| format!("{}$*{}", lead, trail)),
    ]
}

/// Per-chunk strategy: weighted union over literal / `*` / `**` /
/// flanked-DSL. NO `$*`-alone chunk (would lift to `*` and bump
/// canon_prefix into the rewrite path).
fn chunk_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => lit_strategy(1, 3),
        1 => Just("*".to_string()),
        1 => Just("**".to_string()),
        3 => dsl_chunk_strategy(),
    ]
}

/// Full canonical keyexpr — 1..=4 chunks joined by `/`. Post-
/// process strips known pico-divergence patterns:
///
///   * any `**` chunk → drop ALL subsequent chunks whose first
///     byte is `*` or `$` (pico bug #1) OR `*`-shape after any
///     literal that follows the `**` (pico bug #3, which aborts
///     the process via SIGABRT)
///
/// Simplest safe constraint: once a `**` chunk appears, drop every
/// later chunk that is exactly `*` or starts with `$` or is `**`.
/// Literal-only tails are safe. Equivalent: keep `**` only as the
/// final chunk OR followed exclusively by Mixed/literal chunks.
fn keyexpr_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(chunk_strategy(), 1..=4).prop_map(|chunks| {
        let mut canonical: Vec<String> = Vec::with_capacity(chunks.len());
        let mut seen_double_star = false;
        for c in chunks {
            if seen_double_star {
                // After a `**` anywhere in the keyexpr, drop any
                // `*`-shape or `$*`-DSL chunk to avoid pico bugs
                // #1 and #3. Mixed literal chunks are safe.
                if c == "*" || c == "**" || c.starts_with('$') {
                    continue;
                }
            }
            if c == "**" {
                seen_double_star = true;
            }
            canonical.push(c);
        }
        canonical.join("/")
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        ..ProptestConfig::default()
    })]

    /// wz/zenoh-pico canonize cross-validation under random
    /// canonical input. The generator pre-filters known pico
    /// divergences so within the AGREED subspace the two impls
    /// must return byte-equal output. A failure would mean a
    /// THIRD divergence class — the property is the gate for it.
    // wz-proves: keyexpr-canon codec-parity partial
    #[test]
    fn keyexpr_canon_wz_pico_property(input in keyexpr_strategy()) {
        let wz_result = canonize_keyexpr(&input);
        let pico_result = zenoh_pico_canonize(&input);
        match (&wz_result, &pico_result) {
            (Ok(wz_out), Ok(pico_out)) => {
                prop_assert_eq!(
                    wz_out.as_str(),
                    pico_out.as_str(),
                    "canonize output mismatch: `{}` → wz=`{}`, pico=`{}`",
                    &input, wz_out, pico_out,
                );
            }
            (Err(wz_err), Err(pico_status)) => {
                let expected = wz_error_to_pico_status(wz_err);
                prop_assert_eq!(
                    expected, *pico_status,
                    "canonize status mismatch: `{}` → wz={:?} (→ {}), pico={}",
                    &input, wz_err, expected, pico_status,
                );
            }
            (Ok(wz_out), Err(pico_status)) => {
                prop_assert!(
                    false,
                    "canonize accept/reject divergence: `{}` → wz=Ok(`{}`), pico=Err({})",
                    &input, wz_out, pico_status,
                );
            }
            (Err(wz_err), Ok(pico_out)) => {
                prop_assert!(
                    false,
                    "canonize accept/reject divergence: `{}` → wz=Err({:?}), pico=Ok(`{}`)",
                    &input, wz_err, pico_out,
                );
            }
        }
    }
}
