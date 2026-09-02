// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — the DROP-IN census: which programs cannot even be
//! attempted against wz's zenoh-c cdylib.
//!
//! ## Why this file exists, and why its absence was the finding
//!
//! The sibling ABI has had `pico_abi_symbol_census.rs` since R311y559 and it
//! reports 659 of 659. This ABI had NO census at all, and the reason is written
//! into `wz-capi-c`'s own crate docs: its scope rule is an upstream PROGRAM, not
//! a symbol list, adopted because a hand-picked list drafted before measuring
//! named four symbols zenoh-c never calls and missed three it does.
//!
//! That rule is right about which BEHAVIOUR to build next and silent about a
//! different question. A census answers the other one: a symbol the real library
//! DEFINES and wz does not is a program that fails at LINK time — no behaviour to
//! compare, no differential to write, and invisible to every corpus leg, because
//! those legs drive the exports wz happens to have. When this file was first run
//! it reported **317** missing public symbols against a corpus report of 29 of 29
//! examples linking. Both numbers were true; they measure different things.
//!
//! So the two gates are complementary and neither subsumes the other: this file
//! bounds the SURFACE, `zenoh_c_examples_on_wz_capi_c_dropin.rs` and
//! `zenoh_c_pure_function_oracle.rs` bound the BEHAVIOUR.
//!
//! ## A RATCHET, not a zero-assertion — and that is a deliberate weaker claim
//!
//! Symbols remain. Asserting emptiness would red the lane every run and be
//! turned off; asserting nothing would let the number climb back.
//! So the gate holds a committed [`BASELINES`] row PER ABI ARM and fails when
//! the set GROWS —
//! and equally when it SHRINKS without the constant moving, because a stale
//! ceiling is a gate measuring nothing. Both directions have to be a deliberate
//! edit, which is the whole content of a ratchet.
//!
//! ## The reference is the built artifact, never a header
//!
//! Both sides are read out of ELF `.dynsym` directly. A header lists what
//! upstream DECLARES; a `.so` lists what it DEFINES, and those differ — the
//! installed header carries `Z_FEATURE_UNSTABLE_API` prototypes this build
//! omits. The artifact is what a linker resolves against, so the artifact is the
//! oracle.
//!
//! ## The two arms must MATCH, and the lane is what arranges that
//!
//! wz's cdylib has two ABI arms and this machine's `libzenohc.so` is exactly one
//! of them. Layer C1cc reads `Z_FEATURE_UNSTABLE_API` out of the installed
//! header and builds the matching arm before running this; comparing a
//! mismatched pair would report the arm difference as missing symbols. The test
//! cannot rebuild the cdylib itself (`wz-capi-c` is deliberately not a
//! dependency of this crate), so it VERIFIES the pairing instead of assuming it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use wz_integration_tests::common::{wz_capi_c_cdylib, zenoh_c_oracle};

/// Public symbols the real `libzenohc.so` defines and wz's cdylib does not,
/// PER ABI ARM.
///
/// # R311y566 — one number was blind on its own machine
///
/// This was a single `const BASELINE = 90`, measured against the author's
/// `~/.local`, which was then a `nounstable` install — R2278 established it was
/// not the published package, which is and was the `unstable-shm` build.
/// Hosted CI provisions an
/// unstable+SHM oracle, which DEFINES 758 public symbols to that one's 568 — so
/// the same wz cdylib is missing 197 there and 90 here, and the gate redded on
/// hosted for a difference that is not a regression. Exactly the class this
/// tree already files under "a diff gate is blind on the machine that produced
/// the commit", walked into while writing a gate to close another one.
///
/// Both recorded rows are MEASURED, and the hosted number was reproduced
/// locally against `target/zenoh-c-shm` before being written here — 197 on both,
/// so the row is a measurement rather than a transcription of a log line.
///
/// An arm with no row is a hard FAIL, not a default: the two unmeasured arms
/// have no oracle on this machine, and a guessed ceiling is a gate that
/// measures nothing. Add the row when the oracle exists.
/// # R311y568 — the `nounstable` arm reached ZERO
///
/// 90 -> 0 and 197 -> 107, in one round. What closed on the published-archive
/// arm: the owned `reply_err` family (11), the `z_owned_task_t` thread plane
/// (6), the `zc_owned_closure_log_t` family (7), six `z_bytes_*` constructors
/// plus the reader's three cursor calls, the string array's mutable half (5),
/// the matching-status closure's own four entry points, the six
/// `z_internal_*_handler_*` pairs the three HAND-WRITTEN channel families never
/// got, the five `z_query_consolidation_*` constructors, five constant getters,
/// the `*_loan_mut` / `*_take_from_loaned` / `*_clone` accessors across sample /
/// reply / query / hello / querier, three `*_keyexpr` declaration getters, two
/// background declares, and the two counted-selector `_with_parameters_substr`
/// gets.
///
/// A zero here is a STRONGER claim than the ratchet was making, and the gate
/// shape does not change to accommodate it: the `assert_eq!` below still fails
/// if the number moves in EITHER direction, so a regression reds the lane and a
/// future improvement on another arm still has to move its row deliberately.
///
/// ## The `unstable-shm` arm: 197 -> 83, and the remainder is TWO PLANES
///
/// The same round also closed the unstable-only half of that arm — the entity-id
/// accessors (`z_subscriber_id` / `z_queryable_id` / `z_querier_id` /
/// `ze_advanced_publisher_id` / `ze_advanced_subscriber_id`),
/// `z_reply_replier_id`, `z_sample_reliability`, `z_keyexpr_relation_to`, the
/// `zc_owned_concurrent_close_handle_t` family, `zc_get_last_error`,
/// `z_bytes_get_contiguous_view`, the two remaining defaults, the advanced
/// publisher's matching trio and delete, and the advanced subscriber's two
/// background declares.
///
/// What is left is 83 symbols in exactly TWO coherent planes, and NOTHING
/// outside them — the classification is a measurement, re-run with the census:
///
/// - **65** — the SHM provider / allocator surface: `z_alloc_layout_*`,
///   `z_shm_provider_*`, `z_shm_client*`, `z_memory_layout_*`,
///   `z_ptr_in_segment_*`, `z_chunk_alloc_result_*`, `zc_shm_client_list_*`.
///   wz exports the SHM BUFFER half already (`z_shm_*` / `z_shm_mut_*`); this is
///   the ALLOCATOR half, which needs a segment provider wz does not have.
/// - **18 — CLOSED at R311y573.** The zenoh-ext `ze_publication_cache` and
///   `ze_querying_subscriber` planes, upstream's older standalone spellings of
///   the two ideas `ze_advanced_*` already carried. Built in
///   `wz-capi-c/src/zenoh_ext.rs` on this crate's own C entry points, which is
///   how upstream builds them too. `deprecated` was never a reason to omit
///   them: a symbol wz does not define is a program upstream can write and wz
///   cannot link.
///
/// The SHM-allocator plane is a FEATURE rather than a set of accessors, which is
/// why it is a recorded number here instead of work a round absorbs. That the
/// remainder is now exactly ONE plane — with no scattered leftovers — is what
/// makes this row a scoped debt rather than a tally.
/// ## R2239 — a row now records WHICH zenoh-c it was measured against
///
/// The rows above were all measured against zenoh-c 1.5.0. R2228 moved the pin
/// to 1.10.0, which GREW upstream's surface by three whole planes, and nothing
/// in this file noticed: three of the four rows still carry a 1.5.0 number and
/// the arm they describe has no 1.10.0 oracle on any machine, so they cannot be
/// re-measured until one exists. A stale ceiling that reads as a measurement is
/// the exact shape this gate's own header calls "a gate measuring nothing".
///
/// So each row carries the version it was measured at, and the gate refuses
/// when the INSTALLED oracle is a different one. Nothing has to remember to
/// re-measure: provisioning a 1.10.0 oracle for an arm whose row says 1.5.0
/// fails with that sentence.
///
/// ## R2282 — a row now records WHO EXECUTES it, and a `none` is judged
///
/// The version field says what a row was measured against. It does not say
/// whether anything ever runs it, and open-debt item 620 is that: for most of
/// this file's life exactly ONE of the four rows was executed, because the
/// census runs in Layer C1cc alone and C1cc's oracle is the published archive.
/// The other three were measured by hand and re-measured by nothing — a
/// committed number outliving what it describes, which is the same defect the
/// version field was added for, one level up.
///
/// The fourth field is therefore either the LANE that executes the row or
/// `none -- <why>`, and `scripts/lib/zenoh_c_census_arm_reach.py` judges it in
/// BOTH directions: it derives which run-ci lanes invoke this test and which
/// oracle arm each of them points at, then reds on a row naming a lane that
/// does not reach that arm AND on a `none` for an arm a lane does reach. The
/// second direction is not hypothetical — R2281 re-aimed Layer C1ce at the
/// `unstable` oracle, and the `unstable` row's `none` became false that round.
const BASELINES: &[(&str, usize, &str, &str)] = &[
    // Reached ZERO at R311y568 against 1.5.0. R2256 re-measured it at 1.10.0
    // and it is TWO: upstream's no-unstable surface went 568 -> 570 and wz's
    // stayed at 568.
    //
    // ⚠ The provenance this row used to carry — "`~/.local`, upstream's
    // published standalone archive" — no longer names this arm. That archive is
    // at 1.10.0 and resolves as `unstable-shm`, so `install-zenoh-c-arm.sh`
    // building from source is the only route to a `nounstable` oracle now.
    // R2258 lowered this 2 -> 1: `z_query_accepts_replies` is one of the two
    // upstream defines on the no-unstable arm as well.
    (
        "nounstable",
        1,
        "1.10.0",
        "none -- no lane points an oracle at this arm, and giving it one costs a \
      whole zenoh graph build for a ceiling no consumer reads: upstream does \
      not publish this arm and wz-capi-c's default features do not model it",
    ),
    // The arm hosted CI provisions. 83 -> 65 at R311y573 against 1.5.0; 65 ->
    // 189 at R2239, and every one of the 124 is upstream GROWING rather than wz
    // regressing. Re-measured, the remainder is FOUR planes and three strays,
    // and the classification is a measurement:
    //
    //   86  the SHM provider / allocator surface (was 65 at 1.5.0)
    //   47  the LINK-events plane        — `z_link_*`, `z_closure_link*`
    //   40  the TRANSPORT-events plane   — `z_transport_*`, `z_closure_transport*`
    //    9  the CANCELLATION-token plane — `z_cancellation_token_*`
    //    4  the `z_internal_*_check` / `_null` pairs of the two event planes
    //    3  strays: `z_query_accepts_replies`, `z_query_source_info`,
    //       `z_session_id` — accessors, each needing a value wz's marshals do
    //       not carry yet
    //
    // Three of those planes did not exist at 1.5.0. They are FEATURES rather
    // than accessors — each needs a runtime surface wz has not built — which is
    // why this is a recorded number and a filed debt rather than work this
    // round absorbs.
    //
    // 191 -> 189 in this same round, and the two are named because a ratchet
    // that moves without saying why is a number: upstream's newer spellings
    // `z_locality_default` and `z_reply_keyexpr_default` are now exported (an
    // addition and a rename respectively — upstream kept the `zc_` locality and
    // dropped the `zc_` reply-keyexpr), and both are driven by the
    // pure-function oracle rather than merely defined.
    // R2257 lowered this 189 -> 180: the cancellation-token plane is built, and
    // it is nine symbols on both unstable arms.
    // R2259 lowered this 178 -> 85: the LINK and TRANSPORT event planes are
    // built. NINETY-THREE on this arm rather than the ninety-two the `unstable`
    // row lost, and the extra one is the finding of the round: the transport
    // TYPE ITSELF differs by arm. `Z_FEATURE_SHARED_MEMORY` widens
    // `z_owned_transport_t` 19 -> 20 bytes, replaces the five-argument
    // `zc_internal_create_transport` with a six-argument
    // `zc_internal_create_transport_shm`, and adds `z_transport_is_shm`. Building
    // the plane from the `unstable` header alone therefore exported one symbol
    // upstream does NOT define here — measured as `extra=1` against this oracle,
    // which is `wz_exports_nothing_the_reference_does_not` red — and left two
    // it does. The remainder is the SHM provider/allocator plane (84) plus
    // `z_query_source_info`.
    // R2261 lowered this 85 -> 84: the query source-info accessor is built, and
    // what remains on this arm is now the SHM provider/allocator plane and
    // NOTHING ELSE — measured, by filtering the difference for the SHM
    // vocabulary and finding the non-SHM remainder empty.
    // R2263 lowered this 84 -> 78: the `z_memory_layout_*` plane, the most
    // self-contained six of what item 607 covers.
    //
    // ⛔ AND THAT ITEM'S PREMISE WAS WRONG, which is the finding of the round.
    // It said wz "does not build the SHM provider / allocator plane". wz DOES:
    // `shm.rs` is 1400 lines and exports 36 symbols, and its own header states
    // the split — the buffer allocator is implemented completely, the transport
    // optimisation is not. What the 78 are is narrower and structured, derived
    // by grouping each symbol under the TYPE it belongs to rather than by a
    // guessed prefix: alloc_layout 12, shm_provider variants 12,
    // precomputed_layout 10, shm_client_storage 7, shm_client_list 7,
    // ptr_in_segment 6, shared_shm_provider 6, chunk_alloc_result 5,
    // shm_client 4, posix_shm_provider 2, and six strays.
    //
    // ⚠ `z_owned_alloc_layout_t` is a TYPEDEF of `z_owned_precomputed_layout_t`
    // upstream, so those two families are one type under two names — 22
    // functions, not two planes.
    // R2264 lowered this 78 -> 73: the five provider spellings that need no
    // machinery wz lacks — three `_aligned` twins and the `_dealloc` pair.
    //
    // ⚠ Building them found a REAL DEFECT in the five that were already there:
    // `claim` aligns an OFFSET, and the segment was `vec![0u8; len]` at
    // alignment 1, so `z_shm_provider_alloc_aligned` returned addresses that
    // were aligned inside the segment and arbitrary in memory (measured:
    // `addr % 64 == 48`). Segments are page-aligned now, which is what
    // upstream's `mmap`ed ones give for free.
    // R2265 lowered this 73 -> 51: the LAYOUT family, twenty-two functions over
    // ONE type. `z_owned_alloc_layout_t` is a typedef of
    // `z_owned_precomputed_layout_t` upstream, so wz typedefs it too and every
    // `z_alloc_layout_*` delegates to its `z_precomputed_layout_*` twin — the
    // census lists two family names and there is one implementation.
    //
    // ⚠ The two `_async` spellings are NOT here: they take
    // `zc_threadsafe_context_t`, which this crate does not declare.
    ("unstable-shm", 51, "1.10.0", "C1cc"),
    // R311y614 — the two arms that had NO oracle on any machine, and therefore
    // no row: the gate hard-FAILED on them rather than guessing a ceiling from
    // a neighbour. `scripts/install-zenoh-c-arm.sh` builds any of the four, so
    // both were provisioned and MEASURED here.
    //
    // Both are ZERO, and the pair is what explains the 65 above rather than
    // merely adding two rows. Public symbol counts, per arm:
    //
    //   nounstable      568   wz 568   missing 0
    //   unstable        657   wz 657   missing 0
    //   nounstable-shm  568   wz 568   missing 0
    //   unstable-shm    758   wz 693   missing 65
    //
    // `nounstable-shm` DEFINES exactly what `nounstable` does, so
    // `Z_FEATURE_SHARED_MEMORY` adds no public symbol on its own — upstream
    // gates the SHM surface behind UNSTABLE as well. At 1.5.0 the whole
    // 101-symbol difference between `unstable` and `unstable-shm` was therefore
    // shared-memory-with-unstable, and the 65 wz was missing was the ALLOCATOR
    // half of it and nothing else: the gap was not "SHM", it was one plane on
    // one of four arms.
    //
    // ⚠ R2256 re-measured that at 1.10.0 and it no longer holds. The
    // shm-with-unstable plane is 122, and of the 189 wz is missing on this arm
    // only 86 are SHM-only — 103 are missing from the `unstable` arm as well.
    // The gap is now FOUR planes on two arms, which the block below the rows
    // sets out.
    //
    // R2239 — that last sentence was true AT 1.5.0. R2256 provisioned all four
    // arms at 1.10.0 and re-measured, and the shape it describes has MOVED:
    //
    //   arm             reference  wz   missing        (1.5.0 was)
    //   nounstable            570  569        1         568/568/0
    //   nounstable-shm        570  569        1         568/568/0
    //   unstable              757  664       93         657/657/0
    //   unstable-shm          878  700      178         758/693/65
    //
    // (R2256 measured 104 and 189; R2257 built the cancellation-token plane and
    // both came down by its nine; R2258 added `z_session_id` and
    // `z_query_accepts_replies`, the latter on all four arms.)
    //
    // `nounstable-shm` still DEFINES exactly what `nounstable` does — the set
    // difference is empty at 1.10.0 too, so upstream still gates its SHM
    // surface behind UNSTABLE as well.
    //
    // ⚠ But the containment claim is GONE: `unstable` is no longer a subset of
    // `unstable-shm`. One symbol is in the first and not the second at 1.10.0,
    // where at 1.5.0 the difference ran one way only. The planes are 187
    // (unstable-only) and 122 (shm-with-unstable).
    //
    // And the 180 is not "the allocator half and nothing else" any more: 94 of
    // it is missing from the `unstable` arm too, and only 86 are SHM-only. The
    // shared part is four planes, counted by leading family token over the set
    // difference rather than by a guessed prefix:
    //
    //   31  LINK events        `z_link_*`, `z_info_links*`
    //   26  the closure halves of the two event planes
    //   25  TRANSPORT events   `z_transport_*`, `z_info_transports`
    //   12  the declare / undeclare / info listeners of those two planes, plus
    //       `z_query_accepts_replies`, `z_query_source_info`, `z_session_id`
    //
    // The cancellation-token plane was the fifth and R2257 built it, which is
    // what took 103 to 94. R2258 then took two of those three strays — 92
    // remain shared, and `z_query_source_info` is the one that genuinely needs
    // a value `QueryMarshal` does not carry, which the other two did not.
    // Three whole planes that did not exist at 1.5.0 are what grew, which is
    // why every one of these numbers moved and why the version column exists.
    // R2257 lowered this 104 -> 95, same plane.
    // R2258 lowered this 95 -> 93: `z_session_id` and
    // `z_query_accepts_replies`, two of the twelve strays.
    // R2259 lowered this 93 -> 1: the LINK and TRANSPORT event planes, taken
    // WHOLE rather than a verb at a time. The families in the comment above are
    // not separable — a `z_link_event_t` is reachable only through a
    // `z_owned_closure_link_event_t`, installed only by
    // `z_declare_link_events_listener` — so shipping any one of them alone
    // leaves a header promising a link that fails, which is the defect item 593
    // names. The ONE that remains is `z_query_source_info`, and it is the one
    // stray R2258 measured as genuinely needing a value `QueryMarshal` does not
    // carry: the marshal has no `(zid, eid, sn)` where `SampleMarshal` does.
    //
    // ⭐ R2261 took it to ZERO. On this arm wz now defines EVERY ONE of the
    // reference's 757 public symbols, and `wz_exports_nothing_the_reference_does_not`
    // says it defines no more — the two together are the drop-in claim, closed
    // on the arm hosted CI provisions for the C examples.
    //
    // Zero is a live ratchet rather than a retired row: one symbol appearing on
    // either side reds this in one direction or the other. The row stays, and
    // its version column is what will catch upstream growing again.
    //
    // ⚠ The item's sentence about this last stray was half right. `QueryMarshal`
    // really did not carry the value — but the TREE did: `QueryView::source_info`
    // is filled by the receive path out of the query's own ext, so the work was
    // one layer of wiring rather than a new wire feature.
    ("unstable", 0, "1.10.0", "C1ce"),
    (
        "nounstable-shm",
        1,
        "1.10.0",
        "none -- no lane points an oracle at this arm, and giving it one costs a \
      whole zenoh graph build for a ceiling no consumer reads: upstream does \
      not publish this arm and wz-capi-c's default features do not model it",
    ),
];

/// The zenoh-c version an oracle prefix declares, out of its own
/// `zenoh_configure.h`.
///
/// The same `#define` `install-zenoh-c.sh` asserts its install against, read
/// here for the other half of that idea: the installer checks that the oracle
/// IS the pinned version, and this checks that a committed measurement was
/// taken against the oracle in front of it.
fn oracle_version(include: &Path) -> String {
    let text = std::fs::read_to_string(include.join("zenoh_configure.h"))
        .expect("the oracle carries a zenoh_configure.h");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("#define ZENOH_C \"") {
            if let Some(v) = rest.strip_suffix('"') {
                return v.to_string();
            }
        }
    }
    panic!(
        "no `#define ZENOH_C \"...\"` in {}/zenoh_configure.h — the oracle does \
         not say which version it is, and a baseline cannot be checked against \
         a version nothing states",
        include.display()
    );
}

/// The committed ceiling for `arm`, or a FAILURE naming what to measure.
fn baseline_for(arm: &str) -> (usize, &'static str) {
    BASELINES
        .iter()
        .find(|(name, _, _, _)| *name == arm)
        // The fourth field says WHO EXECUTES this row and is not read here on
        // purpose: it is a claim about `run-ci.sh`, and a test cannot know
        // which lane invoked it. `zenoh_c_census_arm_reach.py` adjudicates it.
        .map(|(_, n, v, _)| (*n, *v))
        .unwrap_or_else(|| {
            panic!(
                "no census baseline recorded for the '{arm}' ABI arm. The gap is \
                 arm-dependent (each zenoh-c build DEFINES a different symbol \
                 set), so a ceiling from another arm would measure nothing. \
                 Measure this arm and add its row to BASELINES."
            )
        })
}

/// `SHT_DYNSYM`.
const SHT_DYNSYM: u32 = 11;
/// `STB_GLOBAL` / `STB_WEAK` — the binding classes a linker resolves against.
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
/// `SHN_UNDEF` — an entry the object references but does not define.
const SHN_UNDEF: u16 = 0;

/// Read a little-endian `u16` / `u32` / `u64` at `off`, or `None` past the end.
fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// Every GLOBAL/WEAK, DEFINED dynamic symbol name in an ELF64 little-endian
/// shared object.
///
/// Panics rather than returning an error on a malformed input: a parse failure
/// is a broken harness and must not read as "no symbols missing".
fn defined_dynamic_symbols(path: &Path) -> BTreeSet<String> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert_eq!(
        bytes.get(..4),
        Some(&[0x7f, b'E', b'L', b'F'][..]),
        "{} is not an ELF object",
        path.display()
    );
    assert_eq!(bytes[4], 2, "{}: ELF64 expected", path.display());
    assert_eq!(bytes[5], 1, "{}: little-endian expected", path.display());

    let shoff = u64_at(&bytes, 0x28).expect("e_shoff") as usize;
    let shentsize = u16_at(&bytes, 0x3a).expect("e_shentsize") as usize;
    let shnum = u16_at(&bytes, 0x3c).expect("e_shnum") as usize;
    assert_eq!(
        shentsize,
        64,
        "{}: ELF64 section header is 64 B",
        path.display()
    );

    let mut names = BTreeSet::new();
    let mut found_dynsym = false;
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if u32_at(&bytes, sh + 0x04).expect("sh_type") != SHT_DYNSYM {
            continue;
        }
        found_dynsym = true;
        let sym_off = u64_at(&bytes, sh + 0x18).expect("sh_offset") as usize;
        let sym_size = u64_at(&bytes, sh + 0x20).expect("sh_size") as usize;
        let strtab_idx = u32_at(&bytes, sh + 0x28).expect("sh_link") as usize;
        let entsize = u64_at(&bytes, sh + 0x38).expect("sh_entsize") as usize;
        assert_eq!(entsize, 24, "{}: Elf64_Sym is 24 B", path.display());

        let str_sh = shoff + strtab_idx * shentsize;
        let str_off = u64_at(&bytes, str_sh + 0x18).expect("strtab sh_offset") as usize;
        let str_size = u64_at(&bytes, str_sh + 0x20).expect("strtab sh_size") as usize;
        let strtab = &bytes[str_off..str_off + str_size];

        for s in (0..sym_size / entsize).map(|n| sym_off + n * entsize) {
            let st_name = u32_at(&bytes, s).expect("st_name") as usize;
            let st_info = bytes[s + 4];
            let st_shndx = u16_at(&bytes, s + 6).expect("st_shndx");
            if st_shndx == SHN_UNDEF {
                continue;
            }
            let bind = st_info >> 4;
            if bind != STB_GLOBAL && bind != STB_WEAK {
                continue;
            }
            let end = strtab[st_name..]
                .iter()
                .position(|&c| c == 0)
                .expect("NUL-terminated strtab entry");
            let name = std::str::from_utf8(&strtab[st_name..st_name + end]).expect("utf8 symbol");
            if !name.is_empty() {
                names.insert(name.to_owned());
            }
        }
    }
    assert!(found_dynsym, "{}: no .dynsym section", path.display());
    names
}

/// Whether `name` is part of the PUBLIC zenoh-c API surface.
///
/// zenoh-c's four documented prefixes. A leading underscore is upstream's
/// internal plane and is not a drop-in obligation.
fn is_public_api(name: &str) -> bool {
    !name.starts_with('_')
        && (name.starts_with("z_")
            || name.starts_with("zc_")
            || name.starts_with("ze_")
            || name.starts_with("zp_"))
}

/// Which of the four ABI arms this oracle is, named as
/// `scripts/lib/zenoh-c-oracle-arm.sh` names them.
///
/// Read from the oracle's own `zenoh_configure.h`, which is the same fact the
/// shell resolver reads — one rule, two consumers, and neither guesses.
fn oracle_arm(include: &Path) -> String {
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h"))
        .expect("the oracle ships zenoh_configure.h");
    let unstable = configure.contains("#define Z_FEATURE_UNSTABLE_API");
    let shm = configure.contains("#define Z_FEATURE_SHARED_MEMORY");
    match (unstable, shm) {
        (true, true) => "unstable-shm",
        (true, false) => "unstable",
        (false, true) => "nounstable-shm",
        (false, false) => "nounstable",
    }
    .to_owned()
}

/// The oracle's library dir, or `None` with a LOUD note naming what to do.
fn oracle_or_note() -> Option<(PathBuf, PathBuf)> {
    match zenoh_c_oracle() {
        Some((include, libdir, _examples)) => Some((include, libdir)),
        None => {
            eprintln!(
                "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers \
                 and libzenohc.so (default prefix ~/.local, override WZ_ZENOH_C_PREFIX). \
                 Layer C1cc with WZ_C1CC_REQUIRE=1 fails instead of skipping."
            );
            None
        }
    }
}

/// The two public-symbol sets, with the ARM PAIRING verified rather than
/// assumed.
///
/// The pairing check is the half a census like this one gets wrong silently: a
/// cdylib built for the other ABI arm exports a different set, and the
/// difference would be reported as missing symbols with no hint that the
/// comparison itself was invalid. `z_internal_encoding_check` is not the probe —
/// the arm is read from the header the way the LANE reads it, so the test and
/// the lane cannot disagree about which arm was meant.
fn both_surfaces(include: &Path, libdir: &Path) -> (BTreeSet<String>, BTreeSet<String>) {
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h"))
        .expect("the oracle ships zenoh_configure.h");
    let oracle_is_unstable = configure.contains("#define Z_FEATURE_UNSTABLE_API");

    let wz: BTreeSet<String> = defined_dynamic_symbols(&wz_capi_c_cdylib())
        .into_iter()
        .filter(|n| is_public_api(n))
        .collect();
    let reference: BTreeSet<String> = defined_dynamic_symbols(&libdir.join("libzenohc.so"))
        .into_iter()
        .filter(|n| is_public_api(n))
        .collect();

    // `z_source_info_new` is gated on `Z_FEATURE_UNSTABLE_API` in BOTH
    // libraries, so its presence names each side's arm. A disagreement means
    // the cdylib on disk was built for the arm this oracle is not.
    let probe = "z_source_info_new";
    assert_eq!(
        wz.contains(probe),
        oracle_is_unstable,
        "the cdylib on disk is the {} arm and this oracle's header is the {} one, so \
         the census below would report the ARM DIFFERENCE as missing symbols. \
         Layer C1cc builds the matching arm; run it, or build wz-capi-c with \
         {}.",
        if wz.contains(probe) {
            "unstable"
        } else {
            "no-unstable"
        },
        if oracle_is_unstable {
            "unstable"
        } else {
            "no-unstable"
        },
        if oracle_is_unstable {
            "default features"
        } else {
            "--features zenoh-c-no-unstable-api"
        },
    );
    assert_eq!(
        reference.contains(probe),
        oracle_is_unstable,
        "the installed libzenohc.so disagrees with its own zenoh_configure.h about \
         Z_FEATURE_UNSTABLE_API — the oracle is internally inconsistent and cannot \
         serve as one"
    );
    assert!(
        reference.len() > 400,
        "the reference exported only {} public symbols — the oracle is not the real \
         libzenohc, and a census against a stub reports green",
        reference.len()
    );
    (wz, reference)
}

/// THE GATE: the drop-in surface gap does not grow, and the ceiling is honest.
///
/// The claim is weak twice over — it bounds which programs can be ATTEMPTED,
/// not whether wz answers the same way, and it is a ratchet rather than a zero.
/// The behavioural half is the dropin fixture and the pure-function oracle.
///
/// NO cross-impl proof annotation: reading a foreign library's symbol table is not driving
/// it, and A4 additionally forbids a claim in a file whose foreign artifacts its
/// classifier cannot see. The sibling `pico_abi_symbol_census.rs` does claim
/// one, and the difference is A4's own — it registers
/// `zenoh_pico_shared_library` as a foreign root and has no zenoh-c equivalent.
#[test]
#[ignore = "reads the installed zenoh-c oracle; run by run-ci Layer C1cc"]
fn the_wz_capi_c_drop_in_surface_gap_does_not_grow() {
    let Some((include, libdir)) = oracle_or_note() else {
        return;
    };
    let arm = oracle_arm(&include);
    let (baseline, measured_at) = baseline_for(&arm);
    // R2239 — the row must have been measured against THIS oracle's version.
    // Upstream's surface is version-dependent (1.5.0 -> 1.10.0 added three
    // whole planes), so a ceiling from another version bounds a different
    // library.
    let installed = oracle_version(&include);
    assert_eq!(
        installed, measured_at,
        "the '{arm}' census baseline of {baseline} was measured against zenoh-c \
         {measured_at} and the installed oracle is {installed}. Upstream's public \
         surface moves with its version, so that ceiling bounds a different \
         library. Re-measure this arm against {installed} and move BOTH the count \
         and the version in its BASELINES row."
    );
    let (wz, reference) = both_surfaces(&include, &libdir);
    let missing: Vec<&str> = reference
        .difference(&wz)
        .map(String::as_str)
        .collect::<Vec<_>>();

    assert!(
        missing.len() <= baseline,
        "wz's zenoh-c drop-in is missing {} public symbol(s) on the '{arm}' arm, up \
         from the committed baseline of {baseline}. A C program naming any of them \
         fails to LINK, so no behavioural leg can reach it:\n{}",
        missing.len(),
        missing.join("\n")
    );
    assert_eq!(
        missing.len(),
        baseline,
        "the gap on the '{arm}' arm is now {} and its committed baseline is still \
         {baseline}. Lower that row in BASELINES in the same commit as the work that \
         closed the symbols — a ceiling left above the real number is a gate that \
         measures nothing.",
        missing.len()
    );
    eprintln!(
        "api-compat-c census [{arm}]: wz defines {} of the reference's {} public \
         symbols; {} remain (baseline {baseline})",
        reference.len() - missing.len(),
        reference.len(),
        missing.len()
    );
}

/// THE OTHER DIRECTION: wz exports NOTHING the reference does not.
///
/// # R311y568 — the census was blind by construction, and it cost a real defect
///
/// The gate above is `reference - wz`, which answers "can every upstream program
/// be attempted". It is silent about `wz - reference`, and that set is not
/// harmless: a symbol wz exports and upstream does not is one of
///
/// - a symbol upstream gates behind `Z_FEATURE_UNSTABLE_API` that wz exports
///   unconditionally, so wz's surface is arm-dependent in a way the header is
///   not; or
/// - a symbol upstream does not declare AT ALL, i.e. a wz invention wearing a
///   `z_`-prefixed name.
///
/// Both were live when this test was written, and neither could be reached from
/// the other direction. `z_keyexpr_relation_to` and `zc_get_last_error` had just
/// been added ungated (upstream gates both), and `z_view_keyexpr_loan_mut` had
/// been sitting in the tree since the keyexpr plane landed — a symbol that
/// exists in ZENOH-PICO and was transcribed into the zenoh-c ABI, where upstream
/// declares no such function on either arm. The first two were caught only
/// because the pure-function probe failed to LINK against the reference; the
/// third nothing was looking for.
///
/// A ZERO rather than a ratchet, and deliberately so: the missing direction has
/// a legitimate non-zero remainder (features wz has not built), while this one
/// does not — every entry is a mistake by construction, so there is nothing to
/// carry.
#[test]
#[ignore = "reads the installed zenoh-c oracle; run by run-ci Layer C1cc"]
fn wz_exports_nothing_the_reference_does_not() {
    let Some((include, libdir)) = oracle_or_note() else {
        return;
    };
    let arm = oracle_arm(&include);
    let (wz, reference) = both_surfaces(&include, &libdir);
    let extra: Vec<&str> = wz
        .difference(&reference)
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert!(
        extra.is_empty(),
        "wz's zenoh-c drop-in exports {} public symbol(s) the real libzenohc.so does \
         NOT define on the '{arm}' arm. Each is either a symbol upstream gates behind \
         a `Z_FEATURE_*` that wz exports unconditionally, or a name wz invented — \
         both make wz's surface differ from the ABI it claims to be:\n{}",
        extra.len(),
        extra.join("\n")
    );
}

/// The census's own positive control.
///
/// A parser that silently returned an empty set would make the gate above pass
/// unconditionally on the growth direction. This pins that both inputs parse to
/// a plausible surface AND that the two agree on symbols that certainly exist in
/// both, so the measured gap means disagreement rather than blindness.
///
/// It witnesses no atom of its own: it is the gate above's positive control, and
/// crediting it separately would count one claim twice.
#[test]
#[ignore = "reads the installed zenoh-c oracle; run by run-ci Layer C1cc"]
fn the_census_reads_both_libraries_rather_than_nothing() {
    let Some((include, libdir)) = oracle_or_note() else {
        return;
    };
    let (wz, reference) = both_surfaces(&include, &libdir);
    assert!(
        wz.len() > 300,
        "wz parsed to only {} public symbols — the parse, not the ABI, is what that \
         number is measuring",
        wz.len()
    );
    for shared in [
        "z_open",
        "z_close",
        "z_put",
        "z_declare_subscriber",
        "z_get",
    ] {
        assert!(
            wz.contains(shared) && reference.contains(shared),
            "{shared} is absent from one of the two surfaces, so the parse is wrong \
             rather than the ABI"
        );
    }
}
