// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
/// `~/.local` (a plain no-unstable archive). Hosted CI provisions an
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
const BASELINES: &[(&str, usize)] = &[
    // `~/.local`, upstream's published standalone archive.
    ("nounstable", 90),
    // `target/zenoh-c-shm`, built by `scripts/install-zenoh-c-shm.sh`; the arm
    // hosted CI provisions.
    ("unstable-shm", 197),
];

/// The committed ceiling for `arm`, or a FAILURE naming what to measure.
fn baseline_for(arm: &str) -> usize {
    BASELINES
        .iter()
        .find(|(name, _)| *name == arm)
        .map(|(_, n)| *n)
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
    let baseline = baseline_for(&arm);
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
