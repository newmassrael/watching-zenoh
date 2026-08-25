// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2055 (open-debt item 391) — the link-type sweep's ceiling, and the names
//! beneath it, re-read off libpcap's own header instead of remembered.
//!
//! ## The gap
//!
//! `wz_capture::link`'s sweep walks every link type from 0 to a ceiling and
//! asserts that the ones the dispatch reads are exactly `READABLE_LINK_TYPES`.
//! The ceiling was the literal `1000`, chosen once because libpcap's
//! assignments ran out in the 200s at the time someone looked, and nothing in
//! the repository ever looked again. A link type assigned above it would be
//! invisible to the very gate built to see it, and every lane would stay green.
//!
//! That is the same shape as R2054's BSD address-family table, R2053's damage
//! buckets and R2052's opaque-body reasons: a constant that encodes a judgement
//! about the outside world, with nothing that would notice the outside world
//! moving.
//!
//! ## Why the header is the right judge here
//!
//! R2054 chose `tcpdump` over a header constant, because the operative claim
//! there was "two tools read the same capture the same way". This round's claim
//! is different in kind: it is about the SPACE of link-type numbers, which is
//! an assignment registry, and libpcap's header is that registry's shipped
//! form. It even states the bound in words rather than leaving it to be
//! inferred — `DLT_MATCHING_MAX` is documented as "the highest value in the
//! matching range", where "matching" means the `DLT_` value and the `LINKTYPE_`
//! value that appears in capture files are the same number.
//!
//! ## What the header can and cannot adjudicate
//!
//! Its own comment draws the line, and this test honours it rather than
//! inventing one. At or above `DLT_MATCHING_MIN` (104) the two namespaces
//! coincide, so a `LINKTYPE_` this crate declares must be a `DLT_` the header
//! assigns, under the same name. BELOW 104 they diverge per platform — the
//! header calls 1 `DLT_EN10MB` while the capture-file space calls it
//! `LINKTYPE_ETHERNET`, and `LINKTYPE_RAW` (101) has no `DLT_` at all — so the
//! header is silent there and this test says so out loud, with the exempt set
//! DERIVED from the header's own boundary and then pinned.
//!
//! ## The parse, and the shape a probe found
//!
//! MEASURED before this file existed, with a throwaway probe: at this libpcap
//! the header carries 214 numeric `DLT_` define LINES naming 206 distinct
//! names, plus five pure aliases and one function macro. The eight-line gap is
//! the whole reason for the map's direction — a name can be defined TWICE, and
//! `DLT_LOOP` is 12 inside `#ifdef __OpenBSD__` and 108 outside it, because 12
//! is `DLT_RAW` on every other platform. So the map here is VALUE to NAMES, not
//! name to value: the question this test asks is "what does libpcap call 108",
//! which the `#ifdef` cannot confuse, and a name-keyed map would have answered
//! by whichever branch happened to be parsed last.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use wz_capture::link::{LINK_TYPE_SWEEP_CEILING, READABLE_LINK_TYPES};

/// Where libpcap's development package puts the registry. Overridable so the
/// arming behaviour below can be driven in both directions without uninstalling
/// anything.
fn header_path() -> PathBuf {
    std::env::var_os("WZ_DLT_HEADER")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/include/pcap/dlt.h"))
}

/// The fewest numeric `DLT_` defines a header has to yield before its answers
/// are worth believing.
///
/// This is the anti-vacuity floor, and it is the assertion that stops a parse
/// which silently stopped matching from reading as agreement. It is set well
/// under the 206 measured at this pin, because the direction that matters is
/// "the parse found essentially nothing", not "libpcap shrank by ten".
const MIN_PLAUSIBLE_DEFINES: usize = 150;

/// Every link type this crate declares readable that sits BELOW the matching
/// range, and which the header therefore cannot adjudicate.
///
/// Derived, not decided: the test computes this set from `DLT_MATCHING_MIN` and
/// then holds it against this literal. The literal is the second net — it
/// catches a change where a readable code MOVES below the boundary, which would
/// silently grow the un-adjudicated set while every derived assertion still
/// passed.
const EXPECTED_BELOW_MATCHING_RANGE: &[u32] = &[0, 1, 101];

/// `value -> the names the header gives it`, plus the count of numeric defines
/// seen (which is not the map's length: a value can carry several names).
struct Registry {
    by_value: BTreeMap<u32, BTreeSet<String>>,
    numeric_defines: usize,
}

impl Registry {
    fn parse(text: &str) -> Self {
        let mut by_value: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
        let mut numeric_defines = 0usize;
        for line in text.lines() {
            let Some(rest) = line.strip_prefix("#define") else {
                continue;
            };
            let mut words = rest.split_whitespace();
            let (Some(name), Some(value)) = (words.next(), words.next()) else {
                continue;
            };
            // A function macro (`DLT_CLASS(x)`) is not an assignment.
            if !name.starts_with("DLT_") || name.contains('(') {
                continue;
            }
            // Aliases (`#define DLT_CHDLC DLT_C_HDLC`) carry no number of their
            // own; the name they point at is already in the map with its value.
            let Ok(code) = value.parse::<u32>() else {
                continue;
            };
            numeric_defines += 1;
            by_value
                .entry(code)
                .or_default()
                .insert(name["DLT_".len()..].to_string());
        }
        Self {
            by_value,
            numeric_defines,
        }
    }

    /// The single value a sentinel names, refusing a sentinel defined more than
    /// once at different values — which would mean the boundary this test rests
    /// on is itself platform-dependent.
    fn sentinel(&self, name: &str) -> u32 {
        let hits: Vec<u32> = self
            .by_value
            .iter()
            .filter(|(_, names)| names.contains(name))
            .map(|(v, _)| *v)
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "DLT_{name} must be defined at exactly one value; the header gives {hits:?}",
        );
        hits[0]
    }
}

/// Read the header, or explain why the answer is a skip rather than a pass.
fn read_header(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

// NO PROOF TAG, and the absence is deliberate — the same call R2054 made next
// door. Layer A4 counts CROSS-IMPLEMENTATION coverage: which wz atoms are
// proved against a foreign zenoh implementation actually running. This test
// spawns no implementation at all, foreign or otherwise; it reads a header
// libpcap ships. So it contributes nothing to that accounting, and even a
// `none` declaration would be a claim where there is no claim to make.
// Teaching A4 a "reads a third-party header" class would make its number say
// something it does not mean.
//
// The tag token itself is not written above — A4 parses this position, so a
// sentence ABOUT the grammar reads as an instance of it. That is what reds
// this file's first push.
#[test]
fn the_link_type_sweep_ceiling_is_held_to_libpcaps_own_registry() {
    let path = header_path();

    // ── IS THE REGISTRY PRESENT? ──────────────────────────────────────────
    // Absent, this is a SKIP and not a pass -- but an armed lane turns it into
    // a failure, which is how this tree keeps "the oracle was absent" from
    // reading as "the subject was right". Both behaviours are driven before
    // this file is believed; asserting one and assuming the other is how a lane
    // ends up green over an oracle nobody provisioned.
    let Some(text) = read_header(&path) else {
        if std::env::var("WZ_DLT_HEADER_REQUIRE").is_ok() {
            panic!(
                "WZ_DLT_HEADER_REQUIRE is set and {} is not readable. The sweep \
                 ceiling has no other adjudicator, so a lane that armed this \
                 flag was asking for the measurement, not for a skip -- install \
                 libpcap's development headers",
                path.display()
            );
        }
        eprintln!(
            "skip: {} is not readable (libpcap headers absent); set \
             WZ_DLT_HEADER_REQUIRE=1 to make that a failure",
            path.display()
        );
        return;
    };

    let registry = Registry::parse(&text);

    // ── ANTI-VACUITY ──────────────────────────────────────────────────────
    // Everything below is an assertion ABOUT A POPULATION, and a population of
    // zero is green. A header whose shape changed under the parse would yield
    // an empty map and agree with everything.
    assert!(
        registry.numeric_defines >= MIN_PLAUSIBLE_DEFINES,
        "parsed only {} numeric DLT_ defines from {}; the parse, not libpcap, \
         is what changed",
        registry.numeric_defines,
        path.display(),
    );

    let matching_min = registry.sentinel("MATCHING_MIN");
    let matching_max = registry.sentinel("MATCHING_MAX");
    assert!(
        matching_min < matching_max,
        "the matching range is inverted: {matching_min}..={matching_max}",
    );

    // ── THE CEILING ───────────────────────────────────────────────────────
    // `DLT_MATCHING_MAX` is the highest number that can appear as a capture
    // file's link type, because below the matching range the LINKTYPE_ space is
    // full and above it there is nothing assigned. The sweep has to reach it.
    assert!(
        LINK_TYPE_SWEEP_CEILING >= matching_max,
        "libpcap now assigns link types up to {matching_max} and \
         LINK_TYPE_SWEEP_CEILING is {LINK_TYPE_SWEEP_CEILING}: every type above \
         the ceiling is invisible to the sweep built to see it. Raise the \
         ceiling in wz_capture::link -- lowering this assertion would be \
         deleting the instrument",
    );

    // ── THE NAMES, WHERE THE HEADER IS ENTITLED TO SPEAK ──────────────────
    let mut adjudicated = Vec::new();
    let mut exempt = Vec::new();
    for (code, name) in READABLE_LINK_TYPES {
        if *code < matching_min {
            exempt.push(*code);
            continue;
        }
        let names = registry.by_value.get(code).cloned().unwrap_or_default();
        assert!(
            names.contains(*name),
            "wz reads link type {code} as {name}, and in the matching range a \
             LINKTYPE_ is the DLT_ of the same number -- but {} calls {code} \
             {names:?}",
            path.display(),
        );
        adjudicated.push(*code);
    }

    // Sorted so the pin below is about the SET and not about the order
    // `READABLE_LINK_TYPES` happens to be written in -- `readable_link_types_line`
    // sorts for the same reason.
    adjudicated.sort_unstable();
    exempt.sort_unstable();

    // ── AND WHERE IT IS NOT ───────────────────────────────────────────────
    // The exempt set is the header's own boundary applied to this crate's
    // table, then pinned. Writing "the header cannot judge these" without the
    // opposite assertion is how an exemption grows unnoticed.
    assert_eq!(
        exempt, EXPECTED_BELOW_MATCHING_RANGE,
        "the link types below DLT_MATCHING_MIN ({matching_min}) -- the ones \
         libpcap's header cannot adjudicate because DLT_ and LINKTYPE_ diverge \
         there -- have changed",
    );
    assert!(
        !adjudicated.is_empty(),
        "no readable link type fell in the matching range, so the name check \
         above asserted nothing",
    );

    eprintln!(
        "pcap/dlt.h adjudication: {} numeric defines, matching range \
         {matching_min}..={matching_max}, ceiling {LINK_TYPE_SWEEP_CEILING}; \
         names checked for {adjudicated:?}, exempt below the range {exempt:?}",
        registry.numeric_defines,
    );
}
