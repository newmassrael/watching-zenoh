// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2451 (open-debt item 699) — the tracked raweth capture, and the oracle
//! that keeps it a FUNCTION of the encoders that emitted it.
//!
//! # The defect this closes
//!
//! A consumer that links only the C ABI can already read a capture —
//! `wz_dissect_pcap_summary` / `_census` / `_fields` all take pcap bytes, and
//! Round 2443 opened the field re-read those calls answer with. What it could
//! not do was OBTAIN raweth bytes. Measured at R2451: `git ls-files` matched
//! zero `.pcap`; the framing is `pub` in `wz_session_core::raweth_link` and
//! reached from no C door; and this tree cannot capture one either, because its
//! own zenoh-pico build has `Z_FEATURE_RAWETH_TRANSPORT` off
//! (`crates/wz-integration-tests/tests/raweth_framing_pico_layout.rs`, module
//! doc). So the one link zenoh speaks that is not IP had a published reader and
//! no published input.
//!
//! # Why the bytes are not hand-laid, and how that is CHECKED
//!
//! Typing a raweth frame out by hand is the one repair this item refuses, and
//! the reason is that `raweth_framing_pico_layout` exists to catch exactly what
//! a hand-laid frame gets wrong: `ethtype` rides the SENDER's byte order while
//! `data_length` does not, the header is 16 bytes and not the standard 14, the
//! VLAN form is 20, and every one of those is a property of a C compiler's
//! layout of a type in `vendor/zenoh-pico` rather than anything this tree
//! decides. A fixture that got them wrong would be read back by this crate's
//! own parser, agree with itself, and ship.
//!
//! So no byte in the tracked file is written here:
//!
//! * every PAYLOAD is one transport message built by ITS OWN codec, taken from
//!   `crate::datagram_tests::transport_vocabulary` — the list the MID censuses
//!   are themselves derived from, so a MID added there joins this capture by
//!   construction and the sample cannot fall behind the vocabulary it
//!   advertises;
//!
//! ⚠ R2454 changed which of the two lists that is, and hosted Layer C1bt is
//! what said so. It was `transport_census`, which is the vocabulary FILTERED
//! to what the compiling build can name — one entry shorter at
//! `--no-default-features`, where `reassembly` is off. A committed artifact
//! cannot be a function of the flags of whoever last rebuilt it: the byte
//! comparison below red at 296 against 260, and the REFRESHER would have
//! silently shrunk the shipped sample to six messages had it been run there.
//! The two callers are now split by which question they ask — see that
//! function's own doc.
//! * every FRAME is `raweth_link::frame`'s output, with pico's own default MACs
//!   and ethertype (`DEFAULT_SMAC` / `DEFAULT_DMAC` / `DEFAULT_ETHTYPE`, each
//!   cited to `link.c` where it is declared);
//! * the CONTAINER is `crate::pcap::write`'s output, whose file header is
//!   asserted byte by byte against `pcap-savefile(5)` by that module's own
//!   tests rather than against this crate's reader.
//!
//! `the_tracked_raweth_capture_is_byte_identical_to_what_wz_emits` rebuilds all
//! three and compares the whole file. That is the machine form of "these bytes
//! came from the encoder": a hand edit anywhere in the file reds it, and it
//! cannot be satisfied by agreeing with a reading, because nothing in the
//! comparison reads the layout at all.
//!
//! Code spans and NOT intra-doc links throughout this module, on
//! `wz-packet-fixtures`' argument: the module is `#[cfg(test)]`, so rustdoc
//! never compiles it, and a link here would resolve in no build a reader runs
//! while counting against Layer C1bz's budget.
//!
//! # Alternating widths, derived rather than declared
//!
//! Odd-indexed frames carry a VLAN tag, so both header widths occur in one
//! file. That is not decoration: the width axis is one of the three the
//! rejection above names, a consumer implementing a reader needs a specimen of
//! each, and taking the choice off the packet's INDEX means how many of each
//! width there are follows from the census length instead of from a number
//! written here.
//! `the_tracked_raweth_capture_carries_both_header_widths` asserts both are
//! present, so a census that shrank to one entry would red rather than quietly
//! ship a one-width sample.
//!
//! # The recorded bytes are a LITTLE-ENDIAN host's, and that is stated
//!
//! pico `memcpy`s the header struct onto the wire, so `ethtype`, `vlan_type`
//! and `tag` land in the sender's byte order; `raweth_link`'s module doc
//! reproduces that rather than normalising it, and `crate::link`'s
//! `strip_raweth` accepts both spellings on the read side precisely because the
//! sender's endianness is not observable from a capture. The tracked file is
//! therefore a recording of what a little-endian host emits, which is what the
//! deployments this sample is for run. Rebuilding it on a big-endian host
//! produces a different — and equally correct — file, so the comparison below
//! fails there. It fails LOUDLY, naming the endianness, rather than skipping: a
//! fixture whose oracle stands down on some hosts is the shape this workspace
//! has paid for repeatedly, and a red that names its cause costs one reading.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use wz_session_core::raweth_link::{
    frame, RawEthHeader, DEFAULT_DMAC, DEFAULT_ETHTYPE, DEFAULT_SMAC, ETH_HEADER_LEN,
    ETH_VLAN_HEADER_LEN,
};

use crate::link::LINKTYPE_ETHERNET;

/// The tracked capture, read at COMPILE time.
///
/// `include_bytes!` and not a filesystem read: the oracle then has no working
/// directory to be wrong about, and a `cargo test` from anywhere grades the
/// file that is committed beside this source.
const TRACKED: &[u8] = include_bytes!("../../../captures/raweth-transport-messages.pcap");

/// Where it lives, for the refusals below to name.
const TRACKED_PATH: &str = "captures/raweth-transport-messages.pcap";

/// The VLAN tag the odd frames carry.
///
/// The same value `raweth_framing_pico_layout` drives its C probe with, so the
/// one tag in this tree that has been compared against pico's own struct is the
/// one this sample ships.
const VLAN_TAG: u16 = 0x0102;

/// Microseconds between packets, so the capture carries a plausible and
/// DETERMINISTIC timeline. A wall clock here would make the file differ on
/// every rebuild and the comparison below meaningless.
const PACKET_SPACING_MICROS: u32 = 1_000;

/// Rebuild the whole file from the encoders — payloads, frames and container.
///
/// The one place the sample's shape is decided, called by the oracle and by the
/// refresher, so the file that is written and the file that is graded cannot be
/// built by two different rules.
fn rebuild() -> Vec<u8> {
    let census = crate::datagram_tests::transport_vocabulary();
    let frames: Vec<Vec<u8>> = census
        .iter()
        .enumerate()
        .map(|(i, (name, wire))| {
            let mut header = RawEthHeader::new(DEFAULT_DMAC, DEFAULT_SMAC, DEFAULT_ETHTYPE, 0);
            if i % 2 == 1 {
                header = header.with_vlan(VLAN_TAG);
            }
            frame(&header, wire)
                .unwrap_or_else(|e| panic!("{name} does not fit a raweth frame: {e:?}"))
        })
        .collect();
    let packets: Vec<(u32, u32, &[u8])> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| (0u32, i as u32 * PACKET_SPACING_MICROS, f.as_slice()))
        .collect();
    crate::pcap::write(LINKTYPE_ETHERNET, &packets)
}

/// Rewrite the tracked file from `rebuild`. `#[ignore]`d — it is the REFRESHER,
/// not a check.
///
/// Run it when a census entry or the framing legitimately changes:
///
/// ```text
/// cargo test -p wz-capture --lib refresh_the_tracked_raweth_capture -- --ignored
/// ```
///
/// then run the suite again — `include_bytes!` makes the oracle recompile
/// against the new file, so the refresh is only believed once it has been
/// re-graded. Ignored rather than driven by an environment variable so that no
/// CI run can rewrite the artifact it is meant to be checking, and so the
/// refresh cannot be mistaken for a passing oracle: this test asserts nothing.
#[test]
#[ignore = "REFRESHER, not a check: rewrites the tracked capture"]
fn refresh_the_tracked_raweth_capture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(TRACKED_PATH);
    let bytes = rebuild();
    std::fs::write(&path, &bytes).unwrap_or_else(|e| panic!("writing {path:?}: {e}"));
    std::println!(
        "wrote {} byte(s) to {} — now re-run the suite to grade it",
        bytes.len(),
        TRACKED_PATH
    );
}

/// The tracked file IS what the encoders emit, byte for byte.
///
/// This is the provenance claim in machine form. It reads no layout, so it
/// cannot be satisfied by a fixture that agrees with this crate's parser, and it
/// covers the payloads, the framing and the container in one comparison.
#[test]
fn the_tracked_raweth_capture_is_byte_identical_to_what_wz_emits() {
    let rebuilt = rebuild();
    let endian = if cfg!(target_endian = "little") {
        "little"
    } else {
        "big"
    };
    assert_eq!(
        TRACKED.len(),
        rebuilt.len(),
        "{TRACKED_PATH} is {} byte(s) and the encoders emit {} — refresh it with \
         `cargo test -p wz-capture --lib refresh_the_tracked_raweth_capture -- \
         --ignored` if a census entry or the framing changed on purpose",
        TRACKED.len(),
        rebuilt.len()
    );
    if let Some(at) = TRACKED.iter().zip(rebuilt.iter()).position(|(a, b)| a != b) {
        panic!(
            "{TRACKED_PATH} first differs from what the encoders emit at byte \
             {at}: tracked {:#04x}, emitted {:#04x}. This host is {endian}-endian, \
             and pico's header rides the SENDER's byte order — on a big-endian \
             host this mismatch is expected and the module doc says why. \
             Otherwise the file has been hand-edited, or a census entry changed \
             and the fixture was not refreshed.",
            TRACKED[at], rebuilt[at]
        );
    }
}

/// Both raweth header widths occur in the tracked file.
///
/// Derived from the frames themselves rather than from a count written here, and
/// stated as a property so a census that shrank to a single entry — which would
/// leave the sample with one width and no complaint — reds.
#[test]
fn the_tracked_raweth_capture_carries_both_header_widths() {
    let file = crate::pcap::parse(TRACKED).expect("the tracked capture parses");
    let mut widths = BTreeSet::new();
    for p in &file.packets {
        let (_, n) = RawEthHeader::decode(&p.data).expect("every packet is a raweth frame");
        widths.insert(n);
    }
    let both: BTreeSet<usize> = [ETH_HEADER_LEN, ETH_VLAN_HEADER_LEN].into_iter().collect();
    assert_eq!(
        widths, both,
        "the sample must carry a specimen of BOTH widths — the VLAN form is one \
         of the three things this item's rejection of hand-laid bytes names, and \
         a consumer writing a reader needs one of each"
    );
}

/// Every message in the tracked file reaches the surface a consumer reads, and
/// reaches it NAMED.
///
/// The byte comparison above says the file is what wz emitted; it says nothing
/// about the file being USEFUL. This drives the tracked bytes through the entry
/// point the C door calls (`Dissection::from_capture`, which the
/// `wz_dissect_pcap_*` family wraps) and asserts each frame decoded to a named
/// transport message on a flow marked `raweth`. A capture that was byte-perfect
/// and dissected to `Unknown { mid }` would satisfy the item's letter and be
/// worthless to the consumer that asked for it.
///
/// R2454 — the expectation is DERIVED from the build's own claim rather than
/// declared: `this_build_names` decides each entry, and the two outcomes are
/// held against each other in both directions. A message the census claims and
/// the reader cannot name reds; a message the census disclaims and the reader
/// names anyway also reds, because then the census is what is stale. Spelling
/// the feature here instead would make the test a tautology of the emitter's
/// own `#[cfg]`, and both arms are live: the default build takes the first for
/// all seven, `--no-default-features` takes the second for `Fragment`.
#[test]
fn the_tracked_raweth_capture_reaches_the_consumer_surface() {
    use wz_session_core::inbound::InboundFrame;

    let d = crate::Dissection::from_capture(TRACKED).expect("the tracked capture dissects");
    let flows = d.datagram_flows();
    assert_eq!(
        flows.len(),
        1,
        "one sender and one receiver, so one flow: {}",
        flows.len()
    );
    let flow = &flows[0];
    assert_eq!(
        flow.flow.link().name(),
        "raweth",
        "the flow must SAY which link it was read off"
    );
    let vocabulary = crate::datagram_tests::transport_vocabulary();
    assert_eq!(
        flow.frames.len(),
        vocabulary.len(),
        "every message in the sample must reach the reader"
    );
    for ((name, _), got) in vocabulary.iter().zip(flow.frames.iter()) {
        let nameable = crate::datagram_tests::this_build_names(name);
        match &got.frame {
            Ok(InboundFrame::Unknown { mid }) if nameable => panic!(
                "{name} (MID {mid:#04x}) is in the sample, this build's census \
                 claims it, and the reader could not name it — the capture \
                 would teach a consumer nothing"
            ),
            Ok(InboundFrame::Unknown { .. }) => {}
            Ok(_) if !nameable => panic!(
                "{name} is OUTSIDE this build's census — `this_build_names` \
                 says the codec is not selected — and the reader named it \
                 anyway. The census gate is what is wrong, not the reader"
            ),
            Ok(_) => {}
            Err(e) => panic!("{name} failed to decode out of the sample: {e:?}"),
        }
    }
}
