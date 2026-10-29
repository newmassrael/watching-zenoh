// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! THE ZENOH TEST OVER REAL CAPTURES: the calibration corpus of
//! `captures/corpus/`, read for the verdict of every flow
//! (`docs/flow-zenoh-verdict.md` §6).
//!
//! Each file is a real capture, anonymised by `scripts/lib/capture_anonymise.py`,
//! and `captures/corpus/corpus.json5` says what it is: whether its flows are
//! zenoh (`hypothesis: "zenoh"`) or not (`"other"`), which protocol, and where it
//! was taken. This module holds the two error rates to it:
//!
//! * the FALSE `yes`: no flow of an `other` file reads `yes`;
//! * the FALSE `no`: no flow of a `zenoh` file reads `no`.
//!
//! Both are hard: a single flow breaks them. Beside them, every file's tally of
//! the three words is pinned in [`EXPECTED`], so a change to the decoder or to
//! the model that moves a flow from one word to another is a change this test
//! names, in the direction it went, and the table is the ROC point the corpus
//! measures. The tally of a file that carries lz4 depends on whether this build
//! opens lz4, and the table says both.

use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::session_table::ZenohVerdict;
use crate::Dissection;

/// The corpus directory, from the crate.
fn corpus_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../captures/corpus")
}

/// One file of the corpus, as the manifest describes it.
struct Entry {
    file: String,
    hypothesis: String,
    packets: u64,
}

fn manifest() -> Vec<Entry> {
    let text = std::fs::read_to_string(corpus_dir().join("corpus.json5"))
        .expect("captures/corpus/corpus.json5 reads");
    let doc = json5::parse(&text).unwrap_or_else(|e| panic!("the manifest is JSON5: {e:?}"));
    let Some(Json5Value::Array(files)) = doc.get("files") else {
        panic!("the manifest has a `files` array");
    };
    let text_of = |v: &Json5Value, key: &str| match v.get(key) {
        Some(Json5Value::String(s)) => s.clone(),
        other => panic!("`{key}` is a string in every entry: {other:?}"),
    };
    files
        .iter()
        .map(|v| Entry {
            file: text_of(v, "file"),
            hypothesis: text_of(v, "hypothesis"),
            packets: match v.get("packets") {
                Some(Json5Value::Number(n)) => n.parse().expect("`packets` is an integer"),
                other => panic!("`packets` is a number in every entry: {other:?}"),
            },
        })
        .collect()
}

/// A file's flows by verdict: `(yes, no, undecided)`.
type Tally = (u64, u64, u64);

/// Every flow's verdict in `d`: the stream flows, the datagram flows (a
/// multicast group and a scouting flow included: the verdict is a statement
/// about every flow, whether or not it is a session row), and the serial line.
fn verdicts(d: &Dissection) -> Vec<ZenohVerdict> {
    let mut out: Vec<ZenohVerdict> = d
        .flows()
        .iter()
        .map(|f| ZenohVerdict::of(&f.zenoh_evidence()))
        .chain(
            d.datagram_flows()
                .iter()
                .map(|f| ZenohVerdict::of(&f.zenoh_evidence())),
        )
        .collect();
    if d.serial_census().is_some() {
        out.push(ZenohVerdict::of(&d.serial_zenoh_evidence()));
    }
    out
}

/// The compression reading of every flow of `d` that reads `yes`, as
/// `value/basis` (`lz4`, `off` or `-`; the basis word of the field document),
/// sorted.
fn compression_readings(d: &Dissection) -> Vec<String> {
    use wz_session_core::passive::{Basis, Reading};
    let word = |r: Reading<bool>| {
        let value = match r.value {
            Some(true) => "lz4",
            Some(false) => "off",
            None => "-",
        };
        let basis = match r.basis {
            Basis::Stated => "stated",
            Basis::Inferred => "inferred",
            Basis::Conflicting => "conflicting",
            Basis::Absent => "absent",
        };
        alloc::format!("{value}/{basis}")
    };
    let mut out: Vec<String> = d
        .flows()
        .iter()
        .filter(|f| ZenohVerdict::of(&f.zenoh_evidence()) == ZenohVerdict::Yes)
        .map(|f| word(f.session.compression_reading()))
        .chain(
            d.datagram_flows()
                .iter()
                .filter(|f| ZenohVerdict::of(&f.zenoh_evidence()) == ZenohVerdict::Yes)
                .map(|f| word(f.session.compression_reading())),
        )
        .collect();
    out.sort();
    out
}

/// What every zenoh file's sessions say of compression, and on what grounds,
/// in both builds. A capture that holds the handshake states it; one joined
/// mid-session infers it from the bytes, `lz4` from the batch headers a
/// compressed session puts on every batch and `off` from batches that read
/// whole with none.
const COMPRESSION: &[(&str, &[&str])] = &[
    ("zenoh-tcp-full.pcap", &["off/stated", "off/stated"]),
    (
        "zenoh-tcp-midsession.pcap",
        &["off/inferred", "off/inferred"],
    ),
    ("zenoh-udp-full.pcap", &["off/stated", "off/stated"]),
    ("zenoh-tcp-lz4.pcap", &["lz4/stated", "lz4/stated"]),
    (
        "zenoh-udp-lz4-midsession.pcap",
        &["lz4/inferred", "lz4/inferred"],
    ),
    (
        "zenoh-tcp-lz4-midsession.pcap",
        &["lz4/inferred", "lz4/inferred"],
    ),
];

/// The floors every zenoh session of `d` that reads `yes` puts under its batch
/// size and its SN ring, as `batch_size:basis[>=n] sn_mask:basis[>=n]`.
fn floor_readings(d: &Dissection) -> Vec<String> {
    use wz_session_core::passive::{Basis, FloorReading};
    let word = |r: FloorReading| {
        let basis = match r.basis {
            Basis::Stated => "stated",
            Basis::Inferred => "inferred",
            Basis::Conflicting => "conflicting",
            Basis::Absent => "absent",
        };
        match r.at_least {
            Some(n) => alloc::format!("{basis}>={n}"),
            None => String::from(basis),
        }
    };
    let both = |s: &wz_session_core::passive::PassiveSession| {
        alloc::format!(
            "batch_size:{} sn_mask:{}",
            word(s.batch_size_floor()),
            word(s.sn_mask_floor())
        )
    };
    let mut out: Vec<String> = d
        .flows()
        .iter()
        .filter(|f| ZenohVerdict::of(&f.zenoh_evidence()) == ZenohVerdict::Yes)
        .map(|f| both(&f.session))
        .chain(
            d.datagram_flows()
                .iter()
                .filter(|f| ZenohVerdict::of(&f.zenoh_evidence()) == ZenohVerdict::Yes)
                .map(|f| both(&f.session)),
        )
        .collect();
    out.sort();
    out
}

/// A floor is only a floor if no real sender goes under it. Every zenoh flow of
/// the corpus, from real zenohd 1.10.1 and 1.5.0 and zenoh-pico, stream and
/// datagram, whole and joined mid-session, reads its stated batch size and ring
/// as the bytes bear them out: never `conflicting`. A capture that holds no
/// handshake gets the floors from its bytes alone.
#[test]
fn no_real_zenoh_session_goes_under_the_floors_its_bytes_put_on_its_parameters() {
    let mut conflicts = Vec::new();
    let mut seen = 0usize;
    let mut floors_from_bytes = 0usize;
    for entry in manifest().iter().filter(|e| e.hypothesis == "zenoh") {
        let bytes = std::fs::read(corpus_dir().join(&entry.file))
            .unwrap_or_else(|e| panic!("{}: {e}", entry.file));
        let d =
            Dissection::from_capture(&bytes).unwrap_or_else(|e| panic!("{}: {e:?}", entry.file));
        for reading in floor_readings(&d) {
            seen += 1;
            if reading.contains("conflicting") {
                conflicts.push(alloc::format!("{}: {reading}", entry.file));
            }
            if reading.contains("absent>=") {
                floors_from_bytes += 1;
            }
        }
    }
    assert!(conflicts.is_empty(), "{}", conflicts.join("\n"));
    assert!(seen > 0, "the corpus holds zenoh flows that read yes");
    assert!(
        floors_from_bytes > 0,
        "a capture joined mid-session puts a floor under its batch size"
    );
}

#[test]
fn every_zenoh_session_of_the_corpus_reads_its_compression_and_its_grounds() {
    let mut failures = Vec::new();
    for (file, want) in COMPRESSION {
        let bytes =
            std::fs::read(corpus_dir().join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let d = Dissection::from_capture(&bytes).unwrap_or_else(|e| panic!("{file}: {e:?}"));
        let got = compression_readings(&d);
        if got != *want {
            failures.push(alloc::format!("{file}: {got:?}, pinned {want:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn tally(words: &[ZenohVerdict]) -> Tally {
    let n = |w: ZenohVerdict| words.iter().filter(|v| **v == w).count() as u64;
    (
        n(ZenohVerdict::Yes),
        n(ZenohVerdict::No),
        n(ZenohVerdict::Undecided),
    )
}

/// Every file's tally, `(file, without lz4, with lz4)`, measured on the date the
/// file entered the corpus (2026-10-26). A file with no lz4 batch has the same
/// tally twice; the three lz4 files read alike in both builds because a build
/// that cannot open lz4 weighs no unit it cannot open, and the batches too
/// small to compress carry the SN steps.
///
/// Each zenoh file is two flows, the router's with each client, and every one
/// reads `yes`, the two joined mid-session included: before the batch header
/// was inferred from the bytes, both flows of `zenoh-udp-lz4-midsession` read
/// `no`, the corpus's first finding. The DNS flows are one query and its
/// answer each, two units, which decide nothing: `undecided` is what they
/// should read.
const EXPECTED: &[(&str, Tally, Tally)] = &[
    ("zenoh-tcp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-tcp-midsession.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-udp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-tcp-lz4.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-udp-lz4-midsession.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-tcp-lz4-midsession.pcap", (2, 0, 0), (2, 0, 0)),
    // An upstream zenohd 1.5.0 router, zenoh-pico clients, 240 short sessions
    // (the handshake checks' population) and a link that drops 5% each way:
    // every flow `yes`, the lossy one on the SN steps that survive the loss.
    ("zenoh15-tcp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh15-tcp-midsession.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh15-udp-full.pcap", (2, 0, 0), (2, 0, 0)),
    // The eclipse/zenoh images of four more releases (2026-10-28), over TCP
    // and UDP unicast: every flow `yes`.
    ("zenoh-v1-10-0-tcp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-v1-10-0-udp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-v1-9-0-tcp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-v1-9-0-udp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-v1-8-0-tcp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-v1-8-0-udp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-v1-7-2-tcp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-v1-7-2-udp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-pico-tcp.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-pico-udp.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-handshakes.pcap", (240, 0, 0), (240, 0, 0)),
    ("zenoh-udp-lossy.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-udp-loss-1.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-udp-loss-10.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-udp-loss-20.pcap", (8, 0, 2), (8, 0, 2)),
    ("zenoh-tcp-loss-1.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-tcp-loss-5.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-tcp-reorder-25.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-tcp-dup-5.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-udp-reorder-25.pcap", (2, 0, 0), (2, 0, 0)),
    ("zenoh-udp-dup-5.pcap", (2, 0, 0), (2, 0, 0)),
    // A real link between two machines (an office Wi-Fi, 2026-10-27): the same
    // 1.10.1 router and clients, and zenoh-pico clients, off the loopback.
    ("link-tcp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("link-tcp-large.pcap", (2, 0, 0), (2, 0, 0)),
    ("link-tcp-midsession.pcap", (2, 0, 0), (2, 0, 0)),
    ("link-udp-full.pcap", (2, 0, 0), (2, 0, 0)),
    ("link-pico-tcp.pcap", (2, 0, 0), (2, 0, 0)),
    ("lan-dns.pcap", (0, 159, 28), (0, 159, 28)),
    ("lan-mdns.pcap", (0, 1, 18), (0, 1, 18)),
    ("lan-ssdp.pcap", (0, 2, 0), (0, 2, 0)),
    // The real implementations of three protocols that run beside zenoh, in
    // containers (2026-10-26). The forty MQTT connections that publish once and
    // leave lose their framing in both directions, from their SYN, and frame
    // no unit: model 2 weighs that (`stream_framing`, about six bits a
    // direction), and twenty-odd bytes a direction are rightly too few to say
    // `no` at 2^-20.
    ("stack-mqtt.pcap", (0, 4, 40), (0, 4, 40)),
    ("stack-rtps.pcap", (0, 9, 3), (0, 9, 3)),
    ("stack-coap.pcap", (0, 25, 0), (0, 25, 0)),
    // Upstream vsomeip between two containers: service discovery, a method
    // over UDP and TCP, and a field's notifications.
    ("stack-someip.pcap", (0, 5, 2), (0, 5, 2)),
    // HTTP/3 on aioquic, QUIC versions 1 and 2. Every one of the 23 QUIC
    // connections is `undecided`, as it should be: zenoh runs over QUIC too,
    // and a protected flow carries nothing that tells the two apart. The two
    // `no` are the host's own mDNS on the bridge.
    ("stack-quic.pcap", (0, 2, 23), (0, 2, 23)),
    // A busy network's own protocols (2026-10-27): DHCP between twelve
    // clients and a server, NTP between six clients and a server, LLMNR and
    // WS-Discovery between a file server and four askers. No flow reads
    // `yes`; NTP's 94 flows stay `undecided`, each a pair of 48-byte
    // datagrams, which leaves too little to say `no` at 2^-20.
    ("busylan-dhcp.pcap", (0, 21, 2), (0, 21, 2)),
    ("busylan-ntp.pcap", (0, 0, 94), (0, 0, 94)),
    ("busylan-wsd.pcap", (0, 8, 0), (0, 8, 0)),
    // Structured TCP, the first stream protocols besides MQTT (2026-10-27):
    // HTTP/1.1, plain and over TLS 1.2 and 1.3, 34 connections each. The
    // reader frames no unit of them and loses no framing (neither is weighed),
    // so all 68 flows are `undecided` with nothing weighed, which is why they
    // add no count to the weights.
    ("stack-http.pcap", (0, 0, 34), (0, 0, 34)),
    ("stack-tls.pcap", (0, 0, 34), (0, 0, 34)),
    ("stack-http-post.pcap", (0, 0, 28), (0, 0, 28)),
    // Stream protocols of databases (2026-10-28): neither opens with GET,
    // HTTP or a TLS ClientHello, so the stream reader takes their first two
    // bytes for a length prefix. No flow reads `yes`; PostgreSQL's three `no`
    // flows carry enough residual units to say so.
    ("stack-redis.pcap", (0, 0, 60), (0, 0, 60)),
    ("stack-postgres.pcap", (0, 3, 21), (0, 3, 21)),
    ("stack-ssh.pcap", (0, 2, 15), (0, 2, 15)),
    ("stack-smtp.pcap", (0, 0, 10), (0, 0, 10)),
];

#[test]
fn the_corpus_holds_both_error_rates_and_every_files_tally() {
    let entries = manifest();
    assert!(!entries.is_empty(), "the corpus holds no file");
    let mut rows = Vec::new();
    let mut failures = Vec::new();
    for entry in &entries {
        let bytes = std::fs::read(corpus_dir().join(&entry.file))
            .unwrap_or_else(|e| panic!("{}: {e}", entry.file));
        let d = Dissection::from_capture(&bytes)
            .unwrap_or_else(|e| panic!("{}: the capture reads: {e:?}", entry.file));
        let packets = crate::pcap::parse(&bytes)
            .unwrap_or_else(|e| panic!("{}: a classic pcap: {e:?}", entry.file))
            .packets
            .len() as u64;
        if packets != entry.packets {
            failures.push(alloc::format!(
                "{}: {packets} packets read, the manifest says {}",
                entry.file,
                entry.packets
            ));
        }
        let got = tally(&verdicts(&d));
        rows.push(alloc::format!(
            "{}: {:?} (yes, no, undecided)",
            entry.file,
            got
        ));
        match entry.hypothesis.as_str() {
            "other" if got.0 > 0 => failures.push(alloc::format!(
                "{}: {} flow(s) of another protocol read `yes`",
                entry.file,
                got.0
            )),
            "zenoh" if got.1 > 0 => failures.push(alloc::format!(
                "{}: {} zenoh flow(s) read `no`",
                entry.file,
                got.1
            )),
            "other" | "zenoh" => {}
            other => failures.push(alloc::format!("{}: hypothesis {other:?}", entry.file)),
        }
        let pinned = EXPECTED.iter().find(|(f, _, _)| *f == entry.file);
        match pinned {
            Some((_, plain, lz4)) => {
                let want = if wz_session_core::passive::OPENS_LZ4_BATCHES {
                    lz4
                } else {
                    plain
                };
                if got != *want {
                    failures.push(alloc::format!(
                        "{}: {:?}, pinned {:?} (yes, no, undecided)",
                        entry.file,
                        got,
                        want
                    ));
                }
            }
            None => failures.push(alloc::format!("{}: no pinned tally", entry.file)),
        }
    }
    for (file, _, _) in EXPECTED {
        if !entries.iter().any(|e| e.file == *file) {
            failures.push(alloc::format!("{file}: pinned, and not in the manifest"));
        }
    }
    std::println!("{}", rows.join("\n"));
    assert!(
        failures.is_empty(),
        "{}\n\n{}",
        failures.join("\n"),
        rows.join("\n")
    );
}

// The counts below are a build's that reads every codec and reassembles a stream: the
// null protocols' units read whole only where the codecs are, and an MQTT stream frames
// only where the reassembler is. A lean build reads fewer of them, so it states other
// counts, and the weights rest on this one.

/// One file's counts the measured weights rest on.
#[cfg(all(feature = "network-codecs", feature = "reassembly"))]
#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    /// Framing units read whole, residual, undecoded.
    units: [u64; 3],
    /// Stream directions whose framing held, or was lost first.
    framing: [u64; 2],
    /// Cookie echoes matched, differing.
    cookie: [u64; 2],
    /// Init pairs of opposite kinds, of one kind.
    roles: [u64; 2],
    /// Version headers of this reader's version, of another.
    versions: [u64; 2],
    /// SN steps that followed, that broke: reported, not weighed from here
    /// (`Check::eps_basis`).
    sn: [u64; 2],
}

#[cfg(all(feature = "network-codecs", feature = "reassembly"))]
impl Counts {
    fn and(&mut self, other: &Counts) {
        let add = |a: &mut [u64], b: &[u64]| {
            for (x, y) in a.iter_mut().zip(b) {
                *x += y;
            }
        };
        add(&mut self.units, &other.units);
        add(&mut self.framing, &other.framing);
        add(&mut self.cookie, &other.cookie);
        add(&mut self.roles, &other.roles);
        add(&mut self.versions, &other.versions);
        add(&mut self.sn, &other.sn);
    }
}

#[cfg(all(feature = "network-codecs", feature = "reassembly"))]
fn counts(d: &Dissection) -> Counts {
    use crate::zenoh_evidence::{Check, ZenohEvidence};
    let mut out = Counts::default();
    let mut add = |r: wz_session_core::passive::ReadingEvidence,
                   o: crate::session_table::SessionObservations,
                   e: ZenohEvidence| {
        out.units[0] += r.explained.units;
        out.units[1] += r.residual.units;
        out.units[2] += r.undecoded.units;
        out.framing[0] += o.framing_held;
        out.framing[1] += o.framing_lost;
        for (check, slot) in [
            (Check::CookieEcho, &mut out.cookie),
            (Check::InitRoles, &mut out.roles),
            (Check::VersionHeader, &mut out.versions),
            (Check::SnFollows, &mut out.sn),
        ] {
            let t = e.tally(check);
            slot[0] += t.confirmed;
            slot[1] += t.violated;
        }
    };
    for f in d.flows() {
        add(
            f.ingest.readings(),
            f.session_observations(),
            f.zenoh_evidence(),
        );
    }
    for f in d.datagram_flows() {
        add(
            f.ingest.readings(),
            f.session_observations(),
            f.zenoh_evidence(),
        );
    }
    out
}

/// THE MEASURED WEIGHTS REST ON THIS CORPUS. Model 2's counts
/// ([`crate::zenoh_evidence::model::measured`]) are measured again here, file
/// by file for the null protocols and summed over the zenoh files, so a file
/// added to the corpus, or a reader that reads one differently, fails here
/// until the counts and the weights computed from them move together.
///
/// The counts are a build's that opens lz4. A build that cannot reads the one
/// lz4 batch of `zenoh-tcp-lz4.pcap` that no plain unit stands beside as
/// `undecoded`, which it does not weigh ([`wz_session_core::passive::OPENS_LZ4_BATCHES`]).
#[cfg(all(feature = "network-codecs", feature = "reassembly"))]
#[test]
fn the_corpus_measures_the_counts_model_two_is_computed_from() {
    use crate::zenoh_evidence::model::measured;
    let mut zenoh = Counts::default();
    let mut failures = Vec::new();
    for entry in manifest() {
        let bytes = std::fs::read(corpus_dir().join(&entry.file))
            .unwrap_or_else(|e| panic!("{}: {e}", entry.file));
        let d = Dissection::from_capture(&bytes)
            .unwrap_or_else(|e| panic!("{}: the capture reads: {e:?}", entry.file));
        let c = counts(&d);
        if entry.hypothesis == "zenoh" {
            zenoh.and(&c);
            continue;
        }
        match measured::NULL.iter().find(|m| m.file == entry.file) {
            Some(m) if m.units == c.units && m.framing == c.framing => {}
            Some(m) => failures.push(alloc::format!(
                "{}: units {:?} framing {:?}, stated {:?} {:?}",
                entry.file,
                c.units,
                c.framing,
                m.units,
                m.framing
            )),
            None => failures.push(alloc::format!(
                "{}: units {:?} framing {:?}, and no member states it",
                entry.file,
                c.units,
                c.framing
            )),
        }
    }
    let want = Counts {
        units: if wz_session_core::passive::OPENS_LZ4_BATCHES {
            measured::ZENOH_UNITS
        } else {
            [measured::ZENOH_UNITS[0] - 1, 0, 1]
        },
        framing: measured::ZENOH_FRAMING,
        cookie: measured::ZENOH_COOKIE,
        roles: measured::ZENOH_ROLES,
        versions: measured::ZENOH_VERSIONS,
        sn: zenoh.sn,
    };
    if zenoh != want {
        failures.push(alloc::format!("zenoh: {zenoh:?}, stated {want:?}"));
    }
    let listed: Vec<String> = manifest().into_iter().map(|e| e.file).collect();
    for m in &measured::NULL {
        if !listed.iter().any(|f| f == m.file) {
            failures.push(alloc::format!(
                "{}: stated, and not in the manifest",
                m.file
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
