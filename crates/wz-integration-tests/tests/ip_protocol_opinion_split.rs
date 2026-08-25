// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2058 (open-debt item 250) — the FURNITURE class, split into the numbers a
//! shipped tool has an opinion about and the ones nobody here has examined.
//!
//! ## The gap this closes, in the item's own words
//!
//! Round 2010 derived `is_encapsulation`'s membership from the predicate and
//! pinned it: of the 256 IP protocol numbers, 2 are transport, 13 are
//! encapsulation, and 241 are furniture. The item was explicit that the count
//! did not close it — the claim riding on those 241 is "this could not have
//! carried a session", and outside ICMP and IGMP that claim is INHERITED FROM
//! ABSENCE. Nobody examined them; they simply fell off the end of a `matches!`.
//! Nothing separated a number somebody had judged from a number nobody had
//! looked at, so a tunnel sitting in the furniture pile was indistinguishable
//! from a protocol that genuinely terminates.
//!
//! Round 2010 also found THREE members by hand — 55 MOBILE, 98 ENCAP, 108
//! IPComp — by asking the item's own question of IANA's assignments. Doing that
//! by hand is the thing the item says will not scale, and it is right.
//!
//! ## What is actually available to judge with, measured rather than assumed
//!
//! Three throwaway probes settled this before a line of the test existed, and
//! two of them ruled a candidate OUT:
//!
//! * `/etc/protocols` (shipped by `netbase`) is NOT the IANA registry. Its own
//!   header says so — "If you need a huge list of used numbers please install
//!   the nmap package" — and it names 55 numbers in `0..=255`. So "absent from
//!   this file" does not mean "unassigned".
//! * `tcpdump` is a DECODER-PRESENCE oracle, not a registry: it decodes 25
//!   numbers and prints `ip-proto-N` for the rest. And it cannot be asked "is
//!   this a tunnel" in general — a probe carrying a complete inner IPv4/UDP
//!   datagram under every protocol number got the inner addresses revealed for
//!   protocol 4 ALONE, because every other tunnel has its own encapsulation
//!   header to build first. Adjudicating tunnels that way would mean
//!   reimplementing each tunnel, which is the thing under test.
//! * `nmap-protocols`, the full table `/etc/protocols` points at, is not on this
//!   machine.
//!
//! ## So the claim this gate makes is the one the sources are entitled to
//!
//! Not "IANA calls this a tunnel" — nothing here can say that. What two shipped
//! tools between them CAN say is whether a number is one anybody has an opinion
//! about at all: `netbase` names it, or `tcpdump` decodes it as something other
//! than an unknown. That splits the 241 into
//!
//! * **judged** — a real, named protocol this build has decided terminates. The
//!   claim is a judgement, and now it has a witness rather than a silence.
//! * **never examined** — the honest remainder, which is what "inherited from
//!   absence" meant, now NAMED as such instead of hiding inside a bigger number.
//!
//! And the direction that matters is the one that moves: a number that GAINS an
//! opinion — because `netbase` or `tcpdump` was updated — leaves the second pile
//! and reds this gate, so somebody decides whether it is a tunnel. That is the
//! mechanism whose absence made 55, 98 and 108 hand-finds. All three sit in the
//! judged pile today; before Round 2010 reclassified them the pile would have
//! been 46 and would have held exactly those three.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use wz_capture::link::LINKTYPE_RAW;

/// Where `netbase` puts its protocol table. Overridable so the arming
/// behaviour below can be driven in both directions without uninstalling
/// anything.
fn protocols_path() -> PathBuf {
    std::env::var_os("WZ_PROTOCOLS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/protocols"))
}

/// The numbers `wz_capture::link` treats as a tunnel to look through.
///
/// Held against the predicate itself below rather than trusted — this is the
/// spelling of the set, and the sweep is what makes it the set.
const WZ_ENCAPSULATION: &[u8] = &[4, 41, 47, 50, 51, 55, 94, 97, 98, 108, 115, 137, 143];

/// The numbers this build reads as a transport that terminates here.
const WZ_TRANSPORT: &[u8] = &[6, 17];

/// FURNITURE THAT A SHIPPED TOOL HAS AN OPINION ABOUT — the pile that carries a
/// JUDGEMENT rather than a silence.
///
/// Each of these is a protocol `netbase` names or `tcpdump` decodes, which this
/// build nevertheless reads as terminating. That is a decision; it is allowed to
/// be right, and it must not be invisible.
///
/// MEASURED at this pin, not listed by hand. A number joining this set means a
/// tool started having an opinion about something nobody here has judged, which
/// is exactly the moment to look — so the set is pinned rather than counted.
const FURNITURE_WITH_AN_OPINION: &[u8] = &[
    0, 1, 2, 3, 5, 8, 9, 12, 20, 22, 27, 29, 33, 36, 37, 38, 43, 44, 45, 46, 57, 58, 59, 60, 73,
    77, 81, 88, 89, 93, 103, 112, 113, 124, 132, 133, 135, 136, 138, 139, 140, 141, 142,
];

/// The fewest numbers the two sources must between them speak for before their
/// silence about the rest is worth anything.
///
/// The anti-vacuity floor. Both sources failing open — an unreadable file, a
/// `tcpdump` that prints nothing this parse recognises — would put all 256 in
/// the "never examined" pile and make every assertion below agree with itself.
const MIN_OPINIONS: usize = 40;

/// One IPv4 packet with the given protocol and an eight-byte body, in a
/// `LINKTYPE_RAW` capture. Raw rather than Ethernet so the protocol number is
/// the only thing `tcpdump` has to work from.
fn raw_ipv4_capture(proto: u8) -> Vec<u8> {
    let body = [0u8; 8];
    let mut ip = Vec::with_capacity(28);
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&28u16.to_be_bytes());
    ip.extend_from_slice(&1u16.to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.push(64);
    ip.push(proto);
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum: tcpdump reads it as unverified
    ip.extend_from_slice(&[10, 0, 0, 1]);
    ip.extend_from_slice(&[10, 0, 0, 2]);
    ip.extend_from_slice(&body);

    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&262_144u32.to_le_bytes());
    out.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(ip.len() as u32).to_le_bytes());
    out.extend_from_slice(&(ip.len() as u32).to_le_bytes());
    out.extend_from_slice(&ip);
    out
}

/// Every name `netbase` gives a number — several, for the aliases it carries.
type NamesByNumber = BTreeMap<u8, Vec<String>>;

/// Rows whose number cannot be an IP protocol field value, kept as `(name,
/// value)` so the test can say which name would have folded where.
type OutOfRangeRows = Vec<(String, u32)>;

/// Numbers `netbase`'s table names, and the out-of-range rows it also carries.
///
/// Returns `(named, out_of_range)`. The second is not a curiosity: this file
/// holds `mptcp 262`, and `262 & 0xFF` is 6, which is TCP. A parse that cast
/// before it range-checked would silently give TCP a second name and a reader
/// no way to tell.
fn parse_protocols(text: &str) -> (NamesByNumber, OutOfRangeRows) {
    let mut named: BTreeMap<u8, Vec<String>> = BTreeMap::new();
    let mut out_of_range = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut words = line.split_whitespace();
        let (Some(name), Some(number)) = (words.next(), words.next()) else {
            continue;
        };
        let Ok(value) = number.parse::<u32>() else {
            continue;
        };
        match u8::try_from(value) {
            Ok(byte) => named.entry(byte).or_default().push(name.to_string()),
            Err(_) => out_of_range.push((name.to_string(), value)),
        }
    }
    (named, out_of_range)
}

/// Ask `tcpdump` about one protocol number. `None` means it did not run at all.
fn tcpdump_decodes(dir: &Path, proto: u8) -> Option<bool> {
    let path = dir.join("probe.pcap");
    std::fs::write(&path, raw_ipv4_capture(proto)).ok()?;
    let out = Command::new("tcpdump")
        .arg("-nr")
        .arg(&path)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    Some(!text.contains(&format!("ip-proto-{proto}")))
}

// NO PROOF TAG, deliberately, and the same call R2054 and R2055 made next door.
// Layer A4 counts coverage against a foreign zenoh IMPLEMENTATION actually
// running. `tcpdump` is a foreign TOOL adjudicating an IP protocol table, not a
// zenoh peer, and `netbase` is a text file; this test spawns no implementation,
// so it contributes nothing to that accounting and must claim nothing there.
#[test]
fn the_furniture_class_splits_into_judged_and_never_examined() {
    let path = protocols_path();
    let dir = tempfile::tempdir().expect("tempdir for probe captures");

    // ── ARE THE SOURCES PRESENT? ──────────────────────────────────────────
    // Absent, this is a SKIP and not a pass -- but an armed lane turns it into
    // a failure. Both behaviours are driven before this file is believed:
    // asserting one and assuming the other is how a lane ends up green over an
    // oracle nobody provisioned.
    let table = std::fs::read_to_string(&path).ok();
    let tcpdump_ran = tcpdump_decodes(dir.path(), 6);
    if table.is_none() || tcpdump_ran.is_none() {
        if std::env::var("WZ_PROTO_REGISTRY_REQUIRE").is_ok() {
            panic!(
                "WZ_PROTO_REGISTRY_REQUIRE is set and a source did not answer \
                 ({} readable: {}, tcpdump ran: {}). The furniture split has no \
                 other adjudicator, so a lane that armed this flag was asking \
                 for the measurement, not for a skip",
                path.display(),
                table.is_some(),
                tcpdump_ran.is_some(),
            );
        }
        eprintln!(
            "skip: {} or `tcpdump` is not available here; set \
             WZ_PROTO_REGISTRY_REQUIRE=1 to make that a failure",
            path.display()
        );
        return;
    }
    let (named, out_of_range) = parse_protocols(&table.expect("checked above"));

    // ── THE OUT-OF-RANGE ROW, AND WHY IT IS ASSERTED ──────────────────────
    // `mptcp 262` is in this file and cannot be an IP protocol field value. The
    // assertion is not that it exists -- a future netbase may drop it -- but
    // that whatever is out of range STAYS out, rather than being folded into a
    // byte. 262 & 0xFF is 6.
    for (name, value) in &out_of_range {
        assert!(
            *value > u8::MAX as u32,
            "{name} {value} was filed as out of range and is not"
        );
        let folded = *value as u8;
        assert!(
            !named.get(&folded).is_some_and(|names| names.contains(name)),
            "{name} {value} folded into {folded} and gave that number a second \
             name; {folded} is {:?}",
            named.get(&folded),
        );
    }

    let mut decoded = BTreeSet::new();
    for proto in 0..=u8::MAX {
        if tcpdump_decodes(dir.path(), proto).unwrap_or(false) {
            decoded.insert(proto);
        }
    }
    let named: BTreeSet<u8> = named.keys().copied().collect();
    let opinionated: BTreeSet<u8> = named.union(&decoded).copied().collect();

    // ── ANTI-VACUITY ──────────────────────────────────────────────────────
    // Every claim below is about a population, and the failure mode of both
    // sources is to fall silent rather than to lie. A silent pair would put all
    // 256 numbers in "never examined" and agree with everything.
    assert!(
        opinionated.len() >= MIN_OPINIONS,
        "only {} of 256 protocol numbers drew an opinion from {} ({} named) or \
         tcpdump ({} decoded); the sources, not the assignments, are what \
         changed",
        opinionated.len(),
        path.display(),
        named.len(),
        decoded.len(),
    );
    assert!(!named.is_empty() && !decoded.is_empty(), "both must speak");

    // ── THE DERIVED CLASSES, READ OFF THE PREDICATE ITSELF ────────────────
    let mut encapsulation = BTreeSet::new();
    for proto in 0..=u8::MAX {
        if wz_capture::link::is_encapsulation(proto) {
            encapsulation.insert(proto);
        }
    }
    assert_eq!(
        encapsulation,
        WZ_ENCAPSULATION.iter().copied().collect::<BTreeSet<u8>>(),
        "this file's spelling of the encapsulation set and the predicate disagree"
    );

    // ── NO TUNNEL INVENTED OUT OF NOTHING ─────────────────────────────────
    let unwitnessed: Vec<u8> = encapsulation.difference(&opinionated).copied().collect();
    assert!(
        unwitnessed.is_empty(),
        "this build looks through {unwitnessed:?}, and neither {} nor tcpdump \
         has heard of them. A tunnel no shipped tool knows is a claim worth \
         re-reading",
        path.display(),
    );

    // ── THE SPLIT ITEM 250 ASKED FOR ──────────────────────────────────────
    let classified: BTreeSet<u8> = WZ_ENCAPSULATION
        .iter()
        .chain(WZ_TRANSPORT)
        .copied()
        .collect();
    let furniture: BTreeSet<u8> = (0..=u8::MAX).filter(|p| !classified.contains(p)).collect();
    let judged: BTreeSet<u8> = furniture.intersection(&opinionated).copied().collect();
    let never_examined: BTreeSet<u8> = furniture.difference(&opinionated).copied().collect();

    assert_eq!(
        judged,
        FURNITURE_WITH_AN_OPINION
            .iter()
            .copied()
            .collect::<BTreeSet<u8>>(),
        "the furniture numbers a shipped tool speaks for have moved. A number \
         ADDED here is one a tool started naming or decoding while this build \
         still reads it as terminating -- decide whether it is a tunnel, then \
         move it. A number REMOVED is a witness this pile has lost",
    );
    assert!(
        !judged.is_empty() && !never_examined.is_empty(),
        "the whole point is that furniture is TWO populations; one of them is \
         empty, so the split says nothing"
    );

    eprintln!(
        "IP protocol opinion split: {} named + {} decoded = {} with an opinion; \
         encapsulation {} (all witnessed), transport {}, furniture {} = {} judged \
         + {} never examined",
        named.len(),
        decoded.len(),
        opinionated.len(),
        encapsulation.len(),
        WZ_TRANSPORT.len(),
        furniture.len(),
        judged.len(),
        never_examined.len(),
    );
}
