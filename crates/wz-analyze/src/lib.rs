// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y664 (§1.2a) — the analyzer, as something a person can run.
//!
//! ## What was measured before this crate existed
//!
//! `Dissection::from_pcapng` had two callers in the whole workspace: one test
//! and the C ABI. Every round of this track from R311y648 on added a finding a
//! reader needs — this flow is TLS, here is how much of it there is, here is the
//! random it is keyed by, here is its plaintext — and none of them were reachable
//! without writing Rust. A library nobody can run is not an analyzer.
//!
//! ## Why the work is HERE and `main` is four lines
//!
//! Everything except opening files is in this module, taking bytes and
//! returning a string. That is what makes it testable without writing anything
//! to disk: the tests below drive whole captures and whole key logs through
//! [`analyze`] as `&[u8]`, and the binary's own job -- read two paths, print,
//! choose an exit code -- has nothing left in it to get wrong.

use wz_capture::report::CaptureReport;
use wz_capture::{CaptureError, Dissection};
use wz_tls_record::capture::CaptureOpener;
use wz_tls_record::keylog::KeyLog;
use wz_tls_record::quic::connection::{DirectionCensus, QuicFlowOpener, SequenceKey};

/// How the report should be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// Human-readable.
    #[default]
    Text,
    /// The JSON a consuming tool parses.
    Json,
}

/// Round 2001 (item 473) — which census plane `--csv` renders as ROWS.
///
/// An enum rather than a string carried to the render site, so the set this
/// build emits is a closed thing the parser can refuse against and the usage
/// text can list. A plane arriving as a typo would otherwise become an empty
/// table, which reads as "this capture carried nothing".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsvPlane {
    /// The keyexpr throughput plane: which keyexpr carried what.
    Throughput,
}

impl CsvPlane {
    /// The plane names this build emits, in the order a refusal lists them.
    ///
    /// ONE today, and the refusal names the set rather than saying "unknown":
    /// the other planes are typed tables of the same kind and each is an
    /// addition here, so a reader who asked for one must learn which exist
    /// rather than that theirs does not.
    pub const NAMES: &'static [&'static str] = &["throughput"];

    /// The plane a name means, or `None` if this build emits no such plane.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "throughput" => Some(Self::Throughput),
            _ => None,
        }
    }
}

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The capture file to read. Empty when [`Self::interface`] names a live
    /// tap instead — the two are alternatives and the parser refuses both.
    pub capture: String,
    /// Round 2001 (item 473) — render one census plane as CSV instead of the
    /// report. Implies that plane's census, so the table it renders exists.
    pub csv: Option<CsvPlane>,
    /// Round 1999 (item 470) — read from a live `AF_PACKET` tap on this
    /// interface instead of from a file.
    ///
    /// The capability was in the tree since R311y594 and no argv could reach
    /// it; the crate split of Round 1998 is what made the dependency payable.
    pub interface: Option<String>,
    /// Round 1999 — how long a live read runs, in milliseconds.
    ///
    /// REQUIRED with [`Self::interface`] and that is the point: a tap has no
    /// end, so a live read that stopped on its own would produce a report which
    /// looks complete because the TOOL stopped rather than because the traffic
    /// did. The bound is stated by the operator and NAMED in the report, on the
    /// same argument `--bounded` already makes for the dissection caps.
    pub live_ms: Option<u64>,
    /// NSS key logs to read alongside it, for the ordinary case where the
    /// keys were written by `SSLKEYLOGFILE` into a SEPARATE file from the
    /// capture. Keys embedded in the capture's own Decryption Secrets Blocks
    /// are always used and need no flag.
    ///
    /// R311y708 (Y4) — a LIST, because `--keylog` given twice used to keep the
    /// second and drop the first WITHOUT SAYING SO. That is the failure this
    /// tool exists to end, one level up: the operator with a client-side log and
    /// a server-side log got a report about half their keys and no indication
    /// that the other half had been discarded. Two endpoints writing two
    /// `SSLKEYLOGFILE`s is the ordinary shape of a two-sided capture, not an
    /// exotic one.
    pub keylogs: Vec<String>,
    /// How to render.
    pub format: Format,
    /// R311y666 (§1.2a) — list every flow, not just the capture-wide summary.
    pub per_flow: bool,
    /// R311y667 (§1.2a) — list the decoded MESSAGES, not just how many.
    pub per_message: bool,
    /// R311y709 (Y2) — the short-header connection id length, for a capture
    /// that begins MID-CONNECTION.
    ///
    /// Not on the wire and not inferable: both endpoints remember it from a
    /// handshake such a capture does not contain. `None` leaves the reader
    /// where it was, refusing 1-RTT packets by name.
    pub quic_cid_len: Option<usize>,
    /// R311y670 (§1.2a) — UDP ports the caller declares to be QUIC.
    ///
    /// The one fact about a mid-connection QUIC capture that cannot come from
    /// the bytes; see
    /// [`Dissection::from_capture_declaring_quic`](wz_capture::Dissection::from_capture_declaring_quic).
    pub quic_ports: Vec<u16>,
    /// R311y699 ([REDACTED-REQ]) — payload format declarations, as the LINES
    /// they were typed, in order. First matching rule wins.
    ///
    /// R2114 (open-debt item 237) — lines and not parsed halves. The halves
    /// come back from `parse_declaration` in the QUOTED spelling and
    /// `wz_capture::payload::formats::FormatMap::declare` is the boundary that
    /// reads them back, so splitting here and installing there skipped it: a
    /// pattern with an escaped separator arrived at the map with its
    /// backslashes intact and matched nothing. Holding the line means both
    /// consumption surfaces cross that boundary exactly once.
    pub payload_formats: Vec<String>,
    /// R311y720 (PF4) — declared field names, as the LINES they were typed, in
    /// order. First match wins.
    ///
    /// The analyzer never derives these. See
    /// `wz_capture::payload::formats::FormatMap::name_field` for why a name
    /// that did not come from the deployment would be invented.
    pub payload_field_names: Vec<String>,
    /// R311y720 (§D M3) — link types the caller declared as carrying raw zenoh
    /// SERIAL bytes. See `wz_capture::serial` for why they are declared.
    pub serial_linktypes: Vec<u32>,
    /// R311y670 (§1.2a) — the ceiling on messages listed per flow.
    ///
    /// R311y669 added the ceiling to the library and left `wz-analyze` passing
    /// `None` unconditionally, so the bound had no caller — the shape this crate
    /// exists to correct, one argument deep.
    pub max_messages: Option<usize>,
    /// R311y673 (§1.2a) — which of the three observer planes to build.
    pub census: Census,
    /// R311y675 (§1.1n) — dissect each message into its FIELDS, with the bytes
    /// each was decoded from.
    pub per_field: bool,
    /// R311y884 (open-debt item 234) — read the capture under the LIVE-TAP
    /// bounds instead of unbounded.
    ///
    /// `dropped_by_limits` — the group that says what staying inside the caps
    /// cost — was STRUCTURALLY zero on both consumption surfaces, because
    /// neither built a bounded dissection: this crate calls
    /// `from_capture_declaring`, which takes no limits, and the ABI's
    /// `wz_dissect_pcap_summary` calls `from_capture`. The one door that could
    /// make it non-zero, `wz_dissect_pcap_summary_bounded`, emits the SUMMARY
    /// and not the health group. So a cap biting was invisible everywhere, and
    /// its zeros read as evidence that nothing was dropped.
    ///
    /// The preset is `DissectionLimits::for_live_tap()` — the SAME one the ABI
    /// door uses, so the two surfaces answer one question rather than two.
    pub bounded: bool,
    /// R311y857 — the LOSS AND HEALTH counters, grouped by who lost the packet.
    ///
    /// A flag rather than always-on: the report already carries the five
    /// figures a reader needs to judge whether the capture is usable
    /// (`packets_skipped`, the three stream-health counts, the two invalid
    /// checksum counts), and the full group is thirty-six numbers a reader asks
    /// for when one of those five is non-zero.
    pub health: bool,
    /// R311y674 (§1.2a) — the SELECTOR narrowing what the planes count.
    ///
    /// Compiled at parse time rather than carried as text, so a selector that
    /// does not parse is refused before a file is opened and the analysis has
    /// no failure mode left for it.
    pub select: Option<wz_capture::filter::Filter>,
}

/// R311y673 (§1.2a) — which of `wz-capture`'s three OBSERVER PLANES the report
/// should carry.
///
/// # What was measured
///
/// [`CaptureReport`] has taken a throughput table, an exchange table and a
/// payload census since long before this crate existed, and renders all three in
/// both formats. Swept for consumers, `with_throughput` / `with_exchanges` /
/// `with_payloads` were called from exactly one place each -- `report.rs`'s own
/// `#[cfg(test)]` module -- and `wz-analyze` called none of them. The only
/// program a person runs attached NO plane, so every fact the three hold (which
/// keyexpr carries the traffic, how long a query took to answer, what the
/// payloads are) was unreachable without writing Rust. That is the exact shape
/// this crate was created to end, one layer further in.
///
/// # Why opt-in rather than always
///
/// Each plane is a SEPARATE walk of every frame in the capture
/// (`agg::aggregate`, `exchange::exchanges`, `payload::payloads`), and the cost
/// of walking the same frames three times has never been measured here. Charging
/// it to every reader who wanted a decryption summary would be a silent tax; the
/// flags make it a request. `Default` is all three off, which is exactly the
/// behaviour every existing caller already had.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Census {
    /// The keyexpr THROUGHPUT plane: rows per keyexpr, subtree rollups, the
    /// declaration resolution state.
    pub throughput: bool,
    /// The EXCHANGE plane: queries matched to their replies, first-reply delay,
    /// and the ones that were never answered.
    pub exchanges: bool,
    /// The PAYLOAD plane: what the samples carry, by shape and size.
    pub payloads: bool,
    /// R311y714 (§1.1f) — the NODE plane: the capture keyed by zid rather than
    /// by 5-tuple, and the links where both ends named themselves.
    ///
    /// Deliberately NOT in [`Self::all`]: `--census` is the three RECORD planes
    /// and this one folds handshakes, so a reader asking for the record
    /// censuses is not asking for a topology. It is its own flag.
    pub nodes: bool,
    /// R311y869 (§1.1f) — the INTEREST plane: the declarations the capture
    /// carried, and which traffic each covers.
    ///
    /// NOT in [`Self::all`] for the reason the node plane is not: `--census`
    /// asks what the records were, and this folds the CONTROL plane. It is
    /// also the one plane that needs another — the coverage is a join against
    /// the keyexpr table — so asking for it builds that table whether or not
    /// `--throughput` was given, which is stated here rather than left as a
    /// surprise in the timings.
    pub interests: bool,
}

impl Census {
    /// The three RECORD planes, which is what `--census` asks for.
    ///
    /// R311y714 — `nodes` is not among them, and the omission is the decision
    /// stated on the field: the topology plane folds handshakes rather than
    /// records, so a reader asking for the record censuses has not asked for
    /// it. `--nodes` is its own flag.
    pub const fn all() -> Self {
        Self {
            throughput: true,
            exchanges: true,
            payloads: true,
            nodes: false,
            interests: false,
        }
    }

    /// Whether any plane was asked for at all.
    pub const fn any(&self) -> bool {
        self.throughput || self.exchanges || self.payloads || self.nodes || self.interests
    }
}

/// Why a command line was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// No capture file was named.
    NoCapture,
    /// More than one capture file was named -- refused rather than silently
    /// analysing the last, because "which file did it read" is not a question a
    /// reader should have to work out from the output.
    TwoCaptures,
    /// A flag that takes a value was given none.
    MissingValue(&'static str),
    /// R311y670 — a flag whose value is not the kind of thing it takes.
    /// REFUSED rather than defaulted: `--quic htttp` silently ignored produces a
    /// report claiming a mid-connection QUIC capture carried zenoh, which is the
    /// exact wrong answer the flag exists to prevent.
    BadValue(&'static str, String),
    /// An unrecognised flag. REFUSED rather than ignored: a misspelt
    /// `--keylog` that is silently dropped produces a report saying the capture
    /// could not be decrypted, which is a wrong answer that looks like a right
    /// one.
    UnknownFlag(String),
    /// R311y674 — a selector the filter language did not accept, carrying the
    /// parser's OWN reason.
    ///
    /// [`BadValue`](Self::BadValue) would have fitted the shape and thrown the
    /// reason away. A selector is a small language with a column-accurate error,
    /// and "`--select` does not take `key = demo/**`" is a worse message than
    /// the one the parser already wrote.
    BadSelector(String),
    /// R311y674 — a selector was given and no plane was asked for.
    ///
    /// REFUSED rather than accepted as a no-op. The three census planes are the
    /// only thing a selector narrows, so `--select` alone changes nothing about
    /// the output, and a flag that silently does nothing is the shape this
    /// workspace turns into a refusal wherever a person typed the input.
    SelectWithoutPlane,
    /// R311y725 (N8) — a payload declaration was given and `--fields` was not.
    ///
    /// REFUSED on exactly the rule [`Self::SelectWithoutPlane`] states, and
    /// found by asking that rule's question of a neighbouring flag: the payload
    /// decoding is rendered by the FIELD listing and by nothing else, so
    /// `--payload-format demo/**=protobuf` alone changes not one byte of the
    /// output. It is the worse half of the silence R311y725 closed -- the
    /// run-time note tells a reader their declaration met no traffic, and this
    /// covers the case where the declaration was never consulted at all, so
    /// there was nothing for that note to be computed from.
    PayloadWithoutFields(&'static str),
    /// Round 1999 (item 470) — `--interface` was given together with a capture
    /// file. They are two sources for one report and picking one silently would
    /// make the other's presence meaningless.
    CaptureAndInterface,
    /// Round 1999 — `--interface` without `--for`.
    ///
    /// A live tap has no end. Choosing a default here would put a number in the
    /// report that the operator never chose and cannot see, and the whole
    /// reason the bound is reported is that a short read and a quiet network
    /// look identical.
    InterfaceWithoutBound,
    /// Round 1999 — a flag that cannot work on a live read was given with one.
    ///
    /// REFUSED on exactly [`Self::SelectWithoutPlane`]'s rule. QUIC recovery
    /// re-reads the CAPTURE's own bytes (`quic_pass`), which a tap does not
    /// keep, so `--quic` on a live read would be a flag that changes nothing.
    LiveCannotDo(&'static str),
    /// Round 2001 (item 473) — `--csv` named a plane this build does not emit.
    ///
    /// The message lists the set rather than saying "unknown", because the
    /// planes are typed tables of one kind and the reader's question is which
    /// of them they can have.
    UnknownCsvPlane(String),
    /// Round 2001 — `--csv` and `--json` together.
    ///
    /// Two renderings and one stdout. Picking either silently would make the
    /// other flag's presence meaningless, which is this parser's standing rule.
    CsvAndJson,
}

impl core::fmt::Display for UsageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoCapture => write!(f, "no capture file given"),
            Self::TwoCaptures => write!(f, "more than one capture file given"),
            Self::MissingValue(flag) => write!(f, "{flag} needs a value"),
            Self::UnknownFlag(flag) => write!(f, "unknown option `{flag}`"),
            Self::BadValue(flag, got) => write!(f, "{flag} does not take `{got}`"),
            Self::BadSelector(why) => write!(f, "--select: {why}"),
            Self::SelectWithoutPlane => write!(
                f,
                "--select narrows the census planes and none was asked for; \
                 add --census (or --throughput / --exchanges / --payloads)"
            ),
            Self::PayloadWithoutFields(flag) => write!(
                f,
                "{flag} is rendered by the field listing and it was not asked \
                 for; add --fields"
            ),
            Self::CaptureAndInterface => write!(
                f,
                "a capture file and --interface are two sources for one report; \
                 give one"
            ),
            Self::InterfaceWithoutBound => write!(
                f,
                "--interface needs --for <seconds>: a tap has no end, and a read \
                 that stopped on its own would report as though the traffic had"
            ),
            Self::LiveCannotDo(flag) => write!(
                f,
                "{flag} needs the capture's own bytes, which a live read does \
                 not keep; it would change nothing here"
            ),
            Self::UnknownCsvPlane(got) => write!(
                f,
                "--csv does not emit `{got}`; this build emits: {}",
                CsvPlane::NAMES.join(", ")
            ),
            Self::CsvAndJson => write!(
                f,
                "--csv and --json are two renderings and there is one output; \
                 give one"
            ),
        }
    }
}

/// The usage text, which is also the documentation of what this tool does.
pub const USAGE: &str = "\
wz-analyze -- read a zenoh capture and report what is in it

USAGE:
    wz-analyze <capture.pcapng|capture.pcap> [OPTIONS]
    wz-analyze --interface <name> --for <seconds> [OPTIONS]

OPTIONS:
    --interface <name>
                      read from a live AF_PACKET tap on this interface instead
                      of from a file. Needs CAP_NET_RAW; without it this says
                      so rather than reporting an empty capture. The kernel's
                      own drop count is reported beside what was read -- a
                      packet the kernel discarded because this reader was slow
                      leaves a hole indistinguishable from one the network
                      made, and a live read that could not see its own drops
                      would blame the network for this machine.
                      Refused together with a capture file, and with --quic /
                      --quic-cid-len: QUIC recovery re-reads the capture's own
                      bytes, which a tap does not keep, so those flags would
                      change nothing here.
    --for <seconds>   how long a live read runs. REQUIRED with --interface and
                      meaningless without it. A tap has no end, so a read that
                      stopped on its own would produce a report that looks
                      complete because the TOOL stopped rather than because the
                      traffic did -- the report NAMES this bound for the same
                      reason --bounded names the caps it bit.
    --keylog <file>   an NSS key log (SSLKEYLOGFILE) to decrypt TLS flows with.
                      Repeatable, and every one given is used -- a two-sided
                      capture usually has one log per endpoint. Keys carried
                      inside the capture's own Decryption Secrets Blocks are
                      used without this flag.
    --quic-cid-len <n>
                      the short-header connection id length, for a capture that
                      begins mid-connection. Not on the wire; both endpoints
                      remember it from a handshake such a capture lacks. Used
                      only where the key log holds exactly ONE connection, since
                      the ClientHello that names which one is also absent.
    --flows           list every flow, stream and datagram: endpoints, framing,
                      messages decoded, scouting messages, and for an encrypted
                      one whether its plaintext was read
    --messages        list the decoded messages themselves, under their flow,
                      with the direction, offset and namespace of each.
                      Implies --flows
    --json            render the report as JSON instead of text
    --csv <plane>     render ONE census plane as CSV rows instead of the
                      report, for the tool that reads tables. Turns that
                      plane's census on, so the table it renders exists.
                      REPLACES the report rather than adding to it: a CSV
                      stream holds one table, and a second appended after the
                      first is a file no reader of this format can open --
                      which is also why it is refused together with --json.
                      The rows are the ones --json emits, in the same order:
                      both renderings read the same typed table, so a row here
                      is a row there rather than a third opinion about what a
                      row is. `share_bp` is EMPTY, never 0, where the capture
                      holds no sizeable payload to be a share OF.
                      Planes: throughput.
    --payload-format <keyexpr>=<format>
                      decode the PAYLOAD of messages whose key expression
                      matches <keyexpr>, using <format>. Repeatable; the
                      first matching rule wins. Matching is zenoh's own
                      keyexpr dialect, so `demo/**` covers `demo/a`.
                      A sample whose OWN declared encoding contradicts the
                      rule is weighed against its own bytes -- an encoding
                      travels per sample, so one keyexpr can carry two, and
                      decoding a JSON body as protobuf invents fields. A
                      label those bytes BEAR OUT stops the rule and nothing
                      is decoded; a label they REFUTE is overridden, said
                      on its own line, and the fields are good. A publisher
                      that declared nothing is decoded. A rule that IS
                      applied and whose decoder then refuses the bytes is a
                      finding of its own: neither side was caught out by the
                      other, so what to go look at is the wire. Every
                      finding is also TOTALLED per topic under the listing,
                      so a rule that is wrong for a whole topic reads as one
                      line and not as one per message.
                      Also DEFINES a format this build does not ship, as
                      `#<name>=<layout>` -- e.g.
                      `#profile=counter:u16be,flags:u8,tail:rest` -- which a
                      rule then names like any other format. A definition
                      may be written before or after the rule that uses it.
                      The layout is a fixed record: `<name>:<type>` items,
                      comma-separated, with an optional `rest` last for a
                      variable tail. Bytes the layout does not account for
                      are a finding, not a quiet success. See PAYLOAD FIELD
                      TYPES below for the spellings.
                      A topic whose own name carries `:` or `=` is written
                      with a backslash: `demo/temp\\:c=profile`.
                      Needs --fields.
                      PAYLOAD FORMATS: cbor, json, protobuf
                      PAYLOAD MISBOUND: rule, publisher
                      PAYLOAD REFUSED UNDER: corroborated, unclaimed, refuted
    --payload-name <keyexpr>:<path>=<name>
                      name one decoded field path, e.g.
                      `demo/**:1=temperature`. Repeatable; the first matching
                      declaration wins. A schemaless protobuf walk recovers `1`
                      and its bytes and NEVER a name, so for that format this is
                      the only place a name can come from. A JSON walk is the
                      other case: the document names its own members, and those
                      names ARE the path (`$.sensor.temp`), so a declaration is
                      a rename rather than the only source. A `.` inside a JSON
                      key is escaped in the path (`a.b` becomes `a\\.b`) and a
                      backslash doubles, so a dotted key and a nested member are
                      different paths. Needs --fields.
    --serial <linktype>
                      treat packets on this pcap link type as raw zenoh SERIAL
                      bytes: COBS envelope, CRC32, handshake flags.
                      Repeatable. DECLARED because LINKTYPE_RTAC_SERIAL's
                      pseudo-header is not verifiable here, so nothing is
                      parsed out of one. A pcapng capture's two interfaces are
                      the line's two wires; a one-interface capture is read and
                      reports its direction as unattributed.
    --quic <port>     treat UDP traffic on this port as QUIC. Repeatable.
                      A capture that begins mid-connection carries nothing that
                      distinguishes a QUIC 1-RTT packet from a zenoh datagram --
                      measured, one such packet decodes as a complete zenoh
                      Fragment and the capture reports itself whole -- so this is
                      the only way to settle it, and the report says which flows
                      were declared rather than recognised
    --max-messages <n>  list at most n messages per flow, saying how many more
                      there were. Unbounded by default
    --throughput      the keyexpr plane: which keyexprs carry the traffic, with
                      subtree rollups and the declarations still unresolved
    --exchanges       the query plane: queries matched to their replies, the
                      first-reply delay, and the ones never answered
    --nodes           the node plane: the capture keyed by zid, and the
                      links where both ends named themselves
    --interests       the interest plane: every DeclareSubscriber,
                      DeclareQueryable and DeclareToken the capture carried,
                      and which traffic each one covers -- matched with
                      zenoh's own keyexpr dialect, so a `robot/**` subscriber
                      is reported as covering `robot/1/pose`. Names the two
                      findings a keyexpr ranking cannot: a declaration nothing
                      was published under, and traffic no declaration matches.
                      Builds the keyexpr table for the join whether or not
                      --throughput was given
    --payloads        the payload plane: what the samples carry, by shape
    --census          all three planes above. Each is a separate walk of every
                      frame, which is why they are asked for rather than always
                      built
    --fields          dissect each message into its FIELDS, printing the byte
                      range every field was decoded from. Answers which of
                      those bytes are the keyexpr -- the finest coordinate the
                      reader has without it is a whole record. Bounded by
                      --max-messages like the other listings
    --select <expr>   narrow the census planes to the records the selector
                      matches. Terms are `field op value`:
                        key == demo/**        dir == a       kind == query
                        bytes > 100           time < 5000    delay >= 10
                      joined with and / or / not and parentheses. The report
                      says how many records matched, how many were rejected,
                      and how many are UNDECIDED -- a keyexpr whose declaration
                      went past before the tap started cannot be judged, and
                      counting it as a non-match would make a short total look
                      whole
    --bounded         read the capture under the live-tap ceilings instead of
                      unbounded -- the same preset the C ABI's
                      wz_dissect_pcap_summary_bounded uses. Without it the
                      `dropped_by_limits` group is zero because no cap exists
                      to bite, which is not the same fact as nothing having
                      been dropped. WITH it that group is reported on its own,
                      whether or not --health was asked for: a ceiling you
                      asked for tells you when it bites
    --health          every loss counter this reader keeps, GROUPED BY WHO LOST
                      the packet, because that is the only part a reader can
                      act on: the capture tool's own admission (re-capture with
                      a bigger buffer), this dissection's caps biting (raise
                      them and the data comes back), and what the wire did --
                      fragment chains, retransmits, checksums, framing
                      desyncs, sequence gaps. The capture tool's figure is
                      `not reported` and never 0 on a format with nowhere to
                      record it, since a zero would read as a clean bill of
                      health. The report's own header already carries the five
                      figures that say whether this capture is usable at all
    -h, --help        print this and exit

PAYLOAD FIELD TYPES:
    u8, i8, u16le, u16be, i16le, i16be, u32le, u32be, i32le, i32be, u64le, u64be, i64le, i64be, f32le, f32be, f64le, f64be, rest
    Plus `bytesN` for exactly N raw bytes, rendered as hex, for any N above
    zero. These are the spellings a `#<name>=<layout>` definition may use --
    see --payload-format. `rest` takes every byte left and is only legal as
    the LAST field.
    Ask here rather than reading this reader's source: a deployment writing
    its own record layout needs the spellings before it has anything to run,
    and a list copied into its own notes ages the moment this one grows.

LINK TYPES READ:
    DECAPSULATED -- the link header is stripped and what is under it decoded:
    0 NULL, 1 ETHERNET, 101 RAW, 108 LOOP, 113 LINUX_SLL, 228 IPV4, 229 IPV6,
    271 VSOCK, 276 LINUX_SLL2
    DECLARED -- ANY link type at all, named with `--serial <linktype>`, whose
    packets are then taken as raw zenoh serial bytes: COBS envelope, CRC32,
    handshake flags. No link header is stripped, because none is assumed.
    A DECLARATION WINS over the list above, and this is the one interaction
    worth reading twice: `--serial 1` reads an ETHERNET capture as a serial
    line, finds no COBS envelope in it, and decodes nothing -- so declaring a
    type that is already on the first list is a way to get zero out of a
    capture that would otherwise have read.
    A capture whose packets carry a link type on NEITHER list is opened and
    counted, and none of it is decoded -- the report says which types it
    could not read. Ask here rather than there: an unread capture reports
    `messages decoded: 0`, and that is also what a capture with no zenoh
    traffic reports.

EXT BODIES READ:
    ZBuf  Auth/pubkey, Auth/usrpwd, Declare/timestamp,
          DeclareCommon/wire_expr, Del/source_info, Err/source_info,
          Init/auth, Init/multi_link, Init/shm, Interest/timestamp,
          Join/qos, NetworkOam/timestamp, Open/auth,
          Open/multi_link_syn, Push/timestamp, Put/source_info,
          Query/query_body, Query/source_info, Request/timestamp,
          Response/responder_id, Response/timestamp,
          ResponseFinal/responder_id, ResponseFinal/timestamp
    Z64   Declare/node_id, Declare/qos,
          DeclareQueryable/queryable_info, Fragment/qos, Frame/qos,
          Init/patch, Interest/node_id, Interest/qos, Join/patch,
          NetworkOam/qos, Push/node_id, Push/qos, Request/budget,
          Request/node_id, Request/qos, Request/target, Response/qos,
          ResponseFinal/qos, TransportOam/qos
    An extension body this list omits is COUNTED and NAMED but not
    OPENED: the report shows it as `value` -- raw bytes for a ZBuf, one
    number for a Z64 -- and that reads exactly like `there was no
    structure here`. Ask here rather than there, for the same reason as
    LINK TYPES READ above. The rows left out are left out on purpose and
    each carries a recorded reason: user `attachment` bytes have no
    declared structure to walk, a `Join` `shm` has no producer in this
    tree to judge a walker against, and a nonce or a millisecond
    timeout IS the number it carries.
    A row on this list can still be SILENT, and that is a reading too.
    Seven of the Z64 rows are narrowed by their receiver rather than
    read whole -- a node id keeps sixteen bits, a patch level eight, a
    reply budget thirty-two and a zero there means no budget at all --
    so they speak only when the value on the wire is not the value a
    peer acts on, adding `read_as` and `undefined_bits` beside it. On
    ordinary traffic they say nothing because there is nothing to say.
";

/// Parse a command line, `argv[0]` already removed.
pub fn parse(args: &[String]) -> Result<Options, UsageError> {
    let mut capture: Option<String> = None;
    let mut keylogs: Vec<String> = Vec::new();
    let mut format = Format::Text;
    let mut per_flow = false;
    let mut per_message = false;
    let mut quic_ports: Vec<u16> = Vec::new();
    let mut quic_cid_len: Option<usize> = None;
    let mut payload_formats: Vec<String> = Vec::new();
    let mut payload_field_names: Vec<String> = Vec::new();
    let mut serial_linktypes: Vec<u32> = Vec::new();
    let mut max_messages: Option<usize> = None;
    let mut census = Census::default();
    let mut select: Option<wz_capture::filter::Filter> = None;
    let mut per_field = false;
    let mut bounded = false;
    let mut health = false;
    let mut interface: Option<String> = None;
    let mut live_ms: Option<u64> = None;
    let mut csv: Option<CsvPlane> = None;
    let mut at = 0usize;
    while at < args.len() {
        let arg = &args[at];
        match arg.as_str() {
            "--json" => format = Format::Json,
            "--flows" => per_flow = true,
            "--throughput" => census.throughput = true,
            "--exchanges" => census.exchanges = true,
            "--payloads" => census.payloads = true,
            "--nodes" => census.nodes = true,
            "--interests" => census.interests = true,
            "--census" => census = Census::all(),
            "--fields" => per_field = true,
            "--bounded" => bounded = true,
            "--health" => health = true,
            "--select" => {
                at += 1;
                let raw = args.get(at).ok_or(UsageError::MissingValue("--select"))?;
                select = Some(
                    wz_capture::filter::Filter::parse(raw)
                        .map_err(|err| UsageError::BadSelector(err.to_string()))?,
                );
            }
            "--messages" => {
                // The messages are printed under their flow, so asking for them
                // asks for the flows too. Silently implying it beats refusing a
                // combination that has one sensible meaning.
                per_flow = true;
                per_message = true;
            }
            // R311y699 ([REDACTED-REQ]) — `<keyexpr pattern>=<format>`, repeatable.
            // REFUSED rather than defaulted on either half: a rule whose
            // format name this build has no decoder for would otherwise leave
            // the payload rendered as bytes while the reader believes their
            // rule is live -- the same failure mode the wildcard refusal in
            // `payload::formats` exists for.
            "--payload-format" => {
                at += 1;
                let raw = args
                    .get(at)
                    .ok_or(UsageError::MissingValue("--payload-format"))?;
                let bad = || UsageError::BadValue("--payload-format", raw.clone());
                // R311y856 — ONE parser for both consumption surfaces. The
                // flag says which KIND it accepts and the C ABI takes both in
                // one text; the dialect itself is written down once, in
                // `wz-capture`, so a rule a person tried here and then moved
                // into a config file is not re-spelled by a second reader.
                // R2114 (open-debt item 237) — the flag now takes a DEFINITION
                // too (`#<name>=<layout>`), which is how a deployment gets its
                // own format across without building this workspace. The
                // format-name check moved BELOW the argv loop, because a rule
                // may name a format a later flag defines and a check made here
                // would refuse the deployment's own format for being written
                // second.
                //
                // The RAW line is what is kept, not the parsed halves. Keeping
                // the halves is what made this surface disagree with the other
                // one: `parse_declaration` answers in the QUOTED spelling and
                // `FormatMap::declare` is the boundary that unquotes it, so a
                // pattern handed straight to `insert` arrived with its
                // backslashes still in it and matched no topic at all.
                let declaration = payload_formats::parse_declaration(raw).map_err(|_| bad())?;
                match declaration {
                    payload_formats::DeclarationText::Rule { .. }
                    | payload_formats::DeclarationText::Definition { .. } => {}
                    payload_formats::DeclarationText::Name { .. } => return Err(bad()),
                }
                payload_formats.push(raw.clone());
            }
            // R311y720 (PF4) — `<keyexpr>:<path>=<name>`. Refused at parse
            // time when any of the three is empty, for the reason
            // `--payload-format` refuses an unknown format name: a declaration
            // this reader silently drops leaves the deployment believing their
            // schema is live while every field still renders as a number.
            "--payload-name" => {
                at += 1;
                let raw = args
                    .get(at)
                    .ok_or(UsageError::MissingValue("--payload-name"))?;
                let bad = || UsageError::BadValue("--payload-name", raw.clone());
                // R311y856 — the same shared parser the sibling flag uses; see
                // there for why the dialect is written down once.
                let declaration = payload_formats::parse_declaration(raw).map_err(|_| bad())?;
                let payload_formats::DeclarationText::Name { .. } = declaration else {
                    return Err(bad());
                };
                // R2114 (open-debt item 237) — the RAW line, for the reason the
                // sibling flag above records: the parsed halves are the QUOTED
                // spelling, and handing them to `name_field` skipped the one
                // boundary that reads them back.
                payload_field_names.push(raw.clone());
            }
            // R311y720 (§D M3) — the link type a serial capture was written
            // with. DECLARED and never sniffed: `LINKTYPE_RTAC_SERIAL` (250)
            // carries a pseudo-header whose layout this machine cannot verify,
            // and a reader that parsed one from memory would report a guessed
            // direction as a measurement.
            "--serial" => {
                at += 1;
                let raw = args.get(at).ok_or(UsageError::MissingValue("--serial"))?;
                serial_linktypes.push(
                    raw.parse::<u32>()
                        .map_err(|_| UsageError::BadValue("--serial", raw.clone()))?,
                );
            }
            "--quic" => {
                at += 1;
                let raw = args.get(at).ok_or(UsageError::MissingValue("--quic"))?;
                quic_ports.push(
                    raw.parse::<u16>()
                        .map_err(|_| UsageError::BadValue("--quic", raw.clone()))?,
                );
            }
            // R311y709 (Y2) — bounded at the RFC's own maximum, refused rather
            // than clamped: a caller who typed 21 has a wrong number in hand,
            // and silently reading it as 20 would hide that from them.
            "--quic-cid-len" => {
                at += 1;
                let raw = args
                    .get(at)
                    .ok_or(UsageError::MissingValue("--quic-cid-len"))?;
                let n = raw
                    .parse::<usize>()
                    .map_err(|_| UsageError::BadValue("--quic-cid-len", raw.clone()))?;
                if n > 20 {
                    return Err(UsageError::BadValue("--quic-cid-len", raw.clone()));
                }
                quic_cid_len = Some(n);
            }
            "--max-messages" => {
                at += 1;
                let raw = args
                    .get(at)
                    .ok_or(UsageError::MissingValue("--max-messages"))?;
                max_messages = Some(
                    raw.parse::<usize>()
                        .map_err(|_| UsageError::BadValue("--max-messages", raw.clone()))?,
                );
            }
            // R311y708 (Y4) — PUSH, not assign. The assignment this replaced
            // kept the last `--keylog` and discarded every earlier one in
            // silence.
            "--keylog" => {
                at += 1;
                keylogs.push(
                    args.get(at)
                        .cloned()
                        .ok_or(UsageError::MissingValue("--keylog"))?,
                );
            }
            // Round 2001 (item 473) — and it TURNS THE PLANE ON. A flag that
            // asked for a rendering of a table the run did not build would emit
            // a header and nothing else, which reads as an empty capture.
            "--csv" => {
                at += 1;
                let raw = args.get(at).ok_or(UsageError::MissingValue("--csv"))?;
                let plane =
                    CsvPlane::parse(raw).ok_or_else(|| UsageError::UnknownCsvPlane(raw.clone()))?;
                match plane {
                    CsvPlane::Throughput => census.throughput = true,
                }
                csv = Some(plane);
            }
            "--interface" => {
                at += 1;
                interface = Some(
                    args.get(at)
                        .cloned()
                        .ok_or(UsageError::MissingValue("--interface"))?,
                );
            }
            // Seconds on the command line, milliseconds in `Options`: the
            // operator thinks in seconds and the pump loop thinks in the unit
            // its clock already speaks. A fractional value is accepted because
            // a two-second smoke read is a real thing to want.
            "--for" => {
                at += 1;
                let raw = args.get(at).ok_or(UsageError::MissingValue("--for"))?;
                let secs: f64 = raw
                    .parse()
                    .map_err(|_| UsageError::BadValue("--for", raw.clone()))?;
                if !(secs.is_finite() && secs > 0.0) {
                    return Err(UsageError::BadValue("--for", raw.clone()));
                }
                live_ms = Some((secs * 1000.0) as u64);
            }
            // A lone `-` is a filename by convention in no shell this tool
            // supports, and everything else beginning with `-` is a flag this
            // one does not know.
            other if other.starts_with('-') => return Err(UsageError::UnknownFlag(other.into())),
            other => {
                if capture.is_some() {
                    return Err(UsageError::TwoCaptures);
                }
                capture = Some(other.into());
            }
        }
        at += 1;
    }
    // R311y725 (N8) — a declaration the output has no place to render.
    // Checked before the literal below because that literal MOVES the vectors,
    // and the same rule `SelectWithoutPlane` applies: where a person typed the
    // input, a flag that silently does nothing becomes a refusal.
    if !per_field {
        if !payload_formats.is_empty() {
            return Err(UsageError::PayloadWithoutFields("--payload-format"));
        }
        if !payload_field_names.is_empty() {
            return Err(UsageError::PayloadWithoutFields("--payload-name"));
        }
    }
    // R2114 (open-debt item 237) — the format name a RULE points at, resolved
    // against this build's decoders plus the formats THIS argv described.
    //
    // Here rather than at the flag, because a definition may be written after
    // the rule that uses it -- the same order-independence `FormatMap::
    // declare_all` gives the other surface, which is a property the two must
    // share or a config file that works through the ABI fails here. Still a
    // parse-time refusal, because a rule naming a decoder that does not exist
    // is a mistake a reader wants before the run rather than a note inside a
    // report they are already reading.
    {
        let mut defined: Vec<&str> = Vec::new();
        for raw in &payload_formats {
            if let Ok(payload_formats::DeclarationText::Definition { name, .. }) =
                payload_formats::parse_declaration(raw)
            {
                defined.push(name);
            }
        }
        for raw in &payload_formats {
            if let Ok(payload_formats::DeclarationText::Rule { format, .. }) =
                payload_formats::parse_declaration(raw)
            {
                if payload_formats::builtin(format).is_none() && !defined.contains(&format) {
                    return Err(UsageError::BadValue("--payload-format", raw.clone()));
                }
            }
        }
    }
    // Round 1999 (item 470) — the live source's three refusals, in the order
    // that makes each message the useful one. Source first (which of the two
    // did you mean), then the bound (a tap has no end), then the flags a live
    // read cannot honour.
    if interface.is_some() {
        if capture.is_some() {
            return Err(UsageError::CaptureAndInterface);
        }
        if live_ms.is_none() {
            return Err(UsageError::InterfaceWithoutBound);
        }
        if !quic_ports.is_empty() {
            return Err(UsageError::LiveCannotDo("--quic"));
        }
        if quic_cid_len.is_some() {
            return Err(UsageError::LiveCannotDo("--quic-cid-len"));
        }
    } else if live_ms.is_some() {
        // `--for` alone bounds nothing: a file ends by itself.
        return Err(UsageError::LiveCannotDo("--for"));
    }
    if csv.is_some() && format == Format::Json {
        return Err(UsageError::CsvAndJson);
    }
    Ok(Options {
        capture: match (capture, &interface) {
            (Some(path), _) => path,
            (None, Some(_)) => String::new(),
            (None, None) => return Err(UsageError::NoCapture),
        },
        csv,
        interface,
        live_ms,
        keylogs,
        format,
        per_flow,
        per_message,
        quic_ports,
        quic_cid_len,
        payload_formats,
        payload_field_names,
        serial_linktypes,
        max_messages,
        census,
        per_field,
        bounded,
        health,
        select: match select {
            // A selector with nothing to narrow is a flag that does nothing.
            Some(_) if !census.any() => return Err(UsageError::SelectWithoutPlane),
            other => other,
        },
    })
}

/// What one analysis found, beyond the rendered report.
///
/// R311y716 — no longer `Copy`: it carries the verdict's REASONS, and a list is
/// the only shape that can say which of them. The alternative was a second
/// accessor that recomputes them, which is the two-opinions-about-one-capture
/// shape this crate has paid for before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The rendered report's own verdict: did this reader see the whole
    /// capture. Drives the exit code, so a script can tell a clean read from
    /// one with encrypted flows, gaps or dropped packets in it.
    pub complete: bool,
    /// R311y716 (§C G1 / [REDACTED-REQ]) — WHY, when [`Self::complete`] is false.
    ///
    /// Empty exactly when `complete`. A caller that has to act on the verdict
    /// -- an exit code is one action, a notification onto a live deployment is
    /// another -- needs the reason as much as the bool: "this capture is short"
    /// tells an operator to go and run the tool they were trying not to run.
    pub reasons: Vec<wz_capture::report::VerdictReason>,
    /// Encrypted flows the decryption pass fully opened.
    pub decrypted_flows: usize,
    /// Encrypted flows it did not.
    pub undecrypted_flows: usize,
    /// Key log lines that named a connection this crate can act on.
    pub key_log_connections: usize,
    /// Decryption Secrets Blocks skipped because they carry another protocol's
    /// secrets. Reported so "no keys" and "someone else's keys" stay apart.
    pub foreign_secrets_blocks: usize,
}

/// Read a capture and report on it.
///
/// `keylog` is an EXTERNAL key log, merged with whatever the capture file
/// carried in its own Decryption Secrets Blocks. Merged and not preferred:
/// a capture written by one tool and a key log written by the process under
/// test are the ordinary pair, and either may hold connections the other does
/// not.
pub fn analyze(capture: &[u8], keylog: Option<&[u8]>) -> Result<(String, Outcome), CaptureError> {
    analyze_with(capture, keylog, Format::Text, false, false)
}

/// [`analyze`], rendering in the format given.
///
/// R311y666 — `per_flow` appends a line per flow. The capture-wide report is a
/// SUMMARY, and a summary cannot answer "which connection"; a person looking at
/// a capture with two peers in it and one undecrypted flow has no way, from the
/// totals alone, to say which one it was.
pub fn analyze_with(
    capture: &[u8],
    keylog: Option<&[u8]>,
    format: Format,
    per_flow: bool,
    per_message: bool,
) -> Result<(String, Outcome), CaptureError> {
    analyze_with_limit(capture, keylog, format, per_flow, per_message, None)
}

/// [`analyze_with`], with a CEILING on how many messages one flow lists.
///
/// R311y669 (§1.2a) — R311y668 left the listing unbounded, and everything else
/// in this reader is bounded: a flow may hold up to
/// `wz_capture::tls::MAX_KEPT_RECORDS_PER_DIRECTION` records per direction, and
/// rendering all of them into one string makes the output's size depend on how
/// much traffic there was. That is the leak every `drops` counter in
/// `wz-capture` exists to prevent, arriving one layer up in the renderer.
///
/// `None` is unbounded and stays the DEFAULT, because the ordinary use of
/// `--messages` is a person reading a small capture and a ceiling they did not
/// ask for is its own silent narrowing. What the bound must never do is bite
/// quietly: where it cuts, the rendering says how many rows it left out --
/// `... N more not listed` in text, `message_list_omitted` in JSON -- on the
/// house rule that a bound reporting nothing reports itself as the wire.
pub fn analyze_with_limit(
    capture: &[u8],
    keylog: Option<&[u8]>,
    format: Format,
    per_flow: bool,
    per_message: bool,
    messages_per_flow: Option<usize>,
) -> Result<(String, Outcome), CaptureError> {
    analyze_declaring_quic(
        capture,
        keylog,
        format,
        per_flow,
        per_message,
        messages_per_flow,
        &[],
    )
}

/// [`analyze_with_limit`], told which UDP ports carry QUIC.
///
/// R311y670 (§1.2a) — the one fact a mid-connection QUIC capture cannot supply
/// about itself. See
/// [`Dissection::from_capture_declaring_quic`](wz_capture::Dissection::from_capture_declaring_quic)
/// for the measurement that makes a caller-supplied answer the only honest one.
pub fn analyze_declaring_quic(
    capture: &[u8],
    keylog: Option<&[u8]>,
    format: Format,
    per_flow: bool,
    per_message: bool,
    messages_per_flow: Option<usize>,
    quic_ports: &[u16],
) -> Result<(String, Outcome), CaptureError> {
    analyze_request(&Request {
        capture,
        keylog,
        format,
        per_flow,
        per_message,
        messages_per_flow,
        quic_ports,
        quic_cid_len: None,
        payload_rules: &[],
        payload_field_names: &[],
        serial_linktypes: &[],
        census: Census::default(),
        per_field: false,
        bounded: false,
        health: false,
        select: None,
        csv: None,
    })
}

/// R311y673 (§1.2a) — one analysis, described rather than enumerated.
///
/// # Why this type exists
///
/// The four functions above are the same function with one more argument each
/// time: R311y666 added `per_flow`, R311y667 `per_message`, R311y669
/// `messages_per_flow`, R311y670 `quic_ports`. Arity reached seven and this
/// round needed an eighth. Each addition was individually reasonable and the
/// sequence is a design smell — a positional list of five booleans and options
/// is a list callers get wrong silently, since every one of them type-checks in
/// any order.
///
/// So the knobs become FIELDS. The next one is a field with a name and a
/// default, not a new wrapper and a new positional slot, and the older functions
/// stay as they are: they are a stable surface with callers, and delegating
/// keeps them honest by construction rather than by a second copy of the logic.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// The capture file's bytes.
    pub capture: &'a [u8],
    /// An EXTERNAL key log, merged with whatever the capture carried itself.
    pub keylog: Option<&'a [u8]>,
    /// How to render.
    pub format: Format,
    /// List every flow rather than only the capture-wide summary.
    pub per_flow: bool,
    /// List the decoded messages themselves. Implies `per_flow`.
    pub per_message: bool,
    /// The ceiling on messages listed per flow; `None` is unbounded.
    pub messages_per_flow: Option<usize>,
    /// UDP ports the caller declares to be QUIC.
    pub quic_ports: &'a [u16],
    /// R311y709 (Y2) — the short-header connection id length a mid-connection
    /// capture cannot supply from its own bytes.
    pub quic_cid_len: Option<usize>,
    /// R311y699 ([REDACTED-REQ]) — payload format declarations, as the LINES a
    /// reader wrote. Applied to the field layer, so they need `per_field`.
    ///
    /// R2114 (open-debt item 237) — a line may be a RULE (`<keyexpr>=<format>`)
    /// or a DEFINITION (`#<format>=<layout>`), which is how a deployment
    /// describes a format this build does not ship.
    pub payload_rules: &'a [String],
    /// R311y720 (PF4) — declared field names, as the LINES a reader wrote.
    /// Applied to the decoded payload fields, so like
    /// [`Self::payload_rules`] they need `per_field`.
    pub payload_field_names: &'a [String],
    /// R311y720 (§D M3) — declared serial link types.
    pub serial_linktypes: &'a [u32],
    /// Which observer planes to build. See [`Census`].
    pub census: Census,
    /// R311y675 — dissect each message into its fields.
    pub per_field: bool,
    /// R311y884 — read under `DissectionLimits::for_live_tap()` rather than
    /// unbounded, so `dropped_by_limits` can be non-zero at all.
    pub bounded: bool,
    /// R311y857 — the loss and health counters, grouped by who lost the packet.
    pub health: bool,
    /// R311y674 — the selector narrowing what those planes count. `None`
    /// selects everything, which is what the planes' unfiltered entry points
    /// already pass.
    pub select: Option<&'a wz_capture::filter::Filter>,
    /// Round 2001 (item 473) — render ONE census plane as CSV rows instead of
    /// the report.
    ///
    /// Replaces the rendering rather than adding to it, because a CSV stream
    /// holds one table: appending a second would produce a file no reader of
    /// this format can open.
    pub csv: Option<CsvPlane>,
}

/// Read a capture and report on it, as [`Request`] describes.
pub fn analyze_request(request: &Request<'_>) -> Result<(String, Outcome), CaptureError> {
    // Round 1999 (item 470) — the ONE place a dissection was ever built from
    // bytes, lifted out so a caller that built one another way can reach the
    // report. `analyze_dissection` is the rest of this function, unchanged.
    let dissection = if request.bounded {
        Dissection::from_capture_declaring_bounded(
            request.capture,
            request.quic_ports,
            request.serial_linktypes,
            wz_capture::DissectionLimits::for_live_tap(),
        )?
    } else {
        Dissection::from_capture_declaring(
            request.capture,
            request.quic_ports,
            request.serial_linktypes,
        )?
    };
    analyze_dissection(dissection, request)
}

/// Report on a dissection the CALLER built, as [`Request`] describes.
///
/// Round 1999 (item 470) — a live tap is why this exists. A tap has no capture
/// file behind it, so the analyser cannot be the one to dissect: opening the
/// socket needs a privilege and reading it needs a stop rule, and both are the
/// caller's to decide.
///
/// ⚠ [`Request::capture`] IS STILL READ on this path, and by exactly one thing:
/// [`quic_pass`] re-reads the capture's own bytes to find QUIC packets, because
/// a QUIC flow is recovered from the packet record rather than from the
/// dissection. A caller with no capture bytes passes an empty slice and gets no
/// QUIC decryption — which is why `wz-analyze` REFUSES `--quic` together with a
/// live read rather than accepting a flag that would quietly do nothing.
pub fn analyze_dissection(
    dissection: Dissection,
    request: &Request<'_>,
) -> Result<(String, Outcome), CaptureError> {
    let mut dissection = dissection;
    let &Request {
        capture,
        keylog,
        format,
        per_flow,
        per_message,
        messages_per_flow,
        quic_ports,
        quic_cid_len,
        payload_rules,
        payload_field_names,
        serial_linktypes,
        census,
        per_field,
        bounded,
        health,
        select,
        csv,
    } = request;
    // R311y699 ([REDACTED-REQ]) — the rules become a MAP here, in the composition
    // root: `wz-capture` owns the mapping and never a format, so this is the
    // one place the two meet. A pattern the map refuses is a hard failure
    // rather than a rule silently dropped.
    let mut payload_map = wz_capture::payload::formats::FormatMap::new();
    let mut payload_refusals: Vec<FieldNote> = Vec::new();
    // R311y884 — the refusal names the declaration in the ONE spelling
    // `wz-capture` owns (`payload::formats::declaration_text`, the mirror of
    // `parse_declaration`). Hand-built `format!("{pattern}={name}")` here was
    // the third of three spellings open-debt item 235 names, and the one that
    // happened to be right — which is exactly why nobody noticed the render was
    // not.
    // R2114 (open-debt item 237) — every declaration goes through
    // `FormatMap::declare`, the SAME entry point the C ABI's text door uses.
    //
    // What stood here resolved the format name itself, spelled the refusal
    // itself, and handed `insert` the quoted halves — three second opinions
    // about a grammar `wz-capture` owns, and the third was measurably wrong
    // (item 462's quoting never reached this surface). The refusal now quotes
    // the reader's own LINE, which is what `Declaration::text` means by "how
    // the reader wrote it" and needs no second speller to stay true.
    //
    // Definitions first, so a rule may name a format defined by a later flag —
    // the order-independence `declare_all` gives the other surface.
    //
    // The whole install sits in a BLOCK so the closure's borrow of the refusals
    // ends with it, rather than being ended by a `drop` of something that
    // implements no `Drop` -- which clippy refuses, and is right to: it reads
    // as a resource being released and is only a scope being cut short.
    {
        let is_definition = |line: &str| {
            matches!(
                payload_formats::parse_declaration(line),
                Ok(payload_formats::DeclarationText::Definition { .. })
            )
        };
        let mut declare = |line: &str| {
            if let Err(err) = payload_map.declare(line) {
                payload_refusals.push(FieldNote::PayloadRuleRefused {
                    rule: line.to_owned(),
                    why: err.to_string(),
                });
            }
        };
        for line in payload_rules.iter().filter(|l| is_definition(l)) {
            declare(line);
        }
        for line in payload_rules.iter().filter(|l| !is_definition(l)) {
            declare(line);
        }
        // R311y720 (PF4) — the DECLARED names, installed into the same map and
        // refused the same way. A declaration that names a path under a pattern
        // no rule decodes is not an error: the reader may be declaring ahead of
        // the traffic, and the field simply renders unnamed until it appears.
        for line in payload_field_names {
            declare(line);
        }
    }
    let payload_formats = payload_map;
    // R311y726 — the map is COMPLETE from here on, and this run's ledger of
    // which declarations applied is a separate value that borrows it. Declared
    // at the point the map stops changing, because a ledger over a map still
    // being filled would be a set of handles into a moving list.
    let payload_declarations = Declarations::new(&payload_formats);
    // R311y884 (open-debt item 234) — bounded when the caller asked, and the
    // caller could not ask until this round. `dropped_by_limits` was zero on
    // every surface because no surface built a bounded dissection; zeros that
    // are structural read exactly like zeros that were measured.
    // Round 1999 (item 470) — the construction moved to `analyze_request`, the
    // only caller that has bytes to build from, and these three were read by
    // nothing else here. Named rather than dropped from the pattern so the
    // destructure keeps mirroring `Request` field for field: a pattern that
    // silently stops covering a struct is how a new option becomes one nothing
    // reads.
    let _ = (bounded, quic_ports, serial_linktypes);

    // The capture's own keys first, then the external log folded in.
    let (mut opener, foreign) = CaptureOpener::from_secrets_blocks(dissection.decryption_secrets());
    if let Some(text) = keylog {
        opener.absorb(KeyLog::parse(text));
    }
    let key_log_connections = opener.log().len();
    // The pass runs only where there ARE keys, and that is a truthfulness rule
    // rather than an optimisation. Run with an empty log, every flow is declined
    // as `no_key_for_session` -- "keys were supplied and none are for this
    // session" -- which is false about a run that had no keys at all.
    // `no_keys_supplied` is what such a flow reports when no pass has run, and
    // it is the accurate statement.
    // R311y677 — the field sink is installed BEFORE the pass, because the
    // plaintext exists only during it. A run that did not ask for fields passes
    // the no-op sink and the pass is byte-for-byte what it was.
    let mut fields = FieldSink::new(messages_per_flow);
    // R311y691 — the pass's own SUMMARY, which this reader dropped on the floor.
    //
    // `decrypt_with` has returned a `DecryptionSummary` since long before this
    // crate existed and every call here discarded it, which is the shape this
    // crate was created to end: a fact computed and reachable by nobody. Most of
    // it the report re-derives from the dissection, and one number it cannot --
    // `already_opened`, which is a fact about THIS PASS and not about the
    // capture, and is therefore gone the moment the summary is dropped.
    let pass = if key_log_connections > 0 {
        if per_field {
            dissection.decrypt_with_sink(&mut opener, &mut fields)
        } else {
            dissection.decrypt_with(&mut opener)
        }
    } else {
        wz_capture::DecryptionSummary::default()
    };

    // R311y671 — what the decryptor OBSERVED about its epoch changes, which the
    // dissection does not hold: the epochs are the opener's state, and until this
    // round the `KeyUpdate` messages announcing them were opened and read past.
    let epochs = opener.epoch_witness();
    // R311y698 (§1.2a) — THE QUIC PASS, which is the item this crate was
    // created to make unnecessary and which had never been written.
    //
    // `wz-tls-record::quic` could open a QUIC packet since R311y694 and nothing
    // called it: the register's whole §QUIC section reduced to "there is no
    // caller". It runs unconditionally rather than behind a flag, because the
    // Initial packet space needs NO key at all -- a capture with QUIC in it and
    // no key log still yields its handshake, its version, its connection ID and
    // its ClientHello, which is exactly what tells a reader whether the key log
    // they are about to fetch is the right one.
    //
    // R311y718 — MOVED ABOVE THE CENSUS PLANES, and the move is the round's
    // point rather than a tidy-up. The pass now FRAMES what it recovers
    // (`feed_quic_stream`), so a QUIC flow carries decoded zenoh messages the
    // moment it returns -- and every plane below is built by walking the
    // dissection once. Left where it was, throughput, exchanges, payloads and
    // the node census would each have censused the pre-QUIC view and reported a
    // floor as a total, which is the defect the comment two blocks up records
    // for the DECRYPTION pass in the same words. R311y716 shipped that exact
    // mistake in the alert path; this is the same seam and the same order rule.
    //
    // R311y718 — and the FIELD SINK goes with it, on the same argument the TLS
    // half makes two blocks up: the recovered bytes exist only inside the call,
    // so a `--fields` run over a `quic/...` capture had no window in which to
    // walk them. The no-op `()` when fields were not asked for is what
    // `decrypt_with` passes for the same reason.
    let (quic, quic_flows) = if per_field {
        quic_pass(
            capture,
            &mut dissection,
            opener.log(),
            quic_cid_len,
            &mut fields,
        )
    } else {
        quic_pass(
            capture,
            &mut dissection,
            opener.log(),
            quic_cid_len,
            &mut (),
        )
    };
    let flows = dissection.encrypted_flows();
    let decrypted_flows = flows.iter().filter(|f| f.not_decrypted.is_none()).count();
    // R311y673 — the three OBSERVER PLANES, built only where asked for.
    //
    // Each is a separate walk of every frame the dissection holds, and the
    // report borrows the tables rather than owning them, so they are bound here
    // and outlive the report by construction. Built AFTER the decryption pass on
    // purpose: a flow whose plaintext was just opened carries messages, and a
    // plane built before it would census the ciphertext-only view and report a
    // floor as a total.
    // R311y674 — ONE fold path, filtered or not. `Filter::any()` is the
    // identity the crate's own unfiltered entry points pass, and the reason it
    // exists is stated there: a filtered fold beside an unfiltered copy is two
    // things to keep in step.
    let everything = wz_capture::filter::Filter::any();
    let filter = select.unwrap_or(&everything);
    let throughput = census
        .throughput
        .then(|| wz_capture::agg::aggregate_where(&dissection, filter));
    let exchanges = census
        .exchanges
        .then(|| wz_capture::exchange::exchanges_where(&dissection, filter));
    let payloads = census
        .payloads
        .then(|| wz_capture::payload::payloads_where(&dissection, filter));
    // R311y714 (§1.1f) — built after the decryption pass with the rest, and
    // taking NO selector: `Filter`'s terms are record-level, and a node is
    // named by a handshake that has no keyexpr, kind or payload for them to
    // read. Same reason the QUIC pass below states, one plane over.
    // Round 2016 (item 268) — built when the node PLANE was asked for, or when
    // the INTEREST plane was, because "who declared this" is part of the
    // interest plane's answer and the join needs a census to make it. Exactly
    // the argument `interest_traffic` below makes about the throughput table:
    // built for the join, and attached as a plane only if the reader asked for
    // the plane.
    let node_census =
        (census.nodes || census.interests).then(|| wz_capture::node::nodes(&dissection));
    // R311y869 (§1.1f) — the interest plane and the table its coverage is a
    // join against, built HERE rather than inside the report so the coverage is
    // computed exactly once and against the table the rest of this report
    // describes. `--interests` without `--throughput` still needs the rows, so
    // the table is built for the join and simply not attached as a plane.
    let interest_census = census
        .interests
        .then(|| wz_capture::interest::interests(&dissection));
    let interest_traffic = interest_census.as_ref().map(|_| {
        throughput
            .clone()
            .unwrap_or_else(|| wz_capture::agg::aggregate_where(&dissection, filter))
    });
    let interest_coverage = match (&interest_census, &interest_traffic) {
        (Some(c), Some(t)) => Some(c.coverage(t)),
        _ => None,
    };
    // R311y706 (Y5) — and the report SAYS the selector did not reach this pass.
    //
    // The register carried this as "--select does not reach the QUIC pass", and
    // measuring narrowed it: `Filter`'s terms are ALL record-level -- key, dir,
    // kind, bytes, time, elapsed, offset, delay, replies, errs, first_reply,
    // completion -- and not one of them can be evaluated against a flow whose
    // records this reader has never decoded. So the selector is not UNWIRED
    // here, it is INAPPLICABLE, and wiring it would mean inventing a predicate
    // over bytes nobody has read.
    //
    // What was missing is therefore a SENTENCE, not a filter. A reader who
    // typed `--select` and saw QUIC rows had every reason to read them as
    // selected ones -- the same silence R311y667 closed for the planes that CAN
    // answer a selector and could not judge some of their records.
    let quic_unselected = select.is_some() && !quic_flows.is_empty();
    let mut report = CaptureReport::of(&dissection);
    report = report.with_quic_decryption(&quic);
    if let Some(table) = &throughput {
        report = report.with_throughput(table);
    }
    if let Some(table) = &exchanges {
        report = report.with_exchanges(table);
    }
    if let Some(table) = &payloads {
        report = report.with_payloads(table);
    }
    // Item 268 — the PLANE only when the reader asked for it, even though the
    // census above may have been built for the join alone.
    if census.nodes {
        if let Some(table) = &node_census {
            report = report.with_nodes(table);
        }
    }
    if let (Some(c), Some(cov)) = (&interest_census, &interest_coverage) {
        report = report.with_interests(c, cov, node_census.as_ref());
    }
    let report = report;
    // R311y716 ([REDACTED-REQ]) — the verdict AND its reasons, from ONE call. A
    // caller that took the bool here and re-derived the list somewhere else
    // could report a capture as short for a reason this run never found.
    let reasons = report.reasons();
    let outcome = Outcome {
        complete: reasons.is_empty(),
        reasons,
        decrypted_flows,
        undecrypted_flows: flows.len() - decrypted_flows,
        key_log_connections,
        foreign_secrets_blocks: foreign,
    };
    // Round 2001 (item 473) — the CSV rendering REPLACES the report, because a
    // CSV stream holds one table. The `Outcome` above is computed first and
    // unchanged: whether this reader saw the whole capture is a fact about the
    // capture, not about which of three documents was asked for, and an exit
    // code that moved with the rendering would be the wrong kind of surprise.
    //
    // The table is the one this run already folded (`--csv` turns its census
    // on), and it is re-folded here only if some future caller reaches this
    // path without the parser -- the same `unwrap_or_else` the interest plane
    // uses one screen up, rather than a panic in a library.
    if let Some(plane) = csv {
        let rows = match plane {
            CsvPlane::Throughput => {
                let table = throughput
                    .unwrap_or_else(|| wz_capture::agg::aggregate_where(&dissection, filter));
                wz_capture::census_csv::keyexprs_csv(&table)
            }
        };
        return Ok((rows, outcome));
    }
    // R311y668 — the JSON is COMPOSED and no longer spliced. The report names
    // its own keys ([`CaptureReport::json_fields`]) and this is the only place
    // that decides where the object begins and ends, so a flow list is one more
    // key rather than a second document appended after the first.
    let rendered = match format {
        Format::Text => {
            let mut rendered = report.to_text();
            rendered.push_str(&pass_lines(&pass, format));
            rendered.push_str(&key_mismatch_lines(&dissection, opener.log(), format));
            rendered.push_str(&epoch_lines(&epochs, format));
            rendered.push_str(&quic_lines(&quic_flows, format, messages_per_flow));
            if quic_unselected {
                rendered.push_str(
                    "  QUIC: the --select expression did not narrow these flows -- \
                     every one of its terms is about a decoded record, and this \
                     reader has decoded none of theirs\n",
                );
            }
            if per_field {
                rendered.push_str("fields:\n");
                rendered.push_str(&field_lines(
                    capture,
                    &dissection,
                    &fields,
                    format,
                    messages_per_flow,
                    &payload_declarations,
                    &payload_refusals,
                ));
            }
            // R311y885 — A BOUND IS NEVER SILENT. A reader who asked for
            // ceilings is told what they cost, without also having to ask for
            // the whole loss document; an unbounded run is not shown five
            // structural zeros it would have to know how to read. `--health`
            // still carries the group as one line of that document, from this
            // same emitter, so the two cannot disagree.
            if bounded {
                rendered.push_str(&wz_capture::report::dropped_by_limits_text(&dissection));
            }
            if health {
                // R311y857 — `wz-capture`'s own rendering, not a second
                // selection of the counters. Both surfaces read the same four
                // accessors in the same order, so neither can report a figure
                // the other omits.
                rendered.push_str(&wz_capture::report::health_text(&dissection));
            }
            if per_flow {
                rendered.push_str(&flow_lines(
                    &dissection,
                    format,
                    per_message,
                    messages_per_flow,
                ));
            }
            rendered
        }
        Format::Json => {
            let mut rendered = String::from("{");
            report.json_fields(&mut rendered);
            rendered.push_str(&pass_lines(&pass, format));
            rendered.push_str(&key_mismatch_lines(&dissection, opener.log(), format));
            rendered.push_str(&epoch_lines(&epochs, format));
            rendered.push_str(&quic_lines(&quic_flows, format, messages_per_flow));
            // ONE FACT, TWO RENDERINGS (R311y681): a consumer branching on
            // whether their selector reached these flows must not have to parse
            // the sentence a person reads.
            rendered.push_str(&format!(",\"quic_unselected\":{quic_unselected}"));
            if per_field {
                rendered.push(',');
                rendered.push_str(&field_lines(
                    capture,
                    &dissection,
                    &fields,
                    format,
                    messages_per_flow,
                    &payload_declarations,
                    &payload_refusals,
                ));
            }
            // R311y885 — the JSON half of "a bound is never silent", under the
            // key the ABI's census document uses for the same group. It rides
            // `--bounded` and not `--health`, so the combination a person
            // actually types (a ceiling, because their memory is finite) is
            // told what the ceiling cost.
            //
            // With BOTH flags the numbers appear twice, at the top level and
            // inside `health`. That is accepted rather than overlooked: one
            // location that does not move with a second flag is worth more to a
            // consumer than a document with no repetition in it, and both
            // spellings come from `dropped_by_limits_json`, so they cannot
            // drift apart the way two RENDERINGS would.
            if bounded {
                rendered.push_str(",\"dropped_by_limits\":");
                rendered.push_str(&wz_capture::report::dropped_by_limits_json(&dissection));
            }
            if health {
                // The SAME document `wz_dissect_pcap_summary` embeds, under the
                // same key. A second spelling here is what R311y857 moved the
                // emit into `wz-capture` to prevent.
                rendered.push_str(",\"health\":");
                rendered.push_str(&wz_capture::report::health_json(&dissection));
            }
            if per_flow {
                rendered.push(',');
                rendered.push_str(&flow_lines(
                    &dissection,
                    format,
                    per_message,
                    messages_per_flow,
                ));
            }
            rendered.push('}');
            rendered
        }
    };
    Ok((rendered, outcome))
}

/// R311y691 (§1.2a) — what THIS DECRYPTION PASS did, as opposed to what the
/// capture holds.
///
/// # Why the report cannot say it
///
/// [`CaptureReport`] reads the dissection, so every number it prints is a fact
/// about the CAPTURE: how many encrypted flows there are, how many opened, how
/// many records came out. A pass that ran and found every flow already settled
/// is invisible there -- the capture looks exactly as it did -- and the
/// difference is the whole of what a caller offering a `PlaintextSink` on a
/// second pass needs to know (R311y684).
///
/// So this is small on purpose: the three numbers the summary holds that the
/// dissection cannot re-derive. `flows` is what this pass CONSIDERED, `refused`
/// is what the opener declined before trying a record, and `already_opened` is
/// what it skipped because an earlier pass owned them.
///
/// # What this binary cannot make non-zero, said rather than implied
///
/// `already_opened` is a fact about a SECOND pass and `wz-analyze` runs one, so
/// from this command line it is always 0. It is rendered anyway because the
/// field exists and a consumer must not have to test for a key -- and it is
/// named here so the next round does not read its constancy as evidence that
/// the pass is idempotent, which is a different claim with its own test one
/// crate over.
///
/// Silent in text where there is nothing to say, like every other qualifier in
/// this rendering; structural in JSON, because a consumer must not have to test
/// for a key.
fn pass_lines(pass: &wz_capture::DecryptionSummary, format: Format) -> String {
    if format == Format::Json {
        // THREE numbers and not five. `records` and `frames` are the same facts
        // the report already prints from the dissection, and a fact rendered
        // twice is two things to keep in step -- the defect this crate found in
        // itself at R311y664 and has not repeated since.
        return format!(
            ",\"pass\":{{\"flows_considered\":{},\"flows_refused\":{},\
             \"already_opened\":{}}}",
            pass.flows, pass.refused, pass.already_opened
        );
    }
    if pass.already_opened == 0 {
        return String::new();
    }
    format!(
        "  pass: {} flow(s) were already opened by an earlier pass and were \
         skipped -- their plaintext was not offered again\n",
        pass.already_opened
    )
}

/// R311y708 (G2) — WHEN THE KEYS ARE FOR ANOTHER CONNECTION, NAME BOTH SIDES.
///
/// ## What was measured
///
/// `NotDecrypted::NoKeyForSession` means "keys were supplied, this flow has a
/// `Random`, and nothing supplied is for that session". Its doc says the remedy
/// is "find the right key log" — and the report gave a reader NOTHING to find it
/// with. They saw `"reason":"no_key_for_session"` and a `key_log_connections`
/// COUNT, so the two facts that decide what to do next — which connection this
/// capture is, and which connections their log holds — were both computed and
/// both unreachable.
///
/// `KeyLog::client_randoms` existed for exactly this and had ZERO callers in the
/// workspace (R311y708's zero-consumer sweep, the R311y673 class). So this is not
/// a new capability; it is the one already built, connected.
///
/// ## Why both lists rather than a verdict
///
/// The reader is shown the two SETS and left to compare them. A tool that said
/// "wrong key log" would be guessing between two very different situations that
/// produce the identical enum: the operator grabbed the wrong file, or they
/// grabbed the right file from the wrong one of two capture runs. The sets
/// distinguish those; a verdict does not.
fn key_mismatch_lines(dissection: &Dissection, log: &KeyLog, format: Format) -> String {
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    let wanted: Vec<[u8; 32]> = dissection
        .encrypted_flows()
        .iter()
        .filter(|f| f.not_decrypted == Some(wz_capture::tls::NotDecrypted::NoKeyForSession))
        .filter_map(|f| f.client_random)
        .collect();
    let held: Vec<String> = log.client_randoms().map(|r| hex(r)).collect();

    if format == Format::Json {
        // Emitted UNCONDITIONALLY, unlike the text line: a consumer branching on
        // this must be able to tell "no mismatch" from "this build predates the
        // field", and an absent key cannot say the first.
        return format!(
            ",\"key_mismatch\":{{\"unopened_sessions\":[{}],\"log_holds\":[{}]}}",
            wanted
                .iter()
                .map(|r| format!("\"{}\"", hex(r)))
                .collect::<Vec<_>>()
                .join(","),
            held.iter()
                .map(|r| format!("\"{r}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    if wanted.is_empty() {
        return String::new();
    }
    format!(
        "  key log: {} flow(s) name a session the supplied keys do not cover.\n    \
         this capture wants: {}\n    the key log holds: {}\n",
        wanted.len(),
        wanted.iter().map(|r| hex(r)).collect::<Vec<_>>().join(", "),
        if held.is_empty() {
            String::from("(nothing this reader could parse)")
        } else {
            held.join(", ")
        }
    )
}

/// R311y698 (§1.2a) — one QUIC flow, as far as this reader got into it.
#[derive(Debug, Clone)]
pub struct QuicFlowOutcome {
    /// The five-tuple.
    pub flow: wz_capture::link::FlowKey,
    /// Per-direction tallies, `[A, B]`.
    pub census: [DirectionCensus; 2],
    /// Which direction the client is, settled by whoever sent the first Initial.
    pub client_direction: Option<wz_session_core::passive::Direction>,
    /// The version the connection declared.
    pub version: Option<wz_tls_record::quic::QuicVersion>,
    /// Whether the key log held this connection's secrets.
    pub keys_installed: bool,
    /// Whether a ClientHello was found and its random read.
    pub client_hello_seen: bool,
    /// R311y710 (Y2) — the connection's identity was ADOPTED from a key log
    /// holding exactly one connection, rather than read off the wire.
    ///
    /// A PREMISE where `client_hello_seen` is evidence, and carried apart for
    /// the reason `QuicCensus::declared` is carried apart from recognition one
    /// crate over: a reader acts differently on "I saw this" and "I assumed
    /// this", and a rendering that shows only the consequence shows neither.
    pub identity_adopted: bool,
    /// Each recovered sequence: direction, which one, and how many contiguous
    /// bytes came out.
    pub sequences: Vec<(wz_session_core::passive::Direction, SequenceKey, usize)>,
    /// Sequences the table's bound refused, `[A, B]`.
    pub sequences_dropped: [usize; 2],
}

/// R311y698 (§1.2a) — open every QUIC flow the dissection found.
///
/// # Why this needed no seam in `wz-capture`
///
/// The register estimated this item as needing one -- `push_datagram` counts a
/// QUIC packet and returns without retaining its payload, so the bytes appear
/// to be gone. Measured instead of assumed, which is what R311y679 found for
/// datagram fields and what R311y694-R311y697 got wrong four times in a row:
/// the bytes are in the CALLER'S OWN FILE, `Reread` already parses it a second
/// time for `--fields`, `link::decapsulate` is public, and a datagram flow's
/// key is a public `FlowKey`. Nothing had to be added anywhere.
///
/// So this walks the capture once more, hands each QUIC flow's datagrams to its
/// own [`QuicFlowOpener`] in capture order, and retains nothing but what came
/// out. The cost is one extra parse of the caller's file, paid only by a capture
/// that HAS a QUIC flow -- the early return sits above it.
fn quic_pass(
    capture: &[u8],
    dissection: &mut Dissection,
    log: &KeyLog,
    cid_len: Option<usize>,
    sink: &mut impl wz_capture::PlaintextSink,
) -> (wz_capture::quic::QuicDecryption, Vec<QuicFlowOutcome>) {
    use wz_session_core::passive::Direction;

    let keys: Vec<wz_capture::link::FlowKey> = dissection
        .datagram_flows()
        .iter()
        .filter(|f| f.quic.is_some())
        .map(|f| f.flow)
        .collect();
    let mut summary = wz_capture::quic::QuicDecryption {
        flows_offered: keys.len(),
        ..Default::default()
    };
    if keys.is_empty() {
        return (summary, Vec::new());
    }
    let Some(file) = Reread::of(capture) else {
        // Unreadable on the second pass. The flows are still OFFERED, so the
        // summary says none were opened rather than saying there were none --
        // the distinction `CaptureNotReread` draws one plane over.
        return (summary, Vec::new());
    };
    let mut openers: Vec<(wz_capture::link::FlowKey, QuicFlowOpener)> = keys
        .iter()
        .map(|flow| {
            let opener = QuicFlowOpener::new(log.clone());
            // R311y709 (Y2) — the declaration reaches the OPENER, which is the
            // half y698's own register recorded as the failure mode one round
            // over: a flag the parser reads and nothing acts on.
            (
                *flow,
                match cid_len {
                    Some(len) => opener.declaring_short_connection_id_len(len),
                    None => opener,
                },
            )
        })
        .collect();

    let mut at = 0usize;
    while let Some(packet) = file.packet(at) {
        at += 1;
        let Ok(wz_capture::link::Transport::Udp(datagram)) =
            wz_capture::link::decapsulate(packet.link_type, packet.index, packet.data)
        else {
            continue;
        };
        let Some((_, opener)) = openers.iter_mut().find(|(f, _)| *f == datagram.flow) else {
            continue;
        };
        // The SAME direction rule the field walk uses (`packet_disagreement`),
        // called the same way rather than restated: two readers of one capture
        // that disagree about which half a packet is on would file a client's
        // stream under the server.
        let direction = if datagram.from_low {
            Direction::A
        } else {
            Direction::B
        };
        // R311y719 — the CAPTURE PACKET INDEX travels with the offer. It is the
        // only coordinate that survives decryption for an RFC 9221 datagram: a
        // recovered batch has no stream to be an offset into, and the ordinal
        // of the datagram within this pass is a number that would read as a
        // capture coordinate and is not one.
        opener.push_datagram(direction, packet.index, &datagram.payload);
    }

    let mut flows = Vec::new();
    for (flow, opener) in openers {
        let census = opener.census();
        let packets: usize = census.iter().map(|c| c.packets).sum();
        let opened: usize = census.iter().map(|c| c.opened).sum();
        summary.packets += packets;
        summary.packets_opened += opened;
        summary.packets_no_keys += census.iter().map(|c| c.no_keys).sum::<usize>();
        summary.packets_refused += census.iter().map(|c| c.refused).sum::<usize>();
        summary.crypto_bytes += census.iter().map(|c| c.crypto_bytes).sum::<usize>();
        summary.stream_bytes += census.iter().map(|c| c.stream_bytes).sum::<usize>();
        summary.datagram_bytes += census.iter().map(|c| c.datagram_bytes).sum::<usize>();
        summary.walks_stopped += census.iter().map(|c| c.walks_stopped).sum::<usize>();
        if opener.identity_adopted() {
            summary.flows_identity_adopted += 1;
        }

        // A flow is WHOLE when every packet in it opened. Zero packets is not
        // whole: a QUIC flow the dissection counted and this pass saw none of is
        // a disagreement between two reads of one file, not a success.
        if packets > 0 && opened == packets {
            summary.flows_opened += 1;
        }
        let mut sequences = Vec::new();
        for direction in [Direction::A, Direction::B] {
            for (key, reassembler) in opener.sequences(direction) {
                sequences.push((direction, key, reassembler.stream().len()));
                // R311y718 (§1.2a) — AND THE BYTES GO ON TO A ZENOH FRAMER.
                //
                // Until this round the recovered stream was MEASURED and never
                // read: this loop pushed its LENGTH into a listing and dropped
                // the bytes, so a QUIC capture whose keys were all present
                // reported `stream_bytes: 25` and `messages decoded: 0`. That is
                // the "recovered and never read" shape R311y705 named for the
                // TLS floor, still open on the transport underneath it.
                //
                // CRYPTO is offered too, and refused by the seam rather than
                // filtered out here. The distinction belongs on the far side
                // because it is the FRAMER's rule -- handshake bytes are a TLS
                // exchange with no zenoh in them -- and a caller that quietly
                // skipped them would leave `handshake_offers` at zero and make
                // a capture whose every stream is CRYPTO indistinguishable from
                // one that recovered nothing at all.
                let (stream_id, handshake) = match key {
                    SequenceKey::Stream(id) => (id, false),
                    SequenceKey::Crypto(space) => (space.index() as u64, true),
                };
                summary
                    .framing
                    .absorb(dissection.feed_quic_stream_with_sink(
                        flow,
                        direction,
                        stream_id,
                        handshake,
                        reassembler.stream(),
                        sink,
                    ));
            }
            // R311y719 — AND THE RFC 9221 DATAGRAMS, which is how zenoh's
            // `transport-link-quic-datagram` sends a batch. R311y718 closed the
            // stream half and left these counted in the unread floor, correctly
            // and visibly; this is the other half of the same seam.
            //
            // Each carries the index of the capture packet it came out of, and
            // that index is the coordinate the decoded messages are anchored
            // by -- the same anchor a cleartext datagram's messages use, and
            // the only one that survives decryption.
            for (origin, payload) in opener.datagrams(direction) {
                summary.framing.absorb(
                    dissection
                        .feed_quic_datagram_with_sink(flow, direction, *origin, payload, sink),
                );
            }
        }
        flows.push(QuicFlowOutcome {
            flow,
            census,
            client_direction: opener.client_direction(),
            version: opener.version(),
            keys_installed: opener.keys_installed(),
            client_hello_seen: opener.client_hello_seen(),
            identity_adopted: opener.identity_adopted(),
            sequences,
            sequences_dropped: opener.sequences_dropped(),
        });
    }
    // R311y718 — the stall, measured from the FINISHED dissection rather than
    // folded per offer. A stream fed twice has one leftover and not two, and a
    // sum over offers would report the first offer's pending bytes again after
    // the second offer consumed them. See `QuicStreamFeed::bytes_undecoded`.
    summary.framing.bytes_undecoded = dissection
        .datagram_flows()
        .iter()
        .flat_map(|f| f.quic_streams.iter())
        .map(|s| s.undecoded_bytes() as usize)
        .sum();
    (summary, flows)
}

/// R311y698 (§1.2a) — the per-flow QUIC detail, in whichever format.
///
/// Silent in text where there is nothing to say -- a capture with no QUIC in it
/// gets no line -- and absent from JSON on the same condition, because the
/// capture-wide `quic` object the report already emits is the structural one a
/// consumer branches on. This is the LISTING beside it.
fn quic_lines(flows: &[QuicFlowOutcome], format: Format, per_flow: Option<usize>) -> String {
    use wz_session_core::passive::Direction;

    if flows.is_empty() {
        return String::new();
    }
    if format == Format::Json {
        let mut out = String::from(",\"quic_flows\":[");
        for (index, flow) in flows.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"flow\":\"{}\",\"version\":{},\"client_direction\":{},\
                 \"client_hello\":{},\"identity_adopted\":{},\"keys_installed\":{},\
                 \"sequences_dropped\":[{},{}],\"directions\":[",
                escape(&format!("{:?}", flow.flow)),
                match flow.version {
                    None => String::from("null"),
                    Some(v) => format!("\"{v:?}\""),
                },
                match flow.client_direction {
                    None => String::from("null"),
                    Some(Direction::A) => String::from("\"A\""),
                    Some(Direction::B) => String::from("\"B\""),
                },
                flow.client_hello_seen,
                flow.identity_adopted,
                flow.keys_installed,
                flow.sequences_dropped[0],
                flow.sequences_dropped[1],
            ));
            for (index, census) in flow.census.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"packets\":{},\"opened\":{},\"no_keys\":{},\"refused\":{},\
                     \"frames\":{},\"walks_stopped\":{},\"crypto_bytes\":{},\
                     \"stream_bytes\":{},\"datagrams\":{},\"datagram_bytes\":{}}}",
                    census.packets,
                    census.opened,
                    census.no_keys,
                    census.refused,
                    census.frames,
                    census.walks_stopped,
                    census.crypto_bytes,
                    census.stream_bytes,
                    census.datagrams,
                    census.datagram_bytes,
                ));
            }
            out.push_str("],\"sequences\":[");
            let shown = per_flow.unwrap_or(flow.sequences.len());
            for (index, (direction, key, bytes)) in flow.sequences.iter().take(shown).enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"direction\":\"{}\",\"of\":\"{}\",\"bytes\":{bytes}}}",
                    match direction {
                        Direction::A => "A",
                        Direction::B => "B",
                    },
                    escape(&sequence_name(*key)),
                ));
            }
            out.push_str("]}");
        }
        out.push(']');
        return out;
    }
    let mut out = String::from("quic:\n");
    for flow in flows {
        out.push_str(&format!(
            "  {:?}: {}, {}\n",
            flow.flow,
            match flow.version {
                None => String::from("no long header seen"),
                Some(v) => format!("version {v:?}"),
            },
            // R311y710 (Y2) — the ADOPTED case comes FIRST, because it is the
            // one the two below cannot express. "keys installed from the log"
            // reads as evidence and is true of both, and a reader who cannot
            // tell an assumption from a reading has no way to doubt the right
            // one when the report is wrong.
            if flow.identity_adopted {
                "keys ASSUMED: no ClientHello here, and the key log held exactly \
                 one connection, taken to be this one"
            } else if flow.keys_installed {
                "keys installed from the log"
            } else if flow.client_hello_seen {
                "a ClientHello was read and the key log does not hold it"
            } else {
                "no ClientHello reached this reader, so no key log entry can be found"
            }
        ));
        for (index, census) in flow.census.iter().enumerate() {
            if census.packets == 0 {
                continue;
            }
            out.push_str(&format!(
                "    {}: {} of {} packet(s) opened ({} without a key, {} refused), \
                 {} handshake byte(s), {} stream byte(s), {} datagram(s)\n",
                if index == 0 { "A" } else { "B" },
                census.opened,
                census.packets,
                census.no_keys,
                census.refused,
                census.crypto_bytes,
                census.stream_bytes,
                census.datagrams,
            ));
            if census.walks_stopped > 0 {
                out.push_str(&format!(
                    "      WARNING: {} packet(s) carried a frame type this reader \
                     does not know, so their later frames went unread\n",
                    census.walks_stopped
                ));
            }
        }
        // R311y706 (Y5) — the SAME bound every other listing in this tool takes.
        // `--max-messages` reached the field rows, the message listing and the
        // datagram rows and stopped here, so a capture with many QUIC streams
        // printed all of them under a flag that said otherwise. And the bound
        // REPORTS ITSELF, which is this crate's rule for every bound that
        // bites: a listing short by rows nobody accounted for is a listing that
        // looks whole.
        let shown = per_flow.unwrap_or(flow.sequences.len());
        for (direction, key, bytes) in flow.sequences.iter().take(shown) {
            out.push_str(&format!(
                "    {} {}: {bytes} byte(s)\n",
                match direction {
                    Direction::A => "A",
                    Direction::B => "B",
                },
                sequence_name(*key),
            ));
        }
        if let Some(omitted) = flow.sequences.len().checked_sub(shown).filter(|n| *n > 0) {
            out.push_str(&format!("    ... {omitted} more sequence(s) not listed\n"));
        }
        if flow.sequences_dropped.iter().any(|n| *n > 0) {
            out.push_str(&format!(
                "    WARNING: {} and {} sequence(s) were refused by this reader's \
                 own table bound\n",
                flow.sequences_dropped[0], flow.sequences_dropped[1]
            ));
        }
    }
    out
}

/// How one recovered sequence is named in either rendering.
fn sequence_name(key: SequenceKey) -> String {
    match key {
        SequenceKey::Crypto(space) => format!("crypto/{}", space.name()),
        SequenceKey::Stream(id) => format!("stream/{id}"),
    }
}

/// R311y671 (§1.2a) — the epoch witness, in whichever format.
///
/// # Why this is reported at all
///
/// An epoch boundary is found by TRIAL: the current epoch refuses a record and
/// the next one accepts it. Sound, because a 128-bit AEAD tag is what decides —
/// but evidence that a new epoch ARRIVED, not that this reader understood why.
/// A post-handshake `KeyUpdate` is the sender's own announcement of the same
/// event, and this reader was already opening those records and reading straight
/// past them.
///
/// So the two numbers are printed side by side and never merged. Advances equal
/// to confirmations is a rekeying session captured whole; fewer confirmations
/// means at least one boundary rests on the trial alone — which is NOT a defect
/// (the first application epoch follows the handshake with no `KeyUpdate` at all)
/// but is a fact a reader weighing this decryption should have rather than infer.
///
/// Silent where there was nothing to say, like every other qualifier in this
/// rendering: a capture with no epoch change in it gets no line about epochs.
/// In JSON the key is STRUCTURAL, because a consumer must not have to test for it.
///
/// # R311y672 — and an unconfirmed change now says WHICH KIND it is
///
/// The round above printed one figure for every unconfirmed advance and one
/// parenthetical covering both reasons at once, which is the shape of a sentence
/// that cannot be acted on. The two are not the same fact:
///
/// - A boundary TLS **never announces** — 0-RTT to handshake, handshake to the
///   first application key — is ended by an encrypted `Finished`, so there is no
///   `KeyUpdate` to find and its absence proves nothing. Every capture taken from
///   the start of a connection has one.
/// - A **rekey** IS announced (RFC 8446 §4.6.3). An unconfirmed one means the
///   announcement was missed — a mid-session capture, a hole over the announcing
///   record — or that the trial crossed on a 128-bit coincidence. That is the
///   number a reader weighing this decryption actually wants.
///
/// Reported separately for the same reason `advances` and `advances_confirmed`
/// were never merged: a figure that sums two causes answers neither.
fn epoch_lines(witness: &[wz_tls_record::capture::EpochWitness; 2], format: Format) -> String {
    let [a, b] = witness;
    let advances = a.epoch_advances + b.epoch_advances;
    let confirmed = a.advances_confirmed + b.advances_confirmed;
    let unannounced = a.advances_unannounced + b.advances_unannounced;
    let unwitnessed = a.advances_unwitnessed + b.advances_unwitnessed;
    // R311y685 — and WHICH of the three causes, which the figure above sums.
    let before_first = a.advances_before_first_record + b.advances_before_first_record;
    let after_hole = a.advances_after_hole + b.advances_after_hole;
    let unexplained = a.advances_unexplained + b.advances_unexplained;
    let after_abandon = a.advances_after_abandoned_handshake + b.advances_after_abandoned_handshake;
    // R311y686 — of the KeyUpdates read, the ones that took reassembling, and
    // the handshake bytes this reader had to let go of.
    let reassembled = a.key_updates_reassembled + b.key_updates_reassembled;
    let abandoned = a.handshake_bytes_abandoned + b.handshake_bytes_abandoned;
    let updates = a.key_updates + b.key_updates;
    let requested = a.updates_requested + b.updates_requested;
    let answering = a.updates_answering + b.updates_answering;
    let unanswered = a.requests_unanswered + b.requests_unanswered;
    if format == Format::Json {
        return format!(
            ",\"epochs\":{{\"advances\":{advances},\"advances_confirmed\":{confirmed},\
             \"advances_unannounced\":{unannounced},\"advances_unwitnessed\":{unwitnessed},\
             \"advances_before_first_record\":{before_first},\
             \"advances_after_hole\":{after_hole},\
             \"advances_unexplained\":{unexplained},\
             \"advances_after_abandoned_handshake\":{after_abandon},\
             \"key_updates\":{updates},\"updates_requested\":{requested},\
             \"updates_answering\":{answering},\"requests_unanswered\":{unanswered},\
             \"key_updates_reassembled\":{reassembled},\
             \"handshake_bytes_abandoned\":{abandoned}}}"
        );
    }
    if advances == 0 && updates == 0 {
        return String::new();
    }
    let mut out = format!(
        "  epochs: {advances} key change(s), {confirmed} confirmed by a KeyUpdate; \
         {updates} KeyUpdate message(s) read\n"
    );
    if unannounced > 0 {
        out.push_str(&format!(
            "    {unannounced} crossed a boundary TLS never announces (handshake \
             to first application key) -- expected, nothing was missed\n"
        ));
    }
    if unwitnessed > 0 {
        out.push_str(&format!(
            "    {unwitnessed} was a rekey with NO KeyUpdate behind it -- the \
             announcement was missed and the boundary rests on the trial alone\n"
        ));
        // R311y685 — and WHICH of the three, because they carry different
        // remedies. Two are facts about the capture (it started late, or it
        // lost records) and one is a fact about this reader, and the figure
        // above sums all three.
        if before_first > 0 {
            out.push_str(&format!(
                "      {before_first} before this direction's first record -- \
                 the capture began mid-session and the announcement was never \
                 in it\n"
            ));
        }
        if after_hole > 0 {
            out.push_str(&format!(
                "      {after_hole} on a record with a hole in front of it -- \
                 the announcing record is one the capture lost\n"
            ));
        }
        if after_abandon > 0 {
            out.push_str(&format!(
                "      {after_abandon} after this direction let go of handshake \
                 bytes -- the announcement may be in the tail this reader could \
                 not assemble\n"
            ));
        }
        if unexplained > 0 {
            out.push_str(&format!(
                "      {unexplained} with none of those -- this reader was \
                 watching, lost nothing, and did not see the announcement\n"
            ));
        }
    }
    // R311y672 — the `update_requested` byte, which the round above opened and
    // read past. It is the only fact in this protocol that crosses the two
    // directions, so it is the only one that can explain an advance on the OTHER
    // side, and its absence explains one that never came.
    if requested > 0 {
        out.push_str(&format!(
            "    {requested} KeyUpdate(s) asked the peer to rekey; {answering} \
             answered\n"
        ));
    }
    if unanswered > 0 {
        out.push_str(&format!(
            "    {unanswered} request(s) still unanswered when the capture ended \
             -- an expected key change on the other direction did not arrive\n"
        ));
    }
    // R311y686 — a KeyUpdate found only because its bytes were held across
    // records. Said because the alternative reading of the same capture is the
    // one this reader used to give: an unexplained rekey.
    if reassembled > 0 {
        out.push_str(&format!(
            "    {reassembled} of them began in an earlier record and were read \
             by holding the tail across records\n"
        ));
    }
    if abandoned > 0 {
        out.push_str(&format!(
            "    {abandoned} handshake byte(s) were let go of without \
             completing a message -- an announcement this reader stopped being \
             able to look for\n"
        ));
    }
    out
}

/// R311y675 (§1.1n) — THE FIELD LAYER: which bytes of a message are which field.
///
/// # What was missing, in the store's own words
///
/// R311y641 gave each RECORD its span, and R311y645's carry stated the residue
/// exactly: "The analyzer's finest coordinate is a RECORD -- it can now point at
/// the bytes a record begins at and cannot say which of them are the keyexpr's
/// length prefix." `wz-session-core::dissect` walks every message into per-field
/// spans, is differentially gated against the generated codecs, and nothing in
/// the reader called a single `walk_*`.
///
/// # Why this needs no new accumulation
///
/// The obvious route -- keep each message's bytes on its `PassiveFrame` -- adds
/// an EIGHTH thing that grows with the input, and this crate's whole bound
/// discipline (`DissectionLimits`, and a paired counter for every bound that
/// bites) exists because seven was already too many. It is also unnecessary: the
/// bytes are ALREADY retained, in the one place they have to be, and already
/// bounded there by `stream_bytes_per_direction`.
///
/// So the walk is done AGAIN, on demand, from `StreamAssembler::stream()` at the
/// coordinates the frame already carries. Nothing is stored; the cost is one
/// walk per message a reader asked to see, bounded by `--max-messages` like
/// every other listing.
///
/// # And where the bytes are gone, it says so
///
/// `retained_from()` is the offset the assembler has trimmed to. A frame older
/// than that had its bytes dropped to stay inside the bound, and this reports
/// that rather than skipping the row -- the rule stated at
/// `DissectionDrops`: a dissection that drops to stay inside its budget and does
/// not say so is the failure this crate is built to avoid.
fn field_lines(
    capture: &[u8],
    dissection: &Dissection,
    decrypted: &FieldSink,
    format: Format,
    messages_per_flow: Option<usize>,
    payload_formats: &Declarations<'_>,
    payload_refusals: &[FieldNote],
) -> String {
    use wz_session_core::dissect::to_json;

    // R311y681 — the listing is BUILT as flows, each carrying its rows and the
    // notes that belong beside them, and rendered once per format at the end.
    // Both renderings then read the same values, so neither can carry a notice
    // the other lacks -- which is exactly what this round found: five notices
    // written straight into the text branch and invisible to a consumer.
    let mut listings: Vec<FlowListing> = Vec::new();
    // R311y699 — a rule this reader would not install leads the listing, so a
    // reader sees it before the rows it expected the rule to change.
    if !payload_refusals.is_empty() {
        listings.push(FlowListing {
            rows: String::new(),
            notes: payload_refusals.to_vec(),
        });
    }
    // R311y675 — the separator belongs to the ROW, not to the flow. Counting
    // flows put one comma between two flows and NONE between the rows inside
    // one, which concatenated JSON objects into a document no parser accepts.
    // Measured by running it: the array read `...}}{"from":...`.
    let mut emitted = 0usize;
    for flow in dissection.flows() {
        let mut shown = 0usize;
        let mut omitted = 0usize;
        let mut rows = String::new();
        let mut notes: Vec<FieldNote> = Vec::new();
        // R311y701 (PF2) — this flow's keyexpr id tables, built AS THE ROWS ARE
        // WALKED. In order rather than up front on purpose: an id can be
        // undeclared and rebound, so a table folded to its final state would
        // resolve an early reference through a later binding and print a
        // keyexpr the sender never used.
        //
        // The granularity is the FRAMING UNIT and not the record, which is the
        // one place this differs from the throughput plane: a batch holding
        // `Declare(5)` then `Put(5)` resolves, and the reverse order -- which
        // no conforming sender emits -- would resolve too.
        let mut spaces = wz_capture::agg::KeyexprSpaces::new();
        for frame in &flow.frames {
            spaces.absorb_frame(frame);
            if let Some(cap) = messages_per_flow {
                if shown >= cap {
                    omitted += 1;
                    continue;
                }
            }
            let assembler = flow.assembler(frame.direction);
            let stream = assembler.stream();
            let origin = assembler.retained_from();
            let row = match decrypted_coordinates(flow) {
                // R311y677 — a decrypted flow's rows come from the SINK, which
                // took them while the plaintext existed. Emitted once for the
                // whole flow below rather than once per frame, since the sink
                // walked the stream itself and its rows are not this loop's.
                Some(_) => break,
                None => walk_message(stream, origin, frame),
            };
            shown += 1;
            if format == Format::Json && emitted > 0 {
                rows.push(',');
            }
            emitted += 1;
            render_field_row(
                &mut rows,
                format,
                flow,
                frame,
                &row,
                &to_json,
                PayloadLens {
                    formats: payload_formats,
                    spaces: &spaces,
                },
            );
        }
        // R311y677 — the sink's rows for this flow, if it was a decrypted one.
        //
        // R311y701 (PF2) — a decrypted flow BREAKS out of the loop above before
        // absorbing anything, so its declarations are folded here. All of them,
        // which is the generous form the ordered walk above deliberately is
        // not: the sink's rows do not travel with the frame that produced them,
        // so there is no point in the sequence to fold up to. A capture that
        // rebound an id would resolve an early row through the later binding,
        // and that is stated rather than hidden.
        if decrypted_coordinates(flow).is_some() {
            for frame in &flow.frames {
                spaces.absorb_frame(frame);
            }
        }
        for (f, direction, origin, space, row) in &decrypted.rows {
            if *f != flow.flow {
                continue;
            }
            if format == Format::Json && emitted > 0 {
                rows.push(',');
            }
            emitted += 1;
            render_sink_row(
                &mut rows,
                format,
                RowAt {
                    flow: flow.flow,
                    direction: *direction,
                    origin: *origin,
                    space: *space,
                },
                row,
                PayloadLens {
                    formats: payload_formats,
                    spaces: &spaces,
                },
            );
        }
        if let Some((_, n)) = decrypted.omitted.iter().find(|(f, _)| *f == flow.flow) {
            omitted += n;
        }
        // R311y677 — an ENCRYPTED flow that produced no rows says why, once. It
        // is the R311y676 refusal kept for the case the sink could not fill:
        // a flow whose plaintext was never opened has no bytes to walk, and
        // silence there would read as "this flow carried nothing".
        if rows.is_empty() {
            if let Some(why) = decrypted_coordinates(flow) {
                notes.push(FieldNote::NotDecrypted {
                    flow: flow.flow,
                    why,
                });
            }
        }
        // Per FLOW, like every other listing this tool bounds: a bound that
        // reports nothing reports itself as the wire.
        //
        // R311y681 — and it is reported whether or not a row survived it. The
        // `continue` above used to be reached first, so a flow whose every row
        // the bound took printed nothing AND said nothing: measured, a cleartext
        // capture under `--max-messages 0` was a silent empty listing.
        if omitted > 0 {
            notes.push(FieldNote::Omitted {
                flow: flow.flow,
                count: omitted,
            });
        }
        if rows.is_empty() && notes.is_empty() {
            continue;
        }
        listings.push(FlowListing { rows, notes });
    }
    // R311y679 — DATAGRAM flows, walked from the capture's own bytes.
    //
    // R311y678 declared this unreachable and needing a construction seam. That
    // was wrong, and measuring said so: `pcapng::parse` is public, `Packet`
    // carries `link_type` and `data`, `link::decapsulate` is public, and a
    // datagram frame's `stream_offset` IS its packet index. Nothing had to be
    // added to `wz-capture` and nothing has to be retained -- the capture bytes
    // are in the caller's hand, which is where they were the whole time.
    //
    // Re-parsed rather than kept: the file is already in memory and parsing it
    // twice costs a walk that only a reader who asked for `--fields` pays.
    datagram_field_rows(
        capture,
        DatagramWalk {
            dissection,
            decrypted,
            format,
            messages_per_flow,
            payload_formats,
        },
        &mut emitted,
        &mut listings,
    );
    // R311y725 (N8) — AFTER every row producer, because this is a fact about
    // what the capture turned out to hold and not about the declaration itself.
    //
    // Placed here rather than beside the refusals at the top for the reason the
    // ordering matters at all: both producers above consult the map while they
    // walk (`decode_payload`), and a listing built before `datagram_field_rows`
    // would report a declaration as unbound because the flow that binds it had
    // not been walked yet. That is the R311y700 shape -- a new plane reaching
    // one row producer -- and the placement is what avoids it rather than a
    // second traversal.
    let unbound: Vec<FieldNote> = payload_formats
        .unused()
        .into_iter()
        .map(|d| FieldNote::PayloadDeclarationUnbound {
            declaration: d.text,
            kind: d.kind,
        })
        .collect();
    if !unbound.is_empty() {
        listings.push(FlowListing {
            rows: String::new(),
            notes: unbound,
        });
    }
    render_listings(&listings, payload_formats, format)
}

/// R311y681 (§1.1n) — one flow's contribution to the field listing: the rows it
/// produced and the notes that belong beside them.
///
/// Rows are rendered as they are walked because their shape is per-format
/// already; notes are held as VALUES until the end, which is the whole point of
/// this type. A notice rendered at the point it is discovered has to be rendered
/// once per format, and the two copies then drift -- the shape R311y664 found by
/// running the binary, where one flow reported `NOT DECRYPTED` in text and
/// `"decrypted":true` in JSON in the same run.
struct FlowListing {
    /// The rows, already rendered in the requested format.
    rows: String,
    /// What could not be done, in the order it should be read.
    notes: Vec<FieldNote>,
}

/// R311y681 (§1.1n) — something the field layer could NOT do, held as a value.
///
/// # What was measured
///
/// Every notice this listing produces was written directly into the text branch
/// behind `format == Format::Text`: a flow whose plaintext was never opened, a
/// datagram flow nothing walkable came out of, a capture that could not be
/// re-read, a bound that left messages out, and a disagreement between this
/// reader's two reads of the file. Five notices, none of them reachable by a
/// consuming tool -- which sees an array that is SHORT and no key saying why.
///
/// That is the silence this track spent six rounds removing for a person and
/// left standing for a program, and the store's own carry has said so since
/// R311y678.
#[derive(Clone)]
enum FieldNote {
    /// The flow's messages came out of a decryption whose plaintext is not
    /// retained, so there are no bytes here to walk.
    NotDecrypted {
        flow: wz_capture::link::FlowKey,
        why: String,
    },
    /// A datagram flow this reader walked none of.
    NothingWalkable { flow: wz_capture::link::FlowKey },
    /// The capture could not be parsed a second time, so NO datagram flow could
    /// be walked. Capture-wide, and the only note with no flow.
    CaptureNotReread,
    /// R311y699 ([REDACTED-REQ]) — a payload-format rule this reader would not install.
    ///
    /// Capture-wide, like `CaptureNotReread`, and a NOTE rather than a silent
    /// drop: a rule that vanished leaves the reader believing their mapping is
    /// live while every payload under it renders as raw bytes. The command line
    /// refuses these at parse time; this covers a library caller, which is the
    /// path that would otherwise be silent.
    PayloadRuleRefused { rule: String, why: String },
    /// R311y725 (N8) — a payload declaration this reader INSTALLED and then
    /// applied to nothing.
    ///
    /// Capture-wide, and the counterpart to `PayloadRuleRefused`: that one says
    /// a declaration never took effect because it was rejected, this one says it
    /// took effect and met no traffic. The two failures look identical in the
    /// rows — every field renders unnamed — and send a reader to opposite
    /// places, which is why they are separate notes rather than one.
    PayloadDeclarationUnbound {
        /// The declaration in the syntax the reader typed it in, spelled by the
        /// map that accepted it rather than reassembled here.
        declaration: String,
        /// Which flag it arrived through.
        kind: wz_capture::payload::formats::DeclarationKind,
    },
    /// The `--max-messages` bound left messages out of this flow's listing.
    Omitted {
        flow: wz_capture::link::FlowKey,
        count: usize,
    },
    /// This reader's two reads of the file disagreed about the packet a message
    /// named.
    Disagreement {
        flow: wz_capture::link::FlowKey,
        /// How many disagreed in total. Exact, and unaffected by the bound
        /// below.
        count: usize,
        /// The ones named individually, bounded by the same `--max-messages`
        /// that bounds the rows.
        ///
        /// R311y680 reported the count ALONE, which loses the actionable half:
        /// a wrong index and a wrong flow point at different upstream changes,
        /// and a reader given only "3 skipped" cannot tell which to go look at.
        named: Vec<Disagreed>,
    },
}

/// R311y726 — THE DECLARATIONS IN FORCE FOR ONE RUN, and which of them applied.
///
/// R311y856 moved the type itself into `wz-capture`, beside the map it borrows,
/// so the C ABI can hold one too — the whole of that round. Everything R311y726
/// decided about it is unchanged and now lives on
/// [`wz_capture::payload_decode::Declarations`]; what stays here is the alias
/// this file reads by.
use wz_capture::payload_decode::Declarations;

/// R311y725 (N8) — the CLI's half of a declaration kind: the flag it was typed
/// as, the note kind a consumer branches on, and where the remedy lies.
///
/// R311y726 moved the KIND itself into `wz-capture`, where the distinction
/// between a rule and a name lives, and left these three here, where the
/// command line is. A flag name is not a property of the map.
fn declaration_flag(kind: wz_capture::payload::formats::DeclarationKind) -> &'static str {
    match kind {
        wz_capture::payload::formats::DeclarationKind::FormatRule => "--payload-format",
        wz_capture::payload::formats::DeclarationKind::FieldName => "--payload-name",
        // R2114 (open-debt item 237) — a DEFINITION is typed at the same flag
        // as the rule that uses it. One flag and not a fourth, because the two
        // are one subject: a reader saying which decoder reads which topic, and
        // saying what that decoder is when this build does not already know.
        wz_capture::payload::formats::DeclarationKind::FormatDefinition => "--payload-format",
    }
}

/// The machine-readable note kind. Spelled out rather than derived, on the rule
/// [`wz_capture::report::VerdictReason::name`] states: these go out in the
/// export and a consumer matches on them.
fn declaration_note_kind(kind: wz_capture::payload::formats::DeclarationKind) -> &'static str {
    match kind {
        wz_capture::payload::formats::DeclarationKind::FormatRule => "payload_rule_unbound",
        wz_capture::payload::formats::DeclarationKind::FieldName => "payload_name_unbound",
        // Its OWN kind, because the remedy differs: an unbound rule is a
        // pattern that missed, and an unbound definition is a format nothing
        // referred to at all.
        wz_capture::payload::formats::DeclarationKind::FormatDefinition => "payload_format_unused",
    }
}

/// What a reader should look at, which is the half that differs: a rule that
/// bound nothing means the PATTERN missed every topic, while a name that bound
/// nothing may have matched the topic and missed the PATH.
fn declaration_remedy(kind: wz_capture::payload::formats::DeclarationKind) -> &'static str {
    match kind {
        wz_capture::payload::formats::DeclarationKind::FormatRule => {
            "no key expression in this capture matched the pattern"
        }
        wz_capture::payload::formats::DeclarationKind::FieldName => {
            "no field this reader decoded sat at that path under a matching key expression"
        }
        wz_capture::payload::formats::DeclarationKind::FormatDefinition => {
            "no rule named this format, so nothing was decoded with it"
        }
    }
}

/// One message whose packet did not vouch for it, and why.
#[derive(Clone)]
struct Disagreed {
    /// The packet index the message named.
    at: usize,
    why: Disagreement,
}

/// Why a packet did not vouch for the message that named it.
#[derive(Clone)]
enum Disagreement {
    /// The second read has no packet at that index at all.
    Absent,
    /// It has one, and does not read it as a UDP datagram.
    NotUdp,
    /// It is a UDP datagram, and it disagrees about these coordinates.
    Coordinates(Axes),
}

/// Which of the three coordinates a packet disagreed about.
///
/// All three are reported, not just the first: they fail independently and a
/// reader chasing the cause needs to know whether one moved or all of them did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Axes {
    flow: bool,
    direction: bool,
    index: bool,
}

impl Axes {
    /// Whether the packet disagreed about anything at all.
    fn any(self) -> bool {
        self.flow || self.direction || self.index
    }

    /// The axes that disagreed, by name, in a fixed order.
    fn names(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.flow {
            names.push("flow");
        }
        if self.direction {
            names.push("direction");
        }
        if self.index {
            names.push("index");
        }
        names
    }
}

impl Disagreement {
    /// The machine-readable reason.
    fn kind(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::NotUdp => "not_udp",
            Self::Coordinates(_) => "coordinates",
        }
    }

    /// The same reason as a sentence.
    fn sentence(&self) -> String {
        match self {
            Self::Absent => "the second read has no packet at this index".into(),
            Self::NotUdp => "the second read does not read this packet as a UDP datagram".into(),
            Self::Coordinates(axes) => {
                format!("the packet disagrees about: {}", axes.names().join(", "))
            }
        }
    }
}

impl FieldNote {
    /// The flow this note is about, where it is about one.
    fn flow(&self) -> Option<&wz_capture::link::FlowKey> {
        match self {
            Self::NotDecrypted { flow, .. }
            | Self::NothingWalkable { flow }
            | Self::Omitted { flow, .. }
            | Self::Disagreement { flow, .. } => Some(flow),
            Self::CaptureNotReread
            | Self::PayloadRuleRefused { .. }
            | Self::PayloadDeclarationUnbound { .. } => None,
        }
    }

    /// The machine-readable kind, which is what a consumer branches on.
    fn kind(&self) -> &'static str {
        match self {
            Self::NotDecrypted { .. } => "not_decrypted",
            Self::NothingWalkable { .. } => "nothing_walkable",
            Self::CaptureNotReread => "capture_not_reread",
            Self::PayloadRuleRefused { .. } => "payload_rule_refused",
            Self::PayloadDeclarationUnbound { kind, .. } => declaration_note_kind(*kind),
            Self::Omitted { .. } => "omitted",
            Self::Disagreement { .. } => "disagreement",
        }
    }

    /// The prose, which BOTH renderings carry: the text listing as its line and
    /// the JSON as the `note` key beside the machine fields.
    ///
    /// One function, because a sentence written twice is two sentences to keep
    /// true.
    fn sentence(&self) -> String {
        match self {
            Self::NotDecrypted { why, .. } => format!("NO FIELDS -- {why}"),
            Self::NothingWalkable { .. } => {
                "NO FIELDS -- this reader walked none of this datagram flow's messages".into()
            }
            Self::CaptureNotReread => {
                "NO FIELDS -- this capture's packets could not be re-read to walk them".into()
            }
            Self::PayloadRuleRefused { rule, why } => {
                format!("payload-format rule `{rule}` was NOT installed -- {why}")
            }
            Self::PayloadDeclarationUnbound { declaration, kind } => format!(
                "{} `{declaration}` was installed and BOUND NOTHING -- {}",
                declaration_flag(*kind),
                declaration_remedy(*kind)
            ),
            Self::Omitted { count, .. } => format!("{count} more not listed"),
            Self::Disagreement { count, .. } => format!(
                "{count} message(s) skipped -- this reader's two reads of the file \
                 disagree about the packet they name"
            ),
        }
    }

    /// The note as the text listing prints it, indented to sit under its flow.
    fn to_text(&self) -> String {
        let sentence = self.sentence();
        match self {
            Self::NotDecrypted { flow, .. } | Self::NothingWalkable { flow } => {
                format!("  {} : {sentence}\n", endpoint(&flow.low))
            }
            Self::CaptureNotReread => format!("  datagram flow(s): {sentence}\n"),
            Self::PayloadRuleRefused { .. } | Self::PayloadDeclarationUnbound { .. } => {
                format!("  {sentence}\n")
            }
            Self::Omitted { .. } => format!("    ... {sentence}\n"),
            Self::Disagreement { named, .. } => {
                let mut out = format!("    {sentence}\n");
                for message in named {
                    out.push_str(&format!(
                        "      packet {}: {}\n",
                        message.at,
                        message.why.sentence()
                    ));
                }
                out
            }
        }
    }

    /// The note as JSON: the kind a consumer branches on, the flow it is about,
    /// whatever numbers it carries, and the sentence a person reads.
    fn to_json(&self) -> String {
        let mut out = format!("{{\"kind\":\"{}\"", self.kind());
        if let Some(flow) = self.flow() {
            // `low` / `high` and NOT `from` / `to`: a note is about a FLOW and
            // not about a direction, so borrowing the row keys would put a
            // directional name on a value that has no direction -- the label
            // defect R311y669 and R311y679 each removed once already.
            out.push_str(&format!(
                ",\"low\":\"{}\",\"high\":\"{}\"",
                endpoint(&flow.low),
                endpoint(&flow.high)
            ));
        }
        match self {
            Self::Omitted { count, .. } => out.push_str(&format!(",\"count\":{count}")),
            Self::Disagreement { count, named, .. } => {
                out.push_str(&format!(",\"count\":{count},\"messages\":["));
                for (i, message) in named.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&format!(
                        "{{\"at\":{},\"why\":\"{}\"",
                        message.at,
                        message.why.kind()
                    ));
                    if let Disagreement::Coordinates(axes) = &message.why {
                        let names: Vec<String> =
                            axes.names().iter().map(|n| format!("\"{n}\"")).collect();
                        out.push_str(&format!(",\"axes\":[{}]", names.join(",")));
                    }
                    out.push('}');
                }
                out.push(']');
            }
            _ => {}
        }
        out.push_str(&format!(",\"note\":\"{}\"}}", escape(&self.sentence())));
        out
    }
}

/// The two characters a JSON string cannot carry raw.
///
/// R311y681 — extracted rather than copied a third time: `render_field_row` had
/// it inline for a declined row's reason, and every note's sentence needs the
/// same treatment.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// R311y681 (§1.1n) — the whole field listing, in the requested format.
///
/// The JSON carries THREE keys and all of them are structural: `fields` is the
/// rows, `field_notes` is everything that could not become one, and R311y875's
/// `payload_mapping` is what the run learned about the rules themselves. A
/// consumer must never have to test for the key that explains a short array --
/// that is the same rule the epoch object follows, one listing over.
///
/// R311y875 — `declarations` rather than a pre-rendered list, because the answer
/// is only correct once every row producer has run and this is the first place
/// downstream of all of them.
fn render_listings(
    listings: &[FlowListing],
    declarations: &Declarations<'_>,
    format: Format,
) -> String {
    let mut out = String::new();
    match format {
        Format::Text => {
            for listing in listings {
                out.push_str(&listing.rows);
                for note in &listing.notes {
                    out.push_str(&note.to_text());
                }
            }
            // R311y875 — LAST, under every flow's own notes, because this is the
            // one finding here that is about the reader's command line rather
            // than about a flow. The same placement `PayloadDeclarationUnbound`
            // gets, and for the same reason.
            for misbinding in declarations.misbindings() {
                out.push_str("  ");
                out.push_str(&misbinding.sentence());
                out.push('\n');
            }
            // Round 2031 (item 300) — AND THE THIRD FINDING, in the same place
            // and for the same reason: a rule that was applied and whose
            // decoder refused is about the reader's command line or their
            // capture, not about one flow. It went out per message until this
            // round, so a capture whose rule cannot read a topic said so once
            // per row and never once as a finding.
            for refusal in declarations.refusals() {
                out.push_str("  ");
                out.push_str(&refusal.sentence());
                out.push('\n');
            }
            // Round 2029 (item 298) — AND WHETHER THOSE SAMPLE COUNTS ARE
            // WHOLE. Each sentence above says "N sample(s)", and the verdict
            // is reached during the walk, so `--max-messages` cuts the tally
            // as well as the listing. The FINDINGS survive — a rule bound to
            // the wrong thing shows in the first few samples — and it is the
            // numbers that go soft, which is why saying nothing was the
            // dangerous shape. Printed only when a cap actually bit.
            if !declarations.counts_are_exact() {
                out.push_str(&format!(
                    "  (those sample counts are a FLOOR: {} message(s) were not \
                     walked because of --max-messages, so no rule was applied \
                     to them)\n",
                    declarations.unwalked()
                ));
            }
        }
        Format::Json => {
            out.push_str("\"fields\":[");
            for listing in listings {
                out.push_str(&listing.rows);
            }
            out.push_str("],\"field_notes\":[");
            let mut first = true;
            for note in listings.iter().flat_map(|l| l.notes.iter()) {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&note.to_json());
            }
            out.push_str("],");
            // Through `wz-capture`'s own emitter and not spelled again here:
            // this document and the C ABI's must not disagree about the shape of
            // one finding.
            wz_capture::payload_decode::push_misbindings(Some(declarations), &mut out);
        }
    }
    out
}

/// What the field walk made of one message.
enum FieldRow {
    /// The bytes were there and the walker read them.
    Walked(wz_session_core::dissect::Field),
    /// They were not, and this is why. NEVER a skipped row: a message whose
    /// bytes the bound discarded is a fact about the bound.
    Declined(String),
}

/// R311y677 (§1.1n) — the field trees of every DECRYPTED flow, walked while the
/// plaintext existed.
///
/// R311y676 made `--fields` decline such a flow by name, which was honest and
/// was not the feature: TLS is the interesting case for an analyzer, and the
/// bytes are there for the duration of the decryption pass and nowhere after it.
/// This is the [`wz_capture::PlaintextSink`] that takes them at that moment.
///
/// # The bound is this type's own
///
/// `wz-capture` offers the plaintext and keeps nothing. What is kept here is
/// bounded by the same `--max-messages` that bounds every other listing, and the
/// count left out is kept beside it — a bound that reports nothing reports
/// itself as the wire.
#[derive(Default)]
struct FieldSink {
    /// `(flow, direction, stream offset of the record, what the walk made of
    /// it)`, in wire order.
    ///
    /// R311y683 — a [`FieldRow`] and no longer a bare tree, so a message the
    /// walker refuses inside TLS is DECLINED by name instead of vanishing from
    /// the listing. It was dropped by an `if let Ok`, which is the silence this
    /// whole track exists to end, arriving inside the one transport where a
    /// reader cannot check by eye.
    /// R311y718 — and the COORDINATE SPACE that offset is in, carried rather
    /// than assumed by the renderer.
    ///
    /// It was `CiphertextRecord` at every render site while TLS was the only
    /// producer. A recovered QUIC stream has no ciphertext record to point back
    /// at — its offsets are bytes into the reassembled stream — so a renderer
    /// that stated the space itself would label one producer's rows with the
    /// other's, in a field whose whole purpose is telling three small numbers
    /// apart (see [`OffsetSpace`]).
    rows: Vec<(
        wz_capture::link::FlowKey,
        wz_session_core::passive::Direction,
        usize,
        OffsetSpace,
        FieldRow,
    )>,
    /// Messages the bound left out, per flow.
    omitted: Vec<(wz_capture::link::FlowKey, usize)>,
    /// The ceiling on rows kept per flow; `None` is unbounded.
    cap: Option<usize>,
}

impl FieldSink {
    fn new(cap: Option<usize>) -> Self {
        Self {
            cap,
            ..Default::default()
        }
    }

    fn kept_for(&self, flow: &wz_capture::link::FlowKey) -> usize {
        self.rows.iter().filter(|(f, ..)| f == flow).count()
    }

    fn note_omitted(&mut self, flow: wz_capture::link::FlowKey) {
        match self.omitted.iter_mut().find(|(f, _)| *f == flow) {
            Some((_, n)) => *n += 1,
            None => self.omitted.push((flow, 1)),
        }
    }
}

impl wz_capture::PlaintextSink for FieldSink {
    /// R311y678 — walk the frames THE SESSION decoded, not the framing again.
    ///
    /// R311y677 was handed the plaintext before the frames existed and walked
    /// the `u16`-length-prefixed units itself. That made this a THIRD place that
    /// knows how a zenoh stream is framed, beside the assembler and
    /// `message_bytes`, and worse: a second opinion about where the messages
    /// are, beside the session's, with nothing comparing them. A capture the two
    /// read differently would print `messages decoded: N` over a listing of
    /// something else.
    ///
    /// Now the frames arrive with it, still carrying plaintext coordinates, and
    /// this slices exactly what the session framed.
    fn on_plaintext(&mut self, stream: wz_capture::DecryptedStream<'_>) {
        let bytes = stream.plaintext;
        for frame in stream.frames {
            let at = frame.stream_offset;
            let body = at + frame.prefix_width;
            // R311y687 — the unit's length and this message's place inside it
            // come from the FRAME. This read the two prefix bytes itself, which
            // made it the third place that knows how a zenoh stream is framed,
            // and it took the unit from its first byte for every message in it
            // -- the same batch defect the cleartext path carried.
            let Some(message) = bytes.get(body + frame.unit_offset..body + frame.unit_len) else {
                continue;
            };
            if let Some(cap) = self.cap {
                if self.kept_for(&stream.flow) >= cap {
                    self.note_omitted(stream.flow);
                    continue;
                }
            }
            // Reported in the coordinate space the rest of the report uses: the
            // record this message's bytes came out of. The spans INSIDE the tree
            // stay message-relative, which is the one space they mean anything
            // in -- a field's byte range is a range of the message.
            // R311y718 — the offset AND the space it is in. A remap to a
            // ciphertext record is what makes the number a record offset; its
            // ABSENCE means the offsets are still bytes into the stream that was
            // handed in, which is the QUIC case. The producer decides here,
            // where the answer is a fact, instead of each render site deciding
            // by which loop it happens to sit in.
            let (origin, space) = match stream.record_origin(at) {
                Some(origin) => (origin, OffsetSpace::CiphertextRecord),
                None => (at, MessageRow::stream_byte(frame)),
            };
            // R311y683 — walked and CHECKED against the session that framed it,
            // the same way the cleartext path is. R311y682 closed that half and
            // its own carry named this one: these coordinates come from the
            // same frame, the frame is right here in the loop, and nothing was
            // comparing the two readers.
            self.rows.push((
                stream.flow,
                stream.direction,
                origin,
                space,
                walk_plaintext(message, frame),
            ));
        }
    }

    /// R311y719 — the same walk over a recovered RFC 9221 datagram.
    ///
    /// The ONE difference from the stream case, and it is the reason this is a
    /// separate method: the message is sliced out of the PAYLOAD by the frame's
    /// unit coordinates, and the row is reported at the PACKET the datagram came
    /// out of. Using `stream_offset` to slice here would index the payload by a
    /// packet number.
    fn on_recovered_datagram(&mut self, datagram: wz_capture::RecoveredDatagram<'_>) {
        for frame in datagram.frames {
            let Some(message) = datagram
                .payload
                .get(frame.unit_offset..frame.unit_offset + frame.unit_len)
            else {
                continue;
            };
            if let Some(cap) = self.cap {
                if self.kept_for(&datagram.flow) >= cap {
                    self.note_omitted(datagram.flow);
                    continue;
                }
            }
            self.rows.push((
                datagram.flow,
                datagram.direction,
                datagram.packet_index,
                OffsetSpace::Packet,
                walk_plaintext(message, frame),
            ));
        }
    }
}

/// R311y676 (§1.1n) — a flow whose messages came out of DECRYPTED bytes cannot
/// be walked from the retained stream, and this says so BY NAME.
///
/// # The defect this closes, measured
///
/// `Dissection::decrypt_with` opens the records into a plaintext `Vec`, feeds it
/// to the session, and then `remap_decrypted_offsets` puts every resulting
/// frame's `stream_offset` BACK to the ciphertext record it came out of -- so a
/// reader can point at the packet. The plaintext is a local that the pass drops,
/// deliberately: it is already the unbounded third copy of the flow's bytes that
/// this project carries as an open item.
///
/// So R311y675's walk sliced `assembler.stream()` -- the CIPHERTEXT -- at
/// coordinates that name positions in it but bytes that are not there. Measured
/// on a decrypted fixture before this fix: it read a length prefix of `791` out
/// of encrypted bytes and declined with "the framing unit declares 791 byte(s)
/// and the retained stream holds 73".
///
/// That decline was an ACCIDENT, and the message blamed the bound for a
/// mismatch the bound had nothing to do with. Ciphertext that happened to carry
/// a plausible small length would have walked bytes that are not a message and
/// printed a confident field tree over them -- a wrong answer that looks exactly
/// like a right one, which is the failure mode this whole reader is built
/// against.
fn decrypted_coordinates(flow: &wz_capture::FlowDissection) -> Option<String> {
    flow.encrypted().map(|_| {
        "this flow's messages were decrypted, so their coordinates name the \
         ciphertext record they came out of and the plaintext they were decoded \
         from is not retained"
            .to_string()
    })
}

/// R311y675 — the message's bytes, sliced out of the direction's retained
/// stream at the coordinates the frame carries.
///
/// # R311y687 — the framing is read from the FRAME, and a batch is now right
///
/// This re-read the unit's two length-prefix bytes out of the stream, which made
/// it a second place that knows how a zenoh stream is framed and, worse, made it
/// wrong about a batch: it returned the WHOLE unit from its first byte, for
/// every message in the unit. A unit carrying a KeepAlive and a Close produced
/// two rows and both walked the KeepAlive.
///
/// That is not a hypothetical. It was found by writing the fixture, and the
/// misread never reached a reader only because R311y682's cross-check declined
/// the second row -- "the session read these bytes as Close and the field
/// walker reads them as KeepAlive" -- which is the check earning its place two
/// rounds after it was added.
///
/// Now the unit's length comes from `unit_len` and the message's place inside it
/// from `unit_offset`, both recorded by the framer. Nothing here parses framing.
/// R311y690 (§1.1n) — where this message begins in the direction's retained
/// stream.
///
/// One place, because two of them were the R311y688 shape waiting to happen:
/// [`message_bytes`] sliced at `stream_offset + prefix_width + unit_offset` and
/// the row rendered `message_at` from the same three fields written out again.
/// They agreed by CONSTRUCTION rather than by comparison, which is exactly the
/// property R311y689's carry recorded as still open -- a wrong slice reported a
/// matching wrong offset, and the reader could not tell.
fn message_at(frame: &wz_session_core::passive::PassiveFrame) -> usize {
    frame.stream_offset + frame.prefix_width + frame.unit_offset
}

fn message_bytes<'a>(
    stream: &'a [u8],
    origin: usize,
    frame: &wz_session_core::passive::PassiveFrame,
) -> Result<&'a [u8], String> {
    if frame.stream_offset < origin {
        return Err(format!(
            "bytes discarded to stay inside stream_bytes_per_direction (retained from {origin}, this message begins at {})",
            frame.stream_offset
        ));
    }
    let at = frame.stream_offset - origin;
    let body = at + frame.prefix_width;
    let end = body + frame.unit_len;
    if end > stream.len() {
        return Err(format!(
            "the framing unit declares {} byte(s) and the retained stream holds {}",
            frame.unit_len,
            stream.len().saturating_sub(body)
        ));
    }
    // R311y690 — the SAME function the row's `message_at` is rendered from, so
    // the offset a reader is given is the offset these bytes were taken at. It
    // was two sums of the same three fields, agreeing by construction; a sum
    // written twice is a sum that can be edited once.
    let start = message_at(frame) - origin;
    if start > end {
        return Err(format!(
            "this message stands {} byte(s) into a unit of {}",
            frame.unit_offset, frame.unit_len
        ));
    }
    Ok(&stream[start..end])
}

/// R311y682 (§1.1n) — the stream row, walked and then CHECKED against the
/// session that framed it.
///
/// # What was unwitnessed, in the store's own words
///
/// R311y680 made the datagram path ask its packet to vouch for all three
/// coordinates a row carries, and its own carry stated the residue exactly: "the
/// cleartext stream rows are sliced out of `StreamAssembler::stream()` at
/// `stream_offset`, on the same kind of inherited coordinate rule, and nothing
/// asks that stream to vouch for anything."
///
/// The rule inherited here is that `frame.stream_offset` names a position in the
/// assembler's retained stream and `frame.prefix_width` is the width of the
/// length prefix sitting at it. Nothing tested that. If it moved, this reader
/// would slice bytes that are not the message, hand them to a walker that reads
/// whatever it is given, and print a confident field tree over them — a wrong
/// answer shaped exactly like a right one.
///
/// # The witness, and why it is not a tautology
///
/// The SESSION decoded this message while feeding the stream, and its verdict is
/// on the frame. This walk reads the retained stream afterwards, through
/// different code. Two readers, two times, one claim: that these bytes are that
/// message. They are compared, and a row whose two readers disagree is DECLINED
/// with both opinions named rather than rendered.
///
/// # R311y677's coordinate rule, unchanged
///
/// Spans are MESSAGE-RELATIVE, base 0. R311y675 passed the stream offset, so a
/// cleartext row's spans were absolute while a decrypted row's -- whose
/// plaintext has no position in the stream at all -- could only ever be
/// relative. Two coordinate spaces in one listing, distinguishable by nothing a
/// reader can see. One space everywhere: a span is a range of THE MESSAGE, and
/// where it sits is on the row, once.
fn walk_message(
    stream: &[u8],
    origin: usize,
    frame: &wz_session_core::passive::PassiveFrame,
) -> FieldRow {
    let bytes = match message_bytes(stream, origin, frame) {
        Err(why) => return FieldRow::Declined(why),
        Ok(bytes) => bytes,
    };
    match wz_session_core::dissect::dissect_transport_message(bytes, 0) {
        // The error type is `sce_forge_runtime`'s and is not re-exported
        // publicly here, so it is rendered rather than named -- a dependency
        // this crate has no reason to take on for one message string.
        Err(err) => FieldRow::Declined(format!("the field walker refused these bytes: {err:?}")),
        Ok(field) => {
            let framed = message_name(frame);
            if walk_agrees(&field.name, &framed) {
                FieldRow::Walked(field)
            } else {
                FieldRow::Declined(format!(
                    "the session read these bytes as {framed} and the field \
                     walker reads them as {}, so the coordinate this row was \
                     sliced at does not name the message the session framed",
                    field.name
                ))
            }
        }
    }
}

/// R311y682 — do the session and the field walker agree about what this message
/// is?
///
/// # The asymmetry that is NOT a disagreement
///
/// `InboundFrame`'s variants are cfg-gated and the walker's names are not, so a
/// build without `codec-join` decodes a Join as `Unknown` while the walker still
/// names it. That is by design and firing on it would make this check reject
/// legitimate rows in every reduced build -- the direction a cross-check must
/// never be wrong in, which R311y680 measured the hard way when a flow-key check
/// nearly threw away a scout/hello exchange.
///
/// So `Unknown` from EITHER side, and a frame the session could not decode at
/// all, are silence rather than contradiction. A disagreement is two readers
/// both naming a specific kind and naming different ones.
fn walk_agrees(walked: &str, framed: &str) -> bool {
    walked == "Unknown"
        || framed == "Unknown"
        || framed.starts_with("undecodable(")
        || walked == framed
}

/// R311y688 (§1.1n) — WHICH COORDINATE SPACE a row's `@N` is in.
///
/// # What a reader could not tell
///
/// Three producers put a number after `@` and they are numbers of three
/// different things: a cleartext stream row's is a BYTE OFFSET into the
/// direction's retained stream, a datagram row's is a PACKET INDEX (a datagram
/// link has no stream to be offset within), and a decrypted row's is the offset
/// of the CIPHERTEXT RECORD the plaintext came out of. Nothing on the row said
/// which, and the three are indistinguishable by inspection -- small numbers all
/// round.
///
/// The spans inside every tree are message-relative (R311y677), so a reader
/// adding a span to the row's number gets a capture coordinate in exactly one
/// of the three cases. This says which case that is, and in that case gives the
/// sum rather than leaving the arithmetic to be inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OffsetSpace {
    /// A byte offset into the direction's retained stream, carrying the offset
    /// the MESSAGE itself begins at: past the framing prefix and past whatever
    /// of the unit's batch stands ahead of it.
    StreamByte { message_at: usize },
    /// The index of the packet in the capture file. NOT a byte offset.
    Packet,
    /// The offset of the ciphertext record the plaintext was opened from. The
    /// plaintext has no position in the stream at all, which is why this is not
    /// a byte offset a span can be added to.
    CiphertextRecord,
}

impl OffsetSpace {
    /// The machine-readable name a consumer branches on.
    fn name(self) -> &'static str {
        match self {
            Self::StreamByte { .. } => "stream_byte",
            Self::Packet => "packet",
            Self::CiphertextRecord => "ciphertext_record",
        }
    }

    /// What the text listing puts after the offset.
    fn note(self) -> String {
        match self {
            Self::StreamByte { message_at } => {
                format!(" [stream byte; this message begins at {message_at}]")
            }
            Self::Packet => " [packet index]".into(),
            Self::CiphertextRecord => " [ciphertext record]".into(),
        }
    }

    /// The JSON keys, which are the same fact as [`Self::note`].
    fn json(self) -> String {
        let mut out = format!(",\"offset_space\":\"{}\"", self.name());
        if let Self::StreamByte { message_at } = self {
            out.push_str(&format!(",\"message_at\":{message_at}"));
        }
        out
    }
}

fn render_field_row(
    out: &mut String,
    format: Format,
    flow: &wz_capture::FlowDissection,
    frame: &wz_session_core::passive::PassiveFrame,
    row: &FieldRow,
    to_json: &dyn Fn(&wz_session_core::dissect::Field) -> String,
    lens: PayloadLens<'_>,
) {
    let at = lens.at(frame.direction);
    // R311y688 — a cleartext stream row's offset IS a byte offset, and the
    // message it names begins past the framing prefix and past whatever of the
    // unit stands ahead of it. That sum is the one a reader would otherwise
    // have to do, and get wrong on a batch.
    let space = OffsetSpace::StreamByte {
        message_at: message_at(frame),
    };
    // R311y675 — the arrow follows the DIRECTION. `assembler()` maps A to
    // low_to_high and B to high_to_low, so printing the endpoints in table order
    // for both would say every message travelled the same way -- a row that is
    // wrong about the one thing the direction letter beside it exists to state.
    let (dir, from, to) = match frame.direction {
        wz_session_core::passive::Direction::A => {
            ("A", endpoint(&flow.flow.low), endpoint(&flow.flow.high))
        }
        wz_session_core::passive::Direction::B => {
            ("B", endpoint(&flow.flow.high), endpoint(&flow.flow.low))
        }
    };
    match (format, row) {
        // R311y675 — the keys are `from` / `to` and NOT `low` / `high`. The
        // values follow the direction, so keeping the flow table's key names
        // would put a correct value under a name that says the opposite for
        // every direction-B row -- the same silently-wrong label R311y669
        // removed when a QUIC row was keyed `tls`.
        (Format::Json, FieldRow::Walked(field)) => {
            out.push_str(&format!(
                "{{\"from\":\"{from}\",\"to\":\"{to}\",\"direction\":\"{dir}\",\
                 \"stream_offset\":{}{},\"field\":{}{}}}",
                frame.stream_offset,
                space.json(),
                to_json(field),
                payload_block(field, lens, Format::Json, at)
            ));
        }
        (Format::Json, FieldRow::Declined(why)) => {
            out.push_str(&format!(
                "{{\"from\":\"{from}\",\"to\":\"{to}\",\"direction\":\"{dir}\",\
                 \"stream_offset\":{}{},\"declined\":\"{}\"}}",
                frame.stream_offset,
                space.json(),
                escape(why)
            ));
        }
        (Format::Text, FieldRow::Walked(field)) => {
            out.push_str(&format!(
                "  {from} -> {to} {dir} @{}{}\n",
                frame.stream_offset,
                space.note()
            ));
            push_field_text(out, field, 2);
            out.push_str(&payload_block(field, lens, Format::Text, at));
        }
        (Format::Text, FieldRow::Declined(why)) => {
            out.push_str(&format!(
                "  {from} -> {to} {dir} @{}{}: NO FIELDS -- {why}\n",
                frame.stream_offset,
                space.note()
            ));
        }
    }
}

/// R311y680 (§1.1n) — does the packet at this index really belong to this flow,
/// travelling this way?
///
/// # Why the packet COUNT would not have been this
///
/// R311y679's carry asked for the two parses to be compared and proposed
/// `file.packets.len()`. That comparison is very close to a tautology: both
/// reads are `pcapng::parse` over the same immutable slice, so a disagreement
/// would mean the function is not deterministic, which is not the failure worth
/// guarding. The check that earns its place is the one on the LOOKUP: this
/// reader indexes `file.packets` by a frame's `stream_offset`, on the rule that
/// a datagram frame's offset IS its packet index. That rule is an inherited
/// fact about another crate's coordinate, exactly the kind this workspace has
/// had move under it before, and nothing was testing it.
///
/// So the decapsulated packet is asked to agree about all three coordinates it
/// carries independently: which flow, which direction, which index. A row that
/// cannot answer yes is not rendered from bytes nobody has vouched for, and the
/// count of such rows is REPORTED -- a listing short by rows nobody accounted
/// for is a listing that looks whole.
///
/// # What has no fixture witness, stated so it does not harden into one
///
/// With correct code upstream this can never fire, so there is no capture that
/// exercises it: its witnesses are PROBES. Breaking the index by one, and
/// pointing every lookup at the first packet, each produce the message on the
/// scout/hello fixture. The committed test asserts the other direction -- that a
/// scout and its hello, which live in DIFFERENT flows by design, are both walked
/// and neither is rejected.
///
/// # R311y681 — and it now says WHICH axis, because that is the actionable half
///
/// The round above returned a bool and the caller counted the noes. A reader
/// given "3 messages skipped" cannot act on it: a wrong index means the packet
/// numbering moved under this reader, a wrong flow means the key derivation did,
/// and a wrong direction means `from_low` did. Three different upstream changes,
/// one number. The axes fail independently and are reported independently.
fn packet_disagreement(
    datagram: &wz_capture::link::Datagram,
    flow: &wz_capture::link::FlowKey,
    direction: wz_session_core::passive::Direction,
    index: usize,
) -> Axes {
    let travels = if datagram.from_low {
        wz_session_core::passive::Direction::A
    } else {
        wz_session_core::passive::Direction::B
    };
    Axes {
        flow: datagram.flow != *flow,
        direction: travels != direction,
        index: datagram.packet_index != index,
    }
}

/// R311y681 — one disagreement, counted exactly and named while the bound
/// allows.
///
/// The count is the fact the reader is owed and it is never approximate; the
/// per-message detail is a listing like any other in this crate and takes the
/// same `--max-messages` ceiling.
fn note_disagreement(
    named: &mut Vec<Disagreed>,
    count: &mut usize,
    cap: Option<usize>,
    at: usize,
    why: Disagreement,
) {
    *count += 1;
    if cap.is_none_or(|c| named.len() < c) {
        named.push(Disagreed { at, why });
    }
}

/// R311y683 (§1.1n) — the capture, read a second time, in EITHER format.
///
/// # What was narrower than the tool's own input surface
///
/// R311y679 walked datagram flows by calling `pcapng::parse` directly, and
/// `Dissection::from_capture` accepts both formats. So a classic `.pcap` holding
/// datagram traffic was dissected, counted, and then told that its packets
/// "could not be re-read to walk them" — a notice that was true about the code
/// and false about the file. R311y679's own carry recorded it and R311y680 left
/// it standing.
///
/// The dispatch here is the SAME question `from_capture_declaring_quic` asks
/// (`pcapng::looks_like_pcapng`), and it is asked the same way rather than
/// inferred from a parse failure: a pcapng this reader genuinely cannot re-read
/// must reach the notice, not be retried as a classic pcap and reach it by a
/// second, wronger route.
///
/// # Why an enum and not one packet list
///
/// A pcapng packet carries its own link type (its interface's) and a classic
/// pcap has ONE for the whole file. Flattening them here would mean copying
/// every packet's bytes to attach a number that the file already answers for.
///
/// # R311y693 — what this costs, measured rather than estimated
///
/// The store carried this as an open item reading "parses the whole file a
/// second time for every `--fields` run, outside the bound discipline every
/// other accumulation in this crate follows". Counted: [`Self::of`] has ONE
/// call site, inside [`datagram_field_rows`], which has one, inside
/// [`field_lines`], of which exactly one of its two call sites runs per
/// invocation. At most once per run, and not at all for a capture with no
/// datagram flow -- the early return sits above it.
///
/// So the cost is one extra parse of the caller's own file, paid only by a
/// reader who asked for `--fields` over datagram traffic. It is bounded by the
/// same thing the FIRST parse is bounded by, which is the input the caller
/// handed over; there is no accumulation here that grows with anything else,
/// and a bound of this crate's own would be a bound on someone else's file.
/// Recorded because "outside the bound discipline" and "bounded by the input"
/// are different claims and the item asserted the first.
enum Reread {
    Ng(wz_capture::pcapng::PcapngFile),
    Classic(wz_capture::pcap::PcapFile),
}

/// The two things this walk needs of a packet, in either format.
struct RereadPacket<'a> {
    link_type: u32,
    index: usize,
    data: &'a [u8],
}

impl Reread {
    /// The capture, parsed a second time, or `None` if this reader cannot.
    fn of(capture: &[u8]) -> Option<Self> {
        if wz_capture::pcapng::looks_like_pcapng(capture) {
            wz_capture::pcapng::parse(capture).ok().map(Self::Ng)
        } else {
            wz_capture::pcap::parse(capture).ok().map(Self::Classic)
        }
    }

    /// R311y703 (RP4) — when the packet at `index` was CAPTURED, in
    /// milliseconds since the Unix epoch.
    ///
    /// `None` for a block that carried no timestamp at all, which pcapng
    /// permits and which this reader must not turn into a zero: an invented
    /// arrival time is exactly the fabricated measurement the throughput
    /// plane's `unmeasured` state exists to refuse one layer down.
    fn ts_millis(&self, index: usize) -> Option<u64> {
        match self {
            Self::Ng(file) => file.packets.get(index).and_then(|p| file.ts_millis(p)),
            Self::Classic(file) => file
                .packets
                .get(index)
                .map(|p| p.ts_millis(file.timestamp_unit)),
        }
    }

    /// The packet at `index` in file order.
    fn packet(&self, index: usize) -> Option<RereadPacket<'_>> {
        match self {
            Self::Ng(file) => file.packets.get(index).map(|p| RereadPacket {
                link_type: p.link_type,
                index: p.index,
                data: &p.data,
            }),
            Self::Classic(file) => file.packets.get(index).map(|p| RereadPacket {
                // One link type for the whole file, which is what a classic
                // pcap's header says and the reason this is not a field on the
                // packet.
                link_type: file.link_type,
                index: p.index,
                data: &p.data,
            }),
        }
    }
}

/// R311y679 (§1.1n) — the field rows of every DATAGRAM flow.
///
/// # Why this needed nothing added anywhere
///
/// R311y678 reported this blocked, needing a sink at `push_packet_at` and a
/// construction seam to install it. Measuring said otherwise: `pcapng::parse`
/// is public, a `Packet` carries its `link_type` and its `data`,
/// `link::decapsulate` is public, and a datagram frame's `stream_offset` IS its
/// packet index. Every piece was already reachable from here, and the capture
/// bytes never left the caller's hand.
///
/// So nothing is retained and nothing was added to `wz-capture`. The file is
/// parsed a second time, which costs one walk and is paid only by a reader who
/// asked for `--fields`.
///
/// A capture this reader could not parse a second time yields no rows rather
/// than a panic: it was parsed once already to produce the dissection, so a
/// failure here would be a disagreement between two reads of one file, and the
/// listing says how many flows it could not cover.
struct DatagramWalk<'a> {
    /// The dissection whose datagram table is being walked.
    dissection: &'a Dissection,
    /// Rows the decryption and QUIC passes took while their bytes existed.
    decrypted: &'a FieldSink,
    /// Which rendering the rows are for.
    format: Format,
    /// The per-flow row ceiling, `None` for unbounded.
    messages_per_flow: Option<usize>,
    /// Payload-format rules in force for this run.
    payload_formats: &'a Declarations<'a>,
}

fn datagram_field_rows(
    capture: &[u8],
    walk: DatagramWalk<'_>,
    emitted: &mut usize,
    listings: &mut Vec<FlowListing>,
) {
    let DatagramWalk {
        dissection,
        decrypted,
        format,
        messages_per_flow,
        payload_formats,
    } = walk;
    if dissection.datagram_flows().is_empty() {
        return;
    }
    let Some(file) = Reread::of(capture) else {
        // Unreadable on the second pass. Said rather than silently skipped,
        // which is the whole point of this round's sibling.
        listings.push(FlowListing {
            rows: String::new(),
            notes: vec![FieldNote::CaptureNotReread],
        });
        return;
    };
    for flow in dissection.datagram_flows() {
        let mut out = String::new();
        let mut notes: Vec<FieldNote> = Vec::new();
        // R311y701 (PF2) — this flow's keyexpr tables, on the same rule the
        // stream listing follows: folded in frame order so an id resolves
        // through the binding that was live when it travelled.
        let mut spaces = wz_capture::agg::KeyexprSpaces::new();
        let mut shown = 0usize;
        let mut omitted = 0usize;
        // R311y680 — messages whose packet did not vouch for itself.
        // R311y681 — counted exactly, and named while the bound allows.
        let mut disagreed = 0usize;
        let mut named: Vec<Disagreed> = Vec::new();
        for frame in &flow.frames {
            spaces.absorb_frame(frame);
            // The datagram coordinate: `stream_offset` names the PACKET, because
            // a datagram link has no stream to be offset within.
            // R311y680 — a packet the second read does not have, or one it
            // reads as something other than UDP, is the COUNT half of the
            // disagreement the two parses can have. Silent `continue`s here
            // would drop rows and leave the listing looking whole, which is the
            // failure this whole check exists for.
            let Some(packet) = file.packet(frame.stream_offset) else {
                note_disagreement(
                    &mut named,
                    &mut disagreed,
                    messages_per_flow,
                    frame.stream_offset,
                    Disagreement::Absent,
                );
                continue;
            };
            let Ok(wz_capture::link::Transport::Udp(datagram)) =
                wz_capture::link::decapsulate(packet.link_type, packet.index, packet.data)
            else {
                note_disagreement(
                    &mut named,
                    &mut disagreed,
                    messages_per_flow,
                    frame.stream_offset,
                    Disagreement::NotUdp,
                );
                continue;
            };
            let axes =
                packet_disagreement(&datagram, &flow.flow, frame.direction, frame.stream_offset);
            if axes.any() {
                note_disagreement(
                    &mut named,
                    &mut disagreed,
                    messages_per_flow,
                    frame.stream_offset,
                    Disagreement::Coordinates(axes),
                );
                continue;
            }
            let body = frame.unit_offset;
            let Some(message) = datagram.payload.get(body..) else {
                continue;
            };
            if let Some(cap) = messages_per_flow {
                if shown >= cap {
                    omitted += 1;
                    continue;
                }
            }
            // R311y689 — CHECKED against the frame the session decoded, which is
            // what the other two row producers have done since R311y682 and
            // R311y683 and this one did not. The argument for taking it is
            // R311y687: the equivalent check found a live misread on the
            // cleartext path -- a batched unit's second message walked as its
            // first -- and this path indexes its payload by the same kind of
            // inherited coordinate.
            let row = walk_plaintext(message, frame);
            shown += 1;
            if format == Format::Json && *emitted > 0 {
                out.push(',');
            }
            *emitted += 1;
            render_sink_row(
                &mut out,
                format,
                RowAt {
                    flow: flow.flow,
                    direction: frame.direction,
                    origin: frame.stream_offset,
                    space: OffsetSpace::Packet,
                },
                &row,
                PayloadLens {
                    formats: payload_formats,
                    spaces: &spaces,
                },
            );
        }
        // R311y679 — the SCOUTING list, which is where a discovery capture's
        // messages actually are. `frames` is the transport-MID space and a
        // scouting datagram is a different one (Scout / Hello), walked by a
        // different entry point -- measured, not assumed: the scouting fixture
        // reports `messages decoded: 0` beside `scouting: 3 message(s)`, so a
        // walk of `frames` alone produces an empty listing over a capture that
        // is nothing but discovery traffic.
        for datagram in &flow.scouting {
            let Some(packet) = file.packet(datagram.packet_index) else {
                note_disagreement(
                    &mut named,
                    &mut disagreed,
                    messages_per_flow,
                    datagram.packet_index,
                    Disagreement::Absent,
                );
                continue;
            };
            let Ok(wz_capture::link::Transport::Udp(udp)) =
                wz_capture::link::decapsulate(packet.link_type, packet.index, packet.data)
            else {
                note_disagreement(
                    &mut named,
                    &mut disagreed,
                    messages_per_flow,
                    datagram.packet_index,
                    Disagreement::NotUdp,
                );
                continue;
            };
            let axes =
                packet_disagreement(&udp, &flow.flow, datagram.direction, datagram.packet_index);
            if axes.any() {
                note_disagreement(
                    &mut named,
                    &mut disagreed,
                    messages_per_flow,
                    datagram.packet_index,
                    Disagreement::Coordinates(axes),
                );
                continue;
            }
            if let Some(cap) = messages_per_flow {
                if shown >= cap {
                    omitted += 1;
                    continue;
                }
            }
            let Ok(Some(field)) =
                wz_session_core::dissect::dissect_scouting_message(&udp.payload, 0)
            else {
                continue;
            };
            shown += 1;
            if format == Format::Json && *emitted > 0 {
                out.push(',');
            }
            *emitted += 1;
            render_sink_row(
                &mut out,
                format,
                RowAt {
                    flow: flow.flow,
                    direction: datagram.direction,
                    origin: datagram.packet_index,
                    space: OffsetSpace::Packet,
                },
                &FieldRow::Walked(field),
                PayloadLens {
                    formats: payload_formats,
                    spaces: &spaces,
                },
            );
        }
        // R311y718 — and the QUIC-recovered rows, which come from the SINK.
        //
        // A third producer on this flow, and it cannot be walked from the file
        // the way the two above are: the bytes these messages were framed out
        // of never existed on the wire in that form -- they were decrypted and
        // reassembled -- so there is no packet to re-read them from. That is
        // exactly the situation the sink exists for, and it is why the walk
        // happens inside `feed_quic_stream_with_sink` while the recovered bytes
        // are still alive. The origin is a byte offset into the recovered
        // stream, which is the space the STREAM listing reports in.
        for (f, direction, origin, space, row) in &decrypted.rows {
            if *f != flow.flow {
                continue;
            }
            if let Some(cap) = messages_per_flow {
                if shown >= cap {
                    omitted += 1;
                    continue;
                }
            }
            shown += 1;
            if format == Format::Json && *emitted > 0 {
                out.push(',');
            }
            *emitted += 1;
            render_sink_row(
                &mut out,
                format,
                RowAt {
                    flow: flow.flow,
                    direction: *direction,
                    origin: *origin,
                    space: *space,
                },
                row,
                PayloadLens {
                    formats: payload_formats,
                    spaces: &spaces,
                },
            );
        }
        if omitted > 0 {
            notes.push(FieldNote::Omitted {
                flow: flow.flow,
                count: omitted,
            });
        }
        // R311y680 — and a disagreement between the two reads of this file is
        // REPORTED, not skipped. It cannot be silent for the same reason a bound
        // that bites cannot: a listing short by rows nobody accounted for is a
        // listing that looks whole.
        if disagreed > 0 {
            notes.push(FieldNote::Disagreement {
                flow: flow.flow,
                count: disagreed,
                named,
            });
        }
        // A datagram flow this reader could not walk says so, rather than being
        // absent -- the R311y678 rule, kept now that the absence has a second
        // possible cause.
        if shown == 0 {
            notes.push(FieldNote::NothingWalkable { flow: flow.flow });
        }
        if out.is_empty() && notes.is_empty() {
            continue;
        }
        listings.push(FlowListing { rows: out, notes });
    }
}

/// R311y688 — WHERE a sink row stands, as one value.
///
/// Four coordinates travelled as four arguments and the fifth this round would
/// have added took the call past what `clippy` allows -- which is the arity
/// smell R311y678's carry already recorded about this crate's constructors,
/// arriving in a renderer. They are one fact about one row and they now travel
/// as one.
///
/// `decrypted` is DERIVED rather than carried beside the space, because the two
/// cannot disagree: the ciphertext-record space is exactly the decrypted case.
/// A bool beside it would be a second place to get the same fact wrong, which is
/// how R311y679 came to print `(decrypted)` over cleartext rows.
#[derive(Debug, Clone, Copy)]
struct RowAt {
    flow: wz_capture::link::FlowKey,
    direction: wz_session_core::passive::Direction,
    origin: usize,
    space: OffsetSpace,
}

impl RowAt {
    fn decrypted(&self) -> bool {
        matches!(self.space, OffsetSpace::CiphertextRecord)
    }
}

/// R311y677 — one row the sink produced, in whichever format.
///
/// Structurally identical to [`render_field_row`]'s walked arm and deliberately
/// not merged with it: that one takes a `PassiveFrame` and this one takes what
/// the sink kept, and threading a frame that does not exist through the other
/// would mean inventing one.
///
/// # R311y701 — and the payload rules reach it, which they did not
///
/// R311y699 attached `--payload-format` to `render_field_row` and stopped there.
/// This function draws BOTH of the other two row producers — the decrypted rows a
/// TLS sink kept, and every datagram row — so a rule a reader typed silently
/// covered one third of their capture. It did not report a miss; the block was
/// simply absent, which reads as "no rule matched".
///
/// That is the fourth time a new plane in this crate reached one row producer:
/// R311y668 (`--flows`), R311y678 (the field layer), R311y699 (payloads), here.
/// The rule the repetition earns: a plane is not attached until every producer
/// AND the datagram half have it.
fn render_sink_row(
    out: &mut String,
    format: Format,
    at: RowAt,
    row: &FieldRow,
    lens: PayloadLens<'_>,
) {
    let RowAt {
        flow,
        direction,
        origin,
        space,
    } = at;
    // R311y679 — whether these bytes came out of a DECRYPTION. Not a constant:
    // this renderer took its second caller that round and the datagram rows it
    // produces are cleartext, so a hardcoded `(decrypted)` is a label that is
    // silently false for every one of them -- the shape R311y669 removed when a
    // QUIC row was keyed `tls`. R311y688 DERIVES it from the space, so the two
    // cannot disagree.
    let decrypted = at.decrypted();
    let (dir, from, to) = match direction {
        wz_session_core::passive::Direction::A => ("A", endpoint(&flow.low), endpoint(&flow.high)),
        wz_session_core::passive::Direction::B => ("B", endpoint(&flow.high), endpoint(&flow.low)),
    };
    // R2062 (open-debt item 478) — the misbinding plane learns WHO sent this
    // row, so `PUBLISHER MISLABELLING` can end "Fix the publisher at `X`".
    // `from` is the same endpoint this renderer already prints beside the row,
    // which is what makes the finding and the row agree by construction rather
    // than by a second lookup.
    let keyexpr_at = lens.at(direction).published_by(&from);
    match (format, row) {
        (Format::Json, FieldRow::Walked(field)) => out.push_str(&format!(
            "{{\"from\":\"{from}\",\"to\":\"{to}\",\"direction\":\"{dir}\",\
             \"stream_offset\":{origin}{},\"decrypted\":{decrypted},\"field\":{}{}}}",
            space.json(),
            wz_session_core::dissect::to_json(field),
            payload_block(field, lens, Format::Json, keyexpr_at)
        )),
        // R311y683 — a row the walker refused is still a row, in both formats.
        // The key is `declined`, the same one the cleartext path uses, because
        // a consumer branching on the reason must not have to know which
        // transport produced it.
        (Format::Json, FieldRow::Declined(why)) => out.push_str(&format!(
            "{{\"from\":\"{from}\",\"to\":\"{to}\",\"direction\":\"{dir}\",\
             \"stream_offset\":{origin}{},\"decrypted\":{decrypted},\"declined\":\"{}\"}}",
            space.json(),
            escape(why)
        )),
        (Format::Text, FieldRow::Walked(field)) => {
            let how = if decrypted { " (decrypted)" } else { "" };
            out.push_str(&format!(
                "  {from} -> {to} {dir} @{origin}{}{how}\n",
                space.note()
            ));
            push_field_text(out, field, 2);
            out.push_str(&payload_block(field, lens, Format::Text, keyexpr_at));
        }
        (Format::Text, FieldRow::Declined(why)) => {
            let how = if decrypted { " (decrypted)" } else { "" };
            out.push_str(&format!(
                "  {from} -> {to} {dir} @{origin}{}{how}: NO FIELDS -- {why}\n",
                space.note()
            ));
        }
    }
}

/// R311y683 (§1.1n) — the DECRYPTED row: walked from plaintext, checked against
/// the frame the session decoded out of that same plaintext.
///
/// The sibling of [`walk_message`], and separate from it for one reason: that
/// one slices the bytes out of a retained stream and this one is handed them.
/// What they share is the check, and they share it by calling the same
/// [`walk_agrees`] -- a second copy of that rule would be a second place for the
/// cfg asymmetry to be got wrong.
fn walk_plaintext(message: &[u8], frame: &wz_session_core::passive::PassiveFrame) -> FieldRow {
    match wz_session_core::dissect::dissect_transport_message(message, 0) {
        Err(err) => FieldRow::Declined(format!("the field walker refused these bytes: {err:?}")),
        Ok(field) => {
            let framed = message_name(frame);
            if walk_agrees(&field.name, &framed) {
                FieldRow::Walked(field)
            } else {
                FieldRow::Declined(format!(
                    "the session read this record as {framed} and the field \
                     walker reads its plaintext as {}, so the offset this row \
                     was sliced at does not name the message the session framed",
                    field.name
                ))
            }
        }
    }
}

/// R311y699 — what a payload-format rule did to ONE message.
///
/// R311y856 moved the type into `wz-capture`, beside the decode that produces
/// it and where the C ABI can name it too; every reason R311y699 gave for
/// answering each non-decode BY NAME rather than with silence is stated on
/// [`wz_capture::payload_decode::PayloadDecoding`], unchanged. What stays on
/// this side is the RENDERING — how a person reading a terminal is told which
/// flag to go fix is a property of this surface and of no other.
use wz_capture::payload_decode::PayloadDecoding;

/// R311y700 ([REDACTED-REQ]) — one application SAMPLE a capture carried: the key
/// expression it was published under and the bytes that went with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// The key expression, as the wire spelled it.
    pub keyexpr: String,
    /// The payload bytes.
    pub payload: Vec<u8>,
    /// Which direction of which flow carried it, so a replay can be told to
    /// send one side of a conversation.
    pub direction: wz_session_core::passive::Direction,
    /// The framing unit this message came out of. On a datagram link this IS
    /// the packet index; on a stream it is a byte offset. Carried because it is
    /// the only ordering key a sample has — the capture's own arrival order.
    pub origin: usize,
    /// R311y703 (RP4) — when the capture recorded the packet this message
    /// arrived in, in milliseconds since the Unix epoch.
    ///
    /// # What R311y700 and R311y702 both said about this, and why it was wrong
    ///
    /// Both rounds recorded that a stream flow has no per-message time, on the
    /// argument that its anchor is a byte offset rather than a packet. The
    /// argument is sound and the conclusion is false:
    /// [`wz_capture::FlowDissection::packet_for`] is public, answers exactly
    /// "which capture packet carried the byte at this stream offset", and its
    /// own doc names `PassiveFrame::stream_offset` as the thing to compose it
    /// with. Measured by reading that surface rather than re-deriving the
    /// argument — the discipline this workspace adopted after three such notes
    /// turned out to be claims.
    ///
    /// `None` is still a real answer and there are three ways to reach it: a
    /// capture block that carried no timestamp, a stream offset whose bytes the
    /// assembler had already discarded, and a capture this reader could not
    /// parse a second time. A consumer must not read `None` as zero.
    pub captured_at_millis: Option<u64>,
}

/// R311y700 ([REDACTED-REQ]) — every sample a capture carried, in capture order.
///
/// # Why this is here and not in a replay tool
///
/// A replay tool needs to know what was published; so does the field layer,
/// which already walks every message and pairs a keyexpr with the payload
/// underneath it ([`keyexpr_and_payload`]). Writing that walk a second time in
/// another crate would be a second opinion about which payload belongs to which
/// keyexpr — the shape R311y678 closed on the framing side by making one walk
/// serve both readers.
///
/// So the extraction stays beside the walk it reuses, and the replay tool takes
/// this as its input.
///
/// # What is NOT here, said rather than implied
///
/// A message that names its keyexpr by NUMERIC ID alone yields no sample: this
/// walk reads the wire and the id-to-path table is per-flow state in the
/// throughput plane. A capture that began after the declarations therefore
/// replays less than it holds, and [`Samples::unresolved`] is how many — a
/// floor reported as a floor.
///
/// # R311y701 (RP2) — and DATAGRAM flows, which this read did not cover
///
/// R311y700 walked `dissection.flows()`, which is the TCP half. A multicast or
/// scouting capture therefore yielded ZERO samples and said nothing at all: a
/// replay of it printed an empty plan, which is exactly what a capture holding
/// no application traffic prints. That is the fourth arrival of one shape in
/// this crate — R311y668 (`--flows`), R311y678 (the field layer), R311y699
/// (payload formats), here — and the rule it earns is stated on
/// [`render_sink_row`].
///
/// The datagram half is walked the way [`datagram_field_rows`] walks it: a
/// second read of the caller's own bytes, because a datagram frame's offset IS
/// its packet index and the payload is not retained anywhere. What that read
/// cannot reach is COUNTED rather than skipped ([`Samples::unreachable`]) — a
/// plan short by rows nobody accounted for is a plan that looks whole.
pub fn samples(capture: &[u8], keylog: Option<&[u8]>) -> Result<Samples, CaptureError> {
    let mut dissection = Dissection::from_capture(capture)?;
    let (mut opener, _) = CaptureOpener::from_secrets_blocks(dissection.decryption_secrets());
    if let Some(text) = keylog {
        opener.absorb(KeyLog::parse(text));
    }
    if !opener.log().is_empty() {
        dissection.decrypt_with(&mut opener);
    }
    // R311y703 (RP4) — ONE second read, serving both halves. The datagram walk
    // already needed it for the bytes; the stream half needs it only for the
    // clock, and a second parse for that would read the same immutable slice
    // twice for one field.
    let file = Reread::of(capture);
    let mut out = Samples::default();
    for flow in dissection.flows() {
        // R311y701 (PF2) — folded in frame order, the same rule the field
        // listing follows. A sample's keyexpr is the name it will be
        // RE-PUBLISHED under, so resolving it through a binding that was not
        // live when it travelled would send a payload to the wrong topic.
        let mut spaces = wz_capture::agg::KeyexprSpaces::new();
        for frame in &flow.frames {
            spaces.absorb_frame(frame);
            collect_sample(flow, frame, &spaces, file.as_ref(), &mut out);
        }
    }
    collect_datagram_samples(&dissection, file.as_ref(), &mut out);
    Ok(out)
}

/// R311y701 (RP2) — the samples a DATAGRAM capture carried.
///
/// Scouting datagrams are deliberately NOT walked: a Scout or a Hello is
/// discovery, carries no key expression and no application payload, and a
/// replay of one would be a claim about traffic the application never sent.
fn collect_datagram_samples(dissection: &Dissection, file: Option<&Reread>, out: &mut Samples) {
    let flows = dissection.datagram_flows();
    if flows.is_empty() {
        return;
    }
    let Some(file) = file else {
        // Every datagram message is out of reach, and the count says so rather
        // than the plan quietly holding only the stream half.
        out.unreachable += flows.iter().map(|f| f.frames.len()).sum::<usize>();
        return;
    };
    for flow in flows {
        let mut spaces = wz_capture::agg::KeyexprSpaces::new();
        for frame in &flow.frames {
            spaces.absorb_frame(frame);
            let Some(packet) = file.packet(frame.stream_offset) else {
                out.unreachable += 1;
                continue;
            };
            let Ok(wz_capture::link::Transport::Udp(datagram)) =
                wz_capture::link::decapsulate(packet.link_type, packet.index, packet.data)
            else {
                out.unreachable += 1;
                continue;
            };
            // The same three-axis check the field listing makes, and for the
            // same reason: these bytes are found by an INHERITED coordinate,
            // and a replay built out of a packet that did not vouch for itself
            // would re-publish someone else's payload under this keyexpr.
            if packet_disagreement(&datagram, &flow.flow, frame.direction, frame.stream_offset)
                .any()
            {
                out.unreachable += 1;
                continue;
            }
            let Some(message) = datagram.payload.get(frame.unit_offset..) else {
                out.unreachable += 1;
                continue;
            };
            let FieldRow::Walked(field) = walk_plaintext(message, frame) else {
                out.undecodable += 1;
                continue;
            };
            // The datagram coordinate IS the packet index, so the clock is a
            // direct lookup rather than a run-map question.
            push_sample(
                &field,
                frame.direction,
                frame.stream_offset,
                file.ts_millis(frame.stream_offset),
                &spaces,
                out,
            );
        }
    }
}

/// What [`samples`] recovered, and what it could not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Samples {
    /// The samples, in capture order.
    pub items: Vec<Sample>,
    /// Messages carrying a payload whose keyexpr this walk could not read,
    /// because the sender named it by numeric id alone.
    pub unresolved: usize,
    /// Messages this walk could not read at all.
    pub undecodable: usize,
    /// R311y701 (RP2) — datagram messages this walk could not REACH: the
    /// capture would not parse a second time, the packet the dissection named
    /// is not in that parse, or the packet disagreed about which flow, which
    /// direction or which index it is.
    ///
    /// Separate from [`Self::undecodable`] because the two send a reader to
    /// different places: that one is a message this walker does not understand,
    /// this one is a disagreement between two reads of one file.
    pub unreachable: usize,
}

/// Pull one frame's sample, if it has one.
fn collect_sample(
    flow: &wz_capture::FlowDissection,
    frame: &wz_session_core::passive::PassiveFrame,
    spaces: &wz_capture::agg::KeyexprSpaces,
    file: Option<&Reread>,
    out: &mut Samples,
) {
    let assembler = flow.assembler(frame.direction);
    let stream = assembler.stream();
    let row = walk_message(stream, assembler.retained_from(), frame);
    let FieldRow::Walked(field) = row else {
        out.undecodable += 1;
        return;
    };
    // R311y703 (RP4) — the composition `FlowDissection::packet_for`'s own doc
    // prescribes: a stream offset names a byte, the run map names the packet
    // that carried it, and the file names when that packet arrived.
    let captured_at = file.and_then(|f| {
        flow.packet_for(frame.direction, frame.stream_offset)
            .and_then(|index| f.ts_millis(index))
    });
    push_sample(
        &field,
        frame.direction,
        frame.stream_offset,
        captured_at,
        spaces,
        out,
    );
}

/// R311y701 (RP2) — the sample inside ONE walked message, whichever half of the
/// capture produced it.
///
/// Shared by the stream and datagram walks on purpose: a second copy of this
/// rule would be a second opinion about what counts as a sample and about which
/// non-sample is `unresolved`, and the two halves would drift exactly where a
/// reader compares their counts.
fn push_sample(
    field: &wz_session_core::dissect::Field,
    direction: wz_session_core::passive::Direction,
    origin: usize,
    captured_at_millis: Option<u64>,
    spaces: &wz_capture::agg::KeyexprSpaces,
    out: &mut Samples,
) {
    use wz_session_core::dissect::FieldValue;
    let at = KeyexprAt::new(direction, spaces);
    match keyexpr_and_payload(field, at) {
        Some((keyexpr, payload)) => {
            let FieldValue::Bytes(bytes) = &payload.value else {
                return;
            };
            if bytes.is_empty() {
                return;
            }
            out.items.push(Sample {
                keyexpr,
                payload: bytes.clone(),
                direction,
                origin,
                captured_at_millis,
            });
        }
        None => {
            if subtree_payload_bytes(field).is_some() {
                out.unresolved += 1;
            }
        }
    }
}

// R311y856 — the pair-finder, the id-resolution anchor, the payload-bytes
// finder and the decode itself all moved into `wz-capture::payload_decode`,
// beside the map they consult. Every rule R311y699 / R311y701 settled about
// them -- the innermost-first pairing, why the suffix alone was not the answer,
// why a `payload` group must not shadow a `payload` leaf -- is stated there,
// unchanged. They moved because the C ABI could not reach a single one of them
// and the parity gate said so.
use wz_capture::payload_decode::subtree_payload_bytes;
use wz_capture::payload_decode::{decode_payload, keyexpr_and_payload, KeyexprAt};

/// R311y701 — everything a ROW needs to decode the payload under it.
///
/// The rules a reader typed and the tables their keyexprs resolve through, as
/// one value. They arrived as two arguments and took `render_field_row` past
/// what `clippy` allows — the same arity smell R311y688 settled for the four
/// coordinates of a row, arriving again for the same reason: they are one fact
/// about one listing and a caller that could pass one without the other could
/// pass a rule set with nothing to resolve against.
#[derive(Clone, Copy)]
struct PayloadLens<'a> {
    formats: &'a Declarations<'a>,
    spaces: &'a wz_capture::agg::KeyexprSpaces,
}

impl<'a> PayloadLens<'a> {
    /// This lens, pointed at a row travelling `direction`.
    fn at(self, direction: wz_session_core::passive::Direction) -> KeyexprAt<'a> {
        KeyexprAt::new(direction, self.spaces)
    }
}

/// Render the payload decoding beside the field tree, in whichever format.
fn payload_block(
    field: &wz_session_core::dissect::Field,
    lens: PayloadLens<'_>,
    format: Format,
    at: KeyexprAt<'_>,
) -> String {
    let decoding = decode_payload(field, lens.formats, at);
    if decoding == PayloadDecoding::NoRules {
        return String::new();
    }
    if format == Format::Json {
        // R311y856 — the SHARED emit. This arm used to spell the five states
        // into JSON here, and the C ABI had no payload block at all; the moment
        // it grew one there would have been two renderings of one value, which
        // is the standing `debt-census-emit-two-renderings` and the reason
        // R311y851 refused to add a third case of it. The state vocabulary is a
        // contract a consumer branches on, and a second copy is a second
        // contract that drifts. Only the TEXT arm below stays here.
        let mut body = String::from(",\"payload_decode\":");
        wz_capture::payload_decode::push_decoding(&decoding, &mut body);
        return body;
    }
    match &decoding {
        PayloadDecoding::NoRules => unreachable!("returned above"),
        PayloadDecoding::NoPayload => String::new(),
        PayloadDecoding::KeyexprUnresolved => String::from(
            "    payload: this message names its keyexpr by id only, so no \
             --payload-format rule can be tested against it\n",
        ),
        // R2170 (open-debt item 546) — the THIRD consumer of the vocabulary,
        // and the compiler is what found it: this is the TEXT surface, and the
        // arm is required because the match is exhaustive. Worth stating
        // because the round had already satisfied the JSON emit and both
        // vocabulary documents and still was not done -- a person reading a
        // terminal is a consumer too, and `no_payload` was lying to them in
        // exactly the same way.
        //
        // The number is the DESCRIPTOR's length, not the payload's, and the
        // sentence says where the data went rather than implying it is missing.
        PayloadDecoding::NotOnTheWire { descriptor_bytes } => format!(
            "    payload: not on this wire — the slot holds a {descriptor_bytes}-byte \
             SHM descriptor, so the data was shared out of band and this \
             capture never carried it\n"
        ),
        PayloadDecoding::NoRule(keyexpr) => {
            format!("    payload: no --payload-format rule covers `{keyexpr}`\n")
        }
        PayloadDecoding::Refused {
            keyexpr,
            format: name,
            why,
        } => format!("    payload `{keyexpr}` as {name}: REFUSED -- {why}\n"),
        // R311y873 — this line names the FLAG, which is the whole reason the
        // state is separate from `Refused` above. That one sends a reader to
        // their capture; here the capture is right and the mapping is wrong,
        // and a reader told only "refused" would go doubting a publisher that
        // said exactly what it sent.
        PayloadDecoding::EncodingMismatch {
            keyexpr,
            format: name,
            declared,
            checked,
        } => format!(
            "    payload `{keyexpr}`: NOT DECODED -- the publisher declared \
             {declared} and the --payload-format rule says {name}{}\n",
            // Round 2025 (item 285) — WHETHER ANYTHING WEIGHED THAT LABEL. A
            // binary declaration cannot be judged from bytes, so the refusal
            // is this reader's policy rather than a finding, and an operator
            // whose ROS 2 `application/cdr` traffic is being withheld is owed
            // that distinction on the line that withholds it. Said only in the
            // unchecked case: the ordinary one needs no qualification and a
            // clause on every row would bury this one.
            if *checked {
                ""
            } else {
                " (nothing checked that label: it is binary, so this refusal \
                 is a default rather than a finding)"
            }
        ),
        PayloadDecoding::Decoded {
            keyexpr,
            format: name,
            fields,
            despite_encoding,
        } => {
            // R311y874 — the override is said on its OWN line, above the
            // fields. A reader whose rule was right and whose publisher is
            // mislabelling its topic needs that as a finding, not as a
            // parenthetical on a header they skim; and the fields below are
            // trustworthy either way, so the line must not read as a warning
            // about them.
            let mut out = match despite_encoding {
                Some(declared) => format!(
                    "    payload `{keyexpr}`: the publisher declared {declared} \
                     and its own bytes contradict that, so the \
                     --payload-format rule was applied anyway\n"
                ),
                None => String::new(),
            };
            out.push_str(&format!("    payload `{keyexpr}` as {name}:\n"));
            for f in fields {
                // R311y720 (PF4) — the declared name follows the path rather
                // than replacing it. Both, because they answer different
                // questions: the path is what the WIRE carried and the name is
                // what a deployment SAYS it means, and a rendering that showed
                // only the name would leave a reader unable to check the
                // declaration against the bytes.
                let named = match &f.name {
                    Some(name) => format!("{} ({name})", f.path),
                    None => f.path.clone(),
                };
                out.push_str(&format!(
                    "      [{}..{}] {} = {}\n",
                    f.start, f.end, named, f.value
                ));
            }
            out
        }
    }
}

/// One field per line, indented by nesting, with the BYTES it was decoded from.
///
/// The span is the point of the whole layer, so it leads: a reader comparing
/// this capture against another implementation wants to say "these two bytes"
/// and not "the keyexpr".
fn push_field_text(out: &mut String, field: &wz_session_core::dissect::Field, depth: usize) {
    use wz_session_core::dissect::FieldValue;
    let pad = "  ".repeat(depth);
    let span = field.span;
    match &field.value {
        FieldValue::Nested(children) => {
            out.push_str(&format!(
                "{pad}[{}..{}] {}\n",
                span.start, span.end, field.name
            ));
            for child in children {
                push_field_text(out, child, depth + 1);
            }
        }
        other => {
            out.push_str(&format!(
                "{pad}[{}..{}] {} = {other:?}\n",
                span.start, span.end, field.name
            ));
        }
    }
}

/// R311y666 (§1.2a) — one line per flow.
///
/// Everything here is a fact the dissection already held and no rendering
/// exposed: which endpoints, what the byte stream turned out to be, how many
/// messages came out of it, and -- for an encrypted flow -- whether its
/// plaintext was read and why not.
///
/// R311y668 (§1.2a) — EVERY flow, and the DATAGRAM ones were absent. `flows()`
/// is the TCP half of a dissection; a capture of scouting traffic has all of its
/// content in `datagram_flows()`, so `--flows` over one printed the report's
/// `datagram_flows: N` count above a list with no rows in it. A listing that
/// omits a whole transport is worse than no listing: it reads as "this capture
/// had one connection in it and here it is".
///
/// R311y668 — and the JSON carries the MESSAGES. `--messages` reached only the
/// text branch, so `--json --messages` listed the flows and not their messages:
/// a silent narrowing of exactly the kind R311y667 closed elsewhere.
fn flow_lines(d: &Dissection, format: Format, per_message: bool, cap: Option<usize>) -> String {
    let mut out = String::new();
    if format == Format::Json {
        out.push_str("\"flows\":[");
    } else {
        out.push_str("\nflows:\n");
    }
    let mut emitted = 0usize;
    for flow in d.flows() {
        let encrypted = flow.encrypted();
        let framing = match flow.framing() {
            wz_capture::Framing::Stream => "stream",
            wz_capture::Framing::WebSocket { .. } => "websocket",
            wz_capture::Framing::Encrypted(_) => "tls",
            wz_capture::Framing::Undecided => "undecided",
            wz_capture::Framing::OpeningLost => "opening-lost",
        };
        // R311y669 — BOTH directions where they disagree. The flow-level reason
        // is the FIRST refusal a pass met, so a flow whose direction A hit an
        // epoch boundary and whose direction B had no key at all showed only A's
        // -- one of the two remedies a reader needed. Rendered as `A's / B's` only
        // when they differ, so the ordinary single-cause flow reads exactly as
        // before and the extra words appear precisely where they carry something.
        let state = match encrypted.as_ref() {
            None => "-".to_string(),
            Some(e) => match e.not_decrypted {
                None => "decrypted".to_string(),
                Some(reason) => {
                    let [a, b] = e.not_decrypted_per_direction;
                    match (a, b) {
                        (Some(a), Some(b)) if a != b => format!("{a:?}+{b:?}"),
                        _ => format!("{reason:?}"),
                    }
                }
            },
        };
        // R311y689 — a DECRYPTED flow's frame offsets were remapped to the
        // ciphertext record they came out of, so they are not byte offsets into
        // anything a reader can add a span to. The two spaces are told apart
        // here because this is where the flow's own state is in hand.
        let rows: Vec<MessageRow> = flow
            .frames
            .iter()
            .map(|f| {
                let space = if encrypted.is_some() {
                    OffsetSpace::CiphertextRecord
                } else {
                    MessageRow::stream_byte(f)
                };
                MessageRow::transport(f, space)
            })
            .collect();
        push_flow(
            &mut out,
            format,
            &mut emitted,
            &flow.flow,
            framing,
            flow.frames.len(),
            // A stream flow carries no scouting messages and says so with a
            // zero rather than by the key's absence, which is the same
            // structural rule the report's own `encrypted` block follows: a
            // consumer never has to test for a field to learn a count is nil.
            0,
            &state,
            per_message.then_some(&rows[..]),
            cap,
        );
    }
    // R311y668 — the DATAGRAM half. Absent from this listing until now, which
    // made a scouting-only capture report its flow count above an empty list.
    for flow in d.datagram_flows() {
        let mut rows: Vec<MessageRow> = flow
            .frames
            .iter()
            .map(|f| MessageRow::transport(f, OffsetSpace::Packet))
            .collect();
        rows.extend(flow.scouting.iter().map(MessageRow::scouting));
        // R311y718 — and the zenoh recovered out of this flow's QUIC streams.
        //
        // Their offsets are STREAM BYTES, not packet indices: a recovered QUIC
        // stream is a byte stream and its frames are offset into it exactly as
        // a `tcp/...` flow's are. Rendering them in the packet space beside the
        // rows above would print a byte offset under a column heading a reader
        // resolves against a packet number, which is R311y713's coordinate
        // defect in the one place both spaces meet.
        for stream in &flow.quic_streams {
            rows.extend(
                stream
                    .frames
                    .iter()
                    .map(|f| MessageRow::transport(f, MessageRow::stream_byte(f))),
            );
        }
        // R311y669 — a QUIC flow says so in the framing column and says NOT
        // DECRYPTED in the state one. Both are load-bearing: before this round
        // the row would have read `datagram   3 message(s)` for a flow whose
        // three messages were QUIC packets misread as zenoh.
        let (framing, state) = match &flow.quic {
            // R311y671 — a flow whose declaration its own packets contradict does
            // NOT say `QuicProtected`, because that claims protected bytes this
            // reader identified. It identified none, and the row is the line a
            // person scans for which connection to look at.
            Some(c) if c.declaration_unsupported() => ("quic", "QuicDeclaredUnsupported"),
            // R311y718 — a QUIC flow whose streams DECODED is no longer merely
            // protected: its zenoh is in the rows. The two states are kept
            // apart because the remedy differs — `QuicProtected` sends a reader
            // to find a key log, and this one has nothing left to fetch.
            Some(_) if !flow.quic_streams.is_empty() => ("quic", "QuicDecoded"),
            Some(_) => ("quic", "QuicProtected"),
            // "datagram" sits in the FRAMING column because that column answers
            // "what did these bytes turn out to be", and for UDP the answer is
            // that there was no stream to frame -- one datagram is one unit.
            // `Framing` itself is a stream-only enum, so this is the one value
            // in this column that does not come from it.
            //
            // DTLS is still not recognised, so a plain datagram flow's state is
            // not "decrypted" and not a refusal -- it is not applicable, and
            // saying so is different from claiming either.
            None => ("datagram", "-"),
        };
        push_flow(
            &mut out,
            format,
            &mut emitted,
            &flow.flow,
            framing,
            // A QUIC flow's PACKET count is reported in the report's own `quic`
            // block rather than folded in here: a `message(s)` column carrying
            // packets is the shape of the misread R311y669 removed.
            //
            // R311y718 — what a QUIC flow DOES contribute here is the zenoh
            // decoded out of its streams, and it is counted through the flow's
            // own enumeration so that the number and the rows above cannot
            // disagree about which lists exist.
            flow.decoded_messages(),
            flow.scouting.len(),
            state,
            per_message.then_some(&rows[..]),
            cap,
        );
    }
    // R311y720 (§D M3) — the SERIAL line, which is a third kind of row
    // producer: not a stream flow, not a datagram flow, but a point-to-point
    // link with no addresses at all. Listed with the others rather than in a
    // block of its own, because a reader scanning `--flows` for "what did this
    // capture carry" must not have to know that serial answers somewhere else.
    if let Some(k) = d.serial_census() {
        let rows: Vec<MessageRow> = d
            .serial_frames()
            .iter()
            .map(|frame| MessageRow::transport(frame, OffsetSpace::Packet))
            .collect();
        // The FlowKey a serial line does not have. `port` carries the interface
        // count rather than a port, and the addresses are empty -- a serial
        // link is two wires and has no addressing, so a synthesised 5-tuple
        // would be a fabricated fact in a column readers resolve.
        let flow = wz_capture::link::FlowKey::serial_line();
        push_flow(
            &mut out,
            format,
            &mut emitted,
            &flow,
            "serial",
            d.serial_frames().len(),
            0,
            if k.direction_unattributed {
                "SerialDirectionUnattributed"
            } else if k.roles_witnessed {
                "SerialDirectionMeasured"
            } else {
                "SerialDirectionPositional"
            },
            per_message.then_some(&rows[..]),
            cap,
        );
    }
    if format == Format::Json {
        out.push(']');
    }
    out
}

/// R311y668 (§1.2a) — one flow's row, in whichever format, for whichever
/// transport.
///
/// Written once for the two loops above rather than twice: the stream and the
/// datagram halves differ in three values and a listing whose two halves drift
/// into different shapes is worse than one that lists only half, because a
/// consumer cannot tell which shape it is reading.
///
/// `emitted` is the comma bookkeeping, and it counts across BOTH loops -- the
/// JSON array is one array, so `i > 0` inside either loop alone would drop a
/// separator between the last stream flow and the first datagram one.
#[allow(clippy::too_many_arguments)]
fn push_flow(
    out: &mut String,
    format: Format,
    emitted: &mut usize,
    key: &wz_capture::link::FlowKey,
    framing: &str,
    messages: usize,
    scouting: usize,
    state: &str,
    rows: Option<&[MessageRow]>,
    cap: Option<usize>,
) {
    if format == Format::Json {
        if *emitted > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"low\":\"{}\",\"high\":\"{}\",\"framing\":\"{framing}\",\
             \"messages\":{messages},\"scouting\":{scouting},\"protection\":\"{state}\"",
            endpoint(&key.low),
            endpoint(&key.high),
        ));
        if let Some(rows) = rows {
            let (shown, omitted) = split_at_cap(rows, cap);
            out.push_str(",\"message_list\":[");
            for (i, row) in shown.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                row.push_json(out);
            }
            out.push(']');
            // STRUCTURAL, present with a zero when nothing was cut: a consumer
            // must never have to test for a key to learn whether the list it is
            // reading is the whole one.
            out.push_str(&format!(",\"message_list_omitted\":{omitted}"));
        }
        out.push('}');
    } else {
        out.push_str(&format!(
            "  {} <-> {}  {framing:<12} {messages} message(s)  \
             {scouting} scouting  {state}\n",
            endpoint(&key.low),
            endpoint(&key.high),
        ));
        if let Some(rows) = rows {
            let (shown, omitted) = split_at_cap(rows, cap);
            for row in shown {
                row.push_text(out);
            }
            if omitted > 0 {
                out.push_str(&format!("      ... {omitted} more not listed\n"));
            }
        }
    }
    *emitted += 1;
}

/// R311y669 (§1.2a) — the rows a listing shows, and how many it did not.
///
/// One function for both formats so the two can never disagree about what was
/// cut: a text rendering saying "4 more not listed" beside a JSON one reporting
/// three would be a worse failure than no bound at all.
fn split_at_cap(rows: &[MessageRow], cap: Option<usize>) -> (&[MessageRow], usize) {
    match cap {
        Some(n) if rows.len() > n => (&rows[..n], rows.len() - n),
        _ => (rows, 0),
    }
}

/// R311y668 (§1.2a) — one row of the message listing.
///
/// A type and not a formatting closure per call site, because the two message
/// namespaces do not have the same fields and the listing must not pretend they
/// do: a scouting datagram has no batch to be inside of, and folding that into a
/// `0` would claim a position it does not have.
struct MessageRow {
    /// Which way it travelled, keyed exactly as its flow keys it.
    direction: wz_session_core::passive::Direction,
    /// TCP-space byte offset for a stream flow, packet index for a datagram one
    /// -- which is what `PassiveFrame::stream_offset` already carries there,
    /// because a datagram has no stream to be an offset into.
    offset: usize,
    /// R311y689 (§1.1n) — WHICH of those two (or three) it is, on the row.
    ///
    /// The line above has said "byte offset here, packet index there" since
    /// R311y668 and the OUTPUT said neither: `@12` on one row and `@12` on the
    /// next counted different things and looked identical. R311y688 closed this
    /// for the field listing and left it standing one listing over -- the same
    /// ambiguity, in the listing a reader reaches for first.
    ///
    /// Decided by the CALLER, because only the loop knows which transport it is
    /// walking: `MessageRow::transport` is called from both, and an encrypted
    /// stream flow's offsets are remapped to the ciphertext record they came
    /// out of (`remap_decrypted_offsets`), which is a third space again.
    offset_space: OffsetSpace,
    /// Which framing unit inside the record it came out of, or `None` for a
    /// scouting datagram, which is not inside one.
    batch: Option<usize>,
    /// Which namespace read it. Part of the row rather than implied by where it
    /// is printed, because the two namespaces COLLIDE numerically -- `S_MID_SCOUT`
    /// and `T_MID_INIT` are both `0x01` -- so "a Scout" and "an Init" can be the
    /// same byte read two ways, and a reader must be able to tell which happened.
    space: &'static str,
    /// What it was, by the name its own type gives it.
    name: String,
}

impl MessageRow {
    fn transport(f: &wz_session_core::passive::PassiveFrame, offset_space: OffsetSpace) -> Self {
        Self {
            direction: f.direction,
            offset: f.stream_offset,
            offset_space,
            batch: Some(f.batch_index),
            space: "transport",
            name: message_name(f),
        }
    }

    /// The space a CLEARTEXT stream frame's offset is in, message offset and
    /// all. Separate from the constructor because the caller decides whether
    /// this is the right space at all.
    fn stream_byte(f: &wz_session_core::passive::PassiveFrame) -> OffsetSpace {
        OffsetSpace::StreamByte {
            message_at: message_at(f),
        }
    }

    fn scouting(s: &wz_capture::ScoutingDatagram) -> Self {
        Self {
            direction: s.direction,
            offset: s.packet_index,
            // A scouting datagram's offset is its packet's index, like every
            // other datagram coordinate in this crate.
            offset_space: OffsetSpace::Packet,
            batch: None,
            space: "scouting",
            name: match &s.frame {
                Ok(f) => f.kind_name().to_string(),
                Err(e) => format!("undecodable({e:?})"),
            },
        }
    }

    fn push_json(&self, out: &mut String) {
        let batch = match self.batch {
            Some(b) => b.to_string(),
            // `null` and not a number: JSON has a word for "this row has no
            // such position" and using it is the difference between saying so
            // and claiming index zero.
            None => "null".to_string(),
        };
        out.push_str(&format!(
            "{{\"space\":\"{}\",\"direction\":\"{:?}\",\"offset\":{}{},\
             \"batch\":{batch},\"name\":\"{}\"}}",
            self.space,
            self.direction,
            self.offset,
            self.offset_space.json(),
            self.name
        ));
    }

    fn push_text(&self, out: &mut String) {
        let space = self.offset_space.note();
        match self.batch {
            Some(b) => out.push_str(&format!(
                "      {:?} @{}{space} #{b}  {}\n",
                self.direction, self.offset, self.name
            )),
            None => out.push_str(&format!(
                "      {:?} @{}{space} {}  {}\n",
                self.direction, self.offset, self.space, self.name
            )),
        }
    }
}

/// R311y667 (§1.2a) — what one decoded message WAS, in a word.
///
/// ## Why the name comes from the type and not from a `Debug` rendering
///
/// R311y667 read the leading token of the derived `Debug`. The reason it gave
/// for not matching was sound: `InboundFrame`'s variants are individually
/// `#[cfg]`-gated on seven `codec-*` features this crate does not own, so an
/// exhaustive match HERE would mirror those gates and a mirror drifts, while a
/// `_ =>` arm is worse -- it reports a new message kind as whatever the default
/// happens to be.
///
/// What it left behind is a name resting on a `Debug` shape nothing pinned: a
/// variant whose rendering stopped beginning with its identifier would have
/// quietly renamed a message here and said nothing. R311y668 moved the naming
/// to [`wz_session_core::inbound::InboundFrame::kind_name`], where the arms sit
/// beside the variants under the same `#[cfg]`s and exhaustiveness is the
/// COMPILER's. There is no mirror to drift, no `Debug` shape to depend on, and
/// a variant added upstream fails a match instead of taking a fallback.
fn message_name(frame: &wz_session_core::passive::PassiveFrame) -> String {
    match &frame.frame {
        Ok(f) => f.kind_name().to_string(),
        // A message this reader could NOT decode is named as such rather than
        // omitted: a listing that shows only the successes is the silence this
        // whole track exists to end, one layer up.
        Err(e) => format!("undecodable({e:?})"),
    }
}

/// An endpoint as `addr:port`, IPv4 dotted or IPv6 hex-grouped.
fn endpoint(e: &wz_capture::link::Endpoint) -> String {
    let addr = e.addr();
    if addr.len() == 4 {
        format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], e.port)
    } else {
        let groups: Vec<String> = addr
            .chunks(2)
            .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
            .collect();
        format!("[{}]:{}", groups.join(":"), e.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    /// R311y726 — A DECLARATION LEDGER BELONGS TO ITS RUN, NOT TO THE MAP.
    ///
    /// ## The property, and why it needed a witness
    ///
    /// R311y725 answered "which declarations bound nothing" with a `Cell<bool>`
    /// beside every rule INSIDE `FormatMap`, and it worked. What it also did was
    /// put a fact about one walk into a value that describes what the reader
    /// declared: the marks outlived the walk, so a map could never be consulted
    /// a second time as if it were fresh, and two analyses sharing one map would
    /// have read each other's answers.
    ///
    /// That is not a hypothetical about a threaded future — it is what the type
    /// MEANT, and this test is the difference in one run. The second ledger over
    /// the SAME map reports both declarations unused, because the first ledger's
    /// walk was the first ledger's. Under the R311y725 shape this assertion
    /// fails, which is what makes it a witness rather than a restatement.
    ///
    /// ## Not a `Sync` test, and that is a correction
    ///
    /// The carry this pays said the `Cell` had cost `FormatMap` its `Sync`.
    /// MEASURED, and false: `FormatMap` holds `&dyn PayloadFormat`, a trait
    /// object with no auto-trait bounds, so it was never `Sync` and the `Cell`
    /// changed nothing about that. The real cost was the one above.
    #[test]
    fn a_declaration_ledger_belongs_to_its_run_and_not_to_the_map() {
        use wz_capture::payload::formats::FormatMap;

        let format = payload_formats::builtin("protobuf").expect("a built-in decoder");
        // Literal patterns, so this runs in every feature build: `demo/**`
        // is REFUSED where `filter-wildcards` is off, which is this map's own
        // rule and not a fact this test is about.
        let mut map = FormatMap::new();
        map.insert("demo/a", format).expect("installs");
        map.name_field("demo/a", "1", "temperature")
            .expect("installs");

        let first = Declarations::new(&map);
        assert_eq!(
            first.unused().len(),
            2,
            "before a walk NOTHING has applied, which is the honest answer to \
             the question asked too early"
        );
        assert!(first.for_keyexpr("demo/a").is_some(), "the rule covers it");
        assert_eq!(
            first.field_name("demo/a", "1").as_deref(),
            Some("temperature"),
            "and the declaration names that path"
        );
        assert!(
            first.unused().is_empty(),
            "both declarations applied in this run: {:?}",
            first.unused()
        );

        // THE PROPERTY. A second run over the same declarations starts clean --
        // the marks were never on the map.
        let second = Declarations::new(&map);
        let unused = second.unused();
        assert_eq!(
            unused.len(),
            2,
            "a second run must not inherit the first run's answers: {unused:?}"
        );
        assert_eq!(
            unused.iter().map(|d| d.kind).collect::<Vec<_>>(),
            alloc_vec_kinds(),
            "rules are listed before names, in the order they were installed"
        );
        assert_eq!(
            unused.iter().map(|d| d.text.as_str()).collect::<Vec<_>>(),
            vec!["demo/a=protobuf", "demo/a:1=temperature"],
            "and each is spelled by the map that accepted it, not reassembled \
             by whoever renders it"
        );
        // R311y884 — the rule half reads `demo/a=protobuf` and used to read
        // `demo/a`. This assertion's own sentence is why the change is the fix
        // rather than a churned expectation: the map spells it, and the map now
        // spells it in the grammar `parse_declaration` accepts. The bare pattern
        // carried no `=`, so the ledger reported a line the reader that wrote it
        // could not have written (open-debt item 235).
    }

    /// The two kinds, in the order [`Declarations::unused`] yields them.
    fn alloc_vec_kinds() -> Vec<wz_capture::payload::formats::DeclarationKind> {
        use wz_capture::payload::formats::DeclarationKind;
        vec![DeclarationKind::FormatRule, DeclarationKind::FieldName]
    }

    /// Round 1999 (item 470) — a live read is a complete command line, and
    /// EVERY way of writing an incomplete one is refused by name.
    ///
    /// The table is the test. Each refusal below exists because the alternative
    /// is a flag that quietly changes nothing, which is the shape this parser
    /// already turns into an error twice (`SelectWithoutPlane`,
    /// `PayloadWithoutFields`). Driving the accepted form as well is what keeps
    /// this from being a test that a parser rejecting EVERYTHING would pass.
    #[test]
    fn a_live_read_is_accepted_and_every_incomplete_form_is_refused_by_name() {
        let ok = parse(&args(&["--interface", "eth0", "--for", "2.5"])).expect("a live read");
        assert_eq!(ok.interface.as_deref(), Some("eth0"));
        assert_eq!(ok.live_ms, Some(2_500), "seconds in, milliseconds out");
        assert_eq!(ok.capture, "", "a live read names no file");

        for (why, argv, expected) in [
            (
                "two sources for one report",
                vec!["cap.pcapng", "--interface", "eth0", "--for", "1"],
                UsageError::CaptureAndInterface,
            ),
            (
                "a tap has no end",
                vec!["--interface", "eth0"],
                UsageError::InterfaceWithoutBound,
            ),
            (
                "--for bounds nothing when a file already ends",
                vec!["cap.pcapng", "--for", "1"],
                UsageError::LiveCannotDo("--for"),
            ),
            (
                "QUIC recovery re-reads bytes a tap does not keep",
                vec!["--interface", "eth0", "--for", "1", "--quic", "7447"],
                UsageError::LiveCannotDo("--quic"),
            ),
            (
                "and the flag that only means anything beside it",
                vec!["--interface", "eth0", "--for", "1", "--quic-cid-len", "8"],
                UsageError::LiveCannotDo("--quic-cid-len"),
            ),
            (
                "a bound that is not a number",
                vec!["--interface", "eth0", "--for", "soon"],
                UsageError::BadValue("--for", "soon".into()),
            ),
            (
                "and a bound that is a number but not a duration",
                vec!["--interface", "eth0", "--for", "0"],
                UsageError::BadValue("--for", "0".into()),
            ),
        ] {
            assert_eq!(
                parse(&args(&argv)),
                Err(expected),
                "{why}: {argv:?} must be refused"
            );
        }
    }

    /// Round 2001 (item 473) — `--csv` names a plane, turns that plane's
    /// census on, and refuses the two ways of asking for nothing.
    ///
    /// The census implication is the load-bearing part and is asserted rather
    /// than trusted: without it the run builds no table, the renderer emits a
    /// header and no rows, and a reader sees what an empty capture looks like.
    #[test]
    fn csv_names_a_plane_turns_it_on_and_refuses_the_rest() {
        let ok = parse(&args(&["cap.pcapng", "--csv", "throughput"])).expect("a csv run");
        assert_eq!(ok.csv, Some(CsvPlane::Throughput));
        assert!(
            ok.census.throughput,
            "--csv must turn its own plane on, or it renders a header and no rows"
        );

        // The refusal NAMES the set, so a reader learns which planes exist.
        let refused =
            parse(&args(&["cap.pcapng", "--csv", "throughpt"])).expect_err("a typo is not a plane");
        assert_eq!(refused, UsageError::UnknownCsvPlane("throughpt".into()));
        assert!(
            refused.to_string().contains("throughput"),
            "the message must list what this build emits: {refused}"
        );

        assert_eq!(
            parse(&args(&["cap.pcapng", "--csv", "throughput", "--json"])),
            Err(UsageError::CsvAndJson),
            "two renderings and one output"
        );
        assert_eq!(
            parse(&args(&["cap.pcapng", "--csv"])),
            Err(UsageError::MissingValue("--csv")),
        );
    }

    #[test]
    fn a_capture_path_alone_is_a_complete_command_line() {
        assert_eq!(
            parse(&args(&["cap.pcapng"])),
            Ok(Options {
                capture: "cap.pcapng".into(),
                interface: None,
                live_ms: None,
                keylogs: Vec::new(),
                format: Format::Text,
                per_flow: false,
                per_message: false,
                quic_ports: Vec::new(),
                quic_cid_len: None,
                payload_formats: Vec::new(),
                payload_field_names: Vec::new(),
                serial_linktypes: Vec::new(),
                max_messages: None,
                census: Census::default(),
                per_field: false,
                bounded: false,
                health: false,
                select: None,
                csv: None,
            })
        );
    }

    #[test]
    fn the_keylog_and_json_options_are_read() {
        assert_eq!(
            parse(&args(&[
                "--keylog",
                "keys.txt",
                "cap.pcapng",
                "--json",
                "--messages"
            ])),
            Ok(Options {
                capture: "cap.pcapng".into(),
                interface: None,
                live_ms: None,
                keylogs: args(&["keys.txt"]),
                format: Format::Json,
                // `--messages` implies `--flows`: the messages are printed
                // under their flow, so the pairing has one sensible meaning.
                per_flow: true,
                per_message: true,
                quic_ports: Vec::new(),
                quic_cid_len: None,
                payload_formats: Vec::new(),
                payload_field_names: Vec::new(),
                serial_linktypes: Vec::new(),
                max_messages: None,
                census: Census::default(),
                per_field: false,
                bounded: false,
                health: false,
                select: None,
                csv: None,
            })
        );
    }

    /// R311y708 (Y4) — `--keylog` TWICE KEEPS BOTH.
    ///
    /// MEASURED before this changed: the parser assigned rather than pushed, so
    /// the command line below produced `Some("second.txt")` and the operator was
    /// told nothing about the file that had been dropped. Two endpoints writing
    /// two `SSLKEYLOGFILE`s is the ordinary shape of a two-sided capture, so the
    /// discarded half was as likely to be the interesting one as the kept half.
    ///
    /// ORDER is asserted, not just membership: the merge downstream is textual
    /// append and a reader comparing a report against their own files should
    /// find the keys in the order they typed them.
    #[test]
    fn a_repeated_keylog_keeps_every_file_in_the_order_given() {
        let parsed = parse(&args(&[
            "--keylog",
            "first.txt",
            "cap.pcapng",
            "--keylog",
            "second.txt",
        ]))
        .expect("two key logs is a well-formed command line");
        assert_eq!(
            parsed.keylogs,
            args(&["first.txt", "second.txt"]),
            "both files, in the order the command line gave them"
        );
        assert_eq!(parsed.capture, "cap.pcapng");
    }

    /// A misspelt flag is REFUSED, not treated as a filename and not ignored.
    ///
    /// Both wrong readings produce a confident wrong answer: as a filename it
    /// becomes a second capture, and ignored it produces a report saying the
    /// capture could not be decrypted -- by a tool that was handed the keys.
    #[test]
    fn an_unknown_flag_is_refused_rather_than_read_as_a_filename() {
        assert_eq!(
            parse(&args(&["cap.pcapng", "--keylogs", "keys.txt"])),
            Err(UsageError::UnknownFlag("--keylogs".into()))
        );
        assert_eq!(
            parse(&args(&["cap.pcapng", "--keylog"])),
            Err(UsageError::MissingValue("--keylog"))
        );
        assert_eq!(parse(&args(&[])), Err(UsageError::NoCapture));
        assert_eq!(
            parse(&args(&["a.pcapng", "b.pcapng"])),
            Err(UsageError::TwoCaptures)
        );
    }

    /// R311y670 — the two flags added this round are READ, and a value that is
    /// not a number is REFUSED rather than defaulted.
    ///
    /// Refusal matters more here than for most flags: `--quic htttp` silently
    /// dropped produces a report claiming a mid-connection QUIC capture carried
    /// zenoh, which is the exact wrong answer the flag exists to prevent.
    #[test]
    fn the_quic_and_max_message_options_are_read_and_their_values_checked() {
        let got = parse(&args(&[
            "cap.pcapng",
            "--quic",
            "4433",
            "--quic",
            "7447",
            "--max-messages",
            "16",
        ]))
        .expect("accepted");
        assert_eq!(got.quic_ports, vec![4433, 7447], "--quic is REPEATABLE");
        assert_eq!(got.max_messages, Some(16));

        assert_eq!(
            parse(&args(&["cap.pcapng", "--quic", "htttp"])),
            Err(UsageError::BadValue("--quic", "htttp".into()))
        );
        assert_eq!(
            parse(&args(&["cap.pcapng", "--quic", "70000"])),
            Err(UsageError::BadValue("--quic", "70000".into())),
            "a port past 16 bits is not a port"
        );
        assert_eq!(
            parse(&args(&["cap.pcapng", "--max-messages"])),
            Err(UsageError::MissingValue("--max-messages"))
        );
    }

    /// R311y857 — an Interface Statistics Block whose `opt_isb_ifdrop` says the
    /// capture tool lost `dropped` packets.
    ///
    /// Appended to a pcapng after the packets, which is where a capture tool
    /// writes it. A classic pcap has no such block, and that ABSENCE is what
    /// the control arm below rests on.
    fn isb_with_drops(interface_id: u32, dropped: u64) -> Vec<u8> {
        let mut opts = Vec::new();
        opts.extend_from_slice(&5u16.to_le_bytes()); // opt_isb_ifdrop
        opts.extend_from_slice(&8u16.to_le_bytes());
        opts.extend_from_slice(&dropped.to_le_bytes());
        opts.extend_from_slice(&0u16.to_le_bytes()); // opt_endofopt
        opts.extend_from_slice(&0u16.to_le_bytes());

        let total = (24 + opts.len()) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&0x0000_0005u32.to_le_bytes()); // BT_ISB
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&interface_id.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_high
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_low
        out.extend_from_slice(&opts);
        out.extend_from_slice(&total.to_le_bytes());
        out
    }

    /// Ethernet + IPv4 + UDP from a distinct source port, so N of them are N
    /// distinct 5-tuples and therefore N flows.
    fn udp_from(sport: u16) -> Vec<u8> {
        let payload = [0u8; 4];
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // no checksum: RFC 768
        udp.extend_from_slice(&payload);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// R311y884 (open-debt item 234) — the caps BITING, which no surface could
    /// show.
    ///
    /// `dropped_by_limits` is the group that says what staying inside this
    /// reader's ceilings cost, and it was zero everywhere for a structural
    /// reason rather than a measured one: `wz-analyze` built its dissection
    /// through `from_capture_declaring`, which takes no limits, and the ABI's
    /// `wz_dissect_pcap_summary` through `from_capture`, which takes none
    /// either. With no cap in place nothing can be dropped by one, so the zeros
    /// were true and told a reader nothing — and a reader cannot tell that kind
    /// of zero from the kind that means "nothing was dropped".
    ///
    /// Both arms, because the flag has to do something AND the default has to
    /// keep doing what it did: 1025 flows is one past
    /// `DissectionLimits::for_live_tap`'s `max_flows_per_table`, so bounded
    /// evicts exactly one and unbounded evicts none.
    #[test]
    fn a_cap_that_bites_is_visible_once_the_reader_can_be_bounded() {
        let packets: Vec<Vec<u8>> = (0..1025u16).map(|i| udp_from(2000 + i)).collect();
        let frames: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, i as u64 * 1_000, p.as_slice()))
            .collect();
        let pcapng =
            wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &frames);

        let unbounded = health_run_bounded(&pcapng, true, Format::Json, false);
        assert!(
            unbounded.contains(
                "\"dropped_by_limits\":{\"frames\":0,\"stream_bytes\":0,\"skipped\":0,\"flows\":0"
            ),
            "with no ceiling nothing can be dropped by one -- a structural zero: {unbounded}"
        );

        let bounded = health_run_bounded(&pcapng, true, Format::Json, true);
        assert!(
            bounded.contains("\"flows\":1"),
            "1025 flows is one past the live-tap ceiling, so exactly one is \
             evicted and the group finally says so: {bounded}"
        );
    }

    /// R311y885 — AND IT IS VISIBLE WITHOUT `--health`, because a bound a
    /// reader asked for must not be silent about what it cost.
    ///
    /// # The gap this pins, which the arms above cannot see
    ///
    /// Both arms of the test above pass `--health`. So the claim they establish
    /// is "the group is a measurement once the reader is bounded AND the loss
    /// document was asked for", and the combination a person actually types —
    /// `wz-analyze cap.pcapng --bounded`, because they know their memory is
    /// finite and not because they are auditing losses — was untested. A report
    /// that went short by an evicted flow and said nothing would have satisfied
    /// every assertion in this file.
    ///
    /// The rule this pins is the one the C ABI's bounded doors already hold:
    /// asking for a ceiling is asking to be told when it bites. `--health` stays
    /// the flag for the WHOLE loss document — capture drops, fragments, framing,
    /// sequence — and this is one group of five numbers that rides the bound.
    ///
    /// # Both arms, so it is the BOUND that carries it
    ///
    /// Unbounded and without `--health` the group stays absent: a reader who
    /// asked for neither is not shown a group of structural zeros they would
    /// have to know how to read.
    #[test]
    fn a_bound_is_never_silent_even_without_the_health_flag() {
        let packets: Vec<Vec<u8>> = (0..1025u16).map(|i| udp_from(2000 + i)).collect();
        let frames: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, i as u64 * 1_000, p.as_slice()))
            .collect();
        let pcapng =
            wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &frames);

        let bounded = health_run_bounded(&pcapng, false, Format::Json, true);
        // Round 2042 (item 359) — THE SHAPE PIN NOW CARRIES THE CEILINGS, and
        // extending it rather than trimming it is the point: this fixture
        // builds 1025 flows to make ONE cap bite, and until this round the
        // document said `flows: 1` without saying `of 1024`. A reader could
        // not tell which ceiling was nearest, which is what item 359 asked
        // for; here the answer is in the same object.
        assert!(
            bounded.contains(
                "\"dropped_by_limits\":{\"frames\":0,\"stream_bytes\":0,\"skipped\":0,\
                 \"flows\":1,\"scout_askers\":0,\"caps\":{\"frames_per_flow\":10000,\
                 \"stream_bytes_per_direction\":4194304,\"skipped_packets\":10000,\
                 \"max_flows_per_table\":1024,\"max_scout_askers\":1024}}"
            ),
            "a reader who asked for a ceiling must be told it bit AND what it \
             bit against, without having to also ask for the loss document: \
             {bounded}"
        );

        let unbounded = health_run_bounded(&pcapng, false, Format::Json, false);
        assert!(
            !unbounded.contains("\"dropped_by_limits\""),
            "and a reader who asked for no ceiling is not shown five \
             structural zeros: {unbounded}"
        );
    }

    /// One analysis of `file`, with `--health` on or off and nothing else
    /// changed.
    fn health_run(file: &[u8], health: bool, format: Format) -> String {
        health_run_bounded(file, health, format, false)
    }

    /// The same, with `--bounded` as the one other variable (R311y884).
    fn health_run_bounded(file: &[u8], health: bool, format: Format, bounded: bool) -> String {
        analyze_request(&Request {
            bounded,
            capture: file,
            keylog: None,
            format,
            per_flow: false,
            per_message: false,
            messages_per_flow: None,
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &[],
            payload_field_names: &[],
            serial_linktypes: &[],
            census: Census::default(),
            per_field: false,
            health,
            select: None,
            csv: None,
        })
        .expect("the capture reads")
        .0
    }

    /// R311y857 — THE TWO LOSS GROUPS THIS SURFACE COULD NOT SEE, and the
    /// grouped view of the rest.
    ///
    /// # What was MEASURED, because the debt row was overstated
    ///
    /// `debt-analysis-surface-parity` said the command line "has no flag for
    /// these (capture drops, retransmits, sequence gaps, checksums, framing
    /// desyncs)". Run rather than read, that is mostly false: the report's own
    /// `capture` object has carried `capture_reported_drops`, `retransmits`,
    /// `out_of_order`, `partial_overlaps`, the whole `framing` group, the whole
    /// `sequence` group and `drops` all along, unconditionally. The registry
    /// reason had outlived the code, which is this workspace's debt-47 shape,
    /// and it is recorded here rather than quietly corrected.
    ///
    /// What this surface genuinely could NOT reach is exactly two things, and
    /// they are what the first two arms below pin:
    ///
    /// - `fragment_stats()` — the fragment CHAINS: pieces, completed, expired,
    ///   evicted, malformed, overlapping. No key of the report named any of it.
    /// - the checksums that VERIFIED or were ABSENT. The report carries
    ///   `ip_checksum_invalid` and `transport_checksum_invalid` and nothing
    ///   else, so a reader could see how many checksums were wrong and never
    ///   how many were CHECKED — a count of failures with no denominator.
    ///
    /// # The discriminator
    ///
    /// One capture, two runs, and the evidence is the DIFFERENCE on those two
    /// axes. A build whose flag did nothing fails the second arm; one that
    /// printed the group unconditionally fails the first.
    ///
    /// # The control that makes the number mean something
    ///
    /// A classic pcap has nowhere in the FORMAT to record a drop count, so the
    /// honest answer there is "the file said nothing" and never `0`. That arm
    /// separates a reader that reads the ISB from one that reports a hard-wired
    /// zero and looks right on the pcapng.
    #[test]
    fn the_two_unreachable_loss_groups_reach_the_command_line() {
        let mut pcapng = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &[0u8; 4])],
        );
        pcapng.extend_from_slice(&isb_with_drops(0, 17));

        let quiet = health_run(&pcapng, false, Format::Json);
        assert!(
            !quiet.contains("\"health\":"),
            "without the flag the grouped document must not be printed: {quiet}"
        );
        // The two axes, measured on the CURRENT report rather than assumed.
        assert!(
            !quiet.contains("ip_checksum_valid"),
            "the report carried only the INVALID counts, and this arm is what \
             makes the flag's second half a fix rather than a repeat: {quiet}"
        );
        assert!(
            !quiet.contains("\"pieces\":"),
            "and the fragment chains were reachable from no key at all: {quiet}"
        );

        let asked = health_run(&pcapng, true, Format::Json);
        assert!(
            asked.contains("\"health\":{\"capture_reported_drops\":17"),
            "the grouped document must carry the capture tool's admission: {asked}"
        );
        assert!(
            asked.contains("\"ip_checksum_valid\":") && asked.contains("\"pieces\":"),
            "and the two groups this surface could not reach: {asked}"
        );
        // Grouped by WHO lost the packet, which is the whole reason the flag
        // renders a document of its own rather than five more report keys.
        for group in [
            "dropped_by_limits",
            "fragments",
            "streams",
            "framing",
            "sequence",
        ] {
            assert!(
                asked.contains(&format!("\"{group}\":")),
                "the {group} group is missing: {asked}"
            );
        }

        let text = health_run(&pcapng, true, Format::Text);
        assert!(
            text.contains("17 packet(s) dropped by the capture tool"),
            "a person at a terminal is told the same fact: {text}"
        );

        // THE CONTROL. A classic pcap cannot answer, and silence is not zero.
        let pcap = wz_capture::pcap::write(1, &[(0, 0, &[0u8; 4])]);
        let json = health_run(&pcap, true, Format::Json);
        assert!(
            json.contains("\"health\":{\"capture_reported_drops\":null"),
            "silence must not be reported as a clean bill of health: {json}"
        );
        assert!(
            !json.contains("\"health\":{\"capture_reported_drops\":0"),
            "0 is a claim this format cannot support: {json}"
        );
        let text = health_run(&pcap, true, Format::Text);
        assert!(
            text.contains("not reported (this capture format has nowhere to say)"),
            "and the terminal rendering must not print a zero either: {text}"
        );
    }

    /// R311y895 — the help's LINK TYPES block IS `wz-capture`'s readable set.
    ///
    /// Open-debt item 385: nothing in this tool said what it could read, so the
    /// only way to find out was to run it — and the answer for a capture it
    /// cannot read (`messages decoded: 0`) is the same sentence as "there was
    /// no zenoh traffic here", which R311y893 paid for. The block above is that
    /// answer, and this is what stops it going the way of the `SIX link types`
    /// comment it replaces.
    ///
    /// Pinned against the RENDERER rather than a second copy of the list, and
    /// pinned in BOTH directions: every code the dispatch reads must appear,
    /// and a code in the help that the dispatch does not read must not. The
    /// sweep in `wz-capture` already binds that renderer to the dispatch, so
    /// the three surfaces are one fact.
    #[test]
    fn the_usage_names_every_link_type_this_build_reads_and_no_other() {
        let rendered = wz_capture::link::readable_link_types_line();
        assert!(
            USAGE.contains("LINK TYPES READ:"),
            "the help must have the section at all"
        );
        for entry in rendered.split(", ") {
            assert!(
                USAGE.contains(entry),
                "the dispatch reads {entry} and the help does not say so"
            );
        }
        // The other direction: a `<code> <NAME>` pair in the block that the
        // dispatch does not read. Scanned off the block itself so a stale row
        // left behind by a removed arm cannot survive here.
        // R2055 (item 392) — sliced between the two HEADINGS now, not between
        // the section and its prose. The block grew a second list, and a slice
        // that ran to the first paragraph would have swallowed it and read its
        // sentences as `<code> <NAME>` rows.
        let block = USAGE
            .split("DECAPSULATED -- the link header is stripped and what is under it decoded:")
            .nth(1)
            .expect("the decapsulated heading")
            .split("\n    DECLARED")
            .next()
            .expect("the list, before the second heading");
        for entry in block.split(',') {
            let entry = entry.trim().trim_end_matches('\n').trim();
            if entry.is_empty() {
                continue;
            }
            assert!(
                rendered.contains(entry),
                "the help claims {entry} and the dispatch does not read it"
            );
        }
    }

    /// R2055 (open-debt item 392) — the help's SECOND list, bound to the
    /// parser rather than to its own prose.
    ///
    /// # The gap
    ///
    /// `--serial <linktype>` reads a link type the sweep counts as UNREADABLE,
    /// which is correct: nothing is decapsulated, the declared bytes ARE the
    /// serial stream. So the help said, four lines apart, "any other link type
    /// is opened and counted, and none of it is decoded" and "`--serial`
    /// declares one of the OTHER types". Two meanings of "read", and only prose
    /// between them — a person holding an `RTAC_SERIAL` capture stands exactly
    /// there.
    ///
    /// The block is now two lists, DECAPSULATED and DECLARED, and this test is
    /// what stops the second one going the way of the first. The claim it holds
    /// down is the word ANY: the parser must accept a link type from BOTH
    /// classes, one already on the decapsulated list and one that is not. If
    /// `--serial` is ever narrowed to refuse the first class, this reds and the
    /// help has to change in the same commit.
    ///
    /// ⚠ It does NOT re-prove what happens after acceptance. That is
    /// `wz_capture::serial`'s
    /// `declaring_a_readable_link_type_as_serial_takes_its_decapsulation_away`,
    /// which drives a real Ethernet capture both ways and shows the declaration
    /// takes the decode away. Splitting them keeps each one's failure legible:
    /// this one is about the command line, that one is about the dispatch.
    #[test]
    fn the_usage_names_a_second_list_and_the_parser_accepts_both_its_classes() {
        assert!(
            USAGE.contains("DECAPSULATED -- the link header is stripped"),
            "the help must name the first list as its own list"
        );
        assert!(
            USAGE.contains("DECLARED -- ANY link type at all"),
            "and the second, which is the distinction item 392 is about"
        );
        assert!(
            USAGE.contains("A DECLARATION WINS over the list above"),
            "and it must say which one wins where they overlap"
        );

        // ONE FROM EACH CLASS. `LINKTYPE_ETHERNET` is on the decapsulated list;
        // 250 (`LINKTYPE_RTAC_SERIAL`) is not, and is the type the flag exists
        // for. Taken from the dispatch's own table rather than typed, so a
        // build that stopped decapsulating Ethernet could not leave this test
        // quietly asserting about one class twice.
        let readable: Vec<u32> = wz_capture::link::READABLE_LINK_TYPES
            .iter()
            .map(|(code, _)| *code)
            .collect();
        let on_the_first_list = wz_capture::link::LINKTYPE_ETHERNET;
        let rtac_serial = 250u32;
        assert!(readable.contains(&on_the_first_list));
        assert!(
            !readable.contains(&rtac_serial),
            "250 must be OFF the first list, or the two classes are one"
        );

        let opts = parse(&args(&[
            "--serial",
            &on_the_first_list.to_string(),
            "--serial",
            &rtac_serial.to_string(),
            "capture.pcap",
        ]))
        .expect("both classes are accepted");
        assert_eq!(
            opts.serial_linktypes,
            vec![on_the_first_list, rtac_serial],
            "the help says ANY link type; the parser has to mean it"
        );
    }

    /// Round 2033 (item 303) — THE HELP'S PAYLOAD VOCABULARIES, pinned in both
    /// directions against the walks that ship them.
    ///
    /// # What was actually wrong, measured rather than inherited
    ///
    /// The item says the encoding prose exists in three places and only the
    /// header is asserted. That was true when it was filed; item 281 has since
    /// gated the rustdoc, so the help was the last one — and it had gone wrong
    /// in TWO independent ways while nothing read it.
    ///
    /// `Formats: json, protobuf` omitted `cbor`, which this build ships and
    /// the command line accepts. A person reading `--help` was told a format
    /// they could use did not exist, and the word `cbor` appeared nowhere in
    /// the whole document.
    ///
    /// `Either finding is also TOTALLED per topic` counted TWO, and Round 2031
    /// made it three. That is the exact staleness the item describes — a
    /// sentence that was true, was edited to stay true once, and had nothing
    /// holding it the next time the code moved.
    ///
    /// # Why lists rather than the prose
    ///
    /// A gate over prose would have to pick sentences, and a sentence is the
    /// part of a help page an author is entitled to rewrite. The lists are the
    /// part that is a CONTRACT: the formats the parser accepts, and the words
    /// a `--json` run puts in `wrong` and `under`. Those have shipping walks,
    /// so they are pinned to them and the sentences stay free.
    ///
    /// # Both directions, and off the LIST rather than the document
    ///
    /// Item 281's lesson, from the round that measured it: a first draft that
    /// asked whether the WHOLE document contains a word passes on the word
    /// appearing in unrelated prose. Each block is sliced out by its own
    /// heading and the slice is asserted to have been found, so an anchor that
    /// stops matching fails here rather than silently widening the search.
    #[test]
    fn the_usage_names_every_payload_format_and_finding_word_and_no_other() {
        let block = |heading: &str| {
            let after = USAGE
                .split(heading)
                .nth(1)
                .unwrap_or_else(|| panic!("the help must carry `{heading}`"));
            // R2114 (open-debt item 237) — the FIRST NON-EMPTY line, not the
            // first. An inline heading (`PAYLOAD FORMATS: cbor, ...`) leaves
            // its list on the remainder of the heading's own line; a SECTION
            // heading leaves an empty remainder and puts the list on the line
            // below. One helper reads both, so the fourth population did not
            // need a second reader that could disagree with this one.
            let line = after
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or_else(|| panic!("`{heading}` must be followed by its list"));
            line.split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .collect::<Vec<_>>()
        };
        // Each pair is (heading, the SHIPPING population it must equal).
        let formats: Vec<&str> = wz_capture::payload::formats::BUILTIN_NAMES.to_vec();
        let misbound = wz_capture::payload_decode::Misbound::names();
        let refused = wz_capture::payload_decode::RefusedUnder::names();
        // R2114 (open-debt item 237) — the DESCRIBED-format field types, held
        // to the same rule. The help lists them for a deployment that has to
        // write a layout, and a hand-kept list is exactly what this test class
        // exists to stop.
        let field_types: Vec<&str> = wz_capture::payload::formats::TYPES
            .iter()
            .map(|(name, _)| *name)
            .collect();
        for (heading, shipped) in [
            ("PAYLOAD FORMATS: ", &formats),
            ("PAYLOAD MISBOUND: ", &misbound),
            ("PAYLOAD REFUSED UNDER: ", &refused),
            ("PAYLOAD FIELD TYPES:", &field_types),
        ] {
            let listed = block(heading);
            // ANTI-VACUITY: an empty population makes both directions true.
            assert!(!shipped.is_empty(), "a gate over nothing is green");
            for word in shipped.iter() {
                assert!(
                    listed.contains(word),
                    "this build ships `{word}` and `{heading}` does not say so: \
                     {listed:?}"
                );
            }
            for word in &listed {
                assert!(
                    shipped.contains(word),
                    "`{heading}` claims `{word}` and this build does not ship \
                     it: {shipped:?}"
                );
            }
        }
    }

    /// R311y898, open-debt item 398 — the `LINK TYPES READ:` counterpart one
    /// level in: which extension BODIES this build opens.
    ///
    /// The same failure it defends against, and it is not an analogy: an
    /// extension nobody walks renders as `value`, which on the report is
    /// indistinguishable from a body that genuinely held nothing structured.
    /// The reader could ask which pcap link types this build decodes and could
    /// NOT ask which extension bodies it reads, because both dispatch tables
    /// are private to `wz-session-core::dissect`.
    ///
    /// Pinned against the RENDERER, in BOTH directions, for both encodings
    /// that have walkers — never against a second copy of the list. The
    /// renderer is driven by the dispatch itself
    /// (`dissect::readable_ext_bodies_line`, whose own test holds it to
    /// `zbuf_body_walker` / `z64_body_walker`), so help text, renderer and
    /// dispatch are one fact and a body that gains a reading appears in all
    /// three on one commit.
    #[test]
    fn the_usage_names_every_ext_body_this_build_reads_and_no_other() {
        assert!(
            USAGE.contains("EXT BODIES READ:"),
            "the help must have the section at all"
        );
        let mut readable: Vec<String> = Vec::new();
        for enc in [
            wz_session_core::ext_header::EXT_ENC_ZBUF,
            wz_session_core::ext_header::EXT_ENC_Z64,
        ] {
            let line = wz_session_core::dissect::readable_ext_bodies_line(enc);
            assert!(
                !line.is_empty(),
                "the dispatch reads nothing at encoding {enc:#x}, so this test \
                 asserts nothing",
            );
            for entry in line.split(", ") {
                assert!(
                    USAGE.contains(entry),
                    "the dissector reads {entry} and the help does not say so"
                );
                readable.push(entry.to_string());
            }
        }
        // The other direction: a `<Carrier>/<name>` row in the block that the
        // dispatch does NOT read. Scanned off the block itself so a row left
        // behind by a removed walker cannot survive here — the drift the
        // `SIX link types` comment R311y895 deleted had lived for months.
        let block = USAGE
            .split("EXT BODIES READ:")
            .nth(1)
            .expect("the section")
            .split("\n    An extension body")
            .next()
            .expect("the rows, before their prose");
        let mut claimed = 0usize;
        for token in block.split([',', ' ', '\n']) {
            let token = token.trim();
            if !token.contains('/') {
                continue;
            }
            claimed += 1;
            assert!(
                readable.iter().any(|r| r == token),
                "the help claims {token} and the dispatch does not read it"
            );
        }
        assert_eq!(
            claimed,
            readable.len(),
            "every read row must be claimed exactly once: the help lists \
             {claimed} and the dispatch reads {}",
            readable.len(),
        );
    }

    /// R311y857 — the flag is in the USAGE, which is what the parity gate reads.
    ///
    /// Its own assertion because the gate reads a CONSTANT: a flag the parser
    /// accepts and the usage text does not name is reachable and undiscoverable,
    /// and the gate would report the capability as ABI-only while it is not.
    #[test]
    fn the_health_flag_is_parsed_and_documented() {
        assert!(
            parse(&args(&["cap.pcapng", "--health"]))
                .expect("a capture and a flag")
                .health,
            "the parser must accept it"
        );
        assert!(
            !parse(&args(&["cap.pcapng"]))
                .expect("a capture alone")
                .health,
            "and it must be off by default"
        );
        assert!(
            USAGE.contains("    --health"),
            "the usage text names every flag this tool takes"
        );
    }

    /// R311y869 — the interest flag is parsed AND documented, on the rule the
    /// health flag's twin states: the parity gate reads the USAGE constant, so
    /// a flag the parser takes and the usage text does not name would be
    /// reported as ABI-only while it is not.
    #[test]
    fn the_interest_flag_is_parsed_and_documented() {
        assert!(
            parse(&args(&["cap.pcapng", "--interests"]))
                .expect("a capture and a flag")
                .census
                .interests,
            "the parser must accept it"
        );
        assert!(
            !parse(&args(&["cap.pcapng"]))
                .expect("a capture alone")
                .census
                .interests,
            "and it must be off by default"
        );
        assert!(
            !parse(&args(&["cap.pcapng", "--census"]))
                .expect("every record plane")
                .census
                .interests,
            "--census is the RECORD planes; this one folds the control plane"
        );
        assert!(
            USAGE.contains("    --interests"),
            "the usage text names every flag this tool takes"
        );
    }

    /// The same datagram builder as [`udp_to_zenoh_port`], the other way round,
    /// so a fixture can put the DECLARER on one side and the PUBLISHER on the
    /// other.
    ///
    /// Its own function rather than a parameter: a capture in which both roles
    /// sit on one side would let a plane that ignores `Direction` pass, and
    /// this plane's whole first assertion is about which side declared.
    fn udp_from_zenoh_port(payload: &[u8]) -> Vec<u8> {
        udp_from_publisher(2, payload)
    }

    /// Round 2034 (item 304) — the same datagram from a NAMED publisher, so a
    /// fixture can put more than one of them on one topic.
    ///
    /// A second host rather than a second port: two publishers on a keyexpr is
    /// the ordinary pub/sub shape, and the flow key a reader sees is the
    /// address pair. `host` is the last octet of the sender's address.
    fn udp_from_publisher(host: u8, payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&50000u16.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(payload);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, host]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// A transport `Frame` carrying one network record, as
    /// `wz-capture`'s own datagram fixtures build one.
    fn frame_carrying(record: &[u8]) -> Vec<u8> {
        let mut w = vec![wz_session_core::wire_const::T_MID_FRAME, 0x00];
        w.extend_from_slice(record);
        w
    }

    /// One `Put` on `key` that DECLARES `encoding_id`, in zenoh's own wire
    /// shape.
    ///
    /// R311y875 — the E flag (0x40) is set by hand because `walk_msg_put` reads
    /// an `encoding` group only when it is, so a struct field alone would encode
    /// nothing and every assertion below would pass on a build that never
    /// looked. The wire word is `(id << 1) | has_schema`.
    fn put_declaring(key: &str, encoding_id: u32, payload: &[u8]) -> Vec<u8> {
        wz_codecs::push::Push {
            header: wz_codecs::push::Push::default().header | wz_session_core::wire_const::FLAG_N_N,
            keyexpr: wz_codecs::wireexpr::Wireexpr {
                body: wz_codecs::wireexpr::WireexprVariant::WireexprLocal(
                    wz_codecs::wireexpr_local::WireexprLocal {
                        id: 0,
                        suffix_len: Some(key.len() as u64),
                        suffix: Some(key),
                    },
                ),
            },
            body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                header: wz_codecs::msg_put::MsgPut::default().header | 0x40,
                encoding: Some(wz_codecs::encoding::Encoding {
                    packed_id: encoding_id << 1,
                    schema_len: None,
                    schema: None,
                }),
                payload_len: payload.len() as u64,
                payload,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// R311y875 — THE TWO ENCODING FINDINGS, AND THEIR TALLY, THROUGH THE
    /// TERMINAL A PERSON ACTUALLY READS.
    ///
    /// # The gap this closes
    ///
    /// R311y873 added `EncodingMismatch`'s line and R311y874 added the override
    /// line beside it, and BOTH were proved only by the state's rendering — no
    /// fixture in this tree drove either through `wz-analyze`'s output, because
    /// the round that could have added one built its capture on the C ABI side.
    /// Measured rather than recalled: before this test every `payload_rules` in
    /// this file was `&[]`, so the command line's whole payload-format path had
    /// no capture behind it at all.
    ///
    /// # Why one fixture proves three things
    ///
    /// One rule (`demo/**=protobuf`) and one declaration (`application/json`,
    /// id 5) over bytes that differ: `demo/a` carries two samples that refute
    /// the label and `demo/b` one that bears it out. That is the same pair
    /// R311y874 settled on the ABI side, so the two surfaces are now shown to
    /// agree; the sample counts differ (2 against 1) so the tally cannot pass by
    /// hard-coding either number; and the two topics are separate rows because
    /// the plane is keyed on the TOPIC, which is the coordinate a reader has to
    /// go and fix a publisher at.
    /// R311y909 — A JSON PAYLOAD IS OPENED AT THE TERMINAL, which is the whole
    /// of what this round is for.
    ///
    /// # What was measurably absent
    ///
    /// `wz_capture::payload`'s opening line is that "a capture of a fleet
    /// publishing JSON was, to this tool, a capture of some bytes". That plane
    /// closed half of it — a payload declaring `application/json` gets a
    /// verdict — and the FIELD layer kept the other half open for the whole
    /// track, because `payload_builtin::BUILTIN_NAMES` held exactly one entry
    /// and it was `protobuf`. The test below this one is the proof: every
    /// witness for the encodings check was a `protobuf` rule losing to a JSON
    /// label, and the reason it could only ever be phrased that way is that the
    /// format on the other side of the collision did not exist.
    ///
    /// # Why the terminal and not the decoder
    ///
    /// The decoder's own tests are in `wz-capture`. This one is here for the
    /// reason the test below it was: a state that renders correctly proves the
    /// renderer, and it took a capture driven through `analyze_request` to
    /// prove that the path from a `--payload-format` argument to a printed row
    /// is joined. `--payload-name` rides along, because the JSON case is the
    /// one where the wire already names the field and a rename must therefore
    /// still be a rename rather than the only source.
    #[test]
    fn a_json_publishers_payload_is_opened_into_named_rows_at_the_terminal() {
        const JSON: u32 = 5;
        const BODY: &[u8] = br#"{"temp":21.5}"#;
        let packets = [udp_from_zenoh_port(&frame_carrying(&put_declaring(
            "demo/a", JSON, BODY,
        )))];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .map(|p| (0u32, 1_000_000u64, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        let rules = [String::from("demo/**=json")];
        let names = [String::from("demo/**:$.temp=celsius")];

        let text = analyze_request(&Request {
            capture: &capture,
            keylog: None,
            format: Format::Text,
            per_flow: true,
            per_message: true,
            messages_per_flow: None,
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &rules,
            payload_field_names: &names,
            serial_linktypes: &[],
            census: Census::default(),
            per_field: true,
            bounded: false,
            health: false,
            select: None,
            csv: None,
        })
        .expect("the capture reads")
        .0;

        // ANTI-VACUITY: the sample really decoded, so a listing that reported
        // nothing cannot pass by having been handed nothing.
        assert!(
            text.contains("messages decoded: 1"),
            "the fixture must decode: {text}"
        );
        assert!(
            text.contains("payload `demo/a` as json:"),
            "the rule must be INSTALLED and applied under its own name: {text}"
        );
        assert!(
            text.contains("$ = object 1 member(s)"),
            "the document's own row must be there, so a reader sees the shape \
             before the leaves: {text}"
        );
        // The leaf, its declared rename, and its value -- one line, and the
        // path is the wire's own member name rather than an invented number.
        assert!(
            text.contains("$.temp (celsius) = number 21.5"),
            "the wire's name is the path and the declaration renames it: {text}"
        );
        // And nothing on this capture reads as a mapping quarrel: the publisher
        // said JSON, the rule says JSON, so no override or veto line may appear.
        assert!(
            !text.contains("NOT DECODED") && !text.contains("applied anyway"),
            "the label and the rule agree, so there is no finding to print: \
             {text}"
        );
    }

    /// R311y914 (open-debt items 433, 434) — A CBOR PUBLISHER'S PAYLOAD IS
    /// OPENED AT THE TERMINAL, non-text map keys included.
    ///
    /// # What was measurably absent
    ///
    /// `application/cbor` is entry 8 of the wire table and the field layer had
    /// no decoder for it — the same silence `application/json` was in before
    /// R311y909 and one step worse, because `shape_of` called it `Binary`, so
    /// `inspect` answered `Opaque`, so a cbor label could not be REFUTED, so
    /// `judge_claim` vetoed every rule pointed at a cbor topic. The reader could
    /// not open the bytes and could not be told why.
    ///
    /// # Why the terminal and not the decoder
    ///
    /// The decoder's own tests are in `wz-capture`. This one is here for the
    /// reason the JSON one above it is: what it gates is that the path from a
    /// `--payload-format` argument to a printed row is JOINED, which no unit
    /// test of the walk can show.
    ///
    /// The fixture carries an integer map key deliberately. `--payload-name`
    /// matches a path by string equality, so item 434's collision — the integer
    /// key `5` and a text key `"5"` sharing `$.5` — is a rename landing on the
    /// wrong field, and it is only visible where a rename is actually applied.
    #[test]
    fn a_cbor_publishers_payload_is_opened_into_named_rows_at_the_terminal() {
        const CBOR: u32 = 8;
        // {"t": 21, 5: "a"} -- a text key, then the integer key item 434 is
        // about, so the listing shows both segment rules in one document.
        const BODY: &[u8] = &[0xa2, 0x61, 0x74, 0x15, 0x05, 0x61, 0x61];
        let packets = [udp_from_zenoh_port(&frame_carrying(&put_declaring(
            "demo/a", CBOR, BODY,
        )))];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .map(|p| (0u32, 1_000_000u64, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        let rules = [String::from("demo/**=cbor")];
        let names = [String::from("demo/**:$.t=celsius")];

        let text = analyze_request(&Request {
            capture: &capture,
            keylog: None,
            format: Format::Text,
            per_flow: true,
            per_message: true,
            messages_per_flow: None,
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &rules,
            payload_field_names: &names,
            serial_linktypes: &[],
            census: Census::default(),
            per_field: true,
            bounded: false,
            health: false,
            select: None,
            csv: None,
        })
        .expect("the capture reads")
        .0;

        // ANTI-VACUITY: the sample really decoded, so a listing that reported
        // nothing cannot pass by having been handed nothing.
        assert!(
            text.contains("messages decoded: 1"),
            "the fixture must decode: {text}"
        );
        assert!(
            text.contains("payload `demo/a` as cbor:"),
            "the rule must be INSTALLED and applied under its own name: {text}"
        );
        assert!(
            text.contains("$ = map 2 pair(s)"),
            "the document's own row must be there, so a reader sees the shape \
             before the leaves: {text}"
        );
        assert!(
            text.contains("$.t (celsius) = unsigned 21"),
            "the wire's name is the path and the declaration renames it: {text}"
        );
        // ITEM 434, AT THE SURFACE: the integer key is not `$.5`, so a rename
        // written for a text key `\"5\"` cannot land on it.
        assert!(
            text.contains("$.\\i5 = text \"a\""),
            "an integer map key must reach the terminal in the reserved \
             namespace: {text}"
        );
        // And nothing here reads as a mapping quarrel: the publisher said cbor,
        // the rule says cbor, so no override or veto line may appear. This is
        // the assertion that would have been unwritable before this round --
        // the rule could not be applied at all.
        assert!(
            !text.contains("NOT DECODED") && !text.contains("applied anyway"),
            "the label and the rule agree, so there is no finding to print: \
             {text}"
        );
    }

    /// R2114 (open-debt item 237) — A DEPLOYMENT'S OWN FORMAT, DESCRIBED IN
    /// TEXT, DECODING A CAPTURE THROUGH THE COMMAND LINE.
    ///
    /// # What it proves that nothing else did
    ///
    /// Two things at once, because one fixture reaches both and neither had a
    /// witness on this surface.
    ///
    /// The first is the item: this build ships three decoders and knows nothing
    /// about the record below. It decodes because a LINE said what the record
    /// is. No code crossed a boundary and no callback ran, which is the whole
    /// argument for closing the item this way rather than with a function
    /// pointer the ABI's memory rule forbids.
    ///
    /// The second is a divergence found while closing it. The topic carries a
    /// COLON, so the rule's pattern is quoted -- and until this round the
    /// command line handed `FormatMap::insert` the halves `parse_declaration`
    /// returns, which are the QUOTED spelling. The backslash went into the
    /// pattern, the pattern matched no topic, and the rule silently decoded
    /// nothing. The C ABI never had the bug because it goes through
    /// `FormatMap::declare`, which unquotes; this surface now goes through the
    /// same door. Item 462 made this pattern expressible and only one of the
    /// two surfaces could express it.
    #[test]
    fn a_described_format_decodes_a_topic_whose_name_needs_quoting() {
        // A profile record this tree has never seen: a big-endian counter, a
        // flag byte, and a tail. 0x012c is 300.
        const RECORD: &[u8] = &[0x01, 0x2c, 0x07, 0xde, 0xad];
        const BYTES: u32 = 0;
        let packets = [udp_from_zenoh_port(&frame_carrying(&put_declaring(
            "demo/temp:c",
            BYTES,
            RECORD,
        )))];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .map(|p| (0u32, 1_000_000u64, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        // The DEFINITION is written after the rule that uses it, on purpose:
        // both surfaces resolve names before rules, and a config file whose
        // definition sits at the bottom must work here too.
        let rules = [
            String::from("demo/temp\\:c=profile"),
            String::from("#profile=counter:u16be,flags:u8,tail:rest"),
        ];
        let text = analyze_request(&Request {
            capture: &capture,
            keylog: None,
            format: Format::Text,
            per_flow: true,
            per_message: true,
            messages_per_flow: None,
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &rules,
            payload_field_names: &[],
            serial_linktypes: &[],
            census: Census::default(),
            per_field: true,
            bounded: false,
            health: false,
            select: None,
            csv: None,
        })
        .expect("the capture reads")
        .0;
        // ANTI-VACUITY: the message really decoded, so an empty listing cannot
        // pass this by having been handed nothing.
        assert!(
            text.contains("messages decoded: 1"),
            "the fixture must decode: {text}"
        );
        // The declared field names are the PATHS, and the values are read from
        // the layout's own endianness rather than the host's.
        assert!(
            text.contains("counter"),
            "the described field is named: {text}"
        );
        assert!(
            text.contains("300"),
            "0x012c is 300 read big-endian, and 11265 read the other way: {text}"
        );
        assert!(text.contains("dead"), "the tail is accounted for: {text}");
        // And NOTHING is reported unbound -- neither the rule nor the
        // definition. The rule's half is the quoting: a pattern that reached
        // the map still quoted matches no topic and is reported unbound. The
        // definition's half is a second ledger the first run of this test
        // caught: a described format whose rule fired was still being reported
        // as "installed and BOUND NOTHING", beside the fields it had just
        // produced, because only the rule's handle was being marked.
        assert!(
            !text.contains("BOUND NOTHING"),
            "the quoted pattern must reach the map unquoted, and a definition \
             whose rule fired has been used: {text}"
        );
    }

    #[test]
    fn the_encoding_findings_and_their_tally_reach_the_terminal() {
        const JSON: u32 = 5;
        // Valid protobuf (field 1, varint 150) under a `application/json`
        // label: the publisher's own bytes refute it, so the rule wins.
        const REFUTES: &[u8] = &[0x08, 0x96, 0x01];
        // Actual JSON under the same label: the label holds and the rule loses.
        const BEARS_OUT: &[u8] = br#"{"a":1}"#;
        let packets = [
            udp_from_zenoh_port(&frame_carrying(&put_declaring("demo/a", JSON, REFUTES))),
            udp_from_zenoh_port(&frame_carrying(&put_declaring("demo/b", JSON, BEARS_OUT))),
            udp_from_zenoh_port(&frame_carrying(&put_declaring("demo/a", JSON, REFUTES))),
        ];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        let rules = [String::from("demo/**=protobuf")];

        let run = |format: Format| {
            analyze_request(&Request {
                capture: &capture,
                keylog: None,
                format,
                per_flow: true,
                per_message: true,
                messages_per_flow: None,
                quic_ports: &[],
                quic_cid_len: None,
                payload_rules: &rules,
                payload_field_names: &[],
                serial_linktypes: &[],
                census: Census::default(),
                per_field: true,
                bounded: false,
                health: false,
                select: None,
                csv: None,
            })
            .expect("the capture reads")
            .0
        };

        let text = run(Format::Text);
        // ANTI-VACUITY: all three records really decoded, so a listing that
        // reported nothing cannot pass by having been handed nothing.
        assert!(
            text.contains("messages decoded: 3"),
            "the fixture must decode: {text}"
        );
        // R311y873's LINE, from a capture for the first time. It names the flag,
        // which is the whole reason this state is not `Refused`.
        assert!(
            text.contains(
                "payload `demo/b`: NOT DECODED -- the publisher declared \
                 application/json and the --payload-format rule says protobuf"
            ),
            "the publisher whose bytes bear its label out must send the reader \
             to the RULE: {text}"
        );
        // R311y874's LINE, likewise.
        assert!(
            text.contains(
                "payload `demo/a`: the publisher declared application/json and \
                 its own bytes contradict that, so the --payload-format rule \
                 was applied anyway"
            ),
            "the label its own bytes refute must not hide the data, and the \
             override must be said: {text}"
        );
        // R311y875's PLANE: the same two findings, counted, once per topic.
        //
        // R2062 (item 478) — and now per topic AND SENDER. The claim this leg
        // makes is unchanged: two mislabelled samples are ONE finding, not two.
        // What moved is that the finding names who to fix, which is the whole
        // point of that round — both samples here come from one publisher, so
        // the count is still 2 on one row.
        assert!(
            text.contains(
                "PUBLISHER MISLABELLING -- 2 sample(s) on `demo/a` at \
                 `10.0.0.2:7447` declare `application/json`"
            ),
            "the two mislabelled samples on one topic must be counted ONCE, as \
             a finding about the deployment, and must name the publisher they \
             tell the reader to fix: {text}"
        );
        assert!(
            text.contains("Fix the publisher at `10.0.0.2:7447`"),
            "and the instruction itself must carry that name, which is what a \
             reader acts on: {text}"
        );
        assert!(
            text.contains("MAPPING WRONG -- 1 sample(s) on `demo/b` declare `application/json`"),
            "and the topic whose label holds must be counted separately, \
             against the rule: {text}"
        );

        // And the same plane in the JSON a program reads, through
        // `wz-capture`'s own emitter -- so the two documents cannot disagree
        // about the shape of one finding.
        let json = run(Format::Json);
        assert!(
            json.contains(
                "\"payload_mapping\":[{\"keyexpr\":\"demo/a\",\"format\":\"protobuf\",\
                 \"declared\":\"application/json\",\"wrong\":\"publisher\",\"samples\":2,"
            ),
            "the JSON arm carries the plane too, most samples first: {json}"
        );
        assert!(
            json.contains(
                "{\"keyexpr\":\"demo/b\",\"format\":\"protobuf\",\
                 \"declared\":\"application/json\",\"wrong\":\"rule\",\"samples\":1,"
            ),
            "and both verdicts: {json}"
        );
    }

    /// Round 2034 (item 304) — TWO VERDICTS ON ONE TOPIC IS A DEPLOYMENT, not
    /// a fixture's convenience, and that is what makes the ordering worth
    /// having.
    ///
    /// # The question this answers
    ///
    /// Every earlier witness for the tally put both verdicts on one topic by
    /// having ONE publisher alternate good and bad bytes, because proving the
    /// key needs two rows that differ in `wrong` alone. Item 304's objection is
    /// that nobody had shown a real deployment doing it, and if it never
    /// happens then "most samples first" is sorting a list that is always one
    /// row long per topic.
    ///
    /// It happens, and the reason is structural rather than lucky: a keyexpr is
    /// a TOPIC and several publishers may hold one, which is the ordinary
    /// pub/sub shape rather than an edge case. This fixture is two hosts on
    /// `demo/a` -- one whose label its bytes bear out, so the rule is what is
    /// wrong, and one whose label its bytes refute, so the publisher is. Two
    /// verdicts, one topic, and neither publisher had to change its mind.
    ///
    /// # And the counts differ, so the order is a claim
    ///
    /// Three samples from the mislabelling host and one from the other, so the
    /// larger finding must come first and cannot pass by being tied. A reader
    /// with one broken publisher among many needs it at the top.
    ///
    /// ⚠ WHAT THIS ROUND DID NOT FIX, and filed instead: neither row names the
    /// publisher. `PUBLISHER MISLABELLING` tells a reader to go fix a publisher
    /// and this capture has two of them on that topic. Nothing here can tell
    /// them which.
    #[test]
    fn two_publishers_on_one_topic_are_two_findings_and_the_bigger_is_first() {
        const JSON: u32 = 5;
        // Its own label borne out: the rule loses, nothing is decoded.
        const BEARS_OUT: &[u8] = br#"{"a":1}"#;
        // Its own label refuted: the rule wins over the label.
        const REFUTES: &[u8] = &[0x08, 0x96, 0x01];
        let packets = [
            udp_from_publisher(
                2,
                &frame_carrying(&put_declaring("demo/a", JSON, BEARS_OUT)),
            ),
            udp_from_publisher(3, &frame_carrying(&put_declaring("demo/a", JSON, REFUTES))),
            udp_from_publisher(3, &frame_carrying(&put_declaring("demo/a", JSON, REFUTES))),
            udp_from_publisher(3, &frame_carrying(&put_declaring("demo/a", JSON, REFUTES))),
        ];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        let rules = [String::from("demo/**=protobuf")];

        let text = analyze_request(&Request {
            capture: &capture,
            keylog: None,
            format: Format::Text,
            per_flow: true,
            per_message: true,
            messages_per_flow: None,
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &rules,
            payload_field_names: &[],
            serial_linktypes: &[],
            census: Census::default(),
            per_field: true,
            bounded: false,
            health: false,
            select: None,
            csv: None,
        })
        .expect("the capture reads")
        .0;

        // ANTI-VACUITY: all four records decoded, and they really came from
        // two different senders -- otherwise this is the old one-publisher
        // fixture wearing a new name.
        assert!(
            text.contains("messages decoded: 4"),
            "the fixture must decode: {text}"
        );
        assert!(
            text.contains("10.0.0.2") && text.contains("10.0.0.3"),
            "two publishers must actually be in this capture: {text}"
        );
        // TWO VERDICTS ON ONE TOPIC, from a shape nobody had to contrive.
        let mislabelling = text
            .find("PUBLISHER MISLABELLING -- 3 sample(s) on `demo/a`")
            .unwrap_or_else(|| panic!("the mislabelling host must be a finding: {text}"));
        let mapping = text
            .find("MAPPING WRONG -- 1 sample(s) on `demo/a`")
            .unwrap_or_else(|| panic!("and the honest host a different one: {text}"));
        // AND THE ORDER IS THE CLAIM: most samples first, so the reader meets
        // the three-sample finding before the one-sample one.
        assert!(
            mislabelling < mapping,
            "the larger finding must come first -- that ordering is what item \
             304 asked whether anything real depends on: {text}"
        );
    }

    /// Round 2031 (item 300) — THE THIRD FINDING FROM THE COMMAND LINE, on
    /// both surfaces.
    ///
    /// # The door this exists for
    ///
    /// The tally is proved in `wz-capture`'s own tests. What is proved HERE is
    /// that both renderings reach a reader: the text loop in `render_listings`
    /// and the JSON array in `push_misbindings`. Those are two doors, and this
    /// session has now paid four times for a witness written against whichever
    /// door the fixture already had — so each is asserted, and removing either
    /// alone reds this test.
    ///
    /// # Why two topics
    ///
    /// The finding's whole value is telling the arms apart. `demo/a`'s
    /// publisher declares JSON and ships bytes that are not JSON, so the rule
    /// and the label AGREE and the capture is what to look at. `demo/b`
    /// declares nothing, so the rule is the only claim there is. One row each,
    /// and the sentences send a reader to different places.
    #[test]
    fn a_rule_that_was_applied_and_refused_reaches_the_terminal_and_the_json() {
        const JSON: u32 = 5;
        const NOTHING: u32 = 0;
        // Truncated JSON: the scanner refuses it, and it is not protobuf or
        // anything else this build would decode by accident.
        const TRUNCATED: &[u8] = br#"{"a":"#;
        let packets = [
            udp_from_zenoh_port(&frame_carrying(&put_declaring("demo/a", JSON, TRUNCATED))),
            udp_from_zenoh_port(&frame_carrying(&put_declaring("demo/a", JSON, TRUNCATED))),
            udp_from_zenoh_port(&frame_carrying(&put_declaring(
                "demo/b", NOTHING, TRUNCATED,
            ))),
        ];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        let rules = [String::from("demo/**=json")];

        let run = |format: Format| {
            analyze_request(&Request {
                capture: &capture,
                keylog: None,
                format,
                per_flow: true,
                per_message: true,
                messages_per_flow: None,
                quic_ports: &[],
                quic_cid_len: None,
                payload_rules: &rules,
                payload_field_names: &[],
                serial_linktypes: &[],
                census: Census::default(),
                per_field: true,
                bounded: false,
                health: false,
                select: None,
                csv: None,
            })
            .expect("the capture reads")
            .0
        };

        let text = run(Format::Text);
        // ANTI-VACUITY: all three records decoded as MESSAGES, so it is the
        // payload decode that refused and not the walk that found nothing.
        assert!(
            text.contains("messages decoded: 3"),
            "the fixture must decode: {text}"
        );
        // THE CORROBORATED ARM: both claims agree, so the reader is sent to
        // their capture and NOT to their command line.
        assert!(
            text.contains("WIRE DISAGREES WITH BOTH -- 2 sample(s) on `demo/a`"),
            "two samples on one topic must be counted ONCE, as a finding: \
             {text}"
        );
        // THE UNCLAIMED ARM, told apart from it. A build that read
        // `zenoh/bytes` as corroboration would print the sentence above for
        // this topic too and send a reader to a capture over a rule that is
        // only a guess.
        assert!(
            text.contains("RULE REFUSED -- 1 sample(s) on `demo/b`"),
            "and the topic that declared nothing must be a different finding: \
             {text}"
        );
        // Neither is a MISBINDING: nothing here caught either side out, which
        // is why this is a third plane and not a third word in that one.
        assert!(
            !text.contains("MAPPING WRONG") && !text.contains("PUBLISHER MISLABELLING"),
            "no rule is misbound in this capture: {text}"
        );

        // And the same plane in the JSON a program reads, through
        // `wz-capture`'s own emitter, so the two documents cannot disagree
        // about the shape of one finding.
        let json = run(Format::Json);
        assert!(
            json.contains(
                "\"payload_refusals\":[{\"keyexpr\":\"demo/a\",\"format\":\"json\",\
                 \"under\":\"corroborated\",\"samples\":2,"
            ),
            "the JSON arm carries the plane too, most samples first: {json}"
        );
        assert!(
            json.contains(
                "{\"keyexpr\":\"demo/b\",\"format\":\"json\",\
                 \"under\":\"unclaimed\",\"samples\":1,"
            ),
            "and both claims: {json}"
        );
        assert!(
            json.contains("\"payload_mapping\":[]"),
            "with the misbinding array empty beside it, so a consumer can see \
             the two planes answer different questions: {json}"
        );
    }

    /// R311y869 (§1.1f) — THE PLANE FROM THE COMMAND LINE, both findings.
    ///
    /// The fixture is the deployment a reader opens a capture to understand: a
    /// subscriber on `demo/**` declared by one side, and the other side
    /// publishing two keys — one the subscriber covers and one nobody asked
    /// for. Before this round the analyzer decoded the declaration and had no
    /// output that mentioned it at all.
    ///
    /// EVERY declaration here is built by the PRODUCTION builder
    /// (`wz_session_core::declare_build`), so this asserts the plane reads what
    /// wz emits rather than what a fixture author believed the layout to be.
    #[test]
    fn a_declared_subscriber_and_the_traffic_nobody_asked_for_both_reach_the_cli() {
        let declare =
            wz_session_core::declare_build::build_declare_subscriber(1, 0, Some("demo/**"))
                .expect("the production builder")
                .try_as_borrowed()
                .expect("re-borrow")
                .encode_to_vec();
        let put = |key: &str, payload: &[u8]| {
            wz_codecs::push::Push {
                header: wz_codecs::push::Push::default().header
                    | wz_session_core::wire_const::FLAG_N_N,
                keyexpr: wz_codecs::wireexpr::Wireexpr {
                    body: wz_codecs::wireexpr::WireexprVariant::WireexprLocal(
                        wz_codecs::wireexpr_local::WireexprLocal {
                            id: 0,
                            suffix_len: Some(key.len() as u64),
                            suffix: Some(key),
                        },
                    ),
                },
                body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
                    payload_len: payload.len() as u64,
                    payload,
                    ..Default::default()
                }),
                ..Default::default()
            }
            .encode_to_vec()
        };
        let packets = [
            udp_to_zenoh_port(&frame_carrying(&declare)),
            udp_from_zenoh_port(&frame_carrying(&put("demo/temp", &[0u8; 16]))),
            udp_from_zenoh_port(&frame_carrying(&put("private/log", &[0u8; 8]))),
        ];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);

        let run = |format: Format| {
            analyze_request(&Request {
                capture: &capture,
                keylog: None,
                format,
                per_flow: false,
                per_message: false,
                messages_per_flow: None,
                quic_ports: &[],
                quic_cid_len: None,
                payload_rules: &[],
                payload_field_names: &[],
                serial_linktypes: &[],
                census: Census {
                    interests: true,
                    ..Census::default()
                },
                per_field: false,
                bounded: false,
                health: false,
                select: None,
                csv: None,
            })
            .expect("the capture reads")
            .0
        };

        let text = run(Format::Text);
        // ANTI-VACUITY: the fixture really decoded three records, so a plane
        // reporting nothing cannot pass by having been handed nothing.
        assert!(
            text.contains("messages decoded: 3"),
            "the fixture must decode: {text}"
        );
        assert!(
            text.contains("declared interest: 1 (subscriber 1, queryable 0, liveliness 0)"),
            "the declaration is SEEN: {text}"
        );
        // THE WILDCARD IS EVALUATED against the traffic: `demo/**` covers
        // `demo/temp`, which no prefix comparison would produce.
        assert!(
            text.contains("subscriber demo/** covers 1 key(s), 1 message(s), 16 byte(s)"),
            "and it covers the traffic it matches: {text}"
        );
        // THE MIRROR FINDING, and it is stated as exact because every
        // declaration here was judged.
        assert!(
            text.contains("1 keyexpr(s) carried traffic no declaration here matches"),
            "and names the traffic nobody asked for: {text}"
        );
        assert!(
            !text.contains("AT MOST"),
            "every declaration was judged, so the count is not a floor: {text}"
        );

        let json = run(Format::Json);
        assert!(
            json.contains(
                "\"kind\":\"subscriber\",\"declarer\":\"a\",\"declarer_zid\":null,\
                           \"id\":1,\
                           \"keyexpr\":\"demo/**\",\"open\":true,\"covers\":1"
            ),
            "the export carries the same row: {json}"
        );
        assert!(
            json.contains("\"unclaimed\":1,\"unclaimed_exact\":true"),
            "and the same verdict: {json}"
        );
    }

    /// R311y870 — THE EXCHANGE FROM THE COMMAND LINE: a question that was
    /// answered and closed, beside one that was not answered at all.
    ///
    /// Both in ONE capture on purpose. The two findings are told apart by
    /// nothing but the answers, so a fixture holding only the unanswered one
    /// would be satisfied by a reader that called every interest unanswered.
    #[test]
    fn an_answered_interest_and_an_unanswered_one_are_told_apart_by_the_cli() {
        let interest = |id: u64, ke: &str| {
            frame_carrying(
                &wz_session_core::interest_build::build_interest_subscribers(
                    id,
                    true,
                    false,
                    0,
                    Some(ke),
                )
                .expect("the production interest builder")
                .try_as_borrowed()
                .expect("re-borrow")
                .encode_to_vec(),
            )
        };
        let reply = |id: u64, ke: &str| {
            frame_carrying(
                &wz_session_core::declare_build::build_declare_subscriber_reply(id, ke)
                    .expect("the production reply builder")
                    .try_as_borrowed()
                    .expect("re-borrow")
                    .encode_to_vec(),
            )
        };
        let closed = |id: u64| {
            frame_carrying(
                &wz_session_core::declare_build::build_declare_final_reply(id)
                    .try_as_borrowed()
                    .expect("re-borrow")
                    .encode_to_vec(),
            )
        };
        let packets = [
            udp_to_zenoh_port(&interest(1, "demo/**")),
            udp_from_zenoh_port(&reply(1, "demo/temp")),
            udp_from_zenoh_port(&closed(1)),
            udp_to_zenoh_port(&interest(2, "absent/**")),
        ];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);

        let rendered = analyze_request(&Request {
            capture: &capture,
            keylog: None,
            format: Format::Text,
            per_flow: false,
            per_message: false,
            messages_per_flow: None,
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &[],
            payload_field_names: &[],
            serial_linktypes: &[],
            census: Census {
                interests: true,
                ..Census::default()
            },
            per_field: false,
            bounded: false,
            health: false,
            select: None,
            csv: None,
        })
        .expect("the capture reads")
        .0;

        // ANTI-VACUITY: four records really decoded, so a reader reporting
        // nothing cannot pass by having been handed nothing.
        assert!(
            rendered.contains("messages decoded: 4"),
            "the fixture must decode: {rendered}"
        );
        assert!(
            rendered.contains("interest requests: 2"),
            "both questions are seen: {rendered}"
        );
        // THE ANSWERED ONE: credited across the flow and terminated.
        assert!(
            rendered.contains(
                "current interest 1 for keyexprs+subscribers under demo/** -- \
                 1 answer(s), closed"
            ),
            "the answered exchange: {rendered}"
        );
        // THE OTHER ONE, and it is the only FINDING here.
        assert!(
            rendered.contains(
                "FINDING: interest 2 for keyexprs+subscribers under absent/** \
                 got NO answer at all"
            ),
            "the unanswered exchange: {rendered}"
        );
        assert!(
            !rendered.contains("FINDING: interest 1"),
            "the answered one must NOT be a finding, or the reader is calling \
             every interest unanswered: {rendered}"
        );
        assert!(
            !rendered.contains("never closed"),
            "and nothing here is a truncated answer: {rendered}"
        );
    }

    /// R311y664 — a capture with no keys is analysed and SAYS SO, rather than
    /// failing.
    #[test]
    fn a_capture_without_keys_still_reports() {
        let packet = tls_packet();
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &packet)],
        );
        let (rendered, outcome) = analyze(&file, None).expect("the file parses");
        assert_eq!(outcome.key_log_connections, 0);
        assert_eq!(outcome.decrypted_flows, 0);
        assert_eq!(outcome.undecrypted_flows, 1);
        assert!(
            !outcome.complete,
            "an unreadable flow means the capture was not fully seen"
        );
        assert!(
            rendered.contains("inside TLS") && rendered.contains("NOT DECRYPTED"),
            "and the finding must reach the rendering, which is the only thing \
             a person running this tool ever sees: {rendered}"
        );
    }

    /// R311y664 — an EXTERNAL key log reaches the decryptor.
    ///
    /// The ordinary pair is a capture from one tool and an `SSLKEYLOGFILE` from
    /// the process under test, in two files. Until this crate the only key
    /// material the workspace could use was what a capture carried INSIDE it,
    /// which is the rarer arrangement.
    #[test]
    fn an_external_key_log_is_merged_with_whatever_the_capture_carried() {
        let packet = tls_packet();
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &packet)],
        );
        let log = alloc_keylog(&[7u8; 32]);
        let (_, outcome) = analyze(&file, Some(log.as_bytes())).expect("the file parses");
        assert_eq!(
            outcome.key_log_connections, 1,
            "the external log's connection must be in hand"
        );
    }

    /// A key log naming one connection, in NSS format.
    fn alloc_keylog(random: &[u8; 32]) -> String {
        let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            hex(random),
            hex(&[3u8; 48])
        )
    }

    /// One Ethernet/IPv4/TCP packet carrying a ClientHello and one protected
    /// record -- enough for the flow to be recognised as TLS.
    fn tls_packet() -> Vec<u8> {
        let random = [7u8; 32];
        let mut body = vec![0x03u8, 0x03];
        body.extend_from_slice(&random);
        body.resize(0x30, 0);
        let mut handshake = vec![0x01u8, 0x00, 0x00, body.len() as u8];
        handshake.extend_from_slice(&body);
        let mut stream = vec![0x16u8, 0x03, 0x01];
        stream.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        stream.extend_from_slice(&handshake);
        stream.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x08]);
        stream.extend_from_slice(&[0xAB; 8]);

        let mut tcp = Vec::new();
        tcp.extend_from_slice(&1111u16.to_be_bytes());
        tcp.extend_from_slice(&7447u16.to_be_bytes());
        tcp.extend_from_slice(&1000u32.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.push(5 << 4);
        tcp.push(0x10);
        tcp.extend_from_slice(&64u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&0u16.to_be_bytes());
        tcp.extend_from_slice(&stream);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&tcp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// One Ethernet/IPv4/UDP packet to zenoh's scouting group carrying a SCOUT.
    ///
    /// Hand-laid rather than encoded through `wz-codecs`, which is not a
    /// dependency of this crate: `[S_MID_SCOUT, version, cbyte, zid..]`, with
    /// `cbyte` bit 3 marking the zid present and its top nibble carrying
    /// `zid_len - 1` (`out/wz-codecs/scout.rs:70-92`).
    fn scout_packet() -> Vec<u8> {
        let scout = [0x01u8, 0x09, (3 << 4) | 0x08 | 0x03, 0x11, 0x22, 0x33, 0x44];

        let mut udp = Vec::new();
        udp.extend_from_slice(&43210u16.to_be_bytes());
        udp.extend_from_slice(&7446u16.to_be_bytes());
        udp.extend_from_slice(&((8 + scout.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(&scout);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&[192, 168, 1, 5]);
        // zenoh's `DEFAULT_MULTICAST_SCOUTING_ADDRESS`. The destination is the
        // discriminator: `S_MID_SCOUT` and `T_MID_INIT` are both `0x01`, and a
        // multicast transport has no handshake, so on this address the byte can
        // only be the scouting one.
        ip.extend_from_slice(&[224, 0, 0, 224]);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// R311y668 (§1.2a) — a DATAGRAM flow gets a row, and its scouting messages
    /// get names.
    ///
    /// R311y666 gave `--flows` its listing over `Dissection::flows()`, which is
    /// the TCP half. A scouting capture's entire content is in the other half,
    /// so the report said `datagram_flows: 1` and the list under it had no rows
    /// at all -- which reads as a capture whose one flow carried nothing, and is
    /// the silence this track exists to end arriving through the listing that
    /// was built to end it.
    #[test]
    fn a_datagram_flow_is_listed_and_its_scouting_messages_are_named() {
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &scout_packet())],
        );

        let (text, _) = analyze_with(&file, None, Format::Text, true, true).expect("parses");
        assert!(
            text.contains("1 datagram"),
            "the report must have counted the flow in the first place -- the \
             defect was a count with no row under it: {text}"
        );
        // MEASURED, and it is why the row carries a second number: the
        // capture-wide `messages decoded` total is 0 here while the flow holds
        // one scouting message, because `Dissection::decoded_messages` counts
        // transport frames only. A row that folded scouting into `message(s)`
        // would disagree with the summary printed three lines above it.
        assert!(
            text.contains("messages decoded: 0"),
            "the summary counts transport frames only: {text}"
        );
        assert!(
            text.contains("192.168.1.5:43210") && text.contains("224.0.0.224:7446"),
            "the datagram flow needs a ROW with its endpoints on it: {text}"
        );
        assert!(
            text.contains("datagram"),
            "and the row must say which transport it is: {text}"
        );
        assert!(
            text.contains("1 scouting"),
            "with the scouting count, which the message total does NOT include: \
             {text}"
        );
        assert!(
            text.contains("Scout"),
            "and --messages must NAME the scouting message, which is the whole \
             content of a capture like this one: {text}"
        );
        // Not an `Init`. The two namespaces collide on `0x01`, and naming this
        // one after the transport reading would be a confident wrong answer
        // rather than an absent one.
        assert!(
            !text.contains("Init"),
            "byte 0x01 on the scouting group is a Scout and not an Init: {text}"
        );

        let (json, _) = analyze_with(&file, None, Format::Json, true, true).expect("parses");
        assert!(
            json.contains("\"framing\":\"datagram\"") && json.contains("\"scouting\":1"),
            "the JSON row carries the same two facts: {json}"
        );
        assert!(
            json.contains("\"space\":\"scouting\"") && json.contains("\"name\":\"Scout\""),
            "and the message row says which namespace read it: {json}"
        );
        assert!(
            json.contains("\"batch\":null"),
            "a scouting datagram is not inside a batch, and `null` says that \
             rather than claiming index zero: {json}"
        );
    }

    /// R311y668 (§1.2a) — the two halves are ONE array, and the separator
    /// between them is real.
    ///
    /// The DISCRIMINATOR the single-transport test above cannot be: the flow
    /// list is written by two loops over two different collections, and a comma
    /// counter kept per loop restarts at the first datagram flow -- emitting
    /// `}{` between the last stream row and the first datagram one. Neither the
    /// depth walk in the binary test nor any row assertion sees that: the
    /// nesting stays balanced and every row is present and correct. What sees it
    /// is that the two objects are not separated.
    #[test]
    fn a_capture_with_both_transports_lists_them_in_one_separated_array() {
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[
                (0, 1_000_000, &tls_packet()),
                (0, 2_000_000, &scout_packet()),
            ],
        );

        let (json, _) = analyze_with(&file, None, Format::Json, true, false).expect("parses");
        assert!(
            json.contains("\"framing\":\"tls\"") && json.contains("\"framing\":\"datagram\""),
            "both transports must have a row: {json}"
        );
        assert!(
            !json.contains("}{"),
            "two rows with no comma between them is not an array a consumer can \
             parse, and it is balanced and complete so nothing else catches it: \
             {json}"
        );

        let (text, _) = analyze_with(&file, None, Format::Text, true, false).expect("parses");
        assert_eq!(
            text.lines().filter(|l| l.contains(" <-> ")).count(),
            2,
            "and the text listing has one row each: {text}"
        );
    }

    /// R311y668 (§1.2a) — `--json --messages` carries the messages.
    ///
    /// R311y667 put `if per_message` inside the TEXT branch only, so the JSON
    /// listed flows and dropped their messages: the same silent narrowing that
    /// round closed in the document count, one field lower.
    #[test]
    fn the_json_listing_carries_the_messages_and_not_only_their_number() {
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &scout_packet())],
        );

        let (with, _) = analyze_with(&file, None, Format::Json, true, true).expect("parses");
        assert!(
            with.contains("\"message_list\":["),
            "--json --messages must list them: {with}"
        );

        // And the DISCRIMINATOR: without the flag the key is absent rather than
        // empty, so "not asked for" and "none there" stay different answers.
        let (without, _) = analyze_with(&file, None, Format::Json, true, false).expect("parses");
        assert!(
            !without.contains("message_list"),
            "--json --flows alone must not claim to have listed them: {without}"
        );
    }

    /// One UDP datagram to a zenoh port carrying `payload`.
    fn udp_to_zenoh_port(payload: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&50000u16.to_be_bytes());
        udp.extend_from_slice(&7447u16.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(payload);

        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 1]);
        ip.extend_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// R311y669 (§1.2a) — A QUIC CAPTURE IS NOT READ AS ZENOH.
    ///
    /// THE MEASUREMENT THAT PRODUCED THIS ROUND, run through this very function
    /// before the fix existed: this capture reported `messages decoded: 4`, with
    /// an `Init` and a `Fragment` among them, out of bytes holding no zenoh at
    /// all. A QUIC short header's first byte is a flagged zenoh MID -- `0x41` is
    /// `T_MID_INIT | 0x40` -- so the transport decoder did not fail on it, it
    /// SUCCEEDED. That is a misread, which this crate treats as strictly worse
    /// than an un-read, and it was the last transport where one was still
    /// happening.
    #[test]
    fn a_quic_capture_reports_quic_and_decodes_no_zenoh_from_it() {
        // A v1 Initial (long header) and then a 1-RTT packet (short header), the
        // ordinary opening of any QUIC connection.
        let mut initial = vec![0xC0u8];
        initial.extend_from_slice(&1u32.to_be_bytes());
        initial.push(8);
        initial.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        initial.push(4);
        initial.extend_from_slice(&[8, 9, 10, 11]);
        initial.extend_from_slice(&[0x00, 0x29, 0x01]);
        initial.extend_from_slice(&[0xAA; 40]);
        // `0x41` -- the byte that used to decode as a zenoh Init.
        let mut one_rtt = vec![0x41u8];
        one_rtt.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        one_rtt.extend_from_slice(&[0xBB; 30]);

        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[
                (0, 1_000_000, &udp_to_zenoh_port(&initial)),
                (0, 1_000_001, &udp_to_zenoh_port(&one_rtt)),
            ],
        );

        let (text, outcome) = analyze_with(&file, None, Format::Text, true, true).expect("parses");
        assert!(
            text.contains("messages decoded: 0"),
            "not one zenoh message may be claimed from a QUIC capture: {text}"
        );
        // The two names the pre-fix reading produced, asserted as ABSENT. The
        // count alone would not catch a reading that produced them and counted
        // them elsewhere.
        assert!(
            !text.contains("Init") && !text.contains("Fragment"),
            "and specifically not the two the misread produced: {text}"
        );
        assert!(
            text.contains("QUIC: 1 flow(s), 2 packet(s)"),
            "the capture must SAY it carried QUIC -- silence here is the other \
             half of the same defect: {text}"
        );
        assert!(
            text.contains("NOT DECRYPTED"),
            "and say that none of it was opened: {text}"
        );
        assert!(
            text.contains("quic ") && text.contains("QuicProtected"),
            "the flow row names the transport and its state: {text}"
        );
        assert!(
            !outcome.complete,
            "a capture whose zenoh is inside QUIC this reader does not open is \
             not a capture it saw whole"
        );

        let (json, _) = analyze_with(&file, None, Format::Json, true, true).expect("parses");
        assert!(
            json.contains("\"quic\":{\"flows\":1,\"packets\":2,")
                && json.contains("\"initial\":1")
                && json.contains("\"one_rtt\":1")
                && json.contains("\"decrypted\":false"),
            "the JSON block names the packet kinds, which is what tells a reader \
             WHERE the zenoh would be: {json}"
        );
        assert!(
            json.contains("\"messages_decoded\":0"),
            "and claims no messages: {json}"
        );
    }

    /// R311y669 (§1.2a) — THE DISCRIMINATOR. A zenoh datagram whose first byte
    /// looks like a QUIC short header is still read as zenoh.
    ///
    /// Without this, the round's fix could be "call every `0x40..=0x7F` datagram
    /// QUIC", which closes the misread by creating its mirror image: real zenoh
    /// traffic silently reported as an unopened QUIC flow. The recognition is
    /// flow-scoped precisely so this capture is unaffected, and no assertion in
    /// the test above can show that.
    #[test]
    fn a_zenoh_datagram_whose_first_byte_resembles_quic_is_still_read_as_zenoh() {
        // A zenoh FRAGMENT whose first byte is in the SHORT-HEADER RANGE:
        // `0x46` is `T_MID_FRAGMENT | FLAG_T_FRAGMENT_M`, so the high bit is
        // clear and the next one set -- byte-for-byte what a QUIC 1-RTT header
        // looks like. It is also the very name the pre-fix misread invented for
        // a QUIC packet, which is why this is the right fixture: the two
        // directions of the mistake meet on this byte.
        //
        // Two fixture facts learned by measurement rather than assumed: the
        // datagram path takes the message with NO length prefix (an earlier
        // version prefixed one and its `0x04` decoded as a KeepAlive, proving
        // the framing instead of the byte), and `0x41` will not do because
        // `T_MID_INIT | 0x40` sets INIT's S flag and demands more body.
        let batch = [0x46u8, 0x07, 0xEE];

        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &udp_to_zenoh_port(&batch))],
        );
        let (text, _) = analyze_with(&file, None, Format::Text, true, true).expect("parses");
        assert!(
            text.contains("messages decoded: 1") && text.contains("Fragment"),
            "a zenoh datagram must still be read as zenoh -- a rule deciding on \
             that byte would silence real traffic: {text}"
        );
        assert!(
            !text.contains("QUIC"),
            "and must not be claimed as QUIC: {text}"
        );
    }

    /// R311y669 (§1.2a) — the TEXT row's SHAPE, pinned as a whole line.
    ///
    /// R311y668 carried this: every assertion about the text listing matched a
    /// SUBSTRING, so the column layout could drift without any gate noticing —
    /// the same class the JSON document-count check closed for the other format.
    /// R311y669 then added a column to every row (`quic` / `QuicProtected`),
    /// which is exactly the change the carry predicted, and it went in with no
    /// gate to fail.
    ///
    /// The whole line, byte for byte. A layout change now has to be a deliberate
    /// edit here rather than a silent consequence somewhere else.
    #[test]
    fn the_text_flow_row_has_a_pinned_shape_and_not_only_pinned_words() {
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[
                (0, 1_000_000, &tls_packet()),
                (0, 2_000_000, &scout_packet()),
            ],
        );
        let (text, _) = analyze_with(&file, None, Format::Text, true, true).expect("parses");
        let rows: Vec<&str> = text.lines().filter(|l| l.contains(" <-> ")).collect();
        assert_eq!(
            rows,
            vec![
                "  10.0.0.1:1111 <-> 10.0.0.2:7447  tls          0 message(s)  0 scouting  NoKeysSupplied",
                "  192.168.1.5:43210 <-> 224.0.0.224:7446  datagram     0 message(s)  1 scouting  -",
            ],
            "the row layout is a pinned shape: endpoints, framing in a 12-wide \
             column, the two counts, then the protection state"
        );
        // And the message row under it, which has its own shape.
        let under: Vec<&str> = text.lines().filter(|l| l.starts_with("      ")).collect();
        assert_eq!(
            under,
            vec!["      A @1 [packet index] scouting  Scout"],
            "a scouting row carries the namespace where a batch index would be, \
             and R311y689 put the OFFSET's space beside the offset -- `@1` was a \
             packet index that looked exactly like a byte offset"
        );
    }

    /// R311y669 (§1.2a) — the message listing is BOUNDED, and says what it cut.
    ///
    /// R311y668 carried this: `message_list` rendered up to
    /// `MAX_KEPT_RECORDS_PER_DIRECTION` rows per direction per flow into one
    /// string with no cap at all. Everything else in this reader is bounded and
    /// counts what the bound cost -- a rendering that is not is a rendering whose
    /// size depends on how much traffic there was, which is the leak every
    /// `drops` counter in `wz-capture` exists to prevent.
    ///
    /// The cut is REPORTED in the rendering itself, on the house rule: a bound
    /// that bites without saying so reports itself as the wire.
    #[test]
    fn the_message_listing_is_bounded_and_says_how_many_it_left_out() {
        // Six scouting datagrams, listed under a cap of two.
        let mut packets: Vec<Vec<u8>> = Vec::new();
        for _ in 0..6 {
            packets.push(scout_packet());
        }
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64, p.as_slice()))
            .collect();
        let file = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);

        let (text, _) =
            analyze_with_limit(&file, None, Format::Text, true, true, Some(2)).expect("parses");
        assert_eq!(
            text.lines().filter(|l| l.contains("Scout")).count(),
            2,
            "the cap must bite: {text}"
        );
        assert!(
            text.contains("4 more not listed"),
            "and the rendering must say what it left out, or the listing reads as \
             the whole of what was decoded: {text}"
        );

        let (json, _) =
            analyze_with_limit(&file, None, Format::Json, true, true, Some(2)).expect("parses");
        assert!(
            json.contains("\"message_list_omitted\":4"),
            "the JSON says it structurally rather than in prose: {json}"
        );
        // Unbounded is still available and still the default -- the cap is a
        // caller's choice, not a new silent ceiling on the ordinary path.
        let (all, _) = analyze_with(&file, None, Format::Text, true, true).expect("parses");
        assert_eq!(all.lines().filter(|l| l.contains("Scout")).count(), 6);
        assert!(!all.contains("more not listed"));
    }

    /// One UDP datagram carrying a QUIC 1-RTT packet, whose first byte is a
    /// perfectly good flagged zenoh MID.
    fn one_rtt_packet(first: u8) -> Vec<u8> {
        let mut p = vec![first];
        p.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        p.extend_from_slice(&[0x06]);
        p.extend_from_slice(&[0xCC; 25]);
        udp_to_zenoh_port(&p)
    }

    /// R311y670 (§1.2a) — A MID-CONNECTION QUIC CAPTURE NEEDS THE CALLER TO SAY
    /// SO, and both halves of that are asserted here.
    ///
    /// THE MEASUREMENT THAT PRODUCED THIS ROUND: one QUIC 1-RTT packet beginning
    /// `0x46` decodes as a COMPLETE zenoh `Fragment`, leaves ZERO unaccounted
    /// bytes, and the report says `complete`. Every counter agrees the capture was
    /// read whole. That is the worst output this crate can produce and it is the
    /// shape `tls.rs` says the crate exists to end.
    ///
    /// R311y669's recognition cannot reach it: a short header carries no version,
    /// no connection-id length, nothing to check — so the sound rule needs a long
    /// header and this capture has none. A heuristic would trade the misread for
    /// its mirror image, real zenoh reported as an unopened QUIC flow. So the fact
    /// comes from outside, exactly as an external key log does for TLS.
    ///
    /// The FIRST half of this test records the limit rather than hiding it: with
    /// no flag, the misread is still there. A round that asserted only the fixed
    /// case would leave a reader believing QUIC was closed.
    #[test]
    fn a_mid_connection_quic_capture_needs_the_caller_to_say_so() {
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &one_rtt_packet(0x46))],
        );

        // THE LIMIT, as a fact. Nothing in these bytes says QUIC.
        let (blind, outcome) = analyze_with(&file, None, Format::Text, true, true).expect("parses");
        assert!(
            blind.contains("messages decoded: 1") && blind.contains("Fragment"),
            "without the flag this is still read as zenoh, and saying so is the \
             honest form -- the byte carries no answer: {blind}"
        );
        assert!(
            outcome.complete,
            "and the verdict still says whole, which is exactly why a caller must \
             be able to correct it"
        );

        // THE ROUND: the caller supplies what the capture cannot.
        let (told, outcome) =
            analyze_declaring_quic(&file, None, Format::Text, true, true, None, &[7447])
                .expect("parses");
        assert!(
            told.contains("messages decoded: 0"),
            "not one zenoh message may survive the correction: {told}"
        );
        assert!(
            !told.contains("Fragment"),
            "and specifically not the name the misread produced: {told}"
        );
        assert!(
            told.contains("QUIC: 1 flow(s) (1 declared, not recognised)"),
            "the report must say the classification was a PREMISE and not \
             evidence -- a wrong flag makes every count under it wrong: {told}"
        );
        assert!(
            !outcome.complete,
            "a capture whose zenoh is inside QUIC is not one this reader saw whole"
        );
    }

    /// R311y670 (§1.2a) — a DECLARED flow and a RECOGNISED one are told apart,
    /// including in JSON.
    ///
    /// The hazard the label exists for, stated: a declared port carrying real
    /// zenoh reports that zenoh as an unopened QUIC flow. That is the accepted
    /// cost of a premise, and it is only acceptable while the report says which
    /// flows rest on one.
    #[test]
    fn a_declared_flow_is_marked_as_a_premise_and_a_recognised_one_is_not() {
        // Recognised: a v1 long header, no flag given.
        let mut initial = vec![0xC0u8];
        initial.extend_from_slice(&1u32.to_be_bytes());
        initial.push(8);
        initial.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        initial.push(4);
        initial.extend_from_slice(&[8, 9, 10, 11]);
        initial.extend_from_slice(&[0x00, 0x29, 0x01]);
        initial.extend_from_slice(&[0xAA; 40]);
        let recognised = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &udp_to_zenoh_port(&initial))],
        );
        let (json, _) = analyze_declaring_quic(
            &recognised,
            None,
            Format::Json,
            true,
            false,
            None,
            // Declared TOO, and still counted as recognised: evidence outranks a
            // premise, because the long header is a fact about these bytes.
            &[7447],
        )
        .expect("parses");
        assert!(
            json.contains("\"declared_flows\":0"),
            "a flow whose long header was read is EVIDENCE, flag or no flag: {json}"
        );

        // Declared only.
        let declared = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &one_rtt_packet(0x46))],
        );
        let (json, _) =
            analyze_declaring_quic(&declared, None, Format::Json, true, false, None, &[7447])
                .expect("parses");
        assert!(
            json.contains("\"declared_flows\":1") && json.contains("\"one_rtt\":1"),
            "and one with nothing but a short header rests on the flag: {json}"
        );
    }

    /// A zenoh datagram carrying `payload` to the zenoh port.
    fn zenoh_datagram(payload: &[u8]) -> Vec<u8> {
        udp_to_zenoh_port(payload)
    }

    /// R311y671 (§1.2a) — A DECLARATION ITS OWN FLOW CONTRADICTS SAYS SO.
    ///
    /// THE MEASUREMENT: declaring a port that really carried three ordinary zenoh
    /// datagrams silenced all three and printed `NOT DECRYPTED (this reader
    /// recognises QUIC and opens none of it)`. It recognised nothing -- the JSON
    /// already held the whole signal (`unrecognised: 3`, `one_rtt: 0`,
    /// `initial: 0`) and nothing read it, so the sentence a person actually sees
    /// was confidently wrong about the one thing that mattered.
    ///
    /// The cost of a wrong premise is the worst this reader can inflict, worse
    /// than the misread R311y669 closed: there, bytes that were not zenoh were
    /// named as zenoh; here, bytes that ARE zenoh are withheld and reported as
    /// protected. So the premise must be able to fail out loud.
    #[test]
    fn a_declaration_its_own_flow_contradicts_is_reported_as_probably_wrong() {
        let ka = zenoh_datagram(&[0x04]);
        let init = zenoh_datagram(&[0x01, 0x09, 0x01, 0xAA]);
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[
                (0, 1_000_000, &ka),
                (0, 1_000_001, &init),
                (0, 1_000_002, &ka),
            ],
        );

        let (text, _) =
            analyze_declaring_quic(&file, None, Format::Text, true, true, None, &[7447])
                .expect("parses");
        assert!(
            text.contains("the --quic port is probably wrong"),
            "the rendering must say the premise looks wrong: {text}"
        );
        assert!(
            text.contains("withheld from the zenoh decoder"),
            "and name the COST, which is the part a reader acts on -- their own \
             traffic is missing from this report: {text}"
        );
        assert!(
            text.contains("QuicDeclaredUnsupported") && !text.contains("QuicProtected"),
            "and the flow row must not claim protected bytes it never identified: \
             {text}"
        );

        let (json, _) =
            analyze_declaring_quic(&file, None, Format::Json, true, false, None, &[7447])
                .expect("parses");
        assert!(
            json.contains("\"declarations_unsupported\":1") && json.contains("\"unrecognised\":3"),
            "structurally too: {json}"
        );

        // THE DISCRIMINATOR: a declaration its packets DO support says nothing of
        // the kind. Without this, "always warn about a declared flow" would pass
        // every assertion above while making the flag useless.
        let mut one_rtt = vec![0x41u8];
        one_rtt.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        one_rtt.extend_from_slice(&[0xBB; 30]);
        let supported = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &udp_to_zenoh_port(&one_rtt))],
        );
        let (text, _) =
            analyze_declaring_quic(&supported, None, Format::Text, true, false, None, &[7447])
                .expect("parses");
        assert!(
            !text.contains("probably wrong") && text.contains("QuicProtected"),
            "a supported declaration must stay quiet: {text}"
        );
    }

    /// R311y671 (§1.2a) — WHAT THE SIGNAL MISSES, recorded as a test rather than
    /// as a sentence in a doc comment.
    ///
    /// On a declared flow there is nothing left to check, so any first byte with
    /// bit `0x40` set is accepted as a 1-RTT packet -- and a zenoh `Fragment` with
    /// its M flag is exactly that (`0x46`). A wrong declaration over
    /// fragment-heavy zenoh therefore looks SUPPORTED, and the warning above does
    /// not fire.
    ///
    /// Asserted so the limit cannot quietly become a belief that the premise is
    /// checked. A partial witness that fires on the shape a wrong flag usually
    /// takes -- handshake and keepalive bytes, whose MIDs sit below `0x20` with no
    /// `0x40` flag -- is worth having; believing it complete is not.
    #[test]
    fn the_contradiction_signal_misses_zenoh_whose_first_byte_carries_the_fixed_bit() {
        // A real zenoh Fragment, first byte 0x46, on a wrongly declared port.
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &zenoh_datagram(&[0x46, 0x07, 0xEE]))],
        );
        let (text, _) =
            analyze_declaring_quic(&file, None, Format::Text, true, true, None, &[7447])
                .expect("parses");
        assert!(
            !text.contains("probably wrong"),
            "the limit, stated: this wrong declaration is NOT caught, because the \
             byte is a valid 1-RTT first byte and on a declared flow nothing else \
             is checked: {text}"
        );
        assert!(
            text.contains("\"one_rtt\"") || text.contains("QuicProtected"),
            "it reads as a supported declaration: {text}"
        );
    }

    /// R311y664 — a file that is not a capture is an ERROR, not an empty
    /// report.
    ///
    /// An empty report about an unreadable file is the failure mode this whole
    /// track exists to end, one layer up: it reads as "this capture had nothing
    /// in it".
    #[test]
    fn a_file_that_is_not_a_capture_is_refused() {
        assert!(analyze(b"not a capture at all", None).is_err());
    }
}

#[cfg(test)]
mod message_name_tests {
    use super::*;

    /// R311y667 — a message this reader could NOT decode is NAMED, not omitted.
    ///
    /// A listing that shows only the successes is the silence this whole track
    /// exists to end, arriving one layer up: a flow reporting "2 messages" while
    /// printing two lines out of three reads as a capture that carried two.
    ///
    /// Driven on a hand-built `PassiveFrame` because the shape is hard to reach
    /// through a capture -- a framed unit whose body is short enough to fail the
    /// codec is also short enough that the FRAMER usually rejects it first, and
    /// a fixture that has to defeat two layers to reach one arm is a fixture
    /// that stops testing the arm.
    #[test]
    fn a_message_that_did_not_decode_is_named_rather_than_dropped() {
        let frame = wz_session_core::passive::PassiveFrame {
            direction: wz_session_core::passive::Direction::A,
            stream_offset: 12,
            batch_index: 0,
            unit_offset: 0,
            unit_len: 0,
            batch_offset: None,
            prefix_width: 2,
            frame: Err(wz_session_core::parse_error::InboundParseError::Empty),
            context: Default::default(),
            exceeds_negotiated_batch: false,
            carried: wz_session_core::passive::Carried::Nothing,
            inadmissible_on_link: false,
            sn_verdict: None,
            resync: None,
            observed_at_ms: None,
            reserved_header_bits: 0,
            undefined_mandatory_ext: None,
        };
        let name = message_name(&frame);
        assert!(
            name.starts_with("undecodable("),
            "an undecodable message must say so: {name}"
        );
        assert!(
            name.contains("Empty"),
            "and carry WHY, because the reason is what a reader acts on: {name}"
        );
    }

    /// One `PassiveFrame` at `stream_offset`, claiming to be whatever `frame`
    /// says it is.
    fn frame_at(
        stream_offset: usize,
        frame: Result<
            wz_session_core::inbound::InboundFrame,
            wz_session_core::parse_error::InboundParseError,
        >,
    ) -> wz_session_core::passive::PassiveFrame {
        wz_session_core::passive::PassiveFrame {
            direction: wz_session_core::passive::Direction::A,
            stream_offset,
            batch_index: 0,
            unit_offset: 0,
            unit_len: 1,
            batch_offset: None,
            prefix_width: 2,
            frame,
            context: Default::default(),
            exceeds_negotiated_batch: false,
            carried: wz_session_core::passive::Carried::Nothing,
            inadmissible_on_link: false,
            sn_verdict: None,
            resync: None,
            observed_at_ms: None,
            reserved_header_bits: 0,
            undefined_mandatory_ext: None,
        }
    }

    /// A framed unit: `u16` little-endian length, then the message.
    fn framed(message: &[u8]) -> Vec<u8> {
        let mut out = (message.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(message);
        out
    }

    /// R311y682 (§1.1n) — A ROW WHOSE TWO READERS DISAGREE IS DECLINED, and
    /// this is the committed witness for a branch the datagram path could only
    /// probe.
    ///
    /// ## Why this one HAS a fixture where R311y680's did not
    ///
    /// That check compared a packet against coordinates only correct code can
    /// produce, so no capture reaches its rejecting arm. This one compares two
    /// READERS, and both are reachable from here: a stream holding a KeepAlive
    /// with a frame that says the session read a Frame there is exactly what a
    /// moved coordinate rule would produce, and it can simply be written down.
    ///
    /// ## What must NOT happen, asserted first
    ///
    /// The truthful pairing is asserted before the false one, because a check
    /// that rejects everything would pass the negative leg alone -- and losing
    /// legitimate rows is the direction this workspace has already been wrong
    /// in once.
    #[test]
    fn a_row_whose_two_readers_disagree_is_declined_rather_than_rendered() {
        // `0x04` is the KeepAlive MID with every flag clear; the walker names
        // it KeepAlive and so does the session.
        let stream = framed(&[0x04]);
        let honest = frame_at(
            0,
            Ok(wz_session_core::inbound::InboundFrame::KeepAlive {
                has_ext: false,
                extensions: Vec::new(),
            }),
        );
        match walk_message(&stream, 0, &honest) {
            FieldRow::Walked(field) => assert_eq!(
                field.name, "KeepAlive",
                "the agreeing case must still produce its row"
            ),
            FieldRow::Declined(why) => {
                panic!("a row both readers agree about must NOT be declined: {why}")
            }
        }

        // The same bytes, with a session verdict that names a different
        // message: what a `stream_offset` naming the wrong position looks like
        // from here.
        let crossed = frame_at(
            0,
            Ok(wz_session_core::inbound::InboundFrame::Close {
                reason: 0,
                // R311y839 — a fabricated CROSSED verdict; what matters is that
                // it names Close where the bytes are a KeepAlive, so the scope is
                // inert here. `false` is the value every zenoh unicast Close
                // carries, so the stand-in is the ordinary one.
                session: false,
                has_ext: false,
                extensions: Vec::new(),
            }),
        );
        match walk_message(&stream, 0, &crossed) {
            FieldRow::Walked(field) => panic!(
                "bytes the session read as Close must not be rendered as a \
                 confident {} tree",
                field.name
            ),
            FieldRow::Declined(why) => {
                // BOTH OPINIONS, because one of them alone does not say which
                // reader to go and look at.
                assert!(
                    why.contains("as Close") && why.contains("as KeepAlive"),
                    "the decline must name both readers' verdicts: {why}"
                );
            }
        }
    }

    /// R311y684 (§1.1n) — the two NAME TABLES the agreement check compares are
    /// pinned to each other, on real bytes, for every kind that has a name.
    ///
    /// # What was unpinned
    ///
    /// [`walk_agrees`] compares `InboundFrame::kind_name` with the field
    /// walker's `match mid` arms. They are two independent tables in two crates
    /// that happen to spell the seven kinds identically, and NOTHING made them
    /// keep doing so: a rename on either side would turn every row in the
    /// listing into a dispute, and the round that did it would see a green
    /// suite, because every fixture in this crate carries KeepAlive and Frame
    /// alone.
    ///
    /// So the same bytes go through both readers and the names must match. Not
    /// a comparison of two literal lists -- that would pin the test to the
    /// tables rather than the tables to each other.
    #[test]
    fn the_two_name_tables_agree_on_every_kind_that_has_a_name() {
        // One minimal encoding per transport MID. The Init/Open/Join bodies are
        // the smallest the walker accepts: version, a cbyte whose top nibble is
        // the zid length minus one, and the zid.
        let each: &[(&str, &[u8])] = &[
            // Init: version, a cbyte whose top nibble is the zid length minus
            // one, and the zid.
            ("Init", &[0x01, 0x09, 0x00, 0xAA]),
            // Open with A clear, so the cookie rides this one: lease, initial
            // sn, cookie length, cookie.
            ("Open", &[0x02, 0x01, 0x00, 0x01, 0xAA]),
            ("Close", &[0x03, 0x00]),
            ("KeepAlive", &[0x04]),
            ("Frame", &[0x05, 0x01]),
            ("Fragment", &[0x06, 0x01]),
            // Join: version, cbyte, zid, lease, and the two next-sn values.
            ("Join", &[0x07, 0x09, 0x00, 0xAA, 0x01, 0x00, 0x00]),
        ];
        let mut checked = 0usize;
        for (expected, bytes) in each {
            let walked = wz_session_core::dissect::dissect_transport_message(bytes, 0)
                .unwrap_or_else(|e| panic!("{expected}: the walker must read {bytes:?}: {e:?}"));
            let framed = wz_session_core::inbound::parse_inbound(bytes)
                .unwrap_or_else(|e| panic!("{expected}: the session must read {bytes:?}: {e:?}"));
            let framed = framed.kind_name();
            // ANTI-VACUITY: neither reader may answer `Unknown` here, because
            // `walk_agrees` treats that as silence -- a fixture both readers
            // failed to recognise would satisfy the equality below and pin
            // nothing.
            assert_ne!(
                walked.name, "Unknown",
                "{expected}: the fixture must be a kind the walker names"
            );
            assert_ne!(
                framed, "Unknown",
                "{expected}: and one the session names, or this pins nothing"
            );
            assert_eq!(
                walked.name, *expected,
                "the walker's name for this kind is the one the listing prints"
            );
            assert_eq!(
                framed, *expected,
                "and the session's name for the SAME bytes must be the same \
                 string, or every row of this kind becomes a dispute"
            );
            checked += 1;
        }
        // R311y690 — SEVEN, which is every kind `kind_name` has a name for.
        // Four of them left three renames able to pass silently.
        assert_eq!(checked, 7, "every case in the table must have run");
    }

    /// R311y683 (§1.1n) — the DECRYPTED row gets the same witness, and a
    /// message the walker refuses inside TLS is no longer dropped.
    ///
    /// ## The two defects, both measured on this path
    ///
    /// R311y682 closed the cleartext half and its carry named this one: the
    /// sink slices the plaintext at `frame.stream_offset + prefix_width` and
    /// walked it with nothing comparing the result against the frame those
    /// coordinates came from. Worse than the cleartext case was already, in
    /// fact — a failed walk was dropped by an `if let Ok`, so a record the
    /// walker could not read simply left the listing, in the one transport
    /// where a reader cannot check the bytes by eye.
    #[test]
    fn a_decrypted_row_is_checked_against_its_frame_and_never_dropped() {
        let keepalive = [0x04u8];
        let honest = frame_at(
            0,
            Ok(wz_session_core::inbound::InboundFrame::KeepAlive {
                has_ext: false,
                extensions: Vec::new(),
            }),
        );
        // The truthful pairing FIRST: a check that refused everything would
        // pass the negative leg on its own.
        match walk_plaintext(&keepalive, &honest) {
            FieldRow::Walked(field) => assert_eq!(field.name, "KeepAlive"),
            FieldRow::Declined(why) => panic!("an agreeing decrypted row must be rendered: {why}"),
        }

        let crossed = frame_at(
            0,
            Ok(wz_session_core::inbound::InboundFrame::Close {
                reason: 0,
                session: false,
                has_ext: false,
                extensions: Vec::new(),
            }),
        );
        match walk_plaintext(&keepalive, &crossed) {
            FieldRow::Walked(field) => panic!(
                "plaintext the session read as Close must not be rendered as a \
                 confident {} tree",
                field.name
            ),
            FieldRow::Declined(why) => assert!(
                why.contains("as Close") && why.contains("as KeepAlive"),
                "the decline names both readers: {why}"
            ),
        }

        // AND A WALK THAT FAILS IS A ROW. Empty bytes are what the walker
        // refuses; before this round they became no row at all.
        match walk_plaintext(&[], &honest) {
            FieldRow::Walked(_) => panic!("empty bytes are not a message"),
            FieldRow::Declined(why) => assert!(
                why.contains("the field walker refused these bytes"),
                "a refused walk is declined by name, not dropped: {why}"
            ),
        }
    }

    /// R311y682 (§1.1n) — the cfg asymmetry is silence, not contradiction.
    ///
    /// `InboundFrame`'s variants are feature-gated and the walker's names are
    /// not, so a build without `codec-join` decodes a Join as `Unknown` while
    /// the walker names it. A check that fired on that would reject legitimate
    /// rows in every reduced build.
    #[test]
    fn the_feature_gated_half_of_the_pair_is_not_a_disagreement() {
        assert!(
            walk_agrees("Join", "Unknown"),
            "the session naming Unknown is a codec this build lacks, not a \
             contradiction"
        );
        assert!(
            walk_agrees("Unknown", "Frame"),
            "and the walker naming Unknown is the same asymmetry the other way"
        );
        assert!(
            walk_agrees("KeepAlive", "undecodable(Empty)"),
            "a frame the session could not decode at all names no kind to \
             disagree with"
        );
        assert!(walk_agrees("Frame", "Frame"), "and agreement is agreement");
        // THE ONE THAT MUST FIRE: two readers, two specific kinds, different.
        assert!(
            !walk_agrees("Frame", "KeepAlive"),
            "two specific and different kinds is the disagreement this check \
             exists for"
        );
    }
}

#[cfg(test)]
mod packet_and_note_tests {
    use super::*;
    use wz_session_core::passive::Direction;

    /// One UDP packet, Ethernet/IPv4, carrying `body`.
    fn udp(body: &[u8]) -> Vec<u8> {
        let mut u = Vec::new();
        u.extend_from_slice(&43210u16.to_be_bytes());
        u.extend_from_slice(&7446u16.to_be_bytes());
        u.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
        u.extend_from_slice(&0u16.to_be_bytes());
        u.extend_from_slice(body);
        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + u.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&[192, 168, 1, 5]);
        ip.extend_from_slice(&[224, 0, 0, 224]);
        ip.extend_from_slice(&u);
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// R311y680 (§1.1n) — the cross-check answers NO on each of its three axes
    /// INDEPENDENTLY.
    ///
    /// # Why this test exists at all
    ///
    /// Measured: removing the whole check left every binary test green, because
    /// with correct code upstream it never fires and nothing observable changes.
    /// A guard with no gate is a comment. Its rejecting direction is unreachable
    /// from a capture, so it is driven HERE, on the predicate, where the three
    /// coordinates can be varied one at a time.
    ///
    /// One at a time is the point: a predicate that only compared the flow, or
    /// only the index, would satisfy a test that mutated all three together.
    #[test]
    fn the_packet_cross_check_answers_no_on_each_axis_alone() {
        let packet = udp(&[0x01, 0x09, 0x3B, 0x11, 0x22, 0x33, 0x44]);
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &packet), (0, 1_000_100, &packet)],
        );
        let parsed = wz_capture::pcapng::parse(&file).expect("the fixture parses");
        let first = &parsed.packets[0];
        let wz_capture::link::Transport::Udp(datagram) =
            wz_capture::link::decapsulate(first.link_type, first.index, &first.data)
                .expect("a UDP datagram")
        else {
            panic!("the fixture must decapsulate as UDP");
        };
        let travels = if datagram.from_low {
            Direction::A
        } else {
            Direction::B
        };

        // The truthful call, which is what every real row makes.
        assert!(
            !packet_disagreement(&datagram, &datagram.flow, travels, datagram.packet_index).any(),
            "a packet must vouch for its own coordinates"
        );
        // WRONG DIRECTION, everything else right.
        //
        // R311y681 — and the answer NAMES the axis. Asserting the whole `Axes`
        // rather than `any()` is what makes each leg about ONE coordinate: a
        // predicate that returned "everything disagrees" for every mutation
        // would satisfy three `any()` assertions and be useless to the reader
        // it reports to.
        let other = match travels {
            Direction::A => Direction::B,
            Direction::B => Direction::A,
        };
        assert_eq!(
            packet_disagreement(&datagram, &datagram.flow, other, datagram.packet_index),
            Axes {
                direction: true,
                ..Default::default()
            },
            "the direction axis must be reported on its own"
        );
        // WRONG INDEX, everything else right.
        assert_eq!(
            packet_disagreement(
                &datagram,
                &datagram.flow,
                travels,
                datagram.packet_index + 1
            ),
            Axes {
                index: true,
                ..Default::default()
            },
            "the index axis must be reported on its own"
        );
        // WRONG FLOW, everything else right: the same endpoints with the ports
        // swapped is a different key and a real confusion to guard against.
        let mut crossed = datagram.flow;
        core::mem::swap(&mut crossed.low, &mut crossed.high);
        assert!(
            crossed != datagram.flow,
            "the mutation must actually change the key, or the assertion below \
             is about nothing"
        );
        assert_eq!(
            packet_disagreement(&datagram, &crossed, travels, datagram.packet_index),
            Axes {
                flow: true,
                ..Default::default()
            },
            "the flow axis must be reported on its own"
        );
        // AND THEY COMPOSE. Two axes wrong at once must name two, or the reader
        // chasing the cause is told to look at one of the two places.
        assert_eq!(
            packet_disagreement(&datagram, &crossed, other, datagram.packet_index),
            Axes {
                flow: true,
                direction: true,
                ..Default::default()
            },
            "axes fail independently and must be reported independently"
        );
        assert_eq!(
            Axes {
                flow: true,
                direction: true,
                ..Default::default()
            }
            .names(),
            vec!["flow", "direction"],
            "and the names are what the listing prints"
        );
    }

    /// A real `FlowKey`, decapsulated from a real packet.
    ///
    /// R311y681 — built this way for the reason R311y680 recorded: `Endpoint`
    /// keeps its address bytes private, so the only way to hold one here is to
    /// decode one. The cost is stated where it bites: a test built this way
    /// cannot reach coordinate combinations no real packet produces.
    fn sample_flow() -> wz_capture::link::FlowKey {
        let packet = udp(&[0x01, 0x09, 0x3B, 0x11, 0x22, 0x33, 0x44]);
        let file = wz_capture::pcapng::write(
            &[(wz_capture::link::LINKTYPE_ETHERNET, 6)],
            &[(0, 1_000_000, &packet)],
        );
        let parsed = wz_capture::pcapng::parse(&file).expect("the fixture parses");
        let first = &parsed.packets[0];
        let wz_capture::link::Transport::Udp(datagram) =
            wz_capture::link::decapsulate(first.link_type, first.index, &first.data)
                .expect("a UDP datagram")
        else {
            panic!("the fixture must decapsulate as UDP");
        };
        datagram.flow
    }

    /// R311y681 (§1.1n) — a disagreement names WHICH MESSAGE and WHICH AXIS, in
    /// both renderings, from one value.
    ///
    /// # Why this is driven on the note and not on a capture
    ///
    /// The disagreement branch cannot fire from any capture while the code
    /// upstream of it is correct — R311y680 established that and proved
    /// reachability by probe rather than by fixture. What CAN be gated is the
    /// rendering: given a disagreement, does the reader learn anything it can
    /// act on? R311y680's answer was a bare count, which is the same for a
    /// packet index that moved and a flow key that did.
    #[test]
    fn a_disagreement_names_the_message_and_the_axis_in_both_renderings() {
        let flow = sample_flow();
        let note = FieldNote::Disagreement {
            flow,
            count: 3,
            named: vec![
                Disagreed {
                    at: 7,
                    why: Disagreement::Absent,
                },
                Disagreed {
                    at: 9,
                    why: Disagreement::Coordinates(Axes {
                        direction: true,
                        index: true,
                        ..Default::default()
                    }),
                },
            ],
        };

        let text = note.to_text();
        // The COUNT is exact and unaffected by the bound on the detail below it.
        assert!(
            text.contains("3 message(s) skipped"),
            "the exact count leads: {text}"
        );
        assert!(
            text.contains("packet 7: the second read has no packet at this index"),
            "an absent packet is named as absent: {text}"
        );
        assert!(
            text.contains("packet 9: the packet disagrees about: direction, index"),
            "and a packet that is there names every axis it disagrees on: {text}"
        );

        let json = note.to_json();
        serde_json::from_str::<serde_json::Value>(&json).expect("a note is one JSON value");
        assert!(
            json.contains("\"kind\":\"disagreement\"") && json.contains("\"count\":3"),
            "the machine form carries the kind and the exact count: {json}"
        );
        assert!(
            json.contains("{\"at\":7,\"why\":\"absent\"}"),
            "and names the same messages the text did: {json}"
        );
        assert!(
            json.contains("{\"at\":9,\"why\":\"coordinates\",\"axes\":[\"direction\",\"index\"]}"),
            "with the axes as data rather than as prose: {json}"
        );
        // ONE FACT, TWO RENDERINGS: the sentence the text printed is the
        // sentence the consumer gets, from the same function.
        assert!(
            json.contains("\"note\":\"3 message(s) skipped"),
            "the note key is the text line's own sentence: {json}"
        );
    }

    /// One realistic instance of EVERY `FieldNote` kind, for measuring.
    ///
    /// The variable halves are produced by the same APIs the real producers
    /// call rather than typed out here: the refusal's `why` is what
    /// `FormatMap::declare` actually returns for a rule it rejects, and the
    /// `NotDecrypted` sentence is the one `decrypted_coordinates` builds. A
    /// sentence invented for a measurement measures the invention.
    fn one_of_every_note_kind() -> Vec<FieldNote> {
        use wz_capture::payload::formats::{DeclarationKind, FormatMap};
        let flow = sample_flow();
        let mut map = FormatMap::new();
        let refused = "demo/**=nosuchformat";
        let why = map
            .declare(refused)
            .expect_err("the fixture must name a format the map refuses")
            .to_string();
        vec![
            FieldNote::NotDecrypted {
                flow,
                why: "this flow's messages were decrypted, so their coordinates name the \
                      ciphertext record they came out of and the plaintext they were decoded \
                      from is not retained"
                    .to_string(),
            },
            FieldNote::NothingWalkable { flow },
            FieldNote::CaptureNotReread,
            FieldNote::PayloadRuleRefused {
                rule: refused.to_owned(),
                why,
            },
            FieldNote::PayloadDeclarationUnbound {
                declaration: "demo/**=json".to_owned(),
                kind: DeclarationKind::FormatRule,
            },
            FieldNote::Omitted { flow, count: 12 },
            FieldNote::Disagreement {
                flow,
                count: 3,
                named: vec![Disagreed {
                    at: 7,
                    why: Disagreement::Absent,
                }],
            },
        ]
    }

    /// R2129 (unregistered open-debt item 480) — EVERY note kind is in the
    /// measurement, and the compiler is what says so.
    ///
    /// The numbers themselves are in
    /// [`ten_times_the_traffic_is_the_same_field_notes_and_almost_the_same_bytes`],
    /// beside the denominator that makes them affordable. What this holds is the
    /// POPULATION: an eighth variant makes the match below non-exhaustive and
    /// the crate stops building, so a note kind cannot arrive unmeasured the way
    /// `FieldNote` itself arrived unmeasured beside item 302's two.
    #[test]
    fn the_field_note_prose_is_measured_and_every_kind_is_in_the_measurement() {
        let sample = one_of_every_note_kind();

        // THE POPULATION IS HELD BY THE COMPILER, not by this list's length. An
        // eighth variant makes this match non-exhaustive and the crate stops
        // building, which is a stronger verdict than any count asserted here.
        fn kind_of(note: &FieldNote) -> &'static str {
            match note {
                FieldNote::NotDecrypted { .. } => "not_decrypted",
                FieldNote::NothingWalkable { .. } => "nothing_walkable",
                FieldNote::CaptureNotReread => "capture_not_reread",
                FieldNote::PayloadRuleRefused { .. } => "payload_rule_refused",
                FieldNote::PayloadDeclarationUnbound { .. } => "payload_declaration_unbound",
                FieldNote::Omitted { .. } => "omitted",
                FieldNote::Disagreement { .. } => "disagreement",
            }
        }
        let covered: std::collections::BTreeSet<&str> = sample.iter().map(kind_of).collect();
        assert_eq!(
            covered.len(),
            sample.len(),
            "one instance per kind, no kind twice: {covered:?}"
        );

        for note in &sample {
            let json = note.to_json();
            let sentence = note.sentence();
            // ANTI-VACUITY: a note that rendered nothing would satisfy any
            // ratio below by being zero on both sides.
            assert!(
                json.len() > sentence.len() && !sentence.is_empty(),
                "{}: the JSON carries the sentence and more: {json}",
                kind_of(note)
            );
            // The sentence is carried VERBATIM, so the note key is not a second
            // spelling of the fields beside it -- the property item 302 found
            // the refusal row breaking, where `example` appeared twice.
            assert!(
                json.contains(&sentence.replace('\\', "\\\\")) || sentence.contains('"'),
                "{}: the JSON note key is the sentence itself: {json}",
                kind_of(note)
            );
        }

        // THE SENTENCE THIS PLANE'S DOC COMMENT WRITES, AS AN ASSERTION.
        //
        // Item 480 expected item 302's finding to repeat -- both of 302's row
        // kinds sat at a steady 63% prose -- and the measurement says it does
        // not. Left as prose, "16% to 76%" is a number that rots the first time
        // a sentence is reworded, which is the class open-debt item 530 is open
        // for. The SPREAD is what the finding actually is, so the spread is what
        // is held here: a plane whose kinds converged on one ratio would fail
        // this, and so would a doc comment that kept claiming they had not.
        let percents: Vec<usize> = sample
            .iter()
            .map(|n| n.sentence().len() * 100 / n.to_json().len())
            .collect();
        let low = *percents.iter().min().expect("a non-empty population");
        let high = *percents.iter().max().expect("a non-empty population");
        assert!(
            low < 25 && high > 70,
            "the kinds do NOT share one ratio -- a count-only sentence is cheap \
             and a remedy-bearing one is dear ({low}%..{high}%): {percents:?}"
        );
    }

    /// The `field_notes` array of a rendered JSON analysis, by bracket depth.
    ///
    /// Sliced rather than parsed because what is being measured is the BYTES
    /// this plane costs a consumer, and a parse would hand back a value whose
    /// length is a property of the parser.
    fn field_notes_plane(rendered: &str) -> &str {
        let key = "\"field_notes\":[";
        let start = rendered
            .find(key)
            .expect("a JSON analysis carries a field_notes plane")
            + key.len()
            - 1;
        let mut depth = 0usize;
        for (i, c) in rendered[start..].char_indices() {
            match c {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        return &rendered[start..start + i + 1];
                    }
                }
                _ => {}
            }
        }
        panic!("the field_notes array is not closed");
    }

    /// One flow carrying `messages` copies of the same zenoh datagram.
    fn one_flow_carrying(messages: usize) -> Vec<u8> {
        let packet = udp(&[0x01, 0x09, 0x3B, 0x11, 0x22, 0x33, 0x44]);
        let packets: Vec<_> = (0..messages)
            .map(|i| (0, 1_000_000 + i as u64, packet.as_slice()))
            .collect();
        wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &packets)
    }

    fn field_notes_of(capture: &[u8], limit: usize) -> String {
        let (rendered, _) = analyze_request(&Request {
            capture,
            keylog: None,
            format: Format::Json,
            per_flow: true,
            per_message: true,
            messages_per_flow: Some(limit),
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &[],
            payload_field_names: &[],
            serial_linktypes: &[],
            census: Census::default(),
            // The plane does not exist without this flag, and a run that forgot
            // it measures an EMPTY array without saying so -- the first draft of
            // this gate did exactly that and reported zero notes twice.
            per_field: true,
            bounded: false,
            health: false,
            select: None,
            csv: None,
        })
        .expect("the fixture reads");
        field_notes_plane(&rendered).to_owned()
    }

    /// R2129 (unregistered open-debt item 480) — THE `FieldNote` PLANE IS
    /// BOUNDED BY THE FLOW, NOT BY THE TRAFFIC.
    ///
    /// # The measurement this holds in place
    ///
    /// Item 480 asked what the `FieldNote` sentence costs and answered
    /// "unmeasured", as the sibling of item 302's two row kinds. Measured this
    /// round through the real renderers, one realistic instance per kind, as
    /// JSON bytes and the sentence inside them:
    ///
    /// ```text
    ///                not_decrypted: 257 / 171 (66%)
    ///             nothing_walkable: 158 /  69 (43%)
    ///           capture_not_reread: 108 /  69 (63%)
    ///         payload_rule_refused: 173 / 132 (76%)
    ///  payload_declaration_unbound: 161 / 120 (74%)
    ///                      omitted: 109 /  18 (16%)
    ///                 disagreement: 227 /  95 (41%)
    /// ```
    ///
    /// 1193 bytes carrying 674 of prose, 56% over the plane. Item 480 expected
    /// 302's shape to repeat and it does NOT: 302 found both its row kinds at a
    /// steady 63%, while these run from 16% to 76%. The cheap ones are cheap
    /// because their sentence is a count (`omitted`, 18 bytes) and the dear ones
    /// are dear because their sentence is the only place the remedy is written
    /// (`payload_rule_refused`). A single ratio would describe none of them.
    ///
    /// The rows are also SMALLER than 302's -- 108..257 against 326..400 -- so
    /// the plane is cheaper per row as well as narrower.
    ///
    /// # What makes it affordable, and what this gate catches
    ///
    /// The same thing 302 found: the DENOMINATOR. Every note is pushed once per
    /// flow, once per capture, or once per declaration the caller typed --
    /// never once per message. So ten times the traffic on one flow is the same
    /// note, and the plane may grow only by the digits of its counts: MEASURED,
    /// 3 messages against 30 on one flow is 109 bytes against 111, one note
    /// either way. That is asserted below end to end through `analyze_request`
    /// rather than on a hand-built value, because where a note is PUSHED is the
    /// property at risk and a constructed note cannot show it.
    ///
    /// The one variant that carries a per-message list, `Disagreement.named`,
    /// takes the same `--max-messages` bound as the rows; R311y681's test below
    /// is what holds that, and this gate is the other half.
    #[test]
    fn ten_times_the_traffic_is_the_same_field_notes_and_almost_the_same_bytes() {
        let small = field_notes_of(&one_flow_carrying(3), 1);
        let large = field_notes_of(&one_flow_carrying(30), 1);

        // ANTI-VACUITY, in the shape this round needed twice: the first draft
        // of this gate left `per_field` off and both sides were `[]`, which
        // satisfies every equality below. A population of zero is a dead probe
        // and an exit code cannot tell it from a negative result.
        let rows = small.matches("\"kind\":").count();
        assert!(rows >= 1, "the fixture must produce a note at all: {small}");
        assert!(
            small.contains("\"kind\":\"omitted\"") && small.contains("\"count\":2"),
            "and it must be the bound's own note, with the exact count: {small}"
        );
        assert!(
            large.contains("\"count\":29"),
            "ten times the traffic is ten times the omission: {large}"
        );

        assert_eq!(
            large.matches("\"kind\":").count(),
            rows,
            "ten times the traffic on ONE flow is the SAME note -- a note keyed \
             on anything per-message would render ten times the rows here: \
             {large}"
        );
        let grew = large.len() - small.len();
        assert!(
            grew <= 4 * rows,
            "the plane may grow only by the digits of its counts ({} -> {} is \
             +{grew} for {rows} note(s)): {large}",
            small.len(),
            large.len()
        );
    }

    /// R311y681 (§1.1n) — the per-message detail takes the same bound as the
    /// rows, and the COUNT never does.
    ///
    /// A listing that named every disagreement would be a second unbounded
    /// accumulation in a crate whose whole discipline is that every bound has a
    /// paired counter. So the detail is bounded and the count is exact, and this
    /// is what says the two are not the same number.
    #[test]
    fn naming_the_disagreements_is_bounded_and_counting_them_is_not() {
        let mut named = Vec::new();
        let mut count = 0usize;
        for at in 0..5 {
            note_disagreement(&mut named, &mut count, Some(2), at, Disagreement::Absent);
        }
        assert_eq!(count, 5, "every disagreement is counted");
        assert_eq!(named.len(), 2, "and only the first two are named");
        assert_eq!(
            named.iter().map(|d| d.at).collect::<Vec<_>>(),
            vec![0, 1],
            "the ones named are the ones nearest the start of the flow"
        );

        // Unbounded means unbounded.
        let mut named = Vec::new();
        let mut count = 0usize;
        for at in 0..5 {
            note_disagreement(&mut named, &mut count, None, at, Disagreement::Absent);
        }
        assert_eq!((count, named.len()), (5, 5), "no cap, no omission");
    }
}

// R311y856 — the built-in decoders and the declaration DIALECT moved to
// `wz_capture::payload::formats`. R311y699 put them here on the rule that a
// format decoder grows a third-party dependency an MCU profile cannot carry;
// that rule is right and it did not describe `Protobuf`, which is a
// hand-written varint walk and takes none. What the misplacement cost was
// measured by `analysis_surface_parity.py`: the C ABI could not decode a
// payload, because the registry lived in a binary it must not depend on
// (this one carries `wz-tls-record`, and through it `ring`).
//
// The alias keeps this file's own call sites reading as they did.
use wz_capture::payload::formats as payload_formats;
#[cfg(test)]
mod quic_pass_tests {
    use super::*;
    use wz_tls_record::quic::fixture::{
        application_secret, client_hello, crypto_frame, datagram_frame, log_text, long_header,
        protect, short_header, stream_frame, ICID, SCID,
    };
    use wz_tls_record::quic::{QuicKeys, QuicVersion};
    use wz_tls_record::Suite;

    /// One UDP datagram of a QUIC connection, in the direction `from_client`
    /// says. Ethernet/IPv4, ports 51000 and 4433.
    fn udp(from_client: bool, payload: &[u8]) -> Vec<u8> {
        let (src, dst) = if from_client {
            (51000u16, 4433u16)
        } else {
            (4433u16, 51000u16)
        };
        let mut udp = Vec::new();
        udp.extend_from_slice(&src.to_be_bytes());
        udp.extend_from_slice(&dst.to_be_bytes());
        udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(payload);

        let (from, to) = if from_client {
            ([10u8, 0, 0, 1], [10u8, 0, 0, 2])
        } else {
            ([10u8, 0, 0, 2], [10u8, 0, 0, 1])
        };
        let mut ip = vec![0x45u8, 0];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        ip.extend_from_slice(&from);
        ip.extend_from_slice(&to);
        ip.extend_from_slice(&udp);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        while eth.len() < 60 {
            eth.push(0);
        }
        eth
    }

    /// The connection every test here reads: a client Initial carrying a
    /// ClientHello, a server Initial, and one 1-RTT packet in each direction —
    /// the client's a STREAM frame, the server's an RFC 9221 DATAGRAM.
    ///
    /// Returned as (capture, key log text, the client's stream bytes).
    fn quic_capture(random: &[u8; 32]) -> (Vec<u8>, String, &'static [u8]) {
        let (client_initial, server_initial) = QuicKeys::initial(QuicVersion::V1, &ICID);
        let hello = client_hello(random);

        let first = crypto_frame(0, &hello);
        let (h, o) = long_header(0, &ICID, &[], first.len(), 0);
        let client_initial_packet = protect(&client_initial, 0, &h, o, &first);

        let reply = crypto_frame(0, b"\x02\x00\x00\x04....");
        let (h, o) = long_header(0, &[], &SCID, reply.len(), 0);
        let server_initial_packet = protect(&server_initial, 0, &h, o, &reply);

        const STREAM: &[u8] = b"a zenoh session over quic";
        let client_keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let payload = stream_frame(0, 0, STREAM);
        let (h, o) = short_header(&SCID, 1);
        let client_one_rtt = protect(&client_keys, 1, &h, o, &payload);

        let server_keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(true, 0));
        let payload = datagram_frame(b"a batch");
        // The server's short header is addressed to the CLIENT's connection ID,
        // which this fixture leaves empty -- so its packet number begins at one.
        let (h, o) = short_header(&[], 1);
        let server_one_rtt = protect(&server_keys, 1, &h, o, &payload);

        let packets = [
            udp(true, &client_initial_packet),
            udp(false, &server_initial_packet),
            udp(true, &client_one_rtt),
            udp(false, &server_one_rtt),
        ];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        (capture, log_text(random, 1), STREAM)
    }

    /// R311y718 (§1.2a) — the same connection, carrying REAL ZENOH.
    ///
    /// # Why a second fixture rather than a change to the first
    ///
    /// [`quic_capture`]'s stream is the literal `a zenoh session over quic`,
    /// which is not zenoh: its first two bytes read as a little-endian length
    /// prefix of 8 289, so a framer takes them and waits forever. That makes it
    /// the NEGATIVE arm this round needs — recovered bytes that reach a framer
    /// and yield nothing — and it is only worth keeping while something else
    /// shows the positive one.
    ///
    /// So this is the positive one: the same four packets, with zenoh's own
    /// length-prefixed batch framing inside the STREAM frames. Two messages
    /// from the client and one back, on QUIC stream 0 — which is the stream
    /// zenoh's link actually uses, since it opens exactly one bidirectional
    /// stream per link (`zenoh-link-quic/src/unicast.rs:330`) and a
    /// client-initiated bidi stream is id 0.
    ///
    /// Returned as (capture, key log text, messages the fixture sent).
    fn zenoh_over_quic_capture(random: &[u8; 32]) -> (Vec<u8>, String, usize) {
        /// A framed unit: `u16` little-endian length, then the message. The
        /// same shape `framed` builds one module over, written out here so the
        /// fixture does not borrow the reader's own opinion of the framing.
        fn unit(message: &[u8]) -> Vec<u8> {
            let mut out = (message.len() as u16).to_le_bytes().to_vec();
            out.extend_from_slice(message);
            out
        }

        let (client_initial, server_initial) = QuicKeys::initial(QuicVersion::V1, &ICID);
        let hello = client_hello(random);

        let first = crypto_frame(0, &hello);
        let (h, o) = long_header(0, &ICID, &[], first.len(), 0);
        let client_initial_packet = protect(&client_initial, 0, &h, o, &first);

        let reply = crypto_frame(0, b"\x02\x00\x00\x04....");
        let (h, o) = long_header(0, &[], &SCID, reply.len(), 0);
        let server_initial_packet = protect(&server_initial, 0, &h, o, &reply);

        // `0x04` is the KeepAlive MID with every flag clear. Two of them from
        // the client so the test can tell "the framer ran" from "the framer
        // decoded the one message that happened to start at offset zero".
        let mut client_stream = unit(&[0x04]);
        client_stream.extend_from_slice(&unit(&[0x04]));
        let client_keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let payload = stream_frame(0, 0, &client_stream);
        let (h, o) = short_header(&SCID, 1);
        let client_one_rtt = protect(&client_keys, 1, &h, o, &payload);

        let server_stream = unit(&[0x04]);
        let server_keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(true, 0));
        // The SAME stream id in the other direction: one bidirectional stream
        // is one id, and the two halves are what make it an exchange.
        let payload = stream_frame(0, 0, &server_stream);
        let (h, o) = short_header(&[], 1);
        let server_one_rtt = protect(&server_keys, 1, &h, o, &payload);

        let packets = [
            udp(true, &client_initial_packet),
            udp(false, &server_initial_packet),
            udp(true, &client_one_rtt),
            udp(false, &server_one_rtt),
        ];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        (capture, log_text(random, 1), 3)
    }

    /// R311y709 (Y2) — the same connection, captured AFTER its handshake.
    ///
    /// The two Initial packets are simply absent, which is what a tap started
    /// on a running deployment produces. Nothing in what remains carries the
    /// connection id length, the version, or the ClientHello random.
    fn mid_connection_quic_capture(random: &[u8; 32]) -> (Vec<u8>, String, &'static [u8]) {
        const STREAM: &[u8] = b"a zenoh session over quic";
        let client_keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let payload = stream_frame(0, 0, STREAM);
        let (h, o) = short_header(&SCID, 1);
        let client_one_rtt = protect(&client_keys, 1, &h, o, &payload);

        let packets = [udp(true, &client_one_rtt)];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        (capture, log_text(random, 1), STREAM)
    }

    /// R311y709 (Y2) — A MID-CONNECTION CAPTURE OPENS ONLY ONCE THE LENGTH IS
    /// DECLARED, AND THE FLAG IS WHAT DECLARES IT.
    ///
    /// Both arms run the same bytes through the same public entry point and
    /// differ in ONE option, which is what makes this a test of the wiring
    /// rather than of the opener — that half is pinned in `wz-tls-record`. The
    /// failure this guards is the one R311y669 measured on `--max-messages` and
    /// R311y698's own register recorded again: a flag the parser reads and
    /// nothing acts on.
    ///
    /// `--quic` is on BOTH arms. Without it neither is recognised as QUIC at all
    /// (a short header cannot establish a flow — `wz_capture::quic`'s whole
    /// reason for being flow-scoped), so leaving it off the first arm would make
    /// the difference between the arms two options instead of one.
    #[test]
    fn a_mid_connection_quic_capture_opens_only_once_the_length_is_declared() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(2));
        let (capture, keylog, stream) = mid_connection_quic_capture(&random);

        let run = |cid_len| {
            analyze_request(&Request {
                capture: &capture,
                keylog: Some(keylog.as_bytes()),
                format: Format::Text,
                per_flow: false,
                per_message: false,
                messages_per_flow: None,
                quic_ports: &[4433],
                quic_cid_len: cid_len,
                payload_rules: &[],
                payload_field_names: &[],
                serial_linktypes: &[],
                census: Census::default(),
                per_field: false,
                bounded: false,
                health: false,
                select: None,
                csv: None,
            })
            .expect("the capture reads")
            .0
        };

        // THE POPULATION: without the declaration the flow is QUIC and shut.
        let undeclared = run(None);
        assert!(
            undeclared.contains("QUIC: 1 flow(s)"),
            "the flow must be recognised on both arms or the difference is not \
             the length: {undeclared}"
        );
        assert!(
            undeclared.contains("NOT DECRYPTED"),
            "and unopened, which is the state this round moves: {undeclared}"
        );

        // THE SAME BYTES, WITH THE LENGTH DECLARED.
        let declared = run(Some(SCID.len()));
        assert!(
            declared.contains("packet(s) opened"),
            "the declared length opens the 1-RTT packet: {declared}"
        );
        assert!(
            declared.contains(&format!("{} stream byte(s)", stream.len())),
            "and the application bytes are accounted for: {declared}"
        );
    }

    /// R311y710 (Y2) — AN ASSUMED IDENTITY IS REPORTED AS ONE, IN EVERY PLACE
    /// A READER LOOKS.
    ///
    /// ## The defect this closes, which R311y709 created
    ///
    /// `client_hello_seen` was filled from `opener.client_random().is_some()`.
    /// Adoption sets that random from a key log on a flow whose ClientHello this
    /// reader never saw, so a mid-connection capture reported "a ClientHello was
    /// read" -- a confident wrong statement of exactly the kind this whole crate
    /// exists to end, introduced by the round that added the feature.
    ///
    /// ## Why all three surfaces, and both arms
    ///
    /// The per-flow listing is behind `--flows`; the summary line is what a
    /// person sees first; the JSON is what a consumer branches on. A premise
    /// visible in one of the three is a premise most readers never see.
    ///
    /// The handshake capture is the other arm and it is not decoration: every
    /// assertion below is about a sentence being ABSENT on it, and a reader who
    /// only saw the adopted arm could not tell a correct report from one that
    /// says "assumed" about everything.
    #[test]
    fn an_assumed_identity_is_never_reported_as_a_clienthello() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(2));
        let (mid, keylog, _) = mid_connection_quic_capture(&random);
        let (whole, whole_log, _) = quic_capture(&random);

        let run = |capture: &[u8], log: &str, cid_len, format| {
            analyze_request(&Request {
                capture,
                keylog: Some(log.as_bytes()),
                format,
                per_flow: true,
                per_message: false,
                messages_per_flow: None,
                quic_ports: &[4433],
                quic_cid_len: cid_len,
                payload_rules: &[],
                payload_field_names: &[],
                serial_linktypes: &[],
                census: Census::default(),
                per_field: false,
                bounded: false,
                health: false,
                select: None,
                csv: None,
            })
            .expect("the capture reads")
            .0
        };

        // THE ADOPTED ARM.
        let text = run(&mid, &keylog, Some(SCID.len()), Format::Text);
        assert!(
            text.contains("1 flow(s) opened on an ASSUMED identity"),
            "the SUMMARY must carry the premise: {text}"
        );
        assert!(
            text.contains("keys ASSUMED"),
            "and so must the per-flow listing: {text}"
        );
        assert!(
            !text.contains("a ClientHello was read"),
            "and NOTHING may claim a ClientHello was read, because none was: {text}"
        );
        let json = run(&mid, &keylog, Some(SCID.len()), Format::Json);
        assert!(
            json.contains("\"client_hello\":false,\"identity_adopted\":true"),
            "the two facts are held apart in the JSON, and the first is FALSE \
             here -- which is the exact field R311y709 made into a lie: {json}"
        );
        assert!(
            json.contains("\"flows_identity_adopted\":1"),
            "and the capture-wide object counts it: {json}"
        );

        // THE OTHER ARM: a capture that really did carry its handshake.
        let text = run(&whole, &whole_log, None, Format::Text);
        assert!(
            !text.contains("ASSUMED"),
            "a flow whose ClientHello was read must not be called assumed: {text}"
        );
        assert!(
            text.contains("keys installed from the log"),
            "it is evidence, and says so: {text}"
        );
        let json = run(&whole, &whole_log, None, Format::Json);
        assert!(
            json.contains("\"client_hello\":true,\"identity_adopted\":false"),
            "with the two facts the other way round: {json}"
        );
        assert!(
            json.contains("\"flows_identity_adopted\":0"),
            "and the count at zero rather than the key absent: {json}"
        );
    }

    /// R311y698 (§1.2a) — THE CALLER EXISTS. A QUIC capture and a key log go in
    /// at the command line and the session's bytes come out.
    ///
    /// ## What this is the test for
    ///
    /// Every primitive under it had a test and no caller: the store's register
    /// recorded the whole QUIC section as "reachable only by writing Rust, which
    /// is the shape `wz-analyze` was created to end". A unit test of a decryptor
    /// cannot catch a decryptor nobody runs -- measured at R311y664, where
    /// building this binary exposed two false statements that four rounds of
    /// unit tests had not.
    ///
    /// So this drives the PUBLIC entry point with bytes, exactly as the binary
    /// does, and asserts on the rendering a person reads.
    #[test]
    fn a_quic_capture_and_a_key_log_yield_the_session_at_the_command_line() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(7));
        let (capture, keylog, stream) = quic_capture(&random);

        let (rendered, outcome) = analyze(&capture, Some(keylog.as_bytes())).expect("it reads");

        // The SENTENCE a person sees, which said "NOT DECRYPTED (this reader
        // recognises QUIC and opens none of it)" for every capture until this
        // round -- a confident statement that became false the moment a caller
        // existed.
        assert!(
            rendered.contains("4 of 4 packet(s) opened"),
            "every packet opens: {rendered}"
        );
        assert!(
            !rendered.contains("NOT DECRYPTED"),
            "and the old sentence is gone: {rendered}"
        );
        assert!(
            rendered.contains("stream/0: 25 byte(s)"),
            "the client's stream is listed with its length: {rendered}"
        );
        assert_eq!(stream.len(), 25, "which is the length the fixture sent");
        assert!(
            rendered.contains("crypto/initial"),
            "and the handshake stream is its own sequence: {rendered}"
        );
        assert!(
            rendered.contains("keys installed from the log"),
            "the ClientHello random found this connection in the log: {rendered}"
        );
        // R311y705 — AND THE VERDICT, WHICH THIS TEST GOT WRONG.
        //
        // R311y698 asserted `outcome.complete` here, on the rule it had just
        // moved: "a flow whose every packet opened IS the rows". That rule is
        // the TLS half's and it is EARNED there, because `PlaintextSink` hands
        // the recovered plaintext to the session and the rows exist. It is not
        // earned here: this pass reassembles the stream, records its LENGTH --
        // the `25 byte(s)` asserted eight lines up -- and drops the bytes.
        // Nothing in this build decodes zenoh out of them.
        //
        // So the capture IS a shortfall, and by the sharpest possible measure:
        // its application traffic was decrypted and then not read. Everything
        // else this test asserts stayed true; only the conclusion drawn from
        // them was wrong.
        assert!(
            !outcome.complete,
            "25 recovered application bytes that nothing decoded are a floor, \
             however cleanly the packets opened: {rendered}"
        );
        assert!(
            rendered.contains("were recovered and NOT decoded"),
            "and the reader is TOLD, in the rendering they read rather than \
             only in a bool: {rendered}"
        );
        // THE CONTROL that keeps the leg above from being a constant: a
        // decryption that recovered only HANDSHAKE bytes is not short by them.
        // Those are the TLS handshake inside QUIC, they carry no zenoh, and
        // they are what the key schedule was derived from.
        let handshake_only = wz_capture::quic::QuicDecryption {
            flows_offered: 1,
            flows_opened: 1,
            packets: 1,
            packets_opened: 1,
            crypto_bytes: 41,
            ..Default::default()
        };
        assert!(
            handshake_only.stream_bytes == 0 && handshake_only.datagram_bytes == 0,
            "the control must differ from the case above in the application \
             bytes and nothing else"
        );
    }

    /// R311y718 (§1.2a) — THE ZENOH INSIDE A QUIC STREAM IS DECODED, and the
    /// verdict stops calling the capture short by bytes it has now read.
    ///
    /// ## What was open, in the words of the code that was wrong
    ///
    /// `report.rs`'s verdict carried the paragraph "the pass reassembles the
    /// streams, records their LENGTHS, and drops the bytes. Nothing in this
    /// workspace decodes zenoh out of them", and the register carried the seam
    /// as needing a `wz-capture` structural change. Both were accurate: the
    /// analyzer recovered 25 application bytes out of the QUIC fixture and
    /// reported `messages decoded: 0` beside them.
    ///
    /// ## The three legs, and why each is here
    ///
    /// 1. ANTI-VACUITY FIRST. The fixture must be QUIC to the RECOGNISER, not
    ///    merely to its author — R311y698 shipped a fixture no recogniser
    ///    accepted and nine unit tests passed over it while the capture layer
    ///    decoded the whole connection as zenoh. So the QUIC sentence is
    ///    asserted before anything is claimed about what came out of it.
    /// 2. THE MESSAGES. Three, from two directions of ONE bidirectional stream,
    ///    which is the arrangement zenoh's link produces.
    /// 3. THE VERDICT REASON, BY NAME. `complete` alone would pass on any
    ///    capture with no shortfall at all; naming `QuicBytesNobodyDecodes` is
    ///    what ties this test to the leg it closes, and it is the shape
    ///    R311y716 made possible by turning the verdict into a set of reasons.
    #[test]
    fn the_zenoh_inside_a_quic_stream_is_decoded_and_no_longer_counts_as_unread() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(9).wrapping_add(4));
        let (capture, keylog, sent) = zenoh_over_quic_capture(&random);

        let (rendered, outcome) = analyze(&capture, Some(keylog.as_bytes())).expect("it reads");

        // (1) The capture is QUIC to the reader, and every packet opened. Both
        // halves matter: a fixture the recogniser refused would be read as
        // zenoh straight off the wire and leg (2) would pass for the wrong
        // reason entirely.
        assert!(
            rendered.contains("4 of 4 packet(s) opened"),
            "the fixture is QUIC and it opens: {rendered}"
        );

        // (2) THE ROUND: the zenoh inside the stream reached a decoder.
        assert_eq!(sent, 3, "the fixture sent three messages");
        assert!(
            rendered.contains("messages decoded: 3"),
            "all three, over both directions of stream 0: {rendered}"
        );

        // (3) And the floor lifted for the right reason, named.
        assert!(
            !outcome
                .reasons
                .contains(&wz_capture::report::VerdictReason::QuicBytesNobodyDecodes),
            "the bytes were decoded, so this reason must be gone -- reasons: {:?}",
            outcome.reasons
        );
        // R311y727 (N19) -- and the WHOLE list, which an absence claim about
        // one leg cannot give: it says nothing about the other twenty-two.
        assert_eq!(
            outcome.reasons,
            Vec::new(),
            "and NOTHING else is short about this capture either"
        );
        assert!(
            !rendered.contains("were recovered and NOT decoded"),
            "and the sentence with it: {rendered}"
        );

        // THE CONTROL, and it is the fixture one function up: the same four
        // packets carrying bytes that are NOT zenoh. They reach the same framer
        // through the same seam and decode nothing, and the verdict must still
        // say so -- otherwise leg (3) would be passing because the seam counts
        // an OFFER as a read.
        let (control, control_log, control_stream) = quic_capture(&random);
        let (control_rendered, control_outcome) =
            analyze(&control, Some(control_log.as_bytes())).expect("it reads");
        assert!(
            control_outcome
                .reasons
                .contains(&wz_capture::report::VerdictReason::QuicBytesNobodyDecodes),
            "bytes fed to a framer that decoded nothing are still a floor: \
             {control_rendered}"
        );
        // BY NUMBER, and this is the assertion that pins "an offer is not a
        // read": the control's stream reached a framer in full, so `bytes_fed`
        // covers it -- and every one of those bytes is still unread, so
        // `bytes_undecoded` covers it too. A seam that counted the offer would
        // leave the second at zero and the capture would report itself whole.
        let control_json = analyze_request(&Request {
            capture: &control,
            keylog: Some(control_log.as_bytes()),
            format: Format::Json,
            per_flow: false,
            per_message: false,
            messages_per_flow: None,
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &[],
            payload_field_names: &[],
            serial_linktypes: &[],
            census: Census::default(),
            per_field: false,
            bounded: false,
            health: false,
            select: None,
            csv: None,
        })
        .expect("the capture reads")
        .0;
        assert!(
            control_json.contains(&format!("\"bytes_undecoded\":{}", control_stream.len()))
                && control_json
                    .contains(&format!("\"application_unread\":{}", control_stream.len())),
            "every byte of the control's stream reached a framer and every one \
             of them is still unread, and the verdict's own number says so: \
             {control_json}"
        );
    }

    /// R311y718 (§1.2a / [REDACTED-REQ]) — A NODE INSIDE A QUIC STREAM IS NAMED BY ITS
    /// ZID, which is the plane wiring driven rather than merely written.
    ///
    /// ## Why this test and not a second message-count assertion
    ///
    /// Four census planes walk the datagram table — throughput, exchanges,
    /// payloads, nodes — and each named `flow.frames` directly, so a new list
    /// reached whichever the author remembered. This workspace has shipped that
    /// exact omission four times (R311y668, y678, y699, y700), twice in
    /// consecutive rounds, and the lesson recorded each time was the same: WIRED
    /// IS NOT DRIVEN. So the round closes with a plane driven end to end, and
    /// the node census is the one worth driving — a `quic/...` deployment is
    /// precisely the case where every node identity is inside the encryption,
    /// and a census that missed it would report a whole fleet as having no
    /// participants.
    #[test]
    fn a_node_whose_init_is_inside_a_quic_stream_is_named_by_the_census() {
        /// One length-prefixed INIT naming `zid`, in zenoh's own wire shape.
        fn framed_init(zid: &[u8]) -> Vec<u8> {
            let mut wire = vec![
                wz_session_core::wire_const::T_MID_INIT,
                0x09,
                (((zid.len() as u8) - 1) << 4) | 0x02,
            ];
            wire.extend_from_slice(zid);
            let mut out = (wire.len() as u16).to_le_bytes().to_vec();
            out.extend_from_slice(&wire);
            out
        }

        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(6));
        const ZID: &[u8] = &[0x51, 0x52, 0x53, 0x54];

        let (client_initial, server_initial) = QuicKeys::initial(QuicVersion::V1, &ICID);
        let hello = client_hello(&random);
        let first = crypto_frame(0, &hello);
        let (h, o) = long_header(0, &ICID, &[], first.len(), 0);
        let client_initial_packet = protect(&client_initial, 0, &h, o, &first);

        let reply = crypto_frame(0, b"\x02\x00\x00\x04....");
        let (h, o) = long_header(0, &[], &SCID, reply.len(), 0);
        let server_initial_packet = protect(&server_initial, 0, &h, o, &reply);

        let client_keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let payload = stream_frame(0, 0, &framed_init(ZID));
        let (h, o) = short_header(&SCID, 1);
        let client_one_rtt = protect(&client_keys, 1, &h, o, &payload);

        let packets = [
            udp(true, &client_initial_packet),
            udp(false, &server_initial_packet),
            udp(true, &client_one_rtt),
        ];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        let keylog = log_text(&random, 1);

        let rendered = analyze_request(&Request {
            capture: &capture,
            keylog: Some(keylog.as_bytes()),
            format: Format::Text,
            per_flow: false,
            per_message: false,
            messages_per_flow: None,
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &[],
            payload_field_names: &[],
            serial_linktypes: &[],
            census: Census {
                nodes: true,
                ..Census::default()
            },
            per_field: false,
            bounded: false,
            health: false,
            select: None,
            csv: None,
        })
        .expect("the capture reads")
        .0;

        // ANTI-VACUITY: the fixture is QUIC to the recogniser and its packets
        // opened. Without this the assertion below could pass off a capture
        // read as plain zenoh straight from the wire, which is the misread
        // R311y669 closed and R311y698 nearly reintroduced through a fixture.
        assert!(
            rendered.contains("3 of 3 packet(s) opened"),
            "the fixture is QUIC and it opens: {rendered}"
        );
        // THE PLANE: the zid the Init carried, reached through the QUIC stream.
        assert!(
            rendered.contains("51525354"),
            "the node census names the zid that was inside the QUIC stream: \
             {rendered}"
        );

        // AND THE FIELD LAYER, which is a SECOND plane with a second seam --
        // the sink, not the frame lists -- so it needs its own drive. A
        // `--fields` run over a QUIC capture printed nothing before this round
        // and said nothing about why.
        let fields = analyze_request(&Request {
            capture: &capture,
            keylog: Some(keylog.as_bytes()),
            format: Format::Text,
            per_flow: false,
            per_message: false,
            messages_per_flow: None,
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &[],
            payload_field_names: &[],
            serial_linktypes: &[],
            census: Census::default(),
            per_field: true,
            bounded: false,
            health: false,
            select: None,
            csv: None,
        })
        .expect("the capture reads")
        .0;
        assert!(
            fields.contains("Init"),
            "the field walk names the message it found inside the QUIC \
             stream: {fields}"
        );
    }

    /// R311y719 (§1.2a) — THE RFC 9221 DATAGRAM HALF, which R311y718 closed the
    /// stream half beside and left in the unread floor.
    ///
    /// ## Why this is a second seam and not the same one
    ///
    /// zenoh has TWO QUIC links and they are different transports, read out of
    /// the reference rather than inferred: `transport-link-quic` is streamed
    /// (`zenoh-link-quic/src/unicast.rs:184`) and `transport-link-quic-datagram`
    /// is not (`zenoh-link-quic_datagram/src/unicast.rs:164`). The first needs a
    /// framer with memory across offers; the second sends one whole batch per
    /// RFC 9221 frame, unordered and never retransmitted, which is why the
    /// opener does not reassemble those and why they take the datagram path
    /// through this crate exactly as a multicast batch does.
    ///
    /// ## The trap this test also pins
    ///
    /// The decoded messages land in `quic_datagrams` and NOT beside the
    /// cleartext ones, even though the two share a coordinate. One consumer
    /// resolves that coordinate by re-reading the packet from the file, and for
    /// these the packet holds CIPHERTEXT -- so folding the lists would have the
    /// field walk print names read out of protected bytes. The last assertion
    /// here is that the walk names the message from the SINK instead.
    #[test]
    fn a_zenoh_batch_inside_an_rfc_9221_datagram_is_decoded() {
        use wz_tls_record::quic::fixture::datagram_frame;

        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        const ZID: &[u8] = &[0x61, 0x62, 0x63, 0x64];

        // An INIT as a datagram link carries it: NO length prefix, because the
        // datagram IS the framing unit. Getting this wrong is the difference
        // between one decoded message and none.
        let init = {
            let mut wire = vec![
                wz_session_core::wire_const::T_MID_INIT,
                0x09,
                (((ZID.len() as u8) - 1) << 4) | 0x02,
            ];
            wire.extend_from_slice(ZID);
            wire
        };

        let (client_initial, server_initial) = QuicKeys::initial(QuicVersion::V1, &ICID);
        let hello = client_hello(&random);
        let first = crypto_frame(0, &hello);
        let (h, o) = long_header(0, &ICID, &[], first.len(), 0);
        let client_initial_packet = protect(&client_initial, 0, &h, o, &first);

        let reply = crypto_frame(0, b"\x02\x00\x00\x04....");
        let (h, o) = long_header(0, &[], &SCID, reply.len(), 0);
        let server_initial_packet = protect(&server_initial, 0, &h, o, &reply);

        let client_keys = QuicKeys::derive(Suite::Aes128GcmSha256, &application_secret(false, 0));
        let payload = datagram_frame(&init);
        let (h, o) = short_header(&SCID, 1);
        let client_one_rtt = protect(&client_keys, 1, &h, o, &payload);

        let packets = [
            udp(true, &client_initial_packet),
            udp(false, &server_initial_packet),
            udp(true, &client_one_rtt),
        ];
        let refs: Vec<(u32, u64, &[u8])> = packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, 1_000_000 + i as u64 * 100, p.as_slice()))
            .collect();
        let capture = wz_capture::pcapng::write(&[(wz_capture::link::LINKTYPE_ETHERNET, 6)], &refs);
        let keylog = log_text(&random, 1);

        let run = |per_field, census| {
            analyze_request(&Request {
                capture: &capture,
                keylog: Some(keylog.as_bytes()),
                format: Format::Text,
                per_flow: false,
                per_message: false,
                messages_per_flow: None,
                quic_ports: &[],
                quic_cid_len: None,
                payload_rules: &[],
                payload_field_names: &[],
                serial_linktypes: &[],
                census,
                per_field,
                bounded: false,
                health: false,
                select: None,
                csv: None,
            })
            .expect("the capture reads")
            .0
        };

        let rendered = run(
            false,
            Census {
                nodes: true,
                ..Census::default()
            },
        );
        // ANTI-VACUITY: QUIC to the recogniser, and opened.
        assert!(
            rendered.contains("3 of 3 packet(s) opened"),
            "the fixture is QUIC and it opens: {rendered}"
        );
        // THE ROUND: the batch inside the DATAGRAM frame decoded.
        assert!(
            rendered.contains("messages decoded: 1"),
            "the zenoh inside the RFC 9221 datagram is decoded: {rendered}"
        );
        // And it reached a plane, by the identity only that message carries.
        assert!(
            rendered.contains("61626364"),
            "the node census names the zid the datagram carried: {rendered}"
        );
        // The floor lifted, by name.
        let (_, outcome) = analyze(&capture, Some(keylog.as_bytes())).expect("it reads");
        assert!(
            !outcome
                .reasons
                .contains(&wz_capture::report::VerdictReason::QuicBytesNobodyDecodes),
            "the datagram bytes were read, so this reason must be gone: {:?}",
            outcome.reasons
        );
        // R311y727 (N19) -- and the WHOLE list, which an absence claim about
        // one leg cannot give: it says nothing about the other twenty-two.
        assert_eq!(
            outcome.reasons,
            Vec::new(),
            "and NOTHING else is short about this capture either"
        );
        // AND THE FIELD WALK reads the SINK's copy rather than re-reading the
        // packet, which holds the QUIC ciphertext.
        let fields = run(true, Census::default());
        assert!(
            fields.contains("Init"),
            "the field walk names the message, not the protected bytes: {fields}"
        );
    }

    /// R311y706 (Y5) — THE TWO THINGS THE QUIC LISTING DID NOT DO, both driven
    /// through the analyzer over a real capture.
    ///
    /// ## The bound
    ///
    /// `--max-messages` reached the field rows, the message listing and the
    /// datagram rows and stopped at this one, so a capture with many QUIC
    /// streams printed all of them under a flag that said otherwise. It now
    /// takes the same ceiling, and the ceiling REPORTS ITSELF — this crate's
    /// rule for every bound that bites, because a listing short by rows nobody
    /// accounted for is a listing that looks whole.
    ///
    /// ## The selector
    ///
    /// The register carried "--select does not reach the QUIC pass" and
    /// measuring narrowed it: every `Filter` term is about a DECODED RECORD,
    /// and this reader has decoded none of a QUIC flow's. So the selector is
    /// inapplicable rather than unwired, and what was missing is a sentence — a
    /// reader who typed `--select` and saw QUIC rows had every reason to read
    /// them as selected ones.
    #[test]
    fn the_quic_listing_takes_the_bound_and_says_the_selector_did_not_reach_it() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(7));
        let (capture, keylog, _) = quic_capture(&random);

        let request = |messages_per_flow, select| Request {
            capture: &capture,
            keylog: Some(keylog.as_bytes()),
            format: Format::Text,
            per_flow: false,
            per_message: false,
            messages_per_flow,
            quic_ports: &[],
            quic_cid_len: None,
            payload_rules: &[],
            payload_field_names: &[],
            serial_linktypes: &[],
            census: Census::default(),
            per_field: false,
            bounded: false,
            health: false,
            select,
            csv: None,
        };

        // UNBOUNDED: the fixture's flow carries more than one sequence, or the
        // bound below would have nothing to bite on and the claim would be
        // about a listing that was already short.
        let (whole, _) = analyze_request(&request(None, None)).expect("it reads");
        let sequences = whole
            .lines()
            .filter(|l| l.contains(" byte(s)") && l.contains(": "))
            .count();
        assert!(
            sequences >= 2,
            "the fixture must list at least two sequences: {whole}"
        );
        assert!(
            !whole.contains("not listed"),
            "and say nothing about omissions when there are none: {whole}"
        );

        // BOUNDED at one, and the bound says what it took.
        let (capped, _) = analyze_request(&request(Some(1), None)).expect("it reads");
        assert!(
            capped.contains("more sequence(s) not listed"),
            "the ceiling reaches this listing and reports itself: {capped}"
        );

        // THE SELECTOR, which cannot narrow these flows and now says so.
        let filter = wz_capture::filter::Filter::parse("key == demo/**").expect("compiles");
        let (selected, _) = analyze_request(&request(None, Some(&filter))).expect("it reads");
        assert!(
            selected.contains("the --select expression did not narrow these flows"),
            "a reader who selected must be told these rows were not selected: {selected}"
        );
        assert!(
            !whole.contains("did not narrow these flows"),
            "ANTI-VACUITY: unselected runs say nothing about a selector: {whole}"
        );

        // ONE FACT, TWO RENDERINGS: a consumer branches on the field rather
        // than parsing the sentence.
        let (json, _) = analyze_request(&Request {
            format: Format::Json,
            ..request(None, Some(&filter))
        })
        .expect("it reads");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("one valid document");
        assert_eq!(parsed["quic_unselected"], serde_json::json!(true));
    }

    /// R311y698 (§1.2a) — WITHOUT the key log, the same capture opens its
    /// Initial packets and says which packets it could not open.
    ///
    /// ## Why this half matters as much as the other
    ///
    /// The Initial space needs no key at all, so a keyless run is not a blank:
    /// it yields the version, the connection ID, the ClientHello and therefore
    /// the `Random` a reader needs to go and FIND the right key log. A tool that
    /// refused to look without keys would withhold exactly the fact that tells
    /// its user which keys to fetch.
    ///
    /// It is also the anti-vacuity half of the test above: if the pass opened
    /// packets without keys, "the key log worked" would be a statement about
    /// nothing.
    #[test]
    fn without_keys_the_initial_space_still_opens_and_the_rest_says_why() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(7));
        let (capture, _, _) = quic_capture(&random);

        let (rendered, outcome) = analyze(&capture, None).expect("it reads");
        assert!(
            rendered.contains("2 of 4 packet(s) opened"),
            "the two Initial packets open from the wire alone: {rendered}"
        );
        assert!(
            rendered.contains("a ClientHello was read and the key log does not hold it"),
            "and the reader is told where to go next: {rendered}"
        );
        assert!(
            rendered.contains("crypto/initial"),
            "the handshake bytes are recovered without any key: {rendered}"
        );
        assert!(
            !rendered.contains("stream/0"),
            "and the 1-RTT stream is NOT, which is what makes the other test's \
             claim about the key log mean something: {rendered}"
        );
        assert!(
            !outcome.complete,
            "a flow this reader could not fully open is a shortfall: {rendered}"
        );
    }

    /// R311y698 (§1.2a) — the JSON says the same thing, in one document, and the
    /// `decrypted` field is no longer a literal.
    ///
    /// `"decrypted":false` was hard-coded into the report from R311y669 until
    /// this round. A field that cannot change is a field a consumer cannot
    /// branch on — and it was a wrong answer the moment this workspace could
    /// open a QUIC packet.
    #[test]
    fn the_json_reports_the_decryption_rather_than_a_literal_false() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(7));
        let (capture, keylog, _) = quic_capture(&random);

        let (rendered, _) = analyze_with(
            &capture,
            Some(keylog.as_bytes()),
            Format::Json,
            false,
            false,
        )
        .expect("it reads");
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("one valid document");
        let quic = &parsed["capture"]["quic"];
        assert_eq!(quic["decrypted"], serde_json::json!(true));
        assert_eq!(quic["decryption"]["packets"], serde_json::json!(4));
        assert_eq!(quic["decryption"]["packets_opened"], serde_json::json!(4));
        assert_eq!(quic["decryption"]["stream_bytes"], serde_json::json!(25));
        assert_eq!(quic["decryption"]["datagram_bytes"], serde_json::json!(7));
        assert_eq!(quic["decryption"]["walks_stopped"], serde_json::json!(0));

        // The per-flow listing, whose direction split is the thing a summed
        // figure cannot carry: a key log holding one side's secrets opens one
        // half and not the other.
        let flows = parsed["quic_flows"].as_array().expect("a flow list");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0]["client_direction"], serde_json::json!("A"));
        assert_eq!(flows[0]["keys_installed"], serde_json::json!(true));
        assert_eq!(
            flows[0]["directions"][0]["stream_bytes"],
            serde_json::json!(25)
        );
        assert_eq!(
            flows[0]["directions"][1]["datagram_bytes"],
            serde_json::json!(7),
            "the server's RFC 9221 datagram is on the server's half"
        );
    }

    /// R311y698 (§1.2a) — a key log holding ONE direction's secrets opens that
    /// half and says so about the other.
    ///
    /// The per-direction census is the reason this is reportable at all: a
    /// summed "3 of 4 packets" cannot tell a reader that the half they care
    /// about is the missing one, and this is the exact shape R311y668 had to fix
    /// on the TLS side after measuring it.
    #[test]
    fn a_key_log_for_one_direction_opens_that_half_and_names_the_other() {
        let random: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(7));
        let (capture, keylog, _) = quic_capture(&random);
        // Drop every SERVER line, leaving the handshake and application secrets
        // of the client only.
        let half: String = keylog
            .lines()
            .filter(|line| !line.starts_with("SERVER_"))
            .map(|line| format!("{line}\n"))
            .collect();

        let (rendered, outcome) = analyze(&capture, Some(half.as_bytes())).expect("it reads");
        assert!(
            rendered.contains("3 of 4 packet(s) opened"),
            "the server's 1-RTT packet is the only one left: {rendered}"
        );
        assert!(
            rendered.contains("A stream/0: 25 byte(s)"),
            "the client's half is whole: {rendered}"
        );
        assert!(
            rendered.contains("B: 1 of 2 packet(s) opened (1 without a key, 0 refused)"),
            "and the server's half names WHICH kind of failure it is -- a key \
             log question, not a capture question: {rendered}"
        );
        assert!(!outcome.complete);
    }
}
