// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// How the report should be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// Human-readable.
    #[default]
    Text,
    /// The JSON a consuming tool parses.
    Json,
}

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The capture file to read.
    pub capture: String,
    /// An NSS key log to read alongside it, for the ordinary case where the
    /// keys were written by `SSLKEYLOGFILE` into a SEPARATE file from the
    /// capture. Keys embedded in the capture's own Decryption Secrets Blocks
    /// are always used and need no flag.
    pub keylog: Option<String>,
    /// How to render.
    pub format: Format,
    /// R311y666 (§1.2a) — list every flow, not just the capture-wide summary.
    pub per_flow: bool,
    /// R311y667 (§1.2a) — list the decoded MESSAGES, not just how many.
    pub per_message: bool,
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
    /// An unrecognised flag. REFUSED rather than ignored: a misspelt
    /// `--keylog` that is silently dropped produces a report saying the capture
    /// could not be decrypted, which is a wrong answer that looks like a right
    /// one.
    UnknownFlag(String),
}

impl core::fmt::Display for UsageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoCapture => write!(f, "no capture file given"),
            Self::TwoCaptures => write!(f, "more than one capture file given"),
            Self::MissingValue(flag) => write!(f, "{flag} needs a value"),
            Self::UnknownFlag(flag) => write!(f, "unknown option `{flag}`"),
        }
    }
}

/// The usage text, which is also the documentation of what this tool does.
pub const USAGE: &str = "\
wz-analyze -- read a zenoh capture and report what is in it

USAGE:
    wz-analyze <capture.pcapng|capture.pcap> [OPTIONS]

OPTIONS:
    --keylog <file>   an NSS key log (SSLKEYLOGFILE) to decrypt TLS flows with.
                      Keys carried inside the capture's own Decryption Secrets
                      Blocks are used without this flag.
    --flows           list every flow: endpoints, framing, messages decoded,
                      and for an encrypted one whether its plaintext was read
    --messages        list the decoded messages themselves, under their flow.
                      Implies --flows
    --json            render the report as JSON instead of text
    -h, --help        print this and exit
";

/// Parse a command line, `argv[0]` already removed.
pub fn parse(args: &[String]) -> Result<Options, UsageError> {
    let mut capture: Option<String> = None;
    let mut keylog: Option<String> = None;
    let mut format = Format::Text;
    let mut per_flow = false;
    let mut per_message = false;
    let mut at = 0usize;
    while at < args.len() {
        let arg = &args[at];
        match arg.as_str() {
            "--json" => format = Format::Json,
            "--flows" => per_flow = true,
            "--messages" => {
                // The messages are printed under their flow, so asking for them
                // asks for the flows too. Silently implying it beats refusing a
                // combination that has one sensible meaning.
                per_flow = true;
                per_message = true;
            }
            "--keylog" => {
                at += 1;
                keylog = Some(
                    args.get(at)
                        .cloned()
                        .ok_or(UsageError::MissingValue("--keylog"))?,
                );
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
    Ok(Options {
        capture: capture.ok_or(UsageError::NoCapture)?,
        keylog,
        format,
        per_flow,
        per_message,
    })
}

/// What one analysis found, beyond the rendered report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// The rendered report's own verdict: did this reader see the whole
    /// capture. Drives the exit code, so a script can tell a clean read from
    /// one with encrypted flows, gaps or dropped packets in it.
    pub complete: bool,
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
    let mut dissection = Dissection::from_capture(capture)?;

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
    if key_log_connections > 0 {
        dissection.decrypt_with(&mut opener);
    }

    let flows = dissection.encrypted_flows();
    let decrypted_flows = flows.iter().filter(|f| f.not_decrypted.is_none()).count();
    let report = CaptureReport::of(&dissection);
    let outcome = Outcome {
        complete: report.is_complete(),
        decrypted_flows,
        undecrypted_flows: flows.len() - decrypted_flows,
        key_log_connections,
        foreign_secrets_blocks: foreign,
    };
    let mut rendered = match format {
        Format::Text => report.to_text(),
        Format::Json => report.to_json(),
    };
    if per_flow {
        splice_flows(&mut rendered, &dissection, format, per_message);
    }
    Ok((rendered, outcome))
}

/// R311y666 (§1.2a) — one line per flow.
///
/// Everything here is a fact the dissection already held and no rendering
/// exposed: which endpoints, what the byte stream turned out to be, how many
/// messages came out of it, and -- for an encrypted flow -- whether its
/// plaintext was read and why not.
/// R311y667 (§1.2a) — put the flow list INSIDE the report rather than after it.
///
/// R311y666 appended a second JSON object, so `--json --flows` emitted two
/// documents on one stream. A consumer parsing it as a single value gets the
/// first and silently ignores the second -- which is the whole class of failure
/// this track exists to end, arriving through the output format: the flows are
/// there, the reader does not see them, and nothing says so.
///
/// The text rendering has no such constraint and keeps its appended section.
fn splice_flows(rendered: &mut String, d: &Dissection, format: Format, per_message: bool) {
    let body = flow_lines(d, format, per_message);
    if format == Format::Text {
        rendered.push_str(&body);
        return;
    }
    // The report is one JSON object, so the list becomes another key in it.
    // Checked rather than assumed: a renderer that stopped producing an object
    // would otherwise have this appended to whatever it did produce.
    if rendered.ends_with('}') {
        rendered.pop();
        rendered.push(',');
        rendered.push_str(&body);
        rendered.push('}');
    } else {
        rendered.push_str(&body);
    }
}

fn flow_lines(d: &Dissection, format: Format, per_message: bool) -> String {
    let mut out = String::new();
    if format == Format::Json {
        out.push_str("\"flows\":[");
    } else {
        out.push_str("\nflows:\n");
    }
    for (i, flow) in d.flows().iter().enumerate() {
        let encrypted = flow.encrypted();
        let framing = match flow.framing() {
            wz_capture::Framing::Stream => "stream",
            wz_capture::Framing::WebSocket { .. } => "websocket",
            wz_capture::Framing::Encrypted(_) => "tls",
            wz_capture::Framing::Undecided => "undecided",
            wz_capture::Framing::OpeningLost => "opening-lost",
        };
        let state = match encrypted.as_ref().map(|e| e.not_decrypted) {
            None => "-".to_string(),
            Some(None) => "decrypted".to_string(),
            Some(Some(reason)) => format!("{reason:?}"),
        };
        let key = &flow.flow;
        if format == Format::Json {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"low\":\"{}\",\"high\":\"{}\",\"framing\":\"{framing}\",\
                 \"messages\":{},\"tls\":\"{state}\"}}",
                endpoint(&key.low),
                endpoint(&key.high),
                flow.frames.len()
            ));
        } else {
            out.push_str(&format!(
                "  {} <-> {}  {framing:<12} {} message(s)  {state}\n",
                endpoint(&key.low),
                endpoint(&key.high),
                flow.frames.len()
            ));
            if per_message {
                for f in &flow.frames {
                    out.push_str(&format!(
                        "      {:?} @{} #{}  {}\n",
                        f.direction,
                        f.stream_offset,
                        f.batch_index,
                        message_name(f)
                    ));
                }
            }
        }
    }
    if format == Format::Json {
        out.push(']');
    }
    out
}

/// R311y667 (§1.2a) — what one decoded message WAS, in a word.
///
/// ## Why this reads a `Debug` rendering instead of matching the enum
///
/// A total match is this project's rule and is the wrong tool here:
/// `InboundFrame`'s variants are individually `#[cfg]`-gated on the `codec-*`
/// features, so an exhaustive match in this crate would have to mirror seven
/// feature gates it does not own -- and a mirror drifts. A `_ =>` fallback is
/// worse: it is the arm that silently reports a new message kind as whatever
/// the default happens to be.
///
/// So the name is taken from the derived `Debug`, whose leading token is the
/// variant's own identifier. That is a human-facing listing reading a
/// human-facing rendering; nothing decides anything on it, and a variant added
/// upstream appears here by its right name without this crate being touched.
fn message_name(frame: &wz_session_core::passive::PassiveFrame) -> String {
    match &frame.frame {
        Ok(f) => {
            let rendered = format!("{f:?}");
            rendered
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or("?")
                .to_string()
        }
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

    #[test]
    fn a_capture_path_alone_is_a_complete_command_line() {
        assert_eq!(
            parse(&args(&["cap.pcapng"])),
            Ok(Options {
                capture: "cap.pcapng".into(),
                keylog: None,
                format: Format::Text,
                per_flow: false,
                per_message: false,
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
                keylog: Some("keys.txt".into()),
                format: Format::Json,
                // `--messages` implies `--flows`: the messages are printed
                // under their flow, so the pairing has one sensible meaning.
                per_flow: true,
                per_message: true,
            })
        );
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
}
