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
    /// R311y670 (§1.2a) — UDP ports the caller declares to be QUIC.
    ///
    /// The one fact about a mid-connection QUIC capture that cannot come from
    /// the bytes; see
    /// [`Dissection::from_capture_declaring_quic`](wz_capture::Dissection::from_capture_declaring_quic).
    pub quic_ports: Vec<u16>,
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
}

impl Census {
    /// All three, which is what `--census` asks for.
    pub const fn all() -> Self {
        Self {
            throughput: true,
            exchanges: true,
            payloads: true,
        }
    }

    /// Whether any plane was asked for at all.
    pub const fn any(&self) -> bool {
        self.throughput || self.exchanges || self.payloads
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
    --flows           list every flow, stream and datagram: endpoints, framing,
                      messages decoded, scouting messages, and for an encrypted
                      one whether its plaintext was read
    --messages        list the decoded messages themselves, under their flow,
                      with the direction, offset and namespace of each.
                      Implies --flows
    --json            render the report as JSON instead of text
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
    -h, --help        print this and exit
";

/// Parse a command line, `argv[0]` already removed.
pub fn parse(args: &[String]) -> Result<Options, UsageError> {
    let mut capture: Option<String> = None;
    let mut keylog: Option<String> = None;
    let mut format = Format::Text;
    let mut per_flow = false;
    let mut per_message = false;
    let mut quic_ports: Vec<u16> = Vec::new();
    let mut max_messages: Option<usize> = None;
    let mut census = Census::default();
    let mut select: Option<wz_capture::filter::Filter> = None;
    let mut per_field = false;
    let mut at = 0usize;
    while at < args.len() {
        let arg = &args[at];
        match arg.as_str() {
            "--json" => format = Format::Json,
            "--flows" => per_flow = true,
            "--throughput" => census.throughput = true,
            "--exchanges" => census.exchanges = true,
            "--payloads" => census.payloads = true,
            "--census" => census = Census::all(),
            "--fields" => per_field = true,
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
            "--quic" => {
                at += 1;
                let raw = args.get(at).ok_or(UsageError::MissingValue("--quic"))?;
                quic_ports.push(
                    raw.parse::<u16>()
                        .map_err(|_| UsageError::BadValue("--quic", raw.clone()))?,
                );
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
        quic_ports,
        max_messages,
        census,
        per_field,
        select: match select {
            // A selector with nothing to narrow is a flag that does nothing.
            Some(_) if !census.any() => return Err(UsageError::SelectWithoutPlane),
            other => other,
        },
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
        census: Census::default(),
        per_field: false,
        select: None,
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
    /// Which observer planes to build. See [`Census`].
    pub census: Census,
    /// R311y675 — dissect each message into its fields.
    pub per_field: bool,
    /// R311y674 — the selector narrowing what those planes count. `None`
    /// selects everything, which is what the planes' unfiltered entry points
    /// already pass.
    pub select: Option<&'a wz_capture::filter::Filter>,
}

/// Read a capture and report on it, as [`Request`] describes.
pub fn analyze_request(request: &Request<'_>) -> Result<(String, Outcome), CaptureError> {
    let &Request {
        capture,
        keylog,
        format,
        per_flow,
        per_message,
        messages_per_flow,
        quic_ports,
        census,
        per_field,
        select,
    } = request;
    let mut dissection = Dissection::from_capture_declaring_quic(capture, quic_ports)?;

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
    if key_log_connections > 0 {
        if per_field {
            dissection.decrypt_with_sink(&mut opener, &mut fields);
        } else {
            dissection.decrypt_with(&mut opener);
        }
    }

    // R311y671 — what the decryptor OBSERVED about its epoch changes, which the
    // dissection does not hold: the epochs are the opener's state, and until this
    // round the `KeyUpdate` messages announcing them were opened and read past.
    let epochs = opener.epoch_witness();
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
    let mut report = CaptureReport::of(&dissection);
    if let Some(table) = &throughput {
        report = report.with_throughput(table);
    }
    if let Some(table) = &exchanges {
        report = report.with_exchanges(table);
    }
    if let Some(table) = &payloads {
        report = report.with_payloads(table);
    }
    let report = report;
    let outcome = Outcome {
        complete: report.is_complete(),
        decrypted_flows,
        undecrypted_flows: flows.len() - decrypted_flows,
        key_log_connections,
        foreign_secrets_blocks: foreign,
    };
    // R311y668 — the JSON is COMPOSED and no longer spliced. The report names
    // its own keys ([`CaptureReport::json_fields`]) and this is the only place
    // that decides where the object begins and ends, so a flow list is one more
    // key rather than a second document appended after the first.
    let rendered = match format {
        Format::Text => {
            let mut rendered = report.to_text();
            rendered.push_str(&epoch_lines(&epochs, format));
            if per_field {
                rendered.push_str("fields:\n");
                rendered.push_str(&field_lines(
                    capture,
                    &dissection,
                    &fields,
                    format,
                    messages_per_flow,
                ));
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
            rendered.push_str(&epoch_lines(&epochs, format));
            if per_field {
                rendered.push(',');
                rendered.push_str(&field_lines(
                    capture,
                    &dissection,
                    &fields,
                    format,
                    messages_per_flow,
                ));
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
        if unexplained > 0 {
            out.push_str(&format!(
                "      {unexplained} with neither -- this reader was watching \
                 and did not see the announcement\n"
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
) -> String {
    use wz_session_core::dissect::to_json;

    // R311y681 — the listing is BUILT as flows, each carrying its rows and the
    // notes that belong beside them, and rendered once per format at the end.
    // Both renderings then read the same values, so neither can carry a notice
    // the other lacks -- which is exactly what this round found: five notices
    // written straight into the text branch and invisible to a consumer.
    let mut listings: Vec<FlowListing> = Vec::new();
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
        for frame in &flow.frames {
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
            render_field_row(&mut rows, format, flow, frame, &row, &to_json);
        }
        // R311y677 — the sink's rows for this flow, if it was a decrypted one.
        for (f, direction, origin, row) in &decrypted.rows {
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
                    space: OffsetSpace::CiphertextRecord,
                },
                row,
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
        dissection,
        format,
        messages_per_flow,
        &mut emitted,
        &mut listings,
    );
    render_listings(&listings, format)
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

/// One message whose packet did not vouch for it, and why.
struct Disagreed {
    /// The packet index the message named.
    at: usize,
    why: Disagreement,
}

/// Why a packet did not vouch for the message that named it.
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
            Self::CaptureNotReread => None,
        }
    }

    /// The machine-readable kind, which is what a consumer branches on.
    fn kind(&self) -> &'static str {
        match self {
            Self::NotDecrypted { .. } => "not_decrypted",
            Self::NothingWalkable { .. } => "nothing_walkable",
            Self::CaptureNotReread => "capture_not_reread",
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
/// The JSON carries TWO keys and both are structural: `fields` is the rows and
/// `field_notes` is everything that could not become one. A consumer must never
/// have to test for the key that explains a short array -- that is the same rule
/// the epoch object follows, one listing over.
fn render_listings(listings: &[FlowListing], format: Format) -> String {
    let mut out = String::new();
    match format {
        Format::Text => {
            for listing in listings {
                out.push_str(&listing.rows);
                for note in &listing.notes {
                    out.push_str(&note.to_text());
                }
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
            out.push(']');
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
    rows: Vec<(
        wz_capture::link::FlowKey,
        wz_session_core::passive::Direction,
        usize,
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
            let origin = stream.record_origin(at).unwrap_or(at);
            // R311y683 — walked and CHECKED against the session that framed it,
            // the same way the cleartext path is. R311y682 closed that half and
            // its own carry named this one: these coordinates come from the
            // same frame, the frame is right here in the loop, and nothing was
            // comparing the two readers.
            self.rows.push((
                stream.flow,
                stream.direction,
                origin,
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
    let start = body + frame.unit_offset;
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
) {
    // R311y688 — a cleartext stream row's offset IS a byte offset, and the
    // message it names begins past the framing prefix and past whatever of the
    // unit stands ahead of it. That sum is the one a reader would otherwise
    // have to do, and get wrong on a batch.
    let space = OffsetSpace::StreamByte {
        message_at: frame.stream_offset + frame.prefix_width + frame.unit_offset,
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
                 \"stream_offset\":{}{},\"field\":{}}}",
                frame.stream_offset,
                space.json(),
                to_json(field)
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
fn datagram_field_rows(
    capture: &[u8],
    dissection: &Dissection,
    format: Format,
    messages_per_flow: Option<usize>,
    emitted: &mut usize,
    listings: &mut Vec<FlowListing>,
) {
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
        let mut shown = 0usize;
        let mut omitted = 0usize;
        // R311y680 — messages whose packet did not vouch for itself.
        // R311y681 — counted exactly, and named while the bound allows.
        let mut disagreed = 0usize;
        let mut named: Vec<Disagreed> = Vec::new();
        for frame in &flow.frames {
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
fn render_sink_row(out: &mut String, format: Format, at: RowAt, row: &FieldRow) {
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
    match (format, row) {
        (Format::Json, FieldRow::Walked(field)) => out.push_str(&format!(
            "{{\"from\":\"{from}\",\"to\":\"{to}\",\"direction\":\"{dir}\",\
             \"stream_offset\":{origin}{},\"decrypted\":{decrypted},\"field\":{}}}",
            space.json(),
            wz_session_core::dissect::to_json(field)
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
            // A QUIC flow decodes NO zenoh messages, and its packet count is
            // reported in the report's own `quic` block rather than folded in
            // here: a `message(s)` column carrying packets is the shape of the
            // misread this round removed.
            flow.frames.len(),
            flow.scouting.len(),
            state,
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
            message_at: f.stream_offset + f.prefix_width + f.unit_offset,
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
                quic_ports: Vec::new(),
                max_messages: None,
                census: Census::default(),
                per_field: false,
                select: None,
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
                quic_ports: Vec::new(),
                max_messages: None,
                census: Census::default(),
                per_field: false,
                select: None,
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
            ("Init", &[0x01, 0x09, 0x00, 0xAA]),
            ("Close", &[0x03, 0x00]),
            ("KeepAlive", &[0x04]),
            ("Frame", &[0x05, 0x01]),
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
        assert_eq!(checked, 4, "every case in the table must have run");
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
