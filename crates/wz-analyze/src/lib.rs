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
    if key_log_connections > 0 {
        dissection.decrypt_with(&mut opener);
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
                rendered.push_str(&field_lines(&dissection, format, messages_per_flow));
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
                rendered.push_str(&field_lines(&dissection, format, messages_per_flow));
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
    let updates = a.key_updates + b.key_updates;
    let requested = a.updates_requested + b.updates_requested;
    let answering = a.updates_answering + b.updates_answering;
    let unanswered = a.requests_unanswered + b.requests_unanswered;
    if format == Format::Json {
        return format!(
            ",\"epochs\":{{\"advances\":{advances},\"advances_confirmed\":{confirmed},\
             \"advances_unannounced\":{unannounced},\"advances_unwitnessed\":{unwitnessed},\
             \"key_updates\":{updates},\"updates_requested\":{requested},\
             \"updates_answering\":{answering},\"requests_unanswered\":{unanswered}}}"
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
             announcement was missed (mid-session capture, or a hole over it) and \
             the boundary rests on the trial alone\n"
        ));
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
    dissection: &Dissection,
    format: Format,
    messages_per_flow: Option<usize>,
) -> String {
    use wz_session_core::dissect::{dissect_transport_message, to_json};

    let mut out = String::new();
    if format == Format::Json {
        out.push_str("\"fields\":[");
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
                Some(why) => FieldRow::Declined(why),
                None => match message_bytes(stream, origin, frame) {
                    Err(why) => FieldRow::Declined(why),
                    Ok(bytes) => {
                        match dissect_transport_message(
                            bytes,
                            frame.stream_offset + frame.prefix_width,
                        ) {
                            Ok(field) => FieldRow::Walked(field),
                            // The error type is `sce_forge_runtime`'s and is not
                            // re-exported publicly here, so it is rendered rather than
                            // named -- a dependency this crate has no reason to take on
                            // for one message string.
                            Err(err) => FieldRow::Declined(format!(
                                "the field walker refused these bytes: {err:?}"
                            )),
                        }
                    }
                },
            };
            shown += 1;
            if format == Format::Json && emitted > 0 {
                rows.push(',');
            }
            emitted += 1;
            render_field_row(&mut rows, format, flow, frame, &row, &to_json);
        }
        if rows.is_empty() {
            continue;
        }
        out.push_str(&rows);
        if format == Format::Text && omitted > 0 {
            // Per FLOW, like every other listing this tool bounds: a bound that
            // reports nothing reports itself as the wire.
            out.push_str(&format!("    ... {omitted} more not listed\n"));
        }
    }
    if format == Format::Json {
        out.push(']');
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
/// The length prefix is read from the stream rather than assumed: `prefix_width`
/// says how wide it is, so the width is a fact the framing already settled and
/// only the VALUE is read here.
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
    if body > stream.len() {
        return Err("the framing unit is past the retained stream".into());
    }
    let mut len = 0usize;
    for (i, b) in stream[at..body].iter().enumerate() {
        len |= (*b as usize) << (8 * i);
    }
    let end = body + len;
    if end > stream.len() {
        return Err(format!(
            "the framing unit declares {len} byte(s) and the retained stream holds {}",
            stream.len() - body
        ));
    }
    Ok(&stream[body..end])
}

fn render_field_row(
    out: &mut String,
    format: Format,
    flow: &wz_capture::FlowDissection,
    frame: &wz_session_core::passive::PassiveFrame,
    row: &FieldRow,
    to_json: &dyn Fn(&wz_session_core::dissect::Field) -> String,
) {
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
                 \"stream_offset\":{},\"field\":{}}}",
                frame.stream_offset,
                to_json(field)
            ));
        }
        (Format::Json, FieldRow::Declined(why)) => {
            out.push_str(&format!(
                "{{\"from\":\"{from}\",\"to\":\"{to}\",\"direction\":\"{dir}\",\
                 \"stream_offset\":{},\"declined\":\"{}\"}}",
                frame.stream_offset,
                why.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }
        (Format::Text, FieldRow::Walked(field)) => {
            out.push_str(&format!(
                "  {from} -> {to} {dir} @{}\n",
                frame.stream_offset
            ));
            push_field_text(out, field, 2);
        }
        (Format::Text, FieldRow::Declined(why)) => {
            out.push_str(&format!(
                "  {from} -> {to} {dir} @{}: NO FIELDS -- {why}\n",
                frame.stream_offset
            ));
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
        let rows: Vec<MessageRow> = flow.frames.iter().map(MessageRow::transport).collect();
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
        let mut rows: Vec<MessageRow> = flow.frames.iter().map(MessageRow::transport).collect();
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
    fn transport(f: &wz_session_core::passive::PassiveFrame) -> Self {
        Self {
            direction: f.direction,
            offset: f.stream_offset,
            batch: Some(f.batch_index),
            space: "transport",
            name: message_name(f),
        }
    }

    fn scouting(s: &wz_capture::ScoutingDatagram) -> Self {
        Self {
            direction: s.direction,
            offset: s.packet_index,
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
            "{{\"space\":\"{}\",\"direction\":\"{:?}\",\"offset\":{},\
             \"batch\":{batch},\"name\":\"{}\"}}",
            self.space, self.direction, self.offset, self.name
        ));
    }

    fn push_text(&self, out: &mut String) {
        match self.batch {
            Some(b) => out.push_str(&format!(
                "      {:?} @{} #{b}  {}\n",
                self.direction, self.offset, self.name
            )),
            None => out.push_str(&format!(
                "      {:?} @{} {}  {}\n",
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
            vec!["      A @1 scouting  Scout"],
            "a scouting row carries the namespace where a batch index would be"
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
