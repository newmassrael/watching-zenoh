// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `replay`: put a recorded sequence of samples, each under its own key, paced and mutated as the
//! replay tool paces and mutates a capture (`wz_workload::pacing`, `wz_workload::mutation`, the
//! definitions `wz-replay` and its C ABI re-export).
//!
//! ```text
//! { role: "replay", timing: "capture", gap_ms: 100, speed: 2.0, max_gap_ms: 10000,
//!   samples: [
//!     { key: "k/a", hex: "00ff10", captured_at_ms: 1000 },
//!     { key: "k/b", text: "beta", captured_at_ms: 1400,
//!       mutation: { kind: "flip_bit", at_bit: 0 } },
//!   ] }
//! ```
//!
//! A sample is a key and its bytes (`text` or `hex`, exactly one; a body may hold 0x00), with an
//! optional capture time and an optional mutation: `flip_bit` (`at_bit`), `truncate` (`keep`, the
//! bytes kept), `extend` (`count` bytes from `seed`), `scramble` (`seed`). The first sample waits
//! for nothing; each later one waits the declared gap (`timing: "declared"`, the default) or the
//! interval the capture recorded (`timing: "capture"`, the declared gap where there is none),
//! divided by `speed` and capped by `max_gap_ms` (`null` for no cap). A plan that takes longer than
//! `max_total_ms`, or that would grow a payload by more than `max_extend_bytes` in one mutation or
//! `max_extend_total_bytes` in all, is refused whole before anything is sent, never cut.

use std::time::Duration;

use wz::runtime_tokio::json5::Json5Value;
use wz::runtime_tokio::sample::SampleKind;
use wz_workload::mutation::Mutation;
use wz_workload::pacing::{Pacing, Schedule, Timing, TimingSource};
use wz_workload::payload::parse_hex;

use crate::sessions::{as_str, field, key_set};
use crate::sessions_driver::{integer, Args, Ctx, KeyDef, KeyKind, Play, RoleDef, Structure};

/// The timings a replay is paced by.
const TIMINGS: &[&str] = &["declared", "capture"];

/// The default per-mutation and whole-plan growth a replay may ask for: one mebibyte, sixty-four.
const MAX_EXTEND_BYTES: u64 = 1 << 20;
const MAX_EXTEND_TOTAL_BYTES: u64 = 64 << 20;

static SAMPLES: Structure = Structure {
    expect: "a non-empty list of samples: { key, text or hex, captured_at_ms?, mutation? }",
    judge,
};

pub(crate) static ROLE: RoleDef = RoleDef::played(
    "replay",
    &[
        KeyDef::required("samples", KeyKind::Structured(&SAMPLES)),
        KeyDef::optional("timing", KeyKind::Word(TIMINGS)),
        KeyDef::defaulted("gap_ms", KeyKind::Integer, 100),
        KeyDef::optional("speed", KeyKind::Decimal),
        KeyDef::defaulted("max_gap_ms", KeyKind::IntegerOrNull, 10_000),
        KeyDef::optional("max_total_ms", KeyKind::Integer),
        KeyDef::defaulted("max_extend_bytes", KeyKind::Integer, MAX_EXTEND_BYTES),
        KeyDef::defaulted(
            "max_extend_total_bytes",
            KeyKind::Integer,
            MAX_EXTEND_TOTAL_BYTES,
        ),
    ],
    play,
)
.checked(check);

/// One sample of the plan, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sample {
    key: String,
    bytes: Vec<u8>,
    captured_at_ms: Option<u64>,
    mutation: Mutation,
}

/// One emission of the plan: what goes out, when, and what the pacing and the mutation said.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Emission {
    delay_ms: u64,
    source: TimingSource,
    key: String,
    bytes: Vec<u8>,
    mutated: bool,
}

const SAMPLE_KEYS: &[&str] = &["key", "text", "hex", "captured_at_ms", "mutation"];
const MUTATIONS: &[&str] = &["none", "flip_bit", "truncate", "extend", "scramble"];

/// The keys each mutation takes beside `kind`.
fn mutation_keys(kind: &str) -> &'static [&'static str] {
    match kind {
        "flip_bit" => &["at_bit"],
        "truncate" => &["keep"],
        "extend" => &["count", "seed"],
        "scramble" => &["seed"],
        _ => &[],
    }
}

/// Every refusal a `samples` value earns, by the path under the key.
fn judge(value: &Json5Value) -> Vec<(String, String)> {
    let Json5Value::Array(items) = value else {
        return vec![(String::new(), format!("must be {}", SAMPLES.expect))];
    };
    if items.is_empty() {
        return vec![(String::new(), "must hold at least one sample".to_string())];
    }
    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let at = format!("[{i}]");
        let Json5Value::Object(entry) = item else {
            out.push((at, "must be a mapping".to_string()));
            continue;
        };
        for key in key_set(entry) {
            if !SAMPLE_KEYS.contains(&key) {
                out.push((format!("{at}.{key}"), "unknown key".to_string()));
            }
        }
        match field(entry, "key").and_then(as_str) {
            Some(k) if !k.is_empty() && !k.contains(char::is_whitespace) => {}
            _ => out.push((
                format!("{at}.key"),
                "required, a keyexpr with no whitespace".to_string(),
            )),
        }
        match (field(entry, "text"), field(entry, "hex")) {
            (Some(t), None) if as_str(t).is_none() => {
                out.push((format!("{at}.text"), "must be a string".to_string()))
            }
            (None, Some(h)) => {
                if let Err(why) = as_str(h)
                    .ok_or("must be a string".to_string())
                    .and_then(|t| parse_hex(t).map_err(|e| e.to_string()))
                {
                    out.push((format!("{at}.hex"), why));
                }
            }
            (Some(_), None) => {}
            _ => out.push((at.clone(), "give exactly one of text and hex".to_string())),
        }
        if let Some(t) = field(entry, "captured_at_ms") {
            if integer(t).is_none() {
                out.push((
                    format!("{at}.captured_at_ms"),
                    "must be an integer from 0".to_string(),
                ));
            }
        }
        if let Some(m) = field(entry, "mutation") {
            out.extend(judge_mutation(&format!("{at}.mutation"), m));
        }
    }
    out
}

fn judge_mutation(at: &str, value: &Json5Value) -> Vec<(String, String)> {
    let Json5Value::Object(entry) = value else {
        return vec![(at.to_string(), "must be a mapping with a kind".to_string())];
    };
    let Some(kind) = field(entry, "kind")
        .and_then(as_str)
        .filter(|k| MUTATIONS.contains(k))
    else {
        return vec![(
            format!("{at}.kind"),
            format!("required: {}", MUTATIONS.join(", ")),
        )];
    };
    let takes = mutation_keys(kind);
    let mut out = Vec::new();
    for key in key_set(entry) {
        if key != "kind" && !takes.contains(&key) {
            out.push((
                format!("{at}.{key}"),
                format!("not a key of the `{kind}` mutation"),
            ));
        }
    }
    for key in takes {
        if field(entry, key).and_then(integer).is_none() {
            out.push((
                format!("{at}.{key}"),
                "required, an integer from 0".to_string(),
            ));
        }
    }
    out
}

/// The samples of a value the judge passed.
fn samples(value: &Json5Value) -> Vec<Sample> {
    let Json5Value::Array(items) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let Json5Value::Object(entry) = item else {
                return None;
            };
            let bytes = match (
                field(entry, "text").and_then(as_str),
                field(entry, "hex").and_then(as_str),
            ) {
                (Some(t), _) => t.as_bytes().to_vec(),
                (None, Some(h)) => parse_hex(h).ok()?,
                (None, None) => return None,
            };
            let mutation = field(entry, "mutation").map_or(Mutation::None, mutation_of);
            Some(Sample {
                key: field(entry, "key").and_then(as_str)?.to_string(),
                bytes,
                captured_at_ms: field(entry, "captured_at_ms").and_then(integer),
                mutation,
            })
        })
        .collect()
}

fn mutation_of(value: &Json5Value) -> Mutation {
    let Json5Value::Object(entry) = value else {
        return Mutation::None;
    };
    let int = |key: &str| field(entry, key).and_then(integer).unwrap_or(0);
    let size = |key: &str| usize::try_from(int(key)).unwrap_or(usize::MAX);
    match field(entry, "kind").and_then(as_str) {
        Some("flip_bit") => Mutation::FlipBit { at: size("at_bit") },
        Some("truncate") => Mutation::Truncate { to: size("keep") },
        Some("extend") => Mutation::Extend {
            count: size("count"),
            seed: int("seed"),
        },
        Some("scramble") => Mutation::Scramble { seed: int("seed") },
        _ => Mutation::None,
    }
}

/// The schedule of a replay's keys.
fn schedule(args: &Args) -> Schedule {
    let speed = args
        .decimal("speed")
        .map_or(1.0, |d| d.mantissa() as f64 / 10f64.powi(d.scale() as i32));
    Schedule {
        timing: match args.text("timing") {
            Some("capture") => Timing::Capture,
            _ => Timing::Declared,
        },
        gap_millis: args.int("gap_ms").unwrap_or(100),
        speed,
        max_gap_millis: if args.is_null("max_gap_ms") {
            None
        } else {
            args.int("max_gap_ms")
        },
        max_total_millis: args.int("max_total_ms"),
    }
}

/// The plan a replay's keys make, or why it is refused whole.
fn plan(args: &Args) -> Result<Vec<Emission>, Vec<(&'static str, String)>> {
    let samples = args.raw("samples").map(samples).unwrap_or_default();
    let schedule = schedule(args);
    let mut refused = Vec::new();
    if let Err(why) = schedule.checked() {
        refused.push(("speed", why.to_string()));
    }
    let per = args.int("max_extend_bytes").unwrap_or(MAX_EXTEND_BYTES);
    let all = args
        .int("max_extend_total_bytes")
        .unwrap_or(MAX_EXTEND_TOTAL_BYTES);
    let mut grown = 0u64;
    for (i, sample) in samples.iter().enumerate() {
        if let Mutation::Extend { count, .. } = sample.mutation {
            let count = count as u64;
            if count > per {
                refused.push((
                    "max_extend_bytes",
                    format!("sample {i} extends its payload by {count} bytes, more than {per}"),
                ));
            }
            grown = grown.saturating_add(count);
        }
    }
    if grown > all {
        refused.push((
            "max_extend_total_bytes",
            format!("the plan extends its payloads by {grown} bytes in all, more than {all}"),
        ));
    }
    if !refused.is_empty() {
        return Err(refused);
    }
    let mut pacing = Pacing::new(schedule);
    let emissions: Vec<Emission> = samples
        .into_iter()
        .map(|sample| {
            let (delay_ms, source) = pacing.next(sample.captured_at_ms);
            let outcome = sample.mutation.apply(&sample.bytes);
            Emission {
                delay_ms,
                source,
                key: sample.key,
                bytes: outcome.payload,
                mutated: outcome.changed,
            }
        })
        .collect();
    let total = emissions
        .iter()
        .map(|e| e.delay_ms)
        .fold(0u64, u64::saturating_add);
    if let Some(limit) = schedule.max_total_millis {
        if total > limit {
            return Err(vec![(
                "max_total_ms",
                format!(
                    "the plan takes {total} ms over {} emission(s), more than {limit}; it is refused \
                     whole, never cut",
                    emissions.len()
                ),
            )]);
        }
    }
    Ok(emissions)
}

fn check(args: &Args) -> Vec<(&'static str, String)> {
    plan(args).err().unwrap_or_default()
}

fn play(ctx: Ctx) -> Play {
    Box::pin(run(ctx))
}

async fn run(ctx: Ctx) {
    let Ok(emissions) = plan(ctx.args()) else {
        // The rules refused this plan before the session started; a plan that reaches here holds.
        return;
    };
    let total: u64 = emissions
        .iter()
        .map(|e| e.delay_ms)
        .fold(0, u64::saturating_add);
    ctx.say.line(&format!(
        "plan emissions={} total_ms={total}",
        emissions.len()
    ));
    for (i, e) in emissions.iter().enumerate() {
        tokio::time::sleep(Duration::from_millis(e.delay_ms)).await;
        let source = match e.source {
            TimingSource::Declared => "declared",
            TimingSource::Measured => "measured",
            TimingSource::Unmeasurable => "unmeasurable",
        };
        ctx.say.line(&format!(
            "emission {i} delay_ms={} source={source} mutated={}",
            e.delay_ms, e.mutated
        ));
        ctx.emit(&e.key, SampleKind::Put, &e.bytes);
    }
    ctx.say.line(&format!("done emissions={}", emissions.len()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions_driver::Value;
    use wz::runtime_tokio::json5;

    fn args(samples: &str, rest: &[(&'static str, Value)]) -> Args {
        let raw = json5::parse(samples).expect("parses");
        let mut pairs = vec![("samples", Value::Raw(raw))];
        pairs.extend_from_slice(rest);
        Args::of(&pairs)
    }

    fn delays(a: &Args) -> Vec<u64> {
        plan(a)
            .expect("a plan")
            .iter()
            .map(|e| e.delay_ms)
            .collect()
    }

    /// The replay tool's own vectors, through this role's reading of a document.
    #[test]
    fn the_role_paces_and_mutates_as_the_replay_tool_does() {
        let three = r#"[{ key: "k/a", text: "alpha", captured_at_ms: 0 },
                         { key: "k/b", text: "beta", captured_at_ms: 10,
                           mutation: { kind: "flip_bit", at_bit: 0 } },
                         { key: "k/c", text: "gamma", captured_at_ms: 20 }]"#;
        let declared = args(
            three,
            &[
                ("gap_ms", Value::Int(150)),
                ("max_gap_ms", Value::Int(10_000)),
            ],
        );
        let plan_ = plan(&declared).expect("a plan");
        assert_eq!(delays(&declared), [0, 150, 150]);
        assert_eq!(
            (plan_[1].bytes.as_slice(), plan_[1].mutated),
            (&b"ceta"[..], true)
        );
        let capture = args(
            r#"[{ key: "k/a", hex: "00ff10", captured_at_ms: 1000 },
                { key: "k/b", text: "x", captured_at_ms: 1400 },
                { key: "k/c", text: "y" }]"#,
            &[
                ("timing", Value::Text("capture".into())),
                ("gap_ms", Value::Int(100)),
                (
                    "speed",
                    Value::Decimal(wz_workload::arrivals::Decimal::parse("2.0").unwrap()),
                ),
                ("max_gap_ms", Value::Int(10_000)),
            ],
        );
        let p = plan(&capture).expect("a plan");
        assert_eq!(p[0].bytes, [0x00, 0xff, 0x10]);
        assert_eq!(
            p.iter().map(|e| (e.delay_ms, e.source)).collect::<Vec<_>>(),
            [
                (0, TimingSource::Declared),
                (200, TimingSource::Measured),
                (50, TimingSource::Unmeasurable)
            ]
        );
        let uncapped = args(
            r#"[{ key: "k", text: "a", captured_at_ms: 0 }, { key: "k", text: "b", captured_at_ms: 3600000 }]"#,
            &[
                ("timing", Value::Text("capture".into())),
                ("gap_ms", Value::Int(100)),
                ("max_gap_ms", Value::Null),
            ],
        );
        assert_eq!(delays(&uncapped), [0, 3_600_000]);
    }

    #[test]
    fn a_plan_over_its_ceilings_is_refused_whole() {
        let two = r#"[{ key: "k", text: "a" }, { key: "k", text: "b" }]"#;
        let long = args(
            two,
            &[
                ("gap_ms", Value::Int(100)),
                ("max_total_ms", Value::Int(99)),
            ],
        );
        assert_eq!(check(&long)[0].0, "max_total_ms");
        let exact = args(
            two,
            &[
                ("gap_ms", Value::Int(100)),
                ("max_total_ms", Value::Int(100)),
            ],
        );
        assert!(check(&exact).is_empty());
        let grow = r#"[{ key: "k", text: "a", mutation: { kind: "extend", count: 5, seed: 1 } }]"#;
        let over = args(grow, &[("max_extend_bytes", Value::Int(4))]);
        assert_eq!(check(&over)[0].0, "max_extend_bytes");
        let all = args(grow, &[("max_extend_total_bytes", Value::Int(4))]);
        assert_eq!(check(&all)[0].0, "max_extend_total_bytes");
    }

    #[test]
    fn the_judge_names_each_refusal_by_its_path() {
        let judged = |text: &str| -> Vec<String> {
            judge(&json5::parse(text).expect("parses"))
                .into_iter()
                .map(|(p, _)| p)
                .collect()
        };
        assert_eq!(judged("[]"), [""]);
        assert_eq!(judged(r#"{ key: "k" }"#), [""]);
        assert_eq!(judged(r#"[{ key: "k", text: "a", hex: "00" }]"#), ["[0]"]);
        assert_eq!(judged(r#"[{ key: "k" }]"#), ["[0]"]);
        assert_eq!(judged(r#"[{ key: "k", hex: "0g" }]"#), ["[0].hex"]);
        assert_eq!(
            judged(r#"[{ key: "k", text: "a", extra: 1 }]"#),
            ["[0].extra"]
        );
        assert_eq!(
            judged(r#"[{ key: "k", text: "a", mutation: { kind: "truncate", seed: 1 } }]"#),
            ["[0].mutation.seed", "[0].mutation.keep"]
        );
        assert_eq!(
            judged(r#"[{ key: "k", text: "a", mutation: { kind: "melt" } }]"#),
            ["[0].mutation.kind"]
        );
        assert!(judged(r#"[{ key: "k", text: "a", captured_at_ms: 3 }]"#).is_empty());
    }
}
