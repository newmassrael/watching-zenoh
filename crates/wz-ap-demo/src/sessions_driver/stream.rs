// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A stream of sends, as a role reads it from its keys: WHEN (`period_ms`, or `rate_per_s` as a
//! decimal, under an `arrivals` process: `periodic`, the default; `poisson`, exponential gaps of
//! that mean from an `arrival_seed`; or `burst`, `burst` sends back to back each gap), WHAT
//! (`payload` as text, `payload_hex`, or `payload_bytes` with a `fill` and, for the seeded fill, a
//! `seed`) and UNTIL WHEN (`count`, `duration_ms`, whichever comes first, or until the session
//! ends).
//!
//! The model and its definitions are `wz_workload`'s: the gap a rate gives, the open-loop schedule
//! of intended times (a send that cannot be made on time is made at once and the ones behind it
//! follow until the stream is back on its times, so the offered load is the plan's), and the bytes
//! of the n-th send. The `done` line says how late the latest send was against its intended time
//! (`late_max_us`), which is what a run that could not keep its schedule reports. This module
//! states the keys (`stream_keys!`), the rules across them and the loop that plays them, once, for
//! every role that is a stream; a role adds only how one send is made.

use std::time::Duration;

use tokio::time::Instant;
use wz_workload::arrivals::{gap_nanos as rate_gap, Arrivals, Process};
use wz_workload::payload::{Fill, Payload};

use super::{Args, Ctx};

/// The fill rules of `payload_bytes`.
pub(crate) const FILLS: &[&str] = &["zero", "counter", "seeded"];

/// The arrival processes of a stream.
pub(crate) const PROCESSES: &[&str] = &["periodic", "poisson", "burst"];

/// The key table of a role that is a stream: `key`, the stream's keys, then the role's own.
macro_rules! stream_keys {
    ($($own:expr),* $(,)?) => {
        &[
            KeyDef::required("key", KeyKind::Keyexpr),
            KeyDef::optional("payload", KeyKind::Text),
            KeyDef::optional("payload_hex", KeyKind::Hex),
            KeyDef::optional("payload_bytes", KeyKind::Count),
            KeyDef::optional("fill", KeyKind::Word($crate::sessions_driver::stream::FILLS)),
            KeyDef::optional("seed", KeyKind::Integer),
            KeyDef::optional("period_ms", KeyKind::Millis),
            KeyDef::optional("rate_per_s", KeyKind::Decimal),
            KeyDef::optional("arrivals", KeyKind::Word($crate::sessions_driver::stream::PROCESSES)),
            KeyDef::optional("arrival_seed", KeyKind::Integer),
            KeyDef::optional("burst", KeyKind::Count),
            KeyDef::optional("count", KeyKind::Count),
            KeyDef::optional("duration_ms", KeyKind::Millis),
            $($own,)*
        ]
    };
}
pub(crate) use stream_keys;

/// The rules across a stream's keys, as (key, why).
pub(crate) fn check(args: &Args) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let whats = ["payload", "payload_hex", "payload_bytes"];
    if whats.iter().filter(|k| args.has(k)).count() != 1 {
        out.push((
            "payload",
            "give exactly one of payload, payload_hex and payload_bytes".to_string(),
        ));
    }
    let whens = ["period_ms", "rate_per_s"];
    if whens.iter().filter(|k| args.has(k)).count() != 1 {
        out.push((
            "period_ms",
            "give exactly one of period_ms and rate_per_s".to_string(),
        ));
    }
    if let Some(rate) = args.decimal("rate_per_s") {
        if let Err(why) = rate_gap(rate) {
            out.push(("rate_per_s", why.to_string()));
        }
    }
    let process = args.text("arrivals").unwrap_or("periodic");
    match (process, args.has("arrival_seed")) {
        ("poisson", false) => out.push((
            "arrival_seed",
            "required by the poisson arrivals, so the gaps repeat".to_string(),
        )),
        ("poisson", true) | (_, false) => {}
        (_, true) => out.push((
            "arrival_seed",
            "is read only by the poisson arrivals".to_string(),
        )),
    }
    match (process, args.has("burst")) {
        ("burst", false) => out.push((
            "burst",
            "required by the burst arrivals: the sends of each burst".to_string(),
        )),
        ("burst", true) | (_, false) => {}
        (_, true) => out.push(("burst", "is read only by the burst arrivals".to_string())),
    }
    if !args.has("payload_bytes") {
        for key in ["fill", "seed"] {
            if args.has(key) {
                out.push((key, "is read only with payload_bytes".to_string()));
            }
        }
    } else {
        match (args.text("fill"), args.has("seed")) {
            (Some("seeded"), false) => out.push((
                "seed",
                "required by the seeded fill, so the bytes repeat".to_string(),
            )),
            (Some("seeded"), true) => {}
            (_, true) => out.push(("seed", "is read only by the seeded fill".to_string())),
            _ => {}
        }
    }
    out
}

/// The schedule of a stream whose keys passed [`check`]: the gap the rate or the period gives is
/// the periodic gap, the Poisson mean, or the gap between bursts.
pub(crate) fn schedule(args: &Args) -> Arrivals {
    let gap = match args.decimal("rate_per_s") {
        Some(rate) => rate_gap(rate).unwrap_or(u64::MAX),
        None => args.int("period_ms").unwrap_or(1).saturating_mul(1_000_000),
    };
    Arrivals::new(match args.text("arrivals") {
        Some("poisson") => Process::Poisson {
            mean_gap_nanos: gap,
            seed: args.int("arrival_seed").unwrap_or(0),
        },
        Some("burst") => Process::Burst {
            size: args.int("burst").unwrap_or(1),
            gap_nanos: gap,
        },
        _ => Process::Periodic { gap_nanos: gap },
    })
}

/// Play a stream whose keys passed [`check`]: make each payload and hand it to `send` at its
/// intended time, or at once when that time has passed, until `count` sends or `duration_ms` of
/// intended time, then say how many were sent and how late the latest one was.
pub(crate) async fn run(ctx: &Ctx, key: &str, mut send: impl FnMut(&[u8])) {
    let args = ctx.args();
    let payload = payload(args);
    let mut arrivals = schedule(args);
    let count = args.int("count");
    let duration = args.int("duration_ms").map(Duration::from_millis);
    let mut bytes = vec![0u8; payload.len()];
    let start = Instant::now();
    let mut sent = 0u64;
    let mut late_max = Duration::ZERO;
    loop {
        if count.is_some_and(|n| sent >= n) {
            break;
        }
        let due = Duration::from_nanos(arrivals.due());
        if duration.is_some_and(|d| due >= d) {
            break;
        }
        tokio::time::sleep_until(start + due).await;
        late_max = late_max.max(start.elapsed().saturating_sub(due));
        payload.write(sent, &mut bytes);
        send(&bytes);
        sent += 1;
        arrivals.advance();
    }
    ctx.say.line(&format!(
        "done key={key} count={sent} late_max_us={}",
        late_max.as_micros()
    ));
}

/// The payload of a stream whose keys passed [`check`]: the fill of `payload_bytes` is `counter`
/// when none is named, which is the one a receiver can measure loss and order with.
pub(crate) fn payload(args: &Args) -> Payload {
    if let Some(text) = args.text("payload") {
        return Payload::Fixed(text.as_bytes().to_vec());
    }
    if let Some(bytes) = args.bytes("payload_hex") {
        return Payload::Fixed(bytes.to_vec());
    }
    let fill = match args.text("fill") {
        Some("zero") => Fill::Zero,
        Some("seeded") => Fill::Seeded {
            seed: args.int("seed").unwrap_or(0),
        },
        _ => Fill::Counter,
    };
    Payload::Generated {
        size: args.int("payload_bytes").unwrap_or(0) as usize,
        fill,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions_driver::Value;
    use wz_workload::arrivals::Decimal;

    fn keys(rules: &[(&'static str, Value)]) -> Vec<&'static str> {
        check(&Args::of(rules))
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    }

    fn rate(text: &str) -> Value {
        Value::Decimal(Decimal::parse(text).expect("a decimal"))
    }

    #[test]
    fn a_stream_names_one_what_and_one_when() {
        let text = ("payload", Value::Text("hi".into()));
        let period = ("period_ms", Value::Int(20));
        assert!(keys(&[text.clone(), period.clone()]).is_empty());
        assert_eq!(keys(std::slice::from_ref(&period)), ["payload"]);
        assert_eq!(
            keys(&[
                text.clone(),
                ("payload_bytes", Value::Int(4)),
                period.clone()
            ]),
            ["payload"]
        );
        assert_eq!(keys(std::slice::from_ref(&text)), ["period_ms"]);
        assert_eq!(
            keys(&[text.clone(), period, ("rate_per_s", rate("2"))]),
            ["period_ms"]
        );
        assert!(keys(&[text.clone(), ("rate_per_s", rate("1000000"))]).is_empty());
        assert_eq!(
            keys(&[text.clone(), ("rate_per_s", rate("1000001"))]),
            ["rate_per_s"]
        );
        assert_eq!(
            keys(&[
                text,
                ("rate_per_s", rate("1")),
                ("fill", Value::Text("zero".into()))
            ]),
            ["fill"]
        );
        let bytes = ("payload_bytes", Value::Int(8));
        let every = ("rate_per_s", rate("0.5"));
        let seeded = ("fill", Value::Text("seeded".into()));
        assert_eq!(
            keys(&[bytes.clone(), every.clone(), seeded.clone()]),
            ["seed"]
        );
        assert!(keys(&[
            bytes.clone(),
            every.clone(),
            seeded,
            ("seed", Value::Int(0))
        ])
        .is_empty());
        assert_eq!(keys(&[bytes, every, ("seed", Value::Int(1))]), ["seed"]);
    }

    #[test]
    fn an_arrival_process_takes_its_own_keys_and_no_other() {
        let base = [
            ("payload", Value::Text("x".into())),
            ("period_ms", Value::Int(10)),
        ];
        let with = |extra: &[(&'static str, Value)]| {
            let mut all = base.to_vec();
            all.extend_from_slice(extra);
            keys(&all)
        };
        let word = |w: &str| ("arrivals", Value::Text(w.into()));
        assert!(with(&[word("periodic")]).is_empty());
        assert_eq!(with(&[word("poisson")]), ["arrival_seed"]);
        assert!(with(&[word("poisson"), ("arrival_seed", Value::Int(0))]).is_empty());
        assert_eq!(with(&[("arrival_seed", Value::Int(1))]), ["arrival_seed"]);
        assert_eq!(with(&[word("burst")]), ["burst"]);
        assert!(with(&[word("burst"), ("burst", Value::Int(3))]).is_empty());
        assert_eq!(
            with(&[
                word("poisson"),
                ("arrival_seed", Value::Int(1)),
                ("burst", Value::Int(2))
            ]),
            ["burst"]
        );
        let poisson = Args::of(&[
            word("poisson"),
            ("arrival_seed", Value::Int(4)),
            ("rate_per_s", rate("100")),
        ]);
        assert_eq!(
            schedule(&poisson).process(),
            Process::Poisson {
                mean_gap_nanos: 10_000_000,
                seed: 4
            }
        );
        let burst = Args::of(&[
            word("burst"),
            ("burst", Value::Int(3)),
            ("period_ms", Value::Int(5)),
        ]);
        assert_eq!(
            schedule(&burst).process(),
            Process::Burst {
                size: 3,
                gap_nanos: 5_000_000
            }
        );
    }

    #[test]
    fn the_keys_read_into_the_workload() {
        let half = Args::of(&[("rate_per_s", rate("0.5"))]);
        assert_eq!(
            schedule(&half).process(),
            Process::Periodic {
                gap_nanos: 2_000_000_000
            }
        );
        let every = Args::of(&[("period_ms", Value::Int(20))]);
        assert_eq!(
            schedule(&every).process(),
            Process::Periodic {
                gap_nanos: 20_000_000
            }
        );
        let made = Args::of(&[("payload_bytes", Value::Int(3))]);
        assert_eq!(
            payload(&made),
            Payload::Generated {
                size: 3,
                fill: Fill::Counter
            }
        );
        let hex = Args::of(&[("payload_hex", Value::Bytes(vec![0, 0xff]))]);
        assert_eq!(payload(&hex), Payload::Fixed(vec![0, 0xff]));
    }
}
