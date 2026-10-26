// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A stream of sends, as a role reads it from its keys: WHEN (`period_ms`, or `rate_per_s` as a
//! decimal), WHAT (`payload` as text, `payload_hex`, or `payload_bytes` with a `fill` and, for the
//! seeded fill, a `seed`) and UNTIL WHEN (`count`, `duration_ms`, whichever comes first, or until
//! the session ends).
//!
//! The model and its definitions are `wz_workload`'s: the gap a rate gives, the open-loop schedule
//! of absolute deadlines that counts the deadlines it passed instead of bursting, and the bytes of
//! the n-th send. This module only reads the keys into them and states the rules across the keys,
//! once, for every role that is a stream.

use wz_workload::arrivals::{gap_nanos as rate_gap, Periodic};
use wz_workload::payload::{Fill, Payload};

use super::Args;

/// The fill rules of `payload_bytes`.
pub(crate) const FILLS: &[&str] = &["zero", "counter", "seeded"];

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

/// The schedule of a stream whose keys passed [`check`].
pub(crate) fn schedule(args: &Args) -> Periodic {
    let gap = match args.decimal("rate_per_s") {
        Some(rate) => rate_gap(rate).unwrap_or(u64::MAX),
        None => args.int("period_ms").unwrap_or(1).saturating_mul(1_000_000),
    };
    Periodic::new(gap)
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
    fn the_keys_read_into_the_workload() {
        let half = Args::of(&[("rate_per_s", rate("0.5"))]);
        assert_eq!(schedule(&half).gap_nanos(), 2_000_000_000);
        let every = Args::of(&[("period_ms", Value::Int(20))]);
        assert_eq!(schedule(&every).gap_nanos(), 20_000_000);
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
