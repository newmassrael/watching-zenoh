// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2624 — publish ONE Put carrying a timestamp OFFSET from the session's own
//! clock, and print the value sent, so a leg can compare it with what a foreign
//! subscriber on the far side of a wz router receives.
//!
//! ## Why the offset is the whole interface
//!
//! wz's router consumes an inbound timestamp in `treat_timestamp`
//! (`crates/wz-runtime-tokio/src/node_clock.rs`), and which of its arms runs is
//! decided by ONE number -- how far ahead the timestamp is against uhlc's 500 ms
//! drift bound:
//!
//! * INSIDE the bound  -> ABSORB. `update_with_timestamp` succeeds and the
//!   function returns early, leaving the message untouched. The subscriber must
//!   therefore receive the timestamp THIS PROGRAM SENT, unchanged.
//! * BEYOND the bound  -> REPLACE. uhlc rejects it, and wz falls through to
//!   stamping its own now, which is zenoh's shipped `drop_future_timestamp:
//!   false` behaviour. The subscriber must receive a DIFFERENT, SMALLER value.
//!
//! So one binary and one flag drive both arms, and they are each other's
//! control: same publisher, same topology, one number changed, opposite
//! outcomes. That is what no pair of upstream example binaries could do, since
//! none of them lets the timestamp be chosen at all.
//!
//! ## What makes it a FOREIGN witness
//!
//! Every byte on the wire here is produced by zenoh 1.10.1 -- its session, its
//! codec, its `Timestamp` type. This program chooses a VALUE and nothing else,
//! which is the same kind of parameterisation `z_view_size --id <x>` already
//! relies on. The clock identity is upstream's too: the timestamp is built from
//! `Session::new_timestamp()` and only its time component is moved, so the id
//! that travels is the foreign session's own.

use std::time::Duration;

// R2624 — NO `use zenoh::internal::traits::TimestampBuilderTrait;` here, and
// that absence is a MEASUREMENT rather than a guess. The first draft imported
// it, because that is how `zenoh-ext` reaches `.timestamp(..)`
// (`zenoh-ext/src/advanced_publisher.rs` @ `        traits::{`). The compiler
// reported the import UNUSED: `#[zenoh_macros::internal_trait]` also emits an
// inherent method on the builder, so the call resolves without the trait being
// in scope. Keeping a dead import would have made this oracle look like it
// needed a feature it does not.
use zenoh::time::{Timestamp, NTP64};

/// Exit with a diagnostic rather than a panic: this runs as a child process in a
/// fixture, and a clean message on stderr is what the leg surfaces when it fails.
fn die(msg: &str) -> ! {
    eprintln!("future-stamp: {msg}");
    std::process::exit(2);
}

struct Args {
    endpoint: String,
    key: String,
    value: String,
    offset_ms: i64,
}

fn parse_args() -> Args {
    let mut endpoint = None;
    let mut key = None;
    let mut value = None;
    let mut offset_ms = None;
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut take = |what: &str| argv.next().unwrap_or_else(|| die(&format!("{what} needs a value")));
        match flag.as_str() {
            "-e" | "--endpoint" => endpoint = Some(take("--endpoint")),
            "-k" | "--key" => key = Some(take("--key")),
            "-v" | "--value" => value = Some(take("--value")),
            "--offset-ms" => {
                let raw = take("--offset-ms");
                offset_ms = Some(
                    raw.parse::<i64>()
                        .unwrap_or_else(|_| die(&format!("--offset-ms {raw} is not an integer"))),
                );
            }
            other => die(&format!("unknown argument {other}")),
        }
    }
    Args {
        endpoint: endpoint.unwrap_or_else(|| die("--endpoint is required")),
        key: key.unwrap_or_else(|| die("--key is required")),
        value: value.unwrap_or_else(|| die("--value is required")),
        // No default: the offset is the experiment, so leaving it implicit would
        // let a fixture drive an arm it did not mean to.
        offset_ms: offset_ms.unwrap_or_else(|| die("--offset-ms is required")),
    }
}

#[tokio::main]
async fn main() {
    let args = parse_args();

    // CLIENT mode against one explicit endpoint, with scouting off: the fixture
    // points this at a wz router's ephemeral port, and a multicast-discovered
    // peer would make "which node did it reach" unanswerable.
    let mut config = zenoh::Config::default();
    for (path, json) in [
        ("mode", "\"client\"".to_string()),
        ("connect/endpoints", format!("[\"{}\"]", args.endpoint)),
        ("scouting/multicast/enabled", "false".to_string()),
    ] {
        if config.insert_json5(path, &json).is_err() {
            die(&format!("could not set config {path}"));
        }
    }

    let session = match zenoh::open(config).await {
        Ok(s) => s,
        Err(e) => die(&format!("open failed: {e}")),
    };

    // The session's OWN timestamp, moved in time but keeping upstream's clock
    // id. `new_timestamp` is the documented way to mint one
    // (`zenoh/src/lib.rs` @ `/// let timestamp = session.new_timestamp();`).
    let base = session.new_timestamp();
    let shift = NTP64::from(Duration::from_millis(args.offset_ms.unsigned_abs()));
    let shifted = if args.offset_ms >= 0 {
        *base.get_time() + shift
    } else {
        *base.get_time() - shift
    };
    let stamp = Timestamp::new(shifted, *base.get_id());

    // Printed BEFORE the put and flushed, so a leg that later fails still has
    // the value to compare against in the captured output.
    println!("future-stamp: sending timestamp ntp64={}", stamp.get_time().as_u64());
    println!(
        "future-stamp: key='{}' value='{}' offset_ms={}",
        args.key, args.value, args.offset_ms
    );

    if let Err(e) = session
        .put(args.key.as_str(), args.value.as_str())
        .timestamp(stamp)
        .await
    {
        die(&format!("put failed: {e}"));
    }
    println!("future-stamp: put done");

    // Close explicitly rather than dropping: the fixture reads this program's
    // exit as "the Put is on the wire", and an implicit drop does not promise
    // the session flushed before the process ends.
    if let Err(e) = session.close().await {
        die(&format!("close failed: {e}"));
    }
}
