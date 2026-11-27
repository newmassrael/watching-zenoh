// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Seal a lifecycle command with a commander's key, for a test or an operator to hand to a node.
//!
//! ```text
//! cargo run -p wz-command-seal --example seal_command -- \
//!     <key.pem> <verb> <node-zid> <peer-zid> <counter> [<generation>]
//! ```
//!
//! The key is the PKCS#8 PEM (`BEGIN PRIVATE KEY`) of a P-256 key, which
//! `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256` writes. The verb is one of
//! `open`, `open_passive`, `close`, `reset` (which takes the generation) and `status`. A zid
//! is spelled as a lifecycle key spells it: the id in lowercase hex with no leading zero. The
//! sealed command is printed in hex on stdout, and the commander's zid, spelled the same way, on
//! stderr: the zid a node's grant names.

use std::fmt::Write as _;
use std::process::ExitCode;

use base64::Engine as _;
use wz_command_seal::{
    seal, zid_of_point, Command, Es256Signer, Object, RingSigner, Verb, Zid, MAX_SEALED_LEN,
};

const USAGE: &str =
    "usage: seal_command <key.pem> <verb> <node-zid> <peer-zid> <counter> [<generation>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("seal_command: {why}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let [key, verb, node, peer, counter, rest @ ..] = args else {
        return Err(USAGE.to_owned());
    };
    let generation = match rest {
        [] => None,
        [generation] => Some(number(generation)?),
        _ => return Err(USAGE.to_owned()),
    };
    let pem = std::fs::read_to_string(key).map_err(|error| format!("{key}: {error}"))?;
    let signer =
        RingSigner::from_pkcs8(&pkcs8_of_pem(&pem)?).map_err(|error| format!("{key}: {error}"))?;
    let verb = Verb::of_word(verb.as_bytes())
        .ok_or_else(|| format!("{verb}: not a verb (open, open_passive, close, reset, status)"))?;
    let command = Command {
        verb,
        node: zid(node)?,
        object: Object {
            peer: zid(peer)?,
            generation,
        },
        counter: number(counter)?,
    };
    let mut out = [0u8; MAX_SEALED_LEN];
    let len = seal(&command, &signer, &mut out).map_err(|error| error.to_string())?;
    let mut text = String::with_capacity(MAX_SEALED_LEN * 2);
    for byte in &out[..len] {
        write!(text, "{byte:02x}").map_err(|error| error.to_string())?;
    }
    eprintln!(
        "commander {:x}",
        u128::from_le_bytes(zid_of_point(&signer.point()))
    );
    println!("{text}");
    Ok(())
}

/// The DER of a PKCS#8 PEM.
fn pkcs8_of_pem(pem: &str) -> Result<Vec<u8>, String> {
    const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
    const END: &str = "-----END PRIVATE KEY-----";
    if pem.contains("-----BEGIN EC PRIVATE KEY-----") {
        return Err(
            "a SEC 1 key: write it as PKCS#8 with `openssl pkcs8 -topk8 -nocrypt`".to_owned(),
        );
    }
    let body = pem
        .split_once(BEGIN)
        .and_then(|(_, after)| after.split_once(END))
        .map(|(body, _)| body)
        .ok_or_else(|| format!("no {BEGIN} block"))?;
    let body: String = body.split_whitespace().collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|error| format!("the PEM body: {error}"))
}

/// A zid as a lifecycle key spells it, refused as `wz_session_core` refuses one: empty, a
/// leading zero, an uppercase digit, or not hex of at most 32 digits.
fn zid(text: &str) -> Result<Zid, String> {
    let refused = || format!("{text}: not a zid (lowercase hex, no leading zero)");
    if text.is_empty() || text.starts_with('0') || text.contains(|c: char| c.is_ascii_uppercase()) {
        return Err(refused());
    }
    u128::from_str_radix(text, 16)
        .map(u128::to_le_bytes)
        .map_err(|_| refused())
}

fn number(text: &str) -> Result<u64, String> {
    text.parse()
        .map_err(|_| format!("{text}: not an unsigned 64-bit number"))
}
