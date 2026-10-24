//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-keyexpr 1.10.1, file
// src/key_expr/fuzzer.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

use alloc::{string::String, vec::Vec};

use super::OwnedKeyExpr;

/// A chunk of one or two letters from a small alphabet (so that two generated key expressions often
/// have chunks in common), with a small chance of being verbatim.
fn random_chunk(rng: &mut impl rand::Rng, out: &mut String) {
    if rng.gen_bool(0.05) {
        out.push('@');
    }
    for _ in 0..rng.gen_range(1..3) {
        out.push(if rng.gen_bool(0.5) { 'a' } else { 'b' });
    }
}

/// One chunk of a random key expression: a wildcard, a literal chunk, or a literal chunk with a
/// `$*` in it.
fn random_chunk_with_wilds(rng: &mut impl rand::Rng) -> String {
    let mut chunk = String::new();
    match rng.gen_range(0..16) {
        0..=2 => chunk.push_str("**"),
        3..=5 => chunk.push('*'),
        6..=7 => {
            // A literal chunk with a `$*` after its first letter, or at its end.
            random_chunk(rng, &mut chunk);
            chunk.push_str("$*");
            if rng.gen_bool(0.5) {
                random_chunk(rng, &mut chunk);
            }
        }
        _ => random_chunk(rng, &mut chunk),
    }
    chunk
}

/// A generator of random key expressions: an endless iterator of canon [`OwnedKeyExpr`]s.
#[derive(Debug)]
pub struct KeyExprFuzzer<Rng: rand::Rng>(pub Rng);

impl<Rng: rand::Rng> Iterator for KeyExprFuzzer<Rng> {
    type Item = OwnedKeyExpr;
    fn next(&mut self) -> Option<Self::Item> {
        let chunks: Vec<String> = (0..self.0.gen_range(1..6))
            .map(|_| random_chunk_with_wilds(&mut self.0))
            .collect();
        // Whatever the chunks make is made canon, which is what the generator promises.
        Some(OwnedKeyExpr::autocanonize(chunks.join("/")).unwrap())
    }
}
