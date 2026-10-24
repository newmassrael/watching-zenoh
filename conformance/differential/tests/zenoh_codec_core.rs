// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-codec`, the codec traits, the integer, byte-string, array and buffer codecs, the codecs of
//! the core types and the extensions (the first slice of the crate): upstream's crate (`up_codec`)
//! and wz's (`wz_codec`) given the same values to write and the same bytes to read, results equal
//! as text, the bytes written and the bytes left unread included.
//!
//! * INTEGERS are written for a grid of values (every power of two and its predecessor, every edge
//!   of a length of the encoding, seeded draws of every bit length) and read from every one- and
//!   two-byte string, every string of six or fewer bytes made of five classes of byte, seeded longer
//!   ones, and every encoding the writer produced; each of the 29 ways of reading an integer is held
//!   to a MODEL as well as to the other crate. A bounded writer is given buffers of every capacity
//!   from none to twelve bytes, which is where the nine-byte slot a value is written through shows.
//! * BYTES, STRINGS and ARRAYS are written at every length that is an edge of the encoding and read
//!   from prefixes whose length is short of, equal to and past the bytes behind it, from invalid
//!   UTF-8 and from truncated and overlong lengths.
//! * The core types (`Encoding`, `Locator`, `Timestamp`, `ZenohIdProto`, `WireExpr`, `ZSlice`, `ZBuf`)
//!   are written and read the same way, and the extensions (unit, 64-bit, buffer, buffer header and
//!   unknown, singly and in lists) from every header byte and eight tails, by every reader the crate
//!   has, `read`, `skip` and `skip_all` among them.
//!
//! Upstream reads a value into a type narrower than the integer it was written as by KEEPING THE LOW
//! BITS (a `u16` or `u32` read directly, a bounded integer read into a narrower type, and the id of
//! an `Encoding`, which is a `u16` read from a 31-bit field), so a wire value that does not fit is
//! another message and not a refused one. wz refuses it. That is one class, and it is counted and
//! held on both sides: each crate matches the model of its own definition for every input and the two
//! differ only on inputs where upstream truncates.
//!
//! The crates are built without `shared-memory`; that arm is held by the surface gate until the
//! member of the shared-memory buffers lands.

use std::collections::BTreeSet;

use rand::{rngs::StdRng, Rng, SeedableRng};

type Rows = Vec<(String, String)>;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A long value as its length and its first bytes, so a row stays a line.
fn summary(b: &[u8]) -> String {
    format!("{}:{}", b.len(), hex(&b[..b.len().min(12)]))
}

/// The reference encoding of an integer: seven bits to a byte, the high bit saying more follows, and
/// a ninth byte that is a whole byte of value.
fn vle(mut x: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..8 {
        if x < 0x80 {
            out.push(x as u8);
            return out;
        }
        out.push((x as u8 & 0x7f) | 0x80);
        x >>= 7;
    }
    out.push(x as u8);
    out
}

/// The reference decoder: the value and the bytes it took, or none if the bytes ran out.
fn vle_read(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for i in 0..9 {
        let byte = *b.get(i)?;
        if i == 8 {
            v |= (byte as u64) << 56;
            return Some((v, 9));
        }
        v |= ((byte & 0x7f) as u64) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    unreachable!()
}

fn write_values() -> Vec<u64> {
    let mut set = BTreeSet::new();
    for v in [
        0u64,
        1,
        2,
        0x7f,
        0x80,
        0x81,
        0xff,
        0x100,
        u32::MAX as u64,
        u64::MAX,
    ] {
        set.insert(v);
    }
    for k in 0..64 {
        set.insert(1u64 << k);
        set.insert((1u64 << k) - 1);
        set.insert((1u64 << k) + 1);
    }
    let mut rng = StdRng::seed_from_u64(0xC0DEC);
    for bits in 1..=64u32 {
        for _ in 0..6 {
            let v: u64 = rng.gen::<u64>() >> (64 - bits);
            set.insert(v);
        }
    }
    set.into_iter().collect()
}

/// The strings an integer is read from.
fn varint_inputs() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![vec![]];
    for a in 0..=255u8 {
        out.push(vec![a]);
    }
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            out.push(vec![a, b]);
        }
    }
    let classes = [0x00u8, 0x01, 0x7f, 0x80, 0xff];
    for len in 3..=6u32 {
        for n in 0..5usize.pow(len) {
            let mut m = n;
            let mut s = Vec::new();
            for _ in 0..len {
                s.push(classes[m % 5]);
                m /= 5;
            }
            out.push(s);
        }
    }
    let mut rng = StdRng::seed_from_u64(0x7A11);
    for _ in 0..4000 {
        let len = rng.gen_range(7..=11);
        out.push(
            (0..len)
                .map(|_| {
                    if rng.gen_bool(0.7) {
                        classes[rng.gen_range(0..5)]
                    } else {
                        rng.gen()
                    }
                })
                .collect(),
        );
    }
    for v in write_values() {
        let mut e = vle(v);
        out.push(e.clone());
        e.push(0x55);
        out.push(e);
    }
    out
}

/// Strings that carry a length in front of a body: the length short of, equal to and past the body,
/// invalid UTF-8, and lengths that are cut off or are not the shortest.
fn prefixed_inputs() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for l in [0usize, 1, 3, 127, 128, 255, 256, 300, 70_000] {
        for delta in [-1i64, 0, 2] {
            let body = (l as i64 + delta).max(0) as usize;
            let mut b = vle(l as u64);
            b.extend(vec![b'a'; body]);
            out.push(b);
        }
    }
    for body in [
        vec![0xffu8],
        vec![0xc3, 0x28],
        vec![0xe2, 0x82],
        vec![0xf0, 0x9f, 0x92, 0x96],
    ] {
        let mut b = vle(body.len() as u64);
        b.extend(body);
        out.push(b);
    }
    out.push(vec![0x80]);
    out.push(vec![0xff, 0xff]);
    out.push(vec![0x81, 0x00, b'x']);
    out.push(vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]);
    out.push(vec![0xff; 9]);
    out.push(vec![]);
    out
}

/// Each bounded reader of an integer, one bound at a time, into each width.
macro_rules! rd_bounded {
    ($c:ident, $bytes:expr, $out:ident, $bound:ty; $($zint:ty),+) => {
        $( {
            let mut r: &[u8] = $bytes;
            let v: Result<$zint, _> = $c::Zenoh080Bounded::<$bound>::new().read(&mut r);
            $out.push(v.ok().map(|x| x as u64));
        } )+
    };
}

/// Each bounded writer of an integer, one bound at a time, from each width.
macro_rules! wr_bounded {
    ($c:ident, $rows:ident, $key:expr, $v:expr; $bound:ty; $($zint:ty),+) => {
        $( {
            let x = $v as $zint;
            let k = format!(
                "{} bounded<{}> as {} {}",
                $key,
                stringify!($bound),
                stringify!($zint),
                x as u64
            );
            let out = enc(|w| $c::Zenoh080Bounded::<$bound>::new().write(w, x));
            $rows.push((k, out));
        } )+
    };
}

/// The array codecs of some lengths, written, measured and read.
macro_rules! array_rows {
    ($c:ident, $rows:ident; $($n:literal),+) => {
        $( {
            let a = [0x5Au8; $n];
            $rows.push((
                format!("array {} write", $n),
                enc(|w| $c::Zenoh080.write(w, a)),
            ));
            $rows.push((
                format!("array {} write ref", $n),
                enc(|w| $c::Zenoh080.write(w, &a)),
            ));
            $rows.push((
                format!("array {} w_len", $n),
                format!("{}", $c::Zenoh080.w_len(a)),
            ));
            for have in [0usize, $n - 1, $n, $n + 3] {
                let src = vec![0xA7u8; have];
                $rows.push((
                    format!("array {} read from {have}", $n),
                    dec(&src, |r| {
                        let x: Result<[u8; $n], _> = $c::Zenoh080.read(r);
                        x
                    }),
                ));
            }
        } )+
    };
}

macro_rules! codec_cases {
    ($name:ident, $c:ident, $p:ident, $b:ident) => {
        mod $name {
            use std::{borrow::Cow, fmt::Debug};

            use $b::{
                buffer::Buffer,
                reader::{DidntRead, Reader},
                writer::{DidntWrite, HasWriter, Writer},
                BBuf, ZBuf, ZSlice,
            };
            use $c::{
                LCodec, RCodec, WCodec, Zenoh080, Zenoh080Bounded, Zenoh080Condition,
                Zenoh080Header, Zenoh080Length, Zenoh080Reliability,
            };
            use $p::{
                common::{
                    ZExtBody, ZExtUnit, ZExtUnknown, ZExtZ64, ZExtZBuf, ZExtZBufHeader,
                },
                core::{
                    encoding::EncodingId, Encoding, Locator, Reliability, Timestamp, WireExpr,
                    ZenohIdProto,
                },
                network::Mapping,
            };

            use super::{hex, summary, Rows};

            /// What a write returned and the bytes it left, whatever the writer.
            fn enc<F>(f: F) -> String
            where
                F: FnOnce(&mut &mut Vec<u8>) -> Result<(), DidntWrite>,
            {
                let mut v: Vec<u8> = Vec::new();
                let r = {
                    let mut w = (&mut v).writer();
                    f(&mut w)
                };
                format!("{} {}", if r.is_ok() { "ok" } else { "err" }, hex(&v))
            }

            /// The same through a buffer of `capacity` bytes.
            fn enc_bbuf<F>(capacity: usize, f: F) -> String
            where
                F: FnOnce(&mut &mut BBuf) -> Result<(), DidntWrite>,
            {
                let mut v = BBuf::with_capacity(capacity);
                let r = {
                    let mut w = (&mut v).writer();
                    f(&mut w)
                };
                format!("{} {}", if r.is_ok() { "ok" } else { "err" }, hex(v.as_slice()))
            }

            /// What a read returned and how many bytes it left behind.
            fn dec<T: Debug, E, F>(bytes: &[u8], f: F) -> String
            where
                F: FnOnce(&mut &[u8]) -> Result<T, E>,
            {
                let mut r: &[u8] = bytes;
                let out = f(&mut r);
                let rem = r.len();
                match out {
                    Ok(v) => format!("ok {v:?} rem={rem}"),
                    Err(_) => format!("err rem={rem}"),
                }
            }

            fn zid(n: usize) -> ZenohIdProto {
                let bytes: Vec<u8> = (0..n).map(|i| i as u8 + 1).collect();
                ZenohIdProto::try_from(bytes.as_slice()).unwrap()
            }

            /// The writes of an integer, whatever its width.
            pub fn int_writes() -> Rows {
                let mut rows = Rows::new();
                for v in super::write_values() {
                    let k = format!("u64 {v}");
                    rows.push((format!("{k} bytes"), enc(|w| Zenoh080.write(w, v))));
                    rows.push((format!("{k} ref"), enc(|w| Zenoh080.write(w, &v))));
                    rows.push((format!("{k} w_len"), format!("{}", Zenoh080.w_len(v))));
                    if v <= u16::MAX as u64 {
                        rows.push((
                            format!("{k} as u16"),
                            enc(|w| Zenoh080.write(w, v as u16)),
                        ));
                        rows.push((
                            format!("{k} as u16 w_len"),
                            format!("{}", Zenoh080.w_len(v as u16)),
                        ));
                    }
                    if v <= u32::MAX as u64 {
                        rows.push((
                            format!("{k} as u32"),
                            enc(|w| Zenoh080.write(w, v as u32)),
                        ));
                        rows.push((
                            format!("{k} as u32 w_len"),
                            format!("{}", Zenoh080.w_len(v as u32)),
                        ));
                    }
                    rows.push((
                        format!("{k} as usize"),
                        enc(|w| Zenoh080.write(w, v as usize)),
                    ));
                    rows.push((
                        format!("{k} as usize w_len"),
                        format!("{}", Zenoh080.w_len(v as usize)),
                    ));
                    if v <= 0xff {
                        rows.push((format!("{k} as u8"), enc(|w| Zenoh080.write(w, v as u8))));
                        rows.push((
                            format!("{k} as u8 w_len"),
                            format!("{}", Zenoh080.w_len(v as u8)),
                        ));
                    }
                    wr_bounded!($c, rows, k, v; u8; u8, u16, u32, u64, usize);
                    wr_bounded!($c, rows, k, v; u16; u8, u16, u32, u64, usize);
                    wr_bounded!($c, rows, k, v; u32; u8, u16, u32, u64, usize);
                    wr_bounded!($c, rows, k, v; u64; u8, u16, u32, u64, usize);
                    wr_bounded!($c, rows, k, v; usize; u8, u16, u32, u64, usize);
                }
                // A bounded buffer: a value is written through a slot of nine bytes whatever it
                // takes, so a buffer with fewer than nine bytes left refuses a value of one byte.
                for capacity in 0..=12 {
                    for v in [0u64, 0x7f, 0x80, 0x3fff, 0x4000, u32::MAX as u64, u64::MAX] {
                        rows.push((
                            format!("bbuf {capacity} u64 {v}"),
                            enc_bbuf(capacity, |w| Zenoh080.write(w, v)),
                        ));
                    }
                    rows.push((
                        format!("bbuf {capacity} u8"),
                        enc_bbuf(capacity, |w| Zenoh080.write(w, 0xA5u8)),
                    ));
                    rows.push((
                        format!("bbuf {capacity} bytes"),
                        enc_bbuf(capacity, |w| Zenoh080.write(w, [1u8, 2, 3].as_slice())),
                    ));
                }
                rows
            }

            /// Each way of reading an integer from `bytes`: the value it gave (none if it refused)
            /// in a fixed order, and the bytes left after the first of them.
            ///
            /// 0 `u64`, 1 `u16`, 2 `u32`, 3 `usize`, then for each bound of `u8`, `u16`, `u32`,
            /// `u64` and `usize` each of the same five widths.
            pub fn int_reads(bytes: &[u8]) -> (Vec<Option<u64>>, usize) {
                let mut out: Vec<Option<u64>> = Vec::new();
                let mut r: &[u8] = bytes;
                let v: Result<u64, _> = Zenoh080.read(&mut r);
                out.push(v.ok());
                let rem = r.len();
                let mut r: &[u8] = bytes;
                let v: Result<u16, _> = Zenoh080.read(&mut r);
                out.push(v.ok().map(u64::from));
                let mut r: &[u8] = bytes;
                let v: Result<u32, _> = Zenoh080.read(&mut r);
                out.push(v.ok().map(u64::from));
                let mut r: &[u8] = bytes;
                let v: Result<usize, _> = Zenoh080.read(&mut r);
                out.push(v.ok().map(|x| x as u64));
                rd_bounded!($c, bytes, out, u8; u8, u16, u32, u64, usize);
                rd_bounded!($c, bytes, out, u16; u8, u16, u32, u64, usize);
                rd_bounded!($c, bytes, out, u32; u8, u16, u32, u64, usize);
                rd_bounded!($c, bytes, out, u64; u8, u16, u32, u64, usize);
                rd_bounded!($c, bytes, out, usize; u8, u16, u32, u64, usize);
                (out, rem)
            }

            /// Byte strings, strings and arrays, written and read.
            pub fn byte_rows() -> Rows {
                let mut rows = Rows::new();
                for n in [0usize, 1, 2, 127, 128, 255, 256, 300, 16_384] {
                    let bytes = vec![0xA5u8; n];
                    let text = "a".repeat(n);
                    let string = text.clone();
                    let k = format!("len {n}");
                    rows.push((format!("{k} bytes"), enc(|w| Zenoh080.write(w, bytes.as_slice()))));
                    rows.push((format!("{k} str"), enc(|w| Zenoh080.write(w, text.as_str()))));
                    rows.push((format!("{k} string"), enc(|w| Zenoh080.write(w, &string))));
                    rows.push((
                        format!("{k} w_len"),
                        format!(
                            "{} {} {}",
                            Zenoh080.w_len(bytes.as_slice()),
                            Zenoh080.w_len(text.as_str()),
                            Zenoh080.w_len(&string)
                        ),
                    ));
                    rows.push((
                        format!("{k} bounded u8"),
                        enc(|w| Zenoh080Bounded::<u8>::new().write(w, bytes.as_slice())),
                    ));
                    rows.push((
                        format!("{k} bounded u16 str"),
                        enc(|w| Zenoh080Bounded::<u16>::new().write(w, text.as_str())),
                    ));
                    rows.push((
                        format!("{k} bounded u32 string"),
                        enc(|w| Zenoh080Bounded::<u32>::new().write(w, &string)),
                    ));
                    rows.push((
                        format!("{k} bounded u64"),
                        enc(|w| Zenoh080Bounded::<u64>::new().write(w, bytes.as_slice())),
                    ));
                    rows.push((
                        format!("{k} bounded usize"),
                        enc(|w| Zenoh080Bounded::<usize>::new().write(w, bytes.as_slice())),
                    ));
                }
                for (i, input) in super::prefixed_inputs().iter().enumerate() {
                    let k = format!("input {i} {}", summary(input));
                    rows.push((
                        format!("{k} vec"),
                        dec(input, |r| {
                            Zenoh080.read(r).map(|v: Vec<u8>| summary(&v))
                        }),
                    ));
                    rows.push((
                        format!("{k} string"),
                        dec(input, |r| {
                            Zenoh080.read(r).map(|v: String| summary(v.as_bytes()))
                        }),
                    ));
                    rows.push((
                        format!("{k} bounded u8 vec"),
                        dec(input, |r| {
                            Zenoh080Bounded::<u8>::new()
                                .read(r)
                                .map(|v: Vec<u8>| summary(&v))
                        }),
                    ));
                    rows.push((
                        format!("{k} bounded u16 string"),
                        dec(input, |r| {
                            Zenoh080Bounded::<u16>::new()
                                .read(r)
                                .map(|v: String| summary(v.as_bytes()))
                        }),
                    ));
                    rows.push((
                        format!("{k} bounded u32 vec"),
                        dec(input, |r| {
                            Zenoh080Bounded::<u32>::new()
                                .read(r)
                                .map(|v: Vec<u8>| summary(&v))
                        }),
                    ));
                    rows.push((
                        format!("{k} bounded u64 string"),
                        dec(input, |r| {
                            Zenoh080Bounded::<u64>::new()
                                .read(r)
                                .map(|v: String| summary(v.as_bytes()))
                        }),
                    ));
                    rows.push((
                        format!("{k} bounded usize vec"),
                        dec(input, |r| {
                            Zenoh080Bounded::<usize>::new()
                                .read(r)
                                .map(|v: Vec<u8>| summary(&v))
                        }),
                    ));
                }
                array_rows!($c, rows; 1, 2, 3, 4, 5, 7, 8, 9, 12, 15, 16);
                rows
            }

            /// The result of reading an `Encoding` from `bytes`.
            pub fn encoding_read(bytes: &[u8]) -> String {
                dec(bytes, |r| {
                    Zenoh080
                        .read(r)
                        .map(|e: Encoding| format!("{} {:?}", e.id, e.schema.as_ref().map(|s| summary(s.as_slice()))))
                })
            }

            /// Encodings written, measured and read back.
            pub fn encoding_rows() -> Rows {
                let mut rows = Rows::new();
                for id in [0 as EncodingId, 1, 2, 63, 64, 127, 128, 255, 256, 0x7fff, 0x8000, u16::MAX] {
                    for schema in [None, Some(0usize), Some(1), Some(255), Some(256)] {
                        let e = Encoding {
                            id,
                            schema: schema.map(|n| ZSlice::from(vec![b's'; n])),
                        };
                        let k = format!("encoding {id} {schema:?}");
                        let written = enc(|w| Zenoh080.write(w, &e));
                        rows.push((format!("{k} write"), written.clone()));
                        rows.push((format!("{k} w_len"), format!("{}", Zenoh080.w_len(&e))));
                        if let Some(bytes) = written.strip_prefix("ok ") {
                            let raw: Vec<u8> = (0..bytes.len() / 2)
                                .map(|i| u8::from_str_radix(&bytes[2 * i..2 * i + 2], 16).unwrap())
                                .collect();
                            rows.push((format!("{k} round trip"), encoding_read(&raw)));
                        }
                    }
                }
                rows
            }

            /// Locators, timestamps, ids, wire expressions, slices and buffers.
            pub fn core_rows() -> Rows {
                let mut rows = Rows::new();
                // Locators: a valid one, one with metadata, one with configuration (which the
                // locator drops), invalid ones, and a long one.
                let long = format!("tcp/{}:7447", "h".repeat(300));
                let strings = [
                    "tcp/127.0.0.1:7447",
                    "udp/[::1]:7447?iface=lo",
                    "tcp/localhost:7447?a=b;c=d",
                    "tcp/127.0.0.1:7447#cfg=1",
                    "tcp/127.0.0.1:7447?b=2;a=1",
                    "tcp/",
                    "/x",
                    "foo",
                    "",
                    long.as_str(),
                ];
                let mut locators = Vec::new();
                for s in strings {
                    if let Ok(l) = Locator::try_from(s.to_string()) {
                        rows.push((format!("locator {s} write"), enc(|w| Zenoh080.write(w, &l))));
                        locators.push(l);
                    }
                    let mut wire = super::vle(s.len() as u64);
                    wire.extend_from_slice(s.as_bytes());
                    rows.push((
                        format!("locator {s:.30} read"),
                        dec(&wire, |r| Zenoh080.read(r).map(|l: Locator| l.as_str().to_string())),
                    ));
                }
                rows.push((
                    "locators write".into(),
                    enc(|w| Zenoh080.write(w, locators.as_slice())),
                ));
                for count in [0u64, 1, 2, 3, 5, 1000] {
                    let mut wire = super::vle(count);
                    for l in locators.iter().take(3) {
                        let s = l.as_str();
                        wire.extend(super::vle(s.len() as u64));
                        wire.extend_from_slice(s.as_bytes());
                    }
                    rows.push((
                        format!("locators read {count}"),
                        dec(&wire, |r| {
                            Zenoh080
                                .read(r)
                                .map(|v: Vec<Locator>| format!("{} {:?}", v.len(), v))
                        }),
                    ));
                }
                // Timestamps: every size of id, times that take every length of encoding.
                for size in 1..=16usize {
                    for time in [0u64, 1, 0x7f, 0x80, 1 << 40, u64::MAX] {
                        let id = uhlc::ID::try_from(&zid(size).to_le_bytes()[..size]).unwrap();
                        let ts = Timestamp::new(uhlc::NTP64(time), id);
                        rows.push((
                            format!("timestamp {size} {time}"),
                            enc(|w| Zenoh080.write(w, &ts)),
                        ));
                        rows.push((
                            format!("timestamp {size} {time} w_len"),
                            format!("{}", Zenoh080.w_len(&ts)),
                        ));
                    }
                }
                for size in 0..=20usize {
                    for fill in [0u8, 1, 0xff] {
                        for have in [size.saturating_sub(1), size] {
                            let mut wire = super::vle(300);
                            wire.extend(super::vle(size as u64));
                            wire.extend(vec![fill; have]);
                            rows.push((
                                format!("timestamp read size {size} fill {fill} have {have}"),
                                dec(&wire, |r| {
                                    Zenoh080.read(r).map(|t: Timestamp| format!("{t}"))
                                }),
                            ));
                        }
                    }
                }
                // Zenoh ids: by the size in front and by a length given.
                for size in 1..=16usize {
                    let id = zid(size);
                    rows.push((format!("zid {size} write"), enc(|w| Zenoh080.write(w, &id))));
                    rows.push((format!("zid {size} w_len"), format!("{}", Zenoh080.w_len(&id))));
                    for length in [size.saturating_sub(1), size, 17] {
                        rows.push((
                            format!("zid {size} write length {length}"),
                            enc(|w| Zenoh080Length::new(length).write(w, &id)),
                        ));
                    }
                }
                for size in 0..=20usize {
                    for fill in [0u8, 1] {
                        let mut wire = vec![size as u8];
                        wire.extend(vec![fill; 20]);
                        rows.push((
                            format!("zid read size {size} fill {fill}"),
                            dec(&wire, |r| Zenoh080.read(r).map(|z: ZenohIdProto| format!("{z}"))),
                        ));
                        rows.push((
                            format!("zid read length {size} fill {fill}"),
                            dec(&wire[1..], |r| {
                                Zenoh080Length::new(size)
                                    .read(r)
                                    .map(|z: ZenohIdProto| format!("{z}"))
                            }),
                        ));
                    }
                }
                // Wire expressions.
                let big = "k".repeat(70_000);
                let max = "k".repeat(65_535);
                for scope in [0u16, 1, 127, 128, 255, 256, u16::MAX] {
                    for suffix in ["", "a", "a/b/c", max.as_str(), big.as_str()] {
                        for mapping in [Mapping::Sender, Mapping::Receiver] {
                            let e = WireExpr {
                                scope,
                                suffix: Cow::Borrowed(suffix),
                                mapping,
                            };
                            rows.push((
                                format!("wire expr {scope} {} {mapping:?}", summary(suffix.as_bytes())),
                                enc(|w| Zenoh080.write(w, &e)),
                            ));
                        }
                    }
                }
                for scope in [0u64, 1, 300, 65_535, 65_536, 70_000] {
                    for body in [vec![], vec![0u8], vec![1, b'a'], vec![3, b'a', b'b']] {
                        let mut wire = super::vle(scope);
                        wire.extend(&body);
                        for condition in [false, true] {
                            rows.push((
                                format!("wire expr read {scope} {} {condition}", hex(&body)),
                                dec(&wire, |r| {
                                    Zenoh080Condition::new(condition)
                                        .read(r)
                                        .map(|e: WireExpr<'static>| format!("{e:?}"))
                                }),
                            ));
                        }
                    }
                }
                // Slices and buffers: each length that is an edge, and a buffer of several slices.
                for n in [0usize, 1, 127, 128, 300] {
                    let zs = ZSlice::from(vec![0x42u8; n]);
                    let mut zb = ZBuf::empty();
                    for (i, part) in [n / 2, n - n / 2, 0, 3].into_iter().enumerate() {
                        zb.push_zslice(ZSlice::from(vec![i as u8; part]));
                    }
                    let flat = ZBuf::from(vec![0x24u8; n]);
                    let k = format!("slice {n}");
                    rows.push((format!("{k} write"), enc(|w| Zenoh080.write(w, &zs))));
                    rows.push((
                        format!("{k} bounded u8"),
                        enc(|w| Zenoh080Bounded::<u8>::new().write(w, &zs)),
                    ));
                    rows.push((
                        format!("{k} bounded u16"),
                        enc(|w| Zenoh080Bounded::<u16>::new().write(w, &zs)),
                    ));
                    rows.push((format!("buf {n} write"), enc(|w| Zenoh080.write(w, &zb))));
                    rows.push((format!("buf {n} flat"), enc(|w| Zenoh080.write(w, &flat))));
                    rows.push((
                        format!("buf {n} bounded u8"),
                        enc(|w| Zenoh080Bounded::<u8>::new().write(w, &zb)),
                    ));
                    rows.push((
                        format!("buf {n} bounded u32"),
                        enc(|w| Zenoh080Bounded::<u32>::new().write(w, &zb)),
                    ));
                    rows.push((
                        format!("buf {n} w_len"),
                        format!(
                            "{} {} {}",
                            Zenoh080.w_len(&zb),
                            Zenoh080Bounded::<u8>::new().w_len(&zb),
                            Zenoh080Bounded::<usize>::new().w_len(&flat)
                        ),
                    ));
                }
                for (i, input) in super::prefixed_inputs().iter().enumerate() {
                    let k = format!("input {i} {}", summary(input));
                    rows.push((
                        format!("{k} slice"),
                        dec(input, |r| {
                            Zenoh080.read(r).map(|z: ZSlice| summary(z.as_slice()))
                        }),
                    ));
                    rows.push((
                        format!("{k} slice bounded u8"),
                        dec(input, |r| {
                            Zenoh080Bounded::<u8>::new()
                                .read(r)
                                .map(|z: ZSlice| summary(z.as_slice()))
                        }),
                    ));
                    rows.push((
                        format!("{k} buf"),
                        dec(input, |r| {
                            Zenoh080.read(r).map(|z: ZBuf| {
                                let v: Vec<u8> = z.zslices().flat_map(|s| s.as_slice().to_vec()).collect();
                                summary(&v)
                            })
                        }),
                    ));
                    rows.push((
                        format!("{k} buf bounded u16"),
                        dec(input, |r| {
                            Zenoh080Bounded::<u16>::new().read(r).map(|z: ZBuf| z.len())
                        }),
                    ));
                }
                // The parameters of the codec the other codecs are made from.
                rows.push((
                    "helpers".into(),
                    format!(
                        "{:?} {:?} {:?} {:?} {:?} {:?}",
                        Zenoh080::new(),
                        Zenoh080Header::new(7),
                        Zenoh080Condition::new(true),
                        Zenoh080Length::new(9),
                        Zenoh080Reliability::new(Reliability::BestEffort),
                        Zenoh080Bounded::<u16>::new()
                    ),
                ));
                rows
            }

            /// The extensions written.
            pub fn ext_writes() -> Rows {
                let mut rows = Rows::new();
                for more in [false, true] {
                    rows.push((
                        format!("unit {more}"),
                        enc(|w| Zenoh080.write(w, (&ZExtUnit::<0x01>::new(), more))),
                    ));
                    for v in [0u64, 1, 127, 128, u64::MAX] {
                        rows.push((
                            format!("z64 {v} {more}"),
                            enc(|w| Zenoh080.write(w, (&ZExtZ64::<0x02>::new(v), more))),
                        ));
                    }
                    for n in [0usize, 1, 5, 300] {
                        rows.push((
                            format!("zbuf {n} {more}"),
                            enc(|w| {
                                Zenoh080.write(
                                    w,
                                    (&ZExtZBuf::<0x03>::new(ZBuf::from(vec![7u8; n])), more),
                                )
                            }),
                        ));
                    }
                    for len in [0usize, 1, 300, u32::MAX as usize, u32::MAX as usize + 1] {
                        rows.push((
                            format!("zbuf header {len} {more}"),
                            enc(|w| Zenoh080.write(w, (&ZExtZBufHeader::<0x04>::new(len), more))),
                        ));
                    }
                    for id in [0x00u8, 0x05, 0x3f] {
                        for mandatory in [false, true] {
                            for body in [
                                ZExtBody::Unit,
                                ZExtBody::Z64(300),
                                ZExtBody::ZBuf(ZBuf::from(vec![9u8; 4])),
                            ] {
                                let ext = ZExtUnknown::new(id, mandatory, body);
                                rows.push((
                                    format!("unknown {ext:?} {more}"),
                                    enc(|w| Zenoh080.write(w, (&ext, more))),
                                ));
                            }
                        }
                    }
                }
                for n in 0..=3usize {
                    let list: Vec<ZExtUnknown> = (0..n)
                        .map(|i| ZExtUnknown::new(i as u8, i % 2 == 0, ZExtBody::Z64(i as u64 * 200)))
                        .collect();
                    rows.push((
                        format!("list {n}"),
                        enc(|w| Zenoh080.write(w, list.as_slice())),
                    ));
                }
                rows
            }

            /// The extensions read from every header byte and eight tails.
            pub fn ext_reads() -> Rows {
                let mut rows = Rows::new();
                let tails: [&[u8]; 8] = [
                    &[],
                    &[0x00],
                    &[0x05],
                    &[0x80, 0x01],
                    &[0x02, 0xaa, 0xbb],
                    &[0x03, 1, 2, 3],
                    &[0xff; 10],
                    &[0x00, 0x00, 0x00],
                ];
                for h in 0..=255u8 {
                    for t in tails {
                        let mut b = vec![h];
                        b.extend_from_slice(t);
                        let k = hex(&b);
                        rows.push((
                            format!("{k} unit"),
                            dec(&b, |r| {
                                let x: Result<(ZExtUnit<0x01>, bool), _> = Zenoh080.read(r);
                                x
                            }),
                        ));
                        rows.push((
                            format!("{k} z64"),
                            dec(&b, |r| {
                                let x: Result<(ZExtZ64<0x02>, bool), _> = Zenoh080.read(r);
                                x
                            }),
                        ));
                        rows.push((
                            format!("{k} zbuf"),
                            dec(&b, |r| {
                                let x: Result<(ZExtZBuf<0x03>, bool), _> = Zenoh080.read(r);
                                x
                            }),
                        ));
                        rows.push((
                            format!("{k} zbuf header"),
                            dec(&b, |r| {
                                let x: Result<(ZExtZBufHeader<0x04>, bool), _> = Zenoh080.read(r);
                                x
                            }),
                        ));
                        rows.push((
                            format!("{k} unknown"),
                            dec(&b, |r| {
                                let x: Result<(ZExtUnknown, bool), _> = Zenoh080.read(r);
                                x
                            }),
                        ));
                        rows.push((
                            format!("{k} unknown by header"),
                            dec(&b[1..], |r| {
                                let x: Result<(ZExtUnknown, bool), _> = Zenoh080Header::new(h).read(r);
                                x
                            }),
                        ));
                        rows.push((
                            format!("{k} z64 by header"),
                            dec(&b[1..], |r| {
                                let x: Result<(ZExtZ64<0x02>, bool), _> = Zenoh080Header::new(h).read(r);
                                x
                            }),
                        ));
                        rows.push((
                            format!("{k} list"),
                            dec(&b, |r| {
                                let x: Result<Vec<ZExtUnknown>, _> = Zenoh080.read(r);
                                x
                            }),
                        ));
                        rows.push((
                            format!("{k} read"),
                            dec(&b[1..], |r| $c::common::extension::read(r, "test", h)),
                        ));
                        rows.push((
                            format!("{k} skip"),
                            dec(&b[1..], |r| $c::common::extension::skip(r, "test", h)),
                        ));
                        rows.push((
                            format!("{k} skip all"),
                            dec(&b, |r| $c::common::extension::skip_all(r, "test")),
                        ));
                    }
                }
                rows
            }
        }
    };
}

codec_cases!(up, up_codec, up_protocol, up_buffers);
codec_cases!(wz, wz_codec, wz_protocol, wz_buffers);

/// The text of two sets of rows is the same row by row, and says which differ.
fn assert_rows_equal(what: &str, a: &Rows, b: &Rows) {
    assert!(!a.is_empty(), "{what}: no rows");
    assert_eq!(a.len(), b.len(), "{what}: the number of rows");
    let bad: Vec<_> = a.iter().zip(b).filter(|(x, y)| x != y).take(5).collect();
    assert!(bad.is_empty(), "{what}: rows differ, first five: {bad:#?}");
}

const MAXES: [u64; 5] = [
    u8::MAX as u64,
    u16::MAX as u64,
    u32::MAX as u64,
    u64::MAX,
    u64::MAX,
];

/// What each crate is defined to read, for the value `v` the unbounded reader gave.
///
/// * `wz`: a value that does not fit the type it is read into is refused.
/// * upstream: a value that does not fit is kept as its low bits, in a direct `u16` or `u32` and in
///   a bounded integer whose bound is wider than the type it is read as.
fn model(index: usize, v: Option<u64>, wz: bool) -> Option<u64> {
    let v = v?;
    let keep = |max: u64| -> Option<u64> {
        if v <= max {
            Some(v)
        } else if wz {
            None
        } else {
            Some(v & max)
        }
    };
    match index {
        0 => Some(v),
        1 => keep(u16::MAX as u64),
        2 => keep(u32::MAX as u64),
        3 => Some(v),
        i => {
            let (bound, width) = ((i - 4) / 5, (i - 4) % 5);
            if v > MAXES[bound] {
                return None;
            }
            keep(MAXES[width])
        }
    }
}

#[test]
fn both_crates_write_integers_to_the_same_bytes() {
    let up = up::int_writes();
    let wz = wz::int_writes();
    assert_rows_equal("integer writes", &up, &wz);
    // The control of the comparison being a comparison of bytes: the plain write is the reference
    // encoding, whatever the grid says.
    for v in write_values() {
        let key = format!("u64 {v} bytes");
        let row = wz.iter().find(|(k, _)| *k == key).unwrap();
        assert_eq!(row.1, format!("ok {}", hex(&vle(v))), "{v}");
        let len = wz
            .iter()
            .find(|(k, _)| *k == format!("u64 {v} w_len"))
            .unwrap();
        assert_eq!(len.1, vle(v).len().to_string(), "{v}");
    }
    // A bounded writer refuses a value past its bound, and a buffer of fewer than nine bytes
    // refuses any value.
    let get = |k: &str| wz.iter().find(|(key, _)| key == k).unwrap().1.clone();
    assert!(get("u64 256 bounded<u8> as u64 256").starts_with("err"));
    assert!(get("u64 255 bounded<u8> as u64 255").starts_with("ok"));
    assert!(get("bbuf 8 u64 0").starts_with("err"));
    assert!(get("bbuf 9 u64 0").starts_with("ok"));
    assert!(get("bbuf 9 u64 18446744073709551615").starts_with("ok"));
    assert!(get("bbuf 12 bytes").starts_with("ok"));
    assert!(get("bbuf 3 bytes").starts_with("err"));
}

#[test]
fn both_crates_read_integers_as_their_own_definition_and_differ_only_where_upstream_truncates() {
    let inputs = varint_inputs();
    assert!(inputs.len() > 70_000, "{}", inputs.len());
    let mut truncated = [0usize; 29];
    let mut refused_after_reading = 0usize;
    for input in &inputs {
        let (u, urem) = up::int_reads(input);
        let (w, wrem) = wz::int_reads(input);
        assert_eq!(urem, wrem, "bytes left of {}", hex(input));
        // The value is the reference's, and the reference's bytes are the ones taken.
        let reference = vle_read(input);
        assert_eq!(u[0], reference.map(|(v, _)| v), "{}", hex(input));
        assert_eq!(w[0], reference.map(|(v, _)| v), "{}", hex(input));
        if let Some((_, n)) = reference {
            assert_eq!(wrem, input.len() - n, "{}", hex(input));
        }
        for i in 0..29 {
            assert_eq!(u[i], model(i, u[0], false), "upstream {i} {}", hex(input));
            assert_eq!(w[i], model(i, w[0], true), "wz {i} {}", hex(input));
            if u[i] != w[i] {
                truncated[i] += 1;
                refused_after_reading += (w[i].is_none() && u[i].is_some()) as usize;
            }
        }
    }
    // The class is reached where it exists and nowhere else: the 64-bit and `usize` readers and
    // every bounded reader of its own width never differ.
    assert!(truncated[1] > 0 && truncated[2] > 0, "{truncated:?}");
    assert_eq!(truncated[0], 0);
    assert_eq!(truncated[3], 0);
    for bound in 0..5 {
        for width in 0..5 {
            let i = 4 + bound * 5 + width;
            let narrower = MAXES[width] < MAXES[bound];
            assert_eq!(truncated[i] > 0, narrower, "bound {bound} width {width}");
        }
    }
    assert!(refused_after_reading > 0);
}

#[test]
fn both_crates_code_byte_strings_strings_and_arrays_alike() {
    assert_rows_equal("byte rows", &up::byte_rows(), &wz::byte_rows());
    // The control: the rows distinguish what they should. A length past the bytes is refused, a
    // bound narrower than the length is refused, and the same prefix is read when it fits.
    let rows = wz::byte_rows();
    let get = |k: &str| rows.iter().find(|(key, _)| key == k).unwrap().1.clone();
    assert!(get("len 256 bounded u8").starts_with("err"));
    assert!(get("len 255 bounded u8").starts_with("ok"));
    assert!(rows
        .iter()
        .any(|(k, v)| k.ends_with(" string") && k.starts_with("input") && v.starts_with("err")));
    assert!(rows
        .iter()
        .any(|(k, v)| k.ends_with(" string") && k.starts_with("input") && v.starts_with("ok")));
    assert!(rows
        .iter()
        .any(|(k, v)| k.starts_with("array 16 read from 15") && v.starts_with("err")));
}

#[test]
fn both_crates_code_encodings_alike_and_differ_only_in_an_id_wider_than_sixteen_bits() {
    assert_rows_equal("encoding rows", &up::encoding_rows(), &wz::encoding_rows());
    let words: [u64; 18] = [
        0,
        1,
        2,
        3,
        0xfe,
        0xff,
        0x100,
        0x101,
        0x1fffe,
        0x1ffff,
        0x20000,
        0x20001,
        0x40000,
        0x40001,
        0xffff_fffe,
        0xffff_ffff,
        0x1_0000_0000,
        u64::MAX,
    ];
    let tails: [&[u8]; 4] = [&[], &[0], &[3, b'a', b'b', b'c'], &[3, b'a']];
    let mut wide = 0;
    for word in words {
        for tail in tails {
            let mut wire = vle(word);
            wire.extend_from_slice(tail);
            let (u, w) = (up::encoding_read(&wire), wz::encoding_read(&wire));
            let too_wide = word <= u32::MAX as u64 && (word >> 1) > u16::MAX as u64;
            if too_wide {
                wide += 1;
                // The class: wz refuses the id, upstream keeps its low sixteen bits.
                assert!(w.starts_with("err"), "wz {} {w}", hex(&wire));
                if word & 1 == 0 || tail.len() > 3 {
                    assert!(u.starts_with("ok"), "upstream {} {u}", hex(&wire));
                    assert!(u.contains(&format!("{} ", (word >> 1) as u16)), "{u}");
                }
            } else {
                assert_eq!(u, w, "{}", hex(&wire));
            }
            if word > u32::MAX as u64 {
                assert!(u.starts_with("err") && w.starts_with("err"));
            }
        }
    }
    // The words from 0x20000 to u32::MAX whose id is past sixteen bits: six of the eighteen, each
    // with four tails.
    assert_eq!(wide, 6 * 4);
}

#[test]
fn both_crates_code_locators_timestamps_ids_wire_expressions_and_buffers_alike() {
    let (up, wz) = (up::core_rows(), wz::core_rows());
    assert_rows_equal("core rows", &up, &wz);
    let get = |k: &str| wz.iter().find(|(key, _)| key == k).unwrap().1.clone();
    // A locator with configuration is refused on the wire (the codec checks that what it read is
    // what it would write), and a plain one is read.
    assert!(get("locator tcp/127.0.0.1:7447#cfg=1 read").starts_with("err"));
    assert!(get("locator tcp/127.0.0.1:7447 read").starts_with("ok"));
    // An id of no byte is refused, and so is a size past sixteen.
    assert!(get("zid read size 0 fill 1").starts_with("err"));
    assert!(get("zid read size 17 fill 1").starts_with("err"));
    assert!(get("zid read size 16 fill 1").starts_with("ok"));
    // A wire expression longer than sixteen bits of length is refused to write.
    assert!(wz
        .iter()
        .any(|(k, v)| k.starts_with("wire expr 0 70000:") && v.starts_with("err")));
    assert!(wz
        .iter()
        .any(|(k, v)| k.starts_with("wire expr 0 65535:") && v.starts_with("ok")));
}

#[test]
fn both_crates_code_extensions_alike() {
    assert_rows_equal("extension writes", &up::ext_writes(), &wz::ext_writes());
    let (up, wz) = (up::ext_reads(), wz::ext_reads());
    assert_eq!(up.len(), 256 * 8 * 11);
    assert_rows_equal("extension reads", &up, &wz);
    // The control: every kind of answer is in the rows, so equal rows are not all one answer. A
    // header of another id, a mandatory extension the crate does not know, and one it may skip.
    let oks = wz.iter().filter(|(_, v)| v.starts_with("ok")).count();
    let errs = wz.iter().filter(|(_, v)| v.starts_with("err")).count();
    assert!(oks > 1000 && errs > 1000, "{oks} {errs}");
    let writes = wz::ext_writes();
    assert!(writes
        .iter()
        .any(|(k, v)| k.starts_with("zbuf header 4294967296") && v.starts_with("err")));
    assert!(writes
        .iter()
        .any(|(k, v)| k.starts_with("zbuf header 4294967295") && v.starts_with("ok")));
}

/// The control: the comparison is on text, so an input that changes the answer changes the row.
#[test]
fn the_comparison_sees_a_value_that_differs() {
    let a = wz::int_writes();
    let first = a.iter().find(|(k, _)| k == "u64 127 bytes").unwrap();
    let second = a.iter().find(|(k, _)| k == "u64 128 bytes").unwrap();
    assert_ne!(first.1, second.1);
    assert_ne!(wz::encoding_read(&[0x02]), wz::encoding_read(&[0x04]));
    assert_ne!(
        wz::int_reads(&[0x80, 0x01]).0[0],
        wz::int_reads(&[0x80, 0x02]).0[0]
    );
    assert_ne!(
        up::int_reads(&[0xff, 0xff, 0x7f]).0[1],
        wz::int_reads(&[0xff, 0xff, 0x7f]).0[1]
    );
}
