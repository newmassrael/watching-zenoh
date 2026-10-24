// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-buffers`: upstream's crate (`up_buffers`) and wz's (`wz_buffers`) given the same
//! sequences of reads and writes, results and states equal after each.
//!
//! * WRITERS (`Vec<u8>`, `&mut [u8]`, `BBuf`, `ZBufWriter`): 200 seeded sequences of 40 operations
//!   each, of `write`, `write_exact`, `write_u8`, `write_zslice`, `with_slot`, `mark` and `rewind`
//!   to a mark that was taken, compared by what each returned and by the bytes written so far.
//! * READERS (`&[u8]`, `ZSlice`, `ZBufReader`): the same bytes cut into slices in 200 ways, read by
//!   sequences of `read`, `read_exact`, `read_u8`, `read_zslice`, `read_zslices`, `read_zbuf`,
//!   `skip`, `backtrack`, `advance`, `mark`, `rewind`, `siphon` and, for the buffer, `seek`.
//! * `ZSlice` and `ZBuf` themselves: `subslice` over every range of a small slice, `to_zslice`,
//!   equality of buffers cut differently, `Display`, `Debug` and `Hash`.
//!
//! Upstream is wrong in two places and wz follows the documented definition there; each is a class
//! that is counted and held on both sides, and the main comparisons leave the operations that reach
//! it out: `ZBufReader::read_u8` reports that there is nothing to read when the cursor stands at
//! the end of a slice that has bytes after it (which `backtrack`, and so `seek` and `advance`
//! backwards, leave it at whenever they land on a boundary, and which an empty slice is), where
//! `read` goes on to the next slice; and two buffers of the same bytes are not equal if one has
//! an empty slice at its end.

use std::hash::{Hash, Hasher};

use rand::{rngs::StdRng, Rng, SeedableRng};

const SEQUENCES: u64 = 200;
const LENGTH: usize = 40;

/// A write operation, with the numbers it is resolved against the writer with.
#[derive(Debug, Clone)]
enum WOp {
    Write(Vec<u8>),
    WriteExact(Vec<u8>),
    WriteU8(u8),
    WriteZSlice(Vec<u8>),
    Slot(usize, usize, u8),
    Mark,
    Rewind(usize),
    IoWrite(Vec<u8>),
}

/// A read operation.
#[derive(Debug, Clone, Copy)]
enum ROp {
    Read(usize),
    ReadExact(usize),
    ReadU8,
    ReadZSlice(usize),
    ReadZSlices(usize),
    ReadZBuf(usize),
    Skip(usize),
    Backtrack(usize),
    Advance(isize),
    Mark,
    Rewind(usize),
    Siphon(usize),
    Seek(u8, i64),
    IoRead(usize),
}

fn bytes(rng: &mut StdRng, max: usize) -> Vec<u8> {
    let n = rng.gen_range(1..=max);
    (0..n).map(|_| rng.gen()).collect()
}

fn write_ops(seed: u64) -> Vec<WOp> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..LENGTH)
        .map(|_| match rng.gen_range(0..9) {
            0 | 1 => WOp::Write(bytes(&mut rng, 6)),
            2 => WOp::WriteExact(bytes(&mut rng, 6)),
            3 => WOp::WriteU8(rng.gen()),
            4 => WOp::WriteZSlice(bytes(&mut rng, 6)),
            5 => WOp::Slot(rng.gen_range(0..8), rng.gen_range(0..8), rng.gen()),
            6 => WOp::Mark,
            7 => WOp::Rewind(rng.gen_range(0..4)),
            _ => WOp::IoWrite(bytes(&mut rng, 4)),
        })
        .collect()
}

fn read_ops(seed: u64) -> Vec<ROp> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..LENGTH)
        .map(|_| match rng.gen_range(0..14) {
            0 => ROp::Read(rng.gen_range(0..8)),
            1 => ROp::ReadExact(rng.gen_range(0..8)),
            2 | 3 => ROp::ReadU8,
            4 => ROp::ReadZSlice(rng.gen_range(0..8)),
            5 => ROp::ReadZSlices(rng.gen_range(0..8)),
            6 => ROp::ReadZBuf(rng.gen_range(0..8)),
            7 => ROp::Skip(rng.gen_range(0..6)),
            8 => ROp::Backtrack(rng.gen_range(0..6)),
            9 => ROp::Advance(rng.gen_range(-6..6)),
            10 => ROp::Mark,
            11 => ROp::Rewind(rng.gen_range(0..4)),
            12 => ROp::Siphon(rng.gen_range(0..8)),
            _ => {
                if rng.gen() {
                    ROp::Seek(rng.gen_range(0..3), rng.gen_range(-20..40))
                } else {
                    ROp::IoRead(rng.gen_range(0..8))
                }
            }
        })
        .collect()
}

/// The bytes of a read, and the ways they are cut into the slices of a buffer.
fn source(seed: u64) -> (Vec<u8>, Vec<usize>) {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5eed);
    let total = rng.gen_range(0..40);
    let data: Vec<u8> = (0..total).map(|_| rng.gen()).collect();
    let mut cuts = Vec::new();
    let mut left = total;
    while left > 0 {
        let n = rng.gen_range(1..=left.min(9));
        cuts.push(n);
        left -= n;
    }
    (data, cuts)
}

macro_rules! buffers {
    ($name:ident, $c:ident) => {
        mod $name {
            use std::{
                fmt::Write as _,
                io::{Read as _, Seek as _, SeekFrom, Write as _},
                num::NonZeroUsize,
            };

            use $c::{
                buffer::{Buffer, SplitBuffer},
                reader::{
                    AdvanceableReader, BacktrackableReader, HasReader, Reader, SiphonableReader,
                },
                writer::{BacktrackableWriter, HasWriter, Writer},
                BBuf, ZBuf, ZSlice,
            };

            use super::{ROp, WOp};

            fn n(r: Result<NonZeroUsize, impl Sized>) -> String {
                match r {
                    Ok(n) => format!("ok {n}"),
                    Err(_) => "err".to_string(),
                }
            }
            fn unit(r: Result<(), impl Sized>) -> String {
                if r.is_ok() { "ok" } else { "err" }.to_string()
            }

            /// The same operations on any backtrackable writer; `bytes` reads what it holds.
            fn drive<W: Writer + BacktrackableWriter>(
                w: &mut W,
                ops: &[WOp],
                bytes: impl Fn(&mut W) -> Vec<u8>,
            ) -> Vec<String> {
                let mut marks: Vec<W::Mark> = Vec::new();
                let mut out = Vec::new();
                for op in ops {
                    let mut line = String::new();
                    match op {
                        WOp::Write(b) => write!(line, "write {} ", n(w.write(b))).unwrap(),
                        WOp::WriteExact(b) => {
                            write!(line, "exact {} ", unit(w.write_exact(b))).unwrap()
                        }
                        WOp::WriteU8(b) => write!(line, "u8 {} ", unit(w.write_u8(*b))).unwrap(),
                        WOp::WriteZSlice(b) => {
                            let z: ZSlice = b.clone().into();
                            write!(line, "zslice {} ", unit(w.write_zslice(&z))).unwrap();
                        }
                        WOp::Slot(len, written, fill) => {
                            let written = written.min(len);
                            // SAFETY: the closure reports no more than the slot holds.
                            let r = unsafe {
                                w.with_slot(*len, |slot| {
                                    slot[..*written].fill(*fill);
                                    *written
                                })
                            };
                            write!(line, "slot {} ", n(r)).unwrap();
                        }
                        WOp::Mark => marks.push(w.mark()),
                        WOp::Rewind(i) => {
                            if !marks.is_empty() {
                                let mark = marks.remove(i % marks.len());
                                write!(line, "rewind {} ", w.rewind(mark)).unwrap();
                                // Marks taken after the one used are of a state that is gone.
                                marks.clear();
                            }
                        }
                        WOp::IoWrite(_) => {}
                    }
                    write!(line, "{:?} rem={}", bytes(w), w.remaining()).unwrap();
                    out.push(line);
                }
                out
            }

            pub fn vec_writer(ops: &[WOp]) -> Vec<String> {
                let mut v: Vec<u8> = Vec::new();
                drive(&mut v, ops, |v| v.clone())
            }

            pub fn slice_writer(ops: &[WOp]) -> Vec<String> {
                let mut storage = [0u8; 24];
                let mut out = Vec::new();
                {
                    let mut w: &mut [u8] = &mut storage;
                    out.extend(drive(&mut w, ops, |w| w.to_vec()));
                }
                out.push(format!("storage {storage:?}"));
                out
            }

            pub fn bbuf_writer(ops: &[WOp]) -> Vec<String> {
                let mut b = BBuf::with_capacity(20);
                let mut out = drive(&mut b, ops, |b| b.as_slice().to_vec());
                out.push(format!("{b:?} cap={} {}", b.capacity(), b.len()));
                out
            }

            pub fn zbuf_writer(ops: &[WOp]) -> Vec<String> {
                let mut z = ZBuf::empty();
                let mut out = Vec::new();
                {
                    let mut w = (&mut z).writer();
                    for op in ops {
                        if let WOp::IoWrite(b) = op {
                            out.push(format!("io {:?}", std::io::Write::write(&mut w, b).ok()));
                        }
                    }
                }
                let mut z = ZBuf::empty();
                {
                    let mut w = (&mut z).writer();
                    let seen = drive(&mut w, ops, |_| Vec::new());
                    out.extend(seen);
                }
                out.push(format!(
                    "{:?} slices={} len={} empty={}",
                    z.slices().collect::<Vec<_>>(),
                    z.zslices().count(),
                    z.len(),
                    Buffer::is_empty(&z)
                ));
                out.push(format!("{:?}", z.to_zslice()));
                out
            }

            /// The cuts with the last byte left out: the same slices but for the end.
            fn shorter(cuts: &[usize]) -> Vec<usize> {
                let mut cuts = cuts.to_vec();
                if let Some(last) = cuts.last_mut() {
                    *last -= 1;
                    if *last == 0 {
                        cuts.pop();
                    }
                }
                cuts
            }

            fn zbuf_of(data: &[u8], cuts: &[usize]) -> ZBuf {
                let mut z = ZBuf::empty();
                let mut at = 0;
                for cut in cuts {
                    z.push_zslice(data[at..at + cut].to_vec().into());
                    at += cut;
                }
                z
            }

            /// The same operations on any backtrackable reader. `moves` runs the three that only a
            /// reader that can be advanced has, and answers with their line.
            ///
            /// `byte_by_byte` says whether `ReadU8` is `read_u8` or a read of one byte: the buffer's
            /// reader is compared the second way, because `read_u8` is where upstream's fault is
            /// (see the class test) and a cursor that backtracking left at the end of a slice
            /// would make every later line differ.
            fn read_drive<R>(
                r: &mut R,
                ops: &[ROp],
                byte_by_byte: bool,
                moves: impl Fn(&mut R, ROp) -> Option<String>,
            ) -> Vec<String>
            where
                R: Reader + BacktrackableReader,
            {
                let mut marks: Vec<R::Mark> = Vec::new();
                let mut out = Vec::new();
                for op in ops {
                    let mut line = String::new();
                    match *op {
                        ROp::Read(len) => {
                            let mut b = vec![0u8; len];
                            let res = r.read(&mut b);
                            let got = res.as_ref().map(|k| k.get()).unwrap_or(0);
                            write!(line, "read {} {:?} ", n(res), &b[..got]).unwrap();
                        }
                        ROp::ReadExact(len) => {
                            let mut b = vec![0u8; len];
                            let res = r.read_exact(&mut b);
                            write!(line, "exact {} ", unit(res)).unwrap();
                        }
                        ROp::ReadZSlice(len) => match r.read_zslice(len) {
                            Ok(z) => write!(line, "zslice {z:?} ").unwrap(),
                            Err(_) => write!(line, "zslice err ").unwrap(),
                        },
                        ROp::ReadZSlices(len) => {
                            let mut parts = Vec::new();
                            let res = r.read_zslices(len, |s| parts.push(s.to_vec()));
                            write!(line, "zslices {} {:?} ", unit(res), parts).unwrap();
                        }
                        ROp::ReadZBuf(len) => match r.read_zbuf(len) {
                            Ok(z) => write!(line, "zbuf {:?} ", z.to_zslice()).unwrap(),
                            Err(_) => write!(line, "zbuf err ").unwrap(),
                        },
                        ROp::ReadU8 if byte_by_byte => {
                            let mut b = [0u8; 1];
                            let got = r.read(&mut b).ok().map(|_| b[0]);
                            write!(line, "one {got:?} ").unwrap();
                        }
                        ROp::ReadU8 => write!(line, "u8 {:?} ", r.read_u8().ok()).unwrap(),
                        ROp::Skip(_) | ROp::Backtrack(_) | ROp::Advance(_) => {
                            if let Some(text) = moves(r, *op) {
                                line.push_str(&text);
                            }
                        }
                        ROp::Mark => marks.push(r.mark()),
                        ROp::Rewind(i) => {
                            if !marks.is_empty() {
                                let mark = marks.remove(i % marks.len());
                                write!(line, "rewind {} ", r.rewind(mark)).unwrap();
                                marks.clear();
                            }
                        }
                        ROp::Siphon(_) | ROp::Seek(..) | ROp::IoRead(_) => {}
                    }
                    write!(line, "rem={} can={}", r.remaining(), r.can_read()).unwrap();
                    out.push(line);
                }
                out
            }

            pub fn slice_reader(data: &[u8], ops: &[ROp]) -> Vec<String> {
                let mut r: &[u8] = data;
                let mut out = read_drive(&mut r, ops, false, |_, _| None);
                for op in ops {
                    if let ROp::Siphon(cap) = op {
                        let mut sink = vec![0u8; *cap];
                        let mut w: &mut [u8] = &mut sink;
                        let mut r: &[u8] = data;
                        out.push(format!("siphon {}", n(r.siphon(&mut w))));
                    }
                }
                out
            }

            pub fn zslice_reader(data: &[u8], ops: &[ROp]) -> Vec<String> {
                let mut z: ZSlice = data.to_vec().into();
                let mut out = read_drive(&mut z, ops, false, |_, _| None);
                let mut z: ZSlice = data.to_vec().into();
                out.push(format!(
                    "u8s {:?}",
                    std::iter::from_fn(|| z.read_u8().ok()).collect::<Vec<_>>()
                ));
                out
            }

            pub fn zbuf_reader(data: &[u8], cuts: &[usize], ops: &[ROp]) -> Vec<String> {
                let z = zbuf_of(data, cuts);
                let mut r = (&z).reader();
                let mut out = read_drive(&mut r, ops, true, |r, op| match op {
                    ROp::Skip(k) => Some(format!("skip {} ", unit(r.skip(k)))),
                    ROp::Backtrack(k) => Some(format!("backtrack {} ", unit(r.backtrack(k)))),
                    ROp::Advance(k) => Some(format!("advance {} ", unit(r.advance(k)))),
                    _ => None,
                });
                out.push(format!(
                    "buffer len={} empty={}",
                    r.len(),
                    Buffer::is_empty(&r)
                ));
                // Siphon, `read_u8` and the io traits are driven on fresh readers, from where
                // the operation says.
                for op in ops {
                    match *op {
                        ROp::Siphon(cap) => {
                            let mut sink = vec![0u8; cap];
                            let mut w: &mut [u8] = &mut sink;
                            let mut r = (&z).reader();
                            out.push(format!(
                                "siphon {} {:?}",
                                n(r.siphon(&mut w)),
                                r.remaining()
                            ));
                        }
                        ROp::Seek(kind, by) => {
                            let mut r = (&z).reader();
                            let pos = match kind {
                                0 => SeekFrom::Start(by.unsigned_abs()),
                                1 => SeekFrom::Current(by),
                                _ => SeekFrom::End(by),
                            };
                            let res = r.seek(pos).ok();
                            let mut one = [0u8; 1];
                            let next = Reader::read(&mut r, &mut one).ok().map(|_| one[0]);
                            out.push(format!("seek {pos:?} {res:?} {next:?}"));
                        }
                        ROp::IoRead(len) => {
                            let mut r = (&z).reader();
                            let mut b = vec![0u8; len];
                            let got = std::io::Read::read(&mut r, &mut b).unwrap();
                            out.push(format!("io {got} {:?}", &b[..got]));
                        }
                        _ => {}
                    }
                }
                let mut r = (&z).reader();
                out.push(format!(
                    "u8s {:?}",
                    std::iter::from_fn(|| r.read_u8().ok()).collect::<Vec<_>>()
                ));
                out
            }

            /// Every range of a slice of `data` through `subslice`.
            pub fn subslices(data: &[u8]) -> Vec<String> {
                let z: ZSlice = data.to_vec().into();
                let mut out = Vec::new();
                for start in 0..=data.len() + 1 {
                    for end in 0..=data.len() + 1 {
                        out.push(format!("{start}..{end}: {:?}", z.subslice(start..end)));
                        out.push(format!("{start}..={end}: {:?}", z.subslice(start..=end)));
                    }
                    out.push(format!("{start}..: {:?}", z.subslice(start..)));
                    out.push(format!("..{start}: {:?}", z.subslice(..start)));
                }
                out
            }

            /// What a buffer cut into `cuts` is: its text, its slices, its contiguous bytes, its
            /// hash of the first slice, and whether it equals the same bytes cut by `other`.
            pub fn buffers(data: &[u8], cuts: &[usize], other: &[usize]) -> Vec<String> {
                use std::hash::{Hash, Hasher};
                let (a, b) = (zbuf_of(data, cuts), zbuf_of(data, other));
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                a.to_zslice().hash(&mut hasher);
                vec![
                    format!("{a:?}"),
                    format!("{} {}", a.len(), Buffer::is_empty(&a)),
                    format!("{:?}", a.slices().collect::<Vec<_>>()),
                    format!("{:?}", a.contiguous()),
                    format!("{}", a.to_zslice()),
                    format!("{}", hasher.finish()),
                    format!("eq {} {}", a == b, b == a),
                    format!("ne {}", a == zbuf_of(data, &shorter(other))),
                ]
            }

            /// The io writer of a buffer, and the io reader of a slice.
            pub fn io(data: &[u8]) -> Vec<String> {
                let mut z = ZBuf::empty();
                let mut w = (&mut z).writer();
                let wrote = std::io::Write::write(&mut w, data).ok();
                let flushed = w.flush().is_ok();
                let mut zs: ZSlice = data.to_vec().into();
                let mut r = &mut zs;
                let mut buf = vec![0u8; 5];
                let read = std::io::Read::read(&mut r, &mut buf).ok();
                let hello = format!("{wrote:?} {flushed} {read:?} {:?}", &buf);
                let mut empty: ZSlice = Vec::new().into();
                let mut r = &mut empty;
                let eof = std::io::Read::read(&mut r, &mut buf).map_err(|e| e.kind());
                vec![hello, format!("{eof:?}")]
            }

            /// The buffer `[1, 2] [3, 4]`, read three bytes, backtracked by one, which leaves the
            /// cursor at the end of the first slice, and read a byte: what `read_u8` answers, and
            /// what a read of one byte answers, at that position.
            pub fn byte_at_the_end_of_a_slice() -> (Option<u8>, Option<u8>) {
                let mut z = ZBuf::empty();
                z.push_zslice(vec![1u8, 2].into());
                z.push_zslice(vec![3u8, 4].into());
                let at_end = |r: &mut $c::ZBufReader<'_>| {
                    Reader::read_exact(r, &mut [0u8; 3]).unwrap();
                    r.backtrack(1).unwrap();
                };
                let mut r = (&z).reader();
                at_end(&mut r);
                let by_u8 = r.read_u8().ok();
                let mut r = (&z).reader();
                at_end(&mut r);
                let mut one = [0u8; 1];
                let by_read = Reader::read(&mut r, &mut one).ok().map(|_| one[0]);
                (by_u8, by_read)
            }

            /// A buffer `[1] [9] <empty> [5]`: a slice written whole closes the slice being
            /// written into, a write of nothing then starts one that stays empty, and a slice
            /// written whole after it goes behind. Returns it read byte by byte and the number
            /// of slices it has.
            pub fn bytes_past_an_empty_slice() -> (Vec<u8>, usize) {
                let mut z = ZBuf::empty();
                z.push_zslice(vec![1u8].into());
                let mut w = (&mut z).writer();
                w.write_zslice(&ZSlice::from(vec![9u8])).unwrap();
                assert!(Writer::write(&mut w, &[]).is_err());
                w.write_zslice(&ZSlice::from(vec![5u8])).unwrap();
                let mut r = (&z).reader();
                let read: Vec<u8> = std::iter::from_fn(|| r.read_u8().ok()).collect();
                (read, z.zslices().count())
            }

            /// The buffer `[1, 2] [3]` and the same bytes with an empty slice behind it (the
            /// slice a write of nothing leaves), each compared with the other both ways round.
            pub fn equal_with_an_empty_slice() -> (bool, bool) {
                let mut plain = ZBuf::empty();
                plain.push_zslice(vec![1u8, 2].into());
                plain.push_zslice(vec![3u8].into());
                let mut with = ZBuf::empty();
                with.push_zslice(vec![1u8, 2].into());
                let mut w = (&mut with).writer();
                w.write_zslice(&ZSlice::from(vec![3u8])).unwrap();
                assert!(Writer::write(&mut w, &[]).is_err());
                assert_eq!(with.zslices().count(), 3);
                (with == plain, plain == with)
            }
        }
    };
}

buffers!(up, up_buffers);
buffers!(wz, wz_buffers);

fn same(label: &str, a: Vec<String>, b: Vec<String>) -> usize {
    assert_eq!(a.len(), b.len(), "{label}");
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(x, y, "{label}, line {i}");
    }
    a.len()
}

#[test]
fn both_crates_write_a_sequence_alike_through_every_writer() {
    let mut lines = 0;
    for seed in 0..SEQUENCES {
        let ops = write_ops(seed);
        lines += same("vec", up::vec_writer(&ops), wz::vec_writer(&ops));
        lines += same("slice", up::slice_writer(&ops), wz::slice_writer(&ops));
        lines += same("bbuf", up::bbuf_writer(&ops), wz::bbuf_writer(&ops));
        lines += same("zbuf", up::zbuf_writer(&ops), wz::zbuf_writer(&ops));
    }
    assert!(lines > 30_000, "{lines} lines");
}

#[test]
fn both_crates_read_a_sequence_alike_through_every_reader() {
    let mut lines = 0;
    let (mut oks, mut errs) = (0, 0);
    for seed in 0..SEQUENCES {
        let ops = read_ops(seed);
        let (data, cuts) = source(seed);
        lines += same(
            "slice",
            up::slice_reader(&data, &ops),
            wz::slice_reader(&data, &ops),
        );
        lines += same(
            "zslice",
            up::zslice_reader(&data, &ops),
            wz::zslice_reader(&data, &ops),
        );
        let z = wz::zbuf_reader(&data, &cuts, &ops);
        lines += same("zbuf", up::zbuf_reader(&data, &cuts, &ops), z.clone());
        oks += z.iter().filter(|l| l.contains(" ok")).count();
        errs += z.iter().filter(|l| l.contains("err")).count();
    }
    assert!(lines > 20_000, "{lines} lines");
    assert!(oks > 1000 && errs > 1000, "ok {oks}, err {errs}");
}

#[test]
fn both_crates_cut_a_slice_and_describe_a_buffer_alike() {
    let mut rng = StdRng::seed_from_u64(9);
    for seed in 0..SEQUENCES {
        let data: Vec<u8> = (0..rng.gen_range(0..9)).map(|_| rng.gen()).collect();
        assert_eq!(
            up::subslices(&data),
            wz::subslices(&data),
            "subslices of {data:?}"
        );
        let (data, cuts) = source(seed);
        let (_, other) = source(seed + 1000);
        let other = if other.iter().sum::<usize>() == data.len() {
            other
        } else {
            cuts.clone()
        };
        assert_eq!(
            up::buffers(&data, &cuts, &other),
            wz::buffers(&data, &cuts, &other),
            "{cuts:?}"
        );
        assert_eq!(up::io(&data), wz::io(&data));
    }
}

/// The two classes in which upstream is wrong, each shown on upstream's crate and held to the
/// documented definition on wz's.
#[test]
fn the_two_places_upstream_is_wrong_are_pinned_on_both_sides() {
    // A byte is read from a cursor that stands at the end of a slice with bytes after it, as
    // backtracking leaves it: a read of one byte moves on, and upstream's `read_u8` does not.
    assert_eq!(up::byte_at_the_end_of_a_slice(), (None, Some(3)));
    assert_eq!(wz::byte_at_the_end_of_a_slice(), (Some(3), Some(3)));

    // The same, with an empty slice, which is how the cursor gets there without backtracking.
    let (read_up, slices_up) = up::bytes_past_an_empty_slice();
    let (read_wz, slices_wz) = wz::bytes_past_an_empty_slice();
    assert_eq!(slices_up, slices_wz);
    assert_eq!(slices_wz, 4, "the buffer has an empty slice in it");
    assert_eq!(read_wz, [1, 9, 5]);
    assert_eq!(read_up, [1, 9], "upstream stopped at the empty slice");

    // Two buffers of the same bytes are equal. Upstream's are not if one has an empty slice last.
    assert_eq!(
        wz::equal_with_an_empty_slice(),
        (true, true),
        "wz compares the bytes"
    );
    assert_eq!(
        up::equal_with_an_empty_slice(),
        (false, false),
        "upstream stops at the end of one"
    );
}

/// The control: the comparison is made on lines, so a reader that lost an operation differs.
#[test]
fn the_comparison_sees_a_reader_that_lost_an_operation() {
    let ops = read_ops(3);
    let (data, cuts) = source(3);
    let full = wz::zbuf_reader(&data, &cuts, &ops);
    let mut short = ops.clone();
    short.remove(4);
    assert_ne!(full, wz::zbuf_reader(&data, &cuts, &short));
    let w = write_ops(3);
    let mut short = w.clone();
    short.remove(2);
    assert_ne!(wz::bbuf_writer(&w), wz::bbuf_writer(&short));
    // The same hash is the same bytes, whoever holds them.
    let mut a = std::collections::hash_map::DefaultHasher::new();
    let mut b = std::collections::hash_map::DefaultHasher::new();
    wz_buffers::ZSlice::from(vec![1u8, 2]).hash(&mut a);
    up_buffers::ZSlice::from(vec![1u8, 2]).hash(&mut b);
    assert_eq!(a.finish(), b.finish());
}
