// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-codec`, the shared-memory arm (the codecs of `zenoh-shm`'s types and of a buffer of
//! slices): upstream's crate (`up_codec`) and wz's (`wz_codec`), built with `shared-memory`, given
//! the same values to write and the same bytes to read, results equal as text, and, because a
//! descriptor names memory another process owns, a buffer written by one crate read by the other.
//!
//! * DESCRIPTORS: a metadata descriptor, a chunk descriptor, a non-zero size and the info of a
//!   buffer, each over the edges of its integers, written to the bytes the other writes, and read
//!   from every one of those encodings, every prefix of it and every one of its bytes set to six
//!   values, as the type it is and as each of the others.
//! * SLICED BUFFERS: the codec of a buffer of slices (`Zenoh080Sliced`) at each of the five bounds,
//!   sliced and not, written and read, with every prefix and changed byte of each encoding read.
//! * A BUFFER IN SHARED MEMORY, written by one crate and read by the other, in both directions:
//!   the descriptor decoded on the reading side maps the same memory and reads the same bytes, and
//!   a written buffer is held (its reference count raised) once each.
//! * SEGMENTS: a segment and a struct in shared memory written as their ids and read by opening
//!   them, across the two crates; an id of nothing, and a cut encoding, refused alike.
//!
//! Where upstream's writer meets a slice that it did not expect, wz refuses and upstream does not.
//! Each is a class, built by hand and held on both sides:
//!
//! * a slice of the shared-memory kind whose buffer is not a buffer in shared memory (a program makes
//!   one: the reader tags the bytes of a descriptor with the kind and nothing else, and a buffer
//!   read and written again is that): upstream panics, wz refuses and writes nothing;
//! * a write that fails on a later slice: upstream has raised the reference count of the buffers it
//!   wrote and holds them for a receiver that will never come, wz has raised none.
//!
//! The crates are built with `test`, so the tests of this binary take one lock.

#![cfg(target_os = "linux")]

use std::{
    cell::Cell,
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    sync::{Mutex, MutexGuard, Once},
};

use rand::{rngs::StdRng, Rng, SeedableRng};

static LOCK: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f`, and says `None` if it panicked, without the report of the panic: a writer that panics
/// is a result of this comparison, and the report would be noise.
fn guarded<T>(f: impl FnOnce() -> T) -> Option<T> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = take_hook();
        set_hook(Box::new(move |info| {
            if !QUIET.with(Cell::get) {
                previous(info)
            }
        }));
    });
    QUIET.with(|q| q.set(true));
    let out = catch_unwind(AssertUnwindSafe(f)).ok();
    QUIET.with(|q| q.set(false));
    out
}

/// What a reading gave: its text, and for a reading that succeeded whether the value writes back to
/// the bytes it consumed.
type Outcome = (String, Option<bool>);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The values every integer of a descriptor takes: the edges of a variable-length integer.
const U16S: [u16; 6] = [0, 1, 0x7f, 0x80, 0x3fff, 0xffff];
const U32S: [u32; 6] = [0, 1, 0x7f, 0x80, 300, u32::MAX];
const LENS: [usize; 6] = [1, 127, 128, 16_384, 70_000, usize::MAX];

macro_rules! codec_cases {
    ($m:ident, $c:ident, $b:ident, $s:ident) => {
        mod $m {
            use std::{
                any::Any,
                fmt::Debug,
                num::NonZeroUsize,
                sync::{atomic::Ordering, Arc},
            };

            use $b::{
                reader::DidntRead,
                writer::{DidntWrite, HasWriter},
                ZBuf, ZSlice, ZSliceKind,
            };
            use $c::{LCodec, RCodec, WCodec, Zenoh080, Zenoh080Sliced};
            use $s::{
                api::{
                    client_storage::GLOBAL_CLIENT_STORAGE,
                    common::types::SegmentID,
                    protocol_implementations::posix::protocol_id::POSIX_PROTOCOL_ID,
                    provider::chunk::ChunkDescriptor,
                },
                metadata::{
                    descriptor::{MetadataDescriptor, OwnedMetadataDescriptor},
                    storage::GLOBAL_METADATA_STORAGE,
                },
                posix_shm::{array::ArrayInSHM, segment::Segment, struct_in_shm::StructInSHM},
                reader::ShmReader,
                ShmBufInfo, ShmBufInner,
            };

            use super::{guarded, Outcome, LENS, U16S, U32S};

            pub fn nz(n: usize) -> NonZeroUsize {
                NonZeroUsize::new(n).unwrap()
            }

            /// The bytes a write gives, `ERR` after them if it was refused and `PANIC` if it
            /// panicked.
            pub fn enc<F>(f: F) -> Vec<u8>
            where
                F: FnOnce(&mut &mut Vec<u8>) -> Result<(), DidntWrite>,
            {
                let mut v: Vec<u8> = Vec::new();
                let r = guarded(|| {
                    let mut w = (&mut v).writer();
                    f(&mut w)
                });
                match r {
                    Some(Ok(())) => {}
                    Some(Err(_)) => v.extend_from_slice(b"ERR"),
                    None => v.extend_from_slice(b"PANIC"),
                }
                v
            }

            fn info(len: usize, id: u16, index: u16, generation: u32) -> ShmBufInfo {
                ShmBufInfo::new(nz(len), MetadataDescriptor { id, index }, generation)
            }

            /// Every descriptor to write, by kind and name, and the bytes it was written as.
            pub fn corpus() -> Vec<(&'static str, String, Vec<u8>)> {
                let mut out: Vec<(&'static str, String, Vec<u8>)> = Vec::new();
                for id in U16S {
                    for index in U16S {
                        let d = MetadataDescriptor { id, index };
                        out.push((
                            "metadata",
                            format!("metadata {id} {index}"),
                            enc(|w| Zenoh080.write(w, &d)),
                        ));
                    }
                }
                for segment in U32S {
                    for chunk in U32S {
                        for len in LENS {
                            let d = ChunkDescriptor::new(segment, chunk, nz(len));
                            out.push((
                                "chunk",
                                format!("chunk {segment} {chunk} {len}"),
                                enc(|w| Zenoh080.write(w, &d)),
                            ));
                        }
                    }
                }
                for len in LENS {
                    out.push((
                        "nonzero",
                        format!("nonzero {len}"),
                        enc(|w| Zenoh080.write(w, nz(len))),
                    ));
                }
                for len in LENS {
                    for id in [0u16, 0x80, u16::MAX] {
                        for index in [0u16, 0x3fff] {
                            for generation in [0u32, 1, u32::MAX] {
                                let i = info(len, id, index, generation);
                                out.push((
                                    "info",
                                    format!("info {len} {id} {index} {generation}"),
                                    enc(|w| Zenoh080.write(w, &i)),
                                ));
                            }
                        }
                    }
                }
                out
            }

            fn go<T, R, W>(bytes: &[u8], read: R, write: W) -> Outcome
            where
                T: Debug,
                R: FnOnce(&mut &[u8]) -> Result<T, DidntRead>,
                W: FnOnce(&T, &mut &mut Vec<u8>) -> Result<(), DidntWrite>,
            {
                let mut r: &[u8] = bytes;
                let out = read(&mut r);
                let rem = r.len();
                match out {
                    Ok(v) => {
                        let consumed = bytes.len() - rem;
                        let again = enc(|w| write(&v, w));
                        (
                            format!("ok {v:?} rem={rem}"),
                            Some(again == bytes[..consumed]),
                        )
                    }
                    Err(_) => ("err".to_string(), None),
                }
            }

            /// Bytes read as a descriptor of the kind.
            pub fn read_as(kind: &str, bytes: &[u8]) -> Outcome {
                match kind {
                    "metadata" => go::<MetadataDescriptor, _, _>(
                        bytes,
                        |r| Zenoh080.read(r),
                        |v, w| Zenoh080.write(w, v),
                    ),
                    "chunk" => go::<ChunkDescriptor, _, _>(
                        bytes,
                        |r| Zenoh080.read(r),
                        |v, w| Zenoh080.write(w, v),
                    ),
                    "nonzero" => go::<NonZeroUsize, _, _>(
                        bytes,
                        |r| Zenoh080.read(r),
                        |v, w| Zenoh080.write(w, *v),
                    ),
                    "info" => go::<ShmBufInfo, _, _>(
                        bytes,
                        |r| Zenoh080.read(r),
                        |v, w| Zenoh080.write(w, v),
                    ),
                    other => panic!("no such descriptor {other}"),
                }
            }

            fn zbuf_of(sizes: &[usize]) -> ZBuf {
                let mut z = ZBuf::empty();
                for (i, n) in sizes.iter().enumerate() {
                    z.push_zslice(ZSlice::from(vec![0xA0u8 + i as u8; *n]));
                }
                z
            }

            /// The kinds of the slices of a buffer, a letter each.
            fn kinds(z: &ZBuf) -> String {
                z.zslices()
                    .map(|s| match s.kind {
                        ZSliceKind::Raw => 'r',
                        ZSliceKind::ShmPtr => 's',
                    })
                    .collect()
            }

            pub const SHAPES: [&[usize]; 4] = [&[], &[5], &[3, 300], &[1, 0, 2]];

            macro_rules! sliced_at {
                ($bound:ty, $sliced:expr, $name:expr, $out:ident, $z:ident) => {
                    let codec = Zenoh080Sliced::<$bound>::new($sliced);
                    let bytes = enc(|w| codec.write(w, &$z));
                    $out.push((
                        "sliced",
                        format!("{} {} w_len={}", $name, $sliced, codec.w_len(&$z)),
                        bytes,
                    ));
                };
            }

            /// Every buffer of raw slices to write at every bound, sliced and not.
            pub fn sliced_corpus() -> Vec<(&'static str, String, Vec<u8>)> {
                let mut out: Vec<(&'static str, String, Vec<u8>)> = Vec::new();
                for (k, shape) in SHAPES.iter().enumerate() {
                    let z = zbuf_of(shape);
                    for sliced in [false, true] {
                        let name = format!("shape {k}");
                        sliced_at!(u8, sliced, format!("u8 {name}"), out, z);
                        sliced_at!(u16, sliced, format!("u16 {name}"), out, z);
                        sliced_at!(u32, sliced, format!("u32 {name}"), out, z);
                        sliced_at!(u64, sliced, format!("u64 {name}"), out, z);
                        sliced_at!(usize, sliced, format!("usize {name}"), out, z);
                    }
                }
                out
            }

            macro_rules! go_sliced {
                ($bound:ty, $sliced:expr, $bytes:expr) => {{
                    let codec = Zenoh080Sliced::<$bound>::new($sliced);
                    let bytes: &[u8] = $bytes;
                    let mut r: &[u8] = bytes;
                    let out: Result<ZBuf, DidntRead> = codec.read(&mut r);
                    let rem = r.len();
                    match out {
                        Ok(v) => {
                            let consumed = bytes.len() - rem;
                            let again = enc(|w| codec.write(w, &v));
                            (
                                format!("ok {v:?} kinds={} rem={rem}", kinds(&v)),
                                Some(again == bytes[..consumed]),
                            )
                        }
                        Err(_) => ("err".to_string(), None),
                    }
                }};
            }

            /// Bytes read by the sliced codec of the bound.
            pub fn read_sliced(bound: &str, sliced: bool, bytes: &[u8]) -> Outcome {
                match bound {
                    "u8" => go_sliced!(u8, sliced, bytes),
                    "u16" => go_sliced!(u16, sliced, bytes),
                    "u32" => go_sliced!(u32, sliced, bytes),
                    "u64" => go_sliced!(u64, sliced, bytes),
                    "usize" => go_sliced!(usize, sliced, bytes),
                    other => panic!("no such bound {other}"),
                }
            }

            /// The buffer a sliced reading of the bytes gives, as a program that reads a message
            /// off the wire holds it.
            pub fn read_back(bytes: &[u8]) -> ZBuf {
                let mut r: &[u8] = bytes;
                Zenoh080Sliced::<u32>::new(true).read(&mut r).unwrap()
            }

            /// The provider's side of one buffer: a segment, the descriptor of a header that names
            /// a chunk of it.
            pub struct Provided {
                pub info: ShmBufInfo,
                owned: OwnedMetadataDescriptor,
                _descriptor: Box<dyn Any>,
                _seg: ArrayInSHM<SegmentID, u8, u32>,
            }

            impl Provided {
                pub fn refcount(&self) -> u32 {
                    self.owned.header().refcount.load(Ordering::SeqCst)
                }
            }

            /// A segment with the byte `fill + i` at offset `i` for `capacity` bytes, a header that
            /// names it, and the info of a buffer of `data_len` bytes of it.
            pub fn provide(capacity: usize, data_len: usize, fill: u8) -> Provided {
                let seg = ArrayInSHM::<SegmentID, u8, u32>::create(nz(4096)).unwrap();
                for i in 0..capacity {
                    // SAFETY: the offset is within the 4096 bytes of the segment.
                    unsafe { seg.elem_mut(i as u32).write(fill.wrapping_add(i as u8)) };
                }
                let held = GLOBAL_METADATA_STORAGE.read().allocate().unwrap();
                let owned: OwnedMetadataDescriptor = (*held).clone();
                let header = owned.header();
                header.set_data_descriptor(&ChunkDescriptor::new(seg.id(), 0, nz(capacity)));
                header.protocol.store(POSIX_PROTOCOL_ID, Ordering::SeqCst);
                let d = MetadataDescriptor::from(&owned);
                let info = ShmBufInfo::new(
                    nz(data_len),
                    d,
                    header.generation.load(Ordering::SeqCst),
                );
                Provided {
                    info,
                    owned,
                    _descriptor: Box::new(held),
                    _seg: seg,
                }
            }

            /// The buffer of a provision, through the global reader, with the count of a buffer
            /// that one holder has.
            pub fn buffer(p: &Provided) -> ShmBufInner {
                p.owned.header().refcount.store(1, Ordering::SeqCst);
                let arc = ShmReader::new(Arc::clone(&GLOBAL_CLIENT_STORAGE.read()))
                    .read_shmbuf(p.info.clone())
                    .unwrap();
                match Arc::try_unwrap(arc) {
                    Ok(inner) => inner,
                    Err(_) => panic!("the reader kept a reference to the buffer"),
                }
            }

            /// A slice of the shared-memory kind over a buffer.
            pub fn shm_slice(inner: ShmBufInner) -> ZSlice {
                let mut s = ZSlice::from(Arc::new(inner));
                s.kind = ZSliceKind::ShmPtr;
                s
            }

            /// A slice of the shared-memory kind over bytes, which is not a buffer.
            pub fn foreign_slice(n: usize) -> ZSlice {
                let mut s = ZSlice::from(vec![0x77u8; n]);
                s.kind = ZSliceKind::ShmPtr;
                s
            }

            pub fn raw_slice(n: usize) -> ZSlice {
                ZSlice::from(vec![0x11u8; n])
            }

            pub fn zbuf(slices: Vec<ZSlice>) -> ZBuf {
                let mut z = ZBuf::empty();
                for s in slices {
                    z.push_zslice(s);
                }
                z
            }

            /// A buffer whose info is the one given, whatever memory it is of: what is written of
            /// it is the info.
            pub fn with_info(p: &Provided, info: ShmBufInfo) -> ShmBufInner {
                let mut inner = buffer(p);
                inner.info = info;
                inner
            }

            pub fn write_u32(z: &ZBuf, sliced: bool) -> Result<Vec<u8>, ()> {
                let mut v: Vec<u8> = Vec::new();
                let r = guarded(|| {
                    let mut w = (&mut v).writer();
                    Zenoh080Sliced::<u32>::new(sliced).write(&mut w, z)
                });
                match r {
                    Some(Ok(())) => Ok(v),
                    _ => Err(()),
                }
            }

            /// The result of writing into a writer of `cap` bytes: whether it was refused, and
            /// whether it panicked.
            pub fn write_capped(z: &ZBuf, cap: usize) -> &'static str {
                let mut buf = vec![0u8; cap];
                let r = guarded(|| {
                    let mut w = buf.as_mut_slice().writer();
                    Zenoh080Sliced::<u32>::new(true).write(&mut w, z)
                });
                match r {
                    Some(Ok(())) => "written",
                    Some(Err(_)) => "refused",
                    None => "panicked",
                }
            }

            /// The result of a sliced write into a vector, and how many bytes the writer holds
            /// after it.
            pub fn write_leftover(z: &ZBuf) -> (&'static str, usize) {
                let mut v: Vec<u8> = Vec::new();
                let r = guarded(|| {
                    let mut w = (&mut v).writer();
                    Zenoh080Sliced::<u32>::new(true).write(&mut w, z)
                });
                let verdict = match r {
                    Some(Ok(())) => "written",
                    Some(Err(_)) => "refused",
                    None => "panicked",
                };
                (verdict, v.len())
            }

            pub fn w_len_u32(z: &ZBuf, sliced: bool) -> usize {
                Zenoh080Sliced::<u32>::new(sliced).w_len(z)
            }

            /// The bytes of a sliced buffer read, and for each slice its kind and its bytes.
            pub fn read_u32(bytes: &[u8]) -> Result<Vec<(char, Vec<u8>)>, ()> {
                let mut r: &[u8] = bytes;
                let z: ZBuf = Zenoh080Sliced::<u32>::new(true)
                    .read(&mut r)
                    .map_err(|_| ())?;
                Ok(z.zslices()
                    .map(|s| {
                        (
                            match s.kind {
                                ZSliceKind::Raw => 'r',
                                ZSliceKind::ShmPtr => 's',
                            },
                            s.as_slice().to_vec(),
                        )
                    })
                    .collect())
            }

            /// The info a descriptor of the bytes read is, then the bytes of the memory it names
            /// read through the global reader.
            pub fn map_info(info_bytes: &[u8]) -> Result<(Vec<u8>, usize), String> {
                let mut r: &[u8] = info_bytes;
                let info: ShmBufInfo = Zenoh080.read(&mut r).map_err(|_| "info".to_string())?;
                let buf = ShmReader::new(Arc::clone(&GLOBAL_CLIENT_STORAGE.read()))
                    .read_shmbuf(info)
                    .map_err(|e| e.to_string())?;
                let bytes = AsRef::<[u8]>::as_ref(&*buf).to_vec();
                let len = buf.len().get();
                Ok((bytes, len))
            }

            /// A segment id as bytes, and the id that is read by opening it, with the codec.
            pub fn segment_write(s: &Segment<u32>) -> Vec<u8> {
                enc(|w| Zenoh080.write(w, s))
            }

            pub fn segment_read(bytes: &[u8]) -> Result<u32, ()> {
                let mut r: &[u8] = bytes;
                let s: Segment<u32> = Zenoh080.read(&mut r).map_err(|_| ())?;
                Ok(s.id())
            }

            pub fn segment_create() -> Segment<u32> {
                Segment::<u32>::create(nz(64)).unwrap()
            }

            pub fn struct_write(s: &StructInSHM<u32, u64>) -> Vec<u8> {
                enc(|w| Zenoh080.write(w, s))
            }

            pub fn struct_read(bytes: &[u8]) -> Result<u32, ()> {
                let mut r: &[u8] = bytes;
                let s: StructInSHM<u32, u64> = Zenoh080.read(&mut r).map_err(|_| ())?;
                Ok(s.id())
            }

            pub fn struct_create() -> StructInSHM<u32, u64> {
                StructInSHM::<u32, u64>::create().unwrap()
            }
        }
    };
}

codec_cases!(up, up_codec, up_buffers, up_shm);
codec_cases!(wz, wz_codec, wz_buffers, wz_shm);

/// The bytes read, as the prefixes of each encoding and each of its bytes set to six values.
fn mutations(corpus: &[(&'static str, String, Vec<u8>)]) -> Vec<(&'static str, String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rng = StdRng::seed_from_u64(0x5A11);
    for (kind, name, bytes) in corpus {
        for cut in 0..bytes.len() {
            out.push((*kind, format!("{name} cut {cut}"), bytes[..cut].to_vec()));
        }
        let positions: Vec<usize> = if bytes.len() <= 16 {
            (0..bytes.len()).collect()
        } else {
            (0..12).map(|_| rng.gen_range(0..bytes.len())).collect()
        };
        for i in positions {
            for v in [0x00u8, 0x01, 0x80, 0xff, bytes[i] ^ 0x20, bytes[i] ^ 0x40] {
                let mut b = bytes.clone();
                b[i] = v;
                out.push((*kind, format!("{name} byte {i} = {v:02x}"), b));
            }
        }
    }
    out
}

const KINDS: [&str; 4] = ["metadata", "chunk", "nonzero", "info"];

#[test]
fn both_crates_write_every_descriptor_to_the_same_bytes() {
    let _g = serial();
    let (u, w) = (up::corpus(), wz::corpus());
    assert_eq!(u.len(), 36 + 216 + 6 + 108);
    assert_eq!(u, w);
    assert!(u.iter().all(|(_, _, b)| !b.ends_with(b"ERR")));
    let distinct: std::collections::BTreeSet<_> = u.iter().map(|(_, _, b)| b.clone()).collect();
    assert!(distinct.len() > 300, "{}", distinct.len());
    // Every encoding reads back as the descriptor it is, to the bytes it came from.
    for (kind, name, bytes) in &u {
        let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
        assert_eq!(a, b, "{name}");
        assert!(
            a.0.starts_with("ok") && a.0.ends_with("rem=0"),
            "{name}: {}",
            a.0
        );
        assert_eq!(a.1, Some(true), "{name} {}", hex(bytes));
    }
}

#[test]
fn both_crates_read_every_cut_and_changed_descriptor_alike() {
    let _g = serial();
    let corpus = up::corpus();
    let mut inputs = mutations(&corpus);
    // The encodings alone are read as every descriptor.
    for (own, name, bytes) in &corpus {
        for kind in KINDS {
            inputs.push((kind, format!("{name} as {kind} (own {own})"), bytes.clone()));
        }
    }
    assert!(inputs.len() > 10_000, "{}", inputs.len());
    let (mut ok, mut refused, mut truncated) = (0usize, 0usize, 0usize);
    for (kind, name, bytes) in &inputs {
        let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
        if a.0 == b.0 {
            if a.0.starts_with("ok") {
                ok += 1;
            } else {
                refused += 1;
            }
            continue;
        }
        // The one class: upstream read an integer wider than its field by keeping the low bits, so
        // the value it holds does not write back to the bytes it was read from, and wz refused it.
        assert!(
            a.0.starts_with("ok") && a.1 == Some(false) && b.0 == "err",
            "{kind} {name} {}\nup {a:?}\nwz {b:?}",
            hex(bytes)
        );
        truncated += 1;
    }
    assert!(ok > 3_000 && refused > 3_000, "{ok} {refused}");
    assert!(truncated > 0, "{truncated}");
}

#[test]
fn an_integer_wider_than_its_field_is_truncated_by_upstream_and_refused_by_wz() {
    let _g = serial();
    // The class of the codec's integers, in each descriptor: a metadata descriptor is two 16-bit
    // fields, a chunk descriptor two 32-bit fields and a size, the info of a buffer a size, a
    // descriptor and a 32-bit generation.
    // 0x10000 as a variable-length integer is 80 80 04, and 2^32 is 80 80 80 80 10.
    let over16 = [0x80u8, 0x80, 0x04];
    let over32 = [0x80u8, 0x80, 0x80, 0x80, 0x10];
    let fits16 = [0xffu8, 0xff, 0x03];
    let fits32 = [0xffu8, 0xff, 0xff, 0xff, 0x0f];
    let cases: Vec<(&str, &str, Vec<u8>, bool)> = vec![
        // (field, kind, bytes, wider than the field)
        (
            "metadata id",
            "metadata",
            [&over16[..], &[1u8]].concat(),
            true,
        ),
        (
            "metadata index",
            "metadata",
            [&[1u8][..], &over16[..]].concat(),
            true,
        ),
        (
            "metadata id fits",
            "metadata",
            [&fits16[..], &[1u8]].concat(),
            false,
        ),
        (
            "metadata index fits",
            "metadata",
            [&[1u8][..], &fits16[..]].concat(),
            false,
        ),
        (
            "chunk segment",
            "chunk",
            [&over32[..], &[1u8, 1]].concat(),
            true,
        ),
        (
            "chunk chunk",
            "chunk",
            [&[1u8][..], &over32[..], &[1u8]].concat(),
            true,
        ),
        (
            "chunk segment fits",
            "chunk",
            [&fits32[..], &[1u8, 1]].concat(),
            false,
        ),
        (
            "chunk chunk fits",
            "chunk",
            [&[1u8][..], &fits32[..], &[1u8]].concat(),
            false,
        ),
        (
            "info metadata id",
            "info",
            [&[1u8][..], &over16[..], &[1u8, 1]].concat(),
            true,
        ),
        (
            "info generation",
            "info",
            [&[1u8, 1, 1][..], &over32[..]].concat(),
            true,
        ),
        (
            "info generation fits",
            "info",
            [&[1u8, 1, 1][..], &fits32[..]].concat(),
            false,
        ),
    ];
    for (field, kind, bytes, wider) in cases {
        let (a, b) = (up::read_as(kind, &bytes), wz::read_as(kind, &bytes));
        if wider {
            assert!(
                a.0.starts_with("ok") && a.1 == Some(false) && b.0 == "err",
                "{field} {}\nup {a:?}\nwz {b:?}",
                hex(&bytes)
            );
        } else {
            assert_eq!(a, b, "{field} {}", hex(&bytes));
            assert!(
                a.0.starts_with("ok") && a.1 == Some(true),
                "{field}: {}",
                a.0
            );
        }
    }
}

#[test]
fn a_size_of_zero_is_refused_by_both_and_so_is_a_chunk_or_info_of_it() {
    let _g = serial();
    // A zero size, a chunk descriptor with a zero length, and the info of a buffer of no bytes.
    let zero = [0u8];
    for kind in ["nonzero"] {
        let (a, b) = (up::read_as(kind, &zero), wz::read_as(kind, &zero));
        assert_eq!(a, b);
        assert_eq!(a.0, "err");
    }
    let chunk_zero_len = [1u8, 2, 0];
    let (a, b) = (
        up::read_as("chunk", &chunk_zero_len),
        wz::read_as("chunk", &chunk_zero_len),
    );
    assert_eq!(a, b);
    assert_eq!(a.0, "err");
    let info_zero_len = [0u8, 1, 2, 3];
    let (a, b) = (
        up::read_as("info", &info_zero_len),
        wz::read_as("info", &info_zero_len),
    );
    assert_eq!(a, b);
    assert_eq!(a.0, "err");
}

#[test]
fn both_crates_write_a_buffer_of_raw_slices_to_the_same_bytes_at_every_bound() {
    let _g = serial();
    let (u, w) = (up::sliced_corpus(), wz::sliced_corpus());
    assert_eq!(u.len(), 4 * 2 * 5);
    assert_eq!(u, w);
    // The sliced framing of a buffer of three slices is not the plain one, and a bound of one byte
    // refuses a slice of 300.
    let get = |n: &str| {
        u.iter()
            .find(|(_, name, _)| name.starts_with(n))
            .unwrap()
            .2
            .clone()
    };
    assert_ne!(get("u32 shape 2 false"), get("u32 shape 2 true"));
    assert!(get("u8 shape 2 false").ends_with(b"ERR"));
    assert!(get("u8 shape 2 true").ends_with(b"ERR") || !get("u8 shape 2 true").is_empty());
    for (_, name, bytes) in &u {
        let bound = name.split(' ').next().unwrap();
        let sliced = name.contains(" true ");
        let (a, b) = (
            up::read_sliced(bound, sliced, bytes),
            wz::read_sliced(bound, sliced, bytes),
        );
        assert_eq!(a, b, "{name}");
        if !bytes.ends_with(b"ERR") {
            assert!(a.0.starts_with("ok"), "{name}: {}", a.0);
            assert_eq!(a.1, Some(true), "{name} {}", hex(bytes));
        }
    }
}

#[test]
fn both_crates_read_every_cut_and_changed_sliced_buffer_alike() {
    let _g = serial();
    let corpus: Vec<(&'static str, String, Vec<u8>)> = up::sliced_corpus()
        .into_iter()
        .filter(|(_, _, b)| !b.ends_with(b"ERR"))
        .collect();
    let inputs = mutations(&corpus);
    assert!(inputs.len() > 2_000, "{}", inputs.len());
    let (mut ok, mut refused, mut shm_tagged) = (0usize, 0usize, 0usize);
    for (_, name, bytes) in &inputs {
        let bound = name.split(' ').next().unwrap();
        let sliced = name.contains(" true ");
        let (a, b) = (
            up::read_sliced(bound, sliced, bytes),
            wz::read_sliced(bound, sliced, bytes),
        );
        assert_eq!(a, b, "{name} {}", hex(bytes));
        if a.0.starts_with("ok") {
            ok += 1;
            shm_tagged += a.0.contains("kinds=") as usize * a.0.contains('s') as usize;
        } else {
            refused += 1;
        }
    }
    assert!(ok > 500 && refused > 500, "{ok} {refused}");
    // The changed bytes reach the tag of the shared-memory kind and the unknown tags.
    assert!(shm_tagged > 0, "{shm_tagged}");
}

#[test]
fn both_crates_write_a_buffer_in_shared_memory_to_the_same_bytes() {
    let _g = serial();
    macro_rules! shapes {
        ($m:ident, $s:ident) => {{
            let mut out: Vec<(String, Result<Vec<u8>, ()>, usize)> = Vec::new();
            let p1 = $m::provide(64, 16, 0x10);
            let p2 = $m::provide(64, 48, 0x40);
            let infos = [
                $s::ShmBufInfo::new(
                    $m::nz(16),
                    $s::metadata::descriptor::MetadataDescriptor { id: 7, index: 9 },
                    11,
                ),
                $s::ShmBufInfo::new(
                    $m::nz(48),
                    $s::metadata::descriptor::MetadataDescriptor {
                        id: 0x1234,
                        index: 0x80,
                    },
                    u32::MAX,
                ),
            ];
            // The info of a buffer is the same in both crates whatever memory it names, so what is
            // written of a buffer in shared memory can be compared as bytes.
            for sliced in [true, false] {
                let build = |kinds: &[u8]| {
                    let mut slices = Vec::new();
                    let mut which = 0;
                    for k in kinds {
                        if *k == b's' {
                            let p = if which == 0 { &p1 } else { &p2 };
                            slices.push($m::shm_slice($m::with_info(p, infos[which].clone())));
                            which += 1;
                        } else {
                            slices.push($m::raw_slice(*k as usize - b'0' as usize));
                        }
                    }
                    $m::zbuf(slices)
                };
                for shape in ["s", "3s", "s4s", "3s4", "s3s"] {
                    let z = build(shape.as_bytes());
                    out.push((
                        format!("{shape} sliced={sliced}"),
                        $m::write_u32(&z, sliced),
                        $m::w_len_u32(&z, sliced),
                    ));
                }
            }
            out
        }};
    }
    let u = shapes!(up, up_shm);
    let w = shapes!(wz, wz_shm);
    assert_eq!(u, w);
    // A buffer in shared memory is written as its descriptor when sliced, and the plain framing
    // reads the bytes of its slice when not.
    let get = |n: &str| u.iter().find(|(name, _, _)| name == n).unwrap().1.clone();
    let sliced = get("s sliced=true").unwrap();
    assert_eq!(sliced[0], 1, "{}", hex(&sliced));
    assert_eq!(sliced[1], 1, "{}", hex(&sliced));
    assert_ne!(sliced, get("s sliced=false").unwrap());
    assert!(u.iter().all(|(_, b, _)| b.is_ok()));
}

#[test]
fn a_buffer_in_shared_memory_written_by_one_crate_is_read_by_the_other_in_both_directions() {
    let _g = serial();
    macro_rules! across {
        ($from:ident, $to:ident, $name:expr) => {{
            let p = $from::provide(64, 24, 0x30);
            let held_before;
            let bytes = {
                let inner = $from::buffer(&p);
                let z = $from::zbuf(vec![$from::raw_slice(2), $from::shm_slice(inner)]);
                held_before = p.refcount();
                $from::write_u32(&z, true).unwrap()
            };
            // The slice was dropped with its buffer (one less) and the write held the buffer for
            // its receiver (one more): the count is what it was before the write.
            assert_eq!(p.refcount(), held_before, "{} {}", $name, p.refcount());
            let read = $to::read_u32(&bytes).unwrap();
            assert_eq!(read.len(), 2, "{}", $name);
            assert_eq!(read[0].0, 'r', "{}", $name);
            assert_eq!(read[0].1, vec![0x11u8; 2], "{}", $name);
            // The reader tags the descriptor with the kind and holds its bytes.
            assert_eq!(read[1].0, 's', "{}", $name);
            let (mapped, len) = $to::map_info(&read[1].1).unwrap();
            assert_eq!(len, 24, "{}", $name);
            let want: Vec<u8> = (0..24u8).map(|i| 0x30u8.wrapping_add(i)).collect();
            assert_eq!(mapped, want, "{}", $name);
        }};
    }
    across!(up, wz, "up to wz");
    across!(wz, up, "wz to up");
    across!(up, up, "up to up");
    across!(wz, wz, "wz to wz");
}

#[test]
fn a_written_buffer_is_held_once_by_each_crate() {
    let _g = serial();
    macro_rules! held {
        ($m:ident) => {{
            let p = $m::provide(64, 16, 0x50);
            let inner = $m::buffer(&p);
            let one = inner.ref_count();
            let z = $m::zbuf(vec![$m::shm_slice(inner.clone()), $m::shm_slice(inner)]);
            let after_clones = p.refcount();
            $m::write_u32(&z, true).unwrap();
            (one, after_clones, p.refcount())
        }};
    }
    let (u, w) = (held!(up), held!(wz));
    // Two slices over one buffer: the clones raise the count by one and the write by two.
    assert_eq!(u, w);
    assert_eq!(u.2, u.1 + 2, "{u:?}");
    // The plain framing holds nothing.
    macro_rules! plain_held {
        ($m:ident) => {{
            let p = $m::provide(64, 16, 0x50);
            let inner = $m::buffer(&p);
            let z = $m::zbuf(vec![$m::shm_slice(inner)]);
            let before = p.refcount();
            let _ = $m::write_u32(&z, false);
            (before, p.refcount())
        }};
    }
    let (a, b) = (plain_held!(up), plain_held!(wz));
    assert_eq!(a, b);
    assert_eq!(a.0, a.1, "{a:?}");
}

#[test]
fn a_slice_of_the_shared_memory_kind_that_is_not_a_buffer_is_refused_by_wz_and_panics_upstream() {
    let _g = serial();
    macro_rules! foreign {
        ($m:ident) => {{
            let mut out: Vec<(String, Result<Vec<u8>, ()>)> = Vec::new();
            // Alone, after a raw slice, before one, and the plain framing, which writes its bytes.
            for (name, slices) in [
                ("alone", vec![$m::foreign_slice(4)]),
                ("after raw", vec![$m::raw_slice(2), $m::foreign_slice(4)]),
                ("before raw", vec![$m::foreign_slice(4), $m::raw_slice(2)]),
            ] {
                let z = $m::zbuf(slices);
                out.push((format!("{name} sliced"), $m::write_u32(&z, true)));
                out.push((format!("{name} plain"), $m::write_u32(&z, false)));
            }
            out
        }};
    }
    let (u, w) = (foreign!(up), foreign!(wz));
    for ((name, a), (_, b)) in u.iter().zip(&w) {
        if name.ends_with("plain") {
            // The plain framing never looks at the kind.
            assert_eq!(a, b, "{name}");
            assert!(a.is_ok(), "{name}");
        } else {
            // Upstream panics (its `unwrap` of the downcast), wz refuses: both are a refused write.
            assert!(a.is_err() && b.is_err(), "{name}: up {a:?} wz {b:?}");
        }
    }
    // The two refusals differ in kind, and the test is able to see that: the panic is `None` of a
    // guarded call, the refusal is `Some(Err)`.
    let z = up::zbuf(vec![up::foreign_slice(4)]);
    assert_eq!(up::write_capped(&z, 64), "panicked");
    let z = wz::zbuf(vec![wz::foreign_slice(4)]);
    assert_eq!(wz::write_capped(&z, 64), "refused");
    // wz writes nothing of a buffer it refuses, wherever the slice is in it; upstream has written
    // what came before the slice when it panics.
    macro_rules! leftovers {
        ($m:ident) => {{
            [
                vec![$m::foreign_slice(4)],
                vec![$m::raw_slice(2), $m::foreign_slice(4)],
                vec![$m::raw_slice(2), $m::raw_slice(3), $m::foreign_slice(4)],
            ]
            .map(|slices| $m::write_leftover(&$m::zbuf(slices)))
        }};
    }
    let (u, w) = (leftovers!(up), leftovers!(wz));
    assert_eq!(w, [("refused", 0); 3], "{w:?}");
    assert!(u.iter().all(|r| r.0 == "panicked"), "{u:?}");
    // A count, the tag of a raw slice and its length and bytes, then the tag of the buffer.
    assert_eq!([u[0].1, u[1].1, u[2].1], [2, 6, 11], "{u:?}");
}

#[test]
fn a_buffer_read_off_the_wire_and_written_again_is_refused_by_wz_and_panics_upstream() {
    let _g = serial();
    macro_rules! again {
        ($m:ident) => {{
            let p = $m::provide(64, 8, 0x60);
            let inner = $m::buffer(&p);
            let z = $m::zbuf(vec![$m::shm_slice(inner)]);
            let bytes = $m::write_u32(&z, true).unwrap();
            // Read it: a slice of the kind over the bytes of a descriptor, which is not a buffer.
            let read = $m::read_back(&bytes);
            $m::write_capped(&read, 256)
        }};
    }
    assert_eq!(again!(up), "panicked");
    assert_eq!(again!(wz), "refused");
}

#[test]
fn a_write_that_fails_on_a_later_slice_holds_no_buffer_in_wz_and_holds_the_earlier_ones_upstream() {
    let _g = serial();
    // A buffer of two buffers in shared memory written into a writer of every capacity from none to
    // the whole encoding and past it: what each write gave, and how far each buffer's reference
    // count moved.
    macro_rules! sweep {
        ($m:ident) => {{
            // The size of an encoding depends on the ids a provision draws (a variable-length
            // integer), so the capacities run to a bound that holds any of them: a count, then for
            // each buffer a tag, a length and a descriptor of at most fifteen bytes.
            let whole = 40usize;
            let mut rows: Vec<(usize, &'static str, i64, i64)> = Vec::new();
            for cap in 0..=whole {
                let pa = $m::provide(64, 8, 0x01);
                let pb = $m::provide(64, 8, 0x02);
                let z = $m::zbuf(vec![
                    $m::shm_slice($m::buffer(&pa)),
                    $m::shm_slice($m::buffer(&pb)),
                ]);
                let (a0, b0) = (pa.refcount(), pb.refcount());
                let result = $m::write_capped(&z, cap);
                rows.push((
                    cap,
                    result,
                    pa.refcount() as i64 - a0 as i64,
                    pb.refcount() as i64 - b0 as i64,
                ));
            }
            rows
        }};
    }
    let (u, w) = (sweep!(up), sweep!(wz));
    // Each crate refuses a writer that is too small and writes into one that is large enough, and
    // never panics on either.
    for rows in [&u, &w] {
        assert_eq!(rows[0].1, "refused", "{rows:?}");
        assert_eq!(rows[rows.len() - 1].1, "written", "{rows:?}");
        assert!(rows.iter().all(|r| r.1 != "panicked"), "{rows:?}");
    }
    // Written whole, each buffer is held once, by both.
    for rows in [&u, &w] {
        for r in rows.iter().filter(|r| r.1 == "written") {
            assert_eq!((r.2, r.3), (1, 1), "{r:?}");
        }
    }
    // Refused, wz holds none: the receiver of a write that failed is not coming.
    for r in w.iter().filter(|r| r.1 != "written") {
        assert_eq!((r.2, r.3), (0, 0), "wz {r:?}");
    }
    // Upstream holds the buffers it had written whole before the capacity ran out, and the count of
    // such a buffer is never released.
    let held: Vec<_> = u
        .iter()
        .filter(|r| r.1 != "written" && (r.2 != 0 || r.3 != 0))
        .collect();
    assert!(
        !held.is_empty(),
        "upstream held nothing of a failed write: {u:?}"
    );
    assert!(held.iter().all(|r| r.2 == 1 && r.3 <= 1), "{held:?}");
}

#[test]
fn a_segment_and_a_struct_in_shared_memory_are_written_as_their_ids_and_opened_by_the_other_crate()
{
    let _g = serial();
    macro_rules! across {
        ($from:ident, $to:ident, $name:expr) => {{
            let s = $from::segment_create();
            let bytes = $from::segment_write(&s);
            assert_eq!($to::segment_read(&bytes), Ok(s.id()), "{}", $name);
            let t = $from::struct_create();
            let bytes = $from::struct_write(&t);
            assert_eq!($to::struct_read(&bytes), Ok(t.id()), "{}", $name);
        }};
    }
    across!(up, wz, "up to wz");
    across!(wz, up, "wz to up");
    across!(up, up, "up to up");
    across!(wz, wz, "wz to wz");
}

#[test]
fn an_id_of_nothing_and_a_cut_encoding_of_one_are_refused_alike() {
    let _g = serial();
    // The id of a segment that is gone.
    macro_rules! gone {
        ($m:ident) => {{
            let s = $m::segment_create();
            let bytes = $m::segment_write(&s);
            drop(s);
            let t = $m::struct_create();
            let tbytes = $m::struct_write(&t);
            drop(t);
            (
                $m::segment_read(&bytes),
                $m::struct_read(&tbytes),
                $m::segment_read(&bytes[..bytes.len() - 1]),
                $m::segment_read(&[]),
                $m::struct_read(&[]),
            )
        }};
    }
    let (u, w) = (gone!(up), gone!(wz));
    assert_eq!(u, w);
    assert_eq!(u, (Err(()), Err(()), Err(()), Err(()), Err(())));
}

/// The control: the comparison is on bytes, so a descriptor that differs gives bytes that differ.
#[test]
fn the_comparison_sees_a_descriptor_that_differs() {
    let _g = serial();
    let c = wz::corpus();
    let get = |n: &str| c.iter().find(|(_, name, _)| name == n).unwrap().2.clone();
    assert_ne!(get("metadata 0 0"), get("metadata 0 1"));
    assert_ne!(get("nonzero 1"), get("nonzero 127"));
    assert_ne!(
        wz::read_as("info", &get("info 1 0 0 0")).0,
        wz::read_as("info", &get("info 1 0 0 1")).0
    );
    assert_ne!(
        wz::read_sliced("u32", true, &[1, 0, 1, 0xAA]).0,
        wz::read_sliced("u32", true, &[1, 0, 1, 0xAB]).0
    );
}
