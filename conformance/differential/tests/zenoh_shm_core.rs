// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-shm`, the platform segments and what is built on them (the first slice of the crate):
//! upstream's crate (`up_shm`) and wz's (`wz_shm`) given the same operations, results equal as
//! text, and, because two processes share a segment by its id and by what is in it, the one
//! crate's segments opened by the other.
//!
//! * SEGMENTS of every width of id (`u8` to `u64`) and of lengths at the edges of a page: created,
//!   created again (refused), opened, written through one mapping and read through the other,
//!   dropped in each order, opened after the last drop; the file the segment is named by is looked
//!   for, so the name `<id>.zenoh` is held;
//! * the segment with an id of its own (`posix_shm::segment`), the segment that is an array
//!   (`ArrayInSHM`, over each width of index, at the edge of its range) and the one that holds a
//!   structure (`StructInSHM`);
//! * the chunk descriptors and the pointer that owns its segment;
//! * THE TWO CRATES TOGETHER: a segment created by one and opened by the other, in both
//!   directions, with the lock each takes and the file left or gone as the last one lets go.
//!
//! Where upstream is lenient or leaks, wz is not, and each place is a class, built by hand and
//! held on both sides:
//!
//! * a segment whose creation fails after the file is made (a size past what a file may be, or
//!   past what can be mapped) is left in `/dev/shm` by upstream, to be found by the next orphan
//!   cleanup, and unlinked by wz;
//! * an array whose size in bytes does not fit a `usize` panics upstream in a build with overflow
//!   checks and asks for a wrapped, smaller size without them; wz refuses it.
//!
//! The segments are one namespace of the machine, so the tests of this binary take one lock and
//! use ids drawn from the process and the clock.

#![cfg(target_os = "linux")]

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, MutexGuard,
    },
};

static LOCK: Mutex<()> = Mutex::new(());
static NEXT: AtomicU64 = AtomicU64::new(0);

fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// An id no other process of this machine is likely to hold: the process, the clock and a counter,
/// below the bit the random ids of zenoh itself fill.
fn fresh_id() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64;
    ((std::process::id() as u64) << 32 | (nanos & 0xFFFF)) << 8
        | (NEXT.fetch_add(1, Ordering::SeqCst) & 0xFF)
}

/// An error as text without the place of the crate that made it (the file and line of a `bail!`
/// are those of each crate's own source, so they differ by construction).
fn plain(e: &impl std::fmt::Display) -> String {
    let s = e.to_string();
    s.split(" at ").next().unwrap_or("").to_string()
}

fn file_of(id: u64) -> String {
    format!("/dev/shm/{id}.zenoh")
}

fn exists(id: u64) -> bool {
    Path::new(&file_of(id)).exists()
}

macro_rules! shm_cases {
    ($m:ident, $s:ident) => {
        mod $m {
            use std::{
                num::NonZeroUsize,
                panic::{catch_unwind, AssertUnwindSafe},
                sync::Arc,
            };

            use $s::{
                api::{
                    common::types::PtrInSegment,
                    provider::chunk::{AllocatedChunk, ChunkDescriptor},
                },
                posix_shm::{
                    array::ArrayInSHM, segment::Segment as PosixSegment, struct_in_shm::StructInSHM,
                },
                shm::{Segment, SegmentID},
            };

            use super::{exists, file_of, plain};

            fn nz(n: usize) -> NonZeroUsize {
                NonZeroUsize::new(n).unwrap()
            }

            /// A segment of this crate by the id of `u64`, held for the tests of the two crates
            /// together.
            pub struct Held(Segment<u64>);

            pub fn create(id: u64, len: usize) -> Result<Held, String> {
                match Segment::<u64>::create(id, nz(len)) {
                    Ok(s) => Ok(Held(s)),
                    Err(e) => Err(format!("{e:?}")),
                }
            }

            pub fn open(id: u64) -> Result<Held, String> {
                match Segment::<u64>::open(id) {
                    Ok(s) => Ok(Held(s)),
                    Err(e) => Err(format!("{e:?}")),
                }
            }

            pub fn ptr(h: &Held) -> *mut u8 {
                h.0.as_ptr()
            }

            pub fn len(h: &Held) -> usize {
                h.0.len().get()
            }

            pub fn ensure_not_persistent(id: u64) {
                Segment::<u64>::ensure_not_persistent(id)
            }

            /// What a segment does over its life, as lines of text.
            fn life<ID: SegmentID>(id: ID, len: usize, out: &mut Vec<String>) {
                let n: u64 = id.into();
                let tag = format!("{} {len}", std::any::type_name::<ID>());
                let a = Segment::<ID>::create(id, nz(len));
                match &a {
                    Ok(s) => out.push(format!("{tag}: create ok id={} len={}", s.id(), s.len())),
                    Err(e) => out.push(format!("{tag}: create {e:?}")),
                }
                out.push(format!("{tag}: file {}", exists(n)));
                match Segment::<ID>::create(id, nz(len)) {
                    Ok(_) => out.push(format!("{tag}: second create ok")),
                    Err(e) => out.push(format!("{tag}: second create {e:?}")),
                }
                let b = Segment::<ID>::open(id);
                match &b {
                    Ok(s) => out.push(format!("{tag}: open ok id={} len={}", s.id(), s.len())),
                    Err(e) => out.push(format!("{tag}: open {e:?}")),
                }
                if let (Ok(a), Ok(b)) = (&a, &b) {
                    // SAFETY: both mappings are `len` bytes long.
                    unsafe {
                        a.as_ptr().write(0xAB);
                        a.as_ptr().add(len - 1).write(0xCD);
                        out.push(format!(
                            "{tag}: read {:02x} {:02x}",
                            b.as_ptr().read(),
                            b.as_ptr().add(len - 1).read()
                        ));
                        b.as_ptr().write(0x11);
                        out.push(format!("{tag}: read back {:02x}", a.as_ptr().read()));
                    }
                    out.push(format!("{tag}: equal {}", a == b));
                }
                drop(a);
                out.push(format!("{tag}: file after the first drop {}", exists(n)));
                match Segment::<ID>::open(id) {
                    Ok(s) => out.push(format!("{tag}: reopen ok len={}", s.len())),
                    Err(e) => out.push(format!("{tag}: reopen {e:?}")),
                }
                drop(b);
                out.push(format!("{tag}: file after the last drop {}", exists(n)));
                match Segment::<ID>::open(id) {
                    Ok(_) => out.push(format!("{tag}: open after ok")),
                    Err(e) => out.push(format!("{tag}: open after {e:?}")),
                }
            }

            /// The life of segments of every width of id, at the edges of a page.
            pub fn lives(base: u64) -> Vec<String> {
                let mut out = Vec::new();
                for len in [1usize, 4095, 4096, 4097, 1 << 20] {
                    life::<u8>(1 + (base % 200) as u8, len, &mut out);
                    life::<u16>(1 + (base % 60_000) as u16, len, &mut out);
                    life::<u32>(1 + (base % 4_000_000_000) as u32, len, &mut out);
                    life::<u64>(base, len, &mut out);
                }
                out
            }

            /// A creation that fails after the file is made: the text of what it gave and whether
            /// the file is still there, before and after `ensure_not_persistent`.
            pub fn failed_create(id: u64, len: usize) -> String {
                let r = match Segment::<u64>::create(id, nz(len)) {
                    Ok(_) => "ok".to_string(),
                    Err(e) => format!("{e:?}"),
                };
                let left = exists(id);
                Segment::<u64>::ensure_not_persistent(id);
                format!("{r} left={left} after={}", exists(id))
            }

            /// The segment with an id of its own, over three widths of id.
            fn posix<ID>(len: usize, out: &mut Vec<String>)
            where
                rand::distributions::Standard: rand::distributions::Distribution<ID>,
                ID: SegmentID,
            {
                let tag = std::any::type_name::<ID>();
                match PosixSegment::<ID>::create(nz(len)) {
                    Ok(s) => {
                        out.push(format!("{tag} {len}: create ok len={}", s.len()));
                        let id = s.id();
                        match PosixSegment::<ID>::open(id) {
                            Ok(o) => {
                                // SAFETY: both mappings are `len` bytes long.
                                unsafe {
                                    s.as_ptr().write(7);
                                    out.push(format!(
                                        "{tag} {len}: open ok len={} read {}",
                                        o.len(),
                                        o.as_ptr().read()
                                    ));
                                }
                                out.push(format!("{tag} {len}: same id {}", o.id() == id));
                            }
                            Err(e) => out.push(format!("{tag} {len}: open {}", plain(&e))),
                        }
                        drop(s);
                        match PosixSegment::<ID>::open(id) {
                            Ok(_) => out.push(format!("{tag} {len}: open after ok")),
                            Err(e) => out.push(format!("{tag} {len}: open after {}", plain(&e))),
                        }
                    }
                    Err(e) => out.push(format!("{tag} {len}: create {}", plain(&e))),
                }
            }

            pub fn posix_segments() -> Vec<String> {
                let mut out = Vec::new();
                for len in [1usize, 4096, 100_000] {
                    posix::<u8>(len, &mut out);
                    posix::<u32>(len, &mut out);
                    posix::<u64>(len, &mut out);
                }
                out
            }

            fn array<Index>(counts: &[usize], out: &mut Vec<String>)
            where
                Index: num_traits::Unsigned
                    + num_traits::PrimInt
                    + 'static
                    + num_traits::AsPrimitive<usize>
                    + std::fmt::Debug,
                isize: num_traits::AsPrimitive<Index>,
                usize: num_traits::AsPrimitive<Index>,
            {
                let tag = std::any::type_name::<Index>();
                for &count in counts {
                    match ArrayInSHM::<u64, u64, Index>::create(nz(count)) {
                        Ok(a) => {
                            out.push(format!("{tag} {count}: create ok elems={}", a.elem_count()));
                            let last = a.elem_count().get() - 1;
                            let at: Index = num_traits::AsPrimitive::as_(last);
                            // SAFETY: `at` is the last element of the array.
                            unsafe {
                                a.elem_mut(at).write(0xFEED);
                                let back = a.index(a.elem(at));
                                out.push(format!(
                                    "{tag} {count}: last {:x} index {:?}",
                                    a.elem(at).read(),
                                    back
                                ));
                            }
                            match ArrayInSHM::<u64, u64, Index>::open(a.id()) {
                                Ok(o) => {
                                    // SAFETY: the same element of the same segment.
                                    out.push(format!(
                                        "{tag} {count}: open elems={} read {:x}",
                                        o.elem_count(),
                                        unsafe { o.elem(at).read() }
                                    ));
                                }
                                Err(e) => out.push(format!("{tag} {count}: open {}", plain(&e))),
                            }
                        }
                        Err(e) => out.push(format!("{tag} {count}: create {}", plain(&e))),
                    }
                }
            }

            pub fn arrays() -> Vec<String> {
                let mut out = Vec::new();
                array::<u8>(&[1, 2, 255, 256, 257, 1000], &mut out);
                array::<u16>(&[1, 65_535, 65_536, 65_537], &mut out);
                array::<u32>(&[1, 4096, 100_000], &mut out);
                out
            }

            pub fn structs() -> Vec<String> {
                let mut out = Vec::new();
                match StructInSHM::<u64, [u64; 4]>::create() {
                    Ok(mut s) => {
                        s[0] = 1;
                        s[3] = 4;
                        out.push(format!("create ok {:?}", *s));
                        match StructInSHM::<u64, [u64; 4]>::open(s.id()) {
                            Ok(o) => out.push(format!("open ok {:?} {}", *o, o == s)),
                            Err(e) => out.push(format!("open {}", plain(&e))),
                        }
                        out.push(format!(
                            "elem_mut is deref {}",
                            s.elem_mut() as *const _ == &*s as *const _
                        ));
                    }
                    Err(e) => out.push(format!("create {}", plain(&e))),
                }
                out
            }

            /// An array whose size in bytes overflows a `usize`: the text of what it gave, with a
            /// panic told apart from a refusal.
            pub fn overflowing_array() -> String {
                let count = usize::MAX / 8 + 1;
                let r = catch_unwind(AssertUnwindSafe(
                    || match ArrayInSHM::<u64, u64, u64>::create(nz(count)) {
                        Ok(_) => "ok".to_string(),
                        Err(e) => format!("err {}", plain(&e)),
                    },
                ));
                match r {
                    Ok(t) => t,
                    Err(_) => "panic".to_string(),
                }
            }

            pub fn chunks() -> Vec<String> {
                let mut out = Vec::new();
                let d = ChunkDescriptor::new(1, 2, nz(3));
                out.push(format!("{d:?} {}", d == d.clone()));
                out.push(format!("{}", d == ChunkDescriptor::new(1, 2, nz(4))));
                let seg: Arc<dyn std::any::Any + Send + Sync> = Arc::new(0u8);
                let p = PtrInSegment::new(0x1000 as *mut u8, seg.clone());
                let q = PtrInSegment::new(0x1000 as *mut u8, Arc::new(1u8));
                let r = PtrInSegment::new(0x2000 as *mut u8, seg);
                out.push(format!("{p:?} {} {}", p == q, p == r));
                out.push(format!("{} {}", p.ptr() as usize, p.clone() == p));
                let c = AllocatedChunk::new(d, p);
                out.push(format!("{c:?}"));
                out
            }

            #[allow(dead_code)]
            pub fn file(id: u64) -> String {
                file_of(id)
            }
        }
    };
}

shm_cases!(up, up_shm);
shm_cases!(wz, wz_shm);

#[test]
fn both_crates_give_a_segment_the_same_life_in_every_width_of_id() {
    let _g = serial();
    let base = fresh_id();
    let (a, b) = (up::lives(base), wz::lives(base));
    assert_eq!(a, b);
    assert!(a.len() > 200, "{}", a.len());
    // Every step of the life is among the lines: creation, the refusal of a second, the file by
    // its name, the shared bytes, the file that stays for the first drop and goes with the last.
    assert!(a.iter().any(|l| l.contains("second create SegmentExists")));
    assert!(a
        .iter()
        .any(|l| l.contains("file after the first drop true")));
    assert!(a
        .iter()
        .any(|l| l.contains("file after the last drop false")));
    assert!(a.iter().any(|l| l.contains("read ab cd")));
    assert!(a.iter().any(|l| l.contains("open after OsError(2)")));
    assert!(a.iter().all(|l| !l.contains("create OsError")), "{a:?}");
}

#[test]
fn both_crates_give_the_segment_with_an_id_of_its_own_the_same_life() {
    let _g = serial();
    let (a, b) = (up::posix_segments(), wz::posix_segments());
    assert_eq!(a, b);
    assert_eq!(a.len(), 36);
    assert!(a.iter().all(|l| !l.contains("create Unable")), "{a:?}");
}

#[test]
fn both_crates_give_arrays_and_structures_the_same_counts_and_errors() {
    let _g = serial();
    let (a, b) = (up::arrays(), wz::arrays());
    assert_eq!(a, b);
    // The edge of the index: 256 elements of a `u8` index are made and 257 are refused.
    assert!(a
        .iter()
        .any(|l| l.starts_with("u8 256: create ok elems=256")));
    assert!(a.iter().any(|l| l.starts_with("u8 257: create Unable")));
    assert!(a
        .iter()
        .any(|l| l.starts_with("u16 65536: create ok elems=65536")));
    assert!(a.iter().any(|l| l.starts_with("u16 65537: create Unable")));
    let (a, b) = (up::structs(), wz::structs());
    assert_eq!(a, b);
    assert_eq!(a.len(), 3);
    assert!(a[1].starts_with("open ok [1, 0, 0, 4] true"), "{a:?}");
    assert!(a[2].ends_with("true"), "{a:?}");
}

#[test]
fn both_crates_describe_chunks_and_pointers_alike() {
    assert_eq!(up::chunks(), wz::chunks());
    assert_eq!(up::chunks().len(), 5);
}

#[test]
fn a_segment_of_one_crate_is_opened_by_the_other_in_both_directions() {
    let _g = serial();
    for upstream_creates in [true, false] {
        let id = fresh_id();
        let created = if upstream_creates {
            up::create(id, 8192).map(|h| {
                (
                    up::ptr(&h),
                    up::len(&h),
                    Box::new(h) as Box<dyn std::any::Any>,
                )
            })
        } else {
            wz::create(id, 8192).map(|h| {
                (
                    wz::ptr(&h),
                    wz::len(&h),
                    Box::new(h) as Box<dyn std::any::Any>,
                )
            })
        };
        let (cp, clen, created) = created.unwrap();
        assert_eq!(clen, 8192);
        assert!(exists(id));
        let opened = if upstream_creates {
            wz::open(id).map(|h| {
                (
                    wz::ptr(&h),
                    wz::len(&h),
                    Box::new(h) as Box<dyn std::any::Any>,
                )
            })
        } else {
            up::open(id).map(|h| {
                (
                    up::ptr(&h),
                    up::len(&h),
                    Box::new(h) as Box<dyn std::any::Any>,
                )
            })
        };
        let (op, olen, opened) = opened.unwrap();
        assert_eq!(olen, 8192);
        // SAFETY: both mappings are 8192 bytes long.
        unsafe {
            for i in [0usize, 1, 4095, 8191] {
                cp.add(i).write(i as u8 ^ 0x5A);
            }
            for i in [0usize, 1, 4095, 8191] {
                assert_eq!(op.add(i).read(), i as u8 ^ 0x5A);
            }
            op.add(100).write(0x77);
            assert_eq!(cp.add(100).read(), 0x77);
        }
        // The creator lets go first: the file stays for the one that opened it, which lets go last.
        drop(created);
        assert!(exists(id), "gone with the creator");
        // The other crate, asked to make a live segment not persistent, leaves it.
        if upstream_creates {
            up::ensure_not_persistent(id);
        } else {
            wz::ensure_not_persistent(id);
        }
        assert!(exists(id), "removed while held");
        drop(opened);
        assert!(!exists(id), "left after the last drop");
        // Opening what is gone is refused by both.
        assert_eq!(up::open(id).err(), wz::open(id).err());
    }
}

#[test]
fn both_crates_refuse_a_segment_made_by_the_other_that_already_exists() {
    let _g = serial();
    for upstream_creates in [true, false] {
        let id = fresh_id();
        if upstream_creates {
            let _a = up::create(id, 4096).unwrap();
            assert_eq!(wz::create(id, 4096).err().as_deref(), Some("SegmentExists"));
        } else {
            let _a = wz::create(id, 4096).unwrap();
            assert_eq!(up::create(id, 4096).err().as_deref(), Some("SegmentExists"));
        }
    }
}

#[test]
fn a_creation_that_fails_after_the_file_is_made_leaves_it_in_upstream_only() {
    let _g = serial();
    // A size that is not a file size (a negative one to the kernel) and one that cannot be mapped.
    let mut seen = Vec::new();
    for len in [1usize << 63, 1usize << 62] {
        let (iu, iw) = (fresh_id(), fresh_id());
        let (u, w) = (up::failed_create(iu, len), wz::failed_create(iw, len));
        seen.push((u, w));
    }
    for (u, w) in &seen {
        // Both fail the same way, and upstream leaves the file where wz has taken it back.
        let (uerr, werr) = (
            u.split(" left=").next().unwrap(),
            w.split(" left=").next().unwrap(),
        );
        assert_eq!(uerr, werr, "{u} / {w}");
        assert!(uerr.starts_with("OsError"), "{u}");
        assert!(u.contains("left=true after=false"), "{u}");
        assert!(w.contains("left=false after=false"), "{w}");
    }
}

#[test]
fn an_array_whose_size_overflows_is_refused_by_wz_and_panics_in_upstream() {
    let _g = serial();
    let (u, w) = (up::overflowing_array(), wz::overflowing_array());
    assert_eq!(u, "panic");
    assert!(
        w.starts_with("err Unable to create SHM array segment"),
        "{w}"
    );
}

/// The control: the comparison is on text, so a segment that lives differently gives lines that
/// differ.
#[test]
fn the_comparison_sees_a_segment_that_differs() {
    let _g = serial();
    let base = fresh_id();
    let a = wz::lives(base);
    let mut other = wz::lives(base);
    assert_eq!(a, other);
    other.pop();
    assert_ne!(a, other);
    assert_ne!(wz::arrays(), wz::posix_segments());
    let r = catch_unwind(AssertUnwindSafe(|| wz::chunks()));
    assert!(r.is_ok());
}
