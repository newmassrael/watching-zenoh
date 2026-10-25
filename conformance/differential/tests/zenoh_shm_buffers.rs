// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-shm`, the buffers and the reader (the third slice of the crate): upstream's crate
//! (`up_shm`) and wz's (`wz_shm`) given the same buffers to read, results equal as text, and,
//! because the reader reads what another process provided, a buffer provided by one crate read by
//! the other.
//!
//! The test plays the provider (the one the next slice builds): a segment of 4096 bytes with a
//! pattern in it, a metadata descriptor whose header names a chunk of it, and the info a sender
//! would put on the wire.
//!
//! * READS: buffers at several chunks and lengths, the bytes, the length, the capacity, the
//!   protocol and the reference count of each;
//! * CONVERSIONS: the immutable and the mutable buffer and their borrowed forms into one another
//!   (unique and valid, shared, invalidated), into a slice and a buffer, resized and relaid out,
//!   typed;
//! * INVALID BUFFERS: a generation that is not the buffer's, a watchdog that invalidated it, a
//!   protocol no client has, a segment that is gone;
//! * THE CLIENT STORAGE and the memory layout: every way to build and to ask;
//! * THE TWO CRATES TOGETHER: a buffer provided by one and read by the other, in both directions.
//!
//! Where upstream takes what another process hands over without looking, wz looks; each place is
//! a class, built by hand and held on both sides:
//!
//! * a length in the info that is past the chunk its descriptor names: upstream builds a slice of
//!   it (run on upstream inside the segment, so it reads memory that is not the buffer's), wz
//!   refuses the read;
//! * a chunk past the end of the segment: upstream gives the address (and a buffer that is not
//!   read), wz refuses;
//! * the length in the public `info` of a buffer set past its capacity: upstream's slice is that
//!   long, wz's is held to the capacity;
//! * a memory layout extended past what a size can be aligned to: upstream panics, wz refuses.
//!
//! The crates are built with `test`, so the tests of this binary take one lock.

#![cfg(target_os = "linux")]

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Mutex, MutexGuard},
};

static LOCK: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// An error as text without the place of the crate that made it.
fn plain(e: &impl std::fmt::Display) -> String {
    let s = e.to_string();
    s.split(" at ").next().unwrap_or("").to_string()
}

/// What a sender puts on the wire about a buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Parts {
    data_len: usize,
    id: u16,
    index: u16,
    generation: u32,
}

macro_rules! shm_cases {
    ($m:ident, $s:ident, $b:ident, $r:ident) => {
        mod $m {
            use std::{
                any::Any,
                borrow::Borrow,
                mem::MaybeUninit,
                num::NonZeroUsize,
                panic::{catch_unwind, AssertUnwindSafe},
                sync::{atomic::Ordering, Arc},
            };

            use $b::{buffer::Buffer, ZBuf, ZSlice};
            use $s::{
                api::{
                    buffer::{
                        traits::{OwnedShmBuf, ShmBuf, ShmBufIntoImmut, ShmBufUnsafeMut},
                        typed::Typed,
                        zshm::{zshm, ZShm},
                        zshmmut::{zshmmut, ZShmMut},
                    },
                    client::{shm_client::ShmClient, shm_segment::ShmSegment},
                    client_storage::{ShmClientStorage, GLOBAL_CLIENT_STORAGE},
                    common::{types::SegmentID, with_id::WithProtocolID},
                    protocol_implementations::posix::{
                        posix_shm_client::PosixShmClient, protocol_id::POSIX_PROTOCOL_ID,
                    },
                    provider::{
                        chunk::ChunkDescriptor,
                        memory_layout::{MemoryLayout, TypedLayout},
                        types::AllocAlignment,
                    },
                },
                metadata::{
                    descriptor::{MetadataDescriptor, OwnedMetadataDescriptor},
                    storage::GLOBAL_METADATA_STORAGE,
                },
                posix_shm::array::ArrayInSHM,
                reader::ShmReader,
                ShmBufHardRef, ShmBufInfo, ShmBufInner,
            };

            use super::{plain, Parts};

            fn nz(n: usize) -> NonZeroUsize {
                NonZeroUsize::new(n).unwrap()
            }

            /// The provider's side of one buffer: a segment, the descriptor of a header that
            /// names a chunk of it, and what goes on the wire.
            pub struct Provided {
                pub parts: Parts,
                owned: OwnedMetadataDescriptor,
                _descriptor: Box<dyn Any>,
                pub seg: Option<ArrayInSHM<SegmentID, u8, u32>>,
            }

            impl Provided {
                pub fn set_refcount(&self, v: u32) {
                    self.owned.header().refcount.store(v, Ordering::SeqCst)
                }
                pub fn refcount(&self) -> u32 {
                    self.owned.header().refcount.load(Ordering::SeqCst)
                }
                pub fn set_protocol(&self, v: u32) {
                    self.owned.header().protocol.store(v, Ordering::SeqCst)
                }
                pub fn invalidate(&self) {
                    self.owned
                        .header()
                        .watchdog_invalidated
                        .store(true, Ordering::SeqCst)
                }
                pub fn drop_segment(&mut self) {
                    self.seg = None;
                }
            }

            /// A segment with the byte `fill + i` at offset `chunk + i` for the `capacity` bytes
            /// of the chunk, a header that names it, and the info of a buffer of `data_len`.
            pub fn provide(chunk: u32, capacity: usize, data_len: usize, fill: u8) -> Provided {
                let seg = ArrayInSHM::<SegmentID, u8, u32>::create(nz(4096)).unwrap();
                for i in 0..capacity {
                    // SAFETY: the offset is within the 4096 bytes of the segment.
                    unsafe { seg.elem_mut(chunk + i as u32).write(fill.wrapping_add(i as u8)) };
                }
                let held = GLOBAL_METADATA_STORAGE.read().allocate().unwrap();
                let owned: OwnedMetadataDescriptor = (*held).clone();
                let header = owned.header();
                header.set_data_descriptor(&ChunkDescriptor::new(seg.id(), chunk, nz(capacity)));
                header.protocol.store(POSIX_PROTOCOL_ID, Ordering::SeqCst);
                let d = MetadataDescriptor::from(&owned);
                let parts = Parts {
                    data_len,
                    id: d.id,
                    index: d.index,
                    generation: header.generation.load(Ordering::SeqCst),
                };
                Provided {
                    parts,
                    owned,
                    _descriptor: Box::new(held),
                    seg: Some(seg),
                }
            }

            fn info_of(parts: Parts) -> ShmBufInfo {
                ShmBufInfo::new(
                    nz(parts.data_len),
                    MetadataDescriptor {
                        id: parts.id,
                        index: parts.index,
                    },
                    parts.generation,
                )
            }

            fn reader_of(storage: Arc<ShmClientStorage>) -> ShmReader {
                ShmReader::new(storage)
            }

            fn global_reader() -> ShmReader {
                reader_of(Arc::clone(&GLOBAL_CLIENT_STORAGE.read()))
            }

            /// Reads a buffer through the global storage and reports the facts of it.
            pub fn read(parts: Parts) -> Result<(Vec<u8>, usize, usize, u32), String> {
                let buf = global_reader()
                    .read_shmbuf(info_of(parts))
                    .map_err(|e| plain(&e))?;
                Ok((
                    AsRef::<[u8]>::as_ref(&*buf).to_vec(),
                    buf.len().get(),
                    buf.capacity().get(),
                    buf.protocol(),
                ))
            }

            /// Reads a buffer and gives it as an owned `ShmBufInner`.
            fn take(p: &Provided) -> ShmBufInner {
                p.set_refcount(1);
                let arc = global_reader().read_shmbuf(info_of(p.parts)).unwrap();
                match Arc::try_unwrap(arc) {
                    Ok(inner) => inner,
                    Err(_) => panic!("the reader kept a reference to the buffer"),
                }
            }

            fn sum(bytes: &[u8]) -> u64 {
                bytes.iter().map(|b| *b as u64).sum()
            }

            /// The reads: several chunks and lengths, with what each reports.
            pub fn reads() -> Vec<String> {
                let mut out = Vec::new();
                for (chunk, cap, len) in [
                    (0u32, 16usize, 16usize),
                    (100, 50, 50),
                    (100, 50, 10),
                    (4000, 96, 96),
                    (3, 1, 1),
                    (4095, 1, 1),
                ] {
                    let p = provide(chunk, cap, len, 0x21);
                    p.set_refcount(1);
                    out.push(match read(p.parts) {
                        Ok((bytes, l, c, proto)) => format!(
                            "{chunk} {cap} {len}: ok sum={} len={l} cap={c} protocol={proto} first={:?}",
                            sum(&bytes),
                            bytes.first()
                        ),
                        Err(e) => format!("{chunk} {cap} {len}: err {e}"),
                    });
                    out.push(format!(
                        "{chunk} {cap} {len}: refcount after the read {}",
                        p.refcount()
                    ));
                }
                out
            }

            /// The conversions between the buffer types.
            pub fn conversions() -> Vec<String> {
                let mut out = Vec::new();
                let p = provide(0, 16, 16, 0x40);
                let inner = take(&p);
                out.push(format!("inner len={} cap={} ref={}", inner.len(), inner.capacity(), inner.ref_count()));
                // a clone is a second reference, so the buffer is not unique and cannot be mutable
                let clone = inner.clone();
                out.push(format!("inner clone refs {} {}", inner.ref_count(), clone.ref_count()));
                let refused = ZShmMut::try_from(clone);
                out.push(format!("inner clone into mut {}", refused.is_ok()));
                drop(refused);
                out.push(format!("inner refs after {}", inner.ref_count()));
                let shm: ZShm = inner.into();
                out.push(format!("zshm valid={} sum={}", shm.is_valid(), sum(&shm)));
                // unique and valid: into a mutable one
                let mut mutable: ZShmMut = match ZShmMut::try_from(shm) {
                    Ok(m) => m,
                    Err(_) => {
                        out.push("zshmmut refused".into());
                        return out;
                    }
                };
                out.push("zshmmut ok".to_string());
                mutable[0] = 0xEE;
                out.push(format!("write {} {}", mutable[0], mutable.is_valid()));
                // SAFETY: the buffer is valid and nobody else writes it.
                let w = unsafe { mutable.as_mut_unchecked() };
                w[1] = 0xDD;
                out.push(format!("unchecked {} {}", mutable[1], mutable.len()));
                let borrowed: &zshm = Borrow::<zshm>::borrow(&mutable);
                out.push(format!("borrowed {} eq={}", borrowed.len(), borrowed == mutable));
                let borrowed_mut: &zshmmut = Borrow::<zshmmut>::borrow(&mutable);
                out.push(format!("borrowed mut {}", borrowed_mut.len()));
                let owned_copy: ZShm = borrowed.to_owned();
                out.push(format!("to_owned sum={}", sum(&owned_copy)));
                // shared now: the mutable conversion is refused
                let shared = ZShmMut::try_from(owned_copy);
                out.push(format!("shared into mut {}", shared.is_ok()));
                drop(shared);
                let hard = ShmBufHardRef::from(&mutable);
                let _ = &hard;
                let immut: ZShm = mutable.into_immut();
                out.push(format!("immut sum={}", sum(&immut)));
                let slice: ZSlice = immut.clone().into();
                let zbuf: ZBuf = immut.clone().into();
                out.push(format!("slice len={} zbuf len={}", slice.len(), zbuf.len()));
                // resize and relayout
                let mut owned = immut;
                out.push(format!("resize down {:?}", owned.try_resize(nz(8))));
                out.push(format!("resize to capacity {:?}", owned.try_resize(nz(16))));
                out.push(format!("resize up {:?}", owned.try_resize(nz(17))));
                out.push(format!("len {}", owned.len()));
                let layout_ok = MemoryLayout::new(8usize, AllocAlignment::ALIGN_8_BYTES).unwrap();
                out.push(format!("relayout {:?}", owned.try_relayout(layout_ok)));
                let layout_big = MemoryLayout::new(32usize, AllocAlignment::ALIGN_8_BYTES).unwrap();
                out.push(format!("relayout big {:?}", owned.try_relayout(layout_big)));
                out
            }

            /// Typed access.
            pub fn typed() -> Vec<String> {
                let mut out = Vec::new();
                let p = provide(0, 4, 4, 0);
                let buf: ZShmMut = ZShmMut::try_from(take(&p)).ok().unwrap();
                match Typed::<MaybeUninit<u32>, ZShmMut>::new(buf) {
                    Ok(t) => {
                        let t = t.initialize(0xDEAD_BEEF);
                        out.push(format!("typed {:x}", *t));
                        out.push(format!("typed valid {}", t.is_valid()));
                    }
                    Err(e) => out.push(format!("typed err {}", plain(&e))),
                }
                let q = provide(0, 8, 8, 0);
                let big: ZShmMut = ZShmMut::try_from(take(&q)).ok().unwrap();
                match Typed::<MaybeUninit<u32>, ZShmMut>::new(big) {
                    Ok(_) => out.push("typed 8 ok".to_string()),
                    Err(e) => out.push(format!("typed 8 err {}", plain(&e))),
                }
                let r = provide(1, 4, 4, 0);
                let odd: ZShmMut = ZShmMut::try_from(take(&r)).ok().unwrap();
                match Typed::<MaybeUninit<u32>, ZShmMut>::new(odd) {
                    Ok(_) => out.push("typed odd ok".to_string()),
                    Err(e) => out.push(format!("typed odd err {}", plain(&e).split(',').next().unwrap_or(""))),
                }
                out
            }

            /// The buffers that cannot be read.
            pub fn invalid() -> Vec<String> {
                let mut out = Vec::new();
                let p = provide(0, 16, 16, 1);
                let mut wrong = p.parts;
                wrong.generation = wrong.generation.wrapping_add(1);
                out.push(format!("generation {:?}", read(wrong).err()));
                p.invalidate();
                p.set_refcount(1);
                out.push(format!("invalidated {:?}", read(p.parts).err()));
                let q = provide(0, 16, 16, 1);
                q.set_protocol(7);
                out.push(format!("protocol {:?}", read(q.parts).err()));
                let mut r = provide(0, 16, 16, 1);
                r.drop_segment();
                // A reader of its own: the global one may have the segment mounted already.
                let storage = Arc::new(ShmClientStorage::builder().with_default_client_set().build());
                let gone = reader_of(storage).read_shmbuf(info_of(r.parts));
                out.push(format!("segment gone {}", gone.err().map(|e| plain(&e)).unwrap_or_default()));
                out.push(format!(
                    "metadata gone {:?}",
                    read(Parts { id: r.parts.id.wrapping_add(7), ..r.parts }).is_err()
                ));
                out
            }

            /// A client of another protocol, to put in a storage.
            #[derive(Debug)]
            struct OtherClient(u32);

            impl WithProtocolID for OtherClient {
                fn id(&self) -> u32 {
                    self.0
                }
            }

            impl ShmClient for OtherClient {
                fn attach(&self, _segment: SegmentID) -> Result<Arc<dyn ShmSegment>, $r::Error> {
                    Err("no segments".into())
                }
            }

            /// The client storage: every way to build it and to ask it.
            pub fn storage() -> Vec<String> {
                let mut out = Vec::new();
                let default = ShmClientStorage::builder().with_default_client_set().build();
                out.push(format!("default {:?}", default.supported_protocols()));
                let with: Arc<dyn ShmClient> = Arc::new(OtherClient(5));
                let one = ShmClientStorage::builder().with_client(with.clone()).build();
                out.push(format!("one {:?}", one.supported_protocols()));
                let dup = ShmClientStorage::builder()
                    .with_default_client_set()
                    .with_client(Arc::new(PosixShmClient))
                    .map(|b| b.build().supported_protocols())
                    .map_err(|e| plain(&e));
                out.push(format!("duplicate {dup:?}"));
                let two = ShmClientStorage::builder()
                    .with_default_client_set()
                    .with_client(with.clone())
                    .unwrap()
                    .build();
                out.push(format!("two {:?}", two.supported_protocols()));
                let many = ShmClientStorage::builder()
                    .with_clients(&[with.clone(), Arc::new(OtherClient(5)), Arc::new(OtherClient(2))])
                    .build();
                out.push(format!("many {:?}", many.supported_protocols()));
                let more = ShmClientStorage::builder()
                    .with_default_client_set()
                    .with_clients(&[Arc::new(OtherClient(9)) as Arc<dyn ShmClient>])
                    .build();
                out.push(format!("more {:?}", more.supported_protocols()));
                out.push(format!(
                    "builder {:?} {:?}",
                    ShmClientStorage::builder(),
                    ShmClientStorage::builder().with_default_client_set()
                ));
                out.push(format!("equal {} {}", default == default, default == one));
                out.push(format!("posix id {}", PosixShmClient.id()));
                // reading through a storage without the protocol
                let p = provide(0, 16, 16, 1);
                p.set_refcount(1);
                let r = reader_of(Arc::new(one)).read_shmbuf(info_of(p.parts));
                out.push(format!("no client {}", r.err().map(|e| plain(&e)).unwrap_or_default()));
                out
            }

            /// The memory layout: a grid of sizes and alignments, the conversions, the text.
            pub fn layouts() -> Vec<String> {
                let mut out = Vec::new();
                for pow in [0u8, 1, 3, 12] {
                    let a = AllocAlignment::new(pow).unwrap();
                    for size in [0usize, 1, 2, 7, 8, 16, 4096, 4097] {
                        out.push(match MemoryLayout::new(size, a) {
                            Ok(l) => format!("{pow} {size}: ok {l} {:?}", l.size()),
                            Err(e) => format!("{pow} {size}: err {e}"),
                        });
                    }
                }
                let l = MemoryLayout::new(8usize, AllocAlignment::ALIGN_4_BYTES).unwrap();
                for pow in [0u8, 2, 3, 12] {
                    let a = AllocAlignment::new(pow).unwrap();
                    out.push(match l.extend(a) {
                        Ok(e) => format!("extend {pow}: ok {e}"),
                        Err(e) => format!("extend {pow}: err {e}"),
                    });
                }
                out.push(format!(
                    "try_from {:?} {:?} {:?} {:?}",
                    MemoryLayout::try_from(8usize).map(|l| l.to_string()),
                    MemoryLayout::try_from(0usize).map(|l| l.to_string()),
                    MemoryLayout::try_from(nz(3)).map(|l| l.to_string()),
                    MemoryLayout::try_from((16usize, AllocAlignment::ALIGN_8_BYTES)).map(|l| l.to_string()),
                ));
                out.push(format!(
                    "types {} {} {}",
                    MemoryLayout::for_type::<u64>(),
                    MemoryLayout::for_type::<[u8; 3]>(),
                    MemoryLayout::for_value(&1u16)
                ));
                out.push(format!("from ref {}", MemoryLayout::from(&l)));
                let t = TypedLayout::<u32>::new();
                let _ = (t, t.clone(), TypedLayout::for_value(&1u32), TypedLayout::<u8>::default());
                out.push(format!("typed {t:?}"));
                out
            }

            /// A length in the info that is past the chunk its descriptor names (inside the
            /// segment).
            pub fn long_info() -> String {
                let p = provide(0, 100, 100, 3);
                p.set_refcount(1);
                let parts = Parts { data_len: 200, ..p.parts };
                match read(parts) {
                    Ok((bytes, len, cap, _)) => format!("ok len={len} cap={cap} bytes={}", bytes.len()),
                    Err(e) => format!("err {e}"),
                }
            }

            /// A chunk past the end of the segment: only whether the read is refused (nothing is
            /// read through the buffer).
            pub fn far_chunk(chunk: u32) -> String {
                let p = provide(0, 100, 100, 3);
                // The header names a chunk of the segment beyond it.
                p.owned.header().set_data_descriptor(&ChunkDescriptor::new(
                    p.seg.as_ref().unwrap().id(),
                    chunk,
                    nz(100),
                ));
                p.set_refcount(1);
                // Upstream built with `test` asserts the index where it takes the address (without
                // it the address is given), so a panic is told apart from the other answers.
                let r = catch_unwind(AssertUnwindSafe(|| {
                    match global_reader().read_shmbuf(info_of(p.parts)) {
                        Ok(buf) => {
                            // Not read through: only taken in and let go.
                            std::mem::forget(buf);
                            "ok".to_string()
                        }
                        Err(e) => format!("err {}", plain(&e)),
                    }
                }));
                r.unwrap_or_else(|_| "panic".to_string())
            }

            /// The length in the public info of a buffer set past its capacity.
            pub fn info_past_capacity() -> String {
                let p = provide(0, 100, 100, 3);
                let mut inner = take(&p);
                inner.info.data_len = nz(180);
                let n = AsRef::<[u8]>::as_ref(&inner).len();
                format!("len field {} slice {}", inner.len(), n)
            }

            /// A layout extended past what a size can be aligned to.
            pub fn extend_overflow() -> Vec<String> {
                // The largest size that can be aligned to 4096 and the one past it.
                [usize::MAX - 4095, usize::MAX - 4094]
                    .iter()
                    .map(|&size| {
                        let l = match MemoryLayout::new(size, AllocAlignment::ALIGN_1_BYTE) {
                            Ok(l) => l,
                            Err(e) => return format!("layout {e}"),
                        };
                        let r = catch_unwind(AssertUnwindSafe(|| {
                            l.extend(AllocAlignment::new(12).unwrap()).map(|e| e.to_string())
                        }));
                        match r {
                            Ok(Ok(s)) => format!("ok {s}"),
                            Ok(Err(e)) => format!("err {e}"),
                            Err(_) => "panic".to_string(),
                        }
                    })
                    .collect()
            }
        }
    };
}

shm_cases!(up, up_shm, up_buffers, up);
shm_cases!(wz, wz_shm, wz_buffers, wz);

#[test]
fn both_crates_read_the_same_buffers_alike() {
    let _g = serial();
    let (a, b) = (up::reads(), wz::reads());
    assert_eq!(a, b);
    assert_eq!(a.len(), 12);
    assert!(a[0].starts_with("0 16 16: ok sum="), "{a:?}");
    // the last byte of the segment is a chunk
    assert!(a[10].starts_with("4095 1 1: ok"), "{a:?}");
    assert!(a[2].contains("len=50 cap=50 protocol=0"), "{a:?}");
    // a buffer shorter than its chunk is read with its own length and the chunk's capacity
    assert!(a[4].contains("len=10 cap=50"), "{a:?}");
    assert!(a[1].ends_with("refcount after the read 0"), "{a:?}");
}

#[test]
fn both_crates_convert_the_buffers_alike() {
    let _g = serial();
    let (a, b) = (up::conversions(), wz::conversions());
    assert_eq!(a, b);
    assert!(a.contains(&"zshmmut ok".to_string()), "{a:?}");
    assert!(a.contains(&"shared into mut false".to_string()), "{a:?}");
    assert!(
        a.contains(&"inner clone into mut false".to_string()),
        "{a:?}"
    );
    assert!(a.contains(&"inner clone refs 2 2".to_string()), "{a:?}");
    assert!(a.contains(&"inner refs after 1".to_string()), "{a:?}");
    assert!(
        a.iter().any(|l| l == "resize to capacity Some(())"),
        "{a:?}"
    );
    assert!(a.iter().any(|l| l == "resize up None"), "{a:?}");
    assert!(
        a.iter()
            .any(|l| l.starts_with("relayout big Err(SizeTooBig)")),
        "{a:?}"
    );
    assert!(a.len() > 14, "{}", a.len());
}

#[test]
fn both_crates_type_a_buffer_alike() {
    let _g = serial();
    let (a, b) = (up::typed(), wz::typed());
    assert_eq!(a, b);
    assert_eq!(a[0], "typed deadbeef");
    assert!(a[2].starts_with("typed 8 err"), "{a:?}");
    assert!(a[3].starts_with("typed odd err"), "{a:?}");
}

#[test]
fn both_crates_refuse_the_buffers_that_cannot_be_read_alike() {
    let _g = serial();
    let (a, b) = (up::invalid(), wz::invalid());
    assert_eq!(a, b);
    assert!(a[0].contains("Buffer is invalidated"), "{a:?}");
    assert!(a[1].contains("Buffer is invalidated"), "{a:?}");
    assert!(a[2].contains("Unsupported SHM protocol: 7"), "{a:?}");
    assert!(a[3].contains("Unable to open POSIX shm segment"), "{a:?}");
}

#[test]
fn both_crates_build_and_ask_a_client_storage_alike() {
    let _g = serial();
    let (a, b) = (up::storage(), wz::storage());
    assert_eq!(a, b);
    assert_eq!(a[0], "default [0]");
    assert_eq!(a[1], "one [5]");
    assert!(
        a[2].starts_with("duplicate Err(\"Client already exists for id 0"),
        "{a:?}"
    );
    assert_eq!(a[3], "two [0, 5]");
    assert_eq!(a[4], "many [2, 5]");
    assert_eq!(a.last().unwrap(), "no client Unsupported SHM protocol: 0");
}

#[test]
fn both_crates_lay_memory_out_alike() {
    let _g = serial();
    let (a, b) = (up::layouts(), wz::layouts());
    assert_eq!(a, b);
    assert!(a.len() > 36, "{}", a.len());
    assert!(a.iter().any(|l| l.starts_with("extend 0: err")), "{a:?}");
}

/// A buffer provided by one crate is read by the other, with the bytes and the facts the provider
/// put there: the reader of each crate reads what the provider of the other made.
#[test]
fn a_buffer_provided_by_one_crate_is_read_by_the_other_in_both_directions() {
    let _g = serial();
    macro_rules! across {
        ($prov:ident, $read:ident) => {{
            for (chunk, cap, len) in [
                (0u32, 64usize, 64usize),
                (100, 200, 150),
                (3000, 1000, 1000),
            ] {
                let p = $prov::provide(chunk, cap, len, 0x55);
                p.set_refcount(1);
                let (bytes, l, c, proto) = $read::read(p.parts).unwrap();
                assert_eq!((l, c, proto), (len, cap, 0));
                let expect: Vec<u8> = (0..len).map(|i| 0x55u8.wrapping_add(i as u8)).collect();
                assert_eq!(bytes, expect);
            }
        }};
    }
    across!(up, wz);
    across!(wz, up);
}

#[test]
fn a_length_past_the_chunk_is_refused_by_wz_only() {
    let _g = serial();
    // upstream builds a slice of the length, inside the segment
    assert_eq!(up::long_info(), "ok len=200 cap=100 bytes=200");
    let w = wz::long_info();
    assert!(
        w.starts_with("err Buffer length 200 exceeds the chunk capacity 100"),
        "{w}"
    );
}

#[test]
fn a_chunk_past_the_segment_is_refused_by_wz_only() {
    let _g = serial();
    // The first chunk past the segment and one far past it.
    for chunk in [4096u32, 5000] {
        let u = up::far_chunk(chunk);
        assert!(u == "ok" || u == "panic", "{chunk}: {u}");
        let w = wz::far_chunk(chunk);
        assert!(
            w.starts_with(&format!(
                "err Chunk {chunk} is out of range for the segment of 4096 bytes"
            )),
            "{chunk}: {w}"
        );
    }
    // The last byte of the segment is read by both.
    assert_eq!(up::far_chunk(4095), wz::far_chunk(4095));
}

#[test]
fn the_length_in_the_info_of_a_buffer_is_held_to_its_capacity_in_wz_only() {
    let _g = serial();
    assert_eq!(up::info_past_capacity(), "len field 180 slice 180");
    assert_eq!(wz::info_past_capacity(), "len field 180 slice 100");
}

#[test]
fn a_layout_extended_past_what_a_size_aligns_to_is_refused_by_wz_only() {
    let _g = serial();
    // The largest size that aligns is made by both, the size past it panics upstream and is refused
    // by wz.
    let (u, w) = (up::extend_overflow(), wz::extend_overflow());
    assert!(u[0].starts_with("ok [size="), "{u:?}");
    assert_eq!(u[0], w[0]);
    assert_eq!(u[1], "panic");
    assert!(w[1].starts_with("err incorrect layout arguments"), "{w:?}");
}

/// The control: the comparison is on text, so a buffer that reads differently gives lines that
/// differ.
#[test]
fn the_comparison_sees_a_buffer_that_differs() {
    let _g = serial();
    let a = wz::reads();
    let mut b = wz::reads();
    assert_eq!(a, b);
    b.pop();
    assert_ne!(a, b);
    assert_ne!(wz::layouts(), wz::storage());
    let r = catch_unwind(AssertUnwindSafe(|| wz::invalid()));
    assert!(r.is_ok());
}
