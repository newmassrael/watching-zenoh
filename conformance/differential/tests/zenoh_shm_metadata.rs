// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-shm`, the metadata and the watchdog (the second slice of the crate): what keeps a buffer
//! alive across processes. Upstream's crate (`up_shm`) and wz's (`wz_shm`) given the same
//! operations, results equal as text, and, because a process reads another's metadata and
//! confirms its watchdog, each crate's descriptors linked and confirmed by the other.
//!
//! * THE STORAGE: descriptors allocated in turn (the index of each, the fields of a header as it
//!   is handed out, the generation that rises when a descriptor is taken back);
//! * THE WATCHDOG: a descriptor the validator watches and nothing confirms is invalidated within
//!   a period, one the confirmator confirms stays valid, and one whose confirmation is dropped is
//!   invalidated after it, the same timeline in both crates;
//! * THE TWO CRATES TOGETHER: a descriptor allocated by one crate, linked by the other through
//!   its id and index, shares its header bytes; the one crate's validator is kept satisfied by
//!   the other's confirmator, and invalidates the descriptor when that confirmation stops;
//! * THE TYPES of the provider's API that the metadata reaches (alignment, the errors).
//!
//! Where upstream takes what another process hands over without looking, wz looks; each place is
//! a class, built by hand and held on both sides:
//!
//! * a descriptor linked at an index past the headers of its segment: upstream takes a header past
//!   the end of the segment (so the case is not run on upstream, and the edge below it is run on
//!   both), wz refuses it;
//! * a structure opened from a segment smaller than it: upstream opens it, wz refuses;
//! * the length of a header that was never given a data descriptor: upstream builds a
//!   `NonZeroUsize` out of zero (an abort with debug assertions, undefined behaviour without, so
//!   that side runs in a child process), wz reads it as one byte.
//!
//! The crates are built with `test`, whose watchdog tasks panic on a missed period, so the tests
//! of this binary take one lock and hold their sleeps to a few periods.

#![cfg(target_os = "linux")]

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Mutex, MutexGuard},
    time::Duration,
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

fn pause(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

macro_rules! shm_cases {
    ($m:ident, $s:ident, $r:ident) => {
        mod $m {
            use std::{
                any::Any,
                num::NonZeroUsize,
                panic::{catch_unwind, AssertUnwindSafe},
                sync::atomic::Ordering,
            };

            use $s::{
                api::{
                    cleanup::cleanup_orphaned_shm_segments,
                    provider::chunk::ChunkDescriptor,
                    provider::types::{
                        AllocAlignment, ZAllocError, ZLayoutAllocError, ZLayoutError,
                    },
                },
                init::init,
                metadata::{
                    descriptor::{MetadataDescriptor, OwnedMetadataDescriptor},
                    storage::GLOBAL_METADATA_STORAGE,
                    subscription::GLOBAL_METADATA_SUBSCRIPTION,
                },
                posix_shm::struct_in_shm::StructInSHM,
                shm::Segment,
                watchdog::{
                    confirmator::{ConfirmedDescriptor, GLOBAL_CONFIRMATOR},
                    validator::GLOBAL_VALIDATOR,
                },
            };

            use super::{pause, plain};

            /// A descriptor handed out by this crate's storage.
            pub struct Alloc {
                pub id: u16,
                pub index: u16,
                owned: OwnedMetadataDescriptor,
                _held: Box<dyn Any>,
            }

            impl Alloc {
                pub fn refcount(&self) -> u32 {
                    self.owned.header().refcount.load(Ordering::SeqCst)
                }
                pub fn generation(&self) -> u32 {
                    self.owned.header().generation.load(Ordering::SeqCst)
                }
                pub fn invalidated(&self) -> bool {
                    self.owned
                        .header()
                        .watchdog_invalidated
                        .load(Ordering::SeqCst)
                }
                pub fn set_protocol(&self, v: u32) {
                    self.owned.header().protocol.store(v, Ordering::SeqCst)
                }
                /// Gives the header a data descriptor.
                pub fn set_data(&self, segment: u32, chunk: u32, len: usize) {
                    self.owned
                        .header()
                        .set_data_descriptor(&ChunkDescriptor::new(
                            segment,
                            chunk,
                            NonZeroUsize::new(len).unwrap(),
                        ))
                }
                pub fn data(&self) -> String {
                    format!("{:?}", self.owned.header().data_descriptor())
                }
                /// Confirms the watchdog bit of this descriptor.
                pub fn confirm_bit(&self) {
                    self.owned.confirm()
                }
                /// Reads and clears the watchdog bit of this descriptor: nonzero if confirmed.
                pub fn take_bit(&self) -> bool {
                    self.owned.test_validate() != 0
                }
                pub fn protocol(&self) -> u32 {
                    self.owned.header().protocol.load(Ordering::SeqCst)
                }
                pub fn watchdog_cmp(&self, other: &Alloc) -> std::cmp::Ordering {
                    use std::ops::Deref;
                    self.owned.deref().cmp(other.owned.deref())
                }
                pub fn watch(&self) {
                    GLOBAL_VALIDATOR.read().add(self.owned.clone());
                }
                pub fn confirm_here(&self) -> ConfirmedDescriptor {
                    GLOBAL_CONFIRMATOR.read().add(self.owned.clone())
                }
                pub fn give_back(self) -> (OwnedMetadataDescriptor, u32) {
                    let owned = self.owned.clone();
                    drop(self);
                    let generation = owned.header().generation.load(Ordering::SeqCst);
                    (owned, generation)
                }
            }

            pub fn alloc() -> Alloc {
                let held = GLOBAL_METADATA_STORAGE.read().allocate().unwrap();
                let owned: OwnedMetadataDescriptor = (*held).clone();
                let d = MetadataDescriptor::from(&owned);
                Alloc {
                    id: d.id,
                    index: d.index,
                    owned,
                    _held: Box::new(held),
                }
            }

            /// A descriptor of another process's metadata linked and confirmed here.
            pub struct Linked {
                owned: OwnedMetadataDescriptor,
                _confirmed: ConfirmedDescriptor,
            }

            impl Linked {
                pub fn refcount(&self) -> u32 {
                    self.owned.header().refcount.load(Ordering::SeqCst)
                }
                pub fn generation(&self) -> u32 {
                    self.owned.header().generation.load(Ordering::SeqCst)
                }
                pub fn set_refcount(&self, v: u32) {
                    self.owned.header().refcount.store(v, Ordering::SeqCst)
                }
                pub fn protocol(&self) -> u32 {
                    self.owned.header().protocol.load(Ordering::SeqCst)
                }
                pub fn data(&self) -> String {
                    format!("{:?}", self.owned.header().data_descriptor())
                }
            }

            pub fn link_confirm(id: u16, index: u16) -> Result<Linked, String> {
                let owned = GLOBAL_METADATA_SUBSCRIPTION
                    .read()
                    .link(&MetadataDescriptor { id, index })
                    .map_err(|e| plain(&e))?;
                let confirmed = GLOBAL_CONFIRMATOR.read().add(owned.clone());
                Ok(Linked {
                    owned,
                    _confirmed: confirmed,
                })
            }

            pub fn link_only(id: u16, index: u16) -> Result<(), String> {
                GLOBAL_METADATA_SUBSCRIPTION
                    .read()
                    .link(&MetadataDescriptor { id, index })
                    .map(|_| ())
                    .map_err(|e| plain(&e))
            }

            /// The storage: the indexes of descriptors handed out in turn, the fields of each
            /// header, and the generation after a descriptor is taken back.
            pub fn storage() -> Vec<String> {
                let mut out = Vec::new();
                let first: Vec<Alloc> = (0..5).map(|_| alloc()).collect();
                let base = first[0].index;
                out.push(format!(
                    "indexes {:?}",
                    first.iter().map(|a| a.index - base).collect::<Vec<_>>()
                ));
                out.push(format!(
                    "same segment {}",
                    first.iter().all(|a| a.id == first[0].id)
                ));
                for a in &first {
                    out.push(format!(
                        "header refcount={} invalidated={} generation={} protocol={}",
                        a.refcount(),
                        a.invalidated(),
                        a.generation() - first[0].generation(),
                        a.protocol()
                    ));
                }
                first[2].set_protocol(7);
                out.push(format!("protocol after a write {}", first[2].protocol()));
                let mut it = first.into_iter();
                let a0 = it.next().unwrap();
                let g0 = a0.generation();
                let (_owned, g1) = a0.give_back();
                out.push(format!(
                    "generation after the descriptor is taken back +{}",
                    g1 - g0
                ));
                out
            }

            /// The watchdog bit of each header is its own: with the descriptors around the edges of
            /// a word of sixty-four bits and of thirty-two, confirm one and read them all.
            pub fn watchdog_matrix() -> Vec<String> {
                let held: Vec<Alloc> = (0..130).map(|_| alloc()).collect();
                let picks = [0usize, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129];
                let mut out = Vec::new();
                for &i in &picks {
                    for a in &held {
                        a.take_bit();
                    }
                    held[i].confirm_bit();
                    let seen: Vec<usize> =
                        (0..held.len()).filter(|&j| held[j].take_bit()).collect();
                    out.push(format!("confirm {i}: set {seen:?}"));
                    // Reading cleared it.
                    out.push(format!("confirm {i}: again {}", held[i].take_bit()));
                }
                // Two descriptors of one word compare by their masks, two of different words by
                // the word.
                let order = |i: usize, j: usize| format!("{:?}", held[i].watchdog_cmp(&held[j]));
                out.push(format!(
                    "order {} {} {} {}",
                    order(0, 1),
                    order(1, 0),
                    order(63, 64),
                    order(5, 5)
                ));
                out
            }

            /// The same descriptor linked again by this crate's subscription, from its id and
            /// index: the fields it reads are the ones the storage wrote.
            pub fn link_back() -> Vec<String> {
                let mut out = Vec::new();
                let a = alloc();
                a.set_protocol(42);
                a.set_data(3, 4, 5);
                match link_confirm(a.id, a.index) {
                    Ok(l) => {
                        out.push(format!(
                            "linked refcount={} protocol={}",
                            l.refcount(),
                            l.protocol()
                        ));
                        out.push(format!("data {} / {}", a.data(), l.data()));
                        l.set_refcount(9);
                        out.push(format!("write through the link reads {}", a.refcount()));
                    }
                    Err(e) => out.push(format!("link {e}")),
                }
                // The edges of the index: the first and the last header are linked, a segment
                // that does not exist is refused.
                out.push(format!("first {:?}", link_only(a.id, 0)));
                out.push(format!("last {:?}", link_only(a.id, 32767)));
                out.push(format!(
                    "no segment {:?}",
                    link_only(a.id.wrapping_add(1), 0).is_err()
                ));
                out
            }

            /// The timeline of a descriptor the validator watches: unconfirmed, confirmed, and
            /// after the confirmation is dropped.
            pub fn watchdog_timeline() -> Vec<String> {
                let mut out = Vec::new();
                let a = alloc();
                a.watch();
                let confirmed = a.confirm_here();
                pause(450);
                out.push(format!("confirmed: invalidated={}", a.invalidated()));
                drop(confirmed);
                pause(450);
                out.push(format!(
                    "confirmation dropped: invalidated={}",
                    a.invalidated()
                ));

                let b = alloc();
                b.watch();
                pause(300);
                out.push(format!("never confirmed: invalidated={}", b.invalidated()));
                out
            }

            /// Initialisation and the cleanup of orphans are callable at any time and twice.
            pub fn init_and_cleanup() -> String {
                init();
                init();
                cleanup_orphaned_shm_segments();
                cleanup_orphaned_shm_segments();
                "ok".to_string()
            }

            /// A structure opened from a segment smaller than it.
            pub fn small_struct(id: u16) -> Vec<String> {
                // The structure is 32 bytes: a segment of 8, of one byte less, of exactly that and
                // of one byte more.
                [8usize, 31, 32, 33]
                    .iter()
                    .map(|&len| {
                        let seg =
                            Segment::<u16>::create(id, NonZeroUsize::new(len).unwrap()).unwrap();
                        let r = match StructInSHM::<u16, [u64; 4]>::open(id) {
                            Ok(_) => "ok".to_string(),
                            Err(e) => format!("err {}", plain(&e)),
                        };
                        drop(seg);
                        format!("{len}: {r}")
                    })
                    .collect()
            }

            /// The length of a header that was never given a data descriptor.
            pub fn unset_len() -> String {
                let a = alloc();
                let owned: OwnedMetadataDescriptor = (*a.owned_ref()).clone();
                let r = catch_unwind(AssertUnwindSafe(|| owned.header().len().get()));
                match r {
                    Ok(n) => format!("len {n}"),
                    Err(_) => "panic".to_string(),
                }
            }

            impl Alloc {
                fn owned_ref(&self) -> &OwnedMetadataDescriptor {
                    &self.owned
                }
            }

            /// The alignment type: every power, the sizes aligned, the text of each.
            pub fn alignment() -> Vec<String> {
                let mut out = Vec::new();
                for pow in [0u8, 1, 2, 3, 12, 62, 63, 64, 65, 255] {
                    out.push(match AllocAlignment::new(pow) {
                        Ok(a) => format!("{pow}: ok {a} {a:?} {}", a.get_alignment_value()),
                        Err(e) => format!("{pow}: err {e} {e:?}"),
                    });
                }
                for (pow, size) in [(2u8, 7usize), (2, 8), (2, 9), (3, 1), (12, 4097), (0, 1)] {
                    let a = AllocAlignment::new(pow).unwrap();
                    out.push(format!(
                        "align {pow} {size}: {}",
                        a.align_size(NonZeroUsize::new(size).unwrap())
                    ));
                }
                let huge = AllocAlignment::new(12).unwrap();
                let r = catch_unwind(AssertUnwindSafe(|| {
                    huge.align_size(NonZeroUsize::new(usize::MAX - 5).unwrap())
                }));
                out.push(format!("huge {}", r.is_err()));
                out.push(format!(
                    "types {:?} {:?} {:?} {:?}",
                    AllocAlignment::for_type::<u8>(),
                    AllocAlignment::for_type::<u32>(),
                    AllocAlignment::for_type::<u64>(),
                    AllocAlignment::for_value(&1u16)
                ));
                out.push(format!(
                    "consts {:?} {:?} {:?} {:?} default {:?}",
                    AllocAlignment::ALIGN_1_BYTE,
                    AllocAlignment::ALIGN_2_BYTES,
                    AllocAlignment::ALIGN_4_BYTES,
                    AllocAlignment::ALIGN_8_BYTES,
                    AllocAlignment::default()
                ));
                out.push(format!(
                    "order {}",
                    AllocAlignment::ALIGN_2_BYTES < AllocAlignment::ALIGN_8_BYTES
                ));
                out
            }

            /// The errors: their text, their debug form and the conversions between them.
            pub fn errors() -> Vec<String> {
                let mut out = Vec::new();
                for e in [
                    ZAllocError::NeedDefragment,
                    ZAllocError::OutOfMemory,
                    ZAllocError::Other,
                ] {
                    out.push(format!("{e} {e:?}"));
                    let l: ZLayoutAllocError = e.into();
                    out.push(format!("{l} {l:?}"));
                }
                for e in [
                    ZLayoutError::IncorrectLayoutArgs,
                    ZLayoutError::ProviderIncompatibleLayout,
                ] {
                    out.push(format!("{e} {e:?}"));
                    let l: ZLayoutAllocError = e.into();
                    out.push(format!("{l} {l:?}"));
                }
                let source: $r::Error = "x".into();
                let from_result: ZAllocError = source.into();
                out.push(format!("from error {from_result}"));
                out
            }
        }
    };
}

shm_cases!(up, up_shm, up);
shm_cases!(wz, wz_shm, wz);

#[test]
fn both_crates_hand_out_descriptors_in_the_same_order_with_the_same_headers() {
    let _g = serial();
    let (a, b) = (up::storage(), wz::storage());
    assert_eq!(a, b);
    assert_eq!(a[0], "indexes [0, 1, 2, 3, 4]");
    assert_eq!(a[1], "same segment true");
    assert!(a[2].starts_with("header refcount=1 invalidated=false generation=0 protocol=0"));
    assert!(a.last().unwrap().ends_with("+1"), "{a:?}");
}

#[test]
fn both_crates_link_a_descriptor_back_by_its_id_and_index() {
    let _g = serial();
    let (a, b) = (up::link_back(), wz::link_back());
    assert_eq!(a, b);
    assert_eq!(a[0], "linked refcount=1 protocol=42");
    assert_eq!(
        a[1],
        "data ChunkDescriptor { segment: 3, chunk: 4, len: 5 } / \
         ChunkDescriptor { segment: 3, chunk: 4, len: 5 }"
    );
    assert_eq!(a[2], "write through the link reads 9");
    assert_eq!(a[3], "first Ok(())");
    assert_eq!(a[4], "last Ok(())");
}

#[test]
fn both_crates_keep_a_confirmed_descriptor_and_invalidate_the_others_alike() {
    let _g = serial();
    let (a, b) = (up::watchdog_timeline(), wz::watchdog_timeline());
    assert_eq!(a, b);
    assert_eq!(
        a,
        [
            "confirmed: invalidated=false",
            "confirmation dropped: invalidated=true",
            "never confirmed: invalidated=true"
        ]
    );
}

#[test]
fn both_crates_initialise_and_clean_up_alike() {
    let _g = serial();
    assert_eq!(up::init_and_cleanup(), wz::init_and_cleanup());
}

/// The one crate allocates, the other links and confirms: the header is the same bytes and the
/// watchdog the same bits, so a validator that watches the descriptor is kept satisfied by the
/// other crate's confirmator and invalidates it when that stops.
#[test]
fn a_descriptor_of_one_crate_is_linked_and_kept_alive_by_the_other() {
    let _g = serial();
    // upstream allocates, wz links; and the other way round.
    macro_rules! across {
        ($alloc:ident, $link:ident) => {{
            // A descriptor past the first words of watchdog bits, so that the word its bit is in
            // is part of what the two crates must agree on.
            let _pad: Vec<_> = (0..70).map(|_| $alloc::alloc()).collect();
            let a = $alloc::alloc();
            a.set_protocol(5);
            let l = $link::link_confirm(a.id, a.index).unwrap();
            assert_eq!(l.refcount(), a.refcount());
            assert_eq!(l.generation(), a.generation());
            assert_eq!(l.protocol(), 5);
            l.set_refcount(3);
            assert_eq!(a.refcount(), 3);
            a.watch();
            pause(450);
            assert!(
                !a.invalidated(),
                "invalidated while the other crate confirms"
            );
            drop(l);
            pause(450);
            assert!(a.invalidated(), "kept alive after the confirmation stopped");
        }};
    }
    across!(up, wz);
    across!(wz, up);
}

#[test]
fn a_descriptor_past_the_headers_of_its_segment_is_refused_by_wz_only() {
    let _g = serial();
    let a = wz::alloc();
    for index in [32768u16, 32769, 40000, u16::MAX] {
        let r = wz::link_only(a.id, index);
        assert!(
            r.as_ref()
                .err()
                .is_some_and(|e| e.starts_with("Metadata index")),
            "{index}: {r:?}"
        );
    }
    // The edge below it is read by both: upstream is held to it, not to the indexes past it, which
    // it takes a header at without a check.
    let u = up::alloc();
    assert_eq!(up::link_only(u.id, 32767), Ok(()));
    assert_eq!(wz::link_only(a.id, 32767), Ok(()));
}

#[test]
fn a_structure_opened_from_a_segment_smaller_than_it_is_refused_by_wz_only() {
    let _g = serial();
    let id = 1 + (std::process::id() % 60_000) as u16;
    let (u, w) = (up::small_struct(id), wz::small_struct(id));
    // Upstream opens all four; wz refuses the two that are smaller than the structure and opens the
    // exact size and the larger one.
    assert_eq!(u, ["8: ok", "31: ok", "32: ok", "33: ok"]);
    assert!(
        w[0].starts_with("8: err Unable to open SHM structure segment"),
        "{w:?}"
    );
    assert!(
        w[1].starts_with("31: err Unable to open SHM structure segment"),
        "{w:?}"
    );
    assert_eq!(w[2..], ["32: ok", "33: ok"]);
}

#[test]
fn the_length_of_a_header_without_a_data_descriptor_is_one_byte_in_wz_only() {
    let _g = serial();
    assert_eq!(wz::unset_len(), "len 1");
    // Upstream builds a `NonZeroUsize` out of zero: with debug assertions that is a check that
    // aborts the process (it cannot be caught), and without them undefined behaviour. So the
    // upstream side runs in a child process of this binary, which must not end well.
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "upstream_reads_an_unset_length_in_a_child",
            "--exact",
            "--nocapture",
        ])
        .env("ZSHM_CHILD", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "{status:?}");
}

/// The child of the test above: it reads the length of an unset header through upstream, and does
/// nothing when it is run as one of the tests.
#[test]
fn upstream_reads_an_unset_length_in_a_child() {
    if std::env::var("ZSHM_CHILD").is_err() {
        return;
    }
    let _g = serial();
    println!("{}", up::unset_len());
}

#[test]
fn both_crates_keep_the_watchdog_bit_of_each_header_apart() {
    let _g = serial();
    let (a, b) = (up::watchdog_matrix(), wz::watchdog_matrix());
    assert_eq!(a, b);
    assert_eq!(a.len(), 23);
    // Only the confirmed header reads as confirmed, at both sides of each word edge.
    assert_eq!(a[0], "confirm 0: set [0]");
    assert_eq!(a[6], "confirm 32: set [32]");
    assert_eq!(a[12], "confirm 64: set [64]");
    assert_eq!(a[1], "confirm 0: again false");
    assert_eq!(a[22], "order Less Greater Less Equal");
}

#[test]
fn both_crates_align_sizes_alike() {
    let _g = serial();
    let (a, b) = (up::alignment(), wz::alignment());
    assert_eq!(a, b);
    assert!(a.len() > 18);
    assert!(a.iter().any(|l| l == "align 2 7: 8"));
    assert!(a.iter().any(|l| l.starts_with("64: err")));
    assert!(a.iter().any(|l| l == "huge true"));
}

#[test]
fn both_crates_spell_the_errors_alike() {
    let _g = serial();
    let (a, b) = (up::errors(), wz::errors());
    assert_eq!(a, b);
    assert_eq!(a.len(), 11);
}

/// The control: the comparison is on text, so a timeline that differs gives lines that differ.
#[test]
fn the_comparison_sees_a_descriptor_that_differs() {
    let _g = serial();
    let a = wz::storage();
    let mut b = wz::storage();
    assert_eq!(a, b);
    b.pop();
    assert_ne!(a, b);
    assert_ne!(wz::alignment(), wz::errors());
    let r = catch_unwind(AssertUnwindSafe(|| wz::unset_len()));
    assert!(r.is_ok());
}
