// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-shm`, the provider and its backends (the fourth and last slice of the crate): upstream's
//! crate (`up_shm`) and wz's (`wz_shm`) given the same operations, results equal as text, and a
//! provider of the one crate read by the reader of the other.
//!
//! * THE PROVIDERS: each of the three POSIX backends (talc, buddy, binary heap) and the default one
//!   through the builders, a script of allocations of several sizes, frees (by dropping the
//!   buffer), garbage collections and defragmentations, what each reports (the sizes, the errors)
//!   and the bytes of each buffer;
//! * THE BACKENDS: what each says of a layout, its protocol id and what it has available;
//! * THE POLICIES: just alloc, garbage collect, defragment, deallocate and block on, alone and
//!   nested, through the type, through a value, and the precomputed and typed layouts;
//! * THE TWO CRATES TOGETHER: a buffer allocated by the provider of one crate read through the
//!   reader of the other, in both directions, with the bytes the provider wrote.
//!
//! Where upstream is lenient or loses memory, wz is not, and each place is a class, built by hand
//! and held on both sides:
//!
//! * the binary heap backend takes the largest free chunk off its list to look at it and, when the
//!   memory that is free is less than the request, answers out of memory without putting the chunk
//!   back: upstream loses it (a later request that fits finds nothing, and panics in a build with
//!   `test`), wz keeps it;
//! * `ShmProvider::map` of a chunk with a length longer than the chunk: upstream wraps it, wz
//!   refuses it;
//! * a request that cannot be aligned to the backend's alignment (a size that is too close to the
//!   largest `usize`): upstream panics out of the allocation builder, wz answers with the layout
//!   error.
//!
//! The segments and the global metadata are the machine's, so the tests of this binary take one
//! lock.

#![cfg(target_os = "linux")]

use std::sync::{Mutex, MutexGuard};

static LOCK: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// What a sender puts on the wire about a buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Parts {
    data_len: usize,
    id: u16,
    index: u16,
    generation: u32,
}

macro_rules! provider_cases {
    ($m:ident, $s:ident, $c:ident, $b:ident) => {
        mod $m {
            use std::{
                num::NonZeroUsize,
                panic::{catch_unwind, AssertUnwindSafe},
                sync::Arc,
            };

            use $b::ZSlice;
            use $c::Wait;
            use $s::{
                api::{
                    buffer::{traits::ShmBuf, zshmmut::ZShmMut},
                    client_storage::GLOBAL_CLIENT_STORAGE,
                    common::with_id::WithProtocolID,
                    protocol_implementations::posix::{
                        posix_shm_provider_backend::PosixShmProviderBackend,
                        posix_shm_provider_backend_binary_heap::PosixShmProviderBackendBinaryHeap,
                        posix_shm_provider_backend_buddy::PosixShmProviderBackendBuddy,
                        posix_shm_provider_backend_talc::PosixShmProviderBackendTalc,
                    },
                    provider::{
                        memory_layout::{MemoryLayout, TypedLayout},
                        shm_provider::{
                            BlockOn, ConstBool, ConstUsize, Deallocate, Defragment, GarbageCollect,
                            JustAlloc, ShmProvider, ShmProviderBuilder,
                        },
                        shm_provider_backend::ShmProviderBackend,
                        types::{AllocAlignment, ZLayoutAllocError},
                    },
                },
                metadata::descriptor::MetadataDescriptor,
                reader::ShmReader,
                ShmBufInfo, ShmBufInner,
            };

            use super::Parts;

            fn nz(n: usize) -> NonZeroUsize {
                NonZeroUsize::new(n).unwrap()
            }

            fn page(n: usize) -> MemoryLayout {
                MemoryLayout::new(n, AllocAlignment::ALIGN_8_BYTES).unwrap()
            }

            /// A script of allocations, frees, collections and defragmentations over one provider,
            /// by the name of the backend, as lines of text.
            fn script<Backend: ShmProviderBackend + Sync>(
                name: &str,
                provider: &ShmProvider<Backend>,
            ) -> Vec<String> {
                let mut out = Vec::new();
                let mut held: Vec<ZShmMut> = Vec::new();
                for size in [100usize, 200, 300, 50, 1000, 24] {
                    match provider.alloc(size).wait() {
                        Ok(mut b) => {
                            b[0] = size as u8;
                            out.push(format!("{name}: alloc {size} ok len={} first={}", b.len(), b[0]));
                            held.push(b);
                        }
                        Err(e) => out.push(format!("{name}: alloc {size} err {e}")),
                    }
                }
                out.push(format!("{name}: held {}", held.len()));
                // free in an order that leaves holes
                let b2 = held.remove(2);
                let b0 = held.remove(0);
                drop(b2);
                drop(b0);
                out.push(format!("{name}: gc largest {}", provider.garbage_collect()));
                out.push(format!("{name}: defragment {}", provider.defragment()));
                for size in [250usize, 120, 5000] {
                    out.push(match provider.alloc(size).wait() {
                        Ok(b) => {
                            let t = format!("{name}: after gc alloc {size} ok len={}", b.len());
                            held.push(b);
                            t
                        }
                        Err(e) => format!("{name}: after gc alloc {size} err {e}"),
                    });
                }
                held.clear();
                out.push(format!("{name}: gc after all freed {}", provider.garbage_collect()));
                out
            }

            /// The default backend and the three through their builders, the same script on each.
            pub fn providers() -> Vec<String> {
                let mut out = Vec::new();
                let default = ShmProviderBuilder::default_backend(page(4096)).wait().unwrap();
                out.extend(script("default", &default));
                let talc = ShmProviderBuilder::backend(
                    PosixShmProviderBackendTalc::builder(page(4096)).wait().unwrap(),
                )
                .wait();
                out.extend(script("talc", &talc));
                let buddy = ShmProviderBuilder::backend(
                    PosixShmProviderBackendBuddy::builder(page(4096)).wait().unwrap(),
                )
                .wait();
                out.extend(script("buddy", &buddy));
                let heap = ShmProviderBuilder::backend(
                    PosixShmProviderBackendBinaryHeap::builder(page(4096)).wait().unwrap(),
                )
                .wait();
                out.extend(script("heap", &heap));
                out
            }

            /// What each backend says of the layouts it is given, its identity and its room.
            pub fn backends() -> Vec<String> {
                let mut out = Vec::new();
                let t = PosixShmProviderBackendTalc::builder(page(4096)).wait().unwrap();
                let b = PosixShmProviderBackendBuddy::builder(page(4096)).wait().unwrap();
                let h = PosixShmProviderBackendBinaryHeap::builder(page(4096)).wait().unwrap();
                let d: PosixShmProviderBackend =
                    PosixShmProviderBackend::builder(page(4096)).wait().unwrap();
                let layout_for: [(&str, &dyn Fn(MemoryLayout) -> String); 4] = [
                    ("talc", &|l| format!("{:?}", t.layout_for(l).map(|e| e.to_string()))),
                    ("buddy", &|l| format!("{:?}", b.layout_for(l).map(|e| e.to_string()))),
                    ("heap", &|l| format!("{:?}", h.layout_for(l).map(|e| e.to_string()))),
                    ("default", &|l| format!("{:?}", d.layout_for(l).map(|e| e.to_string()))),
                ];
                for (name, lf) in layout_for {
                    for (size, pow) in [(1usize, 0u8), (7, 0), (8, 3), (9, 2), (64, 6)] {
                        let layout = MemoryLayout::new(size, AllocAlignment::new(pow).unwrap());
                        out.push(match layout {
                            Ok(l) => format!("{name} {size}/{pow}: {}", lf(l)),
                            Err(e) => format!("{name} {size}/{pow}: layout err {e}"),
                        });
                    }
                }
                out.push(format!("ids {} {} {} {}", t.id(), b.id(), h.id(), d.id()));
                out.push(format!(
                    "available talc={} buddy>0={} heap={}",
                    t.available(),
                    b.available() > 0,
                    h.available()
                ));
                out.push(format!("debug {t:?} / {h:?}").split(" / ").next().unwrap().to_string());
                out
            }

            fn fresh_heap() -> ShmProvider<PosixShmProviderBackendBinaryHeap> {
                ShmProviderBuilder::backend(
                    PosixShmProviderBackendBinaryHeap::builder(page(4096)).wait().unwrap(),
                )
                .wait()
            }

            fn texts<T: std::ops::Deref<Target = [u8]>, E: std::fmt::Display>(
                r: Result<T, E>,
            ) -> String {
                match r {
                    Ok(b) => format!("ok len={}", b.len()),
                    Err(e) => format!("err {e}"),
                }
            }

            /// The policies over a binary heap (the backend that tells fragmentation from running
            /// out), alone and nested.
            pub fn policies() -> Vec<String> {
                let mut out = Vec::new();
                // Four buffers of 1000 leave 96 bytes free. The first, the second and the last are
                // dropped, so their memory is free in the buffers and not yet in the backend: the
                // backend has the 96 bytes only, and two holes of 1000 beside each other once the
                // collection hands them back (the first two). A request of 2000 needs the
                // collection to give them back and the defragmentation to join them.
                macro_rules! fragmented {
                    ($policy:ty) => {{
                        let p = fresh_heap();
                        let a = p.alloc(1000usize).wait().unwrap();
                        let b = p.alloc(1000usize).wait().unwrap();
                        let c = p.alloc(1000usize).wait().unwrap();
                        let d = p.alloc(1000usize).wait().unwrap();
                        drop(a);
                        drop(b);
                        drop(d);
                        let t = texts(p.alloc(2000usize).with_policy::<$policy>().wait());
                        drop(c);
                        t
                    }};
                }
                // the same after a collection that the policy of the request would not make
                macro_rules! collected {
                    ($policy:ty) => {{
                        let p = fresh_heap();
                        let a = p.alloc(1000usize).wait().unwrap();
                        let b = p.alloc(1000usize).wait().unwrap();
                        let c = p.alloc(1000usize).wait().unwrap();
                        let d = p.alloc(1000usize).wait().unwrap();
                        drop(a);
                        drop(b);
                        drop(d);
                        let collected = p.garbage_collect();
                        let t = texts(p.alloc(2000usize).with_policy::<$policy>().wait());
                        drop(c);
                        format!("collected {collected}: {t}")
                    }};
                }
                out.push(format!("collected just {}", collected!(JustAlloc)));
                out.push(format!("collected defragment {}", collected!(Defragment<JustAlloc, JustAlloc>)));
                out.push(format!("just {}", fragmented!(JustAlloc)));
                out.push(format!(
                    "gc {}",
                    fragmented!(GarbageCollect<JustAlloc, JustAlloc, ConstBool<true>>)
                ));
                out.push(format!("defragment {}", fragmented!(Defragment<JustAlloc, JustAlloc>)));
                out.push(format!(
                    "gc then defragment {}",
                    fragmented!(GarbageCollect<Defragment<JustAlloc, JustAlloc>, Defragment<JustAlloc, JustAlloc>, ConstBool<true>>)
                ));
                out.push(format!(
                    "gc of nothing {}",
                    fragmented!(GarbageCollect<JustAlloc, JustAlloc, ConstBool<true>>)
                ));
                // too big for the segment under each policy
                let p = fresh_heap();
                out.push(format!(
                    "too big just {}",
                    texts(p.alloc(5000usize).wait())
                ));
                out.push(format!(
                    "too big gc {}",
                    texts(p.alloc(5000usize).with_policy::<GarbageCollect>().wait())
                ));
                // the policy that deallocates is unsafe: it frees what is busy
                let p = fresh_heap();
                let held: Vec<_> = (0..4).map(|_| p.alloc(1000usize).wait().unwrap()).collect();
                // SAFETY: the buffers held are not read after the policy frees them.
                let r = unsafe {
                    p.alloc(1500usize)
                        .with_unsafe_policy::<Deallocate<ConstUsize<2>, JustAlloc, JustAlloc>>()
                }
                .wait();
                out.push(format!("deallocate {}", texts(r)));
                drop(held);
                // a policy given as a value
                let p = fresh_heap();
                // SAFETY: the policy is the safe garbage collection.
                let r = unsafe {
                    p.alloc(100usize)
                        .with_runtime_policy(GarbageCollect::new(JustAlloc, JustAlloc, true))
                }
                .wait();
                out.push(format!("value {}", texts(r)));
                // block on, in a thread that frees the memory the request waits for
                let p = Arc::new(fresh_heap());
                let first = p.alloc(3500usize).wait().unwrap();
                let q = p.clone();
                let waiter = std::thread::spawn(move || {
                    texts(q.alloc(3500usize).with_policy::<BlockOn<GarbageCollect>>().wait())
                });
                std::thread::sleep(std::time::Duration::from_millis(50));
                drop(first);
                out.push(format!("block on {}", waiter.join().unwrap()));
                out
            }

            /// Precomputed layouts, typed layouts and alignment.
            pub fn layouts() -> Vec<String> {
                let mut out = Vec::new();
                let p = ShmProviderBuilder::default_backend(page(4096)).wait().unwrap();
                match p.alloc_layout(100usize) {
                    Ok(l) => {
                        for _ in 0..3 {
                            out.push(format!("precomputed {}", texts(l.alloc().wait())));
                        }
                    }
                    Err(e) => out.push(format!("precomputed err {e}")),
                }
                out.push(format!(
                    "zero {:?}",
                    p.alloc_layout(0usize).map(|_| ()).map_err(|e| e.to_string())
                ));
                let t = p.alloc(TypedLayout::<[u32; 4]>::new()).wait();
                out.push(format!("typed {}", t.is_ok()));
                if let Ok(t) = t {
                    out.push(format!("typed valid {}", t.is_valid()));
                }
                let aligned = p
                    .alloc(MemoryLayout::new(64usize, AllocAlignment::ALIGN_8_BYTES).unwrap())
                    .wait();
                out.push(format!(
                    "aligned {:?}",
                    aligned.map(|b| (b.as_ptr() as usize % 8, b.len())).map_err(|e| e.to_string())
                ));
                #[allow(deprecated)]
                let into = p.alloc(10usize).into_layout().map(|_| ()).map_err(|e| e.to_string());
                out.push(format!("into_layout {into:?}"));
                out
            }

            /// The async form of an allocation.
            pub fn async_alloc() -> Vec<String> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let mut out = Vec::new();
                    let p = ShmProviderBuilder::default_backend(page(4096)).wait().unwrap();
                    // Only the blocking policy is asynchronous, and it waits for memory that
                    // something frees: a request that nothing will ever free for would wait for
                    // ever, so the policy collects the buffers that were dropped.
                    let alloc = |n: usize| p.alloc(n).with_policy::<BlockOn<GarbageCollect>>();
                    out.push(format!("async {}", texts(alloc(100).await)));
                    let first = alloc(3000).await.unwrap();
                    let waiting = alloc(3000);
                    let (waited, ()) = tokio::join!(async { waiting.await }, async {
                        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                        drop(first);
                    });
                    out.push(format!("async block on {}", texts(waited)));
                    out
                })
            }

            /// A buffer allocated here, with what a sender would say of it and its bytes. The
            /// slice keeps the buffer alive.
            pub struct Provided {
                pub parts: Parts,
                pub bytes: Vec<u8>,
                _slice: ZSlice,
                _provider: Box<dyn std::any::Any>,
            }

            pub fn provide(sizes: &[usize]) -> Vec<Provided> {
                let provider = Arc::new(
                    ShmProviderBuilder::default_backend(page(65536)).wait().unwrap(),
                );
                sizes
                    .iter()
                    .map(|&size| {
                        let mut b = provider.alloc(size).wait().unwrap();
                        for (i, x) in b.iter_mut().enumerate() {
                            *x = (i as u8).wrapping_mul(7).wrapping_add(size as u8);
                        }
                        let bytes = b.to_vec();
                        let slice: ZSlice = b.into();
                        let inner = slice.downcast_ref::<ShmBufInner>().unwrap();
                        let metadata = inner.info.metadata.clone();
                        let parts = Parts {
                            data_len: inner.info.data_len.get(),
                            id: metadata.id,
                            index: metadata.index,
                            generation: inner.info.generation,
                        };
                        Provided {
                            parts,
                            bytes,
                            _slice: slice,
                            _provider: Box::new(provider.clone()),
                        }
                    })
                    .collect()
            }

            /// Reads what a sender described through the global client storage.
            pub fn read(parts: Parts) -> Result<Vec<u8>, String> {
                let storage = Arc::clone(&GLOBAL_CLIENT_STORAGE.read());
                let info = ShmBufInfo::new(
                    nz(parts.data_len),
                    MetadataDescriptor {
                        id: parts.id,
                        index: parts.index,
                    },
                    parts.generation,
                );
                let buf = ShmReader::new(storage).read_shmbuf(info).map_err(|e| {
                    let s = e.to_string();
                    s.split(" at ").next().unwrap_or("").to_string()
                })?;
                Ok(AsRef::<[u8]>::as_ref(&*buf).to_vec())
            }

            /// The binary heap that popped a chunk and answered out of memory.
            pub fn heap_loses_the_chunk() -> Vec<String> {
                let backend = PosixShmProviderBackendBinaryHeap::builder(page(4096)).wait().unwrap();
                let mut out = Vec::new();
                let first = backend.alloc(&page(3072));
                out.push(format!(
                    "first {:?}",
                    first.as_ref().map(|c| c.descriptor.len.get()).map_err(|e| format!("{e:?}"))
                ));
                // 1024 bytes are free as one chunk: ask for more than is free
                let big = backend.alloc(&page(2048));
                out.push(format!("too big {:?}", big.map(|_| ()).map_err(|e| format!("{e:?}"))));
                // and now for exactly what is free
                let r = catch_unwind(AssertUnwindSafe(|| {
                    backend
                        .alloc(&page(1024))
                        .map(|c| c.descriptor.len.get())
                        .map_err(|e| format!("{e:?}"))
                }));
                out.push(match r {
                    Ok(v) => format!("fits {v:?}"),
                    Err(_) => "fits panic".to_string(),
                });
                out.push(format!("available {}", backend.available()));
                // A chunk given back is available again, by its size. Upstream's backend died
                // holding its lock when it panicked above, so giving the chunk back is a panic of
                // its own there, and the count it answers is the one it had.
                let freed = catch_unwind(AssertUnwindSafe(|| {
                    if let Ok(c) = first {
                        backend.free(&c.descriptor);
                    }
                }));
                out.push(format!("free {}", if freed.is_ok() { "ok" } else { "panic" }));
                out.push(format!("available after free {}", backend.available()));
                out
            }

            /// The bytes a binary heap says are available over taking and giving back.
            pub fn heap_available() -> Vec<String> {
                let backend = PosixShmProviderBackendBinaryHeap::builder(page(4096)).wait().unwrap();
                let mut out = vec![backend.available().to_string()];
                let a = backend.alloc(&page(1024)).unwrap();
                out.push(backend.available().to_string());
                let b = backend.alloc(&page(1024)).unwrap();
                out.push(backend.available().to_string());
                backend.free(&b.descriptor);
                out.push(backend.available().to_string());
                backend.free(&a.descriptor);
                out.push(backend.available().to_string());
                out
            }

            /// `ShmProvider::map` of a chunk with a length at its own, past it and far past it.
            pub fn map_long() -> Vec<String> {
                let p = ShmProviderBuilder::default_backend(page(4096)).wait().unwrap();
                let backend = PosixShmProviderBackendTalc::builder(page(4096)).wait().unwrap();
                [64usize, 65, 128]
                    .iter()
                    .map(|&len| {
                        let chunk = backend.alloc(&page(64)).unwrap();
                        match p.map(chunk, len) {
                            Ok(b) => format!("{len}: ok len={}", b.len()),
                            Err(e) => format!("{len}: err {e}"),
                        }
                    })
                    .collect()
            }

            /// One allocation of `size` bytes, as text, with a panic told apart.
            pub fn request(size: usize) -> String {
                let p = ShmProviderBuilder::default_backend(page(4096)).wait().unwrap();
                let r = catch_unwind(AssertUnwindSafe(|| {
                    p.alloc(size).wait().map(|b| b.len()).map_err(|e| match e {
                        ZLayoutAllocError::Alloc(a) => format!("alloc {a}"),
                        ZLayoutAllocError::Layout(l) => format!("layout {l}"),
                    })
                }));
                match r {
                    Ok(v) => format!("{:?}", v),
                    Err(_) => "panic".to_string(),
                }
            }

            /// Requests whose size cannot be rounded up to the backend's alignment in a `usize`.
            pub fn unalignable() -> Vec<String> {
                [usize::MAX - 6, usize::MAX - 3]
                    .iter()
                    .map(|&size| request(size))
                    .collect()
            }

            /// Requests past `isize::MAX` once rounded up, and the largest that is not.
            pub const HUGE: [usize; 3] = [isize::MAX as usize - 7, isize::MAX as usize, usize::MAX - 7];
        }
    };
}

provider_cases!(up, up_shm, up_core, up_buffers);
provider_cases!(wz, wz_shm, wz_core, wz_buffers);

#[test]
fn both_crates_allocate_free_collect_and_defragment_alike_on_every_backend() {
    let _g = serial();
    let (a, b) = (up::providers(), wz::providers());
    assert_eq!(a, b);
    assert_eq!(a.len(), 52, "{a:?}");
    assert!(
        a.iter()
            .any(|l| l.starts_with("heap: after gc alloc 250 ok")),
        "{a:?}"
    );
    assert!(
        a.iter()
            .any(|l| l.starts_with("talc: alloc 100 ok len=100 first=100")),
        "{a:?}"
    );
    // 5000 does not fit 4096 in any of them
    assert_eq!(
        a.iter().filter(|l| l.contains("alloc 5000 err")).count(),
        4,
        "{a:?}"
    );
}

#[test]
fn both_crates_describe_the_backends_alike() {
    let _g = serial();
    let (a, b) = (up::backends(), wz::backends());
    assert_eq!(a, b);
    assert_eq!(a.len(), 23);
    assert!(a.iter().any(|l| l == "ids 0 0 0 0"), "{a:?}");
}

#[test]
fn both_crates_apply_the_allocation_policies_alike() {
    let _g = serial();
    let (a, b) = (up::policies(), wz::policies());
    assert_eq!(a, b);
    assert_eq!(a.len(), 12, "{a:?}");
    // After a collection the free memory is two holes of 1000 beside each other: a plain
    // allocation says the memory needs defragmenting and the defragmenting policy joins them.
    assert_eq!(
        a[0],
        "collected just collected 1000: err need defragmentation"
    );
    assert_eq!(a[1], "collected defragment collected 1000: ok len=2000");
    // Without the collection the backend has not been given the memory back.
    assert_eq!(a[2], "just err out of memory");
    assert_eq!(a[11], "block on ok len=3500");
    // The policy that deallocates what is busy ends on the error of the backend.
    assert_eq!(a[9], "deallocate err need defragmentation");
}

#[test]
fn both_crates_precompute_and_type_layouts_alike() {
    let _g = serial();
    let (a, b) = (up::layouts(), wz::layouts());
    assert_eq!(a, b);
    assert!(a.len() >= 8, "{a:?}");
    assert!(
        a.iter().any(|l| l.starts_with("aligned Ok((0, 64))")),
        "{a:?}"
    );
}

#[test]
fn both_crates_allocate_asynchronously_alike() {
    let _g = serial();
    let (a, b) = (up::async_alloc(), wz::async_alloc());
    assert_eq!(a, b);
    assert_eq!(a, ["async ok len=100", "async block on ok len=3000"]);
}

/// A buffer allocated by the provider of one crate is read by the reader of the other, with the
/// bytes the provider wrote.
#[test]
fn a_buffer_allocated_by_one_crate_is_read_by_the_other_in_both_directions() {
    let _g = serial();
    macro_rules! across {
        ($prov:ident, $read:ident) => {{
            let provided = $prov::provide(&[1usize, 64, 1000, 4097]);
            for p in &provided {
                assert_eq!($read::read(p.parts), Ok(p.bytes.clone()), "{:?}", p.parts);
            }
            // the same buffer through the crate that provided it
            for p in &provided {
                assert_eq!($prov::read(p.parts), Ok(p.bytes.clone()));
            }
        }};
    }
    across!(up, wz);
    across!(wz, up);
}

#[test]
fn the_binary_heap_keeps_the_chunk_it_popped_in_wz_only() {
    let _g = serial();
    let (u, w) = (up::heap_loses_the_chunk(), wz::heap_loses_the_chunk());
    assert_eq!(u[..2], w[..2]);
    assert_eq!(u[0], "first Ok(3072)");
    assert_eq!(u[1], "too big Err(\"OutOfMemory\")");
    // upstream lost the chunk of 1024: there is nothing to give, which its test build says by
    // panicking; wz put it back
    assert_eq!(u[2], "fits panic", "{u:?}");
    assert_eq!(w[2], "fits Ok(1024)", "{w:?}");
    // what is available: after the chunk of 3072 is taken, 1024 are; upstream lost one chunk, but
    // keeps the count; after the chunk is given back all 4096 are
    assert_eq!(u[3], "available 1024");
    assert_eq!(w[3], "available 0", "{w:?}");
    assert_eq!(u[4], "free panic", "{u:?}");
    assert_eq!(w[4], "free ok", "{w:?}");
    // `free` raises the count before it takes the lock, so upstream's count rises even though the
    // chunk never reaches its list.
    assert_eq!(u[5], "available after free 4096", "{u:?}");
    // wz handed out the chunk of 1024 that upstream lost, so its count was 0 and is 3072 now.
    assert_eq!(w[5], "available after free 3072", "{w:?}");
}

/// What a chunk given back does to the room of a binary heap, the same in both crates: the count
/// of the bytes available falls by what is taken and rises by what is given back.
#[test]
fn the_bytes_available_of_a_binary_heap_follow_what_is_taken_and_given_back() {
    let _g = serial();
    let (u, w) = (up::heap_available(), wz::heap_available());
    assert_eq!(u, w);
    assert_eq!(u, ["4096", "3072", "2048", "3072", "4096"]);
}

#[test]
fn a_chunk_mapped_with_a_length_past_its_own_is_refused_by_wz_only() {
    let _g = serial();
    let (u, w) = (up::map_long(), wz::map_long());
    assert_eq!(u, ["64: ok len=64", "65: ok len=65", "128: ok len=128"]);
    assert_eq!(w[0], "64: ok len=64");
    assert!(w[1].starts_with("65: err"), "{w:?}");
    assert!(w[2].starts_with("128: err"), "{w:?}");
}

#[test]
fn a_request_that_cannot_be_aligned_is_refused_by_wz_only() {
    let _g = serial();
    let (u, w) = (up::unalignable(), wz::unalignable());
    // Upstream panics and wz answers with the layout error.
    assert_eq!(u, ["panic", "panic"]);
    assert!(w[0].starts_with("Err(\"layout "), "{w:?}");
    assert!(w[1].starts_with("Err(\"layout "), "{w:?}");
}

/// A size that rounds up past `isize::MAX` is no layout: upstream's backend builds one unchecked,
/// which aborts the process in a build with debug assertions (so that side runs in a child
/// process), and wz answers out of memory. The largest size below it is answered alike.
#[test]
fn a_request_past_isize_max_is_refused_by_wz_only() {
    let _g = serial();
    // the largest size that is a layout: both say out of memory
    let (u, w) = (up::request(up::HUGE[0]), wz::request(wz::HUGE[0]));
    assert_eq!(u, w);
    assert_eq!(u, "Err(\"alloc out of memory\")");
    for (i, size) in wz::HUGE.iter().enumerate().skip(1) {
        let w = wz::request(*size);
        assert_eq!(w, "Err(\"alloc out of memory\")", "{size}");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["upstream_huge_request_in_a_child", "--exact", "--nocapture"])
            .env("ZSHM_HUGE", i.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "{size}: {status:?}");
    }
}

/// The child of the test above: it makes the request through upstream, and does nothing when it is
/// run as one of the tests.
#[test]
fn upstream_huge_request_in_a_child() {
    let Ok(i) = std::env::var("ZSHM_HUGE") else {
        return;
    };
    let _g = serial();
    println!("{}", up::request(up::HUGE[i.parse::<usize>().unwrap()]));
}

/// The control: the comparison is on text, so a provider that allocates differently gives lines
/// that differ.
#[test]
fn the_comparison_sees_a_provider_that_differs() {
    let _g = serial();
    let a = wz::providers();
    let mut b = wz::providers();
    assert_eq!(a, b);
    b.pop();
    assert_ne!(a, b);
    assert_ne!(wz::policies(), wz::layouts());
}
