// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, the `handlers` module (the fourth part of the top crate): upstream's crate
//! (`up_zenoh`) and wz's (`wz_zenoh`) given the same sequences of operations on the channels and
//! the callbacks, results equal as text.
//!
//! * the FIFO channel: its capacity (given, and the default), what a handler says of an empty
//!   channel, a channel with items and a full one, its three kinds of wait on an empty channel
//!   (`recv_timeout`, `recv_deadline`, `try_recv`), the iterators (`iter`, `try_iter`, `drain`, the
//!   two `IntoIterator`s), the counts, a clone of the handler, and what every method says once the
//!   callback is gone;
//! * the same through a future and a stream (`recv_async`, `into_recv_async`, `stream`,
//!   `into_stream`), including `is_terminated` before and after, and a value that arrives while
//!   it waits;
//! * the ring channel: the oldest items dropped when it is full, the same waits, the receive that
//!   blocks until another thread pushes, the receive after the callback is gone (the ring has been
//!   deleted), and its default capacity;
//! * the callback: calls counted, a clone, its text, `Callback::new`, the `IntoHandler` of a
//!   callback, of a pair with a closure, of a pair with a callback, of a flume pair and of a
//!   standard channel pair (with the receiver dropped), `CallbackDrop` and when its drop runs,
//!   `locked`, and `set_on_drop` with clones;
//! * the default handler: its capacity and its text;
//! * pushes from four threads into each kind of channel.
//!
//! No difference from upstream was seen.

use std::{
    cell::Cell,
    fmt::Debug,
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex, Once,
    },
    time::{Duration, Instant},
};

use futures::{future::FusedFuture, StreamExt};

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// What a call that may panic made, as text, without the report of the panic. The hook is set once
/// and speaks for every thread but the one inside a call.
fn caught(f: impl FnOnce() -> String) -> String {
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
    let r = catch_unwind(AssertUnwindSafe(f));
    QUIET.with(|q| q.set(false));
    match r {
        Ok(v) => v,
        Err(p) => format!(
            "PANIC {}",
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        ),
    }
}

/// An error as text without the places of the crates that made it.
fn plain(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(j) = rest.find(".rs:") {
        match rest[..j].rfind(" at ") {
            Some(i) => {
                out.push_str(&rest[..i]);
                let after = &rest[j + 4..];
                let digits = after.chars().take_while(char::is_ascii_digit).count();
                rest = &after[digits..];
            }
            None => {
                out.push_str(&rest[..j + 4]);
                rest = &rest[j + 4..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// A result of the family's kind as text.
fn text<T: Debug>(r: Result<T, Box<dyn std::error::Error + Send + Sync>>) -> String {
    match r {
        Ok(v) => format!("Ok({v:?})"),
        Err(e) => format!("Err({})", plain(&e.to_string())),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

macro_rules! handler_cases {
    ($name:ident, $z:ident) => {
        mod $name {
            use super::*;
            use $z::handlers::{
                Callback, CallbackDrop, DefaultHandler, FifoChannel, FifoChannelHandler, IntoHandler,
                RingChannel, RingChannelHandler,
            };

            fn fifo(capacity: usize) -> (Callback<u32>, FifoChannelHandler<u32>) {
                FifoChannel::new(capacity).into_handler()
            }

            fn ring(capacity: usize) -> (Callback<u32>, RingChannelHandler<u32>) {
                RingChannel::new(capacity).into_handler()
            }

            pub fn fifo_basics() -> Vec<String> {
                let mut out = vec![];
                out.push(format!("channel: {:?}", FifoChannel::new(7)));
                let (default_cb, default_h): (Callback<u32>, FifoChannelHandler<u32>) =
                    FifoChannel::default().into_handler();
                out.push(format!("default capacity: {:?}", default_h.capacity()));
                drop(default_cb);
                let (cb, h) = fifo(3);
                out.push(format!("handler: {h:?}"));
                out.push(format!("capacity: {:?}", h.capacity()));
                out.push(format!("empty try_recv: {}", text(h.try_recv())));
                out.push(format!("empty recv_timeout: {}", text(h.recv_timeout(Duration::from_millis(20)))));
                out.push(format!("empty recv_deadline: {}", text(h.recv_deadline(Instant::now()))));
                out.push(format!(
                    "empty: len={} is_empty={} is_full={} senders={} receivers={}",
                    h.len(), h.is_empty(), h.is_full(), h.sender_count(), h.receiver_count()
                ));
                cb.call(1);
                cb.call(2);
                let twin = h.clone();
                out.push(format!(
                    "two in: len={} is_empty={} is_full={} receivers={} same_channel={}",
                    h.len(), h.is_empty(), h.is_full(), h.receiver_count(), h.same_channel(&twin)
                ));
                let (_other_cb, other) = fifo(3);
                out.push(format!("same_channel with another: {}", h.same_channel(&other)));
                cb.call(3);
                out.push(format!("full: len={} is_full={}", h.len(), h.is_full()));
                out.push(format!("try_recv: {}", text(h.try_recv())));
                out.push(format!("recv: {}", text(h.recv())));
                out.push(format!("recv_timeout: {}", text(h.recv_timeout(Duration::from_millis(20)))));
                out.push(format!("twin sees: len={}", twin.len()));
                out.push(format!("try_iter: {:?}", h.try_iter().collect::<Vec<_>>()));
                for i in 10..13 {
                    cb.call(i);
                }
                let drained = h.drain();
                out.push(format!("drain len: {}", drained.len()));
                out.push(format!("drain: {:?}", drained.collect::<Vec<_>>()));
                out.push(format!("after drain: len={}", h.len()));
                for i in 20..23 {
                    cb.call(i);
                }
                let by_ref: Vec<u32> = (&h).into_iter().take(2).collect();
                out.push(format!("by reference, two: {by_ref:?}"));
                out.push(format!("iter, one more: {:?}", h.iter().take(1).collect::<Vec<_>>()));
                drop(cb);
                out.push(format!("callback gone: is_disconnected={} senders={}", h.is_disconnected(), h.sender_count()));
                out.push(format!("owned iter: {:?}", twin.into_iter().collect::<Vec<_>>()));
                out.push(format!("recv: {}", text(h.recv())));
                out.push(format!("try_recv: {}", text(h.try_recv())));
                out.push(format!("recv_timeout: {}", text(h.recv_timeout(Duration::from_millis(20)))));
                out.push(format!("recv_deadline: {}", text(h.recv_deadline(Instant::now() + Duration::from_millis(20)))));
                out.push(format!("iter count: {}", h.iter().count()));
                out.push(format!("try_iter count: {}", h.try_iter().count()));
                out
            }

            pub fn fifo_async() -> Vec<String> {
                let rt = runtime();
                rt.block_on(async {
                    let mut out = vec![];
                    let (cb, h) = fifo(4);
                    cb.call(1);
                    out.push(format!("recv_async: {}", text(h.recv_async().await)));
                    let fut = h.recv_async();
                    out.push(format!("fresh future terminated: {}", fut.is_terminated()));
                    cb.call(2);
                    let mut fut = fut;
                    out.push(format!("polled: {}", text((&mut fut).await)));
                    out.push(format!("terminated after: {}", fut.is_terminated()));
                    cb.call(3);
                    out.push(format!("into_recv_async: {}", text(h.clone().into_recv_async().await)));
                    let tx = cb.clone();
                    let waiting = tokio::spawn({
                        let h = h.clone();
                        async move { text(h.recv_async().await) }
                    });
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    tx.call(4);
                    out.push(format!("arrived while waiting: {}", waiting.await.unwrap()));
                    for i in 5..8 {
                        cb.call(i);
                    }
                    let mut stream = h.stream();
                    out.push(format!(
                        "stream: len={} capacity={:?} empty={} full={}",
                        stream.len(), stream.capacity(), stream.is_empty(), stream.is_full()
                    ));
                    out.push(format!("stream next: {:?} {:?}", stream.next().await, stream.next().await));
                    out.push(format!(
                        "stream same_channel with its clone: {}",
                        stream.same_channel(&stream.clone())
                    ));
                    out.push(format!("stream disconnected: {}", stream.is_disconnected()));
                    drop(stream);
                    let mut owned = h.clone().into_stream();
                    out.push(format!("into_stream next: {:?}", owned.next().await));
                    drop(owned);
                    drop(cb);
                    drop(tx);
                    out.push(format!("stream terminated while an item waits: {}", futures::stream::FusedStream::is_terminated(&h.stream())));
                    out.push(format!("last item by future: {}", text(h.recv_async().await)));
                    out.push(format!("future on a closed channel: {}", text(h.recv_async().await)));
                    let mut s = h.stream();
                    out.push(format!("stream on a closed channel: {:?}", s.next().await));
                    out.push(format!("stream terminated: {}", futures::stream::FusedStream::is_terminated(&s)));
                    out
                })
            }

            pub fn ring_channel() -> Vec<String> {
                let mut out = vec![];
                out.push(format!("channel: {:?}", RingChannel::new(7)));
                let (cb, h) = ring(3);
                out.push(format!("handler: {h:?}"));
                out.push(format!("empty try_recv: {}", text(h.try_recv())));
                out.push(format!("empty recv_timeout: {}", text(h.recv_timeout(Duration::from_millis(20)))));
                out.push(format!("empty recv_deadline: {}", text(h.recv_deadline(Instant::now()))));
                for i in 1..=5 {
                    cb.call(i);
                }
                let mut got = vec![];
                loop {
                    match h.try_recv() {
                        Ok(Some(v)) => got.push(v),
                        other => {
                            out.push(format!("ended with: {}", text(other)));
                            break;
                        }
                    }
                }
                out.push(format!("five pushed into three: {got:?}"));
                cb.call(7);
                out.push(format!("recv: {}", text(h.recv())));
                cb.call(8);
                out.push(format!("recv_deadline: {}", text(h.recv_deadline(Instant::now() + Duration::from_millis(50)))));
                cb.call(9);
                out.push(format!("recv_timeout: {}", text(h.recv_timeout(Duration::from_millis(50)))));
                let pusher = {
                    let cb = cb.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(40));
                        cb.call(11);
                    })
                };
                out.push(format!("recv blocks until a push: {}", text(h.recv())));
                pusher.join().unwrap();
                let pusher = {
                    let cb = cb.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(40));
                        cb.call(12);
                    })
                };
                out.push(format!(
                    "recv_timeout that is long enough: {}",
                    text(h.recv_timeout(Duration::from_secs(5)))
                ));
                pusher.join().unwrap();
                let rt = runtime();
                let pusher = {
                    let cb = cb.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(40));
                        cb.call(13);
                    })
                };
                out.push(format!("recv_async: {}", text(rt.block_on(h.recv_async()))));
                pusher.join().unwrap();
                cb.call(14);
                drop(cb);
                out.push(format!("callback gone, an item left: try_recv {}", text(h.try_recv())));
                out.push(format!("recv: {}", text(h.recv())));
                out.push(format!("recv_deadline: {}", text(h.recv_deadline(Instant::now() + Duration::from_millis(20)))));
                out.push(format!("recv_timeout: {}", text(h.recv_timeout(Duration::from_millis(20)))));
                out.push(format!("recv_async: {}", text(rt.block_on(h.recv_async()))));
                let (cb, h) = RingChannel::default().into_handler();
                let cb: Callback<u32> = cb;
                for i in 0..300 {
                    cb.call(i);
                }
                let mut n = 0;
                let mut first = None;
                while let Ok(Some(v)) = h.try_recv() {
                    first.get_or_insert(v);
                    n += 1;
                }
                out.push(format!("default capacity keeps: {n} from {first:?}"));
                out
            }

            pub fn callbacks() -> Vec<String> {
                let mut out = vec![];
                let sum = Arc::new(AtomicUsize::new(0));
                let cb = {
                    let sum = sum.clone();
                    Callback::from(move |x: u32| {
                        sum.fetch_add(x as usize, Ordering::SeqCst);
                    })
                };
                cb.call(2);
                let twin = cb.clone();
                twin.call(3);
                out.push(format!("calls: {} {cb:?}", sum.load(Ordering::SeqCst)));
                let by_new = {
                    let sum = sum.clone();
                    Callback::new(Arc::new(move |x: u32| {
                        sum.fetch_add(10 * x as usize, Ordering::SeqCst);
                    }))
                };
                by_new.call(1);
                out.push(format!("Callback::new: {}", sum.load(Ordering::SeqCst)));
                let (c, handler): (Callback<u32>, ()) = cb.into_handler();
                c.call(1);
                out.push(format!("into_handler of a callback: {handler:?} {}", sum.load(Ordering::SeqCst)));
                let (c, handler) = ({ let sum = sum.clone(); move |x: u32| { sum.fetch_add(100 * x as usize, Ordering::SeqCst); } }, 5u8).into_handler();
                let c: Callback<u32> = c;
                c.call(1);
                out.push(format!("pair with a closure: handler {handler} {}", sum.load(Ordering::SeqCst)));
                let (c, handler) = (twin, "kept").into_handler();
                let c: Callback<u32> = c;
                c.call(1);
                out.push(format!("pair with a callback: handler {handler} {}", sum.load(Ordering::SeqCst)));

                let (tx, rx) = flume::bounded::<u32>(2);
                let (c, rx): (Callback<u32>, flume::Receiver<u32>) = (tx, rx).into_handler();
                c.call(1);
                c.call(2);
                out.push(format!("flume pair: {:?}", rx.try_iter().collect::<Vec<_>>()));
                drop(rx);
                c.call(3);
                out.push("flume pair with the receiver dropped: no panic".to_string());

                let (tx, rx) = mpsc::sync_channel::<u32>(4);
                let (c, rx): (Callback<u32>, mpsc::Receiver<u32>) = (tx, rx).into_handler();
                c.call(7);
                c.call(8);
                out.push(format!("standard pair: {:?} {:?}", rx.try_recv(), rx.try_recv()));
                drop(rx);
                c.call(9);
                out.push("standard pair with the receiver dropped: no panic".to_string());

                let drops = Arc::new(AtomicUsize::new(0));
                let seen = Arc::new(AtomicUsize::new(0));
                let cd = {
                    let (drops, seen) = (drops.clone(), seen.clone());
                    CallbackDrop {
                        callback: move |x: u32| {
                            seen.fetch_add(x as usize, Ordering::SeqCst);
                        },
                        drop: move || {
                            drops.fetch_add(1, Ordering::SeqCst);
                        },
                    }
                };
                out.push(format!("callback drop text: {cd:?}"));
                let (c, handler): (Callback<u32>, ()) = cd.into_handler();
                c.call(1);
                out.push(format!(
                    "callback drop built: handler {handler:?} seen {} dropped {}",
                    seen.load(Ordering::SeqCst), drops.load(Ordering::SeqCst)
                ));
                let c2 = c.clone();
                drop(c);
                out.push(format!("one clone dropped: dropped {}", drops.load(Ordering::SeqCst)));
                c2.call(2);
                drop(c2);
                out.push(format!(
                    "all dropped: seen {} dropped {}",
                    seen.load(Ordering::SeqCst), drops.load(Ordering::SeqCst)
                ));
                let direct = {
                    let drops = drops.clone();
                    CallbackDrop { callback: |_: u32| {}, drop: move || { drops.fetch_add(1, Ordering::SeqCst); } }
                };
                drop(direct);
                out.push(format!("a callback drop dropped by hand: dropped {}", drops.load(Ordering::SeqCst)));

                let acc = Arc::new(Mutex::new(Vec::new()));
                let locked = {
                    let acc = acc.clone();
                    $z::handlers::locked(move |x: u32| acc.lock().unwrap().push(x))
                };
                for i in 0..3 {
                    locked(i);
                }
                out.push(format!("locked: {:?}", acc.lock().unwrap()));

                let on_drop = Arc::new(AtomicUsize::new(0));
                let mut cb: Callback<u32> = Callback::from(|_: u32| {});
                {
                    let on_drop = on_drop.clone();
                    cb.set_on_drop(move || {
                        on_drop.fetch_add(1, Ordering::SeqCst);
                    });
                }
                let clone = cb.clone();
                drop(cb);
                out.push(format!("set_on_drop, one clone left: {}", on_drop.load(Ordering::SeqCst)));
                drop(clone);
                out.push(format!("set_on_drop, none left: {}", on_drop.load(Ordering::SeqCst)));
                out
            }

            pub fn default_handler() -> Vec<String> {
                let mut out = vec![];
                out.push(format!("text: {:?}", DefaultHandler::default()));
                let (cb, h): (Callback<u8>, FifoChannelHandler<u8>) = DefaultHandler::default().into_handler();
                out.push(format!("capacity: {:?}", h.capacity()));
                cb.call(1);
                cb.call(2);
                out.push(format!("two in: {} {:?}", h.len(), h.try_iter().collect::<Vec<_>>()));
                out.push(format!("handler: {h:?}"));
                out
            }

            pub fn from_threads() -> Vec<String> {
                let mut out = vec![];
                let (cb, h) = fifo(128);
                let hs: Vec<_> = (0..4u32)
                    .map(|t| {
                        let cb = cb.clone();
                        std::thread::spawn(move || {
                            for i in 0..25 {
                                cb.call(t * 100 + i);
                            }
                        })
                    })
                    .collect();
                for j in hs {
                    j.join().unwrap();
                }
                drop(cb);
                let got: Vec<u32> = h.iter().collect();
                let mut in_order = true;
                for t in 0..4u32 {
                    let mine: Vec<u32> = got.iter().copied().filter(|v| v / 100 == t).collect();
                    in_order &= mine == (0..25).map(|i| t * 100 + i).collect::<Vec<_>>();
                }
                out.push(format!("fifo: {} items, each thread in order: {in_order}", got.len()));

                let (cb, h) = ring(10);
                let hs: Vec<_> = (0..4u32)
                    .map(|t| {
                        let cb = cb.clone();
                        std::thread::spawn(move || {
                            for i in 0..25 {
                                cb.call(t * 100 + i);
                            }
                        })
                    })
                    .collect();
                for j in hs {
                    j.join().unwrap();
                }
                let mut kept = vec![];
                while let Ok(Some(v)) = h.try_recv() {
                    kept.push(v);
                }
                out.push(format!("ring of ten: {} items kept", kept.len()));
                let mut ordered = true;
                for t in 0..4u32 {
                    let mine: Vec<u32> = kept.iter().copied().filter(|v| v / 100 == t).collect();
                    ordered &= mine.windows(2).all(|w| w[0] < w[1]);
                }
                out.push(format!("ring: each thread's items still in order: {ordered}"));
                out
            }
        }
    };
}

handler_cases!(up, up_zenoh);
handler_cases!(wz, wz_zenoh);

fn compare(group: &str, up: &[String], wz: &[String]) {
    assert!(up.len() > 2, "{group} holds {} line(s)", up.len());
    assert_eq!(up.len(), wz.len(), "{group}: the groups differ in length");
    if let Some((x, y)) = up.iter().zip(wz).find(|(x, y)| x != y) {
        panic!("{group}\nupstream: {x}\nwz:       {y}");
    }
    if std::env::var_os("WZ_HANDLERS_TRANSCRIPT").is_some() {
        for line in up {
            println!("{group}: {line}");
        }
    }
}

#[test]
fn the_fifo_channel_and_its_handler() {
    let (u, w) = (up::fifo_basics(), wz::fifo_basics());
    assert!(u.iter().any(|l| l.starts_with("callback gone: is_disconnected=true")), "{u:#?}");
    compare("fifo", &u, &w);
}

#[test]
fn the_fifo_channel_through_a_future_and_a_stream() {
    let (u, w) = (up::fifo_async(), wz::fifo_async());
    assert!(u.iter().any(|l| l.starts_with("arrived while waiting: Ok(4)")), "{u:#?}");
    compare("fifo async", &u, &w);
}

#[test]
fn the_ring_channel_drops_the_oldest() {
    let (u, w) = (up::ring_channel(), wz::ring_channel());
    assert!(u.iter().any(|l| l == "five pushed into three: [3, 4, 5]"), "{u:#?}");
    compare("ring", &u, &w);
}

#[test]
fn the_callback_and_what_becomes_a_handler() {
    let (u, w) = (up::callbacks(), wz::callbacks());
    assert!(u.iter().any(|l| l.starts_with("all dropped: seen 3 dropped 1")), "{u:#?}");
    compare("callbacks", &u, &w);
}

#[test]
fn the_default_handler() {
    let (u, w) = (up::default_handler(), wz::default_handler());
    assert!(u.iter().any(|l| l == "capacity: Some(256)"), "{u:#?}");
    compare("default handler", &u, &w);
}

#[test]
fn pushes_from_several_threads() {
    let (u, w) = (up::from_threads(), wz::from_threads());
    assert_eq!(u[0], "fifo: 100 items, each thread in order: true");
    compare("threads", &u, &w);
}

#[test]
fn the_comparison_sees_a_handler_that_differs() {
    let u = up::default_handler();
    let mut w = wz::default_handler();
    w[1] = format!("{} changed", w[1]);
    assert!(u.iter().zip(&w).any(|(x, y)| x != y));
    assert_ne!(up::default_handler(), up::fifo_basics());
}
