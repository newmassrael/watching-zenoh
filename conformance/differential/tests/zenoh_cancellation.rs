// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, the `cancellation` module (the second part of the top crate, the `unstable` arm):
//! upstream's crate (`up_zenoh`) and wz's (`wz_zenoh`) given the same sequences of operations on a
//! `CancellationToken` and on the `SyncGroup` under it, results equal as text.
//!
//! * a token that is new, cancelled with no handler, cancelled twice, cloned (the clone sees what
//!   the original did), its text before and after;
//! * handlers: the ids they are given, one that is removed, ones that run (counted, since the
//!   order a map of them runs in is not part of the contract), one that fails (the text of the
//!   error of the first cancel and of the second), a handler added after the cancel (it comes back
//!   to the caller) and one removed after it;
//! * the notifier of the token: one held keeps the cancel waiting, and it is released when the
//!   notifier is dropped; after the cancel there is none to take;
//! * the same cancel in the three ways it can be asked: `wait`, `.await`, and from inside a
//!   runtime (a runtime of several threads, and one of a single thread, where the blocking
//!   resolution is refused or not by the runtime of the family);
//! * the `SyncGroup` itself (the `internal` arm): its text, its notifiers, its wait and its close.
//!
//! No difference from upstream was seen.

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};

/// What a call that may panic made, as text, without the report of the panic.
fn caught<T: std::fmt::Debug>(f: impl FnOnce() -> T) -> String {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    match r {
        Ok(v) => format!("{v:?}"),
        Err(p) => format!(
            "PANIC {}",
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        ),
    }
}

/// An error as text without the place of the crate that made it.
fn plain(s: &str) -> String {
    s.split(" at ").next().unwrap_or("").to_string()
}

macro_rules! cancel_cases {
    ($name:ident, $z:ident, $core:ident) => {
        mod $name {
            use super::*;
            use $core::Wait;
            use $z::cancellation::{CancellationToken, SyncGroup};

            type Res = Result<(), Box<dyn std::error::Error + Send + Sync>>;

            fn result_text(r: Res) -> String {
                match r {
                    Ok(()) => "Ok".to_string(),
                    Err(e) => format!("Err({})", plain(&e.to_string())),
                }
            }

            pub fn plain_token() -> Vec<String> {
                let mut out = vec![];
                let t = CancellationToken::default();
                out.push(format!("new: {t:?} cancelled={}", t.is_cancelled()));
                let c = t.clone();
                out.push(format!("clone: {c:?} cancelled={}", c.is_cancelled()));
                out.push(format!("first cancel: {}", result_text(t.cancel().wait())));
                out.push(format!(
                    "after: {t:?} cancelled={} clone cancelled={}",
                    t.is_cancelled(),
                    c.is_cancelled()
                ));
                out.push(format!("second cancel: {}", result_text(t.cancel().wait())));
                out.push(format!("cancel by the clone: {}", result_text(c.cancel().wait())));
                out.push(format!("result text: {:?}", t.cancel()));
                out.push(format!("default result: {:?}", $z::cancellation::CancellationToken::default().cancel()));
                out
            }

            pub fn handlers() -> Vec<String> {
                let mut out = vec![];
                let t = CancellationToken::default();
                let ran = Arc::new(AtomicUsize::new(0));
                let mut ids = vec![];
                for _ in 0..5 {
                    let ran = ran.clone();
                    let id = t.add_on_cancel_handler(move || -> Res {
                        ran.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    });
                    ids.push(id.map_err(|_| "refused"));
                }
                out.push(format!("ids: {ids:?}"));
                out.push(format!("text with handlers: {t:?}"));
                out.push(format!("remove 2: {}", t.remove_on_cancel_handler(2)));
                out.push(format!("remove 2 again: {}", t.remove_on_cancel_handler(2)));
                out.push(format!("remove 99: {}", t.remove_on_cancel_handler(99)));
                out.push(format!("text after removal: {t:?}"));
                out.push(format!("cancel: {}", result_text(t.cancel().wait())));
                out.push(format!("handlers that ran: {}", ran.load(Ordering::SeqCst)));
                out.push(format!("text after: {t:?}"));
                let late = t.add_on_cancel_handler(|| -> Res { Ok(()) });
                out.push(format!("late add: {}", if late.is_ok() { "accepted" } else { "handed back" }));
                out.push(format!("remove after: {}", t.remove_on_cancel_handler(0)));
                out
            }

            pub fn a_failing_handler() -> Vec<String> {
                let mut out = vec![];
                let t = CancellationToken::default();
                let _ = t.add_on_cancel_handler(|| -> Res { Err("boom".into()) });
                out.push(format!("first cancel: {}", result_text(t.cancel().wait())));
                out.push(format!("cancelled: {}", t.is_cancelled()));
                out.push(format!("second cancel: {}", result_text(t.cancel().wait())));
                let clone = t.clone();
                out.push(format!("clone cancel: {}", result_text(clone.cancel().wait())));
                out.push(format!("text: {t:?}"));
                // a failing handler among the others: the cancel fails, whichever ran before it
                let t = CancellationToken::default();
                let _ = t.add_on_cancel_handler(|| -> Res { Err("first".into()) });
                let _ = t.add_on_cancel_handler(|| -> Res { Err("first".into()) });
                out.push(format!("two failing: {}", result_text(t.cancel().wait())));
                // a failed cancel does not wait for a notifier that is still held: it closes the group
                let t = CancellationToken::default();
                let held = t.notifier();
                let _ = t.add_on_cancel_handler(|| -> Res { Err("held".into()) });
                let (tx, rx) = mpsc::channel();
                let c = t.clone();
                let h = std::thread::spawn(move || tx.send(result_text(c.cancel().wait())).unwrap());
                out.push(format!("failed cancel with a notifier held: {:?}", rx.recv_timeout(Duration::from_millis(500))));
                out.push(format!("notifier after a failed cancel: {}", t.notifier().is_some()));
                // released before the join, so that a cancel that waits ends and the test fails by its text
                drop(held);
                h.join().unwrap();
                let t = CancellationToken::default();
                let held = t.notifier();
                let _ = t.add_on_cancel_handler(|| -> Res { Err("held".into()) });
                let multi = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                let c = t.clone();
                out.push(format!(
                    "failed cancel awaited with a notifier held: {:?}",
                    multi.block_on(async move {
                        tokio::time::timeout(Duration::from_millis(500), async move { result_text(c.cancel().await) }).await.map_err(|_| "waited")
                    })
                ));
                drop(held);
                out
            }

            /// A notifier held keeps a cancel waiting; the cancel ends when it is dropped.
            pub fn the_notifier() -> Vec<String> {
                let mut out = vec![];
                let t = CancellationToken::default();
                let n1 = t.notifier();
                let n2 = t.notifier();
                out.push(format!("two notifiers: {} {}", n1.is_some(), n2.is_some()));
                let (tx, rx) = mpsc::channel();
                let c = t.clone();
                let h = std::thread::spawn(move || {
                    let r = result_text(c.cancel().wait());
                    tx.send(r).unwrap();
                });
                std::thread::sleep(Duration::from_millis(200));
                out.push(format!("cancel finished while held: {}", rx.try_recv().is_ok()));
                drop(n1);
                std::thread::sleep(Duration::from_millis(100));
                out.push(format!("cancel finished with one held: {}", rx.try_recv().is_ok()));
                drop(n2);
                let r = rx.recv_timeout(Duration::from_secs(5));
                out.push(format!("cancel finished once none is held: {r:?}"));
                h.join().unwrap();
                out.push(format!("notifier after the cancel: {}", t.notifier().is_some()));
                out
            }

            /// The same cancel asked from a runtime.
            pub fn from_a_runtime() -> Vec<String> {
                let mut out = vec![];
                let multi = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                let t = CancellationToken::default();
                let _ = t.add_on_cancel_handler(|| -> Res { Ok(()) });
                let c = t.clone();
                out.push(format!(
                    "multi thread, wait: {}",
                    caught(|| multi.block_on(async move { tokio::spawn(async move { result_text(c.cancel().wait()) }).await.unwrap() }))
                ));
                let t2 = CancellationToken::default();
                let c2 = t2.clone();
                out.push(format!(
                    "multi thread, await: {}",
                    caught(|| multi.block_on(async move { result_text(c2.cancel().await) }))
                ));
                let single = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
                let t3 = CancellationToken::default();
                let c3 = t3.clone();
                out.push(format!(
                    "single thread, wait: {}",
                    caught(|| single.block_on(async move { result_text(c3.cancel().wait()) }))
                ));
                let t4 = CancellationToken::default();
                let c4 = t4.clone();
                out.push(format!(
                    "single thread, await: {}",
                    caught(|| single.block_on(async move { result_text(c4.cancel().await) }))
                ));
                let t5 = CancellationToken::default();
                let held = t5.notifier();
                let c5 = t5.clone();
                out.push(format!(
                    "await with a notifier held, released by a task: {}",
                    caught(|| multi.block_on(async move {
                        let release = tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            drop(held);
                        });
                        let r = result_text(c5.cancel().await);
                        release.await.unwrap();
                        r
                    }))
                ));
                out
            }

            /// The group under a token, which the `internal` arm opens.
            pub fn the_sync_group() -> Vec<String> {
                let mut out = vec![];
                let g = SyncGroup::default();
                out.push(format!("new: {g:?}"));
                let n1 = g.notifier();
                let n2 = g.notifier();
                out.push(format!("two notifiers: {} {} {g:?}", n1.is_some(), n2.is_some()));
                out.push(format!("notifier text: {:?}", n1.as_ref().map(|n| format!("{n:?}").len() > 0)));
                drop(n1);
                out.push(format!("one dropped: {g:?}"));
                let g2 = g.clone();
                let (tx, rx) = mpsc::channel();
                let h = std::thread::spawn(move || {
                    g2.wait();
                    tx.send(()).unwrap();
                });
                std::thread::sleep(Duration::from_millis(150));
                out.push(format!("wait finished while one is held: {}", rx.try_recv().is_ok()));
                drop(n2);
                out.push(format!("wait finished when none is held: {}", rx.recv_timeout(Duration::from_secs(5)).is_ok()));
                h.join().unwrap();
                out.push(format!("notifier after the wait: {}", g.notifier().is_some()));
                out.push(format!("text after: {g:?}"));
                let g3 = SyncGroup::default();
                let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                out.push(format!(
                    "async wait of an empty group: {:?}",
                    caught(|| rt.block_on(async { g3.wait_async().await }))
                ));
                out.push(format!("notifier after the async wait: {}", g3.notifier().is_some()));
                out
            }
        }
    };
}

cancel_cases!(up, up_zenoh, up_core);
cancel_cases!(wz, wz_zenoh, wz_core);

fn compare(group: &str, up: &[String], wz: &[String]) {
    assert!(up.len() > 3, "{group} holds {} line(s)", up.len());
    assert_eq!(up.len(), wz.len(), "{group}: the groups differ in length");
    if let Some((x, y)) = up.iter().zip(wz).find(|(x, y)| x != y) {
        panic!("{group}\nupstream: {x}\nwz:       {y}");
    }
    if std::env::var_os("WZ_CANCEL_TRANSCRIPT").is_some() {
        for line in up {
            println!("{group}: {line}");
        }
    }
}

#[test]
fn a_token_cancelled_with_no_handler() {
    compare("plain token", &up::plain_token(), &wz::plain_token());
}

#[test]
fn handlers_ids_removal_and_what_runs() {
    let (u, w) = (up::handlers(), wz::handlers());
    assert!(u.iter().any(|l| l == "handlers that ran: 4"), "{u:#?}");
    compare("handlers", &u, &w);
}

#[test]
fn a_handler_that_fails() {
    let (u, w) = (up::a_failing_handler(), wz::a_failing_handler());
    assert!(u.iter().any(|l| l.contains("Err(Cancel failed")), "{u:#?}");
    compare("failing handler", &u, &w);
}

#[test]
fn a_held_notifier_keeps_the_cancel_waiting() {
    let (u, w) = (up::the_notifier(), wz::the_notifier());
    assert!(u.iter().any(|l| l == "cancel finished while held: false"), "{u:#?}");
    compare("notifier", &u, &w);
}

#[test]
fn the_cancel_asked_from_a_runtime() {
    compare("runtime", &up::from_a_runtime(), &wz::from_a_runtime());
}

#[test]
fn the_group_under_the_token() {
    compare("sync group", &up::the_sync_group(), &wz::the_sync_group());
}

#[test]
fn the_comparison_sees_a_token_that_differs() {
    let u = up::plain_token();
    let mut w = wz::plain_token();
    w[3] = format!("{} changed", w[3]);
    assert!(u.iter().zip(&w).any(|(x, y)| x != y));
    assert_ne!(up::handlers(), up::a_failing_handler());
}
