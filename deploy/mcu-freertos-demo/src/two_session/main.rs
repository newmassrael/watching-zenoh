// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! mcu-freertos-two-session — open-debt item 900 ON TARGET: one FreeRTOS
//! program, ONE task, two sessions on one cooperative local set.
//!
//! A unicast CLIENT session dials a router (a fixture acceptor in this image)
//! and a multicast GROUP session admits a member, both spawned on one
//! `CoopLocalSet` inside the one FreeRTOS task (`spawn_session` +
//! `spawn_multicast_session`), over the image's lwIP loopback with multicast
//! routed over the loop netif (`lwip-sys/port/cross-test-mcast`, the port the
//! bare-metal multicast boot uses). The four scenarios of the host baseline
//! run in turn (`scenarios.rs`), each printing one `witness:` line; the image
//! exits 0 only when all four held AND the task's stack peak left the margin
//! the bare-metal images are held to. Layer Q.frt2 boots it.
//!
//! It also prints what STEP 0 of the item asked to be measured, as the kernel
//! measured it: the heap each link open took, the heap_4 peak, and the
//! task's stack peak.

#![no_std]
#![no_main]

extern crate alloc;

#[path = "../board.rs"]
mod board;
mod scenarios;

use alloc::rc::Rc;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use panic_semihosting as _;

use wz::link_lwip::LwipLink;

/// The task stack in WORDS (32 KiB, twice the acceptor image's).
///
/// MEASURED, not chosen: at the acceptor image's 16 KiB this image reported a
/// peak of 16216 of 16384 bytes and every scenario failed, the group session
/// reading "link lost" off lwIP state it had never touched, which is what a
/// task stack written past its bottom looks like (it lies at the low end of
/// heap_4, next to lwIP's own statics). At 32 KiB the peak is about 18.6 KB.
/// Most of it is one frame: spawning the sessions moves each session's state
/// by value into its task (`MulticastSession<4>` alone is 6320 bytes), and
/// those copies sit on this stack until the local set boxes them.
const WZ_TASK_STACK_WORDS: u16 = 8192;

/// heap_4's usable bytes, read in `main` before the scheduler allocates.
static HEAP_USABLE: AtomicUsize = AtomicUsize::new(0);

#[entry]
fn main() -> ! {
    HEAP_USABLE.store(board::heap_usable_bytes(), Ordering::Relaxed);
    hprintln!(
        "two-session: FreeRTOS boot; one task, a client and a group session on one local set"
    );
    board::start(Some(wz_task), c"wz", WZ_TASK_STACK_WORDS)
}

extern "C" fn wz_task(_params: *mut c_void) {
    let link = Rc::new(LwipLink::init());
    if let Err(e) = link.route_multicast_over_loopback() {
        hprintln!(
            "two-session FAIL: multicast not routed over the loop netif: {:?}",
            e
        );
        debug::exit(debug::EXIT_FAILURE);
    }
    let heap_at_start = board::heap_free_bytes();

    let mut failed = 0usize;
    let mut report = |name: &str, result: Result<alloc::string::String, alloc::string::String>| {
        match result {
            Ok(detail) => hprintln!("witness: scenario {} PASS ({})", name, detail),
            Err(why) => {
                failed += 1;
                hprintln!("witness: scenario {} FAIL ({})", name, why);
            }
        }
        // Every scenario's sessions, sockets and fixtures are dropped when it
        // returns; what is still allocated afterwards was leaked.
        let left = heap_at_start.saturating_sub(board::heap_free_bytes());
        if left != 0 {
            failed += 1;
            hprintln!(
                "witness: scenario {} FAIL (left {} heap bytes allocated)",
                name,
                left
            );
        }
    };

    match scenarios::flood(&link) {
        Ok((detail, costs)) => {
            report("group-socket-flood", Ok(detail));
            hprintln!(
                "witness: heap per link open: client {} B, group {} B; fixtures: router {} B, \
                 member {} B",
                costs.client,
                costs.group,
                costs.router_fixture,
                costs.member_fixture,
            );
        }
        Err(why) => report("group-socket-flood", Err(why)),
    }
    report("group-peer-lease-expiry", scenarios::lease_expiry(&link));
    report("unicast-close", scenarios::unicast_close(&link));
    report("multicast-stop", scenarios::multicast_stop(&link));

    let usable = HEAP_USABLE.load(Ordering::Relaxed);
    hprintln!(
        "heap: peak {} of {} bytes",
        board::heap_peak_bytes(usable),
        usable
    );
    let stack = board::task_stack_verdict(WZ_TASK_STACK_WORDS);
    hprintln!("stack: peak {} of {} bytes", stack.peak, stack.budget);
    if !stack.fits() {
        hprintln!(
            "two-session FAIL: the stack peak leaves less than {} bytes of the task's stack",
            wz_mcu_stack::MARGIN_BYTES
        );
        debug::exit(debug::EXIT_FAILURE);
    }
    if failed != 0 {
        hprintln!("two-session FAIL: {} check(s) failed", failed);
        debug::exit(debug::EXIT_FAILURE);
    }
    hprintln!(
        "two-session PASS: four isolation scenarios on one task (random_draws={})",
        board::RANDOM_DRAWS.load(Ordering::Relaxed)
    );
    debug::exit(debug::EXIT_SUCCESS);
    #[allow(clippy::empty_loop)]
    loop {}
}
