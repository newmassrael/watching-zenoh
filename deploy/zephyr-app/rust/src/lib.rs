// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! zephyr-app (Rust staticlib) — LAYER-2 Zephyr **cooperative single-task
//! profile** e2e on QEMU `mps2/an385` (Cortex-M3).
//!
//! Path B (the chosen Zephyr integration shape, FreeRTOS-consistent): Zephyr is
//! the kernel only; the Zephyr **main thread** hosts the wz-runtime-coop
//! cooperative executor (`ZephyrRuntime = CoopRuntime<ZephyrClock>`, the SAME
//! executor reused on bare-metal + FreeRTOS), which is exactly zenoh-pico's
//! single-thread mode (`Z_FEATURE_MULTI_THREAD=0`). The C `main()` (src/main.c)
//! calls [`wz_app_main`]; this crate is linked into the Zephyr image as a
//! staticlib, with the kernel and POSIX symbols resolved at the image link
//! (forced kept by the CMakeLists.txt `--undefined` contract, since the Zephyr
//! libraries are scanned before librustlib.a).
//!
//! R2916 — the workload is the profile's NETWORK SEAM over Zephyr's own
//! sockets, where it used to be a wz-link-lwip loopback echo. lwIP `NO_SYS`
//! has no netif over Zephyr's device drivers, while zenoh-pico's Zephyr port
//! runs over Zephyr's sockets; `wz_runtime_zephyr::net` now does too. One task
//! drives a [`ZephyrUdpDriver`] the way the session drive loop does, through
//! its two seams, against a second socket standing in for the peer on the
//! loopback interface:
//!
//! 1. the peer sends to the driver, which was built WITHOUT a peer — an
//!    acceptor learns its peer from the InitSyn;
//! 2. the driver hands the datagram over (`SessionDatagramLink::try_recv`) and
//!    must have learnt the peer and the link's two locators from it;
//! 3. the driver replies through the session's outbound seam
//!    (`BoxedLinkDriver::send_blocking`), and the peer must receive it FROM the
//!    driver's address.
//!
//! The executor, the Zephyr clock, the `k_malloc` allocator and the
//! `irq_lock` critical section run it, so the profile's other seams stay under
//! the same boot.
#![no_std]

extern crate alloc;

use alloc::rc::Rc;
use core::ffi::{c_char, CStr};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicI32, Ordering};

use critical_section::RawRestoreState;

use wz::runtime_coop::session_drive::SessionDatagramLink;
use wz::runtime_coop::{CoopLocalSet, CoopRuntime, CoopTime};
use wz::runtime_core::TimeSource;
// R311y32 — the Zephyr profile seams arrive through the wz facade's
// `platform-zephyr` gate (this deploy is the consumer that proves it), not a
// direct wz-runtime-zephyr dep — mirroring mcu-freertos-demo's wz::runtime_freertos.
use wz::runtime_zephyr::net::{ZephyrUdpDriver, ZephyrUdpSocket};
use wz::runtime_zephyr::{ZephyrAllocator, ZephyrClock};
use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome};
use wz_session_core::reliability::Reliability;

/// Every Rust allocation (the executor task pool, the future boxes, the
/// driver's receive buffer) routes through the Zephyr kernel heap. The
/// deploy's prj.conf sets `CONFIG_HEAP_MEM_POOL_SIZE`.
#[global_allocator]
static ALLOC: ZephyrAllocator = ZephyrAllocator;

/// `CONFIG_SYS_CLOCK_TICKS_PER_SEC` pinned in prj.conf. The `ZephyrClock`
/// timebase; 100 Hz = 10 ms tick resolution.
const TICK_HZ: u32 = 100;
/// The loopback address both sockets bind to.
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
/// The driver's port — zenoh's default.
const LINK_PORT: u16 = 7447;
/// The stand-in peer's port.
const PEER_PORT: u16 = 7448;
/// What the peer sends, and what the driver answers.
const INBOUND: &[u8] = b"InitSyn stand-in";
const REPLY: &[u8] = b"InitAck stand-in";
/// Cooperative-loop budget: one `wz_yield_ms(1)` is ~1 tick (10 ms), so 600
/// iterations ~= 6 s — under the CI QEMU timeout, ample for loopback.
const POLL_BUDGET: u32 = 600;

/// Outcome shared with the cooperative loop: -1 pending, 0 PASS, 1 FAIL.
static RESULT: AtomicI32 = AtomicI32::new(-1);

extern "C" {
    /// `printk("%s\n", msg)` — variadic printk is wrapped C-side (src/main.c)
    /// so the Rust FFI target is a plain non-variadic symbol.
    fn wz_log(msg: *const c_char);
    /// `k_msleep(ms)` — `k_msleep` is `static inline` in the Zephyr headers
    /// (no link symbol), so it too is wrapped C-side. Yields the main thread
    /// for ~`ms`, letting the tick and the net stack's threads run.
    fn wz_yield_ms(ms: i32);
    /// `irq_lock()` — returns the prior IRQ key; wrapped C-side (the Zephyr
    /// `irq_lock` macro expands to `arch_irq_lock()`, an inline, on this UP SoC).
    fn wz_irq_lock() -> u32;
    /// `irq_unlock(key)` — restores the IRQ state `wz_irq_lock` saved.
    fn wz_irq_unlock(key: u32);
}

/// Zephyr-native `critical_section` impl backing wz-runtime-coop's
/// `critical_section::Mutex` (the executor task pool / timer queue) and
/// portable-atomic's `AtomicU64` fallback. It routes to the kernel's
/// `irq_lock`/`irq_unlock` (BASEPRI/PRIMASK save+restore, which nests correctly
/// and restores the *prior* IRQ state) via the C seam. It is defined in the
/// staticlib ROOT crate so its `#[no_mangle] _critical_section_1_0_*` symbols
/// are always bundled into the archive (rustc drops a dependency's impl object
/// from a staticlib because the impl is reached only through those extern
/// symbols, not the Rust call graph). `restore-state-u32` makes
/// `RawRestoreState` the kernel IRQ key.
struct ZephyrCriticalSection;
critical_section::set_impl!(ZephyrCriticalSection);

unsafe impl critical_section::Impl for ZephyrCriticalSection {
    unsafe fn acquire() -> RawRestoreState {
        wz_irq_lock()
    }

    unsafe fn release(key: RawRestoreState) {
        wz_irq_unlock(key);
    }
}

/// Log a static C string via the Zephyr printk seam.
#[inline]
fn log(msg: &CStr) {
    // SAFETY: `msg` is a valid nul-terminated C string with 'static lifetime;
    // `wz_log` only reads it (printk %s).
    unsafe { wz_log(msg.as_ptr()) };
}

fn fail(msg: &CStr) {
    log(msg);
    RESULT.store(1, Ordering::SeqCst);
}

/// Entry point the Zephyr C `main()` calls. Hosts `CoopRuntime<ZephyrClock>`
/// in the Zephyr main thread (the cooperative single-task profile = pico
/// `Z_FEATURE_MULTI_THREAD=0`) and drives the network-seam task to completion.
/// Returns 0 on PASS.
#[no_mangle]
pub extern "C" fn wz_app_main() -> i32 {
    log(c"wz: CoopRuntime<ZephyrClock> + Zephyr-socket session link starting");

    let runtime = CoopRuntime::new(ZephyrClock::<TICK_HZ>);
    let time = CoopTime::new(&runtime);

    let link = match ZephyrUdpSocket::bind(LOOPBACK, LINK_PORT) {
        Ok(s) => s,
        Err(_) => {
            log(c"wz: FAIL - bind the link socket on 127.0.0.1:7447");
            return 1;
        }
    };
    let peer = match ZephyrUdpSocket::bind(LOOPBACK, PEER_PORT) {
        Ok(s) => s,
        Err(_) => {
            log(c"wz: FAIL - bind the peer socket on 127.0.0.1:7448");
            return 1;
        }
    };
    // Built with NO peer, as an acceptor is. `Rc`, because the session keeps
    // the same object as its `Rc<dyn BoxedLinkDriver>` sink; so the task goes
    // in the executor's `!Send` pool, which is what that pool is for.
    let driver = Rc::new(ZephyrUdpDriver::acceptor(link));
    let local = CoopLocalSet::new(&runtime);
    let _task = local.spawn_local(link_task(driver, peer, time));

    // Cooperative loop: run the executor's ready tasks and expired timers,
    // then yield one tick so the systick advances and Zephyr's net threads
    // move the loopback traffic. The task records the outcome.
    for _ in 0..POLL_BUDGET {
        local.run_until_idle();
        let r = RESULT.load(Ordering::SeqCst);
        if r >= 0 {
            return r;
        }
        // SAFETY: standard FFI; blocks this thread for ~1 kernel tick.
        unsafe { wz_yield_ms(1) };
    }

    log(c"wz: FAIL - the link task did not finish within budget");
    1
}

/// The network-seam round trip, driven through the two seams the session
/// drive loop uses.
async fn link_task(
    driver: Rc<ZephyrUdpDriver>,
    peer: ZephyrUdpSocket,
    time: CoopTime<ZephyrClock<TICK_HZ>>,
) {
    if peer.send_to(LOOPBACK, LINK_PORT, INBOUND).is_err() {
        return fail(c"wz: FAIL - the peer's send to the link");
    }

    // (1)+(2) The inbound datagram arrives through the loop's seam.
    let mut frame = None;
    for _ in 0..POLL_BUDGET {
        if let Some(f) = driver.try_recv() {
            frame = Some(f);
            break;
        }
        if driver.rx_error().is_some() {
            return fail(c"wz: FAIL - the link socket failed to receive");
        }
        time.sleep(10).await;
    }
    let Some(frame) = frame else {
        return fail(c"wz: FAIL - no datagram reached the link");
    };
    if frame.bytes.as_slice() != INBOUND {
        return fail(c"wz: FAIL - the link handed over other bytes");
    }
    if driver.peer() != Some((LOOPBACK, PEER_PORT)) {
        return fail(c"wz: FAIL - the link did not learn its peer from the datagram");
    }
    let learnt = driver
        .link_endpoints()
        .map(|e| e.src == "udp/127.0.0.1:7447" && e.dst == "udp/127.0.0.1:7448");
    if learnt != Some(true) {
        return fail(c"wz: FAIL - the link's locators are not its two sockets");
    }
    log(c"wz: the link took the datagram and learnt its peer");

    // (3) The reply leaves through the session's outbound seam.
    if driver.send_blocking(REPLY, Reliability::Reliable) != LinkSendOutcome::Sent {
        return fail(c"wz: FAIL - the link refused the reply");
    }
    let mut buf = [0u8; 64];
    for _ in 0..POLL_BUDGET {
        match peer.try_recv(&mut buf) {
            Ok(Some((len, addr, port))) => {
                if &buf[..len] == REPLY && addr == LOOPBACK && port == LINK_PORT {
                    log(c"wz: the reply reached the peer from the link's address");
                    RESULT.store(0, Ordering::SeqCst);
                } else {
                    fail(c"wz: FAIL - the peer received something else");
                }
                return;
            }
            Ok(None) => time.sleep(10).await,
            Err(_) => return fail(c"wz: FAIL - the peer socket failed to receive"),
        }
    }
    fail(c"wz: FAIL - the reply never reached the peer");
}

/// no_std panic handler — log + halt (yielding, not busy-spinning). The CI
/// verdict is the presence of the `ZEPHYR-WZ PASS` sentinel under a timeout, so
/// a halted (never-PASS) image correctly reads as FAIL.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    log(c"wz: PANIC");
    loop {
        // SAFETY: standard FFI; yields rather than pinning the QEMU CPU at 100%.
        unsafe { wz_yield_ms(100) };
    }
}
