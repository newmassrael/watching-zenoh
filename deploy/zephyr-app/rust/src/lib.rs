// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! zephyr-app (Rust staticlib) — LAYER-2 Zephyr **cooperative single-task
//! profile** e2e on QEMU `qemu_cortex_m3` (ti_lm3s6965, Cortex-M3).
//!
//! Path B (the chosen Zephyr integration shape, FreeRTOS-consistent): Zephyr is
//! the kernel only; the Zephyr **main thread** hosts the wz-runtime-coop
//! cooperative executor (`ZephyrRuntime = CoopRuntime<ZephyrClock>`, the SAME
//! executor reused on bare-metal + FreeRTOS), which is exactly zenoh-pico's
//! single-thread mode (`Z_FEATURE_MULTI_THREAD=0`). The C `main()` (src/main.c)
//! calls [`wz_app_main`]; this crate is linked into the Zephyr image as a
//! staticlib, with the kernel symbols (`sys_clock_tick_get` / `k_malloc` /
//! `k_free`) resolved at the image link (forced kept by the CMakeLists.txt
//! `--undefined` contract, since libkernel.a is scanned before librustlib.a).
//!
//! The workload is the wz-link-lwip NO_SYS UDP **loopback echo** — the exact
//! parity scenario the bare-metal (`deploy/mcu-qemu-demo`) and FreeRTOS
//! (`deploy/mcu-freertos-demo`) profiles run, only with the clock + allocator +
//! critical-section seams swapped to Zephyr's. One task sends a payload to
//! `127.0.0.1:ECHO_PORT` and polls for it back; the Zephyr main thread drives
//! the cooperative loop (poll lwIP loopback + timer wheel, run the executor,
//! yield one tick). This exercises every seam end-to-end: [`ZephyrAllocator`]
//! (`k_malloc`, the executor + socket allocations), [`ZephyrClock`] +
//! `sys_now` (`sys_clock_tick_get`, the timer + lwIP timeouts), and the
//! Zephyr-native `critical_section` impl. The build sets `WZ_LWIP_PORT` (the
//! lwip-sys cross-test port) so wz-link-lwip's `lwip_real_build` cfg lights up;
//! without it `wz::link_lwip` is absent and this crate does not compile (it is
//! only ever built through the deploy's west/CI build, which supplies the env).
#![no_std]

extern crate alloc;

use core::ffi::{c_char, CStr};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicI32, Ordering};

use critical_section::RawRestoreState;

use wz::link_lwip::{ipv4_addr_loopback, LwipLink, LwipUdpSocket};
use wz::runtime_coop::{CoopRuntime, CoopTime};
use wz::runtime_core::{Runtime, TimeSource};
use wz_runtime_zephyr::{ZephyrAllocator, ZephyrClock};

/// Every Rust allocation (the executor task pool + future boxes) routes through
/// the Zephyr kernel heap. The deploy's prj.conf sets `CONFIG_HEAP_MEM_POOL_SIZE`
/// (else `k_malloc` is not compiled in → link error).
#[global_allocator]
static ALLOC: ZephyrAllocator = ZephyrAllocator;

/// `CONFIG_SYS_CLOCK_TICKS_PER_SEC` pinned in prj.conf (qemu_cortex_m3 default).
/// The `ZephyrClock` timebase; 100 Hz = 10 ms tick resolution.
const TICK_HZ: u32 = 100;
/// UDP echo port (matches the bare-metal + FreeRTOS siblings).
const ECHO_PORT: u16 = 5555;
/// Echo payload — identity-checked on receive to prove the full lwIP path.
const PAYLOAD: &[u8] = b"Zephyr lwIP UDP loopback echo";
/// Cooperative-loop budget: one `wz_yield_ms(1)` is ~1 tick (10 ms), so 600
/// iterations ~= 6 s — under the CI QEMU timeout, ample for a loopback echo.
const POLL_BUDGET: u32 = 600;

/// Echo outcome shared with the cooperative loop: -1 pending, 0 PASS, 1 FAIL.
static RESULT: AtomicI32 = AtomicI32::new(-1);

extern "C" {
    /// `printk("%s\n", msg)` — variadic printk is wrapped C-side (src/main.c)
    /// so the Rust FFI target is a plain non-variadic symbol.
    fn wz_log(msg: *const c_char);
    /// `k_msleep(ms)` — `k_msleep` is `static inline` in the Zephyr headers
    /// (no link symbol), so it too is wrapped C-side. Yields the main thread to
    /// the kernel idle thread for ~`ms`, letting the tick advance cooperatively.
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
/// and restores the *prior* IRQ state) via the C seam — UNLIKE the cargo-driven
/// bare-metal / FreeRTOS deploys, which pull cortex-m's single-core impl. It is
/// defined in the staticlib ROOT crate so its `#[no_mangle] _critical_section_1_0_*`
/// symbols are always bundled into the archive (rustc drops a dependency's impl
/// object from a staticlib because the impl is reached only through those extern
/// symbols, not the Rust call graph — the cause of the Stage-1 first-cut link
/// error). `restore-state-u32` makes `RawRestoreState` the kernel IRQ key.
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

/// Entry point the Zephyr C `main()` calls. Hosts `CoopRuntime<ZephyrClock>` +
/// the wz-link-lwip UDP loopback echo in the Zephyr main thread (the
/// cooperative single-task profile = pico `Z_FEATURE_MULTI_THREAD=0`), and
/// drives it to completion. Returns 0 on PASS. Structurally identical to the
/// FreeRTOS demo's `wz_task`, only the clock + yield primitive differ.
#[no_mangle]
pub extern "C" fn wz_app_main() -> i32 {
    log(c"wz: CoopRuntime<ZephyrClock> + wz-link-lwip UDP echo starting");

    let link = LwipLink::init();
    let runtime = CoopRuntime::new(ZephyrClock::<TICK_HZ>);
    let time = CoopTime::new(&runtime);

    let sock = match LwipUdpSocket::bind(&link, ECHO_PORT) {
        Ok(s) => s,
        Err(_) => {
            log(c"wz: FAIL — bind UDP socket on ANY:5555");
            return 1;
        }
    };
    // `CoopTime` owns an Arc of the runtime inner (not a borrow), so moving it
    // into the task while the loop below keeps using `runtime` is sound.
    runtime.spawn(echo_task(sock, time));

    // Cooperative loop: drain lwIP's loopback queue + its timer wheel, run the
    // executor's ready tasks + expired timers, then yield one tick so the
    // systick ISR advances sys_clock_tick_get. echo_task records the outcome.
    for _ in 0..POLL_BUDGET {
        link.poll_loopback();
        link.check_timeouts();
        runtime.run_until_idle();
        let r = RESULT.load(Ordering::SeqCst);
        if r >= 0 {
            return r;
        }
        // SAFETY: standard FFI; blocks this thread for ~1 kernel tick.
        unsafe { wz_yield_ms(1) };
    }

    log(c"wz: FAIL — echo did not complete within budget");
    1
}

/// Async echo: send one PAYLOAD to loopback:ECHO_PORT and poll for it back,
/// recording the outcome in `RESULT`. Identical shape to the bare-metal +
/// FreeRTOS siblings; only the `CoopTime` clock param is `ZephyrClock`.
async fn echo_task(mut sock: LwipUdpSocket, time: CoopTime<ZephyrClock<TICK_HZ>>) {
    if sock
        .send_to(ipv4_addr_loopback(), ECHO_PORT, PAYLOAD)
        .is_err()
    {
        log(c"wz: FAIL — send_to loopback");
        RESULT.store(1, Ordering::SeqCst);
        return;
    }
    for _ in 0..POLL_BUDGET {
        if let Some(dg) = sock.try_recv() {
            let ok = dg.data.as_slice() == PAYLOAD
                && dg.src_port == ECHO_PORT
                && dg.src_addr == ipv4_addr_loopback();
            if ok {
                log(c"wz: lwIP loopback echo round-tripped");
                RESULT.store(0, Ordering::SeqCst);
            } else {
                log(c"wz: FAIL — echo mismatch");
                RESULT.store(1, Ordering::SeqCst);
            }
            return;
        }
        time.sleep(1).await;
    }
    log(c"wz: FAIL — no echo within task budget");
    RESULT.store(1, Ordering::SeqCst);
}

/// lwIP NO_SYS `sys_now()` — milliseconds since boot, from the same kernel tick
/// counter `ZephyrClock` reads. lwIP's `timeouts.c` calls this unconditionally;
/// without it the link fails with "undefined sys_now".
#[no_mangle]
pub extern "C" fn sys_now() -> u32 {
    // ms = ticks * 1000 / TICK_HZ.
    // SAFETY: `sys_clock_tick_get` reads the kernel tick counter; no preconditions.
    let ticks = unsafe { zephyr_sys::sys_clock_tick_get() } as u64;
    (ticks * 1000 / TICK_HZ as u64) as u32
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
