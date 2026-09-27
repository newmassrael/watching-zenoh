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
//! R2917 — the workload is a zenoh SESSION over Zephyr's own sockets: the
//! acceptor handshake to `Established` against a reactive peer, with the
//! anti-amplification cookie round-tripped, then a dispatched application
//! Frame — the same `run_acceptor_e2e_on` scenario the bare-metal and FreeRTOS
//! images run over lwIP, here through [`ZephyrTopology`]: the acceptor is a
//! `ZephyrUdpDriver` built with NO peer (it learns it from the InitSyn), the
//! peer a second socket on the loopback interface. R2916 proved the link's two
//! seams with a single round trip; this drives the whole session through them.
//!
//! The Zephyr clock times the loop, the `k_malloc` allocator backs every
//! allocation and the `irq_lock` critical section guards the executor, so the
//! profile's other seams run under the same boot.
#![no_std]

extern crate alloc;

use alloc::rc::Rc;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::{c_char, CStr};
use core::panic::PanicInfo;

use critical_section::RawRestoreState;

// R311y32 — the Zephyr profile seams arrive through the wz facade's
// `platform-zephyr` gate (this deploy is the consumer that proves it), not a
// direct wz-runtime-zephyr dep — mirroring mcu-freertos-demo's wz::runtime_freertos.
use wz::runtime_zephyr::net::{ZephyrUdpDriver, ZephyrUdpSocket};
use wz::runtime_zephyr::{ZephyrAllocator, ZephyrClock};
use wz_mcu_session_acceptor::{
    run_acceptor_e2e_on, AcceptorE2eOutcome, AcceptorTopology, DataMode, FixtureEntropy, PEER_PORT,
    SESSION_PORT,
};
use wz_session_core::link::BoxedLinkDriver;

/// Every Rust allocation (the session bundle, the executor, the socket link's
/// receive buffer) routes through the Zephyr kernel heap. The deploy's
/// prj.conf sets `CONFIG_HEAP_MEM_POOL_SIZE`.
#[global_allocator]
static ALLOC: ZephyrAllocator = ZephyrAllocator;

/// `CONFIG_SYS_CLOCK_TICKS_PER_SEC` pinned in prj.conf. The `ZephyrClock`
/// timebase; 100 Hz = 10 ms tick resolution.
const TICK_HZ: u32 = 100;
/// The loopback address both endpoints bind to.
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

extern "C" {
    /// `printk("%s\n", msg)` — variadic printk is wrapped C-side (src/main.c)
    /// so the Rust FFI target is a plain non-variadic symbol.
    fn wz_log(msg: *const c_char);
    /// `k_msleep(ms)` — `k_msleep` is `static inline` in the Zephyr headers
    /// (no link symbol), so it too is wrapped C-side. The socket link's
    /// `service` yields through it, and so does the panic handler.
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

/// The e2e's two endpoints on Zephyr's net stack: the acceptor's socket link
/// and a plain socket for the crafted peer, both on the loopback interface.
struct ZephyrTopology {
    driver: Rc<ZephyrUdpDriver>,
    peer: ZephyrUdpSocket,
    rx: Vec<u8>,
}

impl AcceptorTopology for ZephyrTopology {
    // One object is both faces: the session's sink and the loop's link.
    type Link = Rc<ZephyrUdpDriver>;

    fn acceptor_sink(&self) -> Rc<dyn BoxedLinkDriver> {
        self.driver.clone()
    }

    fn acceptor_link(&self) -> Self::Link {
        self.driver.clone()
    }

    fn peer_send(&mut self, bytes: &[u8]) {
        if self.peer.send_to(LOOPBACK, SESSION_PORT, bytes).is_err() {
            log(c"wz: the peer's send was refused");
        }
    }

    fn peer_try_recv(&mut self) -> Option<Vec<u8>> {
        // Zephyr delivers on its own RX thread; the drive loop's `service`
        // already yielded to it this iteration, so nothing to pump here.
        match self.peer.try_recv(&mut self.rx) {
            Ok(Some((len, _, _))) => Some(self.rx[..len].to_vec()),
            Ok(None) => None,
            Err(_) => {
                log(c"wz: the peer socket failed to receive");
                None
            }
        }
    }
}

/// Entry point the Zephyr C `main()` calls: the acceptor session e2e over
/// Zephyr's sockets, on the cooperative single-task profile (pico
/// `Z_FEATURE_MULTI_THREAD=0`). Returns 0 on PASS.
#[no_mangle]
pub extern "C" fn wz_app_main() -> i32 {
    log(c"wz: acceptor session over Zephyr's own sockets starting");

    let Ok(link) = ZephyrUdpSocket::bind(LOOPBACK, SESSION_PORT) else {
        log(c"wz: FAIL - bind the session socket on 127.0.0.1:7460");
        return 1;
    };
    let Ok(peer) = ZephyrUdpSocket::bind(LOOPBACK, PEER_PORT) else {
        log(c"wz: FAIL - bind the peer socket on 127.0.0.1:7461");
        return 1;
    };
    // Built with NO peer, as an acceptor is: it learns it from the InitSyn.
    let driver = Rc::new(ZephyrUdpDriver::acceptor(link));
    let topology = ZephyrTopology {
        driver: driver.clone(),
        peer,
        rx: vec![0u8; 2048],
    };

    // ⚠ FixtureEntropy until this profile has an entropy seam of its own.
    let report = run_acceptor_e2e_on(
        topology,
        ZephyrClock::<TICK_HZ>,
        FixtureEntropy,
        DataMode::WholeFrame,
        || {},
    );

    if driver.rx_error().is_some() {
        log(c"wz: FAIL - the session socket failed to receive");
        return 1;
    }
    if report.outcome != AcceptorE2eOutcome::EstablishedAndDispatched {
        log(match report.outcome {
            AcceptorE2eOutcome::NotEstablished => c"wz: FAIL - the handshake did not establish",
            AcceptorE2eOutcome::FrameNotDispatched => {
                c"wz: FAIL - established, but the Frame was not dispatched"
            }
            _ => c"wz: FAIL - an unexpected verdict",
        });
        return 1;
    }
    log(c"wz: session Established over Zephyr sockets, cookie round-tripped, Frame dispatched");

    // The link learnt its two locators from the InitSyn it answered.
    let learnt = driver
        .link_endpoints()
        .map(|e| e.src == "udp/127.0.0.1:7460" && e.dst == "udp/127.0.0.1:7461");
    if learnt != Some(true) {
        log(c"wz: FAIL - the link's locators are not its two sockets");
        return 1;
    }
    log(c"wz: the session link reports udp/127.0.0.1:7460 -> udp/127.0.0.1:7461");
    0
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
