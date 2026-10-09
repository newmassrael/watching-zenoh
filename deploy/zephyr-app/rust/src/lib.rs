// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! zephyr-app (Rust staticlib) — LAYER-2 Zephyr **cooperative single-task
//! profile** acceptor-session e2e; the lane's reference board is QEMU
//! `mps2/an385` (Cortex-M3), and nothing here names it.
//!
//! Path B (the chosen Zephyr integration shape, FreeRTOS-consistent): Zephyr is
//! the kernel only; the Zephyr **main thread** hosts the wz-runtime-coop
//! cooperative executor (`ZephyrRuntime = CoopRuntime<ZephyrClock>`, the SAME
//! executor reused on bare-metal + FreeRTOS), which is exactly zenoh-pico's
//! single-thread mode (`Z_FEATURE_MULTI_THREAD=0`). The C `main()` (src/main.c)
//! calls [`wz_app_main`]; this crate is linked into the Zephyr image as a
//! staticlib, with the kernel and POSIX symbols resolved at the image link
//! (forced kept by the `--undefined` contract in
//! `deploy/zephyr-common/wz_zephyr_board.cmake`, since the Zephyr libraries are
//! scanned before librustlib.a).
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

// R311y32 — the Zephyr profile seams arrive through the wz facade's
// `platform-zephyr` gate (this deploy is the consumer that proves it), not a
// direct wz-runtime-zephyr dep — mirroring mcu-freertos-demo's wz::runtime_freertos.
use wz::runtime_zephyr::glue::{log, log_line};
use wz::runtime_zephyr::net::{ZephyrUdpDriver, ZephyrUdpSocket};
use wz::runtime_zephyr::{ZephyrClock, ZephyrEntropy, ZephyrEpoch};
use wz_mcu_session_acceptor::{
    run_acceptor_e2e_on_with_progress, AcceptorE2eOutcome, AcceptorTopology, DataMode, PEER_PORT,
    SESSION_PORT,
};
use wz_session_core::epoch::EpochSource;
use wz_session_core::link::BoxedLinkDriver;

/// 2020-01-01T00:00:00Z: an epoch reading below this is not the time.
const EARLIEST_PLAUSIBLE_UNIX_SECS: u64 = 1_577_836_800;

// The allocator over the kernel heap (`CONFIG_HEAP_MEM_POOL_SIZE` in prj.conf),
// the critical section over the kernel IRQ lock and the panic handler: the glue
// every wz Zephyr image carries, written once in the profile crate.
wz::runtime_zephyr::zephyr_image!();

/// The board's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`, as this build was configured:
/// the `ZephyrClock` timebase. Read from the Zephyr build, never typed here, so
/// a board whose kernel ticks at another rate gets a clock that agrees with it.
const TICK_HZ: u32 = wz::runtime_zephyr::tick_hz_from_build!();
/// The loopback address both endpoints bind to.
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

extern "C" {
    /// R2918 — how many times the board's random hook served `ZephyrEntropy`
    /// (deploy/zephyr-common/wz_board_hooks.c), printed with the verdict so a
    /// PASS also shows the session drew its secrets through the seam rather than
    /// around it.
    fn wz_random_draws() -> u32;
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

    // R2918 — the session's secrets come through the profile's entropy seam,
    // from the board's random hook.
    //
    // R3189 (open-debt item 815) — each stage is logged as the e2e ENTERS it, so
    // a boot that stops making progress leaves the stage it stalled in as its
    // last console line instead of only the `starting` line above.
    let report = run_acceptor_e2e_on_with_progress(
        topology,
        ZephyrClock::<TICK_HZ>,
        ZephyrEntropy,
        DataMode::WholeFrame,
        || {},
        |stage| log_line(alloc::format!("wz: stage {}", stage.name())),
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
    // SAFETY: reads a counter the board keeps; no preconditions.
    let draws = unsafe { wz_random_draws() };
    if draws == 0 {
        log(c"wz: FAIL - the session drew nothing through ZephyrEntropy");
        return 1;
    }
    log_line(alloc::format!(
        "wz: the session drew its secrets through ZephyrEntropy ({draws} board draws)"
    ));

    // R2918 — the epoch seam: mint the NTP64 a timestamp carries from this
    // board's clock, through the profile's `ZephyrEpoch`. A date before 2020
    // means the board answered something that is not the time.
    match ZephyrEpoch.try_now_ntp64() {
        Ok(ntp) if ntp.whole_secs() >= EARLIEST_PLAUSIBLE_UNIX_SECS => {
            log_line(alloc::format!(
                "wz: epoch via ZephyrEpoch, NTP64 {:#018x} ({} s since 1970)",
                ntp.as_word(),
                ntp.whole_secs()
            ));
            0
        }
        Ok(_) => {
            log(c"wz: FAIL - the board clock says a date before 2020");
            1
        }
        Err(_) => {
            log(c"wz: FAIL - no time since the epoch is available");
            1
        }
    }
}
