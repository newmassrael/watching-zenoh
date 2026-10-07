// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `wz-runtime-zephyr` — the Zephyr **cooperative single-task profile**.
//!
//! This crate is deliberately THIN, identical in shape to
//! `wz-runtime-freertos`. It does not reimplement the async executor or
//! `impl Runtime` — that is the audited [`wz_runtime_coop::CoopRuntime`] (task
//! pool, custom waker, cancel, timer queue), generic over a [`ClockSource`].
//! The Zephyr profile is that executor running inside ONE Zephyr thread (the
//! analogue of zenoh-pico's `Z_FEATURE_MULTI_THREAD=0` single-thread mode), so
//! this crate supplies only the Zephyr-specific SEAMS:
//!
//! 1. [`ZephyrClock`] — a [`ClockSource`] over the kernel tick counter
//!    (`sys_clock_tick_get`), const-generic over `CONFIG_SYS_CLOCK_TICKS_PER_SEC`.
//! 2. [`ZephyrAllocator`] — a [`GlobalAlloc`] over the Zephyr kernel heap
//!    (`k_malloc`/`k_free`). The deploy binary declares it as its
//!    `#[global_allocator]` and sets `CONFIG_HEAP_MEM_POOL_SIZE`.
//!
//! [`ZephyrRuntime`] is then just `CoopRuntime<ZephyrClock<TICK_HZ>>`.
//!
//! The synchronisation seam needs nothing here: `CoopRuntime` already uses
//! `critical_section::Mutex`, and the deploy supplies the `critical-section`
//! impl (Zephyr/cortex-m has one).
//!
//! 3. R2916 — [`net`], the network seam: UDP over Zephyr's own BSD sockets
//!    and the session's link over them. Networking used to reuse `NO_SYS`
//!    lwIP via `wz-link-lwip`, as the bare-metal and FreeRTOS profiles do,
//!    which has no netif over Zephyr's drivers; zenoh-pico's Zephyr port
//!    uses Zephyr's sockets, and so does this profile now. [`links`] is the same
//!    sockets as the session shell's `SessionLinks` seam (`ZephyrLinks`: an
//!    accepting link and a dialling one), which is what lets a node that
//!    listens and dials, the admin node, run over them.
//! 4. R2918 — [`ZephyrEntropy`], the session core's `EntropySource`, over the
//!    board hook `wzApplicationGetRandom`, which a board serves from its RNG
//!    (`sys_rand_get`, the call zenoh-pico's Zephyr port makes).
//! 5. R2918 — [`ZephyrEpoch`], the session core's `EpochSource`, over the
//!    board hook `wzApplicationGetTimeSinceEpoch` — the same hook, with the
//!    same contract, the FreeRTOS profile reads — which a board serves from
//!    `clock_gettime(CLOCK_REALTIME)`, the read zenoh-pico's port makes.
//!
//! Both are BOARD hooks rather than FFI to the kernel because neither kernel
//! call is a link symbol this crate can name: `sys_rand_get` is a `__syscall`
//! wrapper, and `getentropy` demands an entropy DEVICE, which a board without
//! a TRNG does not have; `clock_gettime` is real but fills a `struct
//! timespec` whose `time_t` width is the C library's choice, so the hook names
//! fixed-width types instead.
#![no_std]

extern crate alloc;

// The host witnesses at the foot of this file panic-test a const parser, which
// needs the standard library's unwinding. Never part of a production build.
#[cfg(test)]
extern crate std;

pub mod glue;
pub mod links;
pub mod net;
pub mod stack;

pub use links::ZephyrLinks;

/// A Zephyr firmware's image glue, written once in its crate root: the global
/// allocator over the kernel heap, a `critical_section` implementation over the
/// kernel's IRQ lock, and the panic handler ([`glue::halt_after_panic`]).
///
/// The `critical_section` implementation is expanded INTO the firmware's crate
/// because it has to be there: a staticlib bundles its root crate's
/// `#[no_mangle]` symbols but drops a dependency's implementation object, which
/// is reached only through the extern `_critical_section_1_0_*` symbols and never
/// through the Rust call graph. The firmware therefore depends on
/// `critical-section` with `restore-state-u32` (the kernel's IRQ key is a
/// `u32`), as this macro's expansion names it.
///
/// ```ignore
/// wz_runtime_zephyr::zephyr_image!();
/// ```
#[macro_export]
macro_rules! zephyr_image {
    () => {
        // Every Rust allocation (the session bundle, the executor, the socket
        // links' receive buffers) goes through the Zephyr kernel heap, which the
        // firmware's prj.conf sizes with `CONFIG_HEAP_MEM_POOL_SIZE`.
        #[global_allocator]
        static WZ_ZEPHYR_ALLOCATOR: $crate::ZephyrAllocator = $crate::ZephyrAllocator;

        struct WzZephyrCriticalSection;
        critical_section::set_impl!(WzZephyrCriticalSection);

        // SAFETY: `irq_lock` / `irq_unlock` save and restore the CPU's prior IRQ
        // state, which nests correctly and is exactly the contract
        // `critical_section::Impl` asks for; the key is the `u32` it returns.
        unsafe impl critical_section::Impl for WzZephyrCriticalSection {
            unsafe fn acquire() -> critical_section::RawRestoreState {
                $crate::glue::irq_lock()
            }

            unsafe fn release(key: critical_section::RawRestoreState) {
                // SAFETY: `key` came from the matching `acquire` above.
                unsafe { $crate::glue::irq_unlock(key) };
            }
        }

        #[panic_handler]
        fn wz_zephyr_panic(_info: &core::panic::PanicInfo) -> ! {
            $crate::glue::halt_after_panic()
        }
    };
}

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::mem::size_of;

use wz_runtime_coop::{ClockSource, CoopRuntime};
use zephyr_sys::{k_free, k_malloc, sys_clock_tick_get};

/// Monotonic [`ClockSource`] reading the Zephyr kernel tick counter.
///
/// Const-generic over `TICK_HZ` = the deploy's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`
/// (the reference deploy pins 100). Mirrors the FreeRTOS profile's
/// `FreertosClock<TICK_HZ>` and the bare-metal `SystickClock<CYCLES_PER_US>`
/// const-generic shape: the timebase is a per-deploy compile-time constant, not
/// a runtime field. Zero-sized + `Copy` (the tick counter is global kernel
/// state). Monotonic by construction: `sys_clock_tick_get` is the kernel's
/// non-decreasing tick count and is `i64` (no wrap at any realistic uptime), so
/// the [`ClockSource`] monotonic contract holds without a floor.
#[derive(Clone, Copy, Default)]
pub struct ZephyrClock<const TICK_HZ: u32>;

impl<const TICK_HZ: u32> ClockSource for ZephyrClock<TICK_HZ> {
    fn now_us(&self) -> u64 {
        // `ticks * 1_000_000` cannot overflow u64 for any realistic uptime
        // (ticks is the boot-relative kernel count), and multiply-before-divide
        // keeps the conversion exact for any TICK_HZ. Returns 0 before the first
        // tick, a valid monotonic epoch.
        // SAFETY: `sys_clock_tick_get` reads the kernel tick counter and has no
        // preconditions; it is safe to call from thread context at any time.
        let ticks = unsafe { sys_clock_tick_get() } as u64;
        ticks * 1_000_000 / TICK_HZ as u64
    }
}

/// The kernel's tick rate as a build produced it, from the decimal text
/// `WZ_TICKS_PER_SEC` carries. [`ZephyrClock`]'s rate is a type parameter, so a
/// firmware must write it down at compile time, and a constant typed into the
/// firmware is right only while it agrees with the board's
/// `CONFIG_SYS_CLOCK_TICKS_PER_SEC`: the clock then runs fast or slow with every
/// timeout scaled by the error and nothing failing. The board's build hands the
/// Kconfig value to cargo in that variable, and [`tick_hz_from_build!`] reads it
/// here, so there is one number and it is the kernel's.
///
/// A value that is not a positive decimal fitting `u32` stops the compile: no
/// rate is a worse answer than a wrong one.
pub const fn parse_tick_hz(text: &str) -> u32 {
    let digits = text.as_bytes();
    assert!(!digits.is_empty(), "WZ_TICKS_PER_SEC is empty");
    let mut value: u64 = 0;
    let mut at = 0;
    while at < digits.len() {
        let digit = digits[at];
        assert!(
            digit.is_ascii_digit(),
            "WZ_TICKS_PER_SEC is not a decimal number"
        );
        value = value * 10 + (digit - b'0') as u64;
        assert!(
            value <= u32::MAX as u64,
            "WZ_TICKS_PER_SEC does not fit u32"
        );
        at += 1;
    }
    assert!(value > 0, "WZ_TICKS_PER_SEC is zero");
    value as u32
}

/// The tick rate this firmware was built for: `CONFIG_SYS_CLOCK_TICKS_PER_SEC`
/// of the Zephyr build that compiled it, as `deploy/zephyr-common` passes it in
/// `WZ_TICKS_PER_SEC`. The variable is read where the macro is USED, so the
/// firmware crate's own compile sees it and cargo reruns that compile when it
/// changes; a build that does not set it fails to compile.
///
/// ```ignore
/// const TICK_HZ: u32 = wz_runtime_zephyr::tick_hz_from_build!();
/// let clock = wz_runtime_zephyr::ZephyrClock::<TICK_HZ>;
/// ```
#[macro_export]
macro_rules! tick_hz_from_build {
    () => {
        $crate::parse_tick_hz(env!(
            "WZ_TICKS_PER_SEC",
            "WZ_TICKS_PER_SEC is not set: build through the board's west build, \
             which passes CONFIG_SYS_CLOCK_TICKS_PER_SEC"
        ))
    };
}

/// A decimal `u32` (zero allowed), readable at compile time, for the plain integer
/// values a board states in Kconfig (a divider, a wait in milliseconds): the same
/// arrangement as [`parse_tick_hz`] without its refusal of zero, which is a
/// rate-specific rule.
pub const fn parse_u32(text: &str) -> u32 {
    let digits = text.as_bytes();
    assert!(!digits.is_empty(), "a build integer is empty");
    let mut value: u64 = 0;
    let mut at = 0;
    while at < digits.len() {
        let digit = digits[at];
        assert!(
            digit.is_ascii_digit(),
            "a build integer is not a decimal number"
        );
        value = value * 10 + (digit - b'0') as u64;
        assert!(value <= u32::MAX as u64, "a build integer does not fit u32");
        at += 1;
    }
    value as u32
}

/// The integer the board's build named in environment variable `$name`, at
/// compile time. A build that does not set it fails to compile.
#[macro_export]
macro_rules! u32_from_build {
    ($name:literal) => {
        $crate::parse_u32(env!(
            $name,
            concat!($name, " is not set: build through the board's west build")
        ))
    };
}

/// A dotted IPv4 address (`"10.0.0.2"`) as its four octets, readable at compile
/// time, for the build-configuration values a board states in Kconfig and the
/// board's build hands to cargo in an environment variable. The same arrangement
/// as [`parse_tick_hz`]: the address is the board's configuration's, not a
/// constant of the firmware, and a value that is not a valid address stops the
/// compile.
pub const fn parse_ipv4(text: &str) -> [u8; 4] {
    let bytes = text.as_bytes();
    let mut octets = [0u8; 4];
    let mut index = 0;
    let mut value: u32 = 0;
    let mut digits = 0;
    let mut at = 0;
    while at < bytes.len() {
        let c = bytes[at];
        if c == b'.' {
            assert!(digits > 0, "an IPv4 octet is empty");
            assert!(index < 3, "an IPv4 address has four octets");
            octets[index] = value as u8;
            index += 1;
            value = 0;
            digits = 0;
        } else {
            assert!(c.is_ascii_digit(), "an IPv4 address is digits and dots");
            value = value * 10 + (c - b'0') as u32;
            assert!(value <= 255, "an IPv4 octet is above 255");
            digits += 1;
        }
        at += 1;
    }
    assert!(digits > 0, "an IPv4 octet is empty");
    assert!(index == 3, "an IPv4 address has four octets");
    octets[3] = value as u8;
    octets
}

/// A MAC address (`"02:00:5e:00:00:01"`) as its six bytes, readable at compile
/// time: two hex digits per byte, colon separated.
pub const fn parse_mac(text: &str) -> [u8; 6] {
    let bytes = text.as_bytes();
    assert!(
        bytes.len() == 17,
        "a MAC address is six colon-separated hex bytes"
    );
    let mut mac = [0u8; 6];
    let mut i = 0;
    while i < 6 {
        let at = i * 3;
        mac[i] = (hex_digit(bytes[at]) << 4) | hex_digit(bytes[at + 1]);
        if i < 5 {
            assert!(bytes[at + 2] == b':', "MAC bytes are separated by colons");
        }
        i += 1;
    }
    mac
}

const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("a MAC address is hex digits"),
    }
}

/// An address a board has no assigned value for, made from `entropy`: six
/// random bytes with the group bit CLEAR (a unicast address, which is what an
/// interface answers to) and the locally administered bit SET (an address
/// nobody was assigned, which is what one a firmware makes for itself must be).
/// That leaves 46 random bits, so two boards on one network agree with a chance
/// of about one in 7e13.
///
/// A failed draw is returned, never turned into an address: a station address
/// made of whatever the buffer held would be the same one on every board.
pub fn random_station_address<E: wz_session_core::entropy::EntropySource>(
    entropy: &mut E,
) -> Result<[u8; 6], wz_session_core::entropy::EntropyUnavailable> {
    /// Set on a group (multicast or broadcast) address; an interface never has one.
    const GROUP: u8 = 0x01;
    /// Set on an address that was not assigned by the interface's manufacturer.
    const LOCALLY_ADMINISTERED: u8 = 0x02;
    let mut mac = [0u8; 6];
    entropy.try_fill_bytes(&mut mac)?;
    mac[0] = (mac[0] & !GROUP) | LOCALLY_ADMINISTERED;
    Ok(mac)
}

/// The IPv4 address the board's build named in environment variable `$name`, as
/// four octets, at compile time. A build that does not set it fails to compile.
///
/// ```ignore
/// const ADDRESS: [u8; 4] = wz_runtime_zephyr::ipv4_from_build!("WZ_STATIC_IPV4");
/// ```
#[macro_export]
macro_rules! ipv4_from_build {
    ($name:literal) => {
        $crate::parse_ipv4(env!(
            $name,
            concat!($name, " is not set: build through the board's west build")
        ))
    };
}

/// The MAC address the board's build named in environment variable `$name`, as
/// six bytes, at compile time. A build that does not set it fails to compile.
#[macro_export]
macro_rules! mac_from_build {
    ($name:literal) => {
        $crate::parse_mac(env!(
            $name,
            concat!($name, " is not set: build through the board's west build")
        ))
    };
}

/// The Zephyr profile's runtime: the wz-runtime-coop cooperative executor (the
/// SSOT) parameterised by [`ZephyrClock`]. Construct with
/// `CoopRuntime::new(ZephyrClock::<TICK_HZ>)`. NOT a reimplementation — the task
/// pool / waker / timer queue are wz-runtime-coop's, only the clock seam is
/// Zephyr-specific.
pub type ZephyrRuntime<const TICK_HZ: u32> = CoopRuntime<ZephyrClock<TICK_HZ>>;

extern "C" {
    /// R2918 — the board's random source: fill `len` bytes at `buf` and return
    /// 0, or return non-zero when the board cannot produce them. A board serves
    /// it from `sys_rand_get` (what zenoh-pico's Zephyr port calls) or, where it
    /// has one, `sys_csrand_get`.
    fn wzApplicationGetRandom(buf: *mut c_void, len: usize) -> i32;

    /// R2918 — the board's wall clock: fill `*secs` / `*nanos` with the time
    /// since the Unix epoch (UTC, `nanos` below 1e9) and return 1, or return 0
    /// when the board does not know the date (no RTC, SNTP not yet synced). The
    /// same hook and contract the FreeRTOS profile reads, so one board-side
    /// answer serves either RTOS.
    fn wzApplicationGetTimeSinceEpoch(secs: *mut u64, nanos: *mut u32) -> i32;
}

/// R2918 — the session core's [`EntropySource`](wz_session_core::entropy::EntropySource)
/// on this profile: the board's `wzApplicationGetRandom`, asked for the whole
/// buffer in one call. A board that fails the call fails the fill — the cookie
/// nonce and the signing key must never be made of whatever the buffer held.
#[derive(Clone, Copy, Default)]
pub struct ZephyrEntropy;

impl wz_session_core::entropy::EntropySource for ZephyrEntropy {
    fn try_fill_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
        // SAFETY: `buf` is live and writable for its whole length.
        let rc = unsafe { wzApplicationGetRandom(buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if rc != 0 {
            return Err(wz_session_core::entropy::EntropyUnavailable);
        }
        Ok(())
    }
}

/// R2918 — the session core's [`EpochSource`](wz_session_core::epoch::EpochSource)
/// on this profile: the board's `wzApplicationGetTimeSinceEpoch`, read once
/// per call. A board answer of `nanos >= 1e9` is refused rather than
/// normalised, since it means the hook and this seam disagree about the unit.
#[derive(Clone, Copy, Default)]
pub struct ZephyrEpoch;

impl wz_session_core::epoch::EpochSource for ZephyrEpoch {
    fn try_since_epoch(
        &self,
    ) -> Result<wz_session_core::epoch::SinceEpoch, wz_session_core::epoch::EpochUnavailable> {
        let mut secs = 0u64;
        let mut nanos = 0u32;
        // SAFETY: the hook writes one u64 and one u32 through pointers to live
        // locals; the board's implementation is the application's own.
        let rc = unsafe { wzApplicationGetTimeSinceEpoch(&mut secs, &mut nanos) };
        if rc != 1 || nanos >= 1_000_000_000 {
            return Err(wz_session_core::epoch::EpochUnavailable);
        }
        Ok(wz_session_core::epoch::SinceEpoch { secs, nanos })
    }
}

/// Zephyr kernel-heap alignment guarantee for the **direct** `k_malloc` path.
///
/// `k_malloc` calls `sys_heap_noalign_alloc` (kernel/mempool.c) — it does NOT
/// over-align — so the only guarantee is the sys_heap base alignment, which for
/// a SMALL heap (the MCU default, `CONFIG_SYS_HEAP_SMALL_ONLY`) is just
/// `sizeof(void*)` = 4 bytes (heap.c asserts `ret & (big_heap ? 7 : 3) == 0`).
/// So 4, NOT 8 — unlike FreeRTOS's heap_4, which guarantees `portBYTE_ALIGNMENT`
/// = 8 (and is asserted), so `FreertosAllocator` correctly uses 8. Any request
/// with `align > 4` (e.g. a `u64`-bearing struct — including wz-runtime-coop's
/// own timer-queue entries) takes the over-aligned branch below, which aligns
/// up regardless of the `k_malloc` base alignment. Setting this to 8 would hand
/// align-8 allocations a 4-aligned pointer on the default heap = UB.
const HEAP_ALIGN: usize = 4;

/// A [`GlobalAlloc`] bridging Rust's allocator to the Zephyr kernel heap
/// (`k_malloc`/`k_free`, sized by `CONFIG_HEAP_MEM_POOL_SIZE`).
///
/// The deploy binary declares it:
/// `#[global_allocator] static ALLOC: ZephyrAllocator = ZephyrAllocator;`.
/// It lives in this profile crate (not the deploy) because — like the FreeRTOS
/// heap — the Zephyr heap IS the kernel's, so every Zephyr deploy routes Rust
/// allocations through it. One audited bridge, shared. Identical over-alignment
/// scheme to `wz_runtime_freertos::FreertosAllocator`.
pub struct ZephyrAllocator;

unsafe impl GlobalAlloc for ZephyrAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= HEAP_ALIGN {
            // k_malloc guarantees HEAP_ALIGN-aligned blocks — direct.
            // SAFETY: k_malloc(size) returns a kernel-heap block or null on OOM.
            unsafe { k_malloc(layout.size()) as *mut u8 }
        } else {
            // Over-aligned request (rare on this profile): over-allocate, align
            // up, and stash the k_malloc base pointer in the usize slot just
            // below the returned address so `dealloc` can recover it.
            let align = layout.align();
            let total = layout.size() + align + size_of::<usize>();
            // SAFETY: as above; null is handled below.
            let base = unsafe { k_malloc(total) } as usize;
            if base == 0 {
                return core::ptr::null_mut();
            }
            let aligned = (base + size_of::<usize>() + align - 1) & !(align - 1);
            // SAFETY: `aligned - size_of::<usize>() >= base`, inside the block.
            unsafe { *((aligned - size_of::<usize>()) as *mut usize) = base };
            aligned as *mut u8
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.align() <= HEAP_ALIGN {
            // SAFETY: `ptr` came from `k_malloc` in the matching `alloc`.
            unsafe { k_free(ptr as *mut c_void) };
        } else {
            // Recover the stashed k_malloc base pointer written by `alloc`.
            // SAFETY: the over-aligned `alloc` branch wrote the base just below.
            let base = unsafe { *((ptr as usize - size_of::<usize>()) as *mut usize) };
            unsafe { k_free(base as *mut c_void) };
        }
    }
}

/// R2918 — host witnesses for the profile's seams. On the host there is no
/// Zephyr kernel, so each symbol a seam calls is DEFINED here, answering from a
/// static the test sets: the kernel tick for [`ZephyrClock`], and the two board
/// hooks for [`ZephyrEntropy`] and [`ZephyrEpoch`]. What is under test is the
/// seam's own arithmetic and failure handling, which is the same code the QEMU
/// image runs against the real kernel and board. (The socket link in [`net`]
/// has no such witness: its symbols are the host C library's own names, so it
/// is witnessed on target, by Layer Qz.)
#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, AtomicU64, AtomicU8, Ordering};
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
    use wz_session_core::epoch::{EpochSource, EpochUnavailable, SinceEpoch};

    static TICKS: AtomicI64 = AtomicI64::new(0);
    static RANDOM_BYTE: AtomicU8 = AtomicU8::new(0);
    static RANDOM_RC: AtomicI32 = AtomicI32::new(0);
    static EPOCH_SECS: AtomicU64 = AtomicU64::new(0);
    static EPOCH_NANOS: AtomicU32 = AtomicU32::new(0);
    static EPOCH_RC: AtomicI32 = AtomicI32::new(1);

    #[no_mangle]
    extern "C" fn sys_clock_tick_get() -> i64 {
        TICKS.load(Ordering::SeqCst)
    }

    #[no_mangle]
    extern "C" fn wzApplicationGetRandom(buf: *mut c_void, len: usize) -> i32 {
        // SAFETY: `ZephyrEntropy` passes a live buffer of `len` bytes.
        let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
        for b in out {
            *b = RANDOM_BYTE.fetch_add(1, Ordering::SeqCst);
        }
        RANDOM_RC.load(Ordering::SeqCst)
    }

    #[no_mangle]
    extern "C" fn wzApplicationGetTimeSinceEpoch(secs: *mut u64, nanos: *mut u32) -> i32 {
        // SAFETY: `ZephyrEpoch` passes pointers to live locals.
        unsafe {
            *secs = EPOCH_SECS.load(Ordering::SeqCst);
            *nanos = EPOCH_NANOS.load(Ordering::SeqCst);
        }
        EPOCH_RC.load(Ordering::SeqCst)
    }

    /// The rate a build hands over is read as the number it spells, in a const
    /// context (the firmware writes it as a type parameter), and anything that is
    /// not a positive decimal fitting `u32` is refused rather than guessed.
    #[test]
    fn a_build_tick_rate_is_read_exactly_and_a_bad_one_is_refused() {
        const HUNDRED: u32 = parse_tick_hz("100");
        assert_eq!(HUNDRED, 100);
        assert_eq!(parse_tick_hz("1000"), 1000);
        assert_eq!(parse_tick_hz("4294967295"), u32::MAX);
        for bad in ["", "0", "10 0", "1e2", "-5", "4294967296", "0x64"] {
            let refused = std::panic::catch_unwind(|| parse_tick_hz(bad)).is_err();
            assert!(refused, "{bad:?} must not be accepted as a tick rate");
        }
    }

    #[test]
    fn a_build_integer_is_read_exactly_and_zero_is_allowed() {
        const WAIT: u32 = parse_u32("5000");
        assert_eq!(WAIT, 5000);
        assert_eq!(parse_u32("0"), 0, "unlike a tick rate, zero is a value");
        assert_eq!(parse_u32("4294967295"), u32::MAX);
        for bad in ["", "-1", "1 0", "0x10", "4294967296", "1.5"] {
            let refused = std::panic::catch_unwind(|| parse_u32(bad)).is_err();
            assert!(refused, "{bad:?} must not be accepted as an integer");
        }
    }

    /// The address and the MAC a board's build names are read at compile time as
    /// the numbers they spell, and anything that is not one is refused.
    #[test]
    fn a_build_address_and_mac_are_read_exactly_and_a_bad_one_is_refused() {
        const ADDRESS: [u8; 4] = parse_ipv4("10.0.2.15");
        assert_eq!(ADDRESS, [10, 0, 2, 15]);
        assert_eq!(parse_ipv4("255.255.255.0"), [255, 255, 255, 0]);
        assert_eq!(parse_ipv4("0.0.0.0"), [0, 0, 0, 0]);
        for bad in [
            "",
            "1.2.3",
            "1.2.3.4.5",
            "1..2.3",
            "256.1.1.1",
            "a.b.c.d",
            "1.2.3.",
            ".1.2.3",
        ] {
            let refused = std::panic::catch_unwind(|| parse_ipv4(bad)).is_err();
            assert!(refused, "{bad:?} must not be accepted as an address");
        }

        const MAC: [u8; 6] = parse_mac("02:00:5e:00:00:01");
        assert_eq!(MAC, [0x02, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        assert_eq!(
            parse_mac("FF:aa:Bb:00:10:0F"),
            [0xFF, 0xAA, 0xBB, 0x00, 0x10, 0x0F]
        );
        for bad in [
            "",
            "02:00:5e:00:00",
            "02-00-5e-00-00-01",
            "02:00:5e:00:00:0g",
            "02:00:5e:00:00:001",
        ] {
            let refused = std::panic::catch_unwind(|| parse_mac(bad)).is_err();
            assert!(refused, "{bad:?} must not be accepted as a MAC");
        }
    }

    #[test]
    fn the_clock_converts_kernel_ticks_to_microseconds_at_the_tick_rate() {
        TICKS.store(1234, Ordering::SeqCst);
        assert_eq!(ZephyrClock::<100>.now_us(), 12_340_000);
        assert_eq!(ZephyrClock::<1000>.now_us(), 1_234_000);
        TICKS.store(i64::from(u32::MAX) * 10, Ordering::SeqCst);
        assert_eq!(
            ZephyrClock::<100>.now_us(),
            u64::from(u32::MAX) * 100_000,
            "a tick count past 32 bits converts without wrapping"
        );
    }

    /// The entropy seam hands the board the whole buffer, and a board that
    /// reports failure fails the fill. One test, because the hook's statics
    /// are shared.
    #[test]
    fn entropy_fills_from_the_board_hook_and_fails_closed() {
        RANDOM_RC.store(0, Ordering::SeqCst);
        RANDOM_BYTE.store(0x10, Ordering::SeqCst);
        let mut buf = [0u8; 5];
        ZephyrEntropy
            .try_fill_bytes(&mut buf)
            .expect("the hook answers 0");
        assert_eq!(buf, [0x10, 0x11, 0x12, 0x13, 0x14]);

        RANDOM_RC.store(-5, Ordering::SeqCst);
        assert_eq!(
            ZephyrEntropy.try_fill_bytes(&mut buf),
            Err(EntropyUnavailable),
            "a non-zero answer from the board fails the fill"
        );
        RANDOM_RC.store(0, Ordering::SeqCst);
    }

    /// The epoch seam returns the board's instant, refuses a failed read and a
    /// nanosecond count outside a second, and feeds the NTP64 a timestamp
    /// carries. One test, because the hook's statics are shared.
    #[test]
    fn epoch_reads_the_board_clock_and_refuses_what_it_cannot_trust() {
        EPOCH_RC.store(1, Ordering::SeqCst);
        EPOCH_SECS.store(1_700_000_000, Ordering::SeqCst);
        EPOCH_NANOS.store(250_000_000, Ordering::SeqCst);
        assert_eq!(
            ZephyrEpoch.try_since_epoch(),
            Ok(SinceEpoch {
                secs: 1_700_000_000,
                nanos: 250_000_000
            })
        );
        assert_eq!(
            ZephyrEpoch.try_now_ntp64().map(|t| t.to_millis()),
            Ok(1_700_000_000_250)
        );

        EPOCH_NANOS.store(1_000_000_000, Ordering::SeqCst);
        assert_eq!(
            ZephyrEpoch.try_since_epoch(),
            Err(EpochUnavailable),
            "a nanosecond count of a whole second is refused"
        );

        EPOCH_NANOS.store(0, Ordering::SeqCst);
        EPOCH_RC.store(0, Ordering::SeqCst);
        assert_eq!(
            ZephyrEpoch.try_since_epoch(),
            Err(EpochUnavailable),
            "a board that does not know the date says so"
        );
        EPOCH_RC.store(1, Ordering::SeqCst);
    }

    /// A source that fills with `byte`, then `byte + 1`, and so on, per call.
    struct Steps(u8);

    impl EntropySource for Steps {
        fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            buf.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    /// A source that cannot draw, and leaves the buffer as it found it.
    struct Dry;

    impl EntropySource for Dry {
        fn try_fill_bytes(&mut self, _buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            Err(EntropyUnavailable)
        }
    }

    /// Whatever the draw was, the address is one an interface can answer to and
    /// nobody was assigned: the group bit is clear and the local bit is set, and
    /// the other forty-six bits are the draw's own.
    #[test]
    fn a_made_up_station_address_is_unicast_and_locally_administered() {
        for byte in [0x00u8, 0x01, 0x02, 0x03, 0xFC, 0xFD, 0xFE, 0xFF] {
            let mac = random_station_address(&mut Steps(byte)).expect("the draw succeeds");
            assert_eq!(mac[0] & 0x01, 0, "{byte:#04x}: not a group address");
            assert_eq!(mac[0] & 0x02, 0x02, "{byte:#04x}: locally administered");
            assert_eq!(
                mac[0] & !0x03,
                byte & !0x03,
                "{byte:#04x}: the other six bits of the first octet are the draw's"
            );
            assert_eq!(mac[1..], [byte; 5], "the rest is the draw untouched");
        }
    }

    /// Two draws are two addresses, which is the whole of why the address is
    /// drawn and not typed; and a source that cannot draw gives no address
    /// rather than the zeroes it left in the buffer.
    #[test]
    fn two_draws_make_two_addresses_and_a_dry_source_makes_none() {
        let mut source = Steps(0x10);
        let first = random_station_address(&mut source).unwrap();
        let second = random_station_address(&mut source).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            random_station_address(&mut Dry),
            Err(EntropyUnavailable),
            "a failed draw is not an address"
        );
    }
}
