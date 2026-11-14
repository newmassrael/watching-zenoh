// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the cooperative engine is given by the system this build runs on: the links its sessions
//! open, the clock that times them, the random source a zid is minted from, and the wall clock a
//! timestamp reads (`docs/upstream-parity.md` section 5a, E2).
//!
//! The engine names none of them: `CoopEngine::open` takes the four as values, so the ABI hands it
//! the ones of its host, in one place. On a host (`engine-coop`) they are `wz-runtime-posix`'s, the
//! process's sockets and clocks; in a Zephyr image (`os-zephyr`, without `std`) they are
//! `wz-runtime-zephyr`'s, the kernel's own sockets, its tick, and the board's random source and
//! wall clock. A build that names both keeps the host's, as the platform exports' host layer does
//! (`os`). Both stacks dial `udp/` and `tcp/` and bind on every interface of the node, so a config
//! reads the same on either; a `tls/` dial is the host's (`tls-mbedtls`), which an image refuses as
//! a stack without a secure channel does.

#[cfg(feature = "engine-coop")]
mod host {
    /// The host's sockets as the session's links.
    pub(crate) type Links = wz_runtime_posix::links::PosixLinks;
    /// The host's monotonic clock.
    pub(crate) type Clock = wz_runtime_posix::PosixClock;
    /// The host kernel's random source.
    pub(crate) type Entropy = wz_runtime_posix::PosixEntropy;
    /// The host's wall clock.
    pub(crate) type Epoch = wz_runtime_posix::PosixEpoch;

    /// Links bound on every interface of the host, whose `tcp/` dial is the host's.
    pub(crate) fn links() -> Links {
        Links::new([0; 4], wz_runtime_posix::stream::PosixTcpDial)
    }

    pub(crate) fn clock() -> Clock {
        wz_runtime_posix::PosixClock
    }

    pub(crate) fn entropy() -> Entropy {
        wz_runtime_posix::PosixEntropy
    }

    pub(crate) fn epoch() -> Epoch {
        wz_runtime_posix::PosixEpoch
    }
}

#[cfg(all(
    feature = "os-zephyr",
    not(feature = "engine-coop"),
    not(feature = "std")
))]
mod host {
    /// The kernel's tick rate as the image's build states it (`CONFIG_SYS_CLOCK_TICKS_PER_SEC`,
    /// handed to cargo by `deploy/zephyr-common/wz_zephyr_board.cmake`), so the clock is the
    /// kernel's and not a number written here.
    const TICK_HZ: u32 = wz_runtime_zephyr::tick_hz_from_build!();

    /// Zephyr's datagram and stream sockets as the session's links.
    pub(crate) type Links = wz_runtime_zephyr::ZephyrIpLinks;
    /// The kernel's tick count.
    pub(crate) type Clock = wz_runtime_zephyr::ZephyrClock<TICK_HZ>;
    /// The board's random source (`wzApplicationGetRandom`), which pico's Zephyr backend reads
    /// as `sys_rand_get`.
    pub(crate) type Entropy = wz_runtime_zephyr::ZephyrEntropy;
    /// The board's wall clock (`wzApplicationGetTimeSinceEpoch`).
    pub(crate) type Epoch = wz_runtime_zephyr::ZephyrEpoch;

    /// Links bound on every interface of the node, as pico's Zephyr links bind (the stack picks
    /// the source address of each dial), whose `tcp/` dial is Zephyr's stream socket.
    pub(crate) fn links() -> Links {
        Links::new([0; 4], wz_runtime_zephyr::stream::ZephyrTcpDial)
    }

    pub(crate) fn clock() -> Clock {
        wz_runtime_zephyr::ZephyrClock::<TICK_HZ>
    }

    pub(crate) fn entropy() -> Entropy {
        wz_runtime_zephyr::ZephyrEntropy
    }

    pub(crate) fn epoch() -> Epoch {
        wz_runtime_zephyr::ZephyrEpoch
    }
}

pub(crate) use host::*;

// A host build's answers, read as the ABI reads them. The open over the links is the engine's
// tests' and the round trips' (`tests/`), which dial through `links()` on every cooperative build.
#[cfg(all(test, feature = "engine-coop"))]
mod tests {
    use super::*;

    use wz_session_core::entropy::EntropySource;
    use wz_session_core::epoch::EpochSource;

    #[test]
    fn the_hosts_wall_clock_is_past_the_epoch_a_timestamp_starts_from() {
        let now = epoch().try_now_ntp64().expect("a host knows the date");
        assert_ne!(now.as_word(), 0);
    }

    #[test]
    fn the_hosts_random_source_fills_what_a_zid_is_minted_from() {
        let mut zid = [0u8; 16];
        entropy()
            .try_fill_bytes(&mut zid)
            .expect("a host has a random source");
        assert_ne!(zid, [0u8; 16], "sixteen random bytes are not all zero");
    }
}
