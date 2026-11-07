// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `datagram-fragment-pacing` policy at a tokio datagram writer.
//!
//! The rule is [`wz_session_core::fragment_pacing::FragmentPacer`]; this holds the clock it asks
//! for (tokio's, so a test under paused time drives it without waiting) and answers a writer
//! with how long to wait. A writer asks before each datagram and notes the write after it:
//!
//! ```ignore
//! let mut pacing = DatagramPacing::of_build();
//! while let Some(datagram) = queue.next_wire().await {
//!     if let Some(wait) = pacing.due(&datagram) {
//!         queue.pause(wait).await;
//!     }
//!     socket.send(&datagram).await?;
//!     pacing.wrote();
//! }
//! ```
//!
//! A build with the policy off holds no pacer, and `due` answers `None` without reading a clock.

use std::time::Duration;
use tokio::time::Instant;
use wz_session_core::fragment_pacing::FragmentPacer;

/// A writer's pacing, and the clock it paces by.
#[derive(Debug)]
pub struct DatagramPacing {
    pacer: Option<FragmentPacer>,
    started: Instant,
}

impl DatagramPacing {
    /// The pacing the build's policy states: none when it is off.
    pub fn of_build() -> Self {
        Self::with(FragmentPacer::of_build())
    }

    /// The pacing of `pacer`, or none. What a test that names a value uses.
    pub fn with(pacer: Option<FragmentPacer>) -> Self {
        Self {
            pacer,
            started: Instant::now(),
        }
    }

    fn now_us(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    /// How long to wait before writing `datagram`, or `None` to write it at once.
    pub fn due(&mut self, datagram: &[u8]) -> Option<Duration> {
        let now = self.now_us();
        let wait = self.pacer.as_mut()?.wait_before(datagram, now);
        (wait > 0).then(|| Duration::from_micros(wait))
    }

    /// Note that the datagram asked about last has been written.
    pub fn wrote(&mut self) {
        let now = self.now_us();
        if let Some(pacer) = self.pacer.as_mut() {
            pacer.wrote(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAGMENT: [u8; 2] = [0x46, 0];
    const FRAME: [u8; 2] = [0x05, 0];

    fn paced(burst: u32, gap_ms: u64) -> DatagramPacing {
        DatagramPacing::with(Some(FragmentPacer::new(burst, gap_ms * 1000)))
    }

    /// The policy off: no datagram is ever asked to wait, whatever it is, and no clock is read.
    #[tokio::test(start_paused = true)]
    async fn with_pacing_off_no_datagram_waits() {
        let mut pacing = DatagramPacing::with(None);
        for _ in 0..10 {
            assert_eq!(pacing.due(&FRAGMENT), None);
            pacing.wrote();
        }
    }

    /// The policy on, on tokio's clock, paused so that every time is exact: a burst of two
    /// leaves together, the third waits the gap, and time already spent counts toward it.
    #[tokio::test(start_paused = true)]
    async fn with_pacing_on_the_wait_is_the_gap_less_the_time_already_spent() {
        let ms = std::time::Duration::from_millis;
        let mut pacing = paced(2, 100);
        for _ in 0..2 {
            assert_eq!(pacing.due(&FRAGMENT), None);
            pacing.wrote();
        }
        assert_eq!(pacing.due(&FRAGMENT), Some(ms(100)));
        // The writer slept 30 ms of it, then was told to go on: 70 remain.
        tokio::time::advance(ms(30)).await;
        let mut again = paced(1, 100);
        assert_eq!(again.due(&FRAGMENT), None);
        again.wrote();
        tokio::time::advance(ms(30)).await;
        assert_eq!(again.due(&FRAGMENT), Some(ms(70)));
        // And one that came after the gap has passed waits no more.
        again.wrote();
        tokio::time::advance(ms(150)).await;
        assert_eq!(again.due(&FRAGMENT), None);
        // A datagram that is not a fragment is never made to wait, and starts the run again.
        again.wrote();
        assert_eq!(again.due(&FRAME), None);
        assert_eq!(again.due(&FRAGMENT), None);
    }
}
