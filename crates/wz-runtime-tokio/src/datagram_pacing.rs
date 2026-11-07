// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `datagram-fragment-pacing` policy at a tokio datagram writer.
//!
//! The rule is [`wz_session_core::fragment_pacing::FragmentPacer`]; this holds the clock it asks
//! for (tokio's, so a test under paused time drives it without waiting) and waits in the writer.
//! A writer waits before each datagram and notes the write after it:
//!
//! ```ignore
//! let mut pacing = <OfBuild as Pacing>::of_build();
//! while let Some(datagram) = queue.next_wire().await {
//!     pacing.before(&datagram, |wait| queue.pause(wait)).await;
//!     socket.send(&datagram).await?;
//!     pacing.wrote();
//! }
//! ```
//!
//! # A type, not a value
//!
//! The policy changes the shape of a writer, not a number in it: on, a writer holds a clock and
//! waits between two writes; off, it does neither. So it is a strategy type and not a field that
//! both builds carry (C3 of `docs/build-configuration.md`): a writer is generic over [`Pacing`],
//! and the writers of a build take [`OfBuild`], which the build's policy selects. Off, upstream's
//! behaviour, that is [`Unpaced`], whose wait is a future that is ready at once and never calls
//! the writer's way to wait, so a build with the policy off links no pacer, no clock and no wait
//! of a writer. A test names [`Paced`] or [`Unpaced`] itself, so one binary holds both.

use core::future::{Future, Ready};
use core::pin::Pin;
use core::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;
use wz_session_core::fragment_pacing::FragmentPacer;
use wz_session_core::policy::SessionPolicy;

/// How a datagram writer paces what it writes.
pub trait Pacing: Send + 'static {
    /// What a writer awaits before a datagram, made of `F`, the future of its own way to wait.
    /// A named type and not an opaque one, so that a writer's future is `Send` by the bound
    /// stated here whatever the lifetime its way to wait borrows.
    type Wait<F: Future<Output = ()> + Send>: Future<Output = ()> + Send;

    /// The pacing this build states for the type: [`Paced`] takes the build's burst and gap.
    fn of_build() -> Self;

    /// Wait as long as `datagram` is due, by `wait`: the writer's own way to wait, which is
    /// called only when there is a wait (a unicast writer's ends on a seal, so teardown never
    /// waits out a gap). Call it once for each datagram, before writing it.
    fn before<F: Future<Output = ()> + Send>(
        &mut self,
        datagram: &[u8],
        wait: impl FnOnce(Duration) -> F,
    ) -> Self::Wait<F>;

    /// Note that the datagram waited for last has been written.
    fn wrote(&mut self);
}

/// Datagrams written as fast as the socket takes them, as upstream writes them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Unpaced;

impl Pacing for Unpaced {
    type Wait<F: Future<Output = ()> + Send> = Ready<()>;

    fn of_build() -> Self {
        Self
    }

    #[inline]
    fn before<F: Future<Output = ()> + Send>(
        &mut self,
        _datagram: &[u8],
        _wait: impl FnOnce(Duration) -> F,
    ) -> Ready<()> {
        core::future::ready(())
    }

    #[inline]
    fn wrote(&mut self) {}
}

/// The fragments of a message written in bursts, a gap apart, on tokio's clock.
#[derive(Debug)]
pub struct Paced {
    pacer: FragmentPacer,
    started: Instant,
}

impl Paced {
    /// The pacing of `pacer`. What a test that names a value uses.
    pub fn new(pacer: FragmentPacer) -> Self {
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
        let wait = self.pacer.wait_before(datagram, now);
        (wait > 0).then(|| Duration::from_micros(wait))
    }
}

impl Pacing for Paced {
    type Wait<F: Future<Output = ()> + Send> = PacedWait<F>;

    fn of_build() -> Self {
        Self::new(FragmentPacer::of_build())
    }

    fn before<F: Future<Output = ()> + Send>(
        &mut self,
        datagram: &[u8],
        wait: impl FnOnce(Duration) -> F,
    ) -> PacedWait<F> {
        PacedWait(self.due(datagram).map(wait))
    }

    fn wrote(&mut self) {
        let now = self.now_us();
        self.pacer.wrote(now);
    }
}

/// The wait of a [`Paced`] writer before one datagram: the writer's own wait when the datagram
/// is due later, nothing when it is due now.
#[derive(Debug)]
pub struct PacedWait<F>(Option<F>);

impl<F: Future<Output = ()>> Future for PacedWait<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // SAFETY: the wait is pinned structurally: `PacedWait` has no `Drop`, is not `Unpin`
        // unless `F` is, and never moves the field out or replaces it once pinned.
        let wait = unsafe { self.map_unchecked_mut(|this| &mut this.0) };
        match wait.as_pin_mut() {
            Some(wait) => wait.poll(cx),
            None => Poll::Ready(()),
        }
    }
}

/// The policy's value as a type, for [`Select`] to name the pacing of.
pub struct Policy<const ON: bool>;

/// The pacing a value of the policy stands for.
pub trait Select {
    /// The writers' pacing.
    type Pacing: Pacing;
}

impl Select for Policy<false> {
    type Pacing = Unpaced;
}

impl Select for Policy<true> {
    type Pacing = Paced;
}

/// The pacing of this build's writers, by its `datagram-fragment-pacing` policy.
pub type OfBuild =
    <Policy<{ SessionPolicy::from_build().datagram_fragment_pacing }> as Select>::Pacing;

#[cfg(test)]
mod tests {
    use super::*;
    use core::any::TypeId;

    const FRAGMENT: [u8; 2] = [0x46, 0];
    const FRAME: [u8; 2] = [0x05, 0];

    fn paced(burst: u32, gap_ms: u64) -> Paced {
        Paced::new(FragmentPacer::new(burst, gap_ms * 1000))
    }

    /// Each value of the policy names its pacing, and the build's is the one its value names.
    #[test]
    fn the_policy_names_the_pacing() {
        assert_eq!(
            TypeId::of::<<Policy<false> as Select>::Pacing>(),
            TypeId::of::<Unpaced>()
        );
        assert_eq!(
            TypeId::of::<<Policy<true> as Select>::Pacing>(),
            TypeId::of::<Paced>()
        );
        let on = SessionPolicy::from_build().datagram_fragment_pacing;
        let expected = if on {
            TypeId::of::<Paced>()
        } else {
            TypeId::of::<Unpaced>()
        };
        assert_eq!(TypeId::of::<OfBuild>(), expected);
    }

    /// The policy off: no datagram ever waits, whatever it is, and the writer's way to wait is
    /// never called.
    #[tokio::test(start_paused = true)]
    async fn with_pacing_off_no_datagram_waits() {
        let mut pacing = Unpaced;
        let mut waited = 0;
        for _ in 0..10 {
            pacing
                .before(&FRAGMENT, |_| {
                    waited += 1;
                    async {}
                })
                .await;
            pacing.wrote();
        }
        assert_eq!(waited, 0);
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

    /// The policy on, through the writer's wait: the wait is called with what is due, and only
    /// then.
    #[tokio::test(start_paused = true)]
    async fn with_pacing_on_the_writer_waits_what_is_due() {
        let mut pacing = paced(1, 100);
        let mut waits = Vec::new();
        for _ in 0..2 {
            pacing
                .before(&FRAGMENT, |due| {
                    waits.push(due);
                    async {}
                })
                .await;
            pacing.wrote();
        }
        assert_eq!(waits, [std::time::Duration::from_millis(100)]);
    }
}
