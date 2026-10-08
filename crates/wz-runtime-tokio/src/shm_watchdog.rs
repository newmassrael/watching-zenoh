// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3039 (`transport-shm`) -- the watchdog: how the holders of a shared-memory
//! chunk say they are alive, and how the chunk's provider notices that none is.
//!
//! # The protocol, from upstream
//!
//! Every header slot of a metadata segment has one BIT in the segment's watchdog
//! array: bit `slot % 64` of word `slot / 64`
//! (`commons/zenoh-shm/src/metadata/segment.rs` @
//! `let watchdog_index = index / 64;`). Two sides use it and never meet:
//!
//! * a HOLDER (the owner of a buffer, and every receiver that has one linked)
//!   CONFIRMS its bit: it sets it. It does so at once when it attaches, "confirm
//!   ASAP", and again every 50 ms for as long as it holds
//!   (`commons/zenoh-shm/src/watchdog/confirmator.rs` @
//!   `WatchdogConfirmator::new(Duration::from_millis(50));`);
//! * the PROVIDER that allocated the chunk VALIDATES it every 100 ms: it clears
//!   the bit and reads what it was. A bit that was not set means nobody
//!   confirmed in the whole window, so the chunk's header is marked
//!   invalidated and the provider stops watching it
//!   (`commons/zenoh-shm/src/watchdog/validator.rs` @
//!   `WatchdogValidator::new(Duration::from_millis(100));`).
//!
//! What the invalidation is FOR is a reader's refusal: a receiver that finds the
//! header invalidated does not trust the buffer. It does not reclaim the chunk,
//! which upstream's default collection leaves to the reference count alone, so a
//! holder that dies without releasing keeps its chunk out of the pool, which is
//! the arm upstream calls the unsafe policy and wz does not take.
//!
//! # What this module owns, and what it does not
//!
//! The CONFIRM half, whole: a `Confirmator` tracks the bits this process holds
//! and a background thread confirms them. The VALIDATE half is the provider's
//! (it needs the provider's store), so this module only calls it on the same
//! thread and the same clock: one thread, ticking at the confirm interval, with
//! every second tick also validating, which keeps a holder's confirmation and a
//! provider's validation in the 1:2 ratio upstream's two intervals have.
//!
//! # Time is a parameter of the tests, not of the code
//!
//! The ticks are plain functions (`Confirmator::tick`, and the provider's
//! `validate_tick`), so a test drives a window by calling them and never sleeps
//! to make one pass. The thread exists to call them on a clock, and starts the
//! first time anything here is used, so a process that never touches shared
//! memory never pays for it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// How often a holder confirms its bits: upstream's confirmator period.
pub const CONFIRM_INTERVAL: Duration = Duration::from_millis(50);

/// How often a provider validates the chunks it allocated: upstream's validator
/// period. Every this-many-over-[`CONFIRM_INTERVAL`] th tick of the thread.
pub const VALIDATE_INTERVAL: Duration = Duration::from_millis(100);

/// One chunk's watchdog bit: the word it lives in, the mask that picks it, and
/// the mapping that word is in.
///
/// Upstream extends the word's lifetime to `'static` with `unsafe`; this keeps
/// the mapping alive instead, by holding a reference to whatever owns it, so a
/// bit cannot outlive the memory it names.
pub(crate) struct WatchdogBit {
    word: *const AtomicU64,
    mask: u64,
    /// Keeps the mapping `word` points into alive while this value exists.
    _mapping: Arc<dyn Send + Sync>,
}

// SAFETY: `word` points into a shared-memory mapping that `_mapping` keeps
// alive and mapped for as long as this value lives, the pointee is an atomic,
// and the only operations made through it are atomic read-modify-writes.
unsafe impl Send for WatchdogBit {}
// SAFETY: as for `Send`; a shared reference reaches the atomic and nothing else.
unsafe impl Sync for WatchdogBit {}

impl WatchdogBit {
    /// A bit in `word`, picked by `mask`, kept valid by `mapping`.
    ///
    /// The caller passes the word it got out of `mapping` itself, which is what
    /// makes the pointer valid for as long as `mapping` is held.
    pub(crate) fn new(word: &AtomicU64, mask: u64, mapping: Arc<dyn Send + Sync>) -> Self {
        Self {
            word: word as *const AtomicU64,
            mask,
            _mapping: mapping,
        }
    }

    fn atomic(&self) -> &AtomicU64 {
        // SAFETY: `word` was taken from a reference into the mapping `_mapping`
        // keeps alive, and that mapping is not unmapped while this value exists.
        unsafe { &*self.word }
    }

    /// Say this holder is alive: set the bit.
    pub(crate) fn confirm(&self) {
        self.atomic().fetch_or(self.mask, Ordering::SeqCst);
    }

    /// Clear the bit and return what it was: upstream's `validate`. Non-zero means
    /// someone confirmed since the last time it was cleared.
    pub(crate) fn validate(&self) -> u64 {
        self.atomic().fetch_and(!self.mask, Ordering::SeqCst) & self.mask
    }

    /// Which bit this is, as a key two holders of the same chunk share.
    fn key(&self) -> (usize, u64) {
        (self.word as usize, self.mask)
    }
}

/// The bits this process holds, and the count of holders of each: a bit is
/// confirmed for as long as anyone in this process holds its chunk, however
/// many do.
struct Tracked {
    bit: WatchdogBit,
    holders: u32,
}

/// Confirms, on every tick, each bit this process holds.
pub(crate) struct Confirmator {
    tracked: Mutex<BTreeMap<(usize, u64), Tracked>>,
}

impl Confirmator {
    fn new() -> Self {
        Self {
            tracked: Mutex::new(BTreeMap::new()),
        }
    }

    /// Confirm `bit` now and keep confirming it until the returned guard drops.
    ///
    /// Now, and not at the next tick: a validation that came between an owner
    /// handing a chunk over and the first tick would find the bit unset and
    /// invalidate a chunk its holder had only just attached to, which is why
    /// upstream confirms "ASAP" before it does anything else.
    pub(crate) fn add(&'static self, bit: WatchdogBit) -> Confirmed {
        bit.confirm();
        let key = bit.key();
        if let Ok(mut tracked) = self.tracked.lock() {
            tracked
                .entry(key)
                .and_modify(|t| t.holders += 1)
                .or_insert(Tracked { bit, holders: 1 });
        }
        Confirmed {
            key,
            confirmator: self,
        }
    }

    /// One confirmation pass over everything held. The thread calls this every
    /// [`CONFIRM_INTERVAL`]; a test calls it to make a window pass.
    pub(crate) fn tick(&self) {
        if let Ok(tracked) = self.tracked.lock() {
            for t in tracked.values() {
                t.bit.confirm();
            }
        }
    }

    /// How many distinct bits are being confirmed. A diagnostic: the witness that what a sender
    /// kept confirmed for a receiver is let go of once the receiver has acknowledged it.
    pub(crate) fn held(&self) -> usize {
        self.tracked.lock().map(|t| t.len()).unwrap_or(0)
    }

    fn remove(&self, key: (usize, u64)) {
        if let Ok(mut tracked) = self.tracked.lock() {
            if let Some(t) = tracked.get_mut(&key) {
                t.holders -= 1;
                if t.holders == 0 {
                    tracked.remove(&key);
                }
            }
        }
    }
}

/// A holder's confirmation of one bit, kept up until this drops: upstream's
/// `ConfirmedDescriptor`. Dropping it is a holder letting go.
pub(crate) struct Confirmed {
    key: (usize, u64),
    confirmator: &'static Confirmator,
}

impl Drop for Confirmed {
    fn drop(&mut self) {
        self.confirmator.remove(self.key);
    }
}

fn instance() -> &'static Confirmator {
    static CONFIRMATOR: OnceLock<Confirmator> = OnceLock::new();
    CONFIRMATOR.get_or_init(Confirmator::new)
}

/// The process's confirmator, starting the thread that ticks it the first time
/// anything asks for it.
pub(crate) fn confirmator() -> &'static Confirmator {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        // A thread that cannot be spawned leaves the chunks confirmed once, at
        // attach, and never again: they would be invalidated after a window, which
        // is the honest result of a process that cannot keep its promise to confirm.
        let _ = std::thread::Builder::new()
            .name("wz-shm-watchdog".to_owned())
            .spawn(run);
    });
    instance()
}

/// The thread body: confirm every [`CONFIRM_INTERVAL`], and every second tick
/// also validate what this process provides and let go of mappings of segments
/// that are gone.
fn run() {
    let confirmator = instance();
    let validate_every = (VALIDATE_INTERVAL.as_millis() / CONFIRM_INTERVAL.as_millis()).max(1);
    let mut tick: u128 = 0;
    loop {
        std::thread::sleep(CONFIRM_INTERVAL);
        confirmator.tick();
        tick += 1;
        if tick % validate_every == 0 {
            crate::shm_provider::validate_tick();
            crate::shm_provider::sweep_peer_segments();
            #[cfg(feature = "session-extshm")]
            crate::shm_auth_segment::poll_tx_handoffs();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// A word of its own to confirm, kept alive by a unit value standing in for the
    /// mapping, so the protocol's arithmetic is tested without a segment.
    fn bit(word: &'static AtomicU64, mask: u64) -> WatchdogBit {
        WatchdogBit::new(word, mask, Arc::new(()))
    }

    /// Confirming sets exactly the bit, and validating reads what it was and
    /// clears it, which is the whole of upstream's two halves.
    #[test]
    fn confirm_sets_the_bit_and_validate_reads_and_clears_it() {
        static WORD: AtomicU64 = AtomicU64::new(0);
        let a = bit(&WORD, 1 << 3);
        let b = bit(&WORD, 1 << 9);

        a.confirm();
        assert_eq!(WORD.load(Ordering::SeqCst), 1 << 3, "only a's bit");
        b.confirm();
        assert_eq!(WORD.load(Ordering::SeqCst), (1 << 3) | (1 << 9));

        let old = a.validate();
        assert_eq!(old, 1 << 3, "validating reads the bit that was set");
        assert_eq!(WORD.load(Ordering::SeqCst), 1 << 9, "and clears only it");
    }

    /// A bit held by two holders is confirmed once and stays confirmed until the
    /// LAST of them lets go.
    #[test]
    fn a_bit_is_tracked_until_its_last_holder_lets_go() {
        static WORD: AtomicU64 = AtomicU64::new(0);
        let confirmator: &'static Confirmator = Box::leak(Box::new(Confirmator::new()));

        let first = confirmator.add(bit(&WORD, 1 << 1));
        let second = confirmator.add(bit(&WORD, 1 << 1));
        assert_eq!(confirmator.held(), 1, "one bit, two holders");

        drop(first);
        assert_eq!(confirmator.held(), 1, "still held by the second");
        WORD.store(0, Ordering::SeqCst);
        confirmator.tick();
        assert_eq!(WORD.load(Ordering::SeqCst), 1 << 1, "and still confirmed");

        drop(second);
        assert_eq!(confirmator.held(), 0);
        WORD.store(0, Ordering::SeqCst);
        confirmator.tick();
        assert_eq!(
            WORD.load(Ordering::SeqCst),
            0,
            "no one holds it, so no one confirms"
        );
    }

    /// Attaching confirms AT ONCE, before any tick: a validation between a hand-over
    /// and the first tick must not find the bit unset.
    #[test]
    fn attaching_confirms_before_the_first_tick() {
        static WORD: AtomicU64 = AtomicU64::new(0);
        let confirmator: &'static Confirmator = Box::leak(Box::new(Confirmator::new()));
        let _held = confirmator.add(bit(&WORD, 1 << 5));
        assert_eq!(WORD.load(Ordering::SeqCst), 1 << 5);
    }
}
