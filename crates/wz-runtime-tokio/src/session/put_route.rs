// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a put owes this session's peer, remembered so the question costs a few loads.
//!
//! [`Session::peer_wants_no_put_on`](super::Session::peer_wants_no_put_on) is asked once per face
//! per put. Answered from the peer's declarations it takes the observer's lock and walks the table,
//! which measured at about 90 ns a face and cut a three-face publisher from 3.07 to 1.71 M puts/s
//! when every peer wanted the key and the question could only ever answer "write it". So the
//! answer is kept, against the one number that says whether it can have changed.
//!
//! Two facts are kept:
//!
//! * what KIND of link this is. Only a peer-to-peer link can answer "nothing is wanted"; a router
//!   or a client never does, and a question about one is a single atomic load. The kind is fixed
//!   for the life of the link and read off the handshake, so it is asked once.
//! * a few recent answers, each tagged with the peer's declaration epoch when it was given. The
//!   epoch moves after every change to what the peer has declared or ended
//!   ([`wz_session_core::declare::DeclEpoch`]), so an answer whose epoch is still the current one is
//!   still true. A key that is put on in a loop is answered from here every time but the first.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// How many keys are remembered at once. A put loop uses one or a few keys; a collision only costs
/// a recomputation, never a wrong answer.
const SLOTS: usize = 8;

/// The kind of the link, as far as a put is concerned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Link {
    /// A router, a client or a remote that declares only what it was asked for: always written to.
    Other,
    /// A peer meeting a peer: it pushes its declarations and ends them, so what is absent is not
    /// wanted.
    PeerHat,
}

#[derive(Default)]
struct Slot {
    filled: bool,
    epoch: u64,
    skip: bool,
    key: String,
}

/// The memo; one per session, shared by its clones.
pub(super) struct PutRouteMemo {
    link: AtomicU8,
    link_epoch: AtomicU64,
    epoch: OnceLock<Arc<AtomicU64>>,
    slots: [Mutex<Slot>; SLOTS],
}

impl PutRouteMemo {
    pub(super) fn new() -> Self {
        Self {
            link: AtomicU8::new(0),
            link_epoch: AtomicU64::new(0),
            epoch: OnceLock::new(),
            slots: std::array::from_fn(|_| Mutex::new(Slot::default())),
        }
    }

    /// The kind of the link, if it was worked out at `epoch` and not before.
    ///
    /// A link that is lost and made again may meet a remote of another role, and the epoch moves
    /// when the peer's declarations are flushed and again when it declares anew, so a kind found
    /// at an older epoch is asked for again rather than trusted.
    pub(super) fn link_at(&self, epoch: u64) -> Option<Link> {
        let link = match self.link.load(Ordering::Acquire) {
            1 => Link::Other,
            2 => Link::PeerHat,
            _ => return None,
        };
        (self.link_epoch.load(Ordering::Acquire) == epoch).then_some(link)
    }

    /// Keep `link` as the kind found at `epoch`.
    pub(super) fn set_link(&self, link: Link, epoch: u64) {
        let code = match link {
            Link::Other => 1,
            Link::PeerHat => 2,
        };
        // The epoch first: a reader that sees the new kind sees at least the new epoch.
        self.link_epoch.store(epoch, Ordering::Release);
        self.link.store(code, Ordering::Release);
    }

    /// The peer's declaration epoch, fetched through `init` the first time.
    pub(super) fn epoch(&self, init: impl FnOnce() -> Arc<AtomicU64>) -> &AtomicU64 {
        self.epoch.get_or_init(init)
    }

    /// The remembered answer for `key` if it was given at `epoch`.
    pub(super) fn recall(&self, key: &str, epoch: u64) -> Option<bool> {
        let slot = self.slots[slot_of(key)].lock().ok()?;
        (slot.filled && slot.epoch == epoch && slot.key == key).then_some(slot.skip)
    }

    /// Keep `skip` as the answer for `key` at `epoch`.
    pub(super) fn remember(&self, key: &str, epoch: u64, skip: bool) {
        if let Ok(mut slot) = self.slots[slot_of(key)].lock() {
            slot.filled = true;
            slot.epoch = epoch;
            slot.skip = skip;
            slot.key.clear();
            slot.key.push_str(key);
        }
    }
}

/// A cheap spread over the slots: the length and three bytes of the key.
fn slot_of(key: &str) -> usize {
    let bytes = key.as_bytes();
    let Some(&last) = bytes.last() else {
        return 0;
    };
    let mid = bytes[bytes.len() / 2];
    (bytes.len().wrapping_mul(31) + usize::from(last) + usize::from(mid).wrapping_mul(7)) % SLOTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_is_recalled_only_at_the_epoch_it_was_given_for_the_same_key() {
        let memo = PutRouteMemo::new();
        assert_eq!(memo.recall("a/b", 1), None);
        memo.remember("a/b", 1, true);
        assert_eq!(memo.recall("a/b", 1), Some(true));
        assert_eq!(memo.recall("a/b", 2), None, "the peer declared something");
        assert_eq!(
            memo.recall("a/c", 1),
            None,
            "another key is another question"
        );
        memo.remember("a/b", 2, false);
        assert_eq!(memo.recall("a/b", 2), Some(false));
        assert_eq!(memo.recall("a/b", 1), None, "the older answer is gone");
    }

    #[test]
    fn keys_that_share_a_slot_replace_each_other_and_never_answer_for_each_other() {
        let memo = PutRouteMemo::new();
        // Find two distinct keys in one slot.
        let first = "k/0";
        let second = (1..200)
            .map(|n| format!("k/{n}"))
            .find(|key| slot_of(key) == slot_of(first))
            .expect("eight slots, two hundred keys");
        memo.remember(first, 5, true);
        memo.remember(&second, 5, false);
        assert_eq!(memo.recall(&second, 5), Some(false));
        assert_eq!(memo.recall(first, 5), None, "evicted, not confused");
    }

    #[test]
    fn the_link_kind_is_kept_only_for_the_epoch_it_was_found_at() {
        let memo = PutRouteMemo::new();
        assert_eq!(memo.link_at(0), None, "nothing found yet");
        memo.set_link(Link::PeerHat, 4);
        assert_eq!(memo.link_at(4), Some(Link::PeerHat));
        assert_eq!(
            memo.link_at(5),
            None,
            "the peer declared, or the link was lost: ask again"
        );
        memo.set_link(Link::Other, 5);
        assert_eq!(memo.link_at(5), Some(Link::Other));
    }
}
