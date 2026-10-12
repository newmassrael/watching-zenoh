# Reason review pins

An atom whose reason says work REMAINS (PARTIAL, UNBUILT or UNVERIFIED) makes
claims about this tree's code, and nothing re-reads a clause when the code it
describes moves. `scripts/lib/reason_review_pin_gate.py` closes that gap without
judging any prose: every tracked file such a reason cites is pinned below to the
git blob it had when a round last read the reason against it, and a push that
changes a pinned file fails until the row is rewritten.

## Why this file exists

Five stale reasons were found by hand in one session (open-debt item 756). In each
the code moved and the reason kept asserting the old state, and a stale assertion
reads as a fact. The citation gates answer whether a cited path or line still
resolves; they cannot say whether the sentence is still true. This table is the
place the question is put in front of the round that changed the evidence.

A pin is NOT evidence that the reason is true. A round can rewrite a row without
reading anything, and nothing here can stop that. What it removes is the silent
case: editing a cited file while the reason that describes it is never on screen.

## How to move a row

1. The gate names the atom, the file and the new blob. Open the atom's reason
   (`mnemosyne-cli query` on the inventory entry) and read each clause that cites
   the file against the file as it is now. A clause that no longer holds is a
   correction to the reason, made through the store's own primitive, in the same
   round.
2. Rewrite the row in place: the new blob, and this round's id. One row per
   (atom, file); a second row for the same pair is refused.
3. `python3 scripts/lib/reason_review_pin_gate.py --emit --round <id>` prints the
   whole table for the tree as it stands. A row whose round is `seed` was TAKEN,
   not read: it records a baseline, and the first real edit to its file replaces
   it with a round id.

A row whose atom stops saying work remains (the atom is built), or stops citing
that file, is dropped in the commit that changes the reason. An empty table is the
normal state once nothing remains.

| atom | file | blob | round |
|---|---|---|---|
| runtime-zero-copy | crates/wz-link-lwip/src/lib.rs | c6b20cd9576f8bb77cd87bacf0daf3a1bddc6f12 | R3299 |
| runtime-zero-copy | crates/wz-link-lwip/src/rx_ring.rs | 2e50ff6d14db541c453cd82b239665bc7939eb49 | R3246 |
| runtime-zero-copy | crates/wz-runtime-tokio/src/lib.rs | 14ff30dcd7940112ddef21f7953f17efe96fd1bf | R3280 |
| runtime-zero-copy | crates/wz-runtime-tokio/src/link_rx_arena.rs | aea4f0f8ecd760416c0117dd10b3c84e5ec12149 | R3260 |
| runtime-zero-copy | crates/wz-runtime-tokio/src/uring_reactor.rs | c9834b6b76fd3e86e6a012614b49c59db8574556 | R3291 |
| runtime-zero-copy | crates/wz-runtime-tokio/src/zero_copy.rs | 9b2876b1c1d2cf23b2e4bc269e457ce54319b8d1 | R3260 |
| runtime-zero-copy | crates/wz-runtime-tokio/tests/shared_unit_dispatch.rs | ca746b43e02569d96631b8fde9a23d8b9273b052 | seed |
| runtime-zero-copy | crates/wz-session-core/src/inbound.rs | 908bbcf30a092774f8e3b2f9ef7ea548f18e27df | R3300 |
| runtime-zero-copy | crates/wz-session-core/src/link.rs | 6c144caf4f37f2e47fe56c6d4ac18f335b017f6f | R3299 |
| runtime-zero-copy | crates/wz-session-core/src/multicast_rx.rs | bc1036db8373c8fcc4b67ea7a335e3e0dc9b2d6a | R3182 |
| runtime-zero-copy | crates/wz-session-core/src/reply.rs | a0f72d4c40723590c6b2824a6166d7950ccf0663 | R3300 |
| runtime-zero-copy | crates/wz-session-core/src/sample.rs | e46203df309881cd26a22606086e7315bbb9d064 | R3299 |
| runtime-zero-copy | out/wz-runtime-tokio/session_rx_pool_ap.rs | d1e97f75208bee65308c650bd330726feed3b7b0 | R3280 |
