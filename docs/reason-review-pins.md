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
| runtime-zero-copy | crates/wz-link-lwip/src/lib.rs | 99b319b1cd392e16d8a2fa77623101da18887d0d | R3246 |
| runtime-zero-copy | crates/wz-link-lwip/src/rx_ring.rs | 2e50ff6d14db541c453cd82b239665bc7939eb49 | R3246 |
| runtime-zero-copy | crates/wz-runtime-tokio/src/lib.rs | df15845530b33d34eba5af35e35484e4f00d9683 | R3260 |
| runtime-zero-copy | crates/wz-runtime-tokio/src/link_rx_arena.rs | aea4f0f8ecd760416c0117dd10b3c84e5ec12149 | R3260 |
| runtime-zero-copy | crates/wz-runtime-tokio/src/uring_reactor.rs | 17a3e106991e8e08899800efe2128f91a7975728 | seed |
| runtime-zero-copy | crates/wz-runtime-tokio/src/zero_copy.rs | 9b2876b1c1d2cf23b2e4bc269e457ce54319b8d1 | R3260 |
| runtime-zero-copy | crates/wz-runtime-tokio/tests/shared_unit_dispatch.rs | ca746b43e02569d96631b8fde9a23d8b9273b052 | seed |
| runtime-zero-copy | crates/wz-session-core/src/inbound.rs | abcaa65ad624771c0712ff60795fdae5685ec14d | R3260 |
| runtime-zero-copy | crates/wz-session-core/src/link.rs | 8f7d2c4045a1c3ee03e083037b25c03c6be2e208 | R3260 |
| runtime-zero-copy | crates/wz-session-core/src/multicast_rx.rs | bc1036db8373c8fcc4b67ea7a335e3e0dc9b2d6a | R3182 |
| runtime-zero-copy | crates/wz-session-core/src/reply.rs | bfdf7e66ac6f8d94ea540e3f11045355439e3aa9 | R3260 |
| runtime-zero-copy | crates/wz-session-core/src/sample.rs | b1c2cdb3d8ab9399b7a7558237760265962e07fe | R3260 |
| runtime-zero-copy | out/wz-runtime-tokio/session_rx_pool_ap.rs | 66d005a9ed543bdd29e8742ab32c923ffd511086 | R3260 |
