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
| runtime-zero-copy | crates/wz-link-lwip/src/lib.rs | ad5239bf1d6026e73397d9fcd0e60b9ab8b051ab | R3218 |
| runtime-zero-copy | crates/wz-link-lwip/src/rx_ring.rs | 7837f3664ca67b01b10786ad397ed192cd480240 | seed |
| runtime-zero-copy | crates/wz-runtime-tokio/src/lib.rs | 2d768eeebaae11f9c8450c7d1aee1bcf0ff199cb | R3232 |
| runtime-zero-copy | crates/wz-runtime-tokio/src/link_rx_arena.rs | b55db327c31bf8efa58020441a09ec572d5f7efa | seed |
| runtime-zero-copy | crates/wz-runtime-tokio/src/uring_reactor.rs | 17a3e106991e8e08899800efe2128f91a7975728 | seed |
| runtime-zero-copy | crates/wz-runtime-tokio/src/zero_copy.rs | 8e135a6dffe4c7f7490faaa2d9642feaf3ea5726 | seed |
| runtime-zero-copy | crates/wz-runtime-tokio/tests/shared_unit_dispatch.rs | ca746b43e02569d96631b8fde9a23d8b9273b052 | seed |
| runtime-zero-copy | crates/wz-session-core/src/inbound.rs | 9dadd34d0e0fd0dd2c121e0424af852310725c5f | R3182 |
| runtime-zero-copy | crates/wz-session-core/src/link.rs | 6efa1966a4048ef2a8d0e3d8394edf473c07a5ae | seed |
| runtime-zero-copy | crates/wz-session-core/src/multicast_rx.rs | bc1036db8373c8fcc4b67ea7a335e3e0dc9b2d6a | R3182 |
| runtime-zero-copy | crates/wz-session-core/src/reply.rs | 95e1625623ec158009aa34bac1e4cf7e9912c966 | R3232 |
| runtime-zero-copy | crates/wz-session-core/src/sample.rs | 1dac34d2321941b9b75d38d877ab09bda7cb8bb6 | R3182 |
| runtime-zero-copy | out/wz-runtime-tokio/session_rx_pool_ap.rs | 4166deb17327a3f5e07b888541d4379020e17f76 | R3218 |
