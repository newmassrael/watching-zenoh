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
| session-close-ingress | crates/wz-integration-tests/tests/wz_router_hat_connect_reconcile.rs | 1fce52d573512d7504a6a90322ee62650ffa38e5 | R4499 |
| session-close-ingress | crates/wz-routing-graph/src/lib.rs | 360f6c5cfd8ef9d74f44324462008fd5207ec9ca | R4658 |
| session-close-ingress | crates/wz-runtime-coop/src/session_drive.rs | cdf17624cb33a5efa41d967ea5a2c1838279d3b3 | R4725-read |
| session-close-ingress | crates/wz-runtime-tokio/src/accept_loop.rs | 52d5b24e795798ed4260007d445e716ceab539dd | R4658 |
| session-close-ingress | crates/wz-runtime-tokio/src/observer.rs | b13f2a243e1e899b3e2b308640af196c6f0bf7b8 | R3450 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_glue.rs | a61680353b8eb53453f80c9bee2b05d21a69606b | R4659 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_lifecycle_open.rs | 5d27c4109b0651d4ef8afb126875f6d118b9d6d5 | R4658 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_open.rs | 0c90e5b1271f3307ca4356405ff3628d7192bb0b | R4657 |
| session-close-ingress | crates/wz-runtime-tokio/tests/session_close_ingress.rs | a07824e170b5c77136c7078309957df63d6ad0bb | R4657 |
| session-close-ingress | crates/wz-session-core/src/drive.rs | cfe0e04a06f0dc8a9942254e8cca6fcf31dcef6c | R4725-read |
| session-close-ingress | crates/wz-session-core/src/observer.rs | fec5fa7990b822b5b3ba5a5b02faccff20d651f4 | R4725-read |
| session-close-ingress | crates/wz-session-core/src/session_actions.rs | f344dc2a8c0ffdbe4ff9e9fc04a8b1270f44a3ff | R4732-read |
| session-close-ingress | crates/wz-session-core/src/switchboard.rs | 2057c273ee65607fe43bfed73ce69a2fec07f560 | R4657 |
| session-close-ingress | crates/wz-session-core/src/zid_hex.rs | c0697f1c5351df69fc262b29c3517b86885846ad | R4638 |
| session-close-ingress | crates/wz-session-lwip/src/session_drive.rs | 88df9e73f85f1ca6c8734aba68f88377c43bb44a | R4657 |
| session-close-ingress | crates/wz-session-mcu/src/slot_host.rs | aec97484d8cf1b8e44da034d423c9132e9aa597c | R4638 |
