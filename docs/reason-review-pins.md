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
| api-compat-rust | conformance/differential/tests/zenoh_keyexpr.rs | 69e68e8a35dbb05a0666ca60491e8acc8c3e87f2 | R3498 |
| api-compat-rust | conformance/differential/tests/zenoh_keyexpr_tree.rs | 1011d70fab8129bf4743e4b0422958333d30ae27 | R3500 |
| api-compat-rust | conformance/patch-scenario/tests/one_zenoh_result.rs | 6ec323ad91aff120e1b3b597f22f37ec284a2fe7 | R3483 |
| api-compat-rust | crates/wz-zenoh-keyexpr/src/keyexpr_tree.rs | d98c16cffa207edb8aa44ec4dbb0b2bcbea3ca09 | R3500 |
| session-close-ingress | crates/wz-integration-tests/tests/wz_router_hat_connect_reconcile.rs | 31cee437ba6c4c3bf6eeab254f30dcdf9c7bd423 | R3450 |
| session-close-ingress | crates/wz-routing-graph/src/lib.rs | 2123f96404cdfc158a6c875d4440a7febca3e3c5 | R3450 |
| session-close-ingress | crates/wz-runtime-coop/src/session_drive.rs | 6905f2746973377266d6459dd9f5bd1ceecb7c9d | R3478 |
| session-close-ingress | crates/wz-runtime-tokio/src/accept_loop.rs | 0b4e6090dddc0ee8a3023a9ef5cf55fa78183084 | R3450 |
| session-close-ingress | crates/wz-runtime-tokio/src/observer.rs | b13f2a243e1e899b3e2b308640af196c6f0bf7b8 | R3450 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_glue.rs | e77fc6a351475e3e9cdf2f144853e111879910ad | R3490 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_lifecycle_open.rs | ea1ce534d88d6f88f8382e2f00dba2e0d56e0707 | R3450 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_open.rs | a6b817b728ae6e86f415a2674840ff765a008938 | R3450 |
| session-close-ingress | crates/wz-runtime-tokio/tests/session_close_ingress.rs | f0a96f82558b0767fc96d9f6539a0cd1da3a42f1 | R3455 |
| session-close-ingress | crates/wz-session-core/src/drive.rs | 0e9495d2a892b347765adaa2a6521c3a8c8f8491 | R3482 |
| session-close-ingress | crates/wz-session-core/src/observer.rs | c2ad4774a53f8f30f2a5f626f57111caec323841 | R3450 |
| session-close-ingress | crates/wz-session-core/src/session_actions.rs | 57ff588e664992b1a878a29102b9914db0c29592 | R3482 |
| session-close-ingress | crates/wz-session-core/src/switchboard.rs | 563daafb74015478bc16e6b876631db745435de6 | R3450 |
| session-close-ingress | crates/wz-session-core/src/zid_hex.rs | eb5aa0a91c1dc61610401a4f4cd348a01ee49910 | R3450 |
| session-close-ingress | crates/wz-session-lwip/src/session_drive.rs | 58377aba344234f4d432cb8c2ce68a1d1de3c3aa | R3480 |
| session-close-ingress | crates/wz-session-mcu/src/slot_host.rs | 0807ee1708c3d5d23c3e4c6f132db911e273d509 | R3450 |
