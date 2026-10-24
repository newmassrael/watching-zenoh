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
| api-compat-rust | conformance/differential/tests/zenoh_protocol_common.rs | 05f5b189986cf72e17d40c9e85a618c10c01f35c | R3540 |
| api-compat-rust | conformance/differential/tests/zenoh_protocol_core.rs | cd3b503814501026e5a9f33b12173fa938a2ad90 | R3538 |
| api-compat-rust | conformance/differential/tests/zenoh_buffers.rs | 6699ae8ad9f60c2932783ab52a8db6bdf1221a46 | R3525 |
| api-compat-rust | conformance/differential/tests/zenoh_collections.rs | dc1c9292396d71325f9b2bd43f111073d2e7220b | R3517 |
| api-compat-rust | conformance/differential/tests/zenoh_macros.rs | 566ab0e1ec45640d217cd12ed8c76aa2ee0aabfd | R3512 |
| api-compat-rust | conformance/differential/tests/zenoh_keyexpr_tree.rs | 387fe0ad8557e41fbe2e3af1820936987eac7f99 | R3503 |
| api-compat-rust | conformance/patch-scenario/tests/one_zenoh_result.rs | 6ec323ad91aff120e1b3b597f22f37ec284a2fe7 | R3483 |
| api-compat-rust | crates/wz-zenoh-keyexpr/src/keyexpr_tree.rs | 47877a38eb6deaa57c3c6807c55d43a95022b2a4 | R3503 |
| api-compat-rust | crates/wz-zenoh-keyexpr/src/keyexpr_tree/arc_tree.rs | fe51b4dcf1e94be08e1d3de05039f228bcbdd3ba | R3503 |
| session-close-ingress | crates/wz-integration-tests/tests/wz_router_hat_connect_reconcile.rs | 31cee437ba6c4c3bf6eeab254f30dcdf9c7bd423 | R3450 |
| session-close-ingress | crates/wz-routing-graph/src/lib.rs | 2123f96404cdfc158a6c875d4440a7febca3e3c5 | R3450 |
| session-close-ingress | crates/wz-runtime-coop/src/session_drive.rs | d12ca70283f5f9bc69cd4b75502f13a56a040121 | R3505 |
| session-close-ingress | crates/wz-runtime-tokio/src/accept_loop.rs | 9d33ff5e66f46f1e43722f60f70568cf24c3619a | R3539 |
| session-close-ingress | crates/wz-runtime-tokio/src/observer.rs | b13f2a243e1e899b3e2b308640af196c6f0bf7b8 | R3450 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_glue.rs | faaea37126cbe4b332d0a2b74853b87b9bb8967d | R3507 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_lifecycle_open.rs | 590a94fbe61702974c57f71d8dea2b7afe6fd079 | R3539 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_open.rs | 50c600fadcd6713e2e3e2418c1ae177eca382cdb | R3539 |
| session-close-ingress | crates/wz-runtime-tokio/tests/session_close_ingress.rs | 4a2e7b8af5a42d178789702cba3f5b6925a2c110 | R3510 |
| session-close-ingress | crates/wz-session-core/src/drive.rs | 91e25434c88fbaaf9361d27b144f952da10c3a0a | R3539 |
| session-close-ingress | crates/wz-session-core/src/observer.rs | c2ad4774a53f8f30f2a5f626f57111caec323841 | R3450 |
| session-close-ingress | crates/wz-session-core/src/session_actions.rs | f7e3387214af75ac567fbcc6f9f72d9458b310a4 | R3539 |
| session-close-ingress | crates/wz-session-core/src/switchboard.rs | 563daafb74015478bc16e6b876631db745435de6 | R3450 |
| session-close-ingress | crates/wz-session-core/src/zid_hex.rs | eb5aa0a91c1dc61610401a4f4cd348a01ee49910 | R3450 |
| session-close-ingress | crates/wz-session-lwip/src/session_drive.rs | 58377aba344234f4d432cb8c2ce68a1d1de3c3aa | R3480 |
| session-close-ingress | crates/wz-session-mcu/src/slot_host.rs | 0807ee1708c3d5d23c3e4c6f132db911e273d509 | R3450 |
