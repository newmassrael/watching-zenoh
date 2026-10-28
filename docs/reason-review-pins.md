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
| api-compat-rust | conformance/differential/tests/zenoh_protocol_transport.rs | 5c458812c876f76ebedae479e3af62ea378ac928 | R3560 |
| api-compat-rust | conformance/differential/tests/zenoh_codec_core.rs | 0d884c8efc9ae9dcbdb3e5b60231f7e0fcca08e9 | R3565 |
| api-compat-rust | conformance/differential/tests/zenoh_codec_messages.rs | 638565e93059b5b9586add4e695a3700c5ed650e | R3569 |
| api-compat-rust | conformance/differential/tests/zenoh_codec_network.rs | 60e7d1a956c411db34d73fbbdad4ae4ea3f236eb | R3575 |
| api-compat-rust | conformance/differential/tests/zenoh_codec_transport.rs | 1afd9cdfc8366b10320a23066697cc9ac2b60139 | R3583 |
| api-compat-rust | conformance/differential/tests/zenoh_shm_core.rs | 27fed964161c382be04463c22ea8b5a79da51485 | R3586 |
| api-compat-rust | conformance/differential/tests/zenoh_shm_metadata.rs | 80586a2554cb92e3a5c075cc4c5e70a90df64ce7 | R3590 |
| api-compat-rust | conformance/differential/tests/zenoh_shm_buffers.rs | 5b1ebbd9bfc7dacdb5eab8f1ac714f92e1dd73cc | R3593 |
| api-compat-rust | conformance/differential/tests/zenoh_shm_provider.rs | e9090e391c662d78d5c31e99ffdae05fb38dcc8b | R3614 |
| api-compat-rust | conformance/differential-shm/tests/zenoh_codec_shm_core.rs | 33bb98ec51b7e610ab1230ac0051c0d18e233fc5 | R3621 |
| api-compat-rust | conformance/differential-shm/tests/zenoh_codec_shm_messages.rs | 0523ef68847635003b5268ed3d5ae8eb9395bd1c | R3621 |
| api-compat-rust | conformance/differential/tests/zenoh_util_time_range.rs | 702035c655eba7a4b1f078b3c9d309141f6d6c32 | R3625 |
| api-compat-rust | conformance/differential/tests/zenoh_util_process.rs | 12450a4ef7be064a4feaf816433c61e16c14ebf4 | R3625 |
| api-compat-rust | conformance/differential/tests/zenoh_util_loader.rs | 75508e2028d7f1d4004f54984e27ed677a9c60e7 | R3632 |
| api-compat-rust | conformance/differential/tests/zenoh_util_net.rs | e3a366075f62c066ad89dc15e14aee88bd941b8e | R3640 |
| api-compat-rust | conformance/differential/tests/zenoh_util_timer.rs | 9ba872417af41a66f3dbd70809c5e8e479f193c3 | R3645 |
| api-compat-rust | crates/wz-zenoh-util/src/ffi/win.rs | 05728f93f2df332aff377decec22187a31977621 | R3650 |
| api-compat-rust | conformance/differential/tests/zenoh_config_file.rs | dc83c6ec5ab219203e2654c4ddce9f08ca46eb90 | R3664 |
| api-compat-rust | conformance/differential/tests/zenoh_config_map.rs | 98f001484ed91827afd9b8139ab19821fa68793c | R3664 |
| api-compat-rust | conformance/differential/tests/zenoh_config_types.rs | 51ef89f6d4a2770eb204d972edfeef723f3c7509 | R3664 |
| api-compat-rust | conformance/differential/tests/zenoh_bytes.rs | edab4da86f55c2b225b99e534178b19298849189 | R3673 |
| api-compat-rust | conformance/differential-shm/tests/zenoh_bytes_shm.rs | 5ccacbf32ff18ece8e87f890ca83c74db907284e | R3673 |
| api-compat-rust | conformance/differential/tests/zenoh_cancellation.rs | 61b4bee338810435b477af488466b70bbf8c030e | R3681 |
| api-compat-rust | conformance/differential/tests/zenoh_api_sample.rs | 8c225600302e7222d4178f2079612a2b9eeacb15 | R3706 |
| api-compat-rust | conformance/differential/tests/zenoh_api_session.rs | bd667154413d7f4f11d04975ccaddf7f7dac5290 | R3832 |
| api-compat-rust | conformance/differential/tests/zenoh_api_key_expr.rs | 1e57c193f433a0516279ec04f437d719e2a50ef4 | R3702 |
| api-compat-rust | conformance/differential/tests/zenoh_api_handlers.rs | 407904c56b6ed8c1dc03055d55007ba0384e6da2 | R3699 |
| api-compat-rust | conformance/differential/tests/zenoh_api_config.rs | 3d57a26789e32537ef2c932cbee1cad601459cc0 | R3688 |
| api-compat-rust | conformance/differential/tests/zenoh_protocol_network.rs | ff1b88360290937b8d76ca3785657a8c96299782 | R3545 |
| api-compat-rust | conformance/differential/tests/zenoh_protocol_common.rs | 05f5b189986cf72e17d40c9e85a618c10c01f35c | R3540 |
| api-compat-rust | conformance/differential/tests/zenoh_protocol_core.rs | cd3b503814501026e5a9f33b12173fa938a2ad90 | R3538 |
| api-compat-rust | conformance/differential/tests/zenoh_buffers.rs | 6699ae8ad9f60c2932783ab52a8db6bdf1221a46 | R3525 |
| api-compat-rust | conformance/differential/tests/zenoh_collections.rs | dc1c9292396d71325f9b2bd43f111073d2e7220b | R3517 |
| api-compat-rust | conformance/differential/tests/zenoh_macros.rs | 566ab0e1ec45640d217cd12ed8c76aa2ee0aabfd | R3512 |
| api-compat-rust | conformance/differential/tests/zenoh_keyexpr_tree.rs | 387fe0ad8557e41fbe2e3af1820936987eac7f99 | R3503 |
| api-compat-rust | conformance/patch-scenario/tests/one_zenoh_result.rs | 6ec323ad91aff120e1b3b597f22f37ec284a2fe7 | R3483 |
| api-compat-rust | crates/wz-zenoh-keyexpr/src/keyexpr_tree.rs | 44c567070fba95a9eb412d64a6a5fb41df9e6e6b | R3556 |
| api-compat-rust | crates/wz-zenoh-keyexpr/src/keyexpr_tree/arc_tree.rs | 4b3fdae75e57b83584a963c11527923732d75cab | R3553 |
| session-close-ingress | crates/wz-integration-tests/tests/wz_router_hat_connect_reconcile.rs | c38dd5c224059fb8a3b14b44a3984f2242ed7890 | R3563 |
| session-close-ingress | crates/wz-routing-graph/src/lib.rs | 22e0d88db35cb07bc22d0b8f9c5e0f7420b4c0db | R3750 |
| session-close-ingress | crates/wz-runtime-coop/src/session_drive.rs | 9d30250c8d09a4376c033ce1a743bcac2311fc7c | R3798 |
| session-close-ingress | crates/wz-runtime-tokio/src/accept_loop.rs | 4128b4765e11d0721653b64a18b02e8e7e3c0da2 | R3775 |
| session-close-ingress | crates/wz-runtime-tokio/src/observer.rs | b13f2a243e1e899b3e2b308640af196c6f0bf7b8 | R3450 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_glue.rs | a2a72da235a50ffada274f895655dd1275061382 | R3825 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_lifecycle_open.rs | 6c584c7bbbb7690647fa29b50de8a6bc8930b2bc | R3668 |
| session-close-ingress | crates/wz-runtime-tokio/src/session_open.rs | 4af95597e7ab033f6d137303b7a80affe672efcb | R3776 |
| session-close-ingress | crates/wz-runtime-tokio/tests/session_close_ingress.rs | 4a2e7b8af5a42d178789702cba3f5b6925a2c110 | R3510 |
| session-close-ingress | crates/wz-session-core/src/drive.rs | a7d3e4ffc2f1b750f2cf77979f05f5759d0acc7a | R3762 |
| session-close-ingress | crates/wz-session-core/src/observer.rs | 37a09ec22c7f801d3a5ef77f6e8386d3af1f90ea | R3749 |
| session-close-ingress | crates/wz-session-core/src/session_actions.rs | 1521b19524577b3705e26bc5bc9ac2252dff8710 | R3825 |
| session-close-ingress | crates/wz-session-core/src/switchboard.rs | 83e9ef90b7de373189f73357941892ee9c62c0e7 | R3749 |
| session-close-ingress | crates/wz-session-core/src/zid_hex.rs | 0f0211fdc425791e4ac3e161ca41de0d104f3420 | R3783 |
| session-close-ingress | crates/wz-session-lwip/src/session_drive.rs | 28b5c1134e7faf25415f30b998629a14fbb9c8a8 | R3760 |
| session-close-ingress | crates/wz-session-mcu/src/slot_host.rs | 6abb1be34aa52d10f17ee7d75b1b22a74d54a1a6 | R3542 |
