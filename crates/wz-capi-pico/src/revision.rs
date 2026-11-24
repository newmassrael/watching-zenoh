// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The revision of this library's wz-own contract, and the stamp that carries it.
//!
//! This crate is a drop-in for zenoh-pico, so the `z_*` / `zp_*` surface is upstream's contract and a
//! number minted here says nothing about it (the argument `wz-capi-c`'s `abi.rs` makes for its own).
//! What the revision covers is what a consumer of THIS build can depend on beyond upstream's header:
//! which arm of the header the library is (the layout switches below) and the set of wz-only
//! behaviours a deployment relies on.
//!
//! # The stamp
//!
//! A tool that describes this library for a device it cannot run on reads the family, the revision
//! and the layout arm from the artifact's bytes (`wz-abi-stamp`; `docs/target-build-contract.md`
//! T6). The four layout values are the switches that change the size of a struct a pico program
//! allocates, each documented where its feature is declared in `Cargo.toml`: a program links the
//! library of the arm it compiled its header against.
//!
//! # When it moves
//!
//! One integer, bumped when something a consumer built against the previous number cannot survive:
//! a removed or renamed wz-only door, or a changed meaning of one. A new door, and a new
//! capability that a consumer opts into, do not move it. It starts at 1 because the library had no
//! revision before this round, so there is no earlier number to be compatible with.

/// The revision the stamp carries.
///
/// It moved to 2 when the meaning of a wz-only behaviour changed: with a registered clock
/// (`wz_ext_clock_source_register`), `z_timestamp_new` gives a program the clock's time whatever
/// the clock's standing, and the `clock-quality-stamping` policy holds back only the data the node
/// stamps; at 1 a `trusted-only` build gave a program no time until the clock was reported trusted.
/// Also at 2, every time one session gives strictly increases, whichever clock it is read from and
/// whether a program asks for it (`z_timestamp_new`) or the session's advanced publisher stamps a
/// sample with it: one last time given per session, which the session's node clock learns. So a
/// stamp made after a registered clock ahead of the system clock is removed goes on from the last
/// one given, and a sample is never stamped at or before a time a program was given; at 1 the
/// first was the system clock's reading and the two were not ordered against each other. And at 2
/// an advanced put or delete that cannot be given a time is refused with
/// `Z_ERR_TIMESTAMP_GENERATION_FAILED` and sends nothing, as pico refuses the put whose
/// `z_timestamp_new` failed: a session with no time left, and a `trusted-only` build whose clock
/// is not yet reported synchronised; at 1 the second sent the sample stamped with the system clock.
///
/// It moved to 3 when a process pool's slot became its object's own size: the report of a size
/// class (`wz_ext_object_pool_class_t`) grew a `bytes` field, the bytes its slots take, and its
/// `slot_bytes` became the class's largest slot rather than the size of each of its slots, so a
/// program built against 2 hands the door a report too small and reads the slots' bytes wrongly.
///
/// It moved to 4 when a querier and a declared key expression took a slot of a pool of their own:
/// the counts a program states (`wz_ext_object_pool_counts_t`) grew `queriers` and `keyexprs`
/// after `payload_bytes`, so a program built against 3 hands the door counts too small.
///
/// It moved to 5 when the structs a door reads from or writes into the program's memory took their
/// own size (`crate::sized`): `struct_size` is now the first field of
/// `wz_ext_object_pool_counts_t`, `wz_ext_object_pool_class_t`, `wz_ext_session_memory_t`,
/// `wz_ext_session_memory_row_t`, `wz_ext_replay_publisher_counts_t`,
/// `wz_ext_replay_subscriber_counts_t`, `wz_ext_e2e_verdict_t` (and so of the verdict a
/// `wz_ext_replay_sample_t` carries), `wz_ext_instance_key_t`, `wz_ext_message_entry_t`,
/// `wz_ext_event_t` and `wz_ext_segment_result_t`, so a program built against 4 hands structs whose
/// first field the library reads as their size. The reading a program's resource source writes
/// (`wz_ext_resource_reading_t`) took one too, which the library sets before it calls the source.
/// From 5 on a field is added at the end, read or written only in a struct whose `struct_size`
/// holds it, so adding one does not move the revision.
///
/// It moved to 6 when the bytes of payload became three pools of fixed blocks: the counts a
/// program states (`wz_ext_object_pool_counts_t`) gave `payload_bytes` up, refusing one not zero
/// with `Z_EINVAL`, and took `small_payload_blocks`, `medium_payload_blocks` and
/// `large_payload_blocks` at the end; and the report of a size class counts the payload blocks of
/// its size among its slots. So a program built against 5 that states payload bytes has its
/// counts refused.
pub const WZ_CAPI_PICO_ABI_REVISION: u32 = 6;

wz_abi_stamp::stamp!(
    family = "capi-pico",
    revision = WZ_CAPI_PICO_ABI_REVISION,
    layout = [
        ("multi_thread", cfg!(feature = "multi-thread")),
        ("unstable_api", cfg!(feature = "unstable-api")),
        ("local_subscriber", cfg!(feature = "local-subscriber")),
        ("local_queryable", cfg!(feature = "local-queryable")),
    ],
);
