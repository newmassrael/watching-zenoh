// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The process pool of configs at the build's count (`HELD_CONFIGS`): a program makes as many
//! configs as the pool holds, the one more is refused as zenoh-pico refuses an allocation it
//! cannot make (`_Z_ERR_SYSTEM_OUT_OF_MEMORY`) and left null, and a config let go makes room for
//! the next.
//!
//! In a process of its own, because the pools are the process's: the first config reserves the
//! configs' pool from the build's count, and a config another test held at the same time would
//! take a slot of it. The pools are in every library without the tokio engine and in one with it
//! that has the doors (`build.rs`, `wz_process_pools`); a library of the tokio engine without
//! the doors keeps its configs on the heap, which holds them to no count.

#![cfg(any(feature = "object-pool", not(feature = "engine-tokio")))]

use wz_capi_pico::result::Z_ERR_SYSTEM_OUT_OF_MEMORY;
use wz_capi_pico::{
    z_config_clone, z_config_default, z_config_drop, z_config_loan, z_config_move,
    z_internal_config_check, z_owned_config_t, ZResult, Z_OK,
};
use wz_session_core::caps;

/// A config made by `z_config_default`, and the code it answered.
///
/// # Safety
/// The config made is dropped through `z_config_drop` once, or is null.
unsafe fn made() -> (z_owned_config_t, ZResult) {
    let mut config: z_owned_config_t = std::mem::zeroed();
    let code = z_config_default(&mut config);
    (config, code)
}

/// The pool holds `HELD_CONFIGS` configs and refuses the one more, by `z_config_default` and by
/// `z_config_clone` alike, each refusal leaving its config null and taking no slot; a config let
/// go is made again. Turned red by a pool laid for more configs than the build's count (the
/// `configs` of `OPEN_FRAME` in `src/process_pool.rs`), by a config placed on the heap when the
/// pool is full (`ConfigState::place` in `src/config.rs`), or by a drop that does not give its
/// slot back (`free_config`).
#[test]
fn the_pool_holds_the_builds_count_of_configs_refuses_the_one_more_and_reuses_one_let_go() {
    assert!(caps::HELD_CONFIGS > 0, "CONTROL: the build holds a config");
    // SAFETY: every config below is made, loaned and dropped through the library's own doors, and
    // each one made is dropped once.
    unsafe {
        let mut held: Vec<z_owned_config_t> = (0..caps::HELD_CONFIGS)
            .map(|at| {
                let (config, code) = made();
                assert_eq!(code, Z_OK, "config {at} of {}", caps::HELD_CONFIGS);
                assert!(z_internal_config_check(&config));
                config
            })
            .collect();

        let (refused, code) = made();
        assert_eq!(code, Z_ERR_SYSTEM_OUT_OF_MEMORY, "the one more is refused");
        assert!(!z_internal_config_check(&refused), "and left null");
        let mut copy: z_owned_config_t = std::mem::zeroed();
        assert_eq!(
            z_config_clone(&mut copy, z_config_loan(&held[0])),
            Z_ERR_SYSTEM_OUT_OF_MEMORY,
            "a copy takes a slot as a new config does"
        );
        assert!(!z_internal_config_check(&copy), "and is left null");

        let mut let_go = held.pop().expect("a config is held");
        z_config_drop(z_config_move(&mut let_go));
        let (again, code) = made();
        assert_eq!(code, Z_OK, "the slot let go is taken again");
        assert!(z_internal_config_check(&again));
        held.push(again);
        let (refused, code) = made();
        assert_eq!(
            code, Z_ERR_SYSTEM_OUT_OF_MEMORY,
            "and the pool is full again"
        );
        assert!(!z_internal_config_check(&refused));

        for config in &mut held {
            z_config_drop(z_config_move(config));
        }
        let mut remade: Vec<z_owned_config_t> = (0..caps::HELD_CONFIGS)
            .map(|at| {
                let (config, code) = made();
                assert_eq!(
                    code, Z_OK,
                    "no refusal took a slot: config {at} is made again"
                );
                config
            })
            .collect();
        for config in &mut remade {
            z_config_drop(z_config_move(config));
        }
    }
}
