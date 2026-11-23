// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The object pools driven through their doors (`wz_ext_object_pool_*`).
//!
//! One test, in a process of its own, because the pools are the process's: the arms run in order
//! against them, and an object another test made while they are reserved would be taken from them.
//! The first object of the process reserves the build's pools, so the arms give those up before a
//! program's own are reserved. A program that reserves its own states the configs it opens from.
//! The counts state every entity, so the arms hold in a build whose limits bound none of them.

#![cfg(all(feature = "object-pool", feature = "peer"))]

use std::ffi::{CStr, CString};

use wz_capi_pico::object_pool::{
    wz_ext_object_pool_bytes, wz_ext_object_pool_class, wz_ext_object_pool_class_t,
    wz_ext_object_pool_counts_t, wz_ext_object_pool_release, wz_ext_object_pool_reserve,
    WZ_EXT_OBJECT_POOL_CLASSES,
};
use wz_capi_pico::result::{Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_SYSTEM_OUT_OF_MEMORY};
use wz_capi_pico::{
    z_bytes_copy_from_buf, z_bytes_copy_from_str, z_bytes_drop, z_bytes_move, z_config_default,
    z_config_loan_mut, z_config_move, z_declare_publisher, z_internal_bytes_check,
    z_internal_publisher_check, z_internal_session_check, z_open, z_owned_bytes_t,
    z_owned_config_t, z_owned_publisher_t, z_owned_session_t, z_publisher_drop, z_publisher_move,
    z_session_drop, z_session_loan, z_session_move, z_view_keyexpr_from_str, z_view_keyexpr_loan,
    z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_ERR_NULL,
    Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// Every pool as `wz_ext_object_pool_class` reports it.
fn classes() -> Vec<wz_ext_object_pool_class_t> {
    (0..WZ_EXT_OBJECT_POOL_CLASSES)
        .map(|class| {
            let mut out = wz_ext_object_pool_class_t::default();
            // SAFETY: `out` is a live struct.
            assert_eq!(unsafe { wz_ext_object_pool_class(class, &mut out) }, Z_OK);
            out
        })
        .collect()
}

fn slots() -> usize {
    classes().iter().map(|class| class.slots).sum()
}

fn in_use() -> usize {
    classes().iter().map(|class| class.in_use).sum()
}

fn refused() -> usize {
    classes().iter().map(|class| class.refused).sum()
}

/// A payload made by the copying constructor, and the code it answered.
unsafe fn payload(text: &CStr) -> (z_owned_bytes_t, i8) {
    let mut bytes: z_owned_bytes_t = std::mem::zeroed();
    let code = z_bytes_copy_from_str(&mut bytes, text.as_ptr());
    (bytes, code)
}

/// A config that listens on a port of the loopback, or dials one, as `key` says.
unsafe fn config(key: u8) -> z_owned_config_t {
    let endpoint = CString::new(format!("tcp/127.0.0.1:{}", free_port())).expect("a locator");
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    cfg
}

/// A publisher declared on `key`, and the code its declaration answered.
unsafe fn publisher(session: &z_owned_session_t, key: &CStr) -> (z_owned_publisher_t, i8) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut publisher: z_owned_publisher_t = std::mem::zeroed();
    let code = z_declare_publisher(
        z_session_loan(session),
        &mut publisher,
        z_view_keyexpr_loan(&ke),
        std::ptr::null(),
    );
    (publisher, code)
}

#[test]
fn reserved_pools_give_each_object_a_slot_refuse_the_one_more_and_are_given_up_when_empty() {
    // SAFETY: every owned value below is made and dropped through the library's own doors, once.
    unsafe {
        // ARM 1: nothing reserved, so the first payload reserves the build's pools and takes a
        // slot of them; dropped, it gives the slot back once, and a second drop of its moved-from
        // handle gives nothing. Empty, the build's pools are given up.
        assert_eq!(
            slots(),
            0,
            "CONTROL: nothing is reserved before the first object"
        );
        assert_eq!(classes()[0].slot_bytes, 16);
        assert_eq!(classes()[1].slot_bytes, 32);
        let (mut early, code) = payload(c"made before any reservation");
        assert_eq!(code, Z_OK);
        assert!(slots() > 0, "the first object reserved the build's pools");
        assert_eq!(in_use(), 1, "and lies in them");
        let unused = wz_ext_object_pool_counts_t {
            bytes: 1,
            ..Default::default()
        };
        assert_eq!(
            wz_ext_object_pool_reserve(&unused),
            Z_EINVAL,
            "the build's pools are reserved already"
        );
        z_bytes_drop(z_bytes_move(&mut early));
        assert_eq!(in_use(), 0, "a dropped payload gives its slot back");
        z_bytes_drop(z_bytes_move(&mut early));
        assert_eq!(in_use(), 0, "and only once");
        assert_eq!(wz_ext_object_pool_release(), Z_OK);
        assert_eq!(slots(), 0);

        // ARM 2: counts that make no pool are refused, and reserve nothing.
        assert_eq!(wz_ext_object_pool_reserve(std::ptr::null()), Z_ERR_NULL);
        let nothing = wz_ext_object_pool_counts_t::default();
        assert_eq!(
            wz_ext_object_pool_reserve(&nothing),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        let unstated = wz_ext_object_pool_counts_t {
            sessions: 1,
            ..Default::default()
        };
        let mut needed = 0usize;
        let limits = wz_session_core::limits::SessionLimits::defaults();
        if limits.max_subscriptions().most().is_none() {
            // A heap build states no bound, so a subscriber count left at zero has none.
            assert_eq!(
                wz_ext_object_pool_bytes(&unstated, &mut needed),
                Z_ERR_CONFIG_INVALID_VALUE
            );
            assert_eq!(needed, 0);
        } else {
            assert_eq!(wz_ext_object_pool_bytes(&unstated, &mut needed), Z_OK);
            assert!(needed > 0);
        }
        assert_eq!(slots(), 0, "a refused plan reserves nothing");

        // ARM 3: one of each entity for one session, two payloads and the bytes of four short
        // ones, and the config each open of the arms below is made from, one at a time.
        let counts = wz_ext_object_pool_counts_t {
            sessions: 1,
            publishers: 1,
            subscribers: 1,
            queryables: 1,
            liveliness_tokens: 1,
            liveliness_subscribers: 1,
            bytes: 2,
            configs: 1,
            payload_bytes: 128,
            ..Default::default()
        };
        let mut bytes = 0usize;
        assert_eq!(wz_ext_object_pool_bytes(&counts, &mut bytes), Z_OK);
        // The payloads' area lies beside the slots, and no class reports it.
        let without_area = wz_ext_object_pool_counts_t {
            payload_bytes: 0,
            ..counts
        };
        let mut slots_only = 0usize;
        assert_eq!(
            wz_ext_object_pool_bytes(&without_area, &mut slots_only),
            Z_OK
        );
        let area = bytes - slots_only;
        assert!(area >= 128, "the area and its marks: {area}");
        // A config's slot is its own size where the build's config is larger than the largest
        // class, and no class reports it then.
        let without_configs = wz_ext_object_pool_counts_t {
            configs: 0,
            ..counts
        };
        let mut bare = 0usize;
        assert_eq!(wz_ext_object_pool_bytes(&without_configs, &mut bare), Z_OK);
        let config_slot = bytes - bare;
        let largest = classes()[WZ_EXT_OBJECT_POOL_CLASSES - 1].slot_bytes;
        let configs_reported = usize::from(config_slot <= largest);
        assert_eq!(wz_ext_object_pool_reserve(&counts), Z_OK);
        assert_eq!(
            wz_ext_object_pool_reserve(&counts),
            Z_EINVAL,
            "reserved once"
        );
        let held_by_plane = usize::from(cfg!(feature = "queryable"))
            + 2 * usize::from(cfg!(feature = "liveliness"));
        let reported = 1 + 1 + 1 + held_by_plane + 2 + configs_reported;
        assert_eq!(slots(), reported);
        let laid: usize = classes().iter().map(|class| class.bytes).sum();
        assert_eq!(
            laid + (1 - configs_reported) * config_slot + area,
            bytes,
            "the reservation is the bytes the door answered"
        );

        // ARM 4: two payloads fit, the third is refused, counted, and left null.
        let (mut first, code) = payload(c"first");
        assert_eq!(code, Z_OK);
        let (mut second, code) = payload(c"second");
        assert_eq!(code, Z_OK);
        let (third, code) = payload(c"third");
        assert_eq!(code, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(!z_internal_bytes_check(&third));
        assert_eq!((in_use(), refused()), (2, 1));

        // ARM 4b: a payload whose bytes the area has no block for is refused before it takes a
        // place, and left null; the program's buffer is its own still.
        let source = [0x5Au8; 200];
        let mut large: z_owned_bytes_t = std::mem::zeroed();
        assert_eq!(
            z_bytes_copy_from_buf(&mut large, source.as_ptr(), source.len()),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
        assert!(!z_internal_bytes_check(&large));
        assert_eq!((in_use(), refused()), (2, 1), "no place was taken for it");
        assert!(source.iter().all(|&byte| byte == 0x5A));

        // ARM 5: the pools are kept while they hold an object.
        assert_eq!(wz_ext_object_pool_release(), Z_EINVAL);
        assert_eq!(slots(), reported);

        // ARM 6: a pooled payload let go makes room for the next.
        z_bytes_drop(z_bytes_move(&mut second));
        assert_eq!(in_use(), 1);
        let (mut again, code) = payload(c"again");
        assert_eq!(code, Z_OK);
        assert_eq!(in_use(), 2);

        // ARM 7: the one session's place is taken; a second open is refused before it dials, and
        // consumes its config.
        let mut cfg = config(Z_CONFIG_LISTEN_KEY);
        let mut session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK
        );
        assert_eq!(in_use(), 3);
        let mut refused_cfg = config(Z_CONFIG_CONNECT_KEY);
        let mut second_session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(
                &mut second_session,
                z_config_move(&mut refused_cfg),
                std::ptr::null()
            ),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
        assert!(!z_internal_session_check(&second_session));
        assert_eq!(in_use(), 3);

        // ARM 8: the one publisher's place is taken; a second declaration is refused, and the
        // place of an undeclared one is taken again.
        let (mut declared, code) = publisher(&session, c"wz/pool/a");
        assert_eq!(code, Z_OK);
        let (refused_publisher, code) = publisher(&session, c"wz/pool/b");
        assert_eq!(code, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(!z_internal_publisher_check(&refused_publisher));
        z_publisher_drop(z_publisher_move(&mut declared));
        let (mut redeclared, code) = publisher(&session, c"wz/pool/b");
        assert_eq!(code, Z_OK);
        assert_eq!(in_use(), 4);

        // ARM 9: everything let go, the pools are given up, and the next object reserves the
        // build's pools again: three payloads fit where the program's pools held two.
        z_publisher_drop(z_publisher_move(&mut redeclared));
        z_session_drop(z_session_move(&mut session));
        z_bytes_drop(z_bytes_move(&mut first));
        z_bytes_drop(z_bytes_move(&mut again));
        assert_eq!(in_use(), 0);
        assert_eq!(wz_ext_object_pool_release(), Z_OK);
        assert_eq!(slots(), 0);
        assert_eq!(wz_ext_object_pool_release(), Z_OK, "nothing to give up");
        let mut after: Vec<z_owned_bytes_t> = (0..3)
            .map(|_| {
                let (bytes, code) = payload(c"after");
                assert_eq!(
                    code, Z_OK,
                    "the build's pools, past the two the program's held"
                );
                bytes
            })
            .collect();
        assert!(slots() > 0, "the build's pools are reserved again");
        assert_eq!(in_use(), 3);
        for bytes in &mut after {
            z_bytes_drop(z_bytes_move(bytes));
        }
        assert_eq!(in_use(), 0);
        assert_eq!(wz_ext_object_pool_release(), Z_OK);
        assert_eq!(slots(), 0);

        #[cfg(feature = "object-pool-region")]
        region_arms();
    }
}

/// The pools laid over memory the program hands over.
#[cfg(feature = "object-pool-region")]
unsafe fn region_arms() {
    use wz_capi_pico::object_pool::wz_ext_object_pool_place;

    #[repr(C, align(16))]
    struct Region([u8; 4096]);

    let mut region = Region([0; 4096]);
    let base = region.0.as_mut_ptr();
    let counts = wz_ext_object_pool_counts_t {
        bytes: 2,
        payload_bytes: 64,
        ..Default::default()
    };
    let mut needed = 0usize;
    assert_eq!(wz_ext_object_pool_bytes(&counts, &mut needed), Z_OK);
    assert!((1..=region.0.len() - 16).contains(&needed), "{needed}");

    // ARM R1: a refused placement takes nothing.
    assert_eq!(
        wz_ext_object_pool_place(std::ptr::null_mut(), needed, &counts),
        Z_ERR_NULL
    );
    assert_eq!(
        wz_ext_object_pool_place(base.add(1).cast(), needed, &counts),
        Z_EINVAL,
        "not aligned to a slot"
    );
    assert_eq!(
        wz_ext_object_pool_place(base.cast(), needed - 1, &counts),
        Z_ERR_SYSTEM_OUT_OF_MEMORY
    );
    assert_eq!(slots(), 0);

    // ARM R2: placed, the payloads lie in the program's memory, and the third is refused.
    assert_eq!(wz_ext_object_pool_place(base.cast(), needed, &counts), Z_OK);
    assert_eq!(
        wz_ext_object_pool_reserve(&counts),
        Z_EINVAL,
        "placed already"
    );
    let (mut first, code) = payload(c"first");
    assert_eq!(code, Z_OK);
    let (mut second, code) = payload(c"second");
    assert_eq!(code, Z_OK);
    for bytes in [&first, &second] {
        // The handle is the owned struct's first word (pico's layout).
        let handle = *(bytes as *const z_owned_bytes_t as *const *const u8);
        let at = handle as usize - base as usize;
        assert!(at < needed, "inside the program's memory");
    }
    let (third, code) = payload(c"third");
    assert_eq!(code, Z_ERR_SYSTEM_OUT_OF_MEMORY);
    assert!(!z_internal_bytes_check(&third));

    // ARM R3: given up once empty, and the memory is the program's again.
    z_bytes_drop(z_bytes_move(&mut first));
    z_bytes_drop(z_bytes_move(&mut second));
    assert_eq!(wz_ext_object_pool_release(), Z_OK);
    assert_eq!(slots(), 0);
}
