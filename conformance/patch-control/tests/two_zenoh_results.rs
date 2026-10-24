// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Without the `[patch]` the graph holds two `zenoh_result`s, and an error of upstream's is not a
//! `ZError` of wz's. This is the failure `../patch-scenario` shows to be gone.

use zenoh_keyexpr::OwnedKeyExpr;

#[test]
fn an_upstream_crates_error_is_not_the_zerror_of_an_unpatched_wz_crate() {
    let error = OwnedKeyExpr::try_from("a//b").expect_err("an empty chunk is not a key expression");
    assert!(
        error.downcast_ref::<wz_result::ZError>().is_none(),
        "the downcast answered without a patch: the probe of `../patch-scenario` is blind"
    );
}
