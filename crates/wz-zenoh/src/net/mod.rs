// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What upstream names `zenoh::net`, which the crate does not publish: the path a public item of
//! the crate is re-exported from, so that the surface the crate states says the same thing.

#[doc(hidden)]
pub mod runtime;
