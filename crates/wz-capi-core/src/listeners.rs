// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The set of C listeners declared on one C-level entity is the port's
//! (`wz_capi_port::listeners`): it names no engine, and the cooperative engine's ABI holds the
//! same set. Re-exported here so the paths of the zenoh-c ABI stay.

pub use wz_capi_port::listeners::ListenerSet;
