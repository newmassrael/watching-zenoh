// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The request message of the network layer. So far only the type of a request id, which the
//! resolution of a transport is defined over; the message arrives with the network slice.

use core::sync::atomic::AtomicU32;

/// The resolution of a RequestId
pub type RequestId = u32;
pub type AtomicRequestId = AtomicU32;
