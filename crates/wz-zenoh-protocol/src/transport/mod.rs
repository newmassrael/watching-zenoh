// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The messages of the transport layer: the opening, keeping and closing of a session between two
//! nodes, and the frames the network messages travel in. So far only the type of a sequence number,
//! which the resolution of a transport is defined over; the messages arrive with the transport slice.

pub type TransportSn = u32;
