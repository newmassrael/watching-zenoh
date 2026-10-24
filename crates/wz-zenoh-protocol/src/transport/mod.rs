//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-protocol 1.10.1, file
// src/transport/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! The messages of the transport layer: the opening, keeping and closing of a session between two
//! nodes, and the frames the network messages travel in. So far only the type of a sequence number,
//! which the resolution of a transport is defined over; the messages arrive with the transport slice.

pub type TransportSn = u32;
