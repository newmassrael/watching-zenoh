/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * wz_ext.h -- the C doors wz has and the upstream libraries do not.
 *
 * The drop-in headers declare upstream's functions only (docs/build-configuration.md,
 * decision C10): a program that includes a drop-in header and not this one is portable to
 * the upstream library. Every function of wz's own is `wz_ext_*` and declared here, so a
 * program that needs one says so by including this file, and the compiler tells it what is
 * not portable. scripts/lib/drop_in_header_gate.py holds both halves.
 *
 * No door is declared yet: the first ones are the switches of section 5 of the design that
 * expose a C call (a watch on a remote declaration, a pool's monitor). Include the drop-in
 * header of the library first; the declarations here use its types.
 */

#ifndef WZ_EXT_H
#define WZ_EXT_H

#endif /* WZ_EXT_H */
