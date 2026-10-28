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
 * Include the drop-in header of the library first; the declarations here use its types.
 */

#ifndef WZ_EXT_H
#define WZ_EXT_H

/* What an open of this config would ask of the operating system, as ONE
 * JSON object with the keys of the target-build manifest
 * (docs/target-build-contract.md T9):
 *
 *     {"requires": [...], "may_require": [...] or null, "unknown": [...]}
 *
 * requires is what every run of the config cannot go on without;
 * may_require is the rest a run may ask for, null when part of it has no
 * facility name, and unknown says why. The words are the manifest's
 * facility vocabulary. The config is read as z_open reads it, and is not
 * consumed. Part of the unstable surface: a library built without its
 * unstable API does not have it.
 *
 * Z_OK with the object, or the code z_open would refuse the config with,
 * the string then naming the reason. */
z_result_t wz_ext_config_device_requires(const z_loaned_config_t *config,
                                         z_owned_string_t *out_requirement);

/* A clock the program registers, which z_timestamp_new then stamps with in
 * place of the system clock: a disciplined hardware clock, or a time master
 * on the device's bus. Part of the unstable surface, and present only in a
 * build with the clock-source capability.
 *
 * The callback reads the time since the Unix epoch as whole seconds and the
 * nanoseconds within the second (below 1000000000). It returns 0 with both
 * written, or any other value when the clock cannot say what time it is: not
 * set, not yet synchronised, its bus silent. It is called from whichever
 * thread stamps, possibly several at once, and must be safe to call that way;
 * context must stay valid for as long as the source is registered. */
typedef int8_t wz_ext_clock_read_fn(void *context, uint64_t *secs,
                                    uint32_t *nanos);

/* Register a clock after those already registered: the first that can say
 * what time it is answers. If every registered clock is unable to, the library
 * knows no date, and z_timestamp_new fails; it does not fall back to the
 * system clock of a clock the program chose. out_handle receives the handle
 * wz_ext_clock_source_unregister takes and may be NULL.
 *
 * Z_OK; Z_ERR_NULL for a NULL callback; Z_ERR_OVERFLOW when the build's
 * CLOCK_SOURCES are all taken. */
z_result_t wz_ext_clock_source_register(wz_ext_clock_read_fn *read,
                                        void *context, uint32_t *out_handle);

/* Remove a clock registered earlier; the library then no longer calls the
 * callback. Z_ERR_INVALID for a handle that is not registered. */
z_result_t wz_ext_clock_source_unregister(uint32_t handle);

/* What the program tells the library about the registered clock. The library
 * cannot know whether the clock follows a reference; the program can. A build
 * whose clock-quality-stamping policy is trusted-only stamps nothing until the
 * program has reported WZ_EXT_CLOCK_SYNC_ACQUIRED. */
typedef uint8_t wz_ext_clock_event_t;
#define WZ_EXT_CLOCK_SYNC_ACQUIRED 0     /* it follows a reference */
#define WZ_EXT_CLOCK_SYNC_LOST 1         /* the reference is gone */
#define WZ_EXT_CLOCK_HOLDOVER_EXPIRED 2  /* the program's bound on running
                                            without a reference has passed */

/* Z_OK; Z_ERR_INVALID for another value. Reporting what is already so is not
 * an error. */
z_result_t wz_ext_clock_report(wz_ext_clock_event_t event);

#endif /* WZ_EXT_H */
