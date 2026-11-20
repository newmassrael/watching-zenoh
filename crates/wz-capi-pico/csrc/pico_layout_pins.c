/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * What the Rust layer of wz-capi-pico writes into the storage a pico program allocates, pinned
 * against zenoh-pico's own header as the image that links the layer compiles it.
 *
 * On a 64-bit host the crate pins each type to the byte against pico's header (src/lib.rs). On
 * any other target the numbers it pinned are not the header's, so an image compiles this file
 * with pico's include directory and the `zenoh-pico/config.h` its switches made: a type the Rust
 * layer writes more of than the program's header gives it fails this build, which is the one
 * direction that writes past a program's storage. The Windows package's test compiles it the same
 * way against the package's headers, once with the compiler of each width the package ships
 * (scripts/lib/pico_windows_package.py). The Rust layer's owned and view types are
 * `repr(C)` over pointer-sized words, and each line below states how many; the crate's test
 * `layout_pins` holds every count to the Rust declaration it names, so the two cannot drift.
 *
 * An owned element (a sample, a query) is the Rust layer's handle in its first word and inert
 * padding after it (`element_bytes` in src/abi.rs), so what it needs of the program's storage is
 * that word.
 */

#include <zenoh-pico.h>

#define WZ_PIN_WORDS_CHECK(type, words)                                                          \
	_Static_assert(sizeof(type) >= (words) * sizeof(void *),                                 \
		       #type " holds fewer words than the wz Rust layer writes into it")
#define WZ_PIN_HANDLE_CHECK(type)                                                                \
	_Static_assert(sizeof(type) >= sizeof(void *),                                           \
		       #type " cannot hold the wz Rust layer's handle")

/* One line per type: the test reads `WZ_PIN_WORDS(<type>, <words>);` and `WZ_PIN_HANDLE(<type>);`
 * as written here, so each stays on one line.
 */
#define WZ_PIN_WORDS(type, words) WZ_PIN_WORDS_CHECK(type, words)
#define WZ_PIN_HANDLE(type) WZ_PIN_HANDLE_CHECK(type)

WZ_PIN_WORDS(z_owned_session_t, 2);
WZ_PIN_WORDS(z_owned_config_t, 4);
WZ_PIN_WORDS(z_owned_bytes_t, 4);
WZ_PIN_WORDS(z_owned_string_t, 4);
WZ_PIN_WORDS(z_view_keyexpr_t, 6);
WZ_PIN_WORDS(z_view_string_t, 4);
WZ_PIN_WORDS(z_owned_encoding_t, 5);
WZ_PIN_HANDLE(z_owned_sample_t);

#if Z_FEATURE_QUERYABLE == 1
WZ_PIN_WORDS(z_owned_closure_query_t, 3);
WZ_PIN_WORDS(z_owned_queryable_t, 4);
WZ_PIN_HANDLE(z_owned_query_t);
#endif

/* The querier is the Rust layer's only where the build asks queries. */
#if Z_FEATURE_QUERY == 1
WZ_PIN_WORDS(z_owned_querier_t, 23);
#endif
