/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The check a release package of the pico C ABI library is held to, compiled against the
 * package's own headers and linked against its own import library
 * (scripts/lib/pico_windows_package.py --test):
 *
 *   package_check <digest> <catalog>
 *
 * 1. The library is the build the package says it is: wz_ext_conformance_digest() equals the
 *    digest of the package's build-statement.json, which the packager wrote from the same
 *    preset the library was built from. A library of another feature set, limit or policy
 *    answers another digest.
 * 2. The configuration sample the package ships is one the library accepts: the message catalog
 *    is read by wz_ext_message_catalog_new and declares at least one message. A catalog the
 *    library refuses prints the refusal.
 * 3. The doors of the additional features run over the core they were built with: the version of
 *    the extension interface they need (wz_ext_additional_interface) is the core's
 *    (wz_ext_interface_version). In a package of one library both are that library's; in a package
 *    of two the doors are the additional library's, and the core the other's, so this holds the
 *    pair a package ships.
 *
 * Exit status 0 means all three held; the last line printed is the count either way.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zenoh-pico.h>

#include "wz_ext.h"

static int checks = 0;
static int failures = 0;

#define CHECK(cond, ...)                                             \
    do {                                                             \
        checks++;                                                    \
        if (!(cond)) {                                               \
            failures++;                                              \
            printf("package-check: FAIL at line %d: ", __LINE__);    \
            printf(__VA_ARGS__);                                     \
            printf("\n");                                            \
        }                                                            \
    } while (0)

/* The whole file as a NUL-terminated string, or NULL. */
static char *read_text(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    char *text = NULL;
    size_t len = 0;
    char chunk[4096];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, f)) > 0) {
        char *grown = realloc(text, len + got + 1);
        if (grown == NULL) {
            free(text);
            fclose(f);
            return NULL;
        }
        text = grown;
        memcpy(text + len, chunk, got);
        len += got;
    }
    fclose(f);
    if (text == NULL) text = calloc(1, 1);
    else text[len] = '\0';
    return text;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("usage: package_check <digest> <catalog>\n");
        return 2;
    }

    const char *digest = wz_ext_conformance_digest();
    CHECK(digest != NULL && strcmp(digest, argv[1]) == 0,
          "the library is not the build its statement names: the library says %s, the statement %s",
          digest == NULL ? "(null)" : digest, argv[1]);

    char *text = read_text(argv[2]);
    CHECK(text != NULL, "the catalog %s could not be read", argv[2]);
    if (text != NULL) {
        wz_ext_owned_message_catalog_t catalog;
        z_owned_string_t refusal;
        z_result_t rc = wz_ext_message_catalog_new(&catalog, text, &refusal);
        if (z_internal_string_check(&refusal)) {
            printf("package-check: the catalog was refused: %.*s\n", (int)z_string_len(z_string_loan(&refusal)),
                   z_string_data(z_string_loan(&refusal)));
            z_string_drop(z_string_move(&refusal));
        }
        CHECK(rc == Z_OK, "wz_ext_message_catalog_new refused the sample (rc %d)", (int)rc);
        if (rc == Z_OK) {
            size_t messages = wz_ext_message_catalog_len(wz_ext_message_catalog_loan(&catalog));
            CHECK(messages > 0, "the sample catalog declares no message");
            wz_ext_message_catalog_drop(wz_ext_message_catalog_move(&catalog));
        }
        free(text);
    }

    wz_ext_interface_version_t core_version;
    core_version.struct_size = sizeof core_version;
    CHECK(wz_ext_interface_version(&core_version) == Z_OK, "the core does not answer its interface version");
    wz_ext_interface_version_t needed;
    needed.struct_size = sizeof needed;
    z_result_t bound = wz_ext_additional_interface(&needed);
    CHECK(bound == Z_OK && needed.major == core_version.major && needed.minor <= core_version.minor,
          "the doors need interface %u.%u and the core is %u.%u (rc %d)", (unsigned)needed.major,
          (unsigned)needed.minor, (unsigned)core_version.major, (unsigned)core_version.minor, (int)bound);

    printf("package-check: %d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
