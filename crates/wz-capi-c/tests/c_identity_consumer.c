/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The identity a client presents, made from a REAL C translation unit:
 * wz_capi_c_identity_make compiled against wz_capi_c.h and linked against the
 * library, as a consumer's program is, in a directory of its own.
 *
 * What the Rust tests of the same door cannot show, and this can: that the
 * header compiles as C, that the symbol exports under the name it declares,
 * that the struct agrees in layout on both sides of the boundary, and that the
 * key the library writes is its owner's alone as the C side reads its mode.
 */

#define _XOPEN_SOURCE 700

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wz_capi_c.h"

static int failures = 0;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);             \
            fprintf(stderr, __VA_ARGS__);                                     \
            fprintf(stderr, "\n");                                            \
            failures++;                                                       \
        }                                                                     \
    } while (0)

static void check_layout(void) {
    /* A bool, 33 chars, then two pointers: the Rust struct is repr(C) in the
     * same order. */
    size_t align = _Alignof(const char *);
    size_t file_at = ((1 + WZ_CAPI_C_IDENTITY_ZID_MAX + align - 1) / align) * align;
    CHECK(offsetof(wz_capi_c_identity_t, made) == 0, "made");
    CHECK(offsetof(wz_capi_c_identity_t, zid) == 1, "zid");
    CHECK(offsetof(wz_capi_c_identity_t, file) == file_at, "file");
    CHECK(offsetof(wz_capi_c_identity_t, reason) == file_at + sizeof(void *), "reason");
}

static bool is_zid_text(const char *zid) {
    size_t n = strlen(zid);
    if (n == 0 || n > 32 || zid[0] == '0') {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        bool digit = zid[i] >= '0' && zid[i] <= '9';
        bool lower = zid[i] >= 'a' && zid[i] <= 'f';
        if (!digit && !lower) {
            return false;
        }
    }
    return true;
}

static void check_make(const char *dir) {
    char cert[512], key[512];
    snprintf(cert, sizeof cert, "%s/me.crt", dir);
    snprintf(key, sizeof key, "%s/me.key", dir);

    wz_capi_c_identity_t first;
    memset(&first, 0xa5, sizeof first);
    CHECK(wz_capi_c_identity_make(cert, key, &first) == Z_OK, "the first make");
    CHECK(first.made, "the first call made nothing");
    CHECK(is_zid_text(first.zid), "zid %s", first.zid);
    CHECK(first.file == NULL && first.reason == NULL, "a refusal on success");

    struct stat st;
    CHECK(stat(key, &st) == 0 && (st.st_mode & 0777) == 0600, "key mode %o",
          (unsigned)(st.st_mode & 0777));

    wz_capi_c_identity_t again;
    CHECK(wz_capi_c_identity_make(cert, key, &again) == Z_OK, "the second make");
    CHECK(!again.made, "the second call made the files again");
    CHECK(strcmp(again.zid, first.zid) == 0, "zid %s then %s", first.zid, again.zid);

    CHECK(unlink(key) == 0, "remove the key");
    wz_capi_c_identity_t half;
    CHECK(wz_capi_c_identity_make(cert, key, &half) == Z_EIO, "half an identity");
    CHECK(!half.made && half.zid[0] == '\0', "half an identity answered a zid");
    CHECK(half.file != NULL && strcmp(half.file, "the private key") == 0, "file %s",
          half.file ? half.file : "(null)");
    CHECK(half.reason != NULL && strlen(half.reason) > 0, "no reason");
    CHECK(access(key, F_OK) != 0, "a key was made beside a certificate");

    CHECK(wz_capi_c_identity_make(NULL, key, &half) == Z_ENULL, "a NULL certificate");
    CHECK(wz_capi_c_identity_make(cert, key, NULL) == Z_ENULL, "a NULL out");
    unlink(cert);
}

int main(void) {
    char dir[] = "/tmp/wz-c-identity-XXXXXX";
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    check_layout();
    check_make(dir);
    rmdir(dir);
    if (failures != 0) {
        fprintf(stderr, "c_identity_consumer: %d failure(s)\n", failures);
        return 1;
    }
    printf("c_identity_consumer: ok\n");
    return 0;
}
