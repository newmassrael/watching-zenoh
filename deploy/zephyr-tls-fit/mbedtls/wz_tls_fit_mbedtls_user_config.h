/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Read by Mbed TLS after Zephyr's own configuration (CONFIG_MBEDTLS_USER_CONFIG_FILE).
 *
 * Zephyr's configuration defines the X.509 creation core only beside the CSR writer
 * (zephyr/modules/mbedtls/configs/config-mbedtls.h), and the certificate writer needs it too:
 * without this definition a build with CONFIG_MBEDTLS_X509_CRT_WRITE_C stops on Mbed TLS's own
 * prerequisite check. The device writes its own self-signed certificate, so it is needed.
 */

#ifndef WZ_TLS_FIT_MBEDTLS_USER_CONFIG_H
#define WZ_TLS_FIT_MBEDTLS_USER_CONFIG_H

#if defined(MBEDTLS_X509_CRT_WRITE_C) && !defined(MBEDTLS_X509_CREATE_C)
#define MBEDTLS_X509_CREATE_C
#endif

#endif /* WZ_TLS_FIT_MBEDTLS_USER_CONFIG_H */
