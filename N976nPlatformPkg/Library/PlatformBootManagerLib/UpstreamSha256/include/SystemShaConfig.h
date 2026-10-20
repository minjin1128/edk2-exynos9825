/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Minimal software-only SHA256 configuration; no entropy, allocations, TLS,
 * CPU feature probing, hardware acceleration or runtime system calls. */
#ifndef N976N_SYSTEM_SHA_CONFIG_H_
#define N976N_SYSTEM_SHA_CONFIG_H_
#if defined(__clang__)
#define MBEDTLS_CHECK_RETURN __attribute__((__warn_unused_result__))
#endif
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_SMALLER
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#endif
