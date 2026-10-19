/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  mbedtls_pk_info_t for mbedtls 2.x / 3.x, used to replace sign_func of the ECKEY pk with the ATECC608B.

  mbedtls 3.x has no public header for mbedtls_pk_info_t, so Variant B / C below are copies of the private
  struct in mbedtls library/pk_wrap.h. A copy that does not match the library breaks silently (memcpy of
  the wrong size, wrong function slots), so the variant is chosen by MBEDTLS_VERSION_NUMBER and other
  versions stop with #error. Compare the copy with library/pk_wrap.h when adding a version.
  - Variant C was checked against mbedtls 3.6.3 / 3.6.5 / 3.6.6 (ESP-IDF 5.0.9 - 5.5.4, Arduino core 3.x)
  - mbedtls 4.x does not use this file (PSA secure element driver, see device_key.hpp)
*/
#ifndef MBEDTLS_PK_INFO_COMPAT_H
#define MBEDTLS_PK_INFO_COMPAT_H

#include <mbedtls/version.h>
#include <mbedtls/pk.h>

#if MBEDTLS_VERSION_NUMBER >= 0x03070000
#error "mbedtls_pk_info_t is not checked for this mbedtls version (compare with library/pk_wrap.h)"
#endif

#if MBEDTLS_VERSION_NUMBER < 0x03000000
// ============================================================
// Variant A: mbedtls 2.x (Arduino core 2.x / ESP-IDF 4.x)
//   mbedtls_pk_info_t is public via pk_internal.h
//   sign_func: (void *ctx, ..., sig, sig_len, f_rng, p_rng)
// ============================================================
#include <mbedtls/pk_internal.h>
#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(member) member
#endif

using custom_sign_ctx_t = void *;

#elif MBEDTLS_VERSION_NUMBER < 0x03050000
// ============================================================
// Variant B: mbedtls 3.0 - 3.4 (early ESP-IDF 5.0 / 5.1 releases)
//   pk_internal.h removed; struct is opaque
//   sign_func: (void *ctx, ..., sig, sig_size, sig_len, f_rng, p_rng)
//   check_pair_func: added f_rng, p_rng
// ============================================================
struct mbedtls_pk_info_t {
    mbedtls_pk_type_t type;
    const char *name;
    size_t (*get_bitlen)(const void *);
    int (*can_do)(mbedtls_pk_type_t type);
    int (*verify_func)(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len);
    int (*sign_func)(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
                     unsigned char *sig, size_t sig_size, size_t *sig_len,
                     int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    int (*verify_rs_func)(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len, void *rs_ctx);
    int (*sign_rs_func)(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t sig_size, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, void *rs_ctx);
#endif
    int (*decrypt_func)(void *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen,
                        size_t osize, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
    int (*encrypt_func)(void *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen,
                        size_t osize, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
    int (*check_pair_func)(const void *pub, const void *prv, int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng);
    void *(*ctx_alloc_func)(void);
    void (*ctx_free_func)(void *ctx);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    void *(*rs_alloc_func)(void);
    void (*rs_free_func)(void *rs_ctx);
#endif
    void (*debug_func)(const void *ctx, mbedtls_pk_debug_item *items);
};

using custom_sign_ctx_t = void *;

#else
// ============================================================
// Variant C: mbedtls 3.5 - 3.6 (ESP-IDF 5.0.9 / 5.1.7 and later, Arduino core 3.x)
//   All function pointers changed from void* to mbedtls_pk_context*
// ============================================================
struct mbedtls_pk_info_t {
    mbedtls_pk_type_t type;
    const char *name;
    size_t (*get_bitlen)(mbedtls_pk_context *pk);
    int (*can_do)(mbedtls_pk_type_t type);
    int (*verify_func)(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len);
    int (*sign_func)(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
                     unsigned char *sig, size_t sig_size, size_t *sig_len,
                     int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    int (*verify_rs_func)(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len, void *rs_ctx);
    int (*sign_rs_func)(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t sig_size, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng, void *rs_ctx);
#endif
    int (*decrypt_func)(mbedtls_pk_context *pk, const unsigned char *input, size_t ilen, unsigned char *output,
                        size_t *olen, size_t osize, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
    int (*encrypt_func)(mbedtls_pk_context *pk, const unsigned char *input, size_t ilen, unsigned char *output,
                        size_t *olen, size_t osize, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
    int (*check_pair_func)(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
    void *(*ctx_alloc_func)(void);
    void (*ctx_free_func)(void *ctx);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    void *(*rs_alloc_func)(void);
    void (*rs_free_func)(void *rs_ctx);
#endif
    void (*debug_func)(mbedtls_pk_context *pk, mbedtls_pk_debug_item *items);
};

using custom_sign_ctx_t = mbedtls_pk_context *;

#endif

#endif  // MBEDTLS_PK_INFO_COMPAT_H
