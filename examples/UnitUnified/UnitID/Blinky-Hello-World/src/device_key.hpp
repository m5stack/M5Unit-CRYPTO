/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  TLS device key for Blinky-Hello-World.
  The private key stays in the ATECC608B (Slot::PrimaryPrivateKey), which signs the TLS handshake.

  - mbedtls 2.x / 3.x (Arduino, ESP-IDF 5.x):
    an ECKEY pk whose sign_func is replaced with the ATECC608B (mbedtls_pk_info_compat.h).
    The TLS random numbers come from ctr_drbg / entropy.
  - mbedtls 4.x (ESP-IDF 6.1 or later):
    a PSA key in the secure element driver location (CONFIG_MBEDTLS_SECURE_ELEMENT_DRIVER_ENABLED),
    whose sign callback uses the ATECC608B. The TLS random numbers come from PSA.

  Only this file depends on the mbedtls version. Include it once, from the example source.
*/
#ifndef BLINKY_DEVICE_KEY_HPP
#define BLINKY_DEVICE_KEY_HPP

#include <cstring>

#include <M5UnitUnifiedCRYPTO.h>
#include <mbedtls/version.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#if MBEDTLS_VERSION_NUMBER < 0x04000000
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include "mbedtls_pk_info_compat.h"
#else
#if !defined(CONFIG_MBEDTLS_SECURE_ELEMENT_DRIVER_ENABLED)
// mbedtls 4.x signs with the ATECC608B through the PSA secure element driver (ESP-IDF 6.1 or later)
#error "Needs ESP-IDF 6.1+ and CONFIG_MBEDTLS_SECURE_ELEMENT_DRIVER_ENABLED=y (sdkconfig.defaults)"
#endif
#include <psa/crypto.h>
#include <psa_crypto_driver_secure_element.h>
#endif

namespace device_key {

using namespace m5::unit::atecc608;

m5::unit::UnitID *unit_ptr{};

#if MBEDTLS_VERSION_NUMBER < 0x04000000
// ==================================================================================================
// mbedtls 2.x / 3.x
// ==================================================================================================

mbedtls_pk_info_t pk_info{};
mbedtls_ctr_drbg_context ctr_drbg{};
mbedtls_entropy_context entropy{};

// If out is nullptr, only size calculation is performed
uint32_t encode_der_integer(uint8_t *out, const uint8_t *input, const uint32_t input_size)
{
    // Skip leading zero
    uint32_t leading_zeros = 0;
    while (leading_zeros < input_size && input[leading_zeros] == 0x00) {
        leading_zeros++;
    }

    // Padding if MSB 1
    bool needs_leading_zero = false;
    if (leading_zeros < input_size && (input[leading_zeros] & 0x80)) {
        needs_leading_zero = true;
    }

    // Size
    uint32_t value_size = input_size - leading_zeros;
    uint32_t total_size = 1 + 1 + (needs_leading_zero ? 1 : 0) + value_size;  // Tag + Length + [0x00] + value

    if (out) {
        uint32_t offset = 0;
        out[offset++]   = 0x02;  // INTEGER tag
        // Length
        out[offset++] = static_cast<uint8_t>((needs_leading_zero ? 1 : 0) + value_size);
        // Optional leading zero for positive integer
        if (needs_leading_zero) {
            out[offset++] = 0x00;
        }
        // Value
        memcpy(out + offset, input + leading_zeros, value_size);
    }
    return total_size;
}

int sign_callback(custom_sign_ctx_t ctx, const mbedtls_md_type_t md_alg, const unsigned char *hash,
                  const size_t hash_len, unsigned char *sig,
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
                  const size_t sig_size,
#endif
                  size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    (void)ctx;
    (void)md_alg;
    (void)(f_rng);
    (void)(p_rng);
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    (void)sig_size;
#endif

    // Sign
    if (hash_len != 32 || !unit_ptr->writeNonce32(Destination::MsgDigestBuffer, hash)) {
        M5_LOGE("NONCE NG:%u", hash_len);
        return MBEDTLS_ERR_PK_FILE_IO_ERROR;
    }
    uint8_t raw_sig[64]{};
    if (!unit_ptr->signExternal(raw_sig, Slot::PrimaryPrivateKey, Source::MsgDigestBuffer)) {
        M5_LOGE("SIGN NG:%u", hash_len);
        return MBEDTLS_ERR_PK_FILE_IO_ERROR;
    }

    // Write DER ASN1
    const uint8_t *R = raw_sig;
    const uint8_t *S = raw_sig + 32;

    uint8_t encoded_r[64]{};  // tag + length + optional 0x00 + value
    uint8_t encoded_s[64]{};
    uint32_t len_r = encode_der_integer(nullptr, R, 32);
    uint32_t len_s = encode_der_integer(nullptr, S, 32);
    if (len_r == 0 || len_s == 0 || len_r > sizeof(encoded_r) || len_s > sizeof(encoded_s)) {
        M5_LOGE("Invalid encoded size R:%u S:%u", len_r, len_s);
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    encode_der_integer(encoded_r, R, 32);
    encode_der_integer(encoded_s, S, 32);

    uint8_t *p = sig;
    *p++       = 0x30;                                 // SEQUENCE tag
    *p++       = static_cast<uint8_t>(len_r + len_s);  // total length
    memcpy(p, encoded_r, len_r);
    p += len_r;
    memcpy(p, encoded_s, len_s);
    p += len_s;
    *sig_len = static_cast<size_t>(p - sig);

    return 0;  // OK
}

bool begin_pk(mbedtls_pk_context *pkey)
{
    int ret = 0;
    uint8_t public_key[64]{};
    mbedtls_ecp_keypair *ecp = nullptr;

    if (!pkey) {
        return false;
    }

    mbedtls_pk_init(pkey);

    // Copy the ECKEY functions and replace sign_func with the ATECC608B
    const mbedtls_pk_info_t *orig_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    memcpy(&pk_info, orig_info, sizeof(*orig_info));
    pk_info.sign_func = sign_callback;
    if (mbedtls_pk_setup(pkey, &pk_info)) {
        return false;
    }

    // Public key
    if (!unit_ptr->generatePublicKey(public_key, Slot::PrimaryPrivateKey)) {
        return false;
    }

    // EC
    ecp = mbedtls_pk_ec(*pkey);
    if (mbedtls_ecp_group_load(&ecp->MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1)) {
        return false;
    }

    ret = mbedtls_mpi_read_binary(&ecp->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), public_key, 32);
    if (ret != 0) {
        return false;
    }
    ret = mbedtls_mpi_read_binary(&ecp->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), public_key + 32, 32);
    if (ret != 0) {
        return false;
    }
    if ((ret = mbedtls_mpi_lset(&ecp->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Z), 1)) != 0) {
        return false;
    }

    return true;
}

//! @brief Prepare the device key in pk
bool begin(m5::unit::UnitID &unit, mbedtls_pk_context *pk)
{
    unit_ptr = &unit;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    reinterpret_cast<const unsigned char *>("M5Unit-ID"), 10);
    if (ret != 0) {
        M5_LOGE("failed! mbedtls_ctr_drbg_seed returned -0x%x", -ret);
        return false;
    }
    return begin_pk(pk);
}

//! @brief Configure the TLS random number generator
void configure(mbedtls_ssl_config *conf)
{
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &ctr_drbg);
}

//! @brief Release the device key
void end(mbedtls_pk_context *pk)
{
    mbedtls_pk_free(pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

#else
// ==================================================================================================
// mbedtls 4.x (PSA crypto)
// ==================================================================================================

psa_key_id_t key_id{};

// Sign a SHA-256 hash with the private key in the slot. The signature is the raw R || S
psa_status_t sign_callback(const uint8_t slot_id, const uint8_t *hash, const size_t hash_len, uint8_t *sig,
                           const size_t sig_size, size_t *sig_len)
{
    if (hash_len != 32 || sig_size < 64) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (!unit_ptr->writeNonce32(Destination::MsgDigestBuffer, hash) ||
        !unit_ptr->signExternal(sig, static_cast<Slot>(slot_id), Source::MsgDigestBuffer)) {
        M5_LOGE("SIGN NG");
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    *sig_len = 64;
    return PSA_SUCCESS;
}

// Export the public key of the slot (raw X || Y)
psa_status_t export_pubkey_callback(const uint8_t slot_id, uint8_t *pubkey, const size_t pubkey_size,
                                    size_t *pubkey_len)
{
    if (pubkey_size < 64) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    if (!unit_ptr->generatePublicKey(pubkey, static_cast<Slot>(slot_id))) {
        return PSA_ERROR_HARDWARE_FAILURE;
    }
    *pubkey_len = 64;
    return PSA_SUCCESS;
}

//! @brief Prepare the device key in pk
bool begin(m5::unit::UnitID &unit, mbedtls_pk_context *pk)
{
    unit_ptr = &unit;

    // The callbacks can be registered only once (PSA_ERROR_BAD_STATE on reconnection)
    secure_element_callbacks_t cbs{};
    cbs.sign            = sign_callback;
    cbs.export_pubkey   = export_pubkey_callback;
    cbs.algorithm       = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    cbs.key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    cbs.key_bits        = 256;
    psa_status_t status = secure_element_register_callbacks(&cbs);
    if (status != PSA_SUCCESS && status != PSA_ERROR_BAD_STATE) {
        M5_LOGE("failed! secure_element_register_callbacks returned %d", static_cast<int>(status));
        return false;
    }

    // A PSA key that refers to the slot of the ATECC608B
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_SECURE_ELEMENT_VOLATILE);
    psa_set_key_type(&attr, cbs.key_type);
    psa_set_key_bits(&attr, cbs.key_bits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, cbs.algorithm);
    secure_element_opaque_key_t opaque{};
    opaque.slot_id = static_cast<uint8_t>(Slot::PrimaryPrivateKey);
    status         = psa_import_key(&attr, reinterpret_cast<const uint8_t *>(&opaque), sizeof(opaque), &key_id);
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        M5_LOGE("failed! psa_import_key returned %d", static_cast<int>(status));
        return false;
    }

    mbedtls_pk_init(pk);
    int ret = mbedtls_pk_wrap_psa(pk, key_id);
    if (ret != 0) {
        M5_LOGE("failed! mbedtls_pk_wrap_psa returned -0x%x", -ret);
        return false;
    }
    return true;
}

/*!
  @brief Configure the TLS signature algorithms
  @details ECDSA P-256 / SHA-256 is the only one the ATECC608B can sign with (CertificateVerify).
  The RSA ones are for verifying the server, whose certificate chain is RSA (Amazon Root CA 1).
 */
void configure(mbedtls_ssl_config *conf)
{
    static const uint16_t sig_algs[] = {MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
                                        MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256, MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256,
                                        MBEDTLS_TLS1_3_SIG_NONE};
    mbedtls_ssl_conf_sig_algs(conf, sig_algs);
}

//! @brief Release the device key
void end(mbedtls_pk_context *pk)
{
    mbedtls_pk_free(pk);
    psa_destroy_key(key_id);
    key_id = PSA_KEY_ID_NULL;
}
#endif

}  // namespace device_key
#endif
