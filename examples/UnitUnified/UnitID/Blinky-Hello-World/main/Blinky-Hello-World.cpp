/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  M5Unit-ID example. Connect to AWS IoT.
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedCRYPTO.h>
#include <M5Utility.h>
#include <M5HAL.hpp>

#include <WiFi.h>

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/debug.h>

#include "../src/mbedtls_pk_info_compat.h"

using namespace m5::unit::atecc608;

namespace {

// ****************************************************************************************************
// Settings
// ****************************************************************************************************
// Fill in the following define or specify with build option
// ****************************************************************************************************
// Enable this define when using M5Core2AWS's built-in chip
#if !defined(USING_M5CORE2_AWS_BUILTIN)
// #define USING_M5CORE2_AWS_BUILTIN
#endif

#if !defined(EXAMPLE_SSID)
#define EXAMPLE_SSID ""  // SSID
#endif
#if !defined(EXAMPLE_PASSWORD)
#define EXAMPLE_PASSWORD ""  // SSID Password
#endif
#if !defined(EXAMPLE_MQTT_URI)
#define EXAMPLE_MQTT_URI ""  // AWS Endpoint URI
#endif
#ifndef EXAMPLE_MQTT_PORT
#define EXAMPLE_MQTT_PORT (8883)  // Port number
#endif
const char *ssid         = EXAMPLE_SSID;
const char *password     = EXAMPLE_PASSWORD;
const char *mqtt_uri     = EXAMPLE_MQTT_URI;
const uint16_t mqtt_port = EXAMPLE_MQTT_PORT;
char mqtt_port_str[32]{};

// Amazon Root CA 1 (Server cert)
constexpr uint8_t root_ca_der[] = {
    0x30, 0x82, 0x03, 0x41, 0x30, 0x82, 0x02, 0x29, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x13, 0x06, 0x6c, 0x9f, 0xcf,
    0x99, 0xbf, 0x8c, 0x0a, 0x39, 0xe2, 0xf0, 0x78, 0x8a, 0x43, 0xe6, 0x96, 0x36, 0x5b, 0xca, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x39, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x06, 0x41,
    0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x10, 0x41, 0x6d, 0x61,
    0x7a, 0x6f, 0x6e, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x20, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35,
    0x30, 0x35, 0x32, 0x36, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x38, 0x30, 0x31, 0x31, 0x37,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x39, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x55, 0x53, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x06, 0x41, 0x6d, 0x61, 0x7a, 0x6f,
    0x6e, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x10, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x20,
    0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x20, 0x31, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02,
    0x82, 0x01, 0x01, 0x00, 0xb2, 0x78, 0x80, 0x71, 0xca, 0x78, 0xd5, 0xe3, 0x71, 0xaf, 0x47, 0x80, 0x50, 0x74, 0x7d,
    0x6e, 0xd8, 0xd7, 0x88, 0x76, 0xf4, 0x99, 0x68, 0xf7, 0x58, 0x21, 0x60, 0xf9, 0x74, 0x84, 0x01, 0x2f, 0xac, 0x02,
    0x2d, 0x86, 0xd3, 0xa0, 0x43, 0x7a, 0x4e, 0xb2, 0xa4, 0xd0, 0x36, 0xba, 0x01, 0xbe, 0x8d, 0xdb, 0x48, 0xc8, 0x07,
    0x17, 0x36, 0x4c, 0xf4, 0xee, 0x88, 0x23, 0xc7, 0x3e, 0xeb, 0x37, 0xf5, 0xb5, 0x19, 0xf8, 0x49, 0x68, 0xb0, 0xde,
    0xd7, 0xb9, 0x76, 0x38, 0x1d, 0x61, 0x9e, 0xa4, 0xfe, 0x82, 0x36, 0xa5, 0xe5, 0x4a, 0x56, 0xe4, 0x45, 0xe1, 0xf9,
    0xfd, 0xb4, 0x16, 0xfa, 0x74, 0xda, 0x9c, 0x9b, 0x35, 0x39, 0x2f, 0xfa, 0xb0, 0x20, 0x50, 0x06, 0x6c, 0x7a, 0xd0,
    0x80, 0xb2, 0xa6, 0xf9, 0xaf, 0xec, 0x47, 0x19, 0x8f, 0x50, 0x38, 0x07, 0xdc, 0xa2, 0x87, 0x39, 0x58, 0xf8, 0xba,
    0xd5, 0xa9, 0xf9, 0x48, 0x67, 0x30, 0x96, 0xee, 0x94, 0x78, 0x5e, 0x6f, 0x89, 0xa3, 0x51, 0xc0, 0x30, 0x86, 0x66,
    0xa1, 0x45, 0x66, 0xba, 0x54, 0xeb, 0xa3, 0xc3, 0x91, 0xf9, 0x48, 0xdc, 0xff, 0xd1, 0xe8, 0x30, 0x2d, 0x7d, 0x2d,
    0x74, 0x70, 0x35, 0xd7, 0x88, 0x24, 0xf7, 0x9e, 0xc4, 0x59, 0x6e, 0xbb, 0x73, 0x87, 0x17, 0xf2, 0x32, 0x46, 0x28,
    0xb8, 0x43, 0xfa, 0xb7, 0x1d, 0xaa, 0xca, 0xb4, 0xf2, 0x9f, 0x24, 0x0e, 0x2d, 0x4b, 0xf7, 0x71, 0x5c, 0x5e, 0x69,
    0xff, 0xea, 0x95, 0x02, 0xcb, 0x38, 0x8a, 0xae, 0x50, 0x38, 0x6f, 0xdb, 0xfb, 0x2d, 0x62, 0x1b, 0xc5, 0xc7, 0x1e,
    0x54, 0xe1, 0x77, 0xe0, 0x67, 0xc8, 0x0f, 0x9c, 0x87, 0x23, 0xd6, 0x3f, 0x40, 0x20, 0x7f, 0x20, 0x80, 0xc4, 0x80,
    0x4c, 0x3e, 0x3b, 0x24, 0x26, 0x8e, 0x04, 0xae, 0x6c, 0x9a, 0xc8, 0xaa, 0x0d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,
    0x42, 0x30, 0x40, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
    0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x84, 0x18, 0xcc, 0x85, 0x34, 0xec, 0xbc, 0x0c, 0x94, 0x94,
    0x2e, 0x08, 0x59, 0x9c, 0xc7, 0xb2, 0x10, 0x4e, 0x0a, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x98, 0xf2, 0x37, 0x5a, 0x41, 0x90, 0xa1, 0x1a,
    0xc5, 0x76, 0x51, 0x28, 0x20, 0x36, 0x23, 0x0e, 0xae, 0xe6, 0x28, 0xbb, 0xaa, 0xf8, 0x94, 0xae, 0x48, 0xa4, 0x30,
    0x7f, 0x1b, 0xfc, 0x24, 0x8d, 0x4b, 0xb4, 0xc8, 0xa1, 0x97, 0xf6, 0xb6, 0xf1, 0x7a, 0x70, 0xc8, 0x53, 0x93, 0xcc,
    0x08, 0x28, 0xe3, 0x98, 0x25, 0xcf, 0x23, 0xa4, 0xf9, 0xde, 0x21, 0xd3, 0x7c, 0x85, 0x09, 0xad, 0x4e, 0x9a, 0x75,
    0x3a, 0xc2, 0x0b, 0x6a, 0x89, 0x78, 0x76, 0x44, 0x47, 0x18, 0x65, 0x6c, 0x8d, 0x41, 0x8e, 0x3b, 0x7f, 0x9a, 0xcb,
    0xf4, 0xb5, 0xa7, 0x50, 0xd7, 0x05, 0x2c, 0x37, 0xe8, 0x03, 0x4b, 0xad, 0xe9, 0x61, 0xa0, 0x02, 0x6e, 0xf5, 0xf2,
    0xf0, 0xc5, 0xb2, 0xed, 0x5b, 0xb7, 0xdc, 0xfa, 0x94, 0x5c, 0x77, 0x9e, 0x13, 0xa5, 0x7f, 0x52, 0xad, 0x95, 0xf2,
    0xf8, 0x93, 0x3b, 0xde, 0x8b, 0x5c, 0x5b, 0xca, 0x5a, 0x52, 0x5b, 0x60, 0xaf, 0x14, 0xf7, 0x4b, 0xef, 0xa3, 0xfb,
    0x9f, 0x40, 0x95, 0x6d, 0x31, 0x54, 0xfc, 0x42, 0xd3, 0xc7, 0x46, 0x1f, 0x23, 0xad, 0xd9, 0x0f, 0x48, 0x70, 0x9a,
    0xd9, 0x75, 0x78, 0x71, 0xd1, 0x72, 0x43, 0x34, 0x75, 0x6e, 0x57, 0x59, 0xc2, 0x02, 0x5c, 0x26, 0x60, 0x29, 0xcf,
    0x23, 0x19, 0x16, 0x8e, 0x88, 0x43, 0xa5, 0xd4, 0xe4, 0xcb, 0x08, 0xfb, 0x23, 0x11, 0x43, 0xe8, 0x43, 0x29, 0x72,
    0x62, 0xa1, 0xa9, 0x5d, 0x5e, 0x08, 0xd4, 0x90, 0xae, 0xb8, 0xd8, 0xce, 0x14, 0xc2, 0xd0, 0x55, 0xf2, 0x86, 0xf6,
    0xc4, 0x93, 0x43, 0x77, 0x66, 0x61, 0xc0, 0xb9, 0xe8, 0x41, 0xd7, 0x97, 0x78, 0x60, 0x03, 0x6e, 0x4a, 0x72, 0xae,
    0xa5, 0xd1, 0x7d, 0xba, 0x10, 0x9e, 0x86, 0x6c, 0x1b, 0x8a, 0xb9, 0x59, 0x33, 0xf8, 0xeb, 0xc4, 0x90, 0xbe, 0xf1,
    0xb9};

auto &lcd = M5.Display;
m5::unit::UnitUnified Units;
m5::unit::UnitID unit;

mbedtls_x509_crt cacert{};   // Server Root CA cert
mbedtls_x509_crt clicert{};  // Client device cert
mbedtls_pk_context pkey{};   //
mbedtls_ssl_config conf{};
mbedtls_ssl_context ssl{};
mbedtls_ctr_drbg_context ctr_drbg{};
mbedtls_entropy_context entropy{};
mbedtls_net_context server_fd{};
mbedtls_pk_info_t my_pk_info{};

char mqtt_topic[128]{};  // Top level topic and thing name
bool waiting_pingresp{};

uint16_t get_next_packet_id()
{
    static uint16_t global_packet_id{1};
    global_packet_id = (global_packet_id == 65535) ? 1 : (global_packet_id + 1);
    return global_packet_id;
}

#if 0
void dump_ssl_peer_cert(mbedtls_ssl_context* ssl, const bool der = false)
{
    const mbedtls_x509_crt* peer_cert = mbedtls_ssl_get_peer_cert(ssl);
    if (peer_cert == nullptr) {
        M5_LOGE("No peer certificate received");
        return;
    }

    char buf[2048]{};
    int ret = mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", peer_cert);
    if (ret > 0) {
        buf[ret] = '\0';
        M5_LOGI("Peer certificate info:\n%s", buf);
    } else {
        M5_LOGE("Failed to parse peer certificate info");
    }
    if (der) {
        M5_LOGI("Peer certificate DER dump:");
        m5::utility::log::dump(peer_cert->raw.p, peer_cert->raw.len, false);
    }
}
#endif

void dump_cert(const mbedtls_x509_crt *cert, const bool raw = false)
{
    if (!cert) {
        return;
    }

    M5_LOGI("ext_types = 0x%X", cert->MBEDTLS_PRIVATE(ext_types));
    for (const mbedtls_x509_sequence *san = &(cert->subject_alt_names); san; san = san->next) {
        M5_LOGI("SAN Tag:%d Len:%zu", san->buf.tag, san->buf.len);
    }

    char buf[2048]{};
    int ret = mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", cert);
    if (ret > 0) {
        buf[ret] = '\0';
        M5_LOGI("Certificate info:\n%s", buf);
    } else {
        M5_LOGE("Failed to parse signer certificate info");
    }
    if (raw) {
        m5::utility::log::dump(cert->raw.p, cert->raw.len, false);
    }
}

void printPEM(const uint8_t *der, const uint32_t dlen)
{
    char buf[1024]{};
    if (convertToPEM(buf, sizeof(buf), der, dlen)) {
        M5.Log.printf("%s", buf);
    } else {
        M5_LOGE("Failed to convert PEM");
    }
}

void print_provisioning(m5::unit::UnitID &u)
{
    char sn[19]{};
    uint8_t cert[768]{};
    uint16_t clen{sizeof(cert)};

    if (!u.readSerialNumber(sn)) {
        M5_LOGE("Failed to readSerialNumber");
        return;
    }
    if (!u.readDeviceCertificate(cert, clen)) {
        M5_LOGE("Failed to readDeviceCertificate");
        return;
    }

    M5.Log.printf("For provisioning:\n");
    M5.Log.printf("SerialNumber:%s\n", sn);
    M5.Log.printf("DeviceCert:\n");
    printPEM(cert, clen);
}

// If out is nullptr, only size calculation is performed
uint32_t encode_der_integer(uint8_t *out, const uint8_t *input, uint32_t input_size)
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

int custom_sign_callback(custom_sign_ctx_t ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,
                         unsigned char *sig,
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
                         size_t sig_size,
#endif
                         size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    (void)ctx;
    (void)md_alg;
    (void)(f_rng);
    (void)(p_rng);
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
    (void)sig_size;
#endif

    // Sign
    if (hash_len != 32 || !unit.writeNonce32(Destination::MsgDigestBuffer, hash)) {
        M5_LOGE("NONCE NG:%u", hash_len);
        return MBEDTLS_ERR_PK_FILE_IO_ERROR;
    }
    uint8_t raw_sig[64]{};
    if (!unit.signExternal(raw_sig, Slot::PrimaryPrivateKey, Source::MsgDigestBuffer)) {
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

bool connectWiFi()
{
    // Tab5 (ESP32-P4) uses ESP32-C6 co-processor for WiFi via SDIO; set pins before WiFi.begin()
#if defined(CONFIG_IDF_TARGET_ESP32P4)
    if (M5.getBoard() == m5::board_t::board_M5Tab5) {
        constexpr int SDIO2_CLK = 12;
        constexpr int SDIO2_CMD = 13;
        constexpr int SDIO2_D0  = 11;
        constexpr int SDIO2_D1  = 10;
        constexpr int SDIO2_D2  = 9;
        constexpr int SDIO2_D3  = 8;
        constexpr int SDIO2_RST = 15;
        WiFi.setPins(SDIO2_CLK, SDIO2_CMD, SDIO2_D0, SDIO2_D1, SDIO2_D2, SDIO2_D3, SDIO2_RST);
    }
#endif

    WiFi.mode(WIFI_STA);
    if (ssid && ssid[0] && password && password[0]) {
        M5_LOGI("Use ssid:%s and password", ssid);
        WiFi.begin(ssid, password);
    } else {
        M5_LOGI("Use inner credential");
        WiFi.begin();
    }
    uint32_t retry{10};
    while (retry--) {
        m5::utility::delay(500);
        if (WiFi.status() == WL_CONNECTED) {
            return true;
        }
        M5.Log.print(".\n");
    }
    return false;
}

bool init_pk(mbedtls_pk_context *pkey)
{
    int ret = 0;
    uint8_t public_key[64]{};
    mbedtls_ecp_keypair *ecp = nullptr;

    if (!pkey) {
        return false;
    }

    mbedtls_pk_init(pkey);

    // sign_func to our process
    //    my_pk_info           = *(mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    const mbedtls_pk_info_t *orig_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    memcpy(&my_pk_info, orig_info, sizeof(*orig_info));
    my_pk_info.sign_func = custom_sign_callback;
    if (mbedtls_pk_setup(pkey, &my_pk_info)) {
        return false;
    }

    // Public key
    if (!unit.generatePublicKey(public_key, Slot::PrimaryPrivateKey)) {
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

int verify_cert(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    char buf[1024]{};
    ((void)data);

    M5_LOGI("Verify requested for (Depth %d):", depth);
    dump_cert(crt);

    if ((*flags) == 0) {
        M5_LOGI("  This certificate has no flags");
    } else {
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", *flags);
        M5_LOGE("Verification issues:\n%s", buf);
    }
    // Returns non-zero if you want to deny connections to a specific server
    return 0;
}

bool connectTLS()
{
    int ret = 0;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&pkey);

    // Seeding the random number generator
    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"M5Unit-ID",
                                     10)) != 0) {
        M5_LOGE("failed! mbedtls_ctr_drbg_seed returned -0x%x", -ret);
        return false;
    }

    //  Load root CA
    if ((ret = mbedtls_x509_crt_parse_der(&cacert, root_ca_der, sizeof(root_ca_der))) != 0) {
        M5_LOGE("failed!  mbedtls_x509_crt_parse returned -0x%x while parsing root cert", -ret);
        return false;
    }

    // Load client cert (Device cert)
    uint8_t dcert[1024]{};
    uint16_t dlen{sizeof(dcert)};
    if (!unit.readDeviceCertificate(dcert, dlen)) {
        M5_LOGE("failed! readDeviceCertificate");
        return false;
    }
    if ((ret = mbedtls_x509_crt_parse_der(&clicert, dcert, dlen)) != 0) {
        M5_LOGE("failed!  mbedtls_x509_crt_parse returned -0x%x while parsing root cert", -ret);
        return false;
    }

    // Pkey
    if (!init_pk(&pkey)) {
        M5_LOGE("failed! init_pk");
        return false;
    }

    // Connect
    M5_LOGI("Connecting to %s:%s...", mqtt_uri, mqtt_port_str);

    if ((ret = mbedtls_net_connect(&server_fd, mqtt_uri, mqtt_port_str, MBEDTLS_NET_PROTO_TCP)) != 0) {
        M5_LOGE("failed! mbedtls_net_connect returned -0x%x", -ret);
        switch (ret) {
            case MBEDTLS_ERR_NET_SOCKET_FAILED:
                M5_LOGE("MBEDTLS_ERR_NET_SOCKET_FAILED");
                break;
            case MBEDTLS_ERR_NET_UNKNOWN_HOST:
                M5_LOGE("MBEDTLS_ERR_NET_UNKNOWN_HOST");
                break;
            case MBEDTLS_ERR_NET_CONNECT_FAILED:
                M5_LOGE("MBEDTLS_ERR_NET_CONNECT_FAILED");
                break;
            default:
                break;
        }
        return false;
    }
    if ((ret = mbedtls_net_set_block(&server_fd)) != 0) {
        M5_LOGE("failed! net_set_block() returned -0x%x", -ret);
        return false;
    }

    // Setting up the SSL/TLS structure
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        M5_LOGE("failed! mbedtls_ssl_config_defaults returned -0x%x", -ret);
        return false;
    }

    mbedtls_ssl_conf_verify(&conf, verify_cert, nullptr);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);

    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey)) != 0) {
        M5_LOGE("failed! mbedtls_ssl_conf_own_cert returned %d", ret);
        return false;
    }
    mbedtls_ssl_conf_read_timeout(&conf, 5000);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        M5_LOGE("failed! mbedtls_ssl_setup returned -0x%x", -ret);
        return false;
    }
    if ((ret = mbedtls_ssl_set_hostname(&ssl, mqtt_uri)) != 0) {
        M5_LOGE("failed! mbedtls_ssl_set_hostname returned %d", ret);
        return false;
    }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, nullptr, mbedtls_net_recv_timeout);

    // Performing the SSL/TLS handshake
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            M5_LOGE("failed! mbedtls_ssl_handshake returned -0x%x", -ret);
            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                M5_LOGE("    Unable to verify the server's certificate");
            }
            return false;
        }
    }

    M5_LOGI("Handshake Protocol:%s Ciphersuite:%s Record expeansion:", mbedtls_ssl_get_version(&ssl),
            mbedtls_ssl_get_ciphersuite(&ssl));
    if ((ret = mbedtls_ssl_get_record_expansion(&ssl)) >= 0) {
        M5_LOGI("Record expansion:%d", ret);
    } else {
        M5_LOGI("Record expansion is unknown (compression)");
    }

    // Verifying peer X.509 certificate
    if ((ret = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
        char buf[256]{};
        M5_LOGE("failed! Server Verification");
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", ret);
        M5_LOGE("%s", buf);
        return false;
    }

    if (mbedtls_ssl_get_peer_cert(&ssl)) {
        char buf[256]{};
        M5_LOGI("Peer certificate information:");
        mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&ssl));
        M5_LOGI("%s", buf);
    }

#if 0
    if ((ret = mbedtls_net_set_nonblock(&server_fd)) != 0) {
        M5_LOGE("failed! net_set_nonblock() returned -0x%x", -ret);
        return false;
    }
#endif

    return true;
}

void cleanupTLS()
{
    mbedtls_net_free(&server_fd);

    mbedtls_x509_crt_free(&clicert);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void mqtt_payload_handler(const char *topic, const char *payload, uint32_t plen)
{
    char top_topic[128]{};
    const char *sub_topic{};

    M5_LOGD("PUBLISH received: topic=%s", topic);

    // Split topic
    const char *slash = strchr(topic, '/');
    if (slash) {
        strncpy(top_topic, topic, slash - topic);
        sub_topic = slash + 1;
    }

    //  Receive "AWSclientId/blink" ?
    if (sub_topic && strcmp(sub_topic, "blink") == 0) {
        static uint32_t blink_count{};
        ++blink_count;
        M5.Log.printf("  == Receive blink %u\n", blink_count);
        lcd.fillScreen((blink_count & 1) ? TFT_ORANGE : TFT_DARKGREEN);
        M5.Speaker.tone(2000, 20);

    } else {
        //        M5.Log.printf("recv msg: %.*s\n", plen, payload);
    }
}

// Read packet
bool mqtt_cycle_read(uint8_t &out_type)
{
    out_type = 0;

    uint8_t buf[128]{};
    int ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf));

    if (ret <= 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            // M5_LOGD("MBEDTLS_ERR_SSL_WANT_READ / MBEDTLS_ERR_SSL_TIMEOUT");
            return true;
        }
        M5_LOGE("mbedtls_ssl_read error: -0x%X", -ret);
        return false;
    }

    out_type = buf[0] >> 4;
    switch (out_type) {
        case 3: {  // PUBLISH
            uint16_t topic_len = (buf[2] << 8) | buf[3];
            if (topic_len + 4 > ret) {
                M5_LOGE("Invalid PUBLISH packet (too short)");
                return false;
            }

            char topic[64]{};
            memcpy(topic, &buf[4], topic_len);

            char payload[128]{};
            uint16_t payload_len = ret - 4 - topic_len;
            memcpy(payload, &buf[4 + topic_len], payload_len);

            mqtt_payload_handler(topic, payload, payload_len);
            break;
        }
        case 13:  // PINGRESP
            M5_LOGD("PINGRESP received");
            waiting_pingresp = false;
            break;
        case 9:   // SUBACK
        case 2:   // CONNACK
        case 4:   // PUBACK
        case 11:  // UNSUBACK
            break;
        default:
            M5_LOGW("Unhandled MQTT packet type: %d", out_type);
            break;
    }
    return true;
}

// Waiting for receipt of specified packet type
bool mqtt_wait_for(uint8_t expected_type, uint32_t timeout_ms)
{
    auto timeout_at = m5::utility::millis() + timeout_ms;
    do {
        uint8_t packet_type{};
        if (!mqtt_cycle_read(packet_type)) {
            return false;
        }
        if (packet_type == expected_type) {
            return true;
        }
    } while (m5::utility::millis() <= timeout_at);
    M5_LOGE("wait_for: timeout waiting for type=%d", expected_type);
    return false;
}

bool publishMQTTMessage(const char *top_topic, const char *sub_topic, const char *message, const bool qos1 = false)
{
    uint8_t publish_pkt[256]{};

    // Build topic
    char full_topic[128]{};
    strcpy(full_topic, top_topic);
    if (sub_topic && sub_topic[0]) {
        if (sub_topic[0] != '/') {
            strcat(full_topic, "/");
        }
        strcat(full_topic, sub_topic);
    }
    uint16_t topic_len = strlen(full_topic);
    size_t message_len = strlen(message);

    if (topic_len > 127 || message_len > 100) {
        M5_LOGE("Topic or payload too long");
        return false;
    }

    // Fixed Header
    publish_pkt[0] = 0x30 | (qos1 ? 0x02 : 0x00);  // Packet Type:PUBLISH| QoS bits
    publish_pkt[1] = 0;                            // Remaining Length

    uint32_t pos = 2;

    // Variable Header
    publish_pkt[pos++] = (topic_len >> 8) & 0xFF;
    publish_pkt[pos++] = topic_len & 0xFF;
    memcpy(publish_pkt + pos, full_topic, topic_len);
    pos += topic_len;

    // QoS1: Packet Identifier
    if (qos1) {
        uint16_t packet_id = get_next_packet_id();
        publish_pkt[pos++] = (packet_id >> 8) & 0xFF;
        publish_pkt[pos++] = packet_id & 0xFF;
    }

    // Payload
    memcpy(publish_pkt + pos, message, message_len);
    pos += message_len;

    // Remaining Length
    uint8_t remaining_len = pos - 2;
    publish_pkt[1]        = remaining_len;

    M5_LOGD("Try Publish %s/%s %s (QoS=%d)", top_topic, sub_topic, message, qos1 ? 1 : 0);

    int ret = mbedtls_ssl_write(&ssl, publish_pkt, pos);
    if (ret <= 0) {
        M5_LOGE("mbedtls_ssl_write failed: -0x%x", -ret);
        return false;
    }

    M5_LOGD("MQTT PUBLISH sent: topic=%s message=%s", full_topic, message);

    return qos1 ? mqtt_wait_for(4 /* PUBACK */, 5000) : true;
}

bool connectMQTT(const char *client_id)
{
    uint8_t connect_pkt[128]{0x10, 0x00};  // Packet Type: CONNECT, Remaining Length
    const uint32_t client_id_len = strlen(client_id);

    uint32_t pos = 2;

    // Protocol Name "MQTT"
    connect_pkt[pos++] = 0x00;
    connect_pkt[pos++] = 0x04;
    connect_pkt[pos++] = 'M';
    connect_pkt[pos++] = 'Q';
    connect_pkt[pos++] = 'T';
    connect_pkt[pos++] = 'T';

    // Protocol Level (4 = MQTT 3.1.1)
    connect_pkt[pos++] = 0x04;

    // Connect Flags: Clean Session (bit 1)
    connect_pkt[pos++] = 0x02;

    // KeepAlive = 10 sec
    connect_pkt[pos++] = 0x00;
    connect_pkt[pos++] = 0x0A;

    // Client ID
    connect_pkt[pos++] = (client_id_len >> 8) & 0xFF;
    connect_pkt[pos++] = client_id_len & 0xFF;
    memcpy(connect_pkt + pos, client_id, client_id_len);
    pos += client_id_len;

    // Fixed Header: Remaining Length
    connect_pkt[1] = pos - 2;

    M5_LOGD("Try MQTT CONNECT [%s]", client_id);

    int ret = mbedtls_ssl_write(&ssl, connect_pkt, pos);
    if (ret <= 0) {
        M5_LOGE("mbedtls_ssl_write CONNECT failed: -0x%x", -ret);
        return false;
    }

    // Wait receive CONNACK
    return mqtt_wait_for(2 /* CONNACK */, 2000);
}

bool subscribeMQTT(const char *topic)
{
    uint16_t packet_id = get_next_packet_id();
    uint16_t topic_len = strlen(topic);
    uint8_t subscribe_pkt[128]{};

    uint32_t pos         = 0;
    subscribe_pkt[pos++] = 0x82;                   // Packet Type: SUBSCRIBE + QoS1
    subscribe_pkt[pos++] = 2 + 2 + topic_len + 1;  // Remaining Length

    subscribe_pkt[pos++] = (packet_id >> 8) & 0xFF;
    subscribe_pkt[pos++] = packet_id & 0xFF;

    subscribe_pkt[pos++] = (topic_len >> 8) & 0xFF;
    subscribe_pkt[pos++] = topic_len & 0xFF;
    memcpy(&subscribe_pkt[pos], topic, topic_len);
    pos += topic_len;
    subscribe_pkt[pos++] = 0x00;  // QoS 0

    M5_LOGD("Try MQTT SUBSCRIBE [%s]", topic);

    int ret = mbedtls_ssl_write(&ssl, subscribe_pkt, pos);
    if (ret <= 0) {
        M5_LOGE("mbedtls_ssl_write failed: -0x%x", -ret);
        return false;
    }

    // Wait receive SUBACK
    return mqtt_wait_for(9 /* SUBACK */, 2000);
}

bool yieldMQTT(uint32_t timeout_ms)
{
    auto start      = m5::utility::millis();
    auto timeout_at = start + timeout_ms;

    static decltype(start) pingresp_timeout_at{}, ping_at{};

    constexpr uint32_t keepAliveMs = 10000;

    do {
        auto now = m5::utility::millis();

        // Read incoming packet
        uint8_t pkt_type = 0;
        if (!mqtt_cycle_read(pkt_type)) {
            return false;
        }

        // Check PINGRESP timeout
        if (waiting_pingresp && now > pingresp_timeout_at) {
            M5_LOGE("PINGRESP timeout");
            waiting_pingresp = false;
            return false;
        }

        // Send PINGREQ if needed
        if (!waiting_pingresp && now - ping_at >= keepAliveMs) {
            uint8_t pingreq[] = {0xC0, 0x00};
            int ret           = mbedtls_ssl_write(&ssl, pingreq, sizeof(pingreq));
            if (ret > 0) {
                M5_LOGD("PINGREQ sent");
                ping_at             = now;
                waiting_pingresp    = true;
                pingresp_timeout_at = now + keepAliveMs;
            } else {
                M5_LOGE("PINGREQ write failed: -0x%X", -ret);
                return false;
            }
        }

        m5::utility::delay(1);
    } while (m5::utility::millis() <= timeout_at);

    return true;
}

}  // namespace

void setup()
{
    // esp_log_level_set("*", ESP_LOG_VERBOSE);
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);
    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }

    lcd.fillScreen(TFT_DARKGRAY);

    auto board = M5.getBoard();

    bool unit_ready{};
#if defined(USING_M5CORE2_AWS_BUILTIN)
#pragma message "Using builtin ATECC608BTNGTLS"
    // Core2 AWS: Use M5.In_I2C for built-in ATECC608B
    if (board == m5::board_t::board_M5StackCore2) {
        M5_LOGI("Using M5.In_I2C");
        unit_ready = Units.add(unit, M5.In_I2C) && Units.begin();
    } else {
        M5_LOGE("Only Core2AWS");
        lcd.fillScreen(TFT_RED);
        while (true) m5::utility::delay(10000);
    }
#else
    // NessoN1: Arduino Wire (I2C_NUM_0) cannot be used for GROVE port.
    //   Wire is used by M5Unified In_I2C for internal devices (IOExpander etc.).
    //   Wire1 exists but is reserved for HatPort — cannot be used for GROVE.
    //   Reconfiguring Wire to GROVE pins breaks In_I2C, causing ESP_ERR_INVALID_STATE in M5.update().
    //   Solution: Use SoftwareI2C via M5HAL (bit-banging) for the GROVE port.
    // NanoC6: Wire.begin() on GROVE pins conflicts with m5::I2C_Class registered by Ex_I2C.setPort()
    //   on the same I2C_NUM_0, causing sporadic NACK errors.
    //   Solution: Use M5.Ex_I2C (m5::I2C_Class) directly instead of Arduino Wire.
    if (board == m5::board_t::board_ArduinoNessoN1) {
        // NessoN1: GROVE is on port_b (GPIO 5/4), not port_a (which maps to Wire pins 8/10)
        auto pin_num_sda = M5.getPin(m5::pin_name_t::port_b_out);
        auto pin_num_scl = M5.getPin(m5::pin_name_t::port_b_in);
        M5_LOGI("getPin(M5HAL): SDA:%u SCL:%u", pin_num_sda, pin_num_scl);
        m5::hal::bus::I2CBusConfig i2c_cfg;
        i2c_cfg.pin_sda = m5::hal::gpio::getPin(pin_num_sda);
        i2c_cfg.pin_scl = m5::hal::gpio::getPin(pin_num_scl);
        auto i2c_bus    = m5::hal::bus::i2c::getBus(i2c_cfg);
        M5_LOGI("Bus:%d", i2c_bus.has_value());
        unit_ready = Units.add(unit, i2c_bus ? i2c_bus.value() : nullptr) && Units.begin();
    } else if (board == m5::board_t::board_M5NanoC6) {
        // NanoC6: Use M5.Ex_I2C (m5::I2C_Class, not Arduino Wire)
        M5_LOGI("Using M5.Ex_I2C");
        unit_ready = Units.add(unit, M5.Ex_I2C) && Units.begin();
    } else {
        auto pin_num_sda = M5.getPin(m5::pin_name_t::port_a_sda);
        auto pin_num_scl = M5.getPin(m5::pin_name_t::port_a_scl);
        M5_LOGI("getPin: SDA:%u SCL:%u", pin_num_sda, pin_num_scl);
        Wire.end();
        Wire.begin(pin_num_sda, pin_num_scl, 400 * 1000U);
        unit_ready = Units.add(unit, Wire) && Units.begin();
    }
#endif

    if (!unit_ready) {
        M5_LOGE("Failed to begin");
        lcd.fillScreen(TFT_RED);
        while (true) m5::utility::delay(10000);
    }

    M5_LOGI("M5UnitUnified initialized");
    M5_LOGI("%s", Units.debugInfo().c_str());
    M5_LOGI("ESP-IDF Version %d.%d.%d", (ESP_IDF_VERSION >> 16) & 0xFF, (ESP_IDF_VERSION >> 8) & 0xFF,
            ESP_IDF_VERSION & 0xFF);

    // Read sn string form unit
    if (!unit.readSerialNumber(mqtt_topic)) {
        M5_LOGE("readSerialNumber failed");
        while (true) m5::utility::delay(10000);
    }
    // Display information for provisioning
    if (!mqtt_uri || !mqtt_uri[0]) {
        print_provisioning(unit);
        M5.Log.printf("*** AWS endpoint is empty ***\n");
        while (true) m5::utility::delay(10000);
    }

    // WiFi
    M5_LOGI("Free heap before WiFi: %u / min: %u", ESP.getFreeHeap(), ESP.getMinFreeHeap());
    if (!connectWiFi()) {
        M5_LOGE("connectWiFi failed!");
        lcd.fillScreen(TFT_RED);
        while (true) m5::utility::delay(10000);
    }
    M5.Log.printf("WiFi connected!\n");

    snprintf(mqtt_port_str, sizeof(mqtt_port_str), "%u", mqtt_port);

    // TLS
    if (!connectTLS()) {
        M5_LOGE("connectTLS failed!");
        lcd.fillScreen(TFT_RED);
        while (true) m5::utility::delay(10000);
    }
    M5_LOGI("TLS Connected");

    // MQTT
    char subscribe_topic[256]{};
    snprintf(subscribe_topic, sizeof(subscribe_topic), "%s/#", mqtt_topic);

    if (!connectMQTT(mqtt_topic)) {
        M5_LOGE("MQTT CONNECT failed!");
        while (true) m5::utility::delay(10000);
    }

    if (!subscribeMQTT(subscribe_topic)) {
        M5_LOGE("MQTT SUBSCRIBE failed!");
        while (true) m5::utility::delay(10000);
    }

    M5.Log.printf(
        "\n****************************************\n"
        "*  AWS client Id - %s  *\n"
        "****************************************\n\n",
        mqtt_topic);

    M5.Speaker.tone(4000, 40);
    lcd.fillScreen(TFT_DARKGREEN);
}

void loop()
{
    M5.update();

    M5.update();

    if (!yieldMQTT(100)) {
        cleanupTLS();
        M5_LOGE("err");
        lcd.fillScreen(TFT_MAGENTA);
        while (true) m5::utility::delay(10000);
    }

    // Send
    auto now = m5::utility::millis();
    static decltype(now) publish_at{};

    if (now > publish_at + 3000) {
        if (publishMQTTMessage(mqtt_topic, "hello", "Hello from M5 QOS0")) {
            M5.Log.printf("publish(QOS0)\n");
        }
        if (publishMQTTMessage(mqtt_topic, "hello", "Hello from M5 QOS1", true)) {
            M5.Log.printf("publish(QOS1)\n");
        }
        publish_at = now;
    }
}
