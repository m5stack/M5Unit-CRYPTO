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
#include <wiring/m5_unit_unified_wiring.hpp>  // Board-aware connection helpers (include last)

#include <esp_system.h>
#include <algorithm>
#include <cstring>
#include <esp_idf_version.h>

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/debug.h>

// The TLS device key in the ATECC608B (the only part that depends on the mbedtls version)
#include "../src/device_key.hpp"
// Wi-Fi station connect (esp_wifi for both frameworks; handles esp_hosted boards such as Tab5)
#include "../src/wifi_connect.hpp"

using namespace m5::unit::atecc608;

namespace {

// ****************************************************************************************************
// Settings
// ****************************************************************************************************
// Fill in the following define or specify with build option
// ****************************************************************************************************
#if !defined(USING_M5CORE2_AWS_BUILTIN)
// For Core2 for AWS built-in ATECC608B (K010-AWS)
// #define USING_M5CORE2_AWS_BUILTIN
#endif

// ESP-IDF: the settings come from menuconfig (main/Kconfig.projbuild)
#if !defined(ARDUINO)
#if !defined(EXAMPLE_SSID)
#define EXAMPLE_SSID CONFIG_EXAMPLE_WIFI_SSID
#endif
#if !defined(EXAMPLE_PASSWORD)
#define EXAMPLE_PASSWORD CONFIG_EXAMPLE_WIFI_PASSWORD
#endif
#if !defined(EXAMPLE_MQTT_URI)
#define EXAMPLE_MQTT_URI CONFIG_EXAMPLE_MQTT_URI
#endif
#if !defined(EXAMPLE_MQTT_PORT)
#define EXAMPLE_MQTT_PORT CONFIG_EXAMPLE_MQTT_PORT
#endif
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
mbedtls_net_context server_fd{};

char mqtt_topic[128]{};  // Top level topic and thing name
bool waiting_pingresp{};

// Time to wait for the server (TLS handshake, CONNACK, SUBACK). A tethered or cellular link can take several seconds
constexpr uint32_t SERVER_RESPONSE_TIMEOUT_MS{15000};
// Read timeout after the handshake. Must be shorter than the MQTT keep alive (10 s) so that the loop sends PINGREQ
// in time (the server closes the connection after 1.5 x keep alive without packets)
constexpr uint32_t MQTT_READ_TIMEOUT_MS{5000};
// Connection attempts (TLS + MQTT) before giving up
constexpr uint32_t CONNECT_ATTEMPTS{3};
constexpr uint32_t CONNECT_RETRY_INTERVAL_MS{3000};

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

    // Called from the TLS handshake (verify_cert), deep in the mbedtls call stack: keep the buffer off the stack
    static char buf[2048]{};
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

int verify_cert(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    // Called from the TLS handshake, deep in the mbedtls call stack: keep the buffer off the stack
    static char buf[1024]{};
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
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&clicert);
    mbedtls_pk_init(&pkey);

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

    // Device key (the private key stays in the ATECC608B)
    if (!device_key::begin(unit, &pkey)) {
        M5_LOGE("failed! device_key::begin");
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
    device_key::configure(&conf);

    mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);

    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey)) != 0) {
        M5_LOGE("failed! mbedtls_ssl_conf_own_cert returned %d", ret);
        return false;
    }
    mbedtls_ssl_conf_read_timeout(&conf, SERVER_RESPONSE_TIMEOUT_MS);

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

    M5_LOGI("Handshake Protocol:%s Ciphersuite:%s Record expansion:", mbedtls_ssl_get_version(&ssl),
            mbedtls_ssl_get_ciphersuite(&ssl));
    mbedtls_ssl_conf_read_timeout(&conf, MQTT_READ_TIMEOUT_MS);
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
    device_key::end(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
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

// MQTT Remaining Length is a variable length integer (1-4 bytes)
uint32_t encode_remaining_length(uint8_t *out, uint32_t len)
{
    uint32_t n{};
    do {
        uint8_t b = len % 128;
        len /= 128;
        out[n++] = b | (len ? 0x80 : 0x00);
    } while (len && n < 4);
    return n;
}

// Send a packet: fixed header byte, Remaining Length and body
bool send_mqtt_packet(const uint8_t header, const uint8_t *body, const uint32_t body_len)
{
    uint8_t pkt[1 + 4 + 256]{};
    if (body_len > 256) {
        M5_LOGE("MQTT packet too long %u", body_len);
        return false;
    }
    uint32_t pos = 0;
    pkt[pos++]   = header;
    pos += encode_remaining_length(pkt + pos, body_len);
    memcpy(pkt + pos, body, body_len);
    pos += body_len;

    int ret = mbedtls_ssl_write(&ssl, pkt, pos);
    if (ret <= 0) {
        M5_LOGE("mbedtls_ssl_write failed: -0x%x", -ret);
        return false;
    }
    return true;
}

// Read exactly len bytes (a packet may arrive in pieces)
bool ssl_read_exact(uint8_t *buf, const uint32_t len)
{
    uint32_t got{};
    while (got < len) {
        int ret = mbedtls_ssl_read(&ssl, buf + got, len - got);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            continue;
        }
        if (ret <= 0) {
            M5_LOGE("mbedtls_ssl_read error: -0x%X", -ret);
            return false;
        }
        got += ret;
    }
    return true;
}

// Read packet
bool mqtt_cycle_read(uint8_t &out_type)
{
    out_type = 0;

    // Fixed header: packet type
    uint8_t header{};
    int ret = mbedtls_ssl_read(&ssl, &header, 1);
    if (ret <= 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_TIMEOUT) {
            // M5_LOGD("MBEDTLS_ERR_SSL_WANT_READ / MBEDTLS_ERR_SSL_TIMEOUT");
            return true;
        }
        M5_LOGE("mbedtls_ssl_read error: -0x%X", -ret);
        return false;
    }

    // Fixed header: Remaining Length
    uint32_t remaining{}, multiplier{1};
    for (uint_fast8_t i = 0; i < 4; ++i) {
        uint8_t b{};
        if (!ssl_read_exact(&b, 1)) {
            return false;
        }
        remaining += (b & 0x7F) * multiplier;
        multiplier *= 128;
        if (!(b & 0x80)) {
            break;
        }
    }

    // Body: keep what fits in the buffer and drop the rest
    uint8_t buf[256]{};
    const uint32_t kept = std::min<uint32_t>(remaining, sizeof(buf));
    if (!ssl_read_exact(buf, kept)) {
        return false;
    }
    for (uint32_t left = remaining - kept; left;) {
        uint8_t drop[64]{};
        const uint32_t n = std::min<uint32_t>(left, sizeof(drop));
        if (!ssl_read_exact(drop, n)) {
            return false;
        }
        left -= n;
    }

    out_type = header >> 4;
    switch (out_type) {
        case 3: {  // PUBLISH
            if (kept < 2) {
                M5_LOGE("Invalid PUBLISH packet (too short)");
                return false;
            }
            const uint16_t topic_len = (buf[0] << 8) | buf[1];
            // Packet Identifier follows the topic when QoS > 0
            const uint32_t offset = 2 + topic_len + (((header >> 1) & 0x03) ? 2 : 0);
            if (offset > kept) {
                M5_LOGE("Invalid PUBLISH packet (too short)");
                return false;
            }

            // Truncate to the buffers (keep the terminating '\0')
            char topic[128]{};
            memcpy(topic, &buf[2], std::min<uint32_t>(topic_len, sizeof(topic) - 1));

            char payload[128]{};
            const uint32_t payload_len = std::min<uint32_t>(kept - offset, sizeof(payload) - 1);
            memcpy(payload, &buf[offset], payload_len);

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
    const auto start_at = m5::utility::millis();
    do {
        uint8_t packet_type{};
        if (!mqtt_cycle_read(packet_type)) {
            return false;
        }
        if (packet_type == expected_type) {
            return true;
        }
    } while (m5::utility::elapsedSince(start_at) <= timeout_ms);
    M5_LOGE("wait_for: timeout waiting for type=%d", expected_type);
    return false;
}

bool publishMQTTMessage(const char *top_topic, const char *sub_topic, const char *message, const bool qos1 = false)
{
    uint8_t body[256]{};

    // Build topic
    char full_topic[128]{};
    const char *sub = sub_topic ? sub_topic : "";
    const char *sep = (sub[0] && sub[0] != '/') ? "/" : "";
    if (strlen(top_topic) + strlen(sep) + strlen(sub) >= sizeof(full_topic)) {
        M5_LOGE("Topic too long");
        return false;
    }
    strcpy(full_topic, top_topic);
    strcat(full_topic, sep);
    strcat(full_topic, sub);
    const uint16_t topic_len = strlen(full_topic);
    const size_t message_len = strlen(message);

    if (2 + topic_len + 2 + message_len > sizeof(body)) {
        M5_LOGE("Topic or payload too long");
        return false;
    }

    uint32_t pos = 0;

    // Variable Header
    body[pos++] = (topic_len >> 8) & 0xFF;
    body[pos++] = topic_len & 0xFF;
    memcpy(body + pos, full_topic, topic_len);
    pos += topic_len;

    // QoS1: Packet Identifier
    if (qos1) {
        uint16_t packet_id = get_next_packet_id();
        body[pos++]        = (packet_id >> 8) & 0xFF;
        body[pos++]        = packet_id & 0xFF;
    }

    // Payload
    memcpy(body + pos, message, message_len);
    pos += message_len;

    M5_LOGD("Try Publish %s/%s %s (QoS=%d)", top_topic, sub_topic, message, qos1 ? 1 : 0);

    // Packet Type: PUBLISH | QoS bits
    if (!send_mqtt_packet(0x30 | (qos1 ? 0x02 : 0x00), body, pos)) {
        return false;
    }

    M5_LOGD("MQTT PUBLISH sent: topic=%s message=%s", full_topic, message);

    return qos1 ? mqtt_wait_for(4 /* PUBACK */, 5000) : true;
}

bool connectMQTT(const char *client_id)
{
    uint8_t connect_pkt[128]{};
    const uint32_t client_id_len = strlen(client_id);
    if (12 + client_id_len > sizeof(connect_pkt)) {
        M5_LOGE("Client ID too long");
        return false;
    }

    uint32_t pos = 0;

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

    M5_LOGD("Try MQTT CONNECT [%s]", client_id);

    // Packet Type: CONNECT
    if (!send_mqtt_packet(0x10, connect_pkt, pos)) {
        return false;
    }

    // Wait receive CONNACK
    return mqtt_wait_for(2 /* CONNACK */, SERVER_RESPONSE_TIMEOUT_MS);
}

bool subscribeMQTT(const char *topic)
{
    uint16_t packet_id = get_next_packet_id();
    uint16_t topic_len = strlen(topic);
    uint8_t subscribe_pkt[128]{};
    if (2 + 2 + topic_len + 1 > sizeof(subscribe_pkt)) {
        M5_LOGE("Topic too long");
        return false;
    }

    uint32_t pos         = 0;
    subscribe_pkt[pos++] = (packet_id >> 8) & 0xFF;
    subscribe_pkt[pos++] = packet_id & 0xFF;

    subscribe_pkt[pos++] = (topic_len >> 8) & 0xFF;
    subscribe_pkt[pos++] = topic_len & 0xFF;
    memcpy(&subscribe_pkt[pos], topic, topic_len);
    pos += topic_len;
    subscribe_pkt[pos++] = 0x00;  // QoS 0

    M5_LOGD("Try MQTT SUBSCRIBE [%s]", topic);

    // Packet Type: SUBSCRIBE (reserved bits 0b0010)
    if (!send_mqtt_packet(0x82, subscribe_pkt, pos)) {
        return false;
    }

    // Wait receive SUBACK
    return mqtt_wait_for(9 /* SUBACK */, SERVER_RESPONSE_TIMEOUT_MS);
}

bool yieldMQTT(uint32_t timeout_ms)
{
    const auto start = m5::utility::millis();

    static m5::utility::elapsed_time_t ping_at{};

    constexpr uint32_t keepAliveMs = 10000;

    do {
        auto now = m5::utility::millis();

        // Read incoming packet
        uint8_t pkt_type = 0;
        if (!mqtt_cycle_read(pkt_type)) {
            return false;
        }

        // Check PINGRESP timeout
        if (waiting_pingresp && m5::utility::elapsedSince(ping_at, now) > keepAliveMs) {
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
                ping_at          = now;
                waiting_pingresp = true;
            } else {
                M5_LOGE("PINGREQ write failed: -0x%X", -ret);
                return false;
            }
        }

        m5::utility::delay(1);
    } while (m5::utility::elapsedSince(start) <= timeout_ms);

    return true;
}

}  // namespace

// TLS, MQTT CONNECT and SUBSCRIBE
bool connectAWS(const char *client_id, const char *subscribe_topic)
{
    waiting_pingresp = false;
    if (!connectTLS()) {
        M5_LOGE("connectTLS failed!");
        return false;
    }
    M5_LOGI("TLS Connected");
    if (!connectMQTT(client_id)) {
        M5_LOGE("MQTT CONNECT failed!");
        return false;
    }
    if (!subscribeMQTT(subscribe_topic)) {
        M5_LOGE("MQTT SUBSCRIBE failed!");
        return false;
    }
    return true;
}

void setup()
{
    // esp_log_level_set("*", ESP_LOG_VERBOSE);
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);
    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }

    lcd.fillScreen(TFT_DARKGRAY);

#if defined(USING_M5CORE2_AWS_BUILTIN)
#pragma message("Using builtin ATECC608BTNGTLS")
    // Core2 AWS: the built-in ATECC608B is on the internal bus (M5.In_I2C)
    if (M5.getBoard() != m5::board_t::board_M5StackCore2) {
        M5_LOGE("Only Core2AWS");
        m5::unit::wiring::failStop();
    }
    const bool unit_ready = Units.add(unit, M5.In_I2C) && Units.begin();
#else
    // Board-aware connection: NessoN1 -> SoftwareI2C on GROVE, NanoC6/NanoH2 -> M5.Ex_I2C, others -> Wire
    const bool unit_ready = m5::unit::wiring::addI2C(Units, unit) && Units.begin();
#endif
    if (!unit_ready) {
        M5_LOGE("Failed to begin");
        m5::unit::wiring::failStop();
    }

    M5_LOGI("M5UnitUnified initialized");
    M5_LOGI("%s", Units.debugInfo().c_str());
    M5_LOGI("ESP-IDF Version %d.%d.%d", (ESP_IDF_VERSION >> 16) & 0xFF, (ESP_IDF_VERSION >> 8) & 0xFF,
            ESP_IDF_VERSION & 0xFF);

    // Read sn string from unit
    if (!unit.readSerialNumber(mqtt_topic)) {
        M5_LOGE("readSerialNumber failed");
        m5::unit::wiring::failStop();
    }
    // Display information for provisioning
    if (!mqtt_uri || !mqtt_uri[0]) {
        print_provisioning(unit);
        M5.Log.printf("*** AWS endpoint is empty ***\n");
        while (true) m5::utility::delay(10000);
    }

    // WiFi
    M5_LOGI("Free heap before WiFi: %u / min: %u", (unsigned)esp_get_free_heap_size(),
            (unsigned)esp_get_minimum_free_heap_size());
    if (!wifi_connect::begin(ssid, password)) {
        M5_LOGE("connectWiFi failed!");
        m5::unit::wiring::failStop();
    }
    M5.Log.printf("WiFi connected!\n");

    snprintf(mqtt_port_str, sizeof(mqtt_port_str), "%u", mqtt_port);

    // TLS and MQTT
    char subscribe_topic[256]{};
    snprintf(subscribe_topic, sizeof(subscribe_topic), "%s/#", mqtt_topic);

    uint32_t attempt{1};
    while (!connectAWS(mqtt_topic, subscribe_topic)) {
        cleanupTLS();
        if (attempt >= CONNECT_ATTEMPTS) {
            M5_LOGE("Failed to connect to AWS IoT");
            m5::unit::wiring::failStop();
        }
        M5_LOGW("Retry connecting to AWS IoT (%u/%u)", static_cast<unsigned>(attempt + 1),
                static_cast<unsigned>(CONNECT_ATTEMPTS));
        m5::utility::delay(CONNECT_RETRY_INTERVAL_MS);
        ++attempt;
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

    if (!yieldMQTT(100)) {
        cleanupTLS();
        M5_LOGE("err");
        lcd.fillScreen(TFT_MAGENTA);
        while (true) m5::utility::delay(10000);
    }

    // Send
    auto now = m5::utility::millis();
    static decltype(now) publish_at{};

    if (m5::utility::elapsedSince(publish_at, now) > 3000) {
        if (publishMQTTMessage(mqtt_topic, "hello", "Hello from M5 QOS0")) {
            M5.Log.printf("publish(QOS0)\n");
        }
        if (publishMQTTMessage(mqtt_topic, "hello", "Hello from M5 QOS1", true)) {
            M5.Log.printf("publish(QOS1)\n");
        }
        publish_at = now;
    }
}

#if !defined(ARDUINO)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_timer.h>

#if CONFIG_FREERTOS_UNICORE
static inline void feedIdleTaskPeriodically(void)
{
    constexpr uint32_t FEED_INTERVAL_MS{2000};
    constexpr TickType_t FEED_SLEEP_TICKS{pdMS_TO_TICKS(5)};
    static uint32_t s_last_feed_ms{};
    const uint32_t now_ms{static_cast<uint32_t>(esp_timer_get_time() / 1000)};
    if (now_ms - s_last_feed_ms >= FEED_INTERVAL_MS) {
        s_last_feed_ms = now_ms;
        vTaskDelay(FEED_SLEEP_TICKS);
    }
}
#endif

extern "C" void app_main(void)
{
    setup();
    for (;;) {
#if CONFIG_FREERTOS_UNICORE
        feedIdleTaskPeriodically();
#endif
        loop();
    }
}
#endif
