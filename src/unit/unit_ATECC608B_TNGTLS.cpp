/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
 @file unit_ATECC608B_TNGTLS.cpp
 @brief ATECC608B-TNGTLS Unit for M5UnitUnified
*/
#include "unit_ATECC608B_TNGTLS.hpp"
#include <M5Utility.hpp>

using namespace m5::utility::mmh3;
using namespace m5::unit::types;
using namespace m5::unit::atecc608;
using m5::unit::types::elapsed_time_t;

namespace {
constexpr uint8_t otp_608b_tngtls[64] = {0x78, 0x36, 0x74, 0x6A, 0x75, 0x5A, 0x4D, 0x79,  //
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

inline bool is_ecdh_source_slot(const uint8_t m)
{
    constexpr uint8_t mask = ECDH_MODE_SRC_SLOT | ECDH_MODE_SRC_TEMPKEY;
    return (m & mask) == ECDH_MODE_SRC_SLOT;
}

bool is_valid_ecdh_slot(const uint16_t slot)
{
    if (!(slot == 0 || (slot >= 2 && slot <= 4))) {
        M5_LIB_LOGE("For TNGTLS, the ECDH command may be run using the ECC private keys stored in Slots 0 and 2-4 (%u)",
                    slot);
        return false;
    }
    return true;
}

bool is_valid_ecdh_output_slot(const uint16_t slot)
{
    if (!(slot == 8)) {
        M5_LIB_LOGE("For TNGTLS, ECDH command output slot only 8 (%u)", slot);
        return false;
    }
    return true;
}

bool is_valid_genkey_private_slot(const uint16_t slot)
{
    if (!(slot >= 2 && slot <= 4)) {
        M5_LIB_LOGE("For TNGTLS, the GenKey command can be used to generate private keys only in Slots 2, 3 and 4 (%u)",
                    slot);
        return false;
    }
    return true;
}

bool is_valid_genkey_public_digest(const uint16_t slot)
{
    if (!(slot == 11)) {
        M5_LIB_LOGE("For TNGTLS, a digest can be created from Slot 11 (%u)", slot);
        return false;
    }
    return true;
}

bool is_valid_sign_external_slot(const uint16_t slot)
{
    if (!(slot == 0 || (slot >= 2 && slot <= 4))) {
        M5_LIB_LOGE("For TNGTLS, Slots 0 and 2-4 are enabled to sign external messages (%u)", slot);
        return false;
    }
    return true;
}

bool is_valid_sign_internal_slot(const uint16_t slot)
{
    if (!(slot == 1)) {
        M5_LIB_LOGE("For TNGTLS, only Slot 1 is capable of signing internally generated messages (%u)", slot);
        return false;
    }
    return true;
}

void set_issue_date(uint8_t* out, const CompCertAccessor::DateTime& issue_date)
{
    if (out) {
        char buf[80]{};
        // format: "YYMMDDhhmmssZ" total 13 bytes (UTC time)
        auto len =
            snprintf(buf, sizeof(buf), "%02d%02d%02d%02d%02d%02dZ", issue_date.tm_year % 100, issue_date.tm_mon + 1,
                     issue_date.tm_mday, issue_date.tm_hour, issue_date.tm_min, issue_date.tm_sec);
        memcpy(out, buf, len);
    }
}

void set_expire_date(uint8_t* out, const CompCertAccessor::DateTime& expire_date)
{
    if (out) {
        char buf[80]{};
        // format: "YYYYMMDDhhmmssZ" total 15 bytes (Generalized time)
        auto len =
            snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02dZ", expire_date.tm_year + 1900, expire_date.tm_mon + 1,
                     expire_date.tm_mday, expire_date.tm_hour, expire_date.tm_min, expire_date.tm_sec);
        memcpy(out, buf, len);
    }
}

void set_signer_id(uint8_t* out, const uint8_t* signer_id)
{
    if (out && signer_id) {
        char buf[5]{};
        snprintf(buf, sizeof(buf), "%02X%02X", signer_id[0], signer_id[1]);
        memcpy(out, buf, 4);
    }
}

void write_bin2hex_uc(uint8_t* out, const uint8_t* data, uint32_t len)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    for (uint32_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];
        *out++       = hex[(byte >> 4) & 0x0F];
        *out++       = hex[byte & 0x0F];
    }
}

uint32_t encode_der_integer(const uint8_t* input, uint32_t input_size, uint8_t* out)
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

bool encode_signature_der(const uint8_t* raw_sig, uint8_t* der_sig, uint32_t& der_sig_size)
{
    if (!raw_sig || !der_sig) {
        return false;
    }

    constexpr uint32_t raw_sig_size   = 64;
    constexpr uint32_t component_size = raw_sig_size / 2;

    uint32_t offset = 0;

    // DER length encoder
    auto der_write_length = [](uint8_t* out, uint32_t length) -> uint32_t {
        if (length < 0x80) {
            if (out) *out = static_cast<uint8_t>(length);
            return 1;
        } else {
            if (out) {
                *out++ = 0x82;  // length in next 2 bytes
                *out++ = static_cast<uint8_t>(length >> 8);
                *out++ = static_cast<uint8_t>(length & 0xFF);
            }
            return 3;
        }
    };

    // Calculate size
    uint32_t r_encoded_size = encode_der_integer(raw_sig, component_size, nullptr);
    uint32_t s_encoded_size = encode_der_integer(raw_sig + component_size, component_size, nullptr);

    uint32_t seq_value_size  = r_encoded_size + s_encoded_size;
    uint32_t seq_length_size = (seq_value_size < 0x80) ? 1 : 3;
    uint32_t seq_total_size  = 1 + seq_length_size + seq_value_size;

    uint32_t bit_string_value_size  = seq_total_size;
    uint32_t bit_string_length_size = (bit_string_value_size + 1 < 0x80) ? 1 : 3;
    uint32_t bit_string_total_size  = 1 + bit_string_length_size + 1 + bit_string_value_size;

    uint32_t required_size = bit_string_total_size;

    if (der_sig_size < required_size) {
        der_sig_size = required_size;
        return false;
    }

    // Encode
    // BIT STRING tag
    der_sig[offset++] = 0x03;
    // BIT STRING length
    offset += der_write_length(der_sig + offset, bit_string_value_size + 1);
    // Unused bits
    der_sig[offset++] = 0x00;
    // SEQUENCE tag
    der_sig[offset++] = 0x30;
    // SEQUENCE length
    offset += der_write_length(der_sig + offset, seq_value_size);
    // INTEGER R
    offset += encode_der_integer(raw_sig, component_size, der_sig + offset);
    // INTEGER S
    offset += encode_der_integer(raw_sig + component_size, component_size, der_sig + offset);

    der_sig_size = offset;
    return true;
}

}  // namespace

namespace m5 {
namespace unit {
// class UnitATECC608B_TNGTLS
const char UnitATECC608B_TNGTLS::name[] = "UnitATECC608B_TNGTLS";
const types::uid_t UnitATECC608B_TNGTLS::uid{"UnitATECC608B_TNGTLS"_mmh3};
const types::attr_t UnitATECC608B_TNGTLS::attr{attribute::AccessI2C};

bool UnitATECC608B_TNGTLS::readRandomArray(uint8_t data[32], const bool /*updateSeed*/)
{
    return UnitATECC608B::readRandomArray(data, true);
}

bool UnitATECC608B_TNGTLS::begin_impl()
{
    const uint8_t* rev = revision();
    if (!(rev[0] == 0x00 && rev[1] == 0x00 && rev[2] == 0x60 && rev[3] >= 0x03)) {
        M5_LIB_LOGE("This is not 608B %02X:%02X:%02X:%02X", rev[0], rev[1], rev[2], rev[3]);
        return false;
    }
    // Device is awake from begin()'s single wakeup session — read OTP directly.
    // Read as a single 32-byte block to minimize I2C transactions.
    // On ESP32 (Core2AWS), each GPIO-based wakeup gives only ~6 usable transactions,
    // so 4-byte×16 reads would exceed the budget.
    // Only the first 8 bytes of OTP are non-zero for TNGTLS; bytes 8-63 are all 0x00.
    uint8_t otp[32]{};
    memset(otp, 0xFF, 32);

    if (!read_data(otp, 32, ZONE_OTP, 0x0000)) {
        M5_LIB_LOGE("Failed to read OTP");
        return false;
    }

    // M5_DUMPI(otp, 32);
    if (memcmp(otp, otp_608b_tngtls, 32) != 0) {
        M5_LIB_LOGE("This is not 608BTNGTLS");
        return false;
    }

    return true;
}

bool UnitATECC608B_TNGTLS::readDeviceCertificate(uint8_t* out, uint16_t& olen, const bool fillAuthKeyId)
{
    constexpr uint16_t offset_cert_sn{15};
    constexpr uint16_t offset_signer_id{120};
    constexpr uint16_t offset_issue_date{128};
    constexpr uint16_t offset_expire_date{143};
    constexpr uint16_t offset_sn03{208};
    constexpr uint16_t offset_sn48{216};
    constexpr uint16_t offset_pubkey{253};
    constexpr uint16_t offset_eui48{355};
    constexpr uint16_t offset_subj_key_id{408};
    constexpr uint16_t offset_auth_key_id{441};
    constexpr uint16_t offset_signature{473};

    if (!out || olen == 0 || olen < template_for_device_size) {
        M5_LIB_LOGE("Argument error");
        return false;
    }

    // Copy template
    memcpy(out, template_for_device, template_for_device_size);

    // Generate and copy public key
    uint8_t pubKey[64]{};
    if (!generatePublicKey(pubKey, Slot::PrimaryPrivateKey)) {
        M5_LIB_LOGE("Failed to generatePublicKey");
        return false;
    }
    memcpy(out + offset_pubkey, pubKey, 64);

    // Read compressed cert
    uint8_t ccert[72]{};
    if (!readDataZone(ccert, 72, Slot::DeviceCompressedCertificate)) {
        M5_LIB_LOGE("Failed to readDataZone");
        return false;
    }

    CompCertAccessor cca{ccert};
#if 0
    M5_LIB_LOGI("CompCert:");
    M5_LIB_LOGI("  Template ID : %u", cca.template_id());
    M5_LIB_LOGI("  Chain ID    : %u", cca.chain_id());
    M5_LIB_LOGI("  Format Ver  : %u", cca.format_version());
    M5_LIB_LOGI("  SN Source   : %u", cca.sn_source());
    M5_LIB_LOGI("  Issue Date  : %04u-%02u-%02u %02u", cca.issue_date().tm_year + 1900, cca.issue_date().tm_mon + 1,
                cca.issue_date().tm_mday, cca.issue_date().tm_hour);
    M5_LIB_LOGI("  Expire Date : %04u-%02u-%02u %02u", cca.expire_date().tm_year + 1900, cca.expire_date().tm_mon + 1,
                cca.expire_date().tm_mday, cca.expire_date().tm_hour);
#endif

    if (cca.template_id() != 3 || cca.chain_id() != 0 || cca.sn_source() != 10) {
        M5_LIB_LOGE("Invalid template <-> cert %u,%u,%u", cca.template_id(), cca.chain_id(), cca.sn_source());
        return false;
    }

    // Signature DER encode
    uint8_t der_sig[80]{};
    uint32_t der_sig_size{sizeof(der_sig)};
    if (!encode_signature_der(cca.signature(), der_sig, der_sig_size)) {
        M5_LIB_LOGE("DER signature encode failed");
        return false;
    }
    if (offset_signature + der_sig_size > olen) {
        M5_LIB_LOGE("Buffer too small");
        return false;
    }
    memcpy(out + offset_signature, der_sig, der_sig_size);

    uint32_t cur_deg_size = template_for_device_size - offset_signature;
    int delta             = (int)der_sig_size - (int)cur_deg_size;
    olen                  = template_for_device_size + delta;
    if (delta) {                              // Adjust length
        uint32_t len = out[2] << 8 | out[3];  // BE
        len += delta;
        if (len < 128 || len > 65535) {
            M5_LIB_LOGE("Failed to adjust %u", len);
            return false;
        }
        out[2] = len >> 8;
        out[3] = len & 0xFF;
    }

    // Issue/Expire data
    set_issue_date(out + offset_issue_date, cca.issue_date());
    set_expire_date(out + offset_expire_date, cca.expire_date());

    // Signer ID
    set_signer_id(out + offset_signer_id, cca.signer_id());

    // Cert serial number
    uint8_t msg[64 + 3]{};
    uint8_t cert_sn[32]{};
    memcpy(msg, pubKey, 64);
    memcpy(msg + 64, ccert + 64, 3);  // Add encoded dates from compressed certificate
    if (!SHA256(Destination::ExternalBuffer, cert_sn, msg, sizeof(msg))) {
        M5_LIB_LOGE("Failed to SHA256");
        return false;
    }
    cert_sn[0] &= 0x7F;                         // Ensure the SN is positive
    cert_sn[0] |= 0x40u;                        // Ensure the SN doesn't have any trimmable bytes
    memcpy(out + offset_cert_sn, cert_sn, 16);  // Top of 16 bytes

    // Subject key ID
    msg[0] = 0x04;
    memcpy(msg + 1, pubKey, 64);
    uint8_t key_id[20]{};
    m5::utility::SHA1::sha1(key_id, msg, 65);
    memcpy(out + offset_subj_key_id, key_id, 20);

    // Chip serial number
    uint8_t chip_sn[9]{};
    if (!readSerialNumber(chip_sn)) {
        M5_LIB_LOGE("Failed to readSerialNumber");
        return false;
    }
    write_bin2hex_uc(out + offset_sn03, chip_sn, 4);      // SN03
    write_bin2hex_uc(out + offset_sn48, chip_sn + 4, 5);  // SN48

    // EUI-48
    uint8_t eui48[12]{};
    if (!readDataZone(eui48, sizeof(eui48), Slot::MACAddress)) {
        M5_LIB_LOGE("Failed to readDataZone");
        return false;
    }
    memcpy(out + offset_eui48, eui48, 12);

    // Auth key id
    if (fillAuthKeyId) {
        // Get subject key ID of signer
        uint8_t pubKeyTmp[72]{};
        if (!readDataZone(pubKeyTmp, sizeof(pubKeyTmp), Slot::SignerPublicKey)) {
            M5_LIB_LOGE("Failed to read signer public key");
            return false;
        }
        memcpy(pubKey, pubKeyTmp + 4, 32);
        memcpy(pubKey + 32, pubKeyTmp + 4 + 32 + 4, 32);
        msg[0] = 0x04;
        memcpy(msg + 1, pubKey, 64);
        uint8_t auth_key_id[20]{};
        m5::utility::SHA1::sha1(auth_key_id, msg, 65);

        memcpy(out + offset_auth_key_id, auth_key_id, 20);
    }
    return true;
}

bool UnitATECC608B_TNGTLS::readSignerCertificate(uint8_t* out, uint16_t& olen)
{
    constexpr uint16_t offset_cert_sn{15};
    constexpr uint16_t offset_issue_date{128};
    constexpr uint16_t offset_expire_date{143};
    constexpr uint16_t offset_signer_id{235};
    constexpr uint16_t offset_pubkey{266};
    constexpr uint16_t offset_subj_key_id{381};
    //    constexpr uint16_t offset_auth_key_id{414};
    constexpr uint16_t offset_signature{446};

    if (!out || olen == 0 || olen < template_for_signer_size) {
        M5_LIB_LOGE("Argument error");
        return false;
    }

    // Copy template
    memcpy(out, template_for_signer, template_for_signer_size);

    // Read and copy signer public key
    uint8_t pubKeyTmp[72]{};
    uint8_t pubKey[64]{};
    if (!readDataZone(pubKeyTmp, sizeof(pubKeyTmp), Slot::SignerPublicKey)) {
        M5_LIB_LOGE("Failed to read signer public key");
        return false;
    }
    memcpy(pubKey, pubKeyTmp + 4, 32);
    memcpy(pubKey + 32, pubKeyTmp + 4 + 32 + 4, 32);
    memcpy(out + offset_pubkey, pubKey, 64);

    // Read compressed signer certificate
    uint8_t ccert[72]{};
    if (!readDataZone(ccert, sizeof(ccert), Slot::SignerCompressedCertificate)) {
        M5_LIB_LOGE("Failed to read signer compressed certificate");
        return false;
    }

    CompCertAccessor cca{ccert};

    if (cca.template_id() != 1 || cca.chain_id() != 0 || cca.sn_source() != 10) {
        M5_LIB_LOGE("Invalid template <-> cert %u,%u,%u", cca.template_id(), cca.chain_id(), cca.sn_source());
        return false;
    }

    // Signature DER encode
    uint8_t der_sig[80]{};
    uint32_t der_sig_size{sizeof(der_sig)};
    if (!encode_signature_der(cca.signature(), der_sig, der_sig_size)) {
        M5_LIB_LOGE("DER signature encode failed");
        return false;
    }
    memcpy(out + offset_signature, der_sig, der_sig_size);

    int delta = (int)der_sig_size - (int)(template_for_signer_size - offset_signature);
    olen      = template_for_signer_size + delta;
    if (delta) {  // Adjust length
        uint32_t len = out[2] << 8 | out[3];
        len += delta;
        out[2] = len >> 8;
        out[3] = len & 0xFF;
    }

    // Issue/Expire date
    set_issue_date(out + offset_issue_date, cca.issue_date());
    set_expire_date(out + offset_expire_date, cca.expire_date());

    // Signer ID
    set_signer_id(out + offset_signer_id, cca.signer_id());

    // Cert serial number
    uint8_t msg[64 + 3]{};
    uint8_t cert_sn[32]{};
    memcpy(msg, pubKey, 64);
    memcpy(msg + 64, ccert + 64, 3);
    if (!SHA256(Destination::ExternalBuffer, cert_sn, msg, sizeof(msg))) {
        M5_LIB_LOGE("Failed to SHA256");
        return false;
    }
    cert_sn[0] &= 0x7F;
    cert_sn[0] |= 0x40u;
    memcpy(out + offset_cert_sn, cert_sn, 16);

    // Subject Key ID
    msg[0] = 0x04;
    memcpy(msg + 1, pubKey, 64);
    uint8_t key_id[20]{};
    m5::utility::SHA1::sha1(key_id, msg, 65);
    memcpy(out + offset_subj_key_id, key_id, 20);

    return true;
}

bool UnitATECC608B_TNGTLS::ecdh_receive32(uint8_t out[32], const uint8_t mode, const uint16_t param2,
                                          const uint8_t pubKey[64])
{
    if (is_ecdh_source_slot(mode) && !is_valid_ecdh_slot(param2)) {
        return false;
    }
    return UnitATECC608B::ecdh_receive32(out, mode, param2, pubKey);
}

bool UnitATECC608B_TNGTLS::ecdh_receive32x2(uint8_t out[32], uint8_t nonce[32], const uint8_t mode,
                                            const uint16_t param2, const uint8_t pubKey[64])
{
    if (is_ecdh_source_slot(mode) && !is_valid_ecdh_slot(param2)) {
        return false;
    }
    return UnitATECC608B::ecdh_receive32x2(out, nonce, mode, param2, pubKey);
}

bool UnitATECC608B_TNGTLS::ecdh_no_output(const uint8_t mode, const uint16_t param2, const uint8_t pubKey[64])
{
    if (is_ecdh_source_slot(mode) && !is_valid_ecdh_slot(param2)) {
        return false;
    }
    if ((mode & ECDH_MODE_OUTPUT_SLOT) && !is_valid_ecdh_output_slot(param2)) {
        return false;
    }

    return UnitATECC608B::ecdh_no_output(mode, param2, pubKey);
}

bool UnitATECC608B_TNGTLS::generate_key(uint8_t pubKey[64], const uint8_t mode, const uint16_t param2,
                                        const uint8_t* data, const uint32_t dlen)
{
    if ((((mode & GENKEY_MODE_PRIVATE) && param2 != 0xFFFF) && !is_valid_genkey_private_slot(param2)) ||
        ((mode & GENKEY_MODE_PUBLIC_DIGEST) && !is_valid_genkey_public_digest(param2))) {
        return false;
    }
    return UnitATECC608B::generate_key(pubKey, mode, param2, data, dlen);
}

bool UnitATECC608B_TNGTLS::sign(uint8_t signature[64], const uint8_t mode, const uint16_t param2,
                                const atecc608::Source src)
{
    if (((mode & SIGN_MODE_EXTERNAL) && !is_valid_sign_external_slot(param2)) ||
        (((mode & ~(SIGN_MODE_INCLUDE_SN)) == 0x00) && !is_valid_sign_internal_slot(param2))) {
        return false;
    }
    return UnitATECC608B::sign(signature, mode, param2, src);
}

}  // namespace unit
}  // namespace m5
