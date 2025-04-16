/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
#if defined(USING_M5CORE2_AWS_BUILTIN)
#pragma message "Usiing  builtin ATECC608B"
    if (M5.getBoard() == m5::board_t::board_M5StackCore2) {
        pin_num_sda = M5.getPin(m5::pin_name_t::in_i2c_sda);
        pin_num_scl = M5.getPin(m5::pin_name_t::in_i2c_scl);
    }
#endif
 /*!
  @file unit_ATECC608B.cpp
  @brief ATECC608B Unit for M5UnitUnified
*/
#include "unit_ATECC608B.hpp"
#include "utility/sha1.hpp"
#include <M5Utility.hpp>

using namespace m5::utility::mmh3;
using namespace m5::unit::types;
using namespace m5::unit::atecc608;
using m5::unit::types::elapsed_time_t;

namespace {
constexpr std::array<uint8_t, 4> RESPONSE{0x04, 0x11, 0x33, 0x43};

// CRC16
m5::utility::CRC16 crc16(0x0000, 0x8005, true, false, 0x0000);

inline bool delay_true(const uint32_t ms)
{
    m5::utility::delay(ms);
    return true;  // Always!
}

void set_issue_date(uint8_t* out, const CompCertAccessor::DateTime& issue_date)
{
    if (out) {
        char buf[14]{};
        // format: "YYMMDDhhmmssZ" total 13 bytes (UTC time)
        snprintf(buf, sizeof(buf), "%02u%02u%02u%02u%02u%02uZ", issue_date.tm_year % 100, issue_date.tm_mon + 1,
                 issue_date.tm_mday, issue_date.tm_hour, issue_date.tm_min, issue_date.tm_sec);
        memcpy(out, buf, 13);
    }
}

void set_expire_date(uint8_t* out, const CompCertAccessor::DateTime& expire_date)
{
    if (out) {
        char buf[16]{};
        // format: "YYYYMMDDhhmmssZ" total 15 bytes (Generalized time)
        snprintf(buf, sizeof(buf), "%04u%02u%02u%02u%02u%02uZ", expire_date.tm_year + 1900, expire_date.tm_mon + 1,
                 expire_date.tm_mday, expire_date.tm_hour, expire_date.tm_min, expire_date.tm_sec);
        memcpy(out, buf, 15);
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
// class UnitATECC608B
const char UnitATECC608B::name[] = "UnitATECC608B";
const types::uid_t UnitATECC608B::uid{"UnitATECC608B"_mmh3};
const types::uid_t UnitATECC608B::attr{0};

bool UnitATECC608B::begin()
{
    if (!wakeup()) {
        M5_LIB_LOGE("Failed to wakeup");
        return false;
    }

    uint8_t revision[4]{};
    if (!readRevision(revision)) {
        M5_LIB_LOGE("Failed to readRevision");
        return false;
    }
    /*
    if(!is_valid_revision(revision)) {
    }
    */
    return !_cfg.idle ? sleep() : true;
}

bool UnitATECC608B::wakeup()
{
    // Clock at wakeup must be less than 100K
    constexpr uint32_t REQUIRED_CLOCK{100 * 1000U};
    auto ad         = adapter();
    auto save_clock = ad->clock();
    if (save_clock > REQUIRED_CLOCK) {
        ad->setClock(REQUIRED_CLOCK);
    }

    /*
      Wake condition can be generated by sending a START condition followed by a low SDA pulse for tWLO ≥ 60 μs,
      and then aSTOP.
      This can be accomplished by sending an invalid address (such as 0x00) on the I2C bus.
    */
    generalCall(nullptr, 0);               // Errors can be ignored
    m5::utility::delayMicroseconds(1500);  // Wait at least 1.5ms

    // m5::utility::delay(2);

    // Check the response
    std::array<uint8_t, 4> response{};
    bool ok = (readWithTransaction(response.data(), response.size()) == m5::hal::error::error_t::OK) &&
              (response == RESPONSE);
    // M5_LIB_LOGV("response:%02X:%02X:%02X:%02X", response[0], response[1], response[2], response[3]);
    ad->setClock(save_clock);
    return ok;
}

bool UnitATECC608B::sleep()
{
    return writeWithTransaction(&WORD_ADRESS_VALUE_SLEEP, 1) == m5::hal::error::error_t::OK && delay_true(1);
}

bool UnitATECC608B::idle()
{
    return writeWithTransaction(&WORD_ADRESS_VALUE_IDLE, 1) == m5::hal::error::error_t::OK && delay_true(1);
}

bool UnitATECC608B::readRevision(uint8_t data[4])
{
    if (!data) {
        return false;
    }
    memset(data, 0, 4);
    if (!wakeup()) {
        return false;
    }

    bool ok{};
    if (send_command(OPCODE_INFO, INFO_MODE_REVISION)) {
        m5::utility::delay(DELAY_INFO);
        ok = receive_response(data, 4);
    }
    return idle() && ok;
}

bool UnitATECC608B::readKeyValid(bool& valid, const atecc608::Slot slot)
{
    valid = false;
    if (!wakeup()) {
        return false;
    }

    bool ok{};
    if (send_command(OPCODE_INFO, INFO_MODE_KEYVALID, m5::stl::to_underlying(slot))) {
        m5::utility::delay(DELAY_INFO);
        uint8_t rbuf[4]{};
        ok    = receive_response(rbuf, sizeof(rbuf));
        valid = ok && (rbuf[0] & 1);
    }
    return idle() && ok;
}

bool UnitATECC608B::readDeviceState(uint16_t& state)
{
    state = 0;
    if (!wakeup()) {
        return false;
    }

    bool ok{};
    if (send_command(OPCODE_INFO, INFO_MODE_DEVICE_STATE)) {
        m5::utility::delay(DELAY_INFO);
        uint8_t rbuf[2]{};
        ok    = receive_response(rbuf, sizeof(rbuf));
        state = rbuf[0] | (rbuf[1] << 8);
    }
    return idle() && ok;
}

bool UnitATECC608B::readRandomArray(uint8_t data[32], const bool updateSeed)
{
    if (!data) {
        return false;
    }
    memset(data, 0, 32);
    if (!wakeup()) {
        return false;
    }

    bool ok{};
    if (send_command(OPCODE_RANDOM, updateSeed ? RANDOM_MODE_UPDATE_SEED : RANDOM_MODE_NOT_UPDATE_SEED)) {
        m5::utility::delay(DELAY_RANDOM);
        ok = receive_response(data, 32);
    }
    return idle() && ok;
}

bool UnitATECC608B::readSerialNumber(uint8_t sn[9])
{
    if (!sn) {
        return false;
    }
    memset(sn, 0, 9);
    if (!wakeup()) {
        return false;
    }

    bool ok = read_data(sn, 4, ZONE_CONFIG, offset_to_param2_for_config(0)) &&
              read_data(sn + 4, 4, ZONE_CONFIG, offset_to_param2_for_config(8)) &&
              read_data(sn + 8, 1, ZONE_CONFIG, offset_to_param2_for_config(12));

    return idle() && ok;
}

bool UnitATECC608B::readZoneLocked(bool& configLocked, bool& dataLocked)
{
    configLocked = dataLocked = true;

    uint8_t rbuf[4]{};
    bool ok = wakeup() && read_data(rbuf, sizeof(rbuf), ZONE_CONFIG, offset_to_param2_for_config(84));
    if (ok) {
        configLocked = (rbuf[3] == 0x00);  // 87 LockConfig (Config zone)
        dataLocked   = (rbuf[2] == 0x00);  // 86 LockValue (Data zone)
    }
    return idle() && ok;
}

bool UnitATECC608B::readSlotLocked(uint16_t& slotLockedBits)
{
    constexpr uint8_t SLOT_LOCKED_CONFIG_BASE{88};  // Offset in ConfigZone

    slotLockedBits = 0xFFFF;

    uint8_t rbuf[4]{};
    bool ok =
        wakeup() && read_data(rbuf, sizeof(rbuf), ZONE_CONFIG, offset_to_param2_for_config(SLOT_LOCKED_CONFIG_BASE));
    if (ok) {
        slotLockedBits = (rbuf[0] | (rbuf[1] << 8)) ^ 0xFFFF;
    }
    return idle() && ok;
}

bool UnitATECC608B::readConfigZone(uint8_t config[128])
{
    if (!config) {
        return false;
    }
    memset(config, 0, 128);
    if (!wakeup()) {
        return false;
    }

    uint_fast16_t offset{};
    for (offset = 0; offset < 128; offset += 32) {
        if (!read_data(config + offset, 32, ZONE_CONFIG, offset_to_param2_for_config(offset))) {
            break;
        }
    }
    return idle() && (offset == 128);
}

bool UnitATECC608B::readDataZone(uint8_t* data, const uint16_t len, const atecc608::Slot slot)
{
    if (!data || !len || !wakeup()) {
        return false;
    }
    memset(data, 0, len);

    constexpr uint8_t BLOCK_SIZE{32};
    constexpr uint8_t WORD_SIZE{4};

    uint8_t* ptr      = data;
    uint16_t offset   = 0;
    int32_t remaining = len;

    while (remaining > 0) {
        uint8_t rlen    = (remaining >= BLOCK_SIZE) ? BLOCK_SIZE : WORD_SIZE;
        uint16_t param2 = slot_block_to_param2(m5::stl::to_underlying(slot), offset);
        if (!read_data(ptr, rlen, ZONE_DATA | ((rlen >= BLOCK_SIZE) ? 0x80 : 0x00), param2)) {
            break;
        }

        ptr += rlen;
        offset += rlen;
        remaining -= rlen;
    }

    return idle() && (offset == len);
}

bool UnitATECC608B::readOTPZone(uint8_t otp[64])
{
    return wakeup() && read_data(otp, 32, ZONE_OTP, offset_to_param2_for_config(0)) &&
           read_data(otp + 32, 32, ZONE_OTP, offset_to_param2_for_config(32)) && idle();
}

bool UnitATECC608B::operate_counter(uint32_t& value, const uint8_t counter, const uint8_t mode)
{
    value = 0;

    if (counter > 1 || !wakeup() || mode > 1) {
        return false;
    }

    bool ok{};
    if (send_command(OPCODE_COUNTER, mode, counter)) {
        m5::utility::delay(mode == 0 ? DELAY_READ : DELAY_COUNTER);
        uint8_t buf[4]{};
        ok    = receive_response(buf, sizeof(buf));
        value = ok ? (buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24)) : 0;
    }
    return idle() && ok;
}

bool UnitATECC608B::selfTest(uint8_t resultBits, const uint8_t testBits)
{
    resultBits = 0xFF;
    if (!testBits) {
        M5_LIB_LOGE("testBits must be set any bits");
        return false;
    }
    if (!wakeup()) {
        return false;
    }

    bool ok{};
    if (send_command(OPCODE_SELFTEST, testBits, 0x0000)) {
        m5::utility::delay(DELAY_SELFTEST);
        ok = receive_response(&resultBits, 1);
    }
    return idle() && ok;
}

bool UnitATECC608B::createNonceRandom(uint8_t tempkey[32], const uint8_t input[20], const bool useRNG,
                                      const bool updateSeed)
{
    if (!tempkey || !input || !wakeup()) {
        return false;
    }
    memset(tempkey, 0, 32);

    bool ok{};
    if (send_command(OPCODE_NONCE, updateSeed ? NONCE_MODE_RANDOM_UPDATE_SEED : NONCE_MODE_RANDOM_NOT_UPDATE_SEED,
                     useRNG ? NONCE_USE_TRNG : NONCE_USE_TEMPKEY, input, 20)) {
        m5::utility::delay(DELAY_NONCE);
        ok = receive_response(tempkey, 32);
    }
    return idle() && ok;
}

bool UnitATECC608B::operate_nonce_fixed(const uint8_t mode, const uint8_t* input, const uint32_t ilen)
{
    if (!input || ilen < ((mode & NONCE_MODE_INPUT_64) ? 64 : 32) ||
        ((mode & NONCE_MODE_PASSTHROUGH) != NONCE_MODE_PASSTHROUGH)) {
        return false;
    }
    if (!wakeup()) {
        return false;
    }

    bool ok{};
    M5_LIB_LOGE(">>>>> nonce fixed %02X len:%u", mode, ilen);

    if (send_command(OPCODE_NONCE, mode, 0x0000, input, ilen)) {
        m5::utility::delay(DELAY_NONCE);
        uint8_t result[1]{};
        ok = receive_response(result, sizeof(result)) && result[0] == 0;
        if (!ok) {
            M5_LIB_LOGE("Error:%02X", result[0]);
        }
    }
    return idle() && ok;
}

bool UnitATECC608B::generatePrivateKey(const atecc608::Slot slot, uint8_t pubKey[64], const bool digest)
{
    return pubKey && generate_key(pubKey, GENKEY_MODE_PRIVATE | (digest ? GENKEY_MODE_DIGEST : 0x00),
                                  m5::stl::to_underlying(slot));
}

bool UnitATECC608B::generateKey(uint8_t pubKey[64])
{
    uint8_t wbuf[3]{};
    return pubKey && generate_key(pubKey, GENKEY_MODE_PRIVATE, 0xFFFF, wbuf, 3);
}

bool UnitATECC608B::generatePublicKey(uint8_t pubKey[64], const atecc608::Slot slot, const bool digest)
{
    return pubKey && generate_key(pubKey, GENKEY_MODE_PUBLIC | (digest ? GENKEY_MODE_DIGEST : 0x00),
                                  m5::stl::to_underlying(slot));
}

bool UnitATECC608B::generate_key(uint8_t pubKey[64], const uint8_t mode, const uint16_t param2, const uint8_t* data,
                                 const uint32_t dlen)
{
    bool ok{};
    if (wakeup() && send_command(OPCODE_GENKEY, mode, param2, data, dlen)) {
        m5::utility::delay(DELAY_GENKEY);
        ok = receive_response(pubKey, 64);
    }
    return idle() && ok;
}

bool UnitATECC608B::readDeviceCertification(uint8_t* out, uint16_t& olen, const bool fillAuthKeyId)
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

    // Signature
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
    if (!SHA256(cert_sn, msg, sizeof(msg))) {
        M5_LIB_LOGE("Failed to SHA256");
        return false;
    }
    cert_sn[0] &= 0x7F;                         // Ensure the SN is positive
    cert_sn[0] |= 0x40u;                        // Ensure the SN doesn't have any trimmable bytes
    memcpy(out + offset_cert_sn, cert_sn, 16);  // Top of 16 bytes

    // Subkect key ID
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
        uint8_t key_id[20]{};
        m5::utility::SHA1::sha1(key_id, msg, 65);

        memcpy(out + offset_auth_key_id, key_id, 20);
    }
    return true;
}

bool UnitATECC608B::readSignerCertification(uint8_t* out, uint16_t& olen)
{
    constexpr uint16_t offset_cert_sn{15};
    constexpr uint16_t offset_issue_date{128};
    constexpr uint16_t offset_expire_date{143};
    constexpr uint16_t offset_signer_id{235};
    constexpr uint16_t offset_pubkey{266};
    constexpr uint16_t offset_subj_key_id{381};
    constexpr uint16_t offset_auth_key_id{414};
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
    if (!SHA256(cert_sn, msg, sizeof(msg))) {
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

bool UnitATECC608B::signInternal(uint8_t signature[64], const atecc608::Slot slot, const bool includeSerial,
                                 const bool tempkey)
{
    if (!signature || !wakeup()) {
        return false;
    }
    bool ok{};
    uint8_t mode = SIGN_MODE_INTERNAL |  //
                   (includeSerial ? SIGN_MODE_INCLUDE_SN : 0x00) | (tempkey ? SIGN_MODE_TEMPKEY : SIGN_MODE_DIGEST);

    if (send_command(OPCODE_SIGN, mode, m5::stl::to_underlying(slot))) {
        m5::utility::delay(DELAY_SIGN);
        ok = receive_response(signature, 64);
    }
    return idle() && ok;
}

bool UnitATECC608B::signExternal(uint8_t signature[64], const atecc608::Slot slot, const bool includeSerial,
                                 const bool tempKey)
{
    if (!signature || !wakeup()) {
        return false;
    }
    bool ok{};
    uint8_t mode = SIGN_MODE_EXTERNAL |  //
                   (includeSerial ? SIGN_MODE_INCLUDE_SN : 0x00) | (tempKey ? SIGN_MODE_TEMPKEY : SIGN_MODE_DIGEST);

    M5_LIB_LOGE(">>>>> mode: %02X", mode);

    if (send_command(OPCODE_SIGN, mode, m5::stl::to_underlying(slot))) {
        m5::utility::delay(DELAY_SIGN);
        ok = receive_response(signature, 64);
    }
    return idle() && ok;
}

bool UnitATECC608B::startSHA256()
{
    bool ok{};
    if (wakeup()) {
        uint8_t status{};
        if (send_command(OPCODE_SHA, SHA_MODE_START)) {
            m5::utility::delay(DELAY_SHA);
            ok = receive_response(&status, 1);
        }
        return idle() && ok && status == 0;
    }
    return false;
}

bool UnitATECC608B::updateSHA256(const uint8_t* data, const uint32_t len)
{
    if (!data || !len || !wakeup()) {
        return false;
    }

    constexpr uint32_t BLOCK_SIZE{64};
    uint32_t remaining = len;
    const uint8_t* ptr = data;
    bool ok            = true;
    uint8_t status{};

    while (remaining > 0) {
        uint32_t chunk_size = (remaining >= BLOCK_SIZE) ? BLOCK_SIZE : remaining;
        if (!send_command(OPCODE_SHA, SHA_MODE_UPDATE, 0x0000, ptr, chunk_size)) {
            //        if (!send_command(OPCODE_SHA, SHA_MODE_UPDATE, chunk_size, ptr, chunk_size)) {
            ok = false;
            break;
        }
        m5::utility::delay(DELAY_SHA);
        if (!receive_response(&status, 1) || status != 0) {
            ok = false;
            break;
        }

        ptr += chunk_size;
        remaining -= chunk_size;
    }
    return idle() && ok;
}

bool UnitATECC608B::finalize_SHA256(uint8_t hash[32], const uint8_t mode)
{
    bool ok{};
    if (!hash || !wakeup()) {
        return false;
    }
    if (send_command(OPCODE_SHA, mode)) {
        m5::utility::delay(DELAY_SHA);
        ok = receive_response(hash, 32);
    }
    return idle() && ok;
}

bool UnitATECC608B::ecdhPlaneText(uint8_t out[32], const uint8_t pubKey[64], const atecc608::Slot slot)
{
    if (!out || !pubKey) {
        return false;
    }
    //    return ecdh_receive32(out, pubKey, 0x0C, m5::stl::to_underlying(slot));
    return ecdh_receive32(out, pubKey, ECDH_MODE_SRC_SLOT | ECDH_MODE_OUTPUT_BUFFER, m5::stl::to_underlying(slot));
}

bool UnitATECC608B::ecdhEncrypted(uint8_t out[32], uint8_t nonce[32], const uint8_t pubKey[64],
                                  const atecc608::Slot slot)
{
    if (!out || !nonce || !pubKey) {
        return false;
    }
    //    return ecdh_receive32x2(out, nonce, pubKey, 0x0E, m5::stl::to_underlying(slot));
    return ecdh_receive32x2(out, nonce, pubKey, ECDH_MODE_SRC_SLOT | ECDH_MODE_OUTPUT_BUFFER | ECDH_MODE_ENCRYPT,
                            m5::stl::to_underlying(slot));
}

bool UnitATECC608B::ecdhTempKey(const uint8_t pubKey[64], const atecc608::Slot slot)
{
    if (!pubKey) {
        return false;
    }
    //    return ecdh_no_output(pubKey, 0x08, m5::stl::to_underlying(slot));
    return ecdh_no_output(pubKey, ECDH_MODE_SRC_SLOT | ECDH_MODE_OUTPUT_TEMPKEY, m5::stl::to_underlying(slot));
}

bool UnitATECC608B::ecdhPlaneText(uint8_t out[32], const uint8_t pubKey[64])
{
    if (!out || !pubKey) {
        return false;
    }
    //    return ecdh_receive32(out, pubKey, 0x0D, 0x0000);
    return ecdh_receive32(out, pubKey, ECDH_MODE_SRC_TEMPKEY | ECDH_MODE_OUTPUT_BUFFER, 0x0000);
}

bool UnitATECC608B::ecdhEncrypted(uint8_t out[32], uint8_t nonce[32], const uint8_t pubKey[64])
{
    if (!out || !nonce || !pubKey) {
        return false;
    }
    //    return ecdh_receive32x2(out, nonce, pubKey, 0x0F, 0x0000);
    return ecdh_receive32x2(out, nonce, pubKey, ECDH_MODE_SRC_TEMPKEY | ECDH_MODE_OUTPUT_BUFFER | ECDH_MODE_ENCRYPT,
                            0x0000);
}

bool UnitATECC608B::ecdhTempKey(const uint8_t pubKey[64])
{
    if (!pubKey) {
        return false;
    }
    //    return ecdh_no_output(pubKey, 0x09, 0x0000);
    return ecdh_no_output(pubKey, ECDH_MODE_SRC_TEMPKEY | ECDH_MODE_OUTPUT_TEMPKEY, 0x0000);
}

bool UnitATECC608B::ecdhSlot(const atecc608::Slot slot, const uint8_t pubKey[64])
{
    if (!pubKey) {
        return false;
    }
    //    return ecdh_no_output(pubKey, 0x05, m5::stl::to_underlying(slot));
    return ecdh_no_output(pubKey, ECDH_MODE_SRC_TEMPKEY | ECDH_MODE_OUTPUT_SLOT, m5::stl::to_underlying(slot));
}

bool UnitATECC608B::verify(const uint8_t mode, const uint16_t param2, const uint8_t signature[64],
                           const uint8_t pubKey[64], uint8_t mac[32])
{
    if (!signature || ((mode & VERIFY_MODE_MAC) && !mac)) {
        return false;
    }

    bool ok{};
    uint8_t response[32 + 1]{};
    const uint8_t response_size = (mode & VERIFY_MODE_MAC) ? 32 : 1;

    if (wakeup()) {
        uint8_t data[128]{};

        // signature
        memcpy(data, signature, 64);
        // pubKey if exists
        if (pubKey) {
            memcpy(data + 64, pubKey, 64);
        }

        M5_LIB_LOGE(">>>>> %02X %04X %p %u / %u", mode, param2, data, pubKey ? 128 : 64, response_size);

        if (send_command(OPCODE_VERIFY, mode, param2, data, pubKey ? 128 : 64)) {
            //            m5::utility::delay(DELAY_VERIFY);
            m5::utility::delay(200);

            if (receive_response(response, response_size)) {
                ok = true;
                if (response_size == 32) {
                    memcpy(mac, response, 32);
                } else {
                    ok &= (response[0] == 0x00);
                }
            }
        }
    }
    return idle() && ok;
}

//
bool UnitATECC608B::send_command(const uint8_t opcode, const uint8_t param1, const uint16_t param2, const uint8_t* data,
                                 uint32_t dlen)
{
    if (dlen > 155) {
        M5_LIB_LOGE("Data length must be smaller than 155. %u", dlen);
        return false;
    }

    uint32_t plen        = dlen + 8;
    uint8_t packet[plen] = {
        WORD_ADRESS_VALUE_COMMAND,      // Word address value
        (uint8_t)(sizeof(packet) - 1),  // packet length
        opcode,                         // Operation code
        param1,                         // param1
        (uint8_t)(param2 & 0xFF),       // param2
        (uint8_t)(param2 >> 8),         // param2
    };
    // data (optional)
    if (data && dlen) {
        memcpy(packet + 6, data, dlen);
    }
    uint16_t crc         = crc16.range(packet + 1, plen - 3);  // From &packet[1] to previouse CRC16
    packet[6 + dlen]     = crc & 0xFF;
    packet[6 + dlen + 1] = crc >> 8;

    // M5_LIB_LOGD("TX(%u): %02X %02X %02X %02X %02X %02X %02X %02X", plen, packet[0], packet[1], packet[2],
    // packet[3],
    //             packet[4], packet[5], packet[6], packet[7]);

    return writeWithTransaction(packet, plen) == m5::hal::error::error_t::OK;
}

bool UnitATECC608B::receive_response(uint8_t* data, const uint32_t dlen)
{
    if (!data || !dlen) {
        return false;
    }

    memset(data, 0, dlen);

    uint8_t head[1]{};
    if (readWithTransaction(head, 1) != m5::hal::error::error_t::OK) {
        M5_LIB_LOGE("Failed to read count byte");
        return false;
    }

    const uint32_t count = head[0];
    if (count < 4) {
        M5_LIB_LOGE("Invalid response count: %u", count);
        return false;
    }

    uint8_t rbuf[count]{};
    rbuf[0] = count;
    if (readWithTransaction(rbuf + 1, count - 1) != m5::hal::error::error_t::OK) {
        M5_LIB_LOGE("Failed to read response body");
        return false;
    }

    const auto crc = crc16.range(rbuf, count - 2);
    if ((crc & 0xFF) != rbuf[count - 2] || (crc >> 8) != rbuf[count - 1]) {
        M5_LIB_LOGE("CRC error: %04X != %02X%02X", crc, rbuf[count - 2], rbuf[count - 1]);
        return false;
    }

    // Error packet? (length == 4)
    if (count == 4) {
        const uint8_t status = rbuf[1];
        if (status) {
            M5_LIB_LOGE("Device returned error: %02X", status);
        }
        return status == 0x00;
    }
    const auto clen = std::min(count - 3, dlen);

    // M5_LIB_LOGD("R>>> count:%u out:%u clen:%u", count, dlen, clen);

    memcpy(data, rbuf + 1, clen);
    return true;
}

bool UnitATECC608B::read_data(uint8_t* rbuf, const uint32_t rlen, const uint8_t zone, const uint16_t address,
                              const uint32_t delayMs)
{
    if (send_command(OPCODE_READ, zone | ((rlen > 4) ? 0x80 : 0x00), address)) {
        m5::utility::delay(delayMs);
        return receive_response(rbuf, rlen) && delay_true(1);  // post delay
    }
    return false;
}

bool UnitATECC608B::read_slot_config_word(uint16_t& cfg, const uint8_t baseOffset, const atecc608::Slot slot)
{
    cfg                    = 0;
    const uint16_t offset  = baseOffset + m5::stl::to_underlying(slot) * 2;
    const uint_fast8_t idx = offset & 0x03;
    uint8_t v[4]{};
    bool ok = wakeup() && read_data(v, sizeof(v), ZONE_CONFIG, offset_to_param2_for_config(offset));
    if (ok) {
        cfg = (v[idx] << 8) | v[idx + 1];  // BE
    }
    return idle() && ok;
}

bool UnitATECC608B::ecdh_receive32(uint8_t out[32], const uint8_t pubKey[64], const uint8_t mode, const uint16_t param2)
{
    bool ok{};
    if (wakeup() && send_command(OPCODE_ECDH, mode, param2, pubKey, 64)) {
        m5::utility::delay(DELAY_ECDH);
        ok = receive_response(out, 32);
    }
    return idle() && ok;
}

bool UnitATECC608B::ecdh_receive32x2(uint8_t out[32], uint8_t nonce[32], const uint8_t pubKey[64], const uint8_t mode,
                                     const uint16_t param2)
{
    bool ok{};
    if (wakeup() && send_command(OPCODE_ECDH, mode, param2, pubKey, 64)) {
        m5::utility::delay(DELAY_ECDH);
        uint8_t buf[64]{};
        ok = receive_response(buf, 64);
        if (ok) {
            memcpy(out, buf, 32);
            memcpy(nonce, buf + 32, 32);
        }
    }
    return idle() && ok;
}

bool UnitATECC608B::ecdh_no_output(const uint8_t pubKey[64], const uint8_t mode, const uint16_t param2)
{
    uint8_t status{};
    bool ok{};
    if (wakeup() && send_command(OPCODE_ECDH, mode, param2, pubKey, 64)) {
        m5::utility::delay(DELAY_ECDH);
        ok = receive_response(&status, 1);
    }
    return idle() && ok && status == 0;
}

}  // namespace unit
}  // namespace m5
