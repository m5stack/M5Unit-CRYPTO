/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*!
 @file unit_ATECC608B.cpp
 @brief ATECC608B Unit for M5UnitUnified
*/
#include "unit_ATECC608B.hpp"
#include <M5Utility.hpp>
#if defined(ARDUINO)
#include <driver/gpio.h>
#endif

using namespace m5::utility::mmh3;
using namespace m5::unit::types;
using namespace m5::unit::atecc608;
namespace {
constexpr std::array<uint8_t, 4> RESPONSE{0x04, 0x11, 0x33, 0x43};

constexpr uint8_t fixed_nonce_mode_table32[] = {NONCE_MODE_TARGET_TEMPKEY, NONCE_MODE_TARGET_DIGEST,
                                                NONCE_MODE_TARGET_ALTKEY, 0xFF};

constexpr uint8_t fixed_nonce_mode_table64[] = {NONCE_MODE_TARGET_TEMPKEY, NONCE_MODE_TARGET_DIGEST, 0xFF, 0xFF};

constexpr uint8_t finalize_sha256_mode_table[] = {SHA_MODE_OUTPUT_TEMPKEY, SHA_MODE_OUTPUT_DIGEST, 0xFF,
                                                  SHA_MODE_OUTPUT_BUFFER};

constexpr uint8_t sign_source_table[] = {SIGN_MODE_TEMPKEY, SIGN_MODE_DIGEST, 0xFF, 0xFF};

constexpr uint8_t verify_source_table[] = {SIGN_MODE_TEMPKEY, SIGN_MODE_DIGEST, 0xFF, 0xFF};

// CRC16
m5::utility::CRC16 crc16(0x0000, 0x8005, true, false, 0x0000);

inline bool delay_true(const uint32_t ms = 1)
{
    m5::utility::delay(ms);
    return true;  // Always!
}

}  // namespace

namespace m5 {
namespace unit {

// class UnitATECC608B
const char UnitATECC608B::name[] = "UnitATECC608B";
const types::uid_t UnitATECC608B::uid{"UnitATECC608B"_mmh3};
const types::attr_t UnitATECC608B::attr{attribute::AccessI2C};

bool UnitATECC608B::begin()
{
    // The Verify(External) command sends up to 163 bytes in a single I2C write transaction
    // (8-byte header + up to 155 bytes data: 64-byte signature + 64-byte pubKey + ...).
    // Arduino Wire's default TX buffer is 128 bytes, which silently truncates larger writes,
    // causing CRC mismatch and device timeout.  Expand the buffer when using Arduino Wire.
    auto ad = asAdapter<AdapterI2C>(Adapter::Type::I2C);
    if (ad && ad->implType() == AdapterI2C::ImplType::TwoWire) {
        constexpr size_t REQUIRED_BUF_SIZE{256};
        auto wire = ad->impl()->getWire();
        if (wire) {
            wire->setBufferSize(REQUIRED_BUF_SIZE);
            M5_LIB_LOGI("Wire TX buffer expanded to %u", REQUIRED_BUF_SIZE);
        }
    }

    if (!wakeup()) {
        M5_LIB_LOGE("Failed to wakeup");
        return false;
    }

    // Read revision inline (device is already awake)
    bool rev_ok{};
    if (send_command(OPCODE_INFO, INFO_MODE_REVISION)) {
        m5::utility::delay(DELAY_INFO);
        rev_ok = receive_response(_revision.data(), 4);
    }
    if (!rev_ok) {
        M5_LIB_LOGE("Failed to readRevision");
        idle();
        return false;
    }

    if (!begin_impl()) {
        M5_LIB_LOGE("Failed to begin_impl");
        idle();
        return false;
    }

    // End the session
    if (!_cfg.idle) {
        return sleep();
    }
    return idle();
}

bool UnitATECC608B::begin_impl()
{
    // Check 608B
    if (!(_revision[0] == 0x00 && _revision[1] == 0x00 && _revision[2] == 0x60 && _revision[3] >= 0x03)) {
        M5_LIB_LOGE("This is not 608B %02X:%02X:%02X:%02X", _revision[0], _revision[1], _revision[2], _revision[3]);
        return false;
    }
    return true;
}

bool UnitATECC608B::wakeup()
{
    auto ad = asAdapter<AdapterI2C>(Adapter::Type::I2C);
    if (!ad) {
        M5_LIB_LOGE("No AdapterI2C");
        return false;
    }

    auto sda_pin = ad->sda();
    auto scl_pin = ad->scl();
    if (sda_pin < 0 && scl_pin < 0) {
        M5_LIB_LOGE("Invalid pin %d,%d", sda_pin, scl_pin);
        return false;
    }

    bool ok{};
    std::array<uint8_t, 4> response{};
    for (uint_fast8_t retry = 0; retry < 3; ++retry) {
        // GPIO SDA pulse wakeup (no general call — avoids affecting other devices)
        m5::utility::delay(1);

        gpio::pin_backup_t sda_backup(sda_pin);
        gpio::pin_backup_t scl_backup(scl_pin);
        gpio_set_direction((gpio_num_t)scl_pin, GPIO_MODE_OUTPUT_OD);
        gpio_set_direction((gpio_num_t)sda_pin, GPIO_MODE_OUTPUT_OD);
        gpio_set_level((gpio_num_t)scl_pin, 1);

        gpio_set_level((gpio_num_t)sda_pin, 1);
        m5::utility::delayMicroseconds(5);
        gpio_set_level((gpio_num_t)sda_pin, 0);
        m5::utility::delayMicroseconds(80);  // tWLO >= 60us
        gpio_set_level((gpio_num_t)sda_pin, 1);
        m5::utility::delayMicroseconds(5);

        scl_backup.restore();
        sda_backup.restore();

        m5::utility::delayMicroseconds(1500);  // tWHI >= 1.5ms

        response.fill(0);
        auto err = readWithTransaction(response.data(), response.size());
        ok       = (err == m5::hal::error::error_t::OK) && (response == RESPONSE);
        if (ok) {
            break;
        }
        M5_LIB_LOGW("Wakeup retry %u err:%d resp:%02X,%02X,%02X,%02X", retry, (int)err, response[0], response[1],
                    response[2], response[3]);
        // Device may be awake with stale state — force sleep before retry
        writeWithTransaction(&WORD_ADDRESS_VALUE_SLEEP, 1);
        m5::utility::delay(2);
    }
    return ok;
}

bool UnitATECC608B::sleep()
{
    writeWithTransaction(&WORD_ADDRESS_VALUE_SLEEP, 1);
    return delay_true();
}

bool UnitATECC608B::idle()
{
    writeWithTransaction(&WORD_ADDRESS_VALUE_IDLE, 1);
    return delay_true();
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
        uint8_t rbuf[4]{};
        ok    = receive_response(rbuf, sizeof(rbuf));
        state = (rbuf[0] << 8) | (rbuf[1] << 0);
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

    // SN is bytes 0-3 and 8-12 of Config Zone.
    // Config Read always returns 4 bytes minimum, so read 4 and take the first byte for sn[8].
    uint8_t tmp[4]{};
    bool ok = read_data(sn, 4, ZONE_CONFIG, offset_to_param2_for_config(0)) &&
              read_data(sn + 4, 4, ZONE_CONFIG, offset_to_param2_for_config(8)) &&
              read_data(tmp, 4, ZONE_CONFIG, offset_to_param2_for_config(12));
    if (ok) {
        sn[8] = tmp[0];
    }

    return idle() && ok;
}

bool UnitATECC608B::readSerialNumber(char str[19])
{
    if (!str) {
        return false;
    }
    uint8_t sn[9]{};
    if (readSerialNumber(sn)) {
        snprintf(str, 19, "%02X%02X%02X%02X%02X%02X%02X%02X%02X", sn[0], sn[1], sn[2], sn[3], sn[4], sn[5], sn[6],
                 sn[7], sn[8]);
        return true;
    }
    return false;
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

    // With DirectTransport, 32-byte block reads work reliably (no bus recovery interference).
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

bool UnitATECC608B::writeGeneralData(const uint8_t* data, const uint16_t len, const uint16_t offset)
{
    constexpr uint16_t SLOT_SIZE{416};
    constexpr uint8_t SLOT{8};
    constexpr uint8_t BLOCK_SIZE{32};

    if (!data || !len) {
        return false;
    }
    if ((offset & 0x1F) || (len & 0x1F)) {
        M5_LIB_LOGE("writeGeneralData: offset(%u) and len(%u) must be 32-byte aligned", offset, len);
        return false;
    }
    if (offset >= SLOT_SIZE) {
        M5_LIB_LOGE("writeGeneralData: offset(%u) exceeds slot size(%u)", offset, SLOT_SIZE);
        return false;
    }

    // Clamp len to fit within slot
    const uint16_t max_len = SLOT_SIZE - offset;
    const uint16_t wlen    = m5::stl::clamp<uint16_t>(len, BLOCK_SIZE, max_len);
    if (len > max_len) {
        M5_LIB_LOGW("writeGeneralData: len %u exceeds available %u, truncated", len, max_len);
    }

    if (!wakeup()) {
        return false;
    }

    const uint8_t* ptr = data;
    uint16_t pos       = offset;
    uint16_t written   = 0;

    while (written < wlen) {
        uint16_t param2 = slot_block_to_param2(SLOT, pos);

        if (!send_command(OPCODE_WRITE, ZONE_DATA | 0x80, param2, ptr, BLOCK_SIZE)) {
            idle();
            return false;
        }
        m5::utility::delay(DELAY_WRITE);

        uint8_t status{0xFF};
        if (!receive_response(&status, 1) || status != 0) {
            M5_LIB_LOGE("writeGeneralData: write failed at offset %u, status:0x%02X", pos, status);
            idle();
            return false;
        }

        ptr += BLOCK_SIZE;
        pos += BLOCK_SIZE;
        written += BLOCK_SIZE;
    }

    return idle();
}

bool UnitATECC608B::readGeneralData(uint8_t* data, const uint16_t len, const uint16_t offset)
{
    constexpr uint16_t SLOT_SIZE{416};
    constexpr uint8_t SLOT{8};
    constexpr uint8_t BLOCK_SIZE{32};

    if (!data || !len) {
        return false;
    }
    if ((offset & 0x1F) || (len & 0x1F)) {
        M5_LIB_LOGE("readGeneralData: offset(%u) and len(%u) must be 32-byte aligned", offset, len);
        return false;
    }
    if (offset >= SLOT_SIZE) {
        M5_LIB_LOGE("readGeneralData: offset(%u) exceeds slot size(%u)", offset, SLOT_SIZE);
        return false;
    }

    const uint16_t max_len = SLOT_SIZE - offset;
    const uint16_t rlen    = m5::stl::clamp<uint16_t>(len, BLOCK_SIZE, max_len);
    if (len > max_len) {
        M5_LIB_LOGW("readGeneralData: len %u exceeds available %u, truncated", len, max_len);
    }

    memset(data, 0, len);

    if (!wakeup()) {
        return false;
    }

    uint8_t* ptr     = data;
    uint16_t pos     = offset;
    uint16_t read_sz = 0;

    while (read_sz < rlen) {
        uint16_t param2 = slot_block_to_param2(SLOT, pos);
        if (!read_data(ptr, BLOCK_SIZE, ZONE_DATA | 0x80, param2)) {
            break;
        }
        ptr += BLOCK_SIZE;
        pos += BLOCK_SIZE;
        read_sz += BLOCK_SIZE;
    }

    return idle() && (read_sz == rlen);
}

bool UnitATECC608B::readOTPZone(uint8_t otp[64])
{
    if (!otp) {
        return false;
    }
    memset(otp, 0, 64);
    if (!wakeup()) {
        return false;
    }

    // 32-byte block reads (same as readConfigZone)
    uint_fast16_t offset{};
    for (offset = 0; offset < 64; offset += 32) {
        if (!read_data(otp + offset, 32, ZONE_OTP | 0x80, offset_to_param2_for_config(offset))) {
            break;
        }
    }
    return idle() && (offset == 64);
}

bool UnitATECC608B::counter(uint32_t& value, const uint8_t counter, const uint8_t mode)
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

bool UnitATECC608B::selfTest(uint8_t& resultBits, const uint8_t testBits)
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

bool UnitATECC608B::createNonce(uint8_t output[32], const uint8_t input[20], const bool useRNG, const bool updateSeed)
{
    if (!input || !wakeup()) {
        return false;
    }
    if (output) {
        memset(output, 0, 32);
    }

    bool ok{};
    uint8_t buf[32]{};

    const uint8_t mode    = (updateSeed ? NONCE_MODE_RANDOM_UPDATE_SEED : NONCE_MODE_RANDOM_NOT_UPDATE_SEED);
    const uint16_t param2 = (useRNG ? NONCE_USE_TRNG : NONCE_USE_TEMPKEY);

    if (send_command(OPCODE_NONCE, mode, param2, input, 20)) {
        m5::utility::delay(DELAY_NONCE);
        ok = receive_response(output ? output : buf, 32);
    }
    return idle() && ok;
}

bool UnitATECC608B::write_nonce(const Destination dest, const uint8_t* input, const uint32_t ilen)
{
    const uint8_t* tbl = ilen > 32 ? fixed_nonce_mode_table64 : fixed_nonce_mode_table32;
    uint8_t mode =
        tbl[m5::stl::to_underlying(dest)] | NONCE_MODE_PASSTHROUGH | ((ilen > 32) ? NONCE_MODE_INPUT_64 : 0x00);
    if (mode == 0xFF || !input || ilen < 32 || !wakeup()) {
        return false;
    }

    bool ok{};
    if (send_command(OPCODE_NONCE, mode, 0x0000, input, ilen)) {
        m5::utility::delay(DELAY_NONCE);
        uint8_t status{};
        ok = receive_response(&status, 1) && (status == 0);
        // if (!ok) {
        //     M5_LIB_LOGE("Error:%02X", result[0]);
        // }
    }
    return idle() && ok;
}

bool UnitATECC608B::generateKey(uint8_t pubKey[64])
{
    uint8_t wbuf[3]{};
    return pubKey && generate_key(pubKey, GENKEY_MODE_PRIVATE, 0xFFFF, wbuf, 3);
}

bool UnitATECC608B::generatePublicKeyDigest(const atecc608::Slot slot, const uint8_t otherData[3])
{
    return generate_key(nullptr, GENKEY_MODE_PUBLIC_DIGEST, m5::stl::to_underlying(slot), otherData, otherData ? 3 : 0);
}

bool UnitATECC608B::generate_key(uint8_t pubKey[64], const uint8_t mode, const uint16_t param2, const uint8_t* data,
                                 const uint32_t dlen)
{
    bool ok{};
    if (wakeup() && delay_true(2) && send_command(OPCODE_GENKEY, mode, param2, data, dlen)) {
        m5::utility::delay(DELAY_GENKEY);
        if (pubKey) {
            ok = receive_response(pubKey, 64);
        } else {
            uint8_t status{};
            ok = receive_response(&status, 1) && (status == 0);
        }
    }
    return idle() && ok;
}

bool UnitATECC608B::sign(uint8_t signature[64], const uint8_t mode, const uint16_t param2, const atecc608::Source src)
{
    const uint8_t smode = sign_source_table[m5::stl::to_underlying(src)];

    if (!signature || smode == 0xFF || !wakeup()) {
        return false;
    }
    memset(signature, 0, 64);

    bool ok{};
    if (send_command(OPCODE_SIGN, mode | smode, param2)) {
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

bool UnitATECC608B::updateSHA256(const uint8_t* msg, const uint32_t mlen)
{
    // No change context
    if (!msg || !mlen) {
        M5_LIB_LOGW("msg is empty");
        return true;
    }
    if (!wakeup()) {
        return false;
    }

    constexpr uint32_t BLOCK_SIZE{64};
    uint32_t remaining = mlen;
    const uint8_t* ptr = msg;
    bool ok{true};

    auto idle_wakeup_at = m5::utility::millis() + 1000;

    while (remaining > 0) {
        uint16_t chunk_size = (remaining >= BLOCK_SIZE) ? BLOCK_SIZE : remaining;
        if (!send_command(OPCODE_SHA, SHA_MODE_UPDATE, chunk_size, ptr, chunk_size)) {
            ok = false;
            break;
        }
        m5::utility::delay(DELAY_SHA);

        uint8_t status{0xFF};
        if (!receive_response(&status, 1) || status != 0) {
            ok = false;
            break;
        }

        ptr += chunk_size;
        remaining -= chunk_size;

        // When long data comes in, WDT causes 0xEE error, so to prevent this, idle -> wakeup transition is used
        auto now = m5::utility::millis();
        if (now > idle_wakeup_at) {
            if (!idle() || !wakeup()) {
                ok = false;
                break;
            }
            idle_wakeup_at = now + 1000;
        }
    }
    return idle() && ok;
}

bool UnitATECC608B::finalizeSHA256(const atecc608::Destination dest, uint8_t digest[32])
{
    bool ok{};
    uint8_t mode = finalize_sha256_mode_table[m5::stl::to_underlying(dest)] | SHA_MODE_FINALIZE;

    if (mode == 0xFF || !digest || !wakeup()) {
        return false;
    }
    memset(digest, 0, 32);

    if (send_command(OPCODE_SHA, mode)) {
        m5::utility::delay(DELAY_SHA);
        ok = receive_response(digest, 32);
    }
    return idle() && ok;
}

bool UnitATECC608B::ecdh_receive32(uint8_t out[32], const uint8_t mode, const uint16_t param2, const uint8_t pubKey[64])
{
    if (!out || !pubKey || !wakeup()) {
        return false;
    }
    memset(out, 0, 32);

    bool ok{};
    if (send_command(OPCODE_ECDH, mode, param2, pubKey, 64)) {
        m5::utility::delay(DELAY_ECDH);
        ok = receive_response(out, 32);
    }
    return idle() && ok;
}

bool UnitATECC608B::ecdh_receive32x2(uint8_t out[32], uint8_t nonce[32], const uint8_t mode, const uint16_t param2,
                                     const uint8_t pubKey[64])
{
    if (!out || !nonce || !pubKey || !wakeup()) {
        return false;
    }
    memset(out, 0, 32);
    memset(nonce, 0, 32);

    bool ok{};
    if (send_command(OPCODE_ECDH, mode, param2, pubKey, 64)) {
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

bool UnitATECC608B::ecdh_no_output(const uint8_t mode, const uint16_t param2, const uint8_t pubKey[64])
{
    bool ok{};
    if (!pubKey || !wakeup()) {
        return false;
    }
    if (send_command(OPCODE_ECDH, mode, param2, pubKey, 64)) {
        m5::utility::delay(DELAY_ECDH);
        uint8_t status{};
        ok = receive_response(&status, 1) && (status == 0);
    }
    return idle() && ok;
}

bool UnitATECC608B::verify(uint8_t mac[32], const uint8_t mode, const uint16_t param2, const uint8_t signature[64],
                           const uint8_t pubKey[64], Source src)
{
    const uint8_t smode = verify_source_table[m5::stl::to_underlying(src)];

    if (!signature || smode == 0xFF || ((mode & VERIFY_MODE_MAC) ? !mac : false) ||
        ((mode & VERIFY_MODE_EXTERNAL) ? !pubKey : false)) {
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

        // M5_LIB_LOGE(">>>>> %02X %04X %p %u / %u", mode, param2, data, pubKey ? 128 : 64, response_size);

        if (send_command(OPCODE_VERIFY, mode | smode, param2, data, pubKey ? 128 : 64)) {
            m5::utility::delay(DELAY_VERIFY);

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
    constexpr uint32_t MAX_DLEN{148};  // Max data: packet = dlen+8, count byte max 155
    if (dlen > MAX_DLEN) {
        M5_LIB_LOGE("Data length must be <= %u. %u", MAX_DLEN, dlen);
        return false;
    }

    uint32_t plen = dlen + 8;
    uint8_t packet[156]{};                            // Max: 148 + 8 = 156
    packet[0] = WORD_ADDRESS_VALUE_COMMAND;           // Word address value
    packet[1] = static_cast<uint8_t>(plen - 1);       // packet length (count)
    packet[2] = opcode;                               // Operation code
    packet[3] = param1;                               // param1
    packet[4] = static_cast<uint8_t>(param2 & 0xFF);  // param2
    packet[5] = static_cast<uint8_t>(param2 >> 8);    // param2
    // data (optional)
    if (data && dlen) {
        memcpy(packet + 6, data, dlen);
    }
    uint16_t crc         = crc16.range(packet + 1, plen - 3);  // From &packet[1] to previous CRC16
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

    // Read entire response in a single I2C transaction: count(1) + data(dlen) + CRC(2)
    // This avoids splitting the read into two transactions, which causes read timeout
    // on m5gfx I2C (I2C_Class) when the body exceeds ~32 bytes.
    const uint32_t max_read = dlen + 3;
    uint8_t rbuf[158]{};  // Max: dlen(max 155) + 3 = 158
    auto rerr = readWithTransaction(rbuf, max_read);
    if (rerr != m5::hal::error::error_t::OK) {
        M5_LIB_LOGE("Failed to read response");
        return false;
    }

    const uint32_t count = rbuf[0];
    if (count < 4) {
        M5_LIB_LOGE("Invalid response count: %u", count);
        return false;
    }

    const auto crc = crc16.range(rbuf, count - 2);
    if ((crc & 0xFF) != rbuf[count - 2] || (crc >> 8) != rbuf[count - 1]) {
        M5_LIB_LOGE("CRC error: %04X != %02X%02X (count:%u max_read:%u)", crc, rbuf[count - 2], rbuf[count - 1], count,
                    max_read);
        M5_DUMPE(rbuf, max_read);
        return false;
    }

    // Any response data or status
    const auto clen = std::min(count - 3 /* count , crc16 */, dlen);
    memcpy(data, rbuf + 1, clen);

    // Did not get the expected data length?
    if ((dlen > 1 && clen == 1) && data[0] != 0) {
        M5_LIB_LOGE("Receive error: %02X", data[0]);
        return false;
    }
    return true;
}

bool UnitATECC608B::read_data(uint8_t* rbuf, const uint32_t rlen, const uint8_t zone, const uint16_t address,
                              const uint32_t delayMs)
{
    if (send_command(OPCODE_READ, zone | ((rlen > 4) ? 0x80 : 0x00), address)) {
        m5::utility::delay(delayMs);
        return receive_response(rbuf, rlen) && delay_true();  // post delay
    }
    M5_LIB_LOGE("Failed send_command:%02X %04X", zone | ((rlen > 4) ? 0x80 : 0x00), address);
    return false;
}

bool UnitATECC608B::read_slot_config_word(uint16_t& cfg, const uint8_t baseOffset, const atecc608::Slot slot)
{
    cfg = 0;

    const uint16_t offset  = baseOffset + m5::stl::to_underlying(slot) * 2;
    const uint_fast8_t idx = offset & 0x03;
    uint8_t v[4]{};
    bool ok = wakeup() && read_data(v, sizeof(v), ZONE_CONFIG, offset_to_param2_for_config(offset));
    if (ok) {
        cfg = v[idx] | (v[idx + 1] << 8);  // LE
    }
    return idle() && ok;
}

}  // namespace unit
}  // namespace m5
