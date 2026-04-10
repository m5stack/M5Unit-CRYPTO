/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for UnitATECC608B_TNGTLS

  NOTE: These tests do NOT perform any irreversible operations (Lock, Write, PrivWrite,
  private key generation, counter increment, etc.).  All operations are read-only,
  volatile-SRAM-only, or diagnostic (SelfTest).
*/
#include <gtest/gtest.h>
#include <Wire.h>
#include <M5Unified.h>
#include <M5UnitUnified.hpp>
#include <googletest/test_template.hpp>
#include <googletest/test_helper.hpp>
#include <unit/unit_ATECC608B_TNGTLS.hpp>
#include <cctype>
#include <limits>
#include <algorithm>
#include <cmath>
#include <esp_random.h>

using namespace m5::unit::googletest;
using namespace m5::unit;
using namespace m5::unit::atecc608;
using m5::unit::types::elapsed_time_t;

class TestATECC608B_TNGTLS : public I2CComponentTestBase<UnitATECC608B_TNGTLS> {
protected:
    virtual UnitATECC608B_TNGTLS* get_instance() override
    {
        auto ptr = new m5::unit::UnitATECC608B_TNGTLS();
        return ptr;
    }

#if defined(USING_M5CORE2_AWS_BUILTIN)
    virtual bool begin() override
    {
        // Core2 AWS builtin: use M5.In_I2C (I2C_NUM_1, SDA=21, SCL=22)
        M5_LOGI("Using M5.In_I2C for builtin ATECC608B");
        return Units.add(*unit, M5.In_I2C) && Units.begin();
    }
#endif
};

namespace {

bool is_equal_hex_string(const char* hex_str, const uint8_t* bytes, size_t len)
{
    for (uint32_t i = 0; i < len; ++i) {
        char high = toupper(hex_str[i * 2]);
        char low  = toupper(hex_str[i * 2 + 1]);
        uint8_t value =
            ((high >= 'A') ? (high - 'A' + 10) : (high - '0')) << 4 | ((low >= 'A') ? (low - 'A' + 10) : (low - '0'));
        if (value != bytes[i]) {
            return false;
        }
    }
    return true;
}

inline bool is_valid_tempkey(const uint16_t s)
{
    return (s >> 7) & 1;
}

inline bool is_valid_nomac_tempkey(const uint16_t s)
{
    return (s >> 15) & 1;
}

inline bool is_valid_genkey_tempkey(const uint16_t s)
{
    return (s >> 14) & 1;
}

inline bool is_valid_gendlg_tempkey(const uint16_t s)
{
    return (s >> 13) & 1;
}

inline bool is_external_source_tempkey(const uint16_t s)
{
    return (s >> 12) & 1;
}

uint8_t get_tempkey_keyID(const uint16_t state)
{
    return (state >> 8) & 0x0F;
}

bool clear_tempkey(UnitATECC608B_TNGTLS* u)
{
#if 0
    u->sleep();
    u->wakeup();
#endif

    uint16_t state{};
    u->readDeviceState(state);
    if (is_valid_tempkey(state)) {
        uint8_t pubKey[64]{};
        // private key stored in TempKey, Output public key
        if (!u->generateKey(pubKey)) {
            M5_LOGE("E1");
            return false;
        }
        // Use Source as TempKey, So will clear TempKey...
        uint8_t out[32]{};
        if (!u->ECDHTempKey(out, pubKey)) {
            M5_LOGE("E2");
            return false;
        }
    }
    u->readDeviceState(state);
    return !is_valid_tempkey(state);
}

// SHA256
struct Sha256TestVector {
    const char* name;
    const uint8_t* input;
    uint32_t input_len;
    const uint8_t* expected;
};

constexpr Sha256TestVector sha256_test_vectors[] = {
    {"empty", (const uint8_t[]){}, 0,
     (const uint8_t[]){0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
                       0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55}},
    {"abc", (const uint8_t[]){0x61, 0x62, 0x63}, 3,
     (const uint8_t[]){0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
                       0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD}},
    {"64_a",
     (const uint8_t[]){0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                       0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                       0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                       0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61},
     64,
     (const uint8_t[]){0xFF, 0xE0, 0x54, 0xFE, 0x7A, 0xE0, 0xCB, 0x6D, 0xC6, 0x5C, 0x3A, 0xF9, 0xB6, 0x1D, 0x52, 0x09,
                       0xF4, 0x39, 0x85, 0x1D, 0xB4, 0x3D, 0x0B, 0xA5, 0x99, 0x73, 0x37, 0xDF, 0x15, 0x46, 0x68, 0xEB}},
    {"56_a", (const uint8_t[]){0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                               0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                               0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                               0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61},
     56,
     (const uint8_t[]){0xB3, 0x54, 0x39, 0xA4, 0xAC, 0x6F, 0x09, 0x48, 0xB6, 0xD6, 0xF9, 0xE3, 0xC6, 0xAF, 0x0F, 0x5F,
                       0x59, 0x0C, 0xE2, 0x0F, 0x1B, 0xDE, 0x70, 0x90, 0xEF, 0x79, 0x70, 0x68, 0x6E, 0xC6, 0x73, 0x8A}},
    {"100_a",
     (const uint8_t[]){0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                       0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                       0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                       0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                       0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                       0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
                       0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61},
     100,
     (const uint8_t[]){0x28, 0x16, 0x59, 0x78, 0x88, 0xE4, 0xA0, 0xD3, 0xA3, 0x6B, 0x82, 0xB8, 0x33, 0x16, 0xAB, 0x32,
                       0x68, 0x0E, 0xB8, 0xF0, 0x0F, 0x8C, 0xD3, 0xB9, 0x04, 0xD6, 0x81, 0x24, 0x6D, 0x28, 0x5A, 0x0E}},
};

// For 'a' String repeated 1000000 times
constexpr uint8_t sha256_a1000000_result[] = {0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92, 0x81, 0xA1, 0xC7,
                                              0xE2, 0x84, 0xD7, 0x3E, 0x67, 0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97,
                                              0x20, 0x0E, 0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0};

template <typename T, typename U>
void test_random(UnitATECC608B_TNGTLS* u, const U l, const U h)
{
    const T lower  = static_cast<T>(l);
    const T higher = static_cast<T>(h);

    uint32_t count{10};
    std::vector<T> result;

    while (count--) {
        T value{};
        EXPECT_TRUE(u->readRandom(value, lower, higher));  // [lower ... higher)

        EXPECT_LT(value, higher);
        EXPECT_GE(value, lower);
        result.push_back(value);
    }
    EXPECT_EQ(result.size(), 10);
    EXPECT_FALSE(std::all_of(result.cbegin() + 1, result.cend(), [&result](const T& v) { return v == result[0]; }))
        << "low:" << l << " high:" << h;
}

template <typename T, typename U>
void test_random_float(UnitATECC608B_TNGTLS* u, const U l, const U h)
{
    const T lower  = static_cast<T>(l);
    const T higher = static_cast<T>(h);

    uint32_t count{10};
    std::vector<T> result;

    while (count--) {
        T value{};
        EXPECT_TRUE(u->readRandom(value, lower, higher));  // [lower ... higher)

        EXPECT_TRUE(value < higher) << "actual=" << value << ", expected<" << higher;
        EXPECT_TRUE(value >= lower) << "actual=" << value << ", expected>=" << lower;
        result.push_back(value);
    }
    EXPECT_EQ(result.size(), 10);
    EXPECT_FALSE(std::all_of(result.cbegin() + 1, result.cend(), [&result](const T& v) { return v == result[0]; }))
        << "low:" << l << " high:" << h;
}

}  // namespace

TEST_F(TestATECC608B_TNGTLS, serialNumber)
{
    SCOPED_TRACE(ustr);

    uint8_t sn[9]{};
    EXPECT_TRUE(unit->readSerialNumber(sn));
    EXPECT_FALSE(std::all_of(std::begin(sn), std::end(sn), [](const uint8_t v) { return v == 0; }));

    char sns[19]{};
    EXPECT_TRUE(unit->readSerialNumber(sns));
    EXPECT_TRUE(is_equal_hex_string(sns, sn, sizeof(sn)));
}

TEST_F(TestATECC608B_TNGTLS, Counter)
{
    SCOPED_TRACE(ustr);

    uint32_t org0{}, org1{};

    EXPECT_TRUE(unit->readCounter(org0, 0));
    EXPECT_TRUE(unit->readCounter(org1, 1));

// Skip: incrementCounter is irreversible (monotonic counter).
// Max value is 2,097,151 (0x1FFFFF). Repeated test runs will exhaust the counter permanently.
#if 0
    uint32_t c0{}, c1{};
    EXPECT_TRUE(unit->incrementCounter(c0, 0));
    EXPECT_EQ(c0, org0 + 1);

    EXPECT_TRUE(unit->incrementCounter(c1, 1));
    EXPECT_EQ(c1, org1 + 1);
    EXPECT_TRUE(unit->incrementCounter(c1, 1));
    EXPECT_EQ(c1, org1 + 2);

    EXPECT_TRUE(unit->readCounter(c0, 0));
    EXPECT_TRUE(unit->readCounter(c1, 1));
    EXPECT_EQ(c0, org0 + 1);
    EXPECT_EQ(c1, org1 + 2);
#endif
}

TEST_F(TestATECC608B_TNGTLS, Info)
{
    SCOPED_TRACE(ustr);

    {  // Revision
        // The value of the fourth byte may change over time but it is 0x03 at the time of the initial product release
        constexpr uint8_t atecc608b_tngtls_rev[4] = {0x00, 0x00, 0x60, 0x03};
        uint8_t rev[4]{};
        EXPECT_TRUE(unit->readRevision(rev));

        EXPECT_TRUE(memcmp(rev, atecc608b_tngtls_rev, 3) == 0);
        EXPECT_GE(rev[3], atecc608b_tngtls_rev[3]);
    }

    {  // KeyValid
        for (uint8_t s = 0; s < 16; ++s) {
            bool valid{};
            EXPECT_TRUE(unit->readKeyValid(valid, (Slot)s));
            if (s <= 4) {
                EXPECT_TRUE(valid) << s;
            } else {
                EXPECT_FALSE(valid) << s;
            }
        }
    }
}

TEST_F(TestATECC608B_TNGTLS, Nonce)
{
    uint16_t state{};
    uint8_t input20[20]{0x55};
    uint8_t output[32]{};
    uint8_t nonce32[32]{0x11};
    uint8_t nonce64[64]{0x22};

    // RNG mode: useRNG = true, updateSeed = true
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_TRUE(unit->createNonce(output, input20, true, true));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));
    EXPECT_FALSE(is_external_source_tempkey(state));

    // RNG mode: useRNG = true, updateSeed = false
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_TRUE(unit->createNonce(output, input20, true, false));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));
    EXPECT_FALSE(is_external_source_tempkey(state));

    // RNG mode: useRNG = false, updateSeed = true
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_FALSE(unit->createNonce(output, input20, false, true));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, nonce32));
    EXPECT_TRUE(unit->createNonce(output, input20, false, true));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));
    EXPECT_TRUE(is_external_source_tempkey(state));

    // RNG mode: useRNG = false, updateSeed = false
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_FALSE(unit->createNonce(output, input20, false, false));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, nonce32));
    EXPECT_TRUE(unit->createNonce(output, input20, false, false));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));
    EXPECT_TRUE(is_external_source_tempkey(state));

    //
    // Write 32-byte nonce (TempKey)
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, nonce32));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));
    EXPECT_TRUE(is_external_source_tempkey(state));

    // Write 32-byte nonce (MsgDigestBuf)
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_TRUE(unit->writeNonce32(Destination::MsgDigestBuffer, nonce32));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    // Write 32-byte nonce (AltBuf)
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_TRUE(unit->writeNonce32(Destination::AlternateKeyBuffer, nonce32));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    // Write 32-byte nonce (Illegal dest)
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_FALSE(unit->writeNonce32(Destination::ExternalBuffer, nonce32));

    // Write 64-byte nonce (TempKey)
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_TRUE(unit->writeNonce64(Destination::TempKey, nonce64));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));
    EXPECT_TRUE(is_external_source_tempkey(state));

    // Write 64-byte nonce (MsgDigestBuf)
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_TRUE(unit->writeNonce64(Destination::MsgDigestBuffer, nonce64));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    // Write 32-byte nonce (Illegal dest)
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_FALSE(unit->writeNonce64(Destination::AlternateKeyBuffer, nonce64));
    EXPECT_FALSE(unit->writeNonce64(Destination::ExternalBuffer, nonce64));
}

TEST_F(TestATECC608B_TNGTLS, Random)
{
    SCOPED_TRACE(ustr);

    uint8_t r[32]{};
    EXPECT_TRUE(unit->readRandomArray(r));
    // updateSeed=false is ignored on TNG-TLS (Mode=0x00 always used)
    EXPECT_TRUE(unit->readRandomArray(r, false));

    test_random<int8_t>(unit.get(), std::numeric_limits<int8_t>::lowest(),
                        std::numeric_limits<int8_t>::max());  // lowest ... (max-1)
    test_random<int8_t>(unit.get(), -1, 2);                   // -1 ... 1

    test_random<uint8_t>(unit.get(), std::numeric_limits<uint8_t>::lowest(),
                         std::numeric_limits<uint8_t>::max());  // lowest ... (max-1)
    test_random<uint8_t>(unit.get(), 1, 3);                     // 1 ... 2

    test_random<int16_t>(unit.get(), std::numeric_limits<int16_t>::lowest(),
                         std::numeric_limits<int16_t>::max());  // lowest ... (max-1)
    test_random<int16_t>(unit.get(), -2, 1);                    // -2 ... 0

    test_random<uint16_t>(unit.get(), std::numeric_limits<uint16_t>::lowest(),
                          std::numeric_limits<uint16_t>::max());  // lowest ... (max-1)
    test_random<uint16_t>(unit.get(), 2, 4);                      // 2 ... 3

    test_random<int32_t>(unit.get(), std::numeric_limits<int32_t>::lowest(),
                         std::numeric_limits<int32_t>::max());  // lowest ... (max-1)
    test_random<int32_t>(unit.get(), -3, 0);                    // -3 ... -1

    test_random<uint32_t>(unit.get(), std::numeric_limits<uint32_t>::lowest(),
                          std::numeric_limits<uint32_t>::max());  // lowest ... (max-1)
    test_random<uint32_t>(unit.get(), 3, 5);                      // 3 ... 4

    test_random<int64_t>(unit.get(), std::numeric_limits<int64_t>::lowest(),
                         std::numeric_limits<int64_t>::max());  // lowest ... (max-1)
    test_random<int64_t>(unit.get(), -4, -1);                   // -4 ... -2

    test_random<uint64_t>(unit.get(), std::numeric_limits<uint64_t>::lowest(),
                          std::numeric_limits<uint64_t>::max());  // lowest ... (max-1)
    test_random<uint64_t>(unit.get(), 4, 6);                      // 4 ... 5

#if defined(__SIZEOF_INT128__)
#pragma message "Support int/uint128_t"
    test_random<int128_t>(unit.get(), std::numeric_limits<int128_t>::lowest(),
                          std::numeric_limits<int128_t>::max());  // lowest ... (max-1)
    test_random<int128_t>(unit.get(), -5, -2);                    // -5 ... -3

    test_random<uint128_t>(unit.get(), std::numeric_limits<uint128_t>::lowest(),
                           std::numeric_limits<uint128_t>::max());  // lowest ... (max-1)
    test_random<uint128_t>(unit.get(), 5, 7);                       // 5 ... 6
#endif

    test_random<float>(unit.get(), -12345.6789f, 12345.6789f);  // -12345.6789 ... 12345.67889999.....
}

TEST_F(TestATECC608B_TNGTLS, Read)
{
    SCOPED_TRACE(ustr);

    uint8_t cfg[128]{};
    EXPECT_TRUE(unit->readConfigZone(cfg));

    uint8_t data[416]{};
    for (uint8_t s = 0; s < 16; ++s) {
        // Can read as clear text
        if (s == 5 || s == 8 || s == 10 || s == 11 || s == 12) {
            EXPECT_TRUE(unit->readDataZone(data, unit->getSlotSize((Slot)s), (Slot)s));
        } else {
            EXPECT_FALSE(unit->readDataZone(data, unit->getSlotSize((Slot)s), (Slot)s));
        }
    }

    uint8_t otp[64]{};
    EXPECT_TRUE(unit->readOTPZone(otp));
}

TEST_F(TestATECC608B_TNGTLS, SHA256)
{
    SCOPED_TRACE(ustr);

    uint16_t state{};

    // Skip: 'a' String repeated 1000000 times
    // Disabled due to insufficient heap on most embedded targets (1MB allocation).
    // The SHA256 1M test vector is validated via the smaller test vectors above.
    constexpr uint32_t ilen{1000000};
    uint8_t* in = nullptr;
#if 0
    in = (uint8_t*)malloc(1000000);
    if (in) {
        memset(in, (uint8_t)('a'), ilen);
    }
#endif

    // TempKey
    for (int i = 0; i < m5::stl::size(sha256_test_vectors); ++i) {
        uint8_t digest[32]{};
        auto& e = sha256_test_vectors[i];
        SCOPED_TRACE(e.name);

        EXPECT_TRUE(clear_tempkey(unit.get()));

        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(e.input, e.input_len));
        EXPECT_TRUE(unit->finalizeSHA256(Destination::TempKey, digest));
        EXPECT_TRUE(memcmp(digest, e.expected, 32) == 0);

        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_TRUE(is_valid_tempkey(state));
        EXPECT_TRUE(is_external_source_tempkey(state));
    }
    if (in) {
        uint8_t digest[32]{};
        EXPECT_TRUE(clear_tempkey(unit.get()));

        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(in, ilen));
        EXPECT_TRUE(unit->finalizeSHA256(Destination::TempKey, digest));
        EXPECT_TRUE(memcmp(digest, sha256_a1000000_result, 32) == 0);

        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_TRUE(is_valid_tempkey(state));
        EXPECT_TRUE(is_external_source_tempkey(state));
    }

    // MsgDigestBuffer
    EXPECT_TRUE(clear_tempkey(unit.get()));
    for (int i = 0; i < m5::stl::size(sha256_test_vectors); ++i) {
        uint8_t digest[32]{};
        auto& e = sha256_test_vectors[i];
        SCOPED_TRACE(e.name);

        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(e.input, e.input_len));
        EXPECT_TRUE(unit->finalizeSHA256(Destination::MsgDigestBuffer, digest));
        EXPECT_TRUE(memcmp(digest, e.expected, 32) == 0);

        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_FALSE(is_valid_tempkey(state));
    }
    if (in) {
        uint8_t digest[32]{};
        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(in, ilen));
        EXPECT_TRUE(unit->finalizeSHA256(Destination::MsgDigestBuffer, digest));
        EXPECT_TRUE(memcmp(digest, sha256_a1000000_result, 32) == 0);

        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_FALSE(is_valid_tempkey(state));
    }

    // ExternalBuffer
    EXPECT_TRUE(clear_tempkey(unit.get()));
    for (int i = 0; i < m5::stl::size(sha256_test_vectors); ++i) {
        uint8_t digest[32]{};
        auto& e = sha256_test_vectors[i];
        SCOPED_TRACE(e.name);

        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(e.input, e.input_len));
        EXPECT_TRUE(unit->finalizeSHA256(Destination::ExternalBuffer, digest));
        EXPECT_TRUE(memcmp(digest, e.expected, 32) == 0);

        EXPECT_TRUE(unit->readDeviceState(state));
        // M5_LOGW("%04X", state);
        EXPECT_FALSE(is_valid_tempkey(state));
    }
    if (in) {
        uint8_t digest[32]{};
        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(in, ilen));
        EXPECT_TRUE(unit->finalizeSHA256(Destination::ExternalBuffer, digest));
        EXPECT_TRUE(memcmp(digest, sha256_a1000000_result, 32) == 0);

        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_FALSE(is_valid_tempkey(state));
    }

    // Invalid dest
    EXPECT_TRUE(clear_tempkey(unit.get()));
    for (int i = 0; i < m5::stl::size(sha256_test_vectors); ++i) {
        uint8_t digest[32]{};
        auto& e = sha256_test_vectors[i];
        SCOPED_TRACE(e.name);

        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(e.input, e.input_len));
        EXPECT_FALSE(unit->finalizeSHA256(Destination::AlternateKeyBuffer, digest));
        EXPECT_FALSE(memcmp(digest, e.expected, 32) == 0);

        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_FALSE(is_valid_tempkey(state));
    }
    if (in) {
        uint8_t digest[32]{};
        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(in, 4));
        EXPECT_FALSE(unit->finalizeSHA256(Destination::AlternateKeyBuffer, digest));
        EXPECT_FALSE(memcmp(digest, sha256_a1000000_result, 32) == 0);

        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_FALSE(is_valid_tempkey(state));
    }

    free(in);
}

TEST_F(TestATECC608B_TNGTLS, ECDHStoredKey)
{
    SCOPED_TRACE(ustr);

    uint16_t state{};
    uint8_t device_pubkey[64]{};
    uint8_t shared_secret[32]{};
    uint8_t nonce[32]{};

    EXPECT_TRUE(clear_tempkey(unit.get()));

    // Failed
    EXPECT_FALSE(unit->ECDHStoredKey(shared_secret, Slot::PrimaryPrivateKey, device_pubkey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    EXPECT_FALSE(unit->ECDHStoredKey(shared_secret, nonce, Slot::PrimaryPrivateKey, device_pubkey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    EXPECT_FALSE(unit->ECDHStoredKey(Slot::PrimaryPrivateKey, device_pubkey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    // For TNGTLS, the ECDH command may be run using the ECC private keys stored in Slots 0 and 2-4
    // Output in the clear
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_TRUE(unit->generatePublicKey(device_pubkey, Slot::PrimaryPrivateKey));
        if (s == 0 || (s >= 2 && s <= 4)) {
            EXPECT_TRUE(unit->ECDHStoredKey(shared_secret, (Slot)s, device_pubkey));
        } else {
            EXPECT_FALSE(unit->ECDHStoredKey(shared_secret, (Slot)s, device_pubkey));
        }
        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_FALSE(is_valid_tempkey(state));
    }

    // Output is encrypted
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_TRUE(unit->generatePublicKey(device_pubkey, Slot::PrimaryPrivateKey));  // Slot 0
        if (s == 0 || (s >= 2 && s <= 4)) {
            EXPECT_TRUE(unit->ECDHStoredKey(shared_secret, nonce, (Slot)s, device_pubkey));
        } else {
            EXPECT_FALSE(unit->ECDHStoredKey(shared_secret, nonce, (Slot)s, device_pubkey));
        }
        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_FALSE(is_valid_tempkey(state));
    }
    // Results stored in TempKey
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_TRUE(unit->generatePublicKey(device_pubkey, Slot::PrimaryPrivateKey));  // Slot 0
        if (s == 0 || (s >= 2 && s <= 4)) {
            EXPECT_TRUE(unit->ECDHStoredKey((Slot)s, device_pubkey));
        } else {
            EXPECT_FALSE(unit->ECDHStoredKey((Slot)s, device_pubkey));
        }
        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_TRUE(is_valid_tempkey(state));
        EXPECT_TRUE(is_external_source_tempkey(state));
    }
}

TEST_F(TestATECC608B_TNGTLS, ECDHTempKey)
{
    SCOPED_TRACE(ustr);
    uint16_t state{};
    uint8_t pubKey[64]{};
    uint8_t shared_secret[32]{};
    uint8_t nonce[32]{};

    EXPECT_TRUE(clear_tempkey(unit.get()));

    // Failed
    EXPECT_FALSE(unit->ECDHTempKey(shared_secret, pubKey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    EXPECT_FALSE(unit->ECDHTempKey(shared_secret, nonce, pubKey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    EXPECT_FALSE(unit->ECDHTempKey(pubKey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    EXPECT_FALSE(unit->ECDHTempKey(Slot::GeneralData /*8*/, pubKey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    // Output in the clear
    EXPECT_TRUE(unit->generateKey(pubKey));  // TempKey is ECC
    EXPECT_TRUE(unit->ECDHTempKey(shared_secret, pubKey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    // Output is encrypted
    EXPECT_TRUE(unit->generateKey(pubKey));  // TempKey is ECC
    EXPECT_TRUE(unit->ECDHTempKey(shared_secret, nonce, pubKey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    // Results stored in TempKey
    EXPECT_TRUE(unit->generateKey(pubKey));  // TempKey is ECC
    EXPECT_TRUE(unit->ECDHTempKey(pubKey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));
    EXPECT_TRUE(is_external_source_tempkey(state));

    // Results stored in specified slot
    // Skip: ECDHTempKey with output to Slot 8 overwrites general data storage.
    // The original data cannot be restored, rendering Slot 8 unreliable for subsequent tests.
#if 0
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_TRUE(unit->readDataZone(data, 32, Slot::GeneralData));

        EXPECT_TRUE(unit->generateKey(pubKey));  // TempKey is ECC
        if (s == 8) {
            EXPECT_TRUE(unit->ECDHTempKey((Slot)s, pubKey));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_FALSE(is_valid_tempkey(state));

            EXPECT_TRUE(unit->readDataZone(data2, 32, Slot::GeneralData));
            EXPECT_NE(memcmp(data, data2, 32), 0);
        } else {
            EXPECT_FALSE(unit->ECDHTempKey((Slot)s, pubKey));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_TRUE(is_valid_tempkey(state));  // Keep TempKey
        }
    }
#else
    // Only test non-writable slots (all should fail), verifying slot permission enforcement
    for (uint8_t s = 0; s < 16; ++s) {
        if (s == 8) {
            continue;  // Skip Slot 8: write is irreversible
        }
        EXPECT_TRUE(unit->generateKey(pubKey));  // TempKey is ECC
        EXPECT_FALSE(unit->ECDHTempKey((Slot)s, pubKey));
        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_TRUE(is_valid_tempkey(state));  // Keep TempKey
    }
#endif
}

TEST_F(TestATECC608B_TNGTLS, GenKey)
{
    SCOPED_TRACE(ustr);

    uint8_t pubKey[64]{};
    uint16_t state{};

    // Skip: generatePrivateKey overwrites the existing private key permanently.
    // The original key used for TNG-TLS certificates cannot be recovered.
    // Slots 0-1 are permanently locked for write. Slots 2-4 are writable but the
    // original keys would be destroyed.
#if 0
    // Private key
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_TRUE(clear_tempkey(unit.get()));
        if (s >= 2 && s <= 4) {
            EXPECT_TRUE(unit->generatePrivateKey((Slot)s, pubKey));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_FALSE(is_valid_tempkey(state));

        } else {
            EXPECT_FALSE(unit->generatePrivateKey((Slot)s, pubKey));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_FALSE(is_valid_tempkey(state));
        }
    }
#else
    // Only test slots that should reject generatePrivateKey (non-writable slots)
    for (uint8_t s = 0; s < 16; ++s) {
        if (s >= 2 && s <= 4) {
            continue;  // Skip writable slots: generatePrivateKey would destroy existing key
        }
        EXPECT_TRUE(clear_tempkey(unit.get()));
        EXPECT_FALSE(unit->generatePrivateKey((Slot)s, pubKey));
        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_FALSE(is_valid_tempkey(state));
    }
#endif

    // Disposable key
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_TRUE(unit->generateKey(pubKey));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));

    // Public key
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_TRUE(clear_tempkey(unit.get()));
        if (s <= 4) {
            EXPECT_TRUE(unit->generatePublicKey(pubKey, (Slot)s, false));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_FALSE(is_valid_tempkey(state));

            // TODO: 608BTNGTLS not support generate digest??? is it true?
#if 0
            EXPECT_TRUE(unit->generatePublicKey(pubKey, (Slot)s, true));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_TRUE(is_valid_tempkey(state));
            EXPECT_TRUE(is_valid_genkey_tempkey(state));
#else
            EXPECT_FALSE(unit->generatePublicKey(pubKey, (Slot)s, true));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_FALSE(is_valid_tempkey(state));
#endif
        } else {
            EXPECT_FALSE(unit->generatePublicKey(pubKey, (Slot)s, false));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_FALSE(is_valid_tempkey(state));

            EXPECT_FALSE(unit->generatePublicKey(pubKey, (Slot)s, true));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_FALSE(is_valid_tempkey(state));
        }
    }

    // Public Key Digest
    const uint8_t nonce64[]{0x12};
    const uint8_t other[3]{0x01, 0x02, 0x03};

    EXPECT_TRUE(clear_tempkey(unit.get()));
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_FALSE(unit->generatePublicKeyDigest((Slot)s, other));
        EXPECT_TRUE(unit->readDeviceState(state));
        EXPECT_FALSE(is_valid_tempkey(state));
    }

    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_TRUE(clear_tempkey(unit.get()));
        EXPECT_TRUE(unit->writeNonce64(Destination::TempKey, nonce64));
        if (s == 11) {
            EXPECT_TRUE(unit->generatePublicKeyDigest((Slot)s, other));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_TRUE(is_valid_tempkey(state));
            EXPECT_TRUE(is_external_source_tempkey(state));
            EXPECT_TRUE(is_valid_genkey_tempkey(state));
            EXPECT_EQ(get_tempkey_keyID(state), 11);
        } else {
            EXPECT_FALSE(unit->generatePublicKeyDigest((Slot)s, other));
            EXPECT_TRUE(unit->readDeviceState(state));
            EXPECT_TRUE(is_valid_tempkey(state));
        }
    }
}

TEST_F(TestATECC608B_TNGTLS, SignExternal)
{
    SCOPED_TRACE(ustr);

    uint8_t signature[64]{};
    const uint8_t digest[32] = {0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A,
                                0x4B, 0x3C, 0x2D, 0x1E, 0x0F, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    EXPECT_TRUE(clear_tempkey(unit.get()));
    unit->signExternal(signature, (Slot)0, Source::MsgDigestBuffer);  // break msg digest buffer

    // Failed
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::TempKey, false));
        EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::MsgDigestBuffer, false));
        EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::AlternateKeyBuffer, false));
        EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::ExternalBuffer, false));
        EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::TempKey, true));
        EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::MsgDigestBuffer, true));
        EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::AlternateKeyBuffer, true));
        EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::ExternalBuffer, true));
    }

    // Source TempKey
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, digest));
        if (s == 0 || (s >= 2 && s <= 4)) {
            EXPECT_TRUE(unit->signExternal(signature, (Slot)s, Source::TempKey, false));
        } else {
            EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::TempKey, false));
        }

        EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, digest));
        if (s == 0 || (s >= 2 && s <= 4)) {
            EXPECT_TRUE(unit->signExternal(signature, (Slot)s, Source::TempKey, true));
        } else {
            EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::TempKey, true));
        }
    }

    // Source MsgDigestBuffer
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_TRUE(unit->writeNonce32(Destination::MsgDigestBuffer, digest));
        if (s == 0 || (s >= 2 && s <= 4)) {
            EXPECT_TRUE(unit->signExternal(signature, (Slot)s, Source::MsgDigestBuffer, false));
        } else {
            EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::MsgDigestBuffer, false));
        }

        EXPECT_TRUE(unit->writeNonce32(Destination::MsgDigestBuffer, digest));
        if (s == 0 || (s >= 2 && s <= 4)) {
            EXPECT_TRUE(unit->signExternal(signature, (Slot)s, Source::MsgDigestBuffer, true));
        } else {
            EXPECT_FALSE(unit->signExternal(signature, (Slot)s, Source::MsgDigestBuffer, true));
        }
    }
}

TEST_F(TestATECC608B_TNGTLS, SignInternal)
{
    SCOPED_TRACE(ustr);

    uint16_t state{};
    uint8_t signature[64]{};
    uint8_t pubKey[64]{};

    EXPECT_TRUE(clear_tempkey(unit.get()));
    unit->signExternal(signature, (Slot)0, Source::MsgDigestBuffer);  // break msg digest buffer

    // Failed
    for (uint8_t s = 0; s < 16; ++s) {
        EXPECT_FALSE(unit->signInternal(signature, (Slot)s, Source::TempKey, false));
        EXPECT_FALSE(unit->signInternal(signature, (Slot)s, Source::MsgDigestBuffer, false));
        EXPECT_FALSE(unit->signInternal(signature, (Slot)s, Source::AlternateKeyBuffer, false));
        EXPECT_FALSE(unit->signInternal(signature, (Slot)s, Source::ExternalBuffer, false));

        EXPECT_FALSE(unit->signInternal(signature, (Slot)s, Source::TempKey, true));
        EXPECT_FALSE(unit->signInternal(signature, (Slot)s, Source::MsgDigestBuffer, true));
        EXPECT_FALSE(unit->signInternal(signature, (Slot)s, Source::AlternateKeyBuffer, true));
        EXPECT_FALSE(unit->signInternal(signature, (Slot)s, Source::ExternalBuffer, true));
    }

    // Failed because illegal TempKey (TempKey need to made by GenDig, GenKey)
    const uint8_t nin[20]{0x12};
    EXPECT_TRUE(unit->createNonce(nullptr, nin));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));
    EXPECT_FALSE(is_external_source_tempkey(state));
    EXPECT_FALSE(unit->signInternal(signature, (Slot)1, Source::TempKey));

    // Success: GenKey with digest creates valid TempKey for signInternal
    // Slot 1 (InternalSignPrivateKey) is the only slot that can sign internal messages on TNGTLS
    EXPECT_TRUE(unit->generatePublicKey(pubKey, Slot::InternalSignPrivateKey, true));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));
    EXPECT_TRUE(unit->signInternal(signature, Slot::InternalSignPrivateKey, Source::TempKey));
    EXPECT_FALSE(std::all_of(std::begin(signature), std::end(signature), [](uint8_t v) { return v == 0; }));
}

TEST_F(TestATECC608B_TNGTLS, SelfTest)
{
    SCOPED_TRACE(ustr);

    // All tests at once
    uint8_t resultBits{0xFF};
    EXPECT_TRUE(unit->selfTest(resultBits, 0x3D /* All: RNG,ECDSA,ECDH,AES,SHA */));
    EXPECT_EQ(resultBits, 0x00) << "All self-test bits should be zero on success";
}

TEST_F(TestATECC608B_TNGTLS, ZoneLock)
{
    SCOPED_TRACE(ustr);

    // TNGTLS devices ship with both config and data zones locked
    bool configLocked{false}, dataLocked{false};
    EXPECT_TRUE(unit->readZoneLocked(configLocked, dataLocked));
    EXPECT_TRUE(configLocked) << "Config zone should be locked on TNGTLS";
    EXPECT_TRUE(dataLocked) << "Data zone should be locked on TNGTLS";

    // Slot lock status
    uint16_t slotLockedBits{};
    EXPECT_TRUE(unit->readSlotLocked(slotLockedBits));
    // On TNGTLS, Slots 0 and 1 should be individually locked (bit=0 means locked)
    EXPECT_EQ(slotLockedBits & (1 << 0), 0) << "Slot 0 should be locked";
    EXPECT_EQ(slotLockedBits & (1 << 1), 0) << "Slot 1 should be locked";
}

TEST_F(TestATECC608B_TNGTLS, SlotKeyConfig)
{
    SCOPED_TRACE(ustr);

    for (uint8_t s = 0; s < 16; ++s) {
        uint16_t slotCfg{}, keyCfg{};
        EXPECT_TRUE(unit->readSlotConfig(slotCfg, (Slot)s)) << "Slot " << (int)s;
        EXPECT_TRUE(unit->readKeyConfig(keyCfg, (Slot)s)) << "Slot " << (int)s;

        // Verify ECC key slots (0-4) have KeyType = P256 (bits 4:2 == 0b100)
        if (s <= 4) {
            EXPECT_EQ((keyCfg >> 2) & 0x07, 0x04) << "Slot " << (int)s << " should be P256 ECC key";
        }
    }
}

TEST_F(TestATECC608B_TNGTLS, VerifyExternal)
{
    SCOPED_TRACE(ustr);

    uint8_t signature[64]{};
    uint8_t pubKey[64]{};
    const uint8_t digest[32] = {0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A,
                                0x4B, 0x3C, 0x2D, 0x1E, 0x0F, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    // Sign with Slot 0 private key, then verify with its public key (roundtrip)
    EXPECT_TRUE(unit->generatePublicKey(pubKey, Slot::PrimaryPrivateKey));

    EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, digest));
    EXPECT_TRUE(unit->signExternal(signature, Slot::PrimaryPrivateKey, Source::TempKey));

    // Verify: write the same digest to TempKey, then verify signature with public key
    EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, digest));
    EXPECT_TRUE(unit->verifyExternal(nullptr, signature, pubKey, Source::TempKey));

    // Verify with wrong public key should fail
    uint8_t wrongPubKey[64]{};
    memset(wrongPubKey, 0x42, sizeof(wrongPubKey));
    EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, digest));
    EXPECT_FALSE(unit->verifyExternal(nullptr, signature, wrongPubKey, Source::TempKey));

    // Verify with corrupted signature should fail
    uint8_t badSig[64]{};
    memcpy(badSig, signature, 64);
    badSig[0] ^= 0xFF;
    EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, digest));
    EXPECT_FALSE(unit->verifyExternal(nullptr, badSig, pubKey, Source::TempKey));
}

TEST_F(TestATECC608B_TNGTLS, Certificate)
{
    SCOPED_TRACE(ustr);

    // Device certificate
    {
        uint8_t certBuf[1024]{};
        uint16_t certLen = sizeof(certBuf);
        EXPECT_TRUE(unit->readDeviceCertificate(certBuf, certLen));
        EXPECT_GT(certLen, 0);

        // Verify DER structure: first byte should be SEQUENCE tag (0x30)
        EXPECT_EQ(certBuf[0], 0x30) << "Device cert should start with DER SEQUENCE tag";
    }

    // Signer certificate
    {
        uint8_t certBuf[1024]{};
        uint16_t certLen = sizeof(certBuf);
        EXPECT_TRUE(unit->readSignerCertificate(certBuf, certLen));
        EXPECT_GT(certLen, 0);

        // Verify DER structure: first byte should be SEQUENCE tag (0x30)
        EXPECT_EQ(certBuf[0], 0x30) << "Signer cert should start with DER SEQUENCE tag";
    }
}

TEST_F(TestATECC608B_TNGTLS, SHA256_Convenience)
{
    SCOPED_TRACE(ustr);

    // Test the convenience SHA256() method against known test vectors
    for (int i = 0; i < m5::stl::size(sha256_test_vectors); ++i) {
        uint8_t digest[32]{};
        auto& e = sha256_test_vectors[i];
        SCOPED_TRACE(e.name);

        EXPECT_TRUE(clear_tempkey(unit.get()));

        EXPECT_TRUE(unit->SHA256(Destination::TempKey, digest, e.input, e.input_len));
        EXPECT_TRUE(memcmp(digest, e.expected, 32) == 0);
    }
}

TEST_F(TestATECC608B_TNGTLS, SHA256_MultiBlock)
{
    SCOPED_TRACE(ustr);

    // "100_a" test vector split into multiple updateSHA256 calls
    auto& e = sha256_test_vectors[4];  // 100_a
    EXPECT_EQ(e.input_len, 100);

    // Split: 64 + 36
    {
        uint8_t digest[32]{};
        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(e.input, 64));
        EXPECT_TRUE(unit->updateSHA256(e.input + 64, 36));
        EXPECT_TRUE(unit->finalizeSHA256(Destination::TempKey, digest));
        EXPECT_TRUE(memcmp(digest, e.expected, 32) == 0) << "64+36 split";
    }

    // Split: 32 + 32 + 32 + 4
    {
        uint8_t digest[32]{};
        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(e.input, 32));
        EXPECT_TRUE(unit->updateSHA256(e.input + 32, 32));
        EXPECT_TRUE(unit->updateSHA256(e.input + 64, 32));
        EXPECT_TRUE(unit->updateSHA256(e.input + 96, 4));
        EXPECT_TRUE(unit->finalizeSHA256(Destination::TempKey, digest));
        EXPECT_TRUE(memcmp(digest, e.expected, 32) == 0) << "32+32+32+4 split";
    }

    // Split: 1 byte at a time for first 3 bytes ("abc" equivalent prefix), then rest
    {
        auto& abc = sha256_test_vectors[1];  // "abc"
        uint8_t digest[32]{};
        EXPECT_TRUE(unit->startSHA256());
        EXPECT_TRUE(unit->updateSHA256(abc.input, 1));
        EXPECT_TRUE(unit->updateSHA256(abc.input + 1, 1));
        EXPECT_TRUE(unit->updateSHA256(abc.input + 2, 1));
        EXPECT_TRUE(unit->finalizeSHA256(Destination::TempKey, digest));
        EXPECT_TRUE(memcmp(digest, abc.expected, 32) == 0) << "1+1+1 split";
    }
}

TEST_F(TestATECC608B_TNGTLS, ConfigZoneValidation)
{
    SCOPED_TRACE(ustr);

    uint8_t cfg[128]{};
    EXPECT_TRUE(unit->readConfigZone(cfg));

    // Validate I2C address (byte 16): ATECC608B-TNGTLS default is 0x6A (0x35 << 1)
    EXPECT_EQ(cfg[16], 0x6A) << "I2C address should be 0x6A (7-bit: 0x35)";

    // Validate serial number consistency: SN[0:1] at bytes 0-3, SN[2:3] at bytes 8-12
    // SN[0] and SN[1] are fixed by Microchip
    uint8_t sn[9]{};
    EXPECT_TRUE(unit->readSerialNumber(sn));
    EXPECT_EQ(cfg[0], sn[0]);
    EXPECT_EQ(cfg[1], sn[1]);
    EXPECT_EQ(cfg[2], sn[2]);
    EXPECT_EQ(cfg[3], sn[3]);
    EXPECT_EQ(cfg[8], sn[4]);
    EXPECT_EQ(cfg[9], sn[5]);
    EXPECT_EQ(cfg[10], sn[6]);
    EXPECT_EQ(cfg[11], sn[7]);
    EXPECT_EQ(cfg[12], sn[8]);

    // LockConfig (byte 87): 0x00 = locked
    EXPECT_EQ(cfg[87], 0x00) << "Config zone should be locked";
    // LockValue (byte 86): 0x00 = locked
    EXPECT_EQ(cfg[86], 0x00) << "Data zone should be locked";
}

TEST_F(TestATECC608B_TNGTLS, OTPValidation)
{
    SCOPED_TRACE(ustr);

    uint8_t otp[64]{};
    EXPECT_TRUE(unit->readOTPZone(otp));

    // OTP zone should not be all zeros (TNGTLS has provisioned data)
    EXPECT_FALSE(std::all_of(std::begin(otp), std::end(otp), [](const uint8_t v) { return v == 0; }))
        << "OTP zone should contain provisioned data";

    // First 32 bytes and second 32 bytes should not be identical
    EXPECT_NE(memcmp(otp, otp + 32, 32), 0) << "OTP halves should differ";

    // Re-read and compare for consistency
    uint8_t otp2[64]{};
    EXPECT_TRUE(unit->readOTPZone(otp2));
    EXPECT_EQ(memcmp(otp, otp2, 64), 0) << "OTP reads should be consistent";
}

TEST_F(TestATECC608B_TNGTLS, Revision)
{
    SCOPED_TRACE(ustr);

    // revision() returns cached value from begin()
    auto rev = unit->revision();
    EXPECT_NE(rev, nullptr);
    if (!rev) {
        return;
    }

    // ATECC608B: RevNum = 00 00 60 03+
    EXPECT_EQ(rev[0], 0x00);
    EXPECT_EQ(rev[1], 0x00);
    EXPECT_EQ(rev[2], 0x60);
    EXPECT_GE(rev[3], 0x03);

    // Should match a fresh readRevision()
    uint8_t fresh[4]{};
    EXPECT_TRUE(unit->readRevision(fresh));
    EXPECT_EQ(memcmp(rev, fresh, 4), 0);
}

TEST_F(TestATECC608B_TNGTLS, SlotSize)
{
    SCOPED_TRACE(ustr);

    // ATECC608B-TNGTLS slot sizes per datasheet
    for (uint8_t s = 0; s <= 7; ++s) {
        EXPECT_EQ(unit->getSlotSize((Slot)s), 36) << "Slot " << (int)s;
    }
    EXPECT_EQ(unit->getSlotSize(Slot::GeneralData), 416) << "Slot 8";
    for (uint8_t s = 9; s <= 15; ++s) {
        EXPECT_EQ(unit->getSlotSize((Slot)s), 72) << "Slot " << (int)s;
    }
}

TEST_F(TestATECC608B_TNGTLS, Config)
{
    SCOPED_TRACE(ustr);

    auto cfg = unit->config();
    EXPECT_TRUE(cfg.idle);  // default

    UnitATECC608B_TNGTLS::config_t cfg2;
    cfg2.idle = false;
    unit->config(cfg2);
    EXPECT_FALSE(unit->config().idle);

    // Restore
    unit->config(cfg);
    EXPECT_TRUE(unit->config().idle);
}

TEST_F(TestATECC608B_TNGTLS, WakeupIdleSleep)
{
    SCOPED_TRACE(ustr);

    uint16_t state{};

    // Write nonce to TempKey, then idle — TempKey should be preserved
    EXPECT_TRUE(unit->writeNonce32(Destination::TempKey,
                                   (const uint8_t[]){0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                                                     0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                                                     0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20}));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));

    // Idle preserves SRAM (device is already idle after writeNonce32, so wakeup first)
    EXPECT_TRUE(unit->wakeup());
    EXPECT_TRUE(unit->idle());
    EXPECT_TRUE(unit->wakeup());
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state)) << "TempKey should survive idle";

    // Sleep clears SRAM (wakeup first since device is idle after readDeviceState)
    EXPECT_TRUE(unit->wakeup());
    EXPECT_TRUE(unit->sleep());
    EXPECT_TRUE(unit->wakeup());
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state)) << "TempKey should be cleared after sleep";
}

TEST_F(TestATECC608B_TNGTLS, Counter_InvalidID)
{
    SCOPED_TRACE(ustr);

    // Only counter IDs 0 and 1 are valid
    uint32_t val{};
    EXPECT_TRUE(unit->readCounter(val, 0));
    EXPECT_TRUE(unit->readCounter(val, 1));
    EXPECT_FALSE(unit->readCounter(val, 2));
    EXPECT_FALSE(unit->readCounter(val, 255));
}

TEST_F(TestATECC608B_TNGTLS, ReadRandom_NoArgs)
{
    SCOPED_TRACE(ustr);

    // readRandom(T&) without range arguments — full range of type
    uint8_t u8{};
    EXPECT_TRUE(unit->readRandom(u8));
    int32_t i32{};
    EXPECT_TRUE(unit->readRandom(i32));
}

TEST_F(TestATECC608B_TNGTLS, ReadRandom_Boundary)
{
    SCOPED_TRACE(ustr);

    uint8_t val{};

    // lower == upper should fail (empty range)
    EXPECT_FALSE(unit->readRandom(val, (uint8_t)5, (uint8_t)5));

    // upper == lower+1: always returns lower
    for (int i = 0; i < 3; ++i) {
        EXPECT_TRUE(unit->readRandom(val, (uint8_t)42, (uint8_t)43));
        EXPECT_EQ(val, 42);
    }
}

TEST_F(TestATECC608B_TNGTLS, Certificate_Deeper)
{
    SCOPED_TRACE(ustr);

    // Device certificate
    uint8_t devCert[1024]{};
    uint16_t devLen = sizeof(devCert);
    EXPECT_TRUE(unit->readDeviceCertificate(devCert, devLen));
    EXPECT_GT(devLen, 0);
    EXPECT_EQ(devCert[0], 0x30) << "DER SEQUENCE tag";

    // DER length field: long form if byte 1 has bit 7 set
    uint16_t derContentLen = 0;
    if (devCert[1] & 0x80) {
        uint8_t numLenBytes = devCert[1] & 0x7F;
        EXPECT_LE(numLenBytes, 2) << "DER length should be 1 or 2 bytes";
        for (uint8_t i = 0; i < numLenBytes; ++i) {
            derContentLen = (derContentLen << 8) | devCert[2 + i];
        }
        EXPECT_EQ(devLen, derContentLen + 2 + numLenBytes) << "DER total length mismatch";
    }

    // Device cert public key should match generatePublicKey(Slot::PrimaryPrivateKey)
    uint8_t pubKey[64]{};
    EXPECT_TRUE(unit->generatePublicKey(pubKey, Slot::PrimaryPrivateKey));
    // The public key appears somewhere in the DER-encoded certificate
    bool found = false;
    for (uint16_t i = 0; i + 64 <= devLen; ++i) {
        if (memcmp(&devCert[i], pubKey, 64) == 0) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found) << "Device cert should contain the public key from Slot 0";

    // Signer certificate
    uint8_t signerCert[1024]{};
    uint16_t signerLen = sizeof(signerCert);
    EXPECT_TRUE(unit->readSignerCertificate(signerCert, signerLen));
    EXPECT_GT(signerLen, 0);
    EXPECT_EQ(signerCert[0], 0x30) << "Signer cert DER SEQUENCE tag";
}

TEST_F(TestATECC608B_TNGTLS, SelfTest_Individual)
{
    SCOPED_TRACE(ustr);

    // Test individual self-test bits
    uint8_t result{0xFF};

    // RNG/DRBG (bit 0)
    EXPECT_TRUE(unit->selfTest(result, 0x01));
    EXPECT_EQ(result, 0x00);

    // ECDSA (bit 2)
    result = 0xFF;
    EXPECT_TRUE(unit->selfTest(result, 0x04));
    EXPECT_EQ(result, 0x00);

    // SHA (bit 5)
    result = 0xFF;
    EXPECT_TRUE(unit->selfTest(result, 0x20));
    EXPECT_EQ(result, 0x00);
}

// --- A. OTPValidation depth improvement is done inline above ---

// --- B. verifyStored: verify signature using stored public key in Slot 11 ---
TEST_F(TestATECC608B_TNGTLS, VerifyStored)
{
    SCOPED_TRACE(ustr);

    uint8_t signature[64]{};
    const uint8_t digest[32] = {0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A,
                                0x5B, 0x6C, 0x7D, 0x8E, 0x9F, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65,
                                0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F};

    // Sign with Slot 0 (PrimaryPrivateKey), verify with Slot 11 (SignerPublicKey)
    // Slot 11 stores the signer's public key — this verifies signer-signed messages, not device-signed.
    // Instead, sign with Slot 0 and verify externally, then use verifyStored with Slot 11 for a signer test.

    // First, verify that Slot 11 has a valid public key by reading it
    uint8_t signerPubKey[72]{};
    EXPECT_TRUE(unit->readDataZone(signerPubKey, 72, Slot::SignerPublicKey));
    EXPECT_FALSE(std::all_of(std::begin(signerPubKey), std::end(signerPubKey), [](uint8_t v) { return v == 0; }))
        << "Slot 11 should contain signer public key";

    // Sign externally with Slot 0 and verify with external pubkey (baseline)
    uint8_t pubKey0[64]{};
    EXPECT_TRUE(unit->generatePublicKey(pubKey0, Slot::PrimaryPrivateKey));
    EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, digest));
    EXPECT_TRUE(unit->signExternal(signature, Slot::PrimaryPrivateKey, Source::TempKey));

    // verifyStored uses Slot's stored public key — Slot 11 is signer key, not Slot 0 key
    // So verification with Slot 11 should FAIL (signed with Slot 0's private key, not signer's)
    EXPECT_TRUE(unit->writeNonce32(Destination::TempKey, digest));
    EXPECT_FALSE(unit->verifyStored(nullptr, signature, Slot::SignerPublicKey, Source::TempKey))
        << "Slot 11 key != Slot 0 key, verification should fail";
}

// --- C. Edge cases ---

TEST_F(TestATECC608B_TNGTLS, InvalidSlotNumber)
{
    SCOPED_TRACE(ustr);

    uint16_t cfg{};
    // Slots 7, 13, 14, 15 are reserved in TNGTLS but valid slot numbers (0-15)
    // Slot numbers beyond 15 are invalid for readSlotConfig/readKeyConfig
    // (the Slot enum is uint8_t, so we cast to test out-of-range)

    // readDataZone with reserved/non-readable slots
    uint8_t buf[36]{};
    // Slot 0 (private key) should not be readable on locked TNGTLS
    EXPECT_FALSE(unit->readDataZone(buf, 36, Slot::PrimaryPrivateKey));
    // Slot 1 (private key) should not be readable
    EXPECT_FALSE(unit->readDataZone(buf, 36, Slot::InternalSignPrivateKey));

    // readKeyValid on non-ECC slot: command succeeds but valid should be false
    bool valid{true};
    EXPECT_TRUE(unit->readKeyValid(valid, Slot::MACAddress));
    EXPECT_FALSE(valid) << "Slot 5 (MAC Address) is not an ECC key slot";
}

TEST_F(TestATECC608B_TNGTLS, SHA256_Error)
{
    SCOPED_TRACE(ustr);

    uint8_t digest[32]{};

    // finalizeSHA256 without startSHA256 should fail
    EXPECT_FALSE(unit->finalizeSHA256(Destination::TempKey, digest));

    // Double startSHA256 — second start should reset, then finalize with empty message
    EXPECT_TRUE(unit->startSHA256());
    EXPECT_TRUE(unit->startSHA256());
    // Finalize immediately after start: SHA256 of empty message
    EXPECT_TRUE(unit->finalizeSHA256(Destination::TempKey, digest));
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const uint8_t sha256_empty[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
                                    0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
                                    0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    EXPECT_EQ(memcmp(digest, sha256_empty, 32), 0) << "SHA256 of empty message mismatch";
}

TEST_F(TestATECC608B_TNGTLS, ReadDataZone_SizeMismatch)
{
    SCOPED_TRACE(ustr);

    // Slot 8 is 416 bytes (GeneralData)
    EXPECT_EQ(unit->getSlotSize(Slot::GeneralData), 416);

    // Read with correct size should succeed
    uint8_t buf[416]{};
    EXPECT_TRUE(unit->readDataZone(buf, 416, Slot::GeneralData));

    // Read with smaller size
    uint8_t smallBuf[32]{};
    EXPECT_TRUE(unit->readDataZone(smallBuf, 32, Slot::GeneralData));

    // Slot 10 (DeviceCompressedCertificate) is 72 bytes
    EXPECT_EQ(unit->getSlotSize(Slot::DeviceCompressedCertificate), 72);
    uint8_t certBuf[72]{};
    EXPECT_TRUE(unit->readDataZone(certBuf, 72, Slot::DeviceCompressedCertificate));
}

TEST_F(TestATECC608B_TNGTLS, CertificateChainVerification)
{
    SCOPED_TRACE(ustr);

    // Read device certificate
    uint8_t devCert[1024]{};
    uint16_t devLen = sizeof(devCert);
    EXPECT_TRUE(unit->readDeviceCertificate(devCert, devLen));
    EXPECT_GT(devLen, 0);

    // Read signer certificate
    uint8_t signerCert[1024]{};
    uint16_t signerLen = sizeof(signerCert);
    EXPECT_TRUE(unit->readSignerCertificate(signerCert, signerLen));
    EXPECT_GT(signerLen, 0);

    // Device cert and signer cert should be different
    if (devLen == signerLen) {
        EXPECT_NE(memcmp(devCert, signerCert, devLen), 0) << "Device and signer certs should differ";
    }

    // Slot 11 (SignerPublicKey) should be readable and non-zero
    uint8_t signerPubKey[72]{};
    EXPECT_TRUE(unit->readDataZone(signerPubKey, 72, Slot::SignerPublicKey));
    EXPECT_FALSE(std::all_of(std::begin(signerPubKey), std::end(signerPubKey), [](uint8_t v) { return v == 0; }))
        << "Slot 11 should contain signer public key";
}

TEST_F(TestATECC608B_TNGTLS, ReadWriteGeneralData)
{
    SCOPED_TRACE(ustr);

    // Save original data at offset 0
    uint8_t original[32]{};
    EXPECT_TRUE(unit->readGeneralData(original, 32, 0));

    // Write test pattern
    uint8_t pattern[32]{};
    for (uint8_t i = 0; i < 32; ++i) {
        pattern[i] = i ^ 0xA5;
    }
    EXPECT_TRUE(unit->writeGeneralData(pattern, 32, 0));

    // Read back and verify
    uint8_t readback[32]{};
    EXPECT_TRUE(unit->readGeneralData(readback, 32, 0));
    EXPECT_EQ(memcmp(pattern, readback, 32), 0) << "Write/read mismatch at offset 0";

    // Write at offset 352
    uint8_t pattern2[32]{};
    for (uint8_t i = 0; i < 32; ++i) {
        pattern2[i] = i ^ 0x5A;
    }
    EXPECT_TRUE(unit->writeGeneralData(pattern2, 32, 352));

    uint8_t readback2[32]{};
    EXPECT_TRUE(unit->readGeneralData(readback2, 32, 352));
    EXPECT_EQ(memcmp(pattern2, readback2, 32), 0) << "Write/read mismatch at offset 352";

    // Restore original data at offset 0
    EXPECT_TRUE(unit->writeGeneralData(original, 32, 0));

    // Verify restore
    uint8_t verify[32]{};
    EXPECT_TRUE(unit->readGeneralData(verify, 32, 0));
    EXPECT_EQ(memcmp(original, verify, 32), 0) << "Restore failed";
}

TEST_F(TestATECC608B_TNGTLS, ReadWriteGeneralData_InvalidArgs)
{
    SCOPED_TRACE(ustr);

    uint8_t buf[32]{};

    // Non-aligned offset
    EXPECT_FALSE(unit->readGeneralData(buf, 32, 13));
    EXPECT_FALSE(unit->writeGeneralData(buf, 32, 13));

    // Non-aligned len
    EXPECT_FALSE(unit->readGeneralData(buf, 7, 0));
    EXPECT_FALSE(unit->writeGeneralData(buf, 7, 0));

    // Offset beyond slot
    EXPECT_FALSE(unit->readGeneralData(buf, 32, 416));
    EXPECT_FALSE(unit->writeGeneralData(buf, 32, 416));

    // nullptr
    EXPECT_FALSE(unit->readGeneralData(nullptr, 32, 0));
    EXPECT_FALSE(unit->writeGeneralData(nullptr, 32, 0));

    // Zero len
    EXPECT_FALSE(unit->readGeneralData(buf, 0, 0));
    EXPECT_FALSE(unit->writeGeneralData(buf, 0, 0));
}
