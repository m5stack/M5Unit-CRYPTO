/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  UnitTest for UnitATECC608B_TNGTLS
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
#include <random>

using namespace m5::unit::googletest;
using namespace m5::unit;
using namespace m5::unit::atecc608;
using m5::unit::types::elapsed_time_t;

const ::testing::Environment* global_fixture = ::testing::AddGlobalTestEnvironment(new GlobalFixture<100000U>());

class TestATECC608B_TNGTLS : public ComponentTestBase<UnitATECC608B_TNGTLS, bool> {
protected:
    virtual UnitATECC608B_TNGTLS* get_instance() override
    {
        auto ptr = new m5::unit::UnitATECC608B_TNGTLS();
        return ptr;
    }
    virtual bool is_using_hal() const override
    {
        return GetParam();
    };
};

// INSTANTIATE_TEST_SUITE_P(ParamValues, TestATECC608B_TNGTLS, ::testing::Values(false, true));
// INSTANTIATE_TEST_SUITE_P(ParamValues, TestATECC608B_TNGTLS, ::testing::Values(true));
INSTANTIATE_TEST_SUITE_P(ParamValues, TestATECC608B_TNGTLS, ::testing::Values(false));

namespace {

auto rng = std::default_random_engine{};

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
}  // namespace

#if 0
TEST_P(TestATECC608B_TNGTLS, serialNumber)
{
    SCOPED_TRACE(ustr);

    uint8_t sn[9]{};
    EXPECT_TRUE(unit->readSerialNumber(sn));
    EXPECT_FALSE(std::all_of(std::begin(sn), std::end(sn), [](const uint8_t v) { return v == 0; }));

    char sns[19]{};
    EXPECT_TRUE(unit->readSerialNumber(sns));
    EXPECT_TRUE(is_equal_hex_string(sns, sn, sizeof(sn)));
}

TEST_P(TestATECC608B_TNGTLS, Counter)
{
    SCOPED_TRACE(ustr);

    uint32_t org0{}, org1{};

    EXPECT_TRUE(unit->readCounter(org0, 0));
    EXPECT_TRUE(unit->readCounter(org1, 1));

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
}

TEST_P(TestATECC608B_TNGTLS, Info)
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
#endif

#if 0
TEST_P(TestATECC608B_TNGTLS, Nonce)
{
    uint16_t state{};
    uint8_t input20[20]{0x55};
    uint8_t output[32]{};
    uint8_t nonce32[32]{0x11};
    uint8_t nonce64[64]{0x22};

    //    clear_tempkey(unit.get());
    //    EXPECT_TRUE(unit->readDeviceState(state));
    //    M5_LOGW("1S:%04X", state);

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

    // RNG mode: useRNG = false, updateSeed = true
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

    // Write 64-byte nonce (MsgDigestBuf))
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_TRUE(unit->writeNonce64(Destination::MsgDigestBuffer, nonce64));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_FALSE(is_valid_tempkey(state));

    // Write 32-byte nonce (Illegal dest)
    EXPECT_TRUE(clear_tempkey(unit.get()));
    EXPECT_FALSE(unit->writeNonce64(Destination::AlternateKeyBuffer, nonce64));
    EXPECT_FALSE(unit->writeNonce64(Destination::ExternalBuffer, nonce64));
}

namespace {
template <typename T, typename U>
void test_random(UnitATECC608B_TNGTLS* u, const U l, const U h)
{
    const T lower  = static_cast<T>(l);
    const T higher = static_cast<T>(h);

    uint32_t count{100};
    std::vector<T> result;

    while (count--) {
        T value{};
        EXPECT_TRUE(u->readRandom(value, lower, higher));  // [lower ... higher)

        EXPECT_LT(value, higher);
        EXPECT_GE(value, lower);
        result.push_back(value);
    }
    EXPECT_EQ(result.size(), 100);
    EXPECT_FALSE(std::all_of(result.cbegin() + 1, result.cend(), [&result](const uint8_t v) { return v == result[0]; }))
        << "low:" << l << " high:" << h;
}

template <typename T, typename U>
void test_random_float(UnitATECC608B_TNGTLS* u, const U l, const U h)
{
    const T lower  = static_cast<T>(l);
    const T higher = static_cast<T>(h);

    uint32_t count{100};
    std::vector<T> result;

    while (count--) {
        T value{};
        EXPECT_TRUE(u->readRandom(value, lower, higher));  // [lower ... higher)

        EXPECT_TRUE(value < higher) << "actual=" << value << ", expected=" << higher;
        EXPECT_TRUE(value >= lower) << "actual=" << value << ", expected=" << higher;
        result.push_back(value);
    }
    EXPECT_EQ(result.size(), 100);
    EXPECT_FALSE(std::all_of(result.cbegin() + 1, result.cend(), [&result](const uint8_t v) { return v == result[0]; }))
        << "low:" << l << " high:" << h;
}

}  // namespace

TEST_P(TestATECC608B_TNGTLS, Random)
{
    SCOPED_TRACE(ustr);

    uint8_t r[32]{};
    EXPECT_TRUE(unit->readRandomArray(r));

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

TEST_P(TestATECC608B_TNGTLS, Read)
{
    SCOPED_TRACE(ustr);

    uint8_t cfg[128]{};
    EXPECT_TRUE(unit->readConfigZone(cfg));

    uint8_t data[416]{};
    for (uint8_t s = 0; s < 16; ++s) {
        // Can read as clear text
        if (s==5 || s == 8 || s == 10 || s == 11 || s == 12) {
            EXPECT_TRUE(unit->readDataZone(data, unit->getSlotSize((Slot)s), (Slot)s));
        } else {
            EXPECT_FALSE(unit->readDataZone(data, unit->getSlotSize((Slot)s), (Slot)s));
        }
    }

    uint8_t otp[64]{};
    EXPECT_TRUE(unit->readOTPZone(otp));
}

TEST_P(TestATECC608B_TNGTLS, SHA256)
{
    SCOPED_TRACE(ustr);

    uint16_t state{};

    // 'a' String repeated 1000000 times
   constexpr uint32_t ilen{1000000};
    //    uint8_t* in = (uint8_t*)malloc(1000000);
    uint8_t* in = nullptr;
    if (in) {
        memset(in, (uint8_t)('a'), ilen);
    }

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
#endif

#if 0
TEST_P(TestATECC608B_TNGTLS, ECDH)
{
    SCOPED_TRACE(ustr);

    // Make private key at TempKey
    uint8_t pubKey[64]{};
    EXPECT_TRUE(unit->generateKey(pubKey);

    // 2. ソフトウェア側で鍵ペア作成（OpenSSLや mbedTLS を使うが今回は固定ベクター）
    const uint8_t software_privkey[32] = {
        0xC5, 0xAA, 0x8D, 0x6A, 0x58, 0x3E, 0xE6, 0xCD,
        0xB4, 0x64, 0x05, 0x69, 0x8C, 0xF1, 0x6B, 0x07,
        0x60, 0x19, 0x9C, 0x17, 0x6D, 0x46, 0xA0, 0x8F,
        0x77, 0xD7, 0x04, 0x2F, 0x7C, 0x43, 0x76, 0x30,
    };
    const uint8_t software_pubkey[64] = {
        0x04,
        0x3A, 0xD0, 0xFD, 0xF2, 0x8D, 0x73, 0x5A, 0x7B,
        0x8F, 0x62, 0xB0, 0xF5, 0xE7, 0x3B, 0xCE, 0x44,
        0xD3, 0x3E, 0xC2, 0x60, 0x30, 0xF7, 0x9C, 0x45,
        0x2A, 0x3A, 0x90, 0x13, 0xD3, 0x41, 0x7E, 0x19,
        0xF8, 0xB0, 0x68, 0x70, 0xDE, 0xA4, 0x02, 0x03,
        0xD5, 0x67, 0x8A, 0x16, 0x7F, 0x9D, 0x0E, 0x5F,
        0x5B, 0x35, 0xAD, 0x69, 0x65, 0x6C, 0x26, 0x60,
        0x62, 0x30, 0x67, 0x26, 0x8B, 0x89, 0xE7, 0xAF
    };

    // 3. ATECC608B による ECDH
    uint8_t shared_secret_atecc[32]{};
    ASSERT_TRUE(atecc.ecdh(shared_secret_atecc, Slot::PrimaryPrivateKey, software_pubkey));

    // 4. ソフト側でも同じ shared secret を生成（例：mbedTLSなどを想定、ここでは固定ベクターとの一致確認）
    const uint8_t expected_shared[32] = {
        0x6A, 0x27, 0x2B, 0x4F, 0x12, 0xC2, 0x88, 0xB3,
        0x68, 0xA3, 0x2D, 0xD2, 0xFC, 0xD3, 0x66, 0x6A,
        0x96, 0x6D, 0x69, 0x0C, 0x7C, 0xE9, 0xD6, 0x0A,
        0x48, 0xAB, 0x4D, 0xA4, 0x23, 0xB3, 0xB5, 0x44,
    };

    EXPECT_EQ(memcmp(shared_secret_atecc, expected_shared, 32), 0) << "ECDH output mismatch!";
}
#endif

#if 0
typedef struct {
    const char* name;
    const uint8_t private_key[32];
    const uint8_t public_key_x[32];
    const uint8_t public_key_y[32];
    const uint8_t expected_shared_secret[32];
} ECDHTestVector;

const ECDHTestVector ecdh_test_vectors[] = {
    {"secp256r1 test vector 1",
     {0x38, 0xf6, 0x5d, 0x6d, 0xce, 0x47, 0x67, 0x60, 0x44, 0xd5, 0x8c, 0xe5, 0x13, 0x95, 0x82, 0xd5,
      0x68, 0xf6, 0x4b, 0xb1, 0x60, 0x98, 0xd1, 0x79, 0xdb, 0xab, 0x07, 0x74, 0x1d, 0xd5, 0xca, 0xf5},
     {0x80, 0x9f, 0x04, 0x28, 0x9c, 0x64, 0x34, 0x8c, 0x01, 0x51, 0x5e, 0xb0, 0x3d, 0x5c, 0xe7, 0xac,
      0x1a, 0x8c, 0xb9, 0x49, 0x8f, 0x5c, 0xaa, 0x50, 0x19, 0x7e, 0x58, 0xd4, 0x3a, 0x86, 0xa7, 0xae},
     {0xb2, 0x9d, 0x84, 0xe8, 0x11, 0x19, 0x7f, 0x25, 0xeb, 0xa8, 0xf5, 0x19, 0x40, 0x92, 0xcb, 0x6f,
      0xf4, 0x40, 0xe2, 0x6d, 0x44, 0x21, 0x01, 0x13, 0x72, 0x46, 0x1f, 0x57, 0x92, 0x71, 0xcd, 0xa3},
     {0x05, 0x7d, 0x63, 0x60, 0x96, 0xcb, 0x80, 0xb6, 0x7a, 0x8c, 0x03, 0x8c, 0x89, 0x0e, 0x88, 0x7d,
      0x1a, 0xdf, 0xa4, 0x19, 0x5e, 0x9b, 0x3c, 0xe2, 0x41, 0xc8, 0xa7, 0x78, 0xc5, 0x9c, 0xda, 0x67}}
    // 他のベクターも同様に追加可能
};

TEST_P(TestATECC608B_TNGTLS, ECDH)
{
    auto& e = ecdh_test_vectors[0];

    // 公開鍵の組み立て（x || y）
    uint8_t pubkey[64];
    memcpy(pubkey, e.public_key_x, 32);
    memcpy(pubkey + 32, e.public_key_y, 32);

    // TempKey に秘密鍵をセット
    uint8_t key64[64]{};
    memcpy(key64, e.private_key, 32);
    EXPECT_TRUE(unit->writeNonce64(Destination::TempKey, key64));

    // ECDH 実行
    uint8_t out[32]{};
    EXPECT_TRUE(unit->ECDHTempKey(out, pubkey));

    // 結果照合
    EXPECT_EQ(memcmp(out, e.expected_shared_secret, 32), 0) << e.name;
}


TEST_P(TestATECC608B_TNGTLS, ECDH)
{
    SCOPED_TRACE(ustr);

    // StoredKey
    uint8_t device_pubkey[64]{};
    EXPECT_TRUE(unit->generateKey(device_pubkey, Slot::PrimaryPrivateKey));  // Slot 0

    uint8_t shared_secret[32]{};
    EXPECT_TRUE(atecc.ECDHStoredKey(shared_secret, device_pubkey, Slot::PrimaryPrivateKey));
    //    EXPECT_NE(shared_secret[0], 0);  // dummy check

    // TempKey
    uint8_t private_key[32]{};
    ASSERT_TRUE(unit->readRandomArray(private_key));  // ランダムな秘密鍵（仮）
    writeDataZone(8, private_key);
    uint8_t pubkey[64]{};
    ASSERT_TRUE(SHA256::generatePublicKey(pubkey, slot8);  // 外部で公開鍵を生成（ソフト）

    // TempKey に秘密鍵を渡す（64バイト: priv || zero）
    uint8_t key_buf[64]{};
    memcpy(key_buf, private_key, 32);
    ASSERT_TRUE(atecc.writeNonce64(Destination::TempKey, key_buf));

    uint8_t shared_secret[32]{};
    ASSERT_TRUE(atecc.ECDHTempKey(shared_secret, pubkey));
    EXPECT_NE(shared_secret[0], 0);
}


TEST_P(TestATECC608B_TNGTLS, ECDHStoredKey)
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

TEST_P(TestATECC608B_TNGTLS, ECDHTempKey)
{
    SCOPED_TRACE(ustr);
    uint16_t state{};
    uint8_t pubKey[64]{};
    uint8_t shared_secret[32]{};
    uint8_t nonce[32]{};
    uint8_t data[32]{}, data2[32]{};

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
}


TEST_P(TestATECC608B_TNGTLS, GenKey)
{
    SCOPED_TRACE(ustr);

    uint8_t pubKey[64]{};
    uint16_t state{};

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

TEST_P(TestATECC608B_TNGTLS, SignExternal)
{
    SCOPED_TRACE(ustr);

    uint16_t state{};
    uint8_t signature[32]{};
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
#endif

TEST_P(TestATECC608B_TNGTLS, SignInternal)
{
    SCOPED_TRACE(ustr);

    uint16_t state{};
    uint8_t signature[32]{};
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

    // Failed because illegal TempKey (TempKey need to made by GenDlg, GenKey)
    const uint8_t nin[2]{};
    EXPECT_TRUE(unit->createNonce(nullptr, nin));
    EXPECT_TRUE(unit->readDeviceState(state));
    EXPECT_TRUE(is_valid_tempkey(state));
    EXPECT_FALSE(is_external_source_tempkey(state));
    EXPECT_FALSE(unit->signInternal(signature, (Slot)1, Source::TempKey));

#if 0    
    // Source TempKey
    for (uint8_t s = 1; s < 2; ++s) {
        M5_LOGW(">>>> %u", s);

        //        EXPECT_TRUE(unit->generatePublicKeyDigest(Slot::SignerPublicKey));
        EXPECT_TRUE(unit->generateKey(pubKey));
        if (s == 1) {
            EXPECT_TRUE(unit->signInternal(signature, (Slot)s, Source::TempKey, false));
        } else {
            EXPECT_FALSE(unit->signInternal(signature, (Slot)s, Source::TempKey, false));
        }

#if 0        
        M5_LOGI("----");

        EXPECT_TRUE(unit->generatePublicKeyDigest(Slot::SignerPublicKey));
        if (s == 1) {
            EXPECT_TRUE(unit->signInternal(signature, (Slot)s, Source::TempKey, true));
        } else {
            EXPECT_FALSE(unit->signInternal(signature, (Slot)s, Source::TempKey, true));
        }
#endif
        M5_LOGW("<<<<");
    }
#endif
    // Source MsgDigestBuffer
}
