/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example using M5UnitUnified for UnitID
*/
#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedCRYPTO.h>
#include <M5Utility.h>

// Enable this define when using M5Core2AWS's built-in chip
#if !defined(USING_M5CORE2_AWS_BUILTIN)
// #define USING_M5CORE2_AWS_BUILTIN
#endif

using namespace m5::unit::atecc608;

namespace {
auto& lcd = M5.Display;
m5::unit::UnitUnified Units;
m5::unit::UnitID unit;

void dump_line(const char* label, const uint8_t* c, const size_t len)
{
    M5.Log.printf("%-12s", label);
    for (size_t i = 0; i < len; ++i) {
        M5.Log.printf("%02X%s", c[i], (i + 1 == len) ? "" : ":");
    }
    M5.Log.printf("\n");
}

void dump_config(const uint8_t c[128])
{
    uint_fast16_t idx{};

    dump_line("SN[0:3]", &c[idx], 4);
    idx += 4;
    dump_line("RevNum", &c[idx], 4);
    idx += 4;
    dump_line("SN[4:8]", &c[idx], 5);
    idx += 5;
    dump_line("AES_Enable", &c[idx], 1);
    idx += 1;
    dump_line("I2C_Enable", &c[idx], 1);
    idx += 1;
    dump_line("Reserved", &c[idx], 1);
    idx += 1;
    dump_line("I2C addr", &c[idx], 1);
    idx += 1;
    dump_line("Reserved", &c[idx], 1);
    idx += 1;
    dump_line("CntMatch", &c[idx], 1);
    idx += 1;
    dump_line("ChipMode", &c[idx], 1);
    idx += 1;

    for (int i = 0; i < 16; ++i) {
        char label[16];
        snprintf(label, sizeof(label), "SlotCfg[%d]", i);
        dump_line(label, &c[idx], 2);
        idx += 2;
    }

    dump_line("Cnt[0]", &c[idx], 8);
    idx += 8;
    dump_line("Cnt[1]", &c[idx], 8);
    idx += 8;
    dump_line("UseLock", &c[idx], 1);
    idx += 1;
    dump_line("VKPerm", &c[idx], 1);
    idx += 1;
    dump_line("SecureBoot", &c[idx], 2);
    idx += 2;
    dump_line("KdfIvLoc", &c[idx], 1);
    idx += 1;
    dump_line("KdfIvStr", &c[idx], 2);
    idx += 2;
    dump_line("Reserved", &c[idx], 9);
    idx += 9;
    dump_line("UseExtra", &c[idx], 1);
    idx += 1;
    dump_line("UseExtraA", &c[idx], 1);
    idx += 1;
    dump_line("LockValue", &c[idx], 1);
    idx += 1;
    dump_line("LockConfig", &c[idx], 1);
    idx += 1;
    dump_line("SlotLocked", &c[idx], 2);
    idx += 2;
    dump_line("ChipOption", &c[idx], 2);
    idx += 2;
    dump_line("X509fmt", &c[idx], 4);
    idx += 4;

    for (int i = 0; i < 16; ++i) {
        char label[16];
        snprintf(label, sizeof(label), "KeyCfg[%d]", i);
        dump_line(label, &c[idx], 2);
        idx += 2;
    }
}

};  // namespace

void setup()
{
    M5.begin();

    Wire.end();

    auto pin_num_sda = M5.getPin(m5::pin_name_t::port_a_sda);
    auto pin_num_scl = M5.getPin(m5::pin_name_t::port_a_scl);

#if defined(USING_M5CORE2_AWS_BUILTIN)
#pragma message "Usiing  builtin ATECC608B"
    if (M5.getBoard() == m5::board_t::board_M5StackCore2) {
        pin_num_sda = M5.getPin(m5::pin_name_t::in_i2c_sda);
        pin_num_scl = M5.getPin(m5::pin_name_t::in_i2c_scl);
    }
#endif

    M5_LOGI("getPin: SDA:%u SCL:%u", pin_num_sda, pin_num_scl);
    Wire.begin(pin_num_sda, pin_num_scl, 400 * 1000U);
    if (!Units.add(unit, Wire) || !Units.begin()) {
        lcd.clear(TFT_RED);
        M5_LOGE("Failed to begin");
        while (true) {
            m5::utility::delay(10000);
        }
    }
    M5_LOGI("M5UnitUnified has been begun");
    M5_LOGI("%s", Units.debugInfo().c_str());
    lcd.clear(TFT_DARKGREEN);

    //
    uint8_t config[128]{};
    unit.readConfigZone(config);

    uint8_t otp[64]{};
    unit.readOTPZone(otp);

    uint8_t data[unit.getSlotSize(Slot::GeneralData)]{};
    unit.readDataZone(data, sizeof(data), Slot::GeneralData);

    bool key_valid[16]{};
    for (uint8_t slot = 0; slot < 16; ++slot) {
        unit.readKeyValid(key_valid[slot], (Slot)slot);
    }

    uint32_t c0{}, c1{};
    unit.readCounter(c0, 0);
    unit.readCounter(c1, 1);

    uint16_t state{};
    unit.readDeviceState(state);

    uint8_t test{};
    unit.selfTest(test);

    //
    M5.Log.printf("Dump config ----------------\n");
    dump_config(config);

    M5.Log.printf("Dump OTP ----------------\n");
    m5::utility::log::dump(otp, sizeof(otp), false);

    M5.Log.printf("Dump Data zone (8:GeneralData) ----------------\n");
    m5::utility::log::dump(data, sizeof(data), false);

    M5.Log.printf("KeyValid ----------------\n");
    m5::utility::log::dump(key_valid, sizeof(key_valid), false);

    M5.Log.printf("Counter: %u, %u\n", c0, c1);

    M5.Log.printf("DeviceState:%04X\n", state);

    M5.Log.printf("SelfTest Result:%02X\n", test);
}

void loop()
{
    // M5.update();
    //  auto touch = M5.Touch.getDetail();
    // Units.update();
    m5::utility::delay(1000);
}
