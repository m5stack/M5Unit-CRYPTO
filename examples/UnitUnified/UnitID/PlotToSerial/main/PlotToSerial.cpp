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
#include <M5HAL.hpp>
#include <soc/gpio_reg.h>
#include <soc/gpio_sig_map.h>

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
    M5.setTouchButtonHeightByRatio(100);
    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }

    auto board = M5.getBoard();

    bool unit_ready{};
#if defined(USING_M5CORE2_AWS_BUILTIN)
#pragma message "Using builtin ATECC608B"
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
        lcd.fillScreen(TFT_RED);
        M5_LOGE("Failed to begin");
        while (true) {
            m5::utility::delay(10000);
        }
    }
    M5_LOGI("M5UnitUnified initialized");
    M5_LOGI("%s", Units.debugInfo().c_str());
    lcd.fillScreen(TFT_DARKGREEN);

    // Diagnostic mode: Units.begin() includes readRevision in unit.begin().
    // Stop here to evaluate wakeup/revision stability without additional API load.
    constexpr bool DIAG_REVISION_ONLY = false;
    if (DIAG_REVISION_ONLY) {
        M5_LOGI("DIAG_REVISION_ONLY=1: skip readConfigZone/readOTPZone/readDataZone...");
        return;
    }

    // Step mode for staged recovery.
    uint8_t config[128]{};
    if (!unit.readConfigZone(config)) {
        M5_LOGE("readConfigZone NG");
    }

    uint8_t otp[64]{};
    if (!unit.readOTPZone(otp)) {
        M5_LOGE("readOTPZone NG");
    }

    uint8_t data[unit.getSlotSize(Slot::GeneralData)]{};
    if (!unit.readDataZone(data, sizeof(data), Slot::GeneralData)) {
        M5_LOGE("readDataZone NG");
    }

    bool key_valid[16]{};
    for (uint8_t slot = 0; slot < 16; ++slot) {
        if (!unit.readKeyValid(key_valid[slot], (Slot)slot)) {
            M5_LOGE("readKeyValid[%u] NG", slot);
        }
    }

    uint32_t c0{}, c1{};
    if (!unit.readCounter(c0, 0)) {
        M5_LOGE("readCounter(0) NG");
    }
    if (!unit.readCounter(c1, 1)) {
        M5_LOGE("readCounter(1) NG");
    }

    uint16_t state{};
    if (!unit.readDeviceState(state)) {
        M5_LOGE("readDeviceState NG");
    }

    uint8_t test{};
    if (!unit.selfTest(test)) {
        M5_LOGE("selfTest NG");
    }

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

static uint32_t s_write_count{};

void loop()
{
    M5.update();

    // BtnA Click: Write/Read GeneralData (Slot 8)
    if (M5.BtnA.wasClicked()) {
        auto cnt = ++s_write_count;
        M5.Log.printf("\n=== Write GeneralData #%u ===\n", (unsigned)cnt);

        // Write HEAD at offset 0, TAIL at offset 384 (416-32)
        uint8_t head[32]{}, tail[32]{};
        snprintf((char*)head, sizeof(head), "M5CRYPTO HEAD #%u", (unsigned)cnt);
        snprintf((char*)tail, sizeof(tail), "M5CRYPTO TAIL #%u", (unsigned)cnt);

        bool ok = unit.writeGeneralData(head, sizeof(head), 0);
        M5.Log.printf("Write [0]:   %s\n", ok ? "OK" : "NG");
        ok = unit.writeGeneralData(tail, sizeof(tail), 384);
        M5.Log.printf("Write [384]: %s\n", ok ? "OK" : "NG");

        // Read back and verify
        uint8_t rH[32]{}, rT[32]{};
        unit.readGeneralData(rH, 32, 0);
        unit.readGeneralData(rT, 32, 384);
        M5.Log.printf("[0]   match: %s\n", memcmp(head, rH, 32) == 0 ? "YES" : "NO");
        M5.Log.printf("[384] match: %s\n", memcmp(tail, rT, 32) == 0 ? "YES" : "NO");
    }

    // BtnA Hold: SHA256 + Sign
    if (M5.BtnA.wasHold()) {
        M5.Log.printf("\n=== SHA256 + Sign ===\n");

        uint8_t digest[32]{};
        const uint8_t msg[] = "Hello ATECC608B";
        bool ok             = unit.SHA256(Destination::TempKey, digest, msg, sizeof(msg) - 1);
        M5.Log.printf("SHA256: %s\n", ok ? "OK" : "NG");
        if (ok) {
            m5::utility::log::dump(digest, 32, false);
        }

        uint8_t nonce_in[20]{};
        memcpy(nonce_in, digest, sizeof(nonce_in));
        ok = unit.createNonce(nullptr, nonce_in, true, true);
        M5.Log.printf("Nonce:  %s\n", ok ? "OK" : "NG");

        if (ok) {
            uint8_t sig[64]{};
            ok = unit.signExternal(sig, Slot::PrimaryPrivateKey, Source::TempKey);
            M5.Log.printf("Sign:   %s\n", ok ? "OK" : "NG");
            if (ok) {
                m5::utility::log::dump(sig, 64, false);
            }
        }
    }

    m5::utility::delay(50);
}
