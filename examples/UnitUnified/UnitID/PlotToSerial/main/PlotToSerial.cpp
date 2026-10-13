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
#include <vector>
#include <wiring/m5_unit_unified_wiring.hpp>  // Board-aware connection helpers (include last)

#if !defined(USING_M5CORE2_AWS_BUILTIN)
// For Core2 for AWS built-in ATECC608B (K010-AWS)
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

}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);
    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }

#if defined(USING_M5CORE2_AWS_BUILTIN)
#pragma message("Using builtin ATECC608B")
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
    lcd.fillScreen(TFT_DARKGREEN);

    uint8_t config[128]{};
    if (!unit.readConfigZone(config)) {
        M5_LOGE("readConfigZone NG");
    }

    uint8_t otp[64]{};
    if (!unit.readOTPZone(otp)) {
        M5_LOGE("readOTPZone NG");
    }

    std::vector<uint8_t> data(unit.getSlotSize(Slot::GeneralData));
    if (!unit.readDataZone(data.data(), data.size(), Slot::GeneralData)) {
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
    m5::utility::log::dump(data.data(), data.size(), false);

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
