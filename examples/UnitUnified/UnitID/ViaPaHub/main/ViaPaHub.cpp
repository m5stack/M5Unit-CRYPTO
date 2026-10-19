/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Example of using UnitID (ATECC608B TNG-TLS) via UnitPaHub

  Core ---> PaHub ---> ch:0 UnitID

  Prints the serial number once, then a random value from the TRNG every second.
*/
#include <algorithm>
#include <cinttypes>

#include <M5Unified.h>
#include <M5UnitUnified.h>
#include <M5UnitUnifiedCRYPTO.h>
#include <M5UnitUnifiedHUB.h>  // UnitPaHub
#include <M5Utility.h>
#include <wiring/m5_unit_unified_wiring.hpp>  // Board-aware connection helpers (include last)

namespace {
auto& lcd = M5.Display;

m5::unit::UnitUnified Units;
m5::unit::UnitPaHub hub;
m5::unit::UnitID unit;

constexpr uint8_t ID_CHANNEL{0};            // PaHub channel the UnitID is connected to
constexpr uint32_t READ_INTERVAL_MS{1000};  // Interval for reading the TRNG

char serial_number[19]{};  // 18 hex characters + '\0'
m5::utility::elapsed_time_t last_read_ms{};

//! True when the board has a real screen (Atom / NanoC6 / NanoH2 have none)
bool has_lcd{};

void draw_text(const char* sn, const char* value)
{
    // 6x8 font scaled so that 18 characters fit the width
    const int32_t text_size = std::max<int32_t>(1, lcd.width() / (18 * 6));
    lcd.startWrite();
    lcd.fillScreen(TFT_DARKGREEN);
    lcd.setTextSize(text_size);
    lcd.setTextColor(TFT_YELLOW, TFT_DARKGREEN);
    lcd.setTextDatum(middle_center);
    lcd.drawString(sn, lcd.width() / 2, lcd.height() / 3);
    lcd.drawString(value, lcd.width() / 2, lcd.height() * 2 / 3);
    lcd.endWrite();
}

}  // namespace

void setup()
{
    M5.begin();
    M5.setTouchButtonHeightByRatio(100);

    // The screen shall be in landscape mode
    if (lcd.height() > lcd.width()) {
        lcd.setRotation(1);
    }

    if (!hub.add(unit, ID_CHANNEL)) {  // PaHub ch:0 -> UnitID
        M5_LOGE("Failed to add children");
        m5::unit::wiring::failStop();
    }

    // Board-aware I2C for the PaHub: NessoN1 -> PortB GROVE (SoftwareI2C), NanoC6/NanoH2 -> Ex_I2C,
    // others -> Wire. The UnitID is reached through the hub (added above), so only the hub is added here.
    if (!m5::unit::wiring::addI2C(Units, hub) || !Units.begin()) {
        M5_LOGE("Failed to begin");
        m5::unit::wiring::failStop();
    }

    M5_LOGI("M5UnitUnified initialized");
    M5_LOGI("%s", Units.debugInfo().c_str());

    if (!unit.readSerialNumber(serial_number)) {
        M5_LOGE("Failed to readSerialNumber");
        m5::unit::wiring::failStop();
    }
    M5.Log.printf("SerialNumber:%s\n", serial_number);

    // A board without a screen reports a 1x1 dummy display
    has_lcd = (lcd.width() > 8 && lcd.height() > 8);
    if (has_lcd) {
        draw_text(serial_number, "");
    }
}

void loop()
{
    M5.update();
    Units.update();

    if (m5::utility::elapsedSince(last_read_ms) >= READ_INTERVAL_MS) {
        last_read_ms = m5::utility::millis();
        uint32_t value{};
        if (unit.readRandom(value, static_cast<uint32_t>(0), static_cast<uint32_t>(UINT32_MAX))) {
            M5.Log.printf(">Random:%" PRIu32 "\n", value);
            if (has_lcd) {
                char buf[16]{};
                snprintf(buf, sizeof(buf), "%08" PRIX32, value);
                draw_text(serial_number, buf);
            }
        } else {
            M5_LOGE("Failed to readRandom");
        }
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
