/*
 * SPDX-FileCopyrightText: 2026 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  Wi-Fi station connect for the AWS IoT examples.

  One esp_wifi (STA) path for both Arduino and ESP-IDF, like M5Unit-OBD. It also handles esp_hosted boards,
  where Wi-Fi runs on a companion chip over SDIO (e.g. M5Tab5: ESP32-P4 + ESP32-C6). Under Arduino the core
  would do the esp_hosted / netif / event / esp_wifi setup inside WiFi.begin; here we do it explicitly.

  To reuse in another example (M5Unit-IMU / OBD / UWB ...), copy this file and, if your esp_hosted board is
  not Tab5, adjust the board check and SDIO pins in begin(). Call wifi_connect::begin() once.
*/
#ifndef WIFI_CONNECT_HPP
#define WIFI_CONNECT_HPP

#include <M5Unified.h>
#include <M5Utility.h>

#include <algorithm>
#include <cstring>
#include <esp_event.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include <freertos/event_groups.h>
#include <nvs_flash.h>
#if defined(ARDUINO) && defined(CONFIG_ESP_HOSTED_ENABLED)
// Hosted Wi-Fi (e.g. Tab5: ESP32-P4 + ESP32-C6 over SDIO). hostedSetPins sets the SDIO pins, hostedInitWiFi
// starts the esp_hosted transport that the Arduino core would otherwise start inside WiFi.begin. Using these
// core helpers (not the WiFi class) keeps this header free of a <WiFi.h> dependency when copied to another example.
#include <esp32-hal-hosted.h>
#endif
#if !CONFIG_SOC_WIFI_SUPPORTED && !defined(ARDUINO) && !defined(CONFIG_ESP_WIFI_REMOTE_ENABLED)
// esp32 / esp32s3 / esp32c3 / esp32c5 / esp32c6 have on-die Wi-Fi. ESP32-P4 (Tab5) has none: its Wi-Fi runs
// on an ESP32-C6 co-processor over SDIO (esp_hosted), bundled by the Arduino core and, on ESP-IDF >= 5.3,
// pulled in by esp_wifi_remote (main/idf_component.yml) with the Tab5 preset (sdkconfig.defaults.esp32p4)
#error "This example needs Wi-Fi: a Wi-Fi capable chip, or ESP-IDF >= 5.3 with esp_wifi_remote for ESP32-P4 (Tab5)"
#endif

namespace wifi_connect {

// Keep reconnecting until connected. After a reset without disconnecting, an access point with PMF (WPA3)
// still holds the old association and refuses the first attempts for a while (comeback time)
constexpr uint32_t DEFAULT_TIMEOUT_MS{20000};

EventGroupHandle_t events{};
constexpr EventBits_t CONNECTED_BIT{BIT0};

void on_event(void *, esp_event_base_t base, int32_t id, void *)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        // Keep reconnecting (the access point may refuse the first attempts after a reset)
        xEventGroupClearBits(events, CONNECTED_BIT);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(events, CONNECTED_BIT);
    }
}

//! @brief Connect as a station. ssid/password may be null/empty to use the config stored in NVS
bool begin(const char *ssid, const char *password, const uint32_t timeout_ms = DEFAULT_TIMEOUT_MS)
{
    // Tab5 (ESP-IDF): the ESP32-C6 is powered by default, so no WLAN_PWR_EN handling is needed here. esp_hosted
    // brings up the SDIO transport on its own; what actually lets the C6 come up is the ACTIVE_HIGH SDIO reset in
    // sdkconfig.defaults.esp32p4 (the preset there also sets the pins).
#if defined(ARDUINO) && defined(CONFIG_ESP_HOSTED_ENABLED)
    // The companion chip, bus and pins are board-specific (not every ESP32-P4 uses an ESP32-C6), so this is
    // keyed on the board. The ESP-IDF build gets the same from esp_hosted's Tab5 preset (sdkconfig.defaults.esp32p4).
    const bool hosted = (M5.getBoard() == m5::board_t::board_M5Tab5);
    if (hosted) {
        // Tab5: ESP32-C6 on SDIO2 (CLK 12 / CMD 13 / D0-D3 11,10,9,8 / reset 15)
        hostedSetPins(12, 13, 11, 10, 9, 8, 15);
        if (!hostedInitWiFi()) {
            M5_LOGE("hostedInitWiFi failed");
            return false;
        }
    }
#endif
    // Wi-Fi keeps its calibration data and the stored station config in NVS
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        M5_LOGE("nvs_flash_init failed %s", esp_err_to_name(err));
        return false;
    }

    events = xEventGroupCreate();
    err    = esp_netif_init();
    if (!events || (err != ESP_OK && err != ESP_ERR_INVALID_STATE)) {
        M5_LOGE("Failed to initialize the network stack");
        return false;
    }
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        M5_LOGE("esp_event_loop_create_default failed %s", esp_err_to_name(err));
        return false;
    }
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
#if defined(ARDUINO) && defined(CONFIG_ESP_HOSTED_ENABLED)
    if (hosted) {
        init_cfg.nvs_enable = false;  // esp_hosted does not use the host NVS for Wi-Fi (as the Arduino core does)
    }
#endif
    err = esp_wifi_init(&init_cfg);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        M5_LOGE("esp_wifi_init failed %s", esp_err_to_name(err));
        return false;
    }
    if (esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, nullptr, nullptr) != ESP_OK ||
        esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, nullptr, nullptr) != ESP_OK ||
        esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK) {
        M5_LOGE("Failed to initialize Wi-Fi");
        return false;
    }

    if (ssid && ssid[0] && password && password[0]) {
        M5_LOGI("Use ssid:%s and password", ssid);
        wifi_config_t cfg{};
        memcpy(cfg.sta.ssid, ssid, std::min(strlen(ssid), sizeof(cfg.sta.ssid)));
        memcpy(cfg.sta.password, password, std::min(strlen(password), sizeof(cfg.sta.password) - 1));
        if (esp_wifi_set_config(WIFI_IF_STA, &cfg) != ESP_OK) {
            M5_LOGE("esp_wifi_set_config failed");
            return false;
        }
    } else {
        // The station config stored in NVS by an earlier connection
        M5_LOGI("Use inner credential");
    }
    if (esp_wifi_start() != ESP_OK) {
        M5_LOGE("esp_wifi_start failed");
        return false;
    }

    const EventBits_t bits = xEventGroupWaitBits(events, CONNECTED_BIT, pdFALSE, pdTRUE, pdMS_TO_TICKS(timeout_ms));
    return (bits & CONNECTED_BIT) != 0;
}

}  // namespace wifi_connect
#endif
