/*
 * SPDX-FileCopyrightText: 2025 M5Stack Technology CO LTD
 *
 * SPDX-License-Identifier: MIT
 */
/*
  M5Unit-ID example. Connect to AWS IoT.
*/
// ****************************************************************************************************
// Settings
// ****************************************************************************************************
// Fill in the following define or specify with build option
// ****************************************************************************************************
// Enable this define when using M5Core2AWS's built-in chip
#if !defined(USING_M5CORE2_AWS_BUILTIN)
// #define USING_M5CORE2_AWS_BUILTIN
#endif

#if !defined(EXAMPLE_SSID)
#define EXAMPLE_SSID ""  // SSID
#endif
#if !defined(EXAMPLE_PASSWORD)
#define EXAMPLE_PASSWORD ""  // SSID Password
#endif
#if !defined(EXAMPLE_MQTT_URI)
#define EXAMPLE_MQTT_URI ""  // AWS Endpoint URI
#endif
#ifndef EXAMPLE_MQTT_PORT
#define EXAMPLE_MQTT_PORT (8883)  // Port number
#endif

#include "main/Blinky-Hello-World.cpp"
