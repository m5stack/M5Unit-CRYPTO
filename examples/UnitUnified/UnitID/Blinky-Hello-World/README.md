# Blinky-Hello-World 

## Overview

Porting from https://github.com/m5stack/Core2-for-AWS-IoT-Kit/tree/master/Blinky-Hello-World

Connection using M5Unit-ID as well as the built-in chip of Core2AWS is possible.

The porting source emits LEDs, but some devices do not have LEDs, so sound is played or displayed on the LCD instead.


## Procedure

### 1. Prepare AWS CLI
See also https://aws-iot-kit-docs.m5stack.com/en/blinky-hello-world/prerequisites/

### 2. Device Provisioning

#### Build, Upload this example program
The unit's device certificate and serial number appear on the serial monitor.  
**(Do not define/build options for AWS endpoints or others yet)**

```log
13:58:46.237 > For provisioning:
13:58:46.237 > SerialNumber:0123456789ABCDEF01
13:58:46.243 > DeviceCert:
13:58:46.243 > -----BEGIN CERTIFICATE-----
13:58:46.243 > MIICHzCCAcWgAwIBAgIQZA4WqITbv400J/JNDnxUvzAKBggqhkjOPQQDAjBPMSEw
13:58:46.248 > HwYDVQQKDBhNaWNyb2NoaXAgVGVjaG5vbG9neSBJbmMxKjAoBgNVBAMMIUNyeXB0
13:58:46.254 > byBBdXRoZW50aWNhdGlvbiBTaWduZXIgMjcwMDAgFw0yMTAyMDkwNzAwMDBaGA8y
13:58:46.260 > ...
13:58:46.271 > ...
13:58:46.276 > ...
13:58:46.282 > k96xje630ZmaBkjydVjW7jTwlA+YLwmwvgclsi+jgY0wgYowKgYDVR0RBCMwIaQf
13:58:46.287 > MB0xGzAZBgNVBAUTEmV1aTQ4X0U4RUIxQjI4MkY5QzAMBgNVHRMBAf8EAjAAMA4G
13:58:46.293 > A1UdDwEB/wQEAwIDiDAdBgNVHQ4EFgQUZrfuaWeTefnuARhc/BKpQ9Ne1PMwHwYD
13:58:46.298 > VR0jBBgwFoAU4Ba5Jh9kfa1JOClbSjYs9U6NeYowCgYIKoZIzj0EAwIDSAAwRQIg
13:58:46.304 > VM6yCjalouuFlh4IA7MMyg3jGxgX7sRBQwyqW13iAugCIQDKCJ6VxEPMzpe0ETdw
13:58:46.310 > aXxnZYgX4Jm7UJRL2irQBDO5fQ==
13:58:46.310 > -----END CERTIFICATE-----
13:58:46.313 > *** AWS endpoint is empty ***
```

#### Make device certificate file
Make device_cert.crt in this example directory

```pem
-----BEGIN CERTIFICATE-----
MIICHzCCAcWgAwIBAgIQZA4WqITbv400J/JNDnxUvzAKBggqhkjOPQQDAjBPMSEw
HwYDVQQKDBhNaWNyb2NoaXAgVGVjaG5vbG9neSBJbmMxKjAoBgNVBAMMIUNyeXB0
byBBdXRoZW50aWNhdGlvbiBTaWduZXIgMjcwMDAgFw0yMTAyMDkwNzAwMDBaGA8y
...
...
...
k96xje630ZmaBkjydVjW7jTwlA+YLwmwvgclsi+jgY0wgYowKgYDVR0RBCMwIaQf
MB0xGzAZBgNVBAUTEmV1aTQ4X0U4RUIxQjI4MkY5QzAMBgNVHRMBAf8EAjAAMA4G
A1UdDwEB/wQEAwIDiDAdBgNVHQ4EFgQUZrfuaWeTefnuARhc/BKpQ9Ne1PMwHwYD
VR0jBBgwFoAU4Ba5Jh9kfa1JOClbSjYs9U6NeYowCgYIKoZIzj0EAwIDSAAwRQIg
VM6yCjalouuFlh4IA7MMyg3jGxgX7sRBQwyqW13iAugCIQDKCJ6VxEPMzpe0ETdw
aXxnZYgX4Jm7UJRL2irQBDO5fQ==
-----END CERTIFICATE-----
```

#### Run AWS IoT setting script
Run the script in [scripts](scripts) from this example directory

```bash
# Usage
./scripts/aws_register_thing.sh device_certificate serialnumber region
```

|Argument|Description|
|---|---|
| device\_certificate| Device certificate file you just created|
| serialnumber      | Serial number used as the name of the Thing|
| region            | AWS IoT Region|


The script needs the [AWS CLI](https://aws.amazon.com/cli/) (configured with your credentials) and OpenSSL.
It creates or reuses the policy, the thing type, the Thing and the certificate, so it can be run again.

example (first run in the region):
```log
./scripts/aws_register_thing.sh device_cert.crt 0123456789ABCDEF01 us-east-1
[1/6] Validating inputs...
Device certificate valid.
Region "us-east-1" is valid.
[2/6] Creating or confirming policy "M5Unit-ID-Policy"...
Policy created.
[3/6] Creating or confirming thing "0123456789ABCDEF01"...
Creating thing type "m5unit-id"...
Thing "0123456789ABCDEF01" created.
[4/6] Checking or registering certificate...
Registering new certificate...
Certificate: arn:aws:iot:us-east-1:123456789012:cert/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
[5/6] Attaching certificate to thing...
[6/6] Attaching policy...
DONE. Thing "0123456789ABCDEF01" is ready and bound to certificate.
AWS IoT Endpoint
{
    "endpointAddress": "exampleexample-ats.iot.region.amazonaws.com"
}
```

#### Amazon Root CA
The example embeds Amazon Root CA 1 (`root_ca_der[]` in main/Blinky-Hello-World.cpp), so you do not need to download it.
[scripts/download_aws_root.sh](scripts/download_aws_root.sh) downloads it and saves it as DER (`./data/AmazonRootCA1.der`)
if you want to check or replace the embedded certificate.

### 3. Build settings

#### ArduinoIDE
Edit Blinky-Hello-World.ino
```cpp
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
#define EXAMPLE_SSID "YOUR_SSID"  // SSID
#endif
#if !defined(EXAMPLE_PASSWORD)
#define EXAMPLE_PASSWORD "PASSWORD"  // SSID Password
#endif
#if !defined(EXAMPLE_MQTT_URI)
#define EXAMPLE_MQTT_URI "exampleexample-ats.iot.region.amazonaws.com"  // AWS Endpoint URI
#endif
#ifndef EXAMPLE_MQTT_PORT
#define EXAMPLE_MQTT_PORT (8883)  // Port number
#endif
```

#### PlatformIO
Edit ini file

```ini
[env:UnitID_Blinky-Hello-World_Core_Arduino_latest]
.
.
build_flags = ${option_release.build_flags}
  -DEXAMPLE_SSID="\"YOUR_SSID\""
  -DEXAMPLE_PASSWORD="\"PASSWORD\""
  -DEXAMPLE_MQTT_URI="\"exampleexample-ats.iot.region.amazonaws.com\""
```

#### ESP-IDF
ESP-IDF 5.x (>= 5.1) or 6.1 and later, on a Wi-Fi capable chip (esp32 / esp32s3 / esp32c3 / esp32c5 / esp32c6).  
ESP-IDF 6.0 is not supported: its mbedtls 4 has no PSA secure element driver, which signs the TLS handshake with the ATECC608B on 6.1.  
Tab5 (ESP32-P4) has no on-die radio; its Wi-Fi runs on the ESP32-C6 co-processor over SDIO and needs ESP-IDF >= 5.3 (esp_wifi_remote + esp_hosted, pulled in automatically; the SDIO preset is in sdkconfig.defaults.esp32p4).  
Set the Wi-Fi and AWS IoT settings in menuconfig.

```sh
cd examples/UnitUnified/UnitID/Blinky-Hello-World
idf.py set-target esp32
idf.py menuconfig
# -> M5Unit-CRYPTO example -> Target unit -> UnitID or Core2 for AWS built-in ATECC608B (esp32 only)
# -> Blinky-Hello-World settings -> Wi-Fi SSID / Wi-Fi password / AWS IoT endpoint / AWS IoT port
idf.py build flash monitor
```

### 4. Upload & Monitor
Build and upload program.  
If the connection is successful, the following log will be output to the serial monitor

```log
.
.
.
15:02:43.135 > 
15:02:43.135 > ****************************************
15:02:43.135 > *  AWS client Id - 0123456789ABCDEF01  *
15:02:43.141 > ****************************************
15:02:43.141 > 
15:02:48.138 > publish(QOS0)
15:02:48.551 > publish(QOS1)
15:02:53.563 > publish(QOS0)
15:02:53.973 > publish(QOS1)
15:02:59.182 > publish(QOS0)
15:02:59.602 > publish(QOS1)
.
.
.
```

See below for the rest https://aws-iot-kit-docs.m5stack.com/en/blinky-hello-world/blinking-the-leds/

(Some devices do not have LEDs, so the display will change and a sound will be made when a Blink Message is received)

