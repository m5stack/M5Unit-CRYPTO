# M5Unit - CRYPTO

## Overview

Library for CRYPTO using [M5UnitUnified](https://github.com/m5stack/M5UnitUnified).  
M5UnitUnified is a library for unified handling of various M5 units products.

### SKU:U124

Unit ID is an encryption coprocessor with hardware-based secure key storage, integrating the ATECC608B hardware encryption chip and using the I2C communication interface. The chip has a built-in 10Kb EEPROM, which can be used to store keys, certificates, data, consumption records, and security configurations. By restricting access policies to memory areas, the configuration can be locked to prevent changes.

Supports the Trust&GO platform (pre-configured with universal certificates, suitable for TLS-based network security authentication, such as AWS-IoT, Azure, Google, and other cloud platform verification registrations). The internal certificate of the encryption chip can be directly obtained through tools to complete automatic registration without exposing the private key.

The pre-configured Trust&GO security element only supports the "Microchip Trust Platform". For more details, please refer to the following link. https://www.microchip.com/en-us/product/ATECC608B-TNGTLS

### SKU:K010-AWS

Core2 for AWS is a dedicated kit for AWS IoT learning projects. It consists of the M5Stack Core2 main control unit and the M5GO-Bottom For AWS expansion base, with an additional custom integration of the ATECC608 Trust&GO hardware encryption, making it an ideal kit for IoT learning and secure project development.


## Related Link

- [Unit ID & Datasheet](https://docs.m5stack.com/en/unit/id)
- [Core2 for AWS](https://docs.m5stack.com/en/products/sku/K010-AWS)

### Required Libraries
- [M5UnitUnified](https://github.com/m5stack/M5UnitUnified)
- [M5Utility](https://github.com/m5stack/M5Utility)
- [M5HAL](https://github.com/m5stack/M5HAL)

## License

- [M5Unit-CRYPTO - MIT](LICENSE)

## Examples
See also [examples/UnitUnified](examples/UnitUnified)

### Ported from Blinky-Hello-World (SKU:K010-AWS)
See also [examples/UnitUnified/UnitID/Blinky-Hello-World](examples/UnitUnified/UnitID/Blinky-Hello-World)

### For ArduinoIDE settings
If you use the built-in ATECC608B chip on **M5Stack Core2 for AWS (SKU:K010-AWS)**,
you must enable the define symbol below.
(Rewrite source or specify with compile options)

- PlotToSerial / Blinky-Hello-World
```cpp
// *************************************************************
// Uncomment if using the built-in ATECC608B on Core2 for AWS
// *************************************************************
#if !defined(USING_M5CORE2_AWS_BUILTIN)
// For Core2 for AWS built-in ATECC608B (K010-AWS)
// #define USING_M5CORE2_AWS_BUILTIN
#endif
```

### For ESP-IDF settings
PlotToSerial and ViaPaHub can be built with ESP-IDF 5.1 or later (5.x and 6.x).
Blinky-Hello-World can be built with ESP-IDF 5.x (>= 5.1) or 6.1 and later (6.0 is not supported); see [its README](examples/UnitUnified/UnitID/Blinky-Hello-World) for the settings.
To use the built-in ATECC608B on **M5Stack Core2 for AWS (SKU:K010-AWS)** in PlotToSerial, choose it in menuconfig.
The choice is passed to the source as `USING_M5CORE2_AWS_BUILTIN` by `examples/UnitUnified/common/variant.cmake`, so the source does not need to be edited.

```sh
cd examples/UnitUnified/UnitID/PlotToSerial
idf.py set-target esp32
idf.py menuconfig
# -> M5Unit-CRYPTO example -> Target unit -> choose ONE:
#      UnitID (U124, ATECC608B-TNGTLS / GROVE)
#      Core2 for AWS built-in ATECC608B (K010-AWS)   (esp32 only)
idf.py build flash monitor
```

ViaPaHub has no variant; run `idf.py set-target <chip>` and `idf.py build flash monitor`.

## Support via [PaHub](https://docs.m5stack.com/en/unit/Unit-PaHub%20v2.1)

|Unit|Support|Note|
|---|---|---|
|UnitID|OK||

See also the [ViaPaHub](examples/UnitUnified/UnitID/ViaPaHub) example and [M5Unit-HUB](https://github.com/m5stack/M5Unit-HUB)

## Doxygen document
[GitHub Pages](https://m5stack.github.io/M5Unit-CRYPTO/)

If you want to generate documents on your local machine, execute the following command

```
bash docs/doxy.sh
```

It will output it under docs/html  
If you want to output Git commit hashes to html, do it for the git cloned folder.

### Required
- [Doxygen](https://www.doxygen.nl/)
- [Git](https://git-scm.com/) (Output commit hash to html)

