# ESP-IDF component manifest for M5Unit-CRYPTO.
# Upstream: https://github.com/m5stack/M5Unit-CRYPTO
#
# The public headers pull in both M5UnitUnified and M5Utility,
# because the unit header includes m5_utility/container/circular_buffer.hpp.
# driver (driver/gpio.h) is used only by the .cpp for the GPIO wake pulse.
file(GLOB_RECURSE SRCS "src/*.cpp")
idf_component_register(
    SRCS ${SRCS}
    INCLUDE_DIRS "src"
    REQUIRES M5UnitUnified M5Utility
    PRIV_REQUIRES driver
)
