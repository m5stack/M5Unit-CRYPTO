# Map the Kconfig "Target unit" choice (common/Kconfig.variant) to the source-level macro that
# both the Arduino and ESP-IDF builds use. Include this from an example's main/CMakeLists.txt
# *after* idf_component_register() (it needs ${COMPONENT_LIB}).
# UnitID (GROVE) is the default and needs no macro.
set(M5UNIT_VARIANT "")
if(CONFIG_EXAMPLE_USING_M5CORE2_AWS_BUILTIN)
    set(M5UNIT_VARIANT USING_M5CORE2_AWS_BUILTIN)
endif()
if(M5UNIT_VARIANT)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE ${M5UNIT_VARIANT})
endif()
