get_filename_component(matter_root "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(lab_sources "app_main.c" "wifi_port.c" "soak_lab.c")
if(CONFIG_MATTER_C_RUNTIME_RGB)
    list(APPEND lab_sources "rgb_light.c" "rgb_led.c")
endif()
idf_component_register(SRCS ${lab_sources} INCLUDE_DIRS "."
    PRIV_INCLUDE_DIRS "${matter_root}/tools/matter/tests"
    REQUIRES matter_c_esp32 esp_wifi esp_event esp_timer bootloader_support esp_driver_uart esp_driver_rmt)
target_compile_options(${COMPONENT_LIB} PRIVATE -fstack-usage)
if(CONFIG_MATTER_C_PROFILE_ALLOCATIONS)
    set_source_files_properties("wifi_port.c" "rgb_light.c" "rgb_led.c" PROPERTIES
        COMPILE_OPTIONS "-include${matter_root}/components/matter_c/matter_idf_memory.h"
        COMPILE_DEFINITIONS MATTER_C_PROFILE_ALLOCATOR=1)
endif()
string(TIMESTAMP lab_utc "%s" UTC)
target_compile_definitions(${COMPONENT_LIB} PRIVATE MATTER_LAB_BOOT_UTC=${lab_utc})
if(NOT MATTER_C_LAB_CONFIG_DIR)
    message(FATAL_ERROR "Runtime lab requires an ignored directory with matter_lab_wifi.h")
endif()
target_include_directories(${COMPONENT_LIB} PRIVATE "${MATTER_C_LAB_CONFIG_DIR}")
