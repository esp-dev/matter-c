cmake_minimum_required(VERSION 3.20)
if(NOT MATTER_LAB_MDNS_DIR)
    message(FATAL_ERROR "Set MATTER_LAB_MDNS_DIR to the pinned Espressif mdns-v1.12.0 component directory")
endif()
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components/matter_c"
    "${CMAKE_CURRENT_LIST_DIR}/../../components/matter_c_esp32" "${MATTER_LAB_MDNS_DIR}")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(matter_c_runtime)
