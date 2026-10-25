idf_component_register(SRCS "matter_idf_udp.c" "matter_idf_store.c" "matter_idf_discovery.c" "matter_idf_ota.c" "matter_idf_resolver.c" "matter_idf_wifi.c" "matter_idf_wifi_retry.c" "matter_idf_multicast.c"
    INCLUDE_DIRS "." REQUIRES matter_c esp_netif lwip nvs_flash mdns PRIV_REQUIRES esp_timer app_update bootloader_support esp_app_format esp_hw_support esp_wifi esp_event)
target_compile_options(${COMPONENT_LIB} PRIVATE -fstack-usage)
if(CONFIG_MATTER_C_PROFILE_ALLOCATIONS)
    target_compile_options(${COMPONENT_LIB} PRIVATE
        "-include${CMAKE_CURRENT_LIST_DIR}/../matter_c/matter_idf_memory.h")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE MATTER_C_PROFILE_ALLOCATOR=1)
endif()
if(NOT CONFIG_LWIP_TCPIP_CORE_LOCKING OR CONFIG_LWIP_IP6_REASSEMBLY)
    message(FATAL_ERROR "Matter IPv6 port needs TCPIP_CORE_LOCKING=y and IP6_REASSEMBLY=n")
endif()
