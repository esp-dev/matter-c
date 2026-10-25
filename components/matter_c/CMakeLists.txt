get_filename_component(matter_root "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${matter_root}/cmake/sources.json")
file(READ "${matter_root}/cmake/sources.json" matter_manifest)
set(matter_sources)
foreach(group core runtime)
    string(JSON count LENGTH "${matter_manifest}" ${group})
    math(EXPR last "${count}-1")
    foreach(index RANGE ${last})
        string(JSON source GET "${matter_manifest}" ${group} ${index})
        list(APPEND matter_sources "${matter_root}/main/apps/matter/${source}.c")
    endforeach()
endforeach()
idf_component_register(SRCS ${matter_sources} "matter_idf_memory.c"
    INCLUDE_DIRS "${matter_root}/main/apps/matter" "."
    REQUIRES mbedtls)
target_compile_features(${COMPONENT_LIB} PUBLIC c_std_99)
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    MATTER_EVENTS_CAPACITY=${CONFIG_MATTER_C_EVENTS_CAPACITY}
    MATTER_TRANSPORT_CAPACITY=${CONFIG_MATTER_C_TRANSPORT_CAPACITY})
target_compile_options(${COMPONENT_LIB} PRIVATE -fstack-usage)
if(IDF_VERSION_MAJOR GREATER_EQUAL 6)
    if(CONFIG_MBEDTLS_HARDWARE_ECC)
        message(FATAL_ERROR "Matter C currently requires CONFIG_MBEDTLS_HARDWARE_ECC=n for software blinding and RNG failure semantics")
    endif()
    # IDF's own Matter backend also uses builtin arithmetic for SPAKE2+.
    target_include_directories(${COMPONENT_LIB} PRIVATE
        "${IDF_PATH}/components/mbedtls/mbedtls/tf-psa-crypto/drivers/builtin/include"
        "${IDF_PATH}/components/mbedtls/mbedtls/library")
endif()
if(CONFIG_MATTER_C_PROFILE_ALLOCATIONS)
    target_compile_options(${COMPONENT_LIB} PRIVATE
        "-include${CMAKE_CURRENT_LIST_DIR}/matter_idf_memory.h")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE MATTER_C_PROFILE_ALLOCATOR=1)
endif()
