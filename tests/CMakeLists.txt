set(DMOD_MODULE_NAME        test_dmtls)
set(DMOD_MODULE_VERSION     ${PROJECT_VERSION})
set(DMOD_AUTHOR_NAME        "Patryk Kubiak")
set(DMOD_STACK_SIZE         8192)
set(DMOD_DMR_PATH ${CMAKE_CURRENT_SOURCE_DIR}/test_dmtls.dmr)
set(DMOD_PRIORITY           0)

dmod_add_test(${DMOD_MODULE_NAME} ${DMOD_MODULE_VERSION}
    dmtls_test.c
)

target_include_directories(${DMOD_MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(${DMOD_MODULE_NAME} dmtls_if)
dmtls_audit_module(${DMOD_MODULE_NAME})

# Register the test module with ctest - this installs dependencies and runs the real module
# through the loader: install the test module's
# dependencies with dmf-get, then execute it through dmod_loader. The test's
# exit code equals its number of failed steps (see dmod_add_test).
find_program(DMF_GET_EXECUTABLE dmf-get HINTS ${DMOD_TOOLS_BIN_DIR} PATHS ENV PATH)
find_program(DMOD_LOADER_EXECUTABLE dmod_loader HINTS ${DMOD_TOOLS_BIN_DIR} PATHS ENV PATH)

if(DMF_GET_EXECUTABLE AND DMOD_LOADER_EXECUTABLE)
    add_test(
        NAME ${DMOD_MODULE_NAME}
        COMMAND ${CMAKE_COMMAND} -E env DMOD_DMF_DIR=${DMOD_DMF_DIR}
            bash -c "${DMF_GET_EXECUTABLE} install -d ${DMOD_DMF_DIR}/${DMOD_MODULE_NAME}-local.dmd -y && ${DMOD_LOADER_EXECUTABLE} ${DMOD_DMF_DIR}/${DMOD_MODULE_NAME}.dmf"
    )
else()
    message(WARNING "dmf-get/dmod_loader not found - 'ctest' will not run ${DMOD_MODULE_NAME}. Build the tools first with -DDMOD_BUILD_TOOLS=ON")
endif()

# The real TLS engine and crypto backend, with only SAL/dmosi/UTC replaced by
# controllable host providers. OpenSSL provides an independent TLS peer.
if(CMAKE_CROSSCOMPILING OR DMOD_ARCH MATCHES "arm")
    if(DMTLS_BUILD_HARDWARE_PROBE)
        add_subdirectory(probe)
    endif()
else()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    find_package(Threads REQUIRED)
    add_test(NAME dmtls_pointer_audit COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/host/test_pointer_audit.py)
    add_library(dmtls_test_engine SHARED
        ../src/dmtls.c ../src/dmtls_platform.c ../src/dmtls_config.c
        ../src/dmtls_connection.c ../src/dmtls_io.c host/platform.c
        ${DMTLS_BACKEND_SOURCES})
    target_include_directories(dmtls_test_engine PRIVATE
        host/stubs ../include ../src ../config
        ${DMOD_DMF_DIR}/inc/dmutc/include ${DMTLS_BACKEND_INCLUDES})
    target_compile_definitions(dmtls_test_engine PRIVATE
        strstr=dmtls_backend_strstr
    MBEDTLS_CONFIG_FILE="dmtls_mbedtls_config.h"
        TF_PSA_CRYPTO_CONFIG_FILE="dmtls_psa_config.h")
    target_link_libraries(dmtls_test_engine PRIVATE Threads::Threads)
    add_test(NAME tls_interoperability COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/host/interoperability.py $<TARGET_FILE:dmtls_test_engine>)
    set_tests_properties(tls_interoperability PROPERTIES TIMEOUT 180)
endif()
