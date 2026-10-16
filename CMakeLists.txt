cmake_minimum_required(VERSION 3.18)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT DEFINED DMOD_MODULE_VERSION)
    set(DMOD_MODULE_VERSION "0.1" CACHE STRING "DMOD module version")
endif()

# If a local dmod checkout is provided, use it instead of fetching from git
if(DEFINED DMOD_DIR AND NOT "${DMOD_DIR}" STREQUAL "")
    set(FETCHCONTENT_SOURCE_DIR_DMOD "${DMOD_DIR}" CACHE PATH "" FORCE)
endif()

include(FetchContent)
FetchContent_Declare(
    dmod
    GIT_REPOSITORY https://github.com/choco-technologies/dmod.git
    GIT_TAG        develop
)

set(DMOD_MODE "DMOD_MODULE" CACHE STRING "DMOD build mode")
set(DMOD_BUILD_TESTS OFF CACHE BOOL "Build tests")
set(DMOD_BUILD_EXAMPLES OFF CACHE BOOL "Build examples")
set(DMOD_BUILD_TOOLS OFF CACHE BOOL "Build tools")
set(DMOD_BUILD_TEMPLATES OFF CACHE BOOL "Build templates")

FetchContent_MakeAvailable(dmod)

project(dmtls VERSION ${DMOD_MODULE_VERSION}
    DESCRIPTION "dmtls DMOD library module"
    LANGUAGES C CXX)

set(DMOD_DIR ${dmod_SOURCE_DIR} CACHE PATH "DMOD source directory")
set(DMOD_SCRIPTS_DIR ${DMOD_DIR}/scripts CACHE PATH "DMOD scripts directory")
include(${DMOD_DIR}/paths.cmake)
dmod_setup_external_module()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/backend.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/pointer-audit.cmake)

# Name of the module
set(DMOD_MODULE_NAME        dmtls)

# Author (should be string)
set(DMOD_AUTHOR_NAME        "Patryk Kubiak")

# Stack size for the module (should be integer)
set(DMOD_STACK_SIZE         1024)

# Path to the .dmr file - enables release package creation in build/packages/
set(DMOD_DMR_PATH           ${CMAKE_CURRENT_SOURCE_DIR}/dmtls.dmr)

# List of MAL interfaces implemented by this module (leave empty if none)
set(DMOD_MAL_IMPLS          )

# List of DIF interfaces implemented by this module (leave empty if none)
set(DMOD_DIF_IMPLS          )

#
#   dmod_add_library - create a library module
#   it has the same signature as add_library
#   and can be used in the same way after the creation
#   (for example, to link libraries)
#
dmod_add_library(${DMOD_MODULE_NAME} ${DMOD_MODULE_VERSION}
    # List of source files - can include C and C++ files
    src/dmtls.c
    src/dmtls_platform.c
    src/dmtls_config.c
    src/dmtls_connection.c
    src/dmtls_io.c
    ${DMTLS_BACKEND_SOURCES}
)

target_include_directories(${DMOD_MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/config
    ${DMTLS_BACKEND_INCLUDES}
)

target_include_directories(${DMOD_MODULE_NAME}_if INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(${DMOD_MODULE_NAME} PRIVATE
    strstr=dmtls_backend_strstr
    MBEDTLS_CONFIG_FILE="dmtls_mbedtls_config.h"
    TF_PSA_CRYPTO_CONFIG_FILE="dmtls_psa_config.h"
)
# Retain ELF metadata for a build-time audit only. The emitted DMF keeps the
# existing header/GOT format; no relocation table or custom loader is used.
dmtls_audit_module(${DMOD_MODULE_NAME})
dmod_link_modules(${DMOD_MODULE_NAME} dmosi dmutc)
option(DMTLS_BUILD_HARDWARE_PROBE "Build the STM32 hardware/RNG interoperability diagnostic" OFF)
enable_testing()
add_subdirectory(tests)
