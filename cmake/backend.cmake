# One pinned upstream implementation is compiled into dmtls itself. Consumers
# import only dmtls_if; no upstream library ABI or duplicate backend is exposed.
include(FetchContent)
FetchContent_Declare(dmtls_backend
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.1.1/mbedtls-4.1.1.tar.bz2
    URL_HASH SHA256=3359a349e23db3d5536fcee032ae7b2ecbfc08972fab643089b5cbf2a375c98c
)
FetchContent_GetProperties(dmtls_backend)
if(NOT dmtls_backend_POPULATED)
    FetchContent_Populate(dmtls_backend)
endif()
set(DMTLS_PSA_DIR ${dmtls_backend_SOURCE_DIR}/tf-psa-crypto)
# Official release tarballs include generated code and bundled PSA sources.
file(GLOB DMTLS_BACKEND_SOURCES CONFIGURE_DEPENDS
    ${dmtls_backend_SOURCE_DIR}/library/*.c
    ${DMTLS_PSA_DIR}/core/*.c
    ${DMTLS_PSA_DIR}/drivers/builtin/src/*.c
    ${DMTLS_PSA_DIR}/extras/*.c
    ${DMTLS_PSA_DIR}/platform/*.c
    ${DMTLS_PSA_DIR}/utilities/*.c
)
set(DMTLS_BACKEND_INCLUDES
    ${dmtls_backend_SOURCE_DIR}/include
    ${dmtls_backend_SOURCE_DIR}/library
    ${DMTLS_PSA_DIR}/include
    ${DMTLS_PSA_DIR}/core
    ${DMTLS_PSA_DIR}/dispatch
    ${DMTLS_PSA_DIR}/extras
    ${DMTLS_PSA_DIR}/platform
    ${DMTLS_PSA_DIR}/utilities
    ${DMTLS_PSA_DIR}/drivers/builtin/include
    ${DMTLS_PSA_DIR}/drivers/builtin/src
)
