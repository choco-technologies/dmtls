# One pinned upstream implementation is compiled into dmtls itself. Consumers
# import only dmtls_if; no upstream library ABI or duplicate backend is exposed.
include(FetchContent)
# Reviewed third-party fork revisions, independent of DMOD module versions.
# The fork preserves the original DMF/GOT ABI; no loader extension is needed.
FetchContent_Declare(dmtls_backend
    URL https://github.com/choco-technologies/mbedtls/archive/41853d1d2a94a92f97fe70fbc1d5c14e19d79d25.tar.gz
    URL_HASH SHA256=f7b170378f6b7e2c84168f36869504dbf67c685fdb7a08cd0cde1a9e8a5aa0f3
)
FetchContent_Declare(dmtls_crypto_backend
    URL https://github.com/choco-technologies/TF-PSA-Crypto/archive/a119c22d541a783aab6f0c5b68047f5d81d1969a.tar.gz
    URL_HASH SHA256=af999d687e6ebf287e170e3b3b1fbb3ff0e80cb331a5e5fa88ef452885b56603
)
foreach(backend IN ITEMS dmtls_backend dmtls_crypto_backend)
    FetchContent_GetProperties(${backend})
    if(NOT ${backend}_POPULATED)
        FetchContent_Populate(${backend})
    endif()
endforeach()
set(DMTLS_PSA_DIR ${dmtls_crypto_backend_SOURCE_DIR})
# Fork archives include unchanged generated library sources from the releases.
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
