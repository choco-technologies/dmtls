#include "dmtls_internal.h"
#include "dmtls_platform.h"
#include <string.h>

dmtls_result_t dmtls_config_new(const void* ca, size_t size, dmtls_config_t* output)
{
    if (ca == NULL || size == 0 || size > DMTLS_MAX_CA_SIZE) return DMTLS_ERR_ARGUMENT;
    dmtls_config_t c = dmtls_backend_calloc(1, sizeof(*c));
    if (c == NULL) return DMTLS_ERR_MEMORY;
    mbedtls_ssl_config_init(&c->backend); mbedtls_x509_crt_init(&c->ca);
    unsigned char* bytes = dmtls_backend_calloc(1, size + 1);
    if (bytes == NULL) {dmtls_backend_free(c); return DMTLS_ERR_MEMORY;}
    memcpy(bytes, ca, size);
    bool pem = size >= 10 && memcmp(bytes, "-----BEGIN", 10) == 0;
    int rc = mbedtls_x509_crt_parse(&c->ca, bytes, pem ? size + (bytes[size - 1] != 0) : size);
    dmtls_backend_free(bytes);
    if (rc != 0 || c->ca.raw.p == NULL) {
        mbedtls_x509_crt_free(&c->ca); dmtls_backend_free(c); return DMTLS_ERR_CERTIFICATE;
    }
    rc = mbedtls_ssl_config_defaults(&c->backend, MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {mbedtls_x509_crt_free(&c->ca); mbedtls_ssl_config_free(&c->backend); dmtls_backend_free(c); return DMTLS_ERR_MEMORY;}
    mbedtls_ssl_conf_authmode(&c->backend, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&c->backend, &c->ca, NULL);
    mbedtls_ssl_conf_min_tls_version(&c->backend, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&c->backend, MBEDTLS_SSL_VERSION_TLS1_3);
    c->magic = DMTLS_CONFIG_MAGIC; c->next = dmtls_config_list; dmtls_config_list = c;
    ++dmtls_configs; *output = c; return DMTLS_OK;
}
dmtls_result_t dmtls_config_free(dmtls_config_t c)
{
    if (!dmtls_valid_config(c)) return DMTLS_ERR_ARGUMENT;
    if (c->references != 0) return DMTLS_ERR_BUSY;
    dmtls_config_t* slot = &dmtls_config_list;
    while (*slot != c) slot = &(*slot)->next;
    *slot = c->next;
    mbedtls_ssl_config_free(&c->backend); mbedtls_x509_crt_free(&c->ca);
    dmtls_backend_free(c); --dmtls_configs; return DMTLS_OK;
}
