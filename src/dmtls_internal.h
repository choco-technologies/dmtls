#ifndef DMTLS_INTERNAL_H
#define DMTLS_INTERNAL_H
#include "dmod.h"
#include "dmtls.h"
#include "dmosi.h"
#include "dmutc.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#include "psa/crypto_extra.h"
#include <stdbool.h>
#define DMTLS_CONFIG_MAGIC 0x544C5343u
#define DMTLS_CONNECTION_MAGIC 0x544C534Eu
#define DMTLS_MAX_CA_SIZE (256u * 1024u)
struct dmtls_config {
    struct dmtls_config* next;
    uint32_t magic;
    uint32_t references;
    mbedtls_ssl_config backend;
    mbedtls_x509_crt ca;
};
struct dmtls_connection {
    struct dmtls_connection* next;
    dmutc_calendar_t utc;
    uint32_t magic;
    dmtls_config_t config;
    dmtls_transport_t transport;
    mbedtls_ssl_context backend;
    dmtls_status_t status;
    uint32_t handshake_started;
    uint32_t io_started;
    uint32_t handshake_timeout;
    uint32_t io_timeout;
    unsigned pending_operation;
    const void* pending_write;
    size_t pending_size;
    dmtls_result_t callback_error;
};
extern struct dmtls_config* dmtls_config_list;
extern struct dmtls_connection* dmtls_connection_list;
extern dmtls_platform_t dmtls_platform;
extern dmosi_mutex_t dmtls_lock;
extern bool dmtls_initialized;
extern uint32_t dmtls_configs;
extern uint32_t dmtls_connections;
extern size_t dmtls_heap_used;
dmtls_result_t dmtls_enter(void);
int dmtls_module_init(void);
int dmtls_module_deinit(void);
dmtls_result_t dmtls_platform_initialize(const dmtls_platform_t* platform);
dmtls_result_t dmtls_platform_shutdown(void);
uint32_t dmtls_verify_bits(uint32_t flags);
dmtls_result_t dmtls_refresh_utc(dmtls_connection_t connection);
void dmtls_leave(void);
bool dmtls_valid_config(dmtls_config_t config);
bool dmtls_valid_connection(dmtls_connection_t connection);
dmtls_result_t dmtls_fail(dmtls_connection_t connection, dmtls_result_t error);
dmtls_result_t dmtls_backend_result(dmtls_connection_t connection, int result);
dmtls_result_t dmtls_config_new(const void* ca, size_t size, dmtls_config_t* output);
dmtls_result_t dmtls_config_free(dmtls_config_t config);
dmtls_result_t dmtls_connection_new(dmtls_config_t config, const char* host,
    const dmtls_transport_t* transport, uint32_t handshake_ms, uint32_t io_ms, dmtls_connection_t* output);
void dmtls_connection_free(dmtls_connection_t connection);
dmtls_result_t dmtls_do_handshake(dmtls_connection_t connection);
dmtls_result_t dmtls_do_read(dmtls_connection_t connection, void* buffer, size_t size, size_t* read);
dmtls_result_t dmtls_do_write(dmtls_connection_t connection, const void* buffer, size_t size, size_t* written);
dmtls_result_t dmtls_do_close(dmtls_connection_t connection);
#endif
