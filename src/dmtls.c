#define DMOD_ENABLE_REGISTRATION ON
#include "dmtls_internal.h"

int dmod_init(const Dmod_Config_t* config) {(void)config; return dmtls_module_init();}
int dmod_deinit(void) {return dmtls_module_deinit();}

dmod_dmtls_api_declaration(1.0, dmtls_result_t, _initialize, (const dmtls_platform_t* platform))
{return dmtls_platform_initialize(platform);}
dmod_dmtls_api_declaration(1.0, dmtls_result_t, _shutdown, (void))
{return dmtls_platform_shutdown();}

dmod_dmtls_api_declaration(1.0, dmtls_result_t, _config_create, (const void* ca, size_t size, dmtls_config_t* output))
{
    if (output == NULL) return DMTLS_ERR_ARGUMENT;
    *output = NULL;
    dmtls_result_t rc = dmtls_enter(); if (rc != DMTLS_OK) return rc;
    rc = dmtls_config_new(ca, size, output); dmtls_leave(); return rc;
}
dmod_dmtls_api_declaration(1.0, dmtls_result_t, _config_destroy, (dmtls_config_t config))
{
    dmtls_result_t rc = dmtls_enter(); if (rc != DMTLS_OK) return rc;
    rc = dmtls_config_free(config); dmtls_leave(); return rc;
}
dmod_dmtls_api_declaration(1.0, dmtls_result_t, _connection_create,
    (dmtls_config_t config, const char* hostname, const dmtls_transport_t* transport,
     uint32_t handshake_timeout_ms, uint32_t io_timeout_ms, dmtls_connection_t* output))
{
    if (output == NULL) return DMTLS_ERR_ARGUMENT;
    *output = NULL;
    dmtls_result_t rc = dmtls_enter(); if (rc != DMTLS_OK) return rc;
    rc = dmtls_connection_new(config, hostname, transport, handshake_timeout_ms, io_timeout_ms, output);
    dmtls_leave(); return rc;
}
dmod_dmtls_api_declaration(1.0, dmtls_result_t, _connection_destroy, (dmtls_connection_t connection))
{
    dmtls_result_t rc = dmtls_enter(); if (rc != DMTLS_OK) return rc;
    if (!dmtls_valid_connection(connection)) rc = DMTLS_ERR_ARGUMENT;
    else dmtls_connection_free(connection);
    dmtls_leave(); return rc;
}
dmod_dmtls_api_declaration(1.0, dmtls_result_t, _handshake, (dmtls_connection_t connection))
{
    dmtls_result_t rc = dmtls_enter(); if (rc != DMTLS_OK) return rc;
    rc = dmtls_valid_connection(connection) ? dmtls_do_handshake(connection) : DMTLS_ERR_ARGUMENT;
    dmtls_leave(); return rc;
}
dmod_dmtls_api_declaration(1.0, dmtls_result_t, _read, (dmtls_connection_t connection, void* buffer, size_t capacity, size_t* received))
{
    if (received == NULL) return DMTLS_ERR_ARGUMENT;
    *received = 0;
    if (buffer == NULL || capacity == 0) return DMTLS_ERR_ARGUMENT;
    dmtls_result_t rc = dmtls_enter(); if (rc != DMTLS_OK) return rc;
    rc = dmtls_valid_connection(connection) ? dmtls_do_read(connection, buffer, capacity, received) : DMTLS_ERR_ARGUMENT;
    dmtls_leave(); return rc;
}
dmod_dmtls_api_declaration(1.0, dmtls_result_t, _write, (dmtls_connection_t connection, const void* buffer, size_t size, size_t* sent))
{
    if (sent == NULL) return DMTLS_ERR_ARGUMENT;
    *sent = 0;
    if (buffer == NULL || size == 0) return DMTLS_ERR_ARGUMENT;
    dmtls_result_t rc = dmtls_enter(); if (rc != DMTLS_OK) return rc;
    rc = dmtls_valid_connection(connection) ? dmtls_do_write(connection, buffer, size, sent) : DMTLS_ERR_ARGUMENT;
    dmtls_leave(); return rc;
}
dmod_dmtls_api_declaration(1.0, dmtls_result_t, _close, (dmtls_connection_t connection))
{
    dmtls_result_t rc = dmtls_enter(); if (rc != DMTLS_OK) return rc;
    rc = dmtls_valid_connection(connection) ? dmtls_do_close(connection) : DMTLS_ERR_ARGUMENT;
    dmtls_leave(); return rc;
}
dmod_dmtls_api_declaration(1.0, dmtls_result_t, _status, (dmtls_connection_t connection, dmtls_status_t* status))
{
    if (status == NULL) return DMTLS_ERR_ARGUMENT;
    *status = (dmtls_status_t){0};
    dmtls_result_t rc = dmtls_enter(); if (rc != DMTLS_OK) return rc;
    if (!dmtls_valid_connection(connection)) rc = DMTLS_ERR_ARGUMENT;
    else *status = connection->status;
    dmtls_leave(); return rc;
}
