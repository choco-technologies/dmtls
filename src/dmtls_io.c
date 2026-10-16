#include "dmtls_internal.h"

dmtls_result_t dmtls_fail(dmtls_connection_t c, dmtls_result_t error)
{
    c->status.error = error; c->status.state = DMTLS_STATE_FAILED;
    c->pending_operation = 0; c->pending_write = NULL; c->pending_size = 0;
    return error;
}
dmtls_result_t dmtls_backend_result(dmtls_connection_t c, int result)
{
    if (c->callback_error != DMTLS_OK) return dmtls_fail(c, c->callback_error);
    if (result == MBEDTLS_ERR_SSL_WANT_READ) return DMTLS_WANT_READ;
    if (result == MBEDTLS_ERR_SSL_WANT_WRITE) return DMTLS_WANT_WRITE;
    if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        c->status.state = DMTLS_STATE_PEER_CLOSED; c->pending_operation = 0;
        return DMTLS_PEER_CLOSED;
    }
    uint32_t flags = mbedtls_ssl_get_verify_result(&c->backend);
    c->status.verification_flags |= dmtls_verify_bits(flags);
    dmtls_result_t error = DMTLS_ERR_PROTOCOL;
    if (result == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED || c->status.verification_flags != 0)
        error = DMTLS_ERR_CERTIFICATE;
    else if (result == MBEDTLS_ERR_SSL_ALLOC_FAILED) error = DMTLS_ERR_MEMORY;
    else if (result == MBEDTLS_ERR_SSL_CONN_EOF || result == 0) error = DMTLS_ERR_TRUNCATED;
    return dmtls_fail(c, error);
}
static dmtls_result_t begin(dmtls_connection_t c, unsigned operation)
{
    if (c->status.state == DMTLS_STATE_FAILED) return c->status.error;
    if (c->status.state == DMTLS_STATE_PEER_CLOSED && operation == 1) return DMTLS_PEER_CLOSED;
    if (c->status.state != DMTLS_STATE_OPEN &&
        !(operation == 3 && (c->status.state == DMTLS_STATE_PEER_CLOSED || c->status.state == DMTLS_STATE_CLOSING)))
        return DMTLS_ERR_STATE;
    if (c->pending_operation != 0 && c->pending_operation != operation) return DMTLS_ERR_BUSY;
    if (c->pending_operation == 0) {c->pending_operation = operation; c->io_started = dmosi_get_tick_count();}
    if ((uint32_t)(dmosi_get_tick_count() - c->io_started) >= c->io_timeout)
        return dmtls_fail(c, DMTLS_ERR_TIMEOUT);
    c->callback_error = DMTLS_OK; return DMTLS_OK;
}
dmtls_result_t dmtls_do_read(dmtls_connection_t c, void* buffer, size_t size, size_t* received)
{
    dmtls_result_t rc = begin(c, 1); if (rc != DMTLS_OK) return rc;
    int n = mbedtls_ssl_read(&c->backend, buffer, size);
    if ((uint32_t)(dmosi_get_tick_count() - c->io_started) >= c->io_timeout) return dmtls_fail(c, DMTLS_ERR_TIMEOUT);
    if (n <= 0) return dmtls_backend_result(c, n);
    *received = (size_t)n; c->pending_operation = 0; return DMTLS_OK;
}
dmtls_result_t dmtls_do_write(dmtls_connection_t c, const void* buffer, size_t size, size_t* sent)
{
    if (c->pending_operation == 2 && (c->pending_write != buffer || c->pending_size != size)) return DMTLS_ERR_ARGUMENT;
    dmtls_result_t rc = begin(c, 2); if (rc != DMTLS_OK) return rc;
    c->pending_write = buffer; c->pending_size = size;
    int n = mbedtls_ssl_write(&c->backend, buffer, size);
    if ((uint32_t)(dmosi_get_tick_count() - c->io_started) >= c->io_timeout) return dmtls_fail(c, DMTLS_ERR_TIMEOUT);
    if (n <= 0) return dmtls_backend_result(c, n);
    *sent = (size_t)n; c->pending_operation = 0; c->pending_write = NULL; c->pending_size = 0;
    return DMTLS_OK;
}
dmtls_result_t dmtls_do_close(dmtls_connection_t c)
{
    if (c->status.state == DMTLS_STATE_CLOSED) return DMTLS_OK;
    dmtls_result_t rc = begin(c, 3); if (rc != DMTLS_OK) return rc;
    c->status.state = DMTLS_STATE_CLOSING;
    int n = mbedtls_ssl_close_notify(&c->backend);
    if ((uint32_t)(dmosi_get_tick_count() - c->io_started) >= c->io_timeout) return dmtls_fail(c, DMTLS_ERR_TIMEOUT);
    if (n != 0) return dmtls_backend_result(c, n);
    c->status.state = DMTLS_STATE_CLOSED; c->pending_operation = 0; return DMTLS_OK;
}
