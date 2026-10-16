#include "dmtls_internal.h"
#include "dmtls_platform.h"
#include <string.h>
#include <limits.h>

static int compare_time(const dmutc_calendar_t* a, const mbedtls_x509_time* b)
{
    const int x[] = {a->year,a->month,a->day,a->hour,a->minute,a->second};
    const int y[] = {b->year,b->mon,b->day,b->hour,b->min,b->sec};
    for (unsigned i=0;i<6;++i) if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
    return 0;
}
uint32_t dmtls_verify_bits(uint32_t flags)
{
    uint32_t bits = 0;
    if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) bits |= DMTLS_VERIFY_UNTRUSTED;
    if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH) bits |= DMTLS_VERIFY_HOSTNAME;
    if (flags & MBEDTLS_X509_BADCERT_EXPIRED) bits |= DMTLS_VERIFY_EXPIRED;
    if (flags & MBEDTLS_X509_BADCERT_FUTURE) bits |= DMTLS_VERIFY_FUTURE;
    if (flags & ~(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_CN_MISMATCH |
        MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE)) bits |= DMTLS_VERIFY_OTHER;
    return bits;
}
static int verify(void* user, mbedtls_x509_crt* cert, int depth, uint32_t* flags)
{
    (void)depth;
    dmtls_connection_t c = user;
    if (compare_time(&c->utc, &cert->valid_from) < 0) *flags |= MBEDTLS_X509_BADCERT_FUTURE;
    if (compare_time(&c->utc, &cert->valid_to) > 0) *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
    c->status.verification_flags |= dmtls_verify_bits(*flags);
    return 0; /* Never clears or suppresses backend verification flags. */
}
static int send_bytes(void* user, const unsigned char* data, size_t size)
{
    dmtls_connection_t c = user; size_t sent = 0;
    dmtls_result_t rc = c->transport.send(c->transport.user, data, size, &sent);
    if (rc == DMTLS_WANT_READ || rc == DMTLS_WANT_WRITE) {
        if (sent != 0) goto error;
        return rc == DMTLS_WANT_READ ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    if (rc != DMTLS_OK || sent == 0 || sent > size || sent > INT_MAX) goto error;
    return (int)sent;
error:
    c->callback_error = DMTLS_ERR_TRANSPORT; return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static int receive_bytes(void* user, unsigned char* data, size_t size)
{
    dmtls_connection_t c = user; size_t received = 0;
    dmtls_result_t rc = c->transport.receive(c->transport.user, data, size, &received);
    if (rc == DMTLS_WANT_READ || rc == DMTLS_WANT_WRITE) {
        if (received != 0) goto error;
        return rc == DMTLS_WANT_READ ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    if (rc != DMTLS_OK || received > size || received > INT_MAX) goto error;
    if (received == 0) c->callback_error = DMTLS_ERR_TRUNCATED;
    return (int)received;
error:
    c->callback_error = DMTLS_ERR_TRANSPORT; return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
dmtls_result_t dmtls_connection_new(dmtls_config_t config, const char* host,
    const dmtls_transport_t* transport, uint32_t handshake_ms, uint32_t io_ms, dmtls_connection_t* output)
{
    if (!dmtls_valid_config(config) || host == NULL || transport == NULL ||
        transport->send == NULL || transport->receive == NULL || handshake_ms == 0 ||
        io_ms == 0 || handshake_ms > INT32_MAX || io_ms > INT32_MAX) return DMTLS_ERR_ARGUMENT;
    size_t length = 0;
    while (host[length] != 0 && length <= 253) {
        unsigned char ch = (unsigned char)host[length++];
        if (ch <= 32 || ch >= 127 || ch == '/' || ch == '\\' || ch == ':') return DMTLS_ERR_ARGUMENT;
    }
    if (length == 0 || length > 253) return DMTLS_ERR_ARGUMENT;
    if (dmtls_connections >= dmtls_platform.max_connections || config->references == UINT32_MAX) return DMTLS_ERR_LIMIT;
    dmtls_connection_t c = dmtls_backend_calloc(1, sizeof(*c));
    if (c == NULL) return DMTLS_ERR_MEMORY;
    c->config = config; c->transport = *transport;
    c->handshake_timeout = handshake_ms; c->io_timeout = io_ms;
    c->handshake_started = dmosi_get_tick_count();
    mbedtls_ssl_init(&c->backend);
    int rc = mbedtls_ssl_setup(&c->backend, &config->backend);
    if (rc == 0) rc = mbedtls_ssl_set_hostname(&c->backend, host);
    if (rc != 0) {mbedtls_ssl_free(&c->backend); dmtls_backend_free(c); return DMTLS_ERR_MEMORY;}
    mbedtls_ssl_set_verify(&c->backend, verify, c);
    mbedtls_ssl_set_bio(&c->backend, c, send_bytes, receive_bytes, NULL);
    c->magic = DMTLS_CONNECTION_MAGIC; c->status.state = DMTLS_STATE_NEW;
    ++config->references; ++dmtls_connections;
    c->next = dmtls_connection_list; dmtls_connection_list = c;
    *output = c; return DMTLS_OK;
}
void dmtls_connection_free(dmtls_connection_t c)
{
    dmtls_connection_t* slot = &dmtls_connection_list;
    while (*slot != c) slot = &(*slot)->next;
    *slot = c->next; --c->config->references; --dmtls_connections;
    mbedtls_ssl_free(&c->backend); dmtls_backend_free(c);
}
dmtls_result_t dmtls_do_handshake(dmtls_connection_t c)
{
    if (c->status.state == DMTLS_STATE_FAILED) return c->status.error;
    if (c->status.state == DMTLS_STATE_OPEN) return DMTLS_OK;
    if (c->status.state != DMTLS_STATE_NEW && c->status.state != DMTLS_STATE_HANDSHAKE) return DMTLS_ERR_STATE;
    if ((uint32_t)(dmosi_get_tick_count() - c->handshake_started) >= c->handshake_timeout)
        return dmtls_fail(c, DMTLS_ERR_TIMEOUT);
    if (dmtls_refresh_utc(c) != DMTLS_OK) return dmtls_fail(c, DMTLS_ERR_TIME);
    c->status.state = DMTLS_STATE_HANDSHAKE;
    c->callback_error = DMTLS_OK;
    int rc = mbedtls_ssl_handshake(&c->backend);
    if ((uint32_t)(dmosi_get_tick_count() - c->handshake_started) >= c->handshake_timeout)
        return dmtls_fail(c, DMTLS_ERR_TIMEOUT);
    if (rc != 0) return dmtls_backend_result(c, rc);
    /* Recheck dates at completion as a handshake can span UTC adjustments. */
    const mbedtls_x509_crt* cert = mbedtls_ssl_get_peer_cert(&c->backend);
    if (cert == NULL) return dmtls_fail(c, DMTLS_ERR_CERTIFICATE);
    for (; cert != NULL; cert = cert->next) {
        uint32_t flags = 0; verify(c, (mbedtls_x509_crt*)cert, 0, &flags);
        if (flags != 0) return dmtls_fail(c, DMTLS_ERR_CERTIFICATE);
    }
    c->status.verification_flags |= dmtls_verify_bits(mbedtls_ssl_get_verify_result(&c->backend));
    if (c->status.verification_flags != 0) return dmtls_fail(c, DMTLS_ERR_CERTIFICATE);
    c->status.state = DMTLS_STATE_OPEN; return DMTLS_OK;
}
