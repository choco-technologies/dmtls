#ifndef DMTLS_H
#define DMTLS_H
#include <stddef.h>
#include <stdint.h>
#include "dmtls_defs.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct dmtls_config* dmtls_config_t;
typedef struct dmtls_connection* dmtls_connection_t;
typedef enum {
    DMTLS_OK = 0, DMTLS_WANT_READ = 1, DMTLS_WANT_WRITE = 2,
    DMTLS_PEER_CLOSED = 3,
    DMTLS_ERR_ARGUMENT = -1, DMTLS_ERR_MEMORY = -2, DMTLS_ERR_STATE = -3,
    DMTLS_ERR_ENTROPY = -4, DMTLS_ERR_TIME = -5, DMTLS_ERR_CERTIFICATE = -6,
    DMTLS_ERR_PROTOCOL = -7, DMTLS_ERR_TRANSPORT = -8, DMTLS_ERR_BUSY = -9,
    DMTLS_ERR_LIMIT = -10, DMTLS_ERR_TRUNCATED = -11, DMTLS_ERR_TIMEOUT = -12
} dmtls_result_t;
typedef enum {
    DMTLS_STATE_NEW, DMTLS_STATE_HANDSHAKE, DMTLS_STATE_OPEN,
    DMTLS_STATE_PEER_CLOSED, DMTLS_STATE_CLOSING, DMTLS_STATE_CLOSED,
    DMTLS_STATE_FAILED
} dmtls_state_t;
/* Entropy callback fills the whole buffer with strong entropy or returns error.
 * It feeds the backend's DRBG, not TLS directly. No fallback is provided.
 * UTC is read from dmutc. Deadlines use the dmosi monotonic tick counter. */
typedef int (*dmtls_entropy_fn)(void*, uint8_t*, size_t);
typedef struct {
    dmtls_entropy_fn entropy;
    void* user;
    size_t heap_limit; /* Total TLS allocation budget, including context metadata. */
    uint32_t max_connections;
} dmtls_platform_t;
/* Transport callbacks must never block or reenter dmtls. OK reports a positive
 * byte count, receive OK/0 reports TCP EOF, WANT_* reports no progress. */
typedef dmtls_result_t (*dmtls_send_fn)(void*, const uint8_t*, size_t, size_t*);
typedef dmtls_result_t (*dmtls_recv_fn)(void*, uint8_t*, size_t, size_t*);
typedef struct { dmtls_send_fn send; dmtls_recv_fn receive; void* user; } dmtls_transport_t;
typedef struct {
    dmtls_state_t state;
    dmtls_result_t error;
    uint32_t verification_flags; /* Stable DMTLS_VERIFY_* bits, not backend ABI. */
} dmtls_status_t;
#define DMTLS_VERIFY_UNTRUSTED 1u
#define DMTLS_VERIFY_HOSTNAME 2u
#define DMTLS_VERIFY_EXPIRED 4u
#define DMTLS_VERIFY_FUTURE 8u
#define DMTLS_VERIFY_OTHER 16u
/* Platform callbacks and user data remain valid until shutdown. Initialize and
 * shutdown are lifecycle operations, externally serialized against all users. */
dmod_dmtls_api(1.0, dmtls_result_t, _initialize, (const dmtls_platform_t* platform));
dmod_dmtls_api(1.0, dmtls_result_t, _shutdown, (void));
/* CA bytes are PEM (NUL not required) or one DER certificate. They are copied.
 * Configuration is immutable and shared; destroy returns BUSY while in use. */
dmod_dmtls_api(1.0, dmtls_result_t, _config_create, (const void* ca, size_t size, dmtls_config_t* output));
dmod_dmtls_api(1.0, dmtls_result_t, _config_destroy, (dmtls_config_t config));
/* Hostname is mandatory, copied, and used for both SNI and peer verification.
 * Transport is borrowed: dmtls never opens or closes the underlying socket.
 * Handshake deadline starts at create; io timeout applies across WANT retries. */
dmod_dmtls_api(1.0, dmtls_result_t, _connection_create,
    (dmtls_config_t config, const char* hostname, const dmtls_transport_t* transport,
     uint32_t handshake_timeout_ms, uint32_t io_timeout_ms, dmtls_connection_t* output));
dmod_dmtls_api(1.0, dmtls_result_t, _connection_destroy, (dmtls_connection_t connection));
dmod_dmtls_api(1.0, dmtls_result_t, _handshake, (dmtls_connection_t connection));
/* Nonblocking operations. Retry writes with the identical bytes/length after
 * WANT_*; the caller retains the buffer until write succeeds or fails. */
dmod_dmtls_api(1.0, dmtls_result_t, _read, (dmtls_connection_t connection, void* buffer, size_t capacity, size_t* received));
dmod_dmtls_api(1.0, dmtls_result_t, _write, (dmtls_connection_t connection, const void* buffer, size_t size, size_t* sent));
dmod_dmtls_api(1.0, dmtls_result_t, _close, (dmtls_connection_t connection));
dmod_dmtls_api(1.0, dmtls_result_t, _status, (dmtls_connection_t connection, dmtls_status_t* status));
#ifdef __cplusplus
}
#endif
#endif
