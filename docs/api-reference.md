# dmtls API

Include `dmtls.h`. All functions use stable `dmtls_result_t` values rather than
backend error numbers. Output handles/counts are cleared before failure.
Opaque handles remain valid until explicitly destroyed; handles absent from the live registry
are rejected by registry membership without dereferencing the supplied pointer.
Concurrent destruction/use and module enable/disable require caller coordination.

## Lifecycle and ownership

`initialize(platform)` requires a full-buffer strong-entropy callback, its
context, a heap limit of at least 32768 bytes and a nonzero connection limit.
The callback is used by a CTR-DRBG. An error during entropy collection fails
closed; no host device, deterministic seed or weak fallback is substituted.
Initialization while already initialized returns BUSY.

`shutdown()` releases PSA crypto state, but returns BUSY while a configuration
or connection exists. After shutdown, initialize can be called again. The
module cannot deinitialize while it has live objects.

`config_create(ca, size, &config)` copies and parses an explicit CA PEM bundle
(NUL optional) or one DER certificate. Empty, malformed and partially invalid
bundles are rejected. Input is bounded to 256 KiB and the global allocation
budget still applies. Peer verification is always REQUIRED; the configuration
is immutable. `config_destroy(config)` returns BUSY while referenced.

`connection_create(config, hostname, transport, handshake_ms, io_ms, &connection)`
creates a client session. Hostname is copied and used for verification and SNI;
empty/oversized or malformed names are rejected. DNS hostnames and IPv4 literals
are accepted; colon-bearing IPv6 literals are not exposed by this interface.
Both deadlines must be in 1..INT32_MAX milliseconds. Handshake time starts at
creation; an I/O deadline spans all WANT retries of one logical operation.

`connection_destroy(connection)` frees TLS state after success or failure;
it does not invoke transport close or implicitly perform a TLS handshake.
Caller callback functions and their context must remain valid until destruction.

## Nonblocking operations

`handshake(connection)` checks dmutc readiness on every step, verifies chain,
hostname and certificate validity periods, then transitions NEW/HANDSHAKE to
OPEN. Dates are checked for each verified certificate, including the trust
anchor, and the retained peer chain is rechecked at completion. UTC failure
produces ERR_TIME; verification failure produces ERR_CERTIFICATE. No application
data is released before successful authentication.

`read(connection, buffer, capacity, &received)` and
`write(connection, buffer, size, &sent)` return OK on positive progress,
WANT_READ/WANT_WRITE when the transport must become ready, or an error.
A write can succeed partially. After WANT, repeat the same logical operation;
write pointer/size/bytes must remain unchanged. Switching operation while one
is pending returns BUSY. Read may use another buffer on retry. Zero-sized
application reads/writes are rejected. Deadline expiry fails the connection.

`close(connection)` sends close_notify and can also require WANT retries. It
is idempotent after success. PEER_CLOSED indicates an authenticated peer
close_notify; a bare TCP close produces ERR_TRUNCATED. Close is not a wait for
TCP shutdown or confirmation of application-level delivery.

`status(connection, &status)` returns state, persistent error and stable
verification bits: UNTRUSTED, HOSTNAME, EXPIRED, FUTURE, OTHER. Flags provide
failure diagnostics; they never authorize overriding verification.

## Transport contract

The send/receive callbacks must not block or reenter dmtls. Set the count to
zero unless returning OK. Send OK requires a count in 1..requested; receive
OK permits zero only to indicate transport EOF. WANT reports no consumed bytes.
An impossible count or callback error fails the connection as ERR_TRANSPORT.
TLS never calls blocking OS networking or sleeps while waiting for bytes.
Cryptographic processing itself is synchronous within a library call.

The recursive global lock serializes access to PSA globals and the allocator.
Reentry from a callback returns BUSY; callers on other tasks wait for the current
step. This provides thread safety without enabling an OS-specific crypto ABI.
