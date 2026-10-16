# dmtls

Transport-independent TLS client library for DMOD, backed by Mbed TLS 4.1.1
and TF-PSA-Crypto 1.1.1. It supports TLS 1.2 and TLS 1.3, certificate chains,
hostname verification and SNI, with ECDHE and RSA/ECDSA authentication.
The backend is compiled into this module; its headers and ABI are private.

Certificate time comes from **dmutc**. Missing, unset or stopped UTC fails the
handshake. Applications provide an explicit strong-entropy callback, used to
seed/reseed the backend DRBG, and nonblocking byte-stream transport callbacks.
There is no software entropy fallback, implicit device path, system CA store
or option to disable certificate verification.

## Build

```sh
cmake -S . -B build/native -DDMOD_DIR=/path/to/dmod
cmake --build build/native --parallel
ctest --test-dir build/native --output-on-failure
```

Use an updated DMOD SDK, runtime and matching metadata tools with absolute
pointer relocation support; older loaders reject this module's extended header.
The CI helper builds matching tools from SDK source.

For Cortex-M7 use `-DDMOD_TOOLS_NAME=arch/armv7/cortex-m7` in a separate build
directory. Direct DMOD dependencies (`dmosi`, `dmutc`) are unversioned; the
packager resolves them. The upstream crypto source archive is pinned with a
SHA-256 hash for reproducibility. Its licenses are included in the package. The validated Cortex-M7 build is about
111.4 KiB compressed (137.5 KiB loaded image), plus TLS heap.

## Use

1. Enable the board's entropy provider and UTC service. dmutc receives its RTC
   source through dmdevfs/libsystemd device rules.
2. Call `dmtls_initialize()` once with the entropy callback, allocation budget
   and maximum connection count. The callback/context must remain valid until
   shutdown. An application adapter can call `dmrng_fill()`; dmtls itself does
   not depend on that hardware driver.
3. Create an immutable configuration from explicit PEM CA certificates or one
   DER CA certificate, then create a connection with the expected hostname,
   transport callbacks and finite handshake/I/O deadlines.
4. Drive handshake/read/write/close. On WANT_READ/WANT_WRITE, wait for transport
   readiness **outside** dmtls, then retry. A partial successful write advances
   the caller's buffer; a WANT retry retains the exact pointer, size and bytes.
5. Destroy connections, destroy configurations, then shut down. The caller owns
   the underlying transport; dmtls never opens or closes its socket.

Configurations can be shared by connections. Destroying an in-use configuration
or shutting down with live handles returns BUSY. Engine calls are serialized
with a recursive dmosi mutex; callback reentry is rejected rather than recursed.
Lifecycle operations must be externally serialized with users.

## Resource and protocol boundaries

- All TLS allocations, including context metadata, count toward `heap_limit`.
  The minimum accepted limit is 32 KiB; realistic handshakes need more. A
  configured quota can fail an operation cleanly; it does not promise that
  every CA chain fits. Freed TLS allocations are wiped.
- Incoming plaintext records can be 16 KiB; outgoing records are limited to
  4 KiB. This remains compatible with peers that do not negotiate smaller
  fragments. Deadlines use monotonic dmosi ticks, with wrap-safe elapsed time.
- TCP EOF without authenticated close_notify is a truncation error. Failed
  connections cannot be reused. Destroy remains available after failure.
- Client authentication, TLS servers, DTLS, renegotiation, 0-RTT, session
  persistence and automatic revocation fetching are not provided. No certificate
  or RNG callback is allowed to silently weaken authentication.
- RTC readiness does not prove that its UTC value is authentic or accurate;
  provisioning/synchronization remains an application responsibility.

See [API reference](docs/api-reference.md) and [validation](docs/testing.md).
