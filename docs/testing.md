# Build and validation

Supported build profiles are x86_64, Cortex-M4 and Cortex-M7. The existing
DMOD SDK, host tools and runtime are used without format changes. DMFs retain
the original 240-byte header. The backend forks use typed DMOD_GLOBAL_POINTER
slots for callbacks/coordinates and inline immutable descriptor text.

Final ELF metadata is audited at build time; it is never used to rewrite a DMF
or generate a runtime relocation table. Absolute pointers outside existing
header/API/GOT relocation sections fail the build. The audit currently reads
ARM ELF32 and x86-64 ELF64; it rejects unsupported ELF architectures explicitly.

## Native

```sh
cmake -S . -B build/native -DDMOD_DIR=/path/to/dmod
cmake --build build/native --parallel
ctest --test-dir build/native --output-on-failure
```

Three CTest entries cover different boundaries:

- `test_dmtls`: three checks in the actual DMOD module loaded by dmod_loader,
  including crypto initialization, the entropy callback, CA parsing, ownership
  and shutdown. The deterministic entropy in this fixture is for tests only;
  that test never opens a connection or protects application data.
- `tls_interoperability`: 18 checks compile the production engine and backend
  into a host test library with controllable SAL/UTC/timer providers. An
  independent OpenSSL peer exercises TLS 1.2/1.3, RSA/ECDSA certificates,
  hostname/CA/date failures, missing UTC, entropy failure, short I/O and WANT
  retries, write retry identity, truncation versus close_notify, deadlines,
  callback reentry, connection limits, malformed CA bundles and allocation
  quotas. Each test checks final TLS allocation cleanup.

- `dmtls_pointer_audit`: three regression cases prove that GOT pointers are
  accepted, a pointer embedded in a mixed static structure is rejected, and
  missing relocation metadata cannot silently disable the check.

The public test CA contains no private key. Interoperability tests generate
private keys in temporary directories; production trust stores are always
supplied explicitly by the caller.

## STM32F746G-DISCO

Build against the existing SDK with Cortex-M7 tools and the board CPU family:

```sh
cmake -S . -B build/cortex-m7 -DDMOD_DIR=/path/to/dmod \
  -DDMOD_TOOLS_NAME=arch/armv7/cortex-m7 -DDMOD_CPU_FAMILY=stm32f7 \
  -DDMTLS_BUILD_HARDWARE_PROBE=ON
cmake --build build/cortex-m7 --parallel
python3 tests/probe/make_fixtures.py build/board-fixtures
```

Install local `dmtls`, `test_dmtls` and `tlsprobe` packages into a dmod-boot test
image with hardware RNG, RTC, the rule-driven UTC service, and `rtc`,
`test_dmutc`, `test_dmrtc`, `test_dmrng` diagnostics. Use the local packages
manifest to select these artifacts. Flash the board, wait for its console,
then upload **only** ca.pem and other.pem to `/` using the boot repository's
`scripts/ymodem_send.py`. Keep every private key on the host.

```sh
python3 tests/probe/run_board.py --boot-dir /path/to/dmod-boot \
  --fixtures build/board-fixtures --port /dev/ttyACM0
```

The opt-in probe uses real dmtls, hardware RNG and rule-selected dmutc. Its
nonblocking callbacks exchange bytes through memory queues. UART waits happen
in the diagnostic application, outside TLS. It claims terminal foreground while
running; its input handle is released at process exit. Python OpenSSL MemoryBIO
provides the independent peer. This validates TLS on hardware; it does not
exercise dmtcp, HTTPS or external Internet connectivity.

Hardware validation completed with seven consecutive probes: TLS 1.2 and TLS
1.3 encrypted echo/close_notify, rejected hostname, untrusted CA, future and
expired certificates, and missing UTC. The harness then passed UTC 6/6, RTC
12/12 and RNG 6/6 checks, restored host UTC and confirmed dmutc@rtc running.
The real module's three lifecycle checks also passed on the board. Renode was
omitted as requested for this change.

Cortex-M7 artifacts measured 140388 bytes DMF and 112574 bytes DMFC (about
137.1 and 109.9 KiB). The compressed image is storage size; loading and TLS
heap need additional RAM. The diagnostic uses a 512 KiB heap quota and one
connection; 32 KiB is only the minimum accepted quota, not a handshake budget.
Raw board logs and generated fixture keys remain local under ignored build
paths, outside release resources.

Cortex-M4 was built from fresh downloads of both fork archives, verified by
SHA-256. Native tests ran with the existing installed dmod_loader/todmd tools.
Hardware firmware used the original DMOD loader revision, with no relocation
extension. The independent process/FreeRTOS lifetime fixes remain in the boot
integration. Fork changes: [Mbed TLS](https://github.com/choco-technologies/mbedtls/pull/1)
and [TF-PSA-Crypto](https://github.com/choco-technologies/TF-PSA-Crypto/pull/1).
