# Crypto backend licenses and source

The backend uses the DMOD forks of Mbed TLS 4.1.1 and TF-PSA-Crypto 1.1.1.
This project elects the Apache-2.0 option offered by those distributions;
the upstream full license notices are retained here and shipped with the module.
Source files retain the upstream copyright and SPDX notices.

Reviewed sources (archive SHA-256 values are enforced in cmake/backend.cmake):

- [Mbed TLS fork, 41853d1](https://github.com/choco-technologies/mbedtls/commit/41853d1d2a94a92f97fe70fbc1d5c14e19d79d25)
- [TF-PSA-Crypto fork, a119c22](https://github.com/choco-technologies/TF-PSA-Crypto/commit/a119c22d541a783aab6f0c5b68047f5d81d1969a)

The adaptation uses DMOD_GLOBAL_POINTER, initializes backend tables at module
startup, and stores immutable descriptor text inline. Cryptographic algorithms,
constants and verification policy remain upstream implementations. The forks'
README-DMOD.md files describe the integration and generated-source provenance.
No DMOD loader or file-format extension is required.
