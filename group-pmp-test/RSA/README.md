# RSA2048 native benchmark adapter

The checked-in Mbed TLS 4.2 tree delegates public-key primitives to its
`tf-psa-crypto` submodule, but that submodule is not populated in this source
tree. Copying only the visible Mbed TLS files would therefore omit the MPI,
entropy and RSA implementation.

`rsa2048_bench.c` keeps the benchmark-facing RSA code in this directory and
uses the target system's OpenSSL `libcrypto` implementation. Key generation is
performed outside the measured interval. Timed RSA rows include a streaming
SHA-256 pass over the requested data followed by one RSA-2048 PSS sign or
verify operation.
