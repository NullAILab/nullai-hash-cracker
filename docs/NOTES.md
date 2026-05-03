# Architecture Notes — Hash Cracker

## Why implement hashes from scratch?

Using OpenSSL or system crypto APIs would hide the algorithm internals. The
point of this project is to understand *how* MD5/SHA-1/SHA-256 work: the
Merkle-Damgård construction, padding rules, round functions, and constants.
Implementing from RFC/FIPS specs builds that understanding and produces
directly auditable code.

Each implementation matches the reference test vectors from its spec:
- MD5 "abc" → 900150983cd24fb0d6963f7d28e17f72
- SHA-1 "abc" → a9993e364706816aba3e25717850c26c9cd0d89d
- SHA-256 "abc" → ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f492b56e84a7ff9

## Brute-force: recursive depth-first search

The `bf_recurse` function builds candidate strings character by character up
to `max_len`. It is depth-first, which means "a", "aa", "aaa", ... "aaaa",
"aaab", ... This is equivalent to counting in base N (charset size).

For a 26-letter lowercase alphabet, max_len=4, the keyspace is:
    26 + 26² + 26³ + 26⁴ = 475,254 candidates

At ~10M SHA-256/s on a modern CPU that completes in ~50ms. For max_len=6 the
keyspace grows to ~320M — manageable for MD5 but slower for SHA-256.

## Dictionary attack

A linear scan of the wordlist with early exit on first match. The hash
comparison is done in lowercase hex (normalised on both sides) to handle
mixed-case hash strings from various tools.

## Hash identification

Length-based detection is not definitive — multiple algorithms can produce
the same digest length in theory — but for the three supported algorithms:
- 32 hex chars = 128 bits → always MD5
- 40 hex chars = 160 bits → almost always SHA-1
- 64 hex chars = 256 bits → SHA-256 or SHA3-256 (we assume the former)

## Performance note

This is a single-threaded educational implementation. Production crackers
(hashcat, John the Ripper) use:
- GPU parallelism (CUDA/OpenCL) — 10–100× faster
- Optimised SIMD inner loops
- Rule engines for word mangling
- Rainbow tables for time-space tradeoffs
