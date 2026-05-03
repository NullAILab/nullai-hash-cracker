# Hash Cracker

![C++](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

> **Difficulty:** Beginner | **Language:** C++17 | **Build:** CMake

Hash computation and cracking tool with MD5, SHA-1, and SHA-256 implemented from scratch — no OpenSSL or external dependencies. Supports dictionary attacks against a wordlist and brute-force attacks over a configurable charset. Useful for learning how hash algorithms work internally and why unsalted hashes are weak password storage.

---

## Project Structure

```
08-hash-cracker/
├── README.md
├── .gitignore
├── src/
│   ├── hash.h / hash.cpp      ← MD5, SHA-1, SHA-256 (RFC / FIPS implementations)
│   ├── cracker.h / cracker.cpp ← Dictionary + brute-force attack engines
│   ├── main.cpp               ← CLI: hash / id / dict / brute
│   └── CMakeLists.txt
└── docs/
    └── NOTES.md
```

---

## Build

```bash
cd src
mkdir build && cd build
cmake ..
make -j$(nproc)       # Linux/macOS
# or: cmake --build . --config Release  (Windows)
```

---

## Usage

```bash
# Compute a hash
./hash-cracker hash md5    "hello"
./hash-cracker hash sha1   "hello"
./hash-cracker hash sha256 "hello"

# Identify hash type by length
./hash-cracker id 5d41402abc4b2a76b9719d911017c592
# → md5

# Dictionary attack
./hash-cracker dict 5d41402abc4b2a76b9719d911017c592 rockyou.txt

# Brute-force — lowercase letters, up to 4 chars
./hash-cracker brute 5d41402abc4b2a76b9719d911017c592

# Brute-force — custom charset and length
./hash-cracker brute <hash> --charset "abc123" --max-len 6

# Force algorithm (e.g. for SHA-256 with custom length)
./hash-cracker brute <hash> --algo sha256 --max-len 4
```

**Example output:**
```
[*] Target    : 5d41402abc4b2a76b9719d911017c592 (md5)
[*] Loaded    : 14 344 391 words
[*] Tested: 54 321
[+] CRACKED!
    Hash      : 5d41402abc4b2a76b9719d911017c592
    Plaintext : hello
    Attempts  : 54 321
    Time      : 0.031s
    Rate      : 1 752 290 hash/s
```

---

## Algorithm Details

All three algorithms are implemented directly from specs with no external dependencies:

| Algorithm | Spec | Digest | Block size |
|-----------|------|--------|-----------|
| MD5 | RFC 1321 | 128 bit | 512 bit |
| SHA-1 | FIPS 180-4 | 160 bit | 512 bit |
| SHA-256 | FIPS 180-4 | 256 bit | 512 bit |

Test vectors verified:
- MD5 `""` → `d41d8cd98f00b204e9800998ecf8427e`
- SHA-1 `"abc"` → `a9993e364706816aba3e25717850c26c9cd0d89d`
- SHA-256 `"abc"` → `ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f492b56e84a7ff9`

---

---

## Challenges & Extensions

- Add **MD4 and NTLM** (same algorithm, used in Windows password hashes)
- Add **rule-based mutations** (append digits, l33t-speak substitution)
- Add **multi-threading** with `std::thread` worker pool over the wordlist
- Add **rainbow table** generation and lookup
- Add **bcrypt** support using a third-party library (slow hash, educational contrast)
- Measure and compare throughput vs. `openssl speed md5`

---

## References

- [RFC 1321 — MD5](https://tools.ietf.org/html/rfc1321)
- [FIPS 180-4 — SHA Family](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [Why MD5/SHA-1 are broken for passwords](https://crackstation.net/hashing-security.htm)
- MITRE ATT&CK: [T1110.002 — Password Cracking](https://attack.mitre.org/techniques/T1110/002/)

---

