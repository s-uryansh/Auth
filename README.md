# Auth: Cryptographic Registration & Authentication Protocol

C++17 implementation of a two-phase password authentication protocol using RSA-OAEP asymmetric encryption and HMAC-based verifiers. Research prototype based on the cryptographic primitives from Kelsey et al. TMPS (NIST/KU Leuven, 2019).

---

## Protocol Overview

### Notation

| Symbol | Meaning |
|--------|---------|
| `U` | Username |
| `P` | Password (plaintext, device-only) |
| `S` | 128-bit random salt (stored locally on device) |
| `B` | 128-bit random secret value |
| `R` | 128-bit server-generated nonce (stored server-side only) |
| `C` | Password hash: `C = H(S, P)` |
| `D` | HMAC verifier: `D = HMAC_B(C)` |
| `E` | Encrypted masked secret: `E = Enc(PKs, B⊕R)` |
| `ED` | Encrypted verifier: `ED = Enc(PKs, D)` |
| `PKs / SKs` | Server RSA-2048 public/private keypair |

---

### Phase 1 — Registration

```text
User Device                                         Server
───────────────────────────────────────────────────────────
Input: U                  ── U ─────────────────────────>

                                    Generate:
                          <── R ──  R <- RAND_bytes 128-bit nonce

Generate:
  S  <- RAND_bytes 128-bit salt
  B  <- RAND_bytes 128-bit secret

Compute:
  E  <- Enc(PKs, B⊕R)     # RSA-OAEP SHA-256
  C  <- SHA-256(S || P)
  D  <- HMAC-SHA256_B(C)
  ED <- Enc(PKs, D)        # RSA-OAEP SHA-256

Store locally:
  UserDB[U] <- S

Wipe: P, B, C, D, B⊕R    # OPENSSL_cleanse

Transmit: {U, E, ED} ─────────────────────────────> ServerDB[U] <- {U, R, E, ED}
```

### Phase 2 — Authentication

```text
User Device                                         Server
───────────────────────────────────────────────────────────
Input: U, P

Retrieve: S <- UserDB[U]

Compute:
  C <- SHA-256(S || P)

Wipe: P                    # OPENSSL_cleanse

Transmit: {U, C} ─────────────────────────────────>

                                    Retrieve: {R, E, ED} <- ServerDB[U]

                                    Compute:
                                      B⊕R <- Dec(SKs, E)
                                      B   <- (B⊕R) ⊕ R
                                      D   <- Dec(SKs, ED)
                                      D'  <- HMAC-SHA256_B(C)

                                    Wipe: B⊕R, B, D, D'  # OPENSSL_cleanse

                                    Verify:
                                      D == D'  ->  SUCCESS  (CRYPTO_memcmp)
                                      D != D'  ->  FAIL
```

Server never receives `P`. Wrong password → wrong `C` → wrong `D'` → no match.

---

## What Changed from V1

| | V1 | V2 |
|--|----|----|
| Encrypted value | `E = Enc(PKs, B)` | `E = Enc(PKs, B⊕R)` |
| Server stores | `{U, E, ED}` | `{U, R, E, ED}` |
| Auth decryption | `B ← Dec(SKs, E)` | `B⊕R ← Dec(SKs, E)` then `B = (B⊕R) ⊕ R` |
| Device compromise | B recoverable from E alone | B unrecoverable without R |
| Offline dict attack | Possible with device+server breach | Requires simultaneous device+server breach |

**Security rationale:** In V1, an attacker who obtains `E` (server DB) and `S` (device DB) can mount an offline dictionary attack — decrypt `E` to get `B`, then brute-force `P` by computing `HMAC_B(H(S, P'))` for each candidate. In V2, decrypting `E` yields only `B⊕R`. Without `R`, which never leaves the server, `B` cannot be recovered. Split-knowledge is now enforced cryptographically: both the device and the server must be compromised simultaneously.

---

## Project Structure

```text
Auth/
├── include/auth/
│   ├── crypto_utils.hpp   # RAII wrappers: EvpMdCtxPtr, EvpPkeyPtr, EvpPkeyCtxPtr
│   ├── server_keys.hpp    # RSA-2048 keypair singleton (GetServerKeys())
│   ├── Registration.hpp   # RegisterUser() — 4-arg (explicit R) and 3-arg (R generated internally)
│   └── Authentication.hpp # ComputeClientHash(), VerifyOnServer(), AuthenticateUser()
├── src/
│   ├── Registration.cpp   # Protocol 1 implementation
│   ├── Authentication.cpp # Protocol 2 implementation
│   └── main.cpp           # Demo: register + valid auth + invalid auth
├── tests/
│   └── test_auth.cpp      # GTest suite (1000+ tests + perf report)
├── .github/workflows/
│   └── ci.yml             # Build + test on push/PR
├── .vscode/
│   ├── c_cpp_properties.json
│   └── settings.json
├── CMakeLists.txt
├── vcpkg.json             # Dependencies: openssl, gtest
├── .clang-format
└── .clang-tidy
```

---

## Implementation Details

### `server_keys.hpp`
RSA-2048 keypair generated once via `EVP_PKEY_keygen`, stored in a static singleton `GetServerKeys()`. In production, load from HSM or persistent secure storage instead.

### `Registration.cpp`
Protocol 1 (V2): server generates `R` before registration begins; user generates `S`, `B` via `RAND_bytes`; computes `B⊕R`, then `C = SHA-256(S||P)` and `D = HMAC-SHA256_B(C)`; encrypts `B⊕R→E` and `D→ED` via RSA-OAEP SHA-256; stores `S` locally; wipes `P`, `B`, `B⊕R`, `C`, `D` via `OPENSSL_cleanse`. Server stores `{U, R, E, ED}`.

Two overloads are provided:

| Signature | Use case |
|-----------|----------|
| `RegisterUser(username, password, server_r, local_db)` | Production / main.cpp — caller supplies R from the server |
| `RegisterUser(username, password, local_db)` | Tests / simulations — R generated internally |

### `Authentication.cpp`
Three functions with explicit client/server boundary:

| Function | Boundary | What it does |
|----------|----------|-------------|
| `ComputeClientHash()` | Client | `C = SHA-256(S\|\|P)`, wipes `P` |
| `VerifyOnServer()` | Server | Validates username, decrypts `E→B⊕R`, recovers `B=(B⊕R)⊕R`, decrypts `ED→D`, recomputes `D'`, constant-time compare, wipes all intermediates |
| `AuthenticateUser()` | Wrapper | `ComputeClientHash` + `VerifyOnServer` |

---

## Security Properties

| Property | How |
|----------|-----|
| Password never transmitted | Only `C = H(S,P)` crosses wire |
| Password never stored server-side | Server holds only `{R, E, ED}` |
| Device compromise does not expose B | B unrecoverable from E without server-held R |
| Asymmetric encryption | RSA-2048 OAEP SHA-256 (`EVP_PKEY_encrypt/decrypt`) |
| Timing-safe comparison | `CRYPTO_memcmp` |
| Memory wiped after use | `OPENSSL_cleanse` on all intermediates |
| CSPRNG | `RAND_bytes` for `S`, `B`, and `R` |
| Username mismatch rejected | `VerifyOnServer` checks `server_record.username == username` |
| Split-knowledge | Offline attack requires simultaneous device + server breach |

---

## Current Status

**Done**
- Phase 1 (Registration) + Phase 2 (Authentication) fully implemented — Protocol V2
- Server nonce R integrated into registration and authentication flows
- Real RSA-OAEP encryption/decryption (no mock)
- Client/server boundary split into distinct functions
- RAII for all OpenSSL contexts
- Constant-time comparison, secure memory erasure
- 3-arg `RegisterUser` convenience overload for test use

**Remaining**
- Persistent storage (currently in-memory `unordered_map`)
- Actual network separation between client and server
- Password change / re-registration flow
- Multi-user concurrency

---

## Install Prerequisites

### Prerequisites
- CMake >= 3.20
- C++17 Compiler
- Git

### Setup
Vcpkg [clone] get package manager. Run bootstrap.

```bash
git clone https://github.com/microsoft/vcpkg.git ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh
export VCPKG_ROOT=~/vcpkg
```

## Building

```bash
git clone https://github.com/s-uryansh/Auth
cd Auth

cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

---

```bash
ctest --test-dir build --output-on-failure
# or verbose:
./build/AuthTests
```

The test suite runs 1000+ parameterized cases across 23 sections and prints a performance report on completion:

```text
══════════════════════════════════════════
  Auth Protocol Performance Report
══════════════════════════════════════════
── Registration  (Protocol 1) ──────────
── Authentication (Protocol 2) ─────────
══════════════════════════════════════════
```

A CSV of all latency samples is written to `/tmp/auth_perf.csv` for external analysis.

| Section | What it covers |
|---------|---------------|
| Registration structural | Username in payload, salt size, E/ED non-empty, RSA ciphertext size |
| Password wiping | `OPENSSL_cleanse` after registration and authentication |
| Salt uniqueness | Fresh `RAND_bytes` per registration, same-user re-registration |
| Correct password succeeds | 50 passwords × round-trip + repeat |
| Wrong password fails | 50 pairs, no information leak |
| Empty / boundary passwords | Empty, single-byte correct and wrong |
| Client hash determinism | Same `S+P` → same `C`; different salt → different `C` |
| Hash differs for different passwords | `H(S,P1) != H(S,P2)`; output is 32 bytes |
| Server username validation | Wrong username rejected, correct accepted |
| Password wipe after auth | Zeroed on success and failure |
| Multi-user isolation | Cross-user auth fails; independent auth succeeds |
| Cross-payload attacks | Correct hash against wrong payload fails; swapped salt fails |
| Password length spectrum | 1–512 bytes, odd/even lengths, off-by-one |
| All-byte-value passwords | Single-byte 0x01–0x32 round-trips |
| Stress — rapid sequential | 5×, 20× correct; wrong-then-correct; alternating |
| Concurrent registration+auth | 4-thread races, mixed correct/wrong |
| Crypto properties | E ≠ ED; OAEP probabilistic (two regs → different E) |
| No-throw guarantee | Registration and wrong-password auth never throw |
| Special character passwords | Control bytes, null-embedded, punctuation |
| Case sensitivity | 20 correct/wrong case pairs |
| Tampered salt | Bit-flip and zeroed salt both fail |
| VerifyOnServer direct | Correct hash verifies; wrong hash does not |
| Misc edge cases | Fixture-level assertions, random round-trips |

---

## Running

```bash
./build/AuthApp
```

```text
[Registration] OK
  ServerDB stores: {U, R, E=Enc(PKs,B⊕R), ED=Enc(PKs,D)}
  UserDB   stores: {S}

[Auth valid]   PASS
[Auth invalid] PASS (correctly rejected)
```

---

## VS Code IntelliSense

Install **CMake Tools** extension, then `Ctrl+Shift+P` → `CMake: Configure`. IntelliSense syncs from the build system via `.vscode/c_cpp_properties.json`. Ensure `VCPKG_ROOT` is set and `vcpkg install` has been run.