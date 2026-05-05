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
| `C` | Password hash: `C = H(S, P)` |
| `D` | HMAC verifier: `D = HMAC_B(C)` |
| `E` | Encrypted secret: `E = Enc(PKs, B)` |
| `ED` | Encrypted verifier: `ED = Enc(PKs, D)` |
| `PKs / SKs` | Server RSA-2048 public/private keypair |

---

### Phase 1 — Registration

```text
User Device                                         Server
───────────────────────────────────────────────────────────
Input: U, P

Generate:
  S  <- RAND_bytes 128-bit salt
  B  <- RAND_bytes 128-bit secret

Compute:
  E  <- Enc(PKs, B)        # RSA-OAEP SHA-256
  C  <- SHA-256(S || P)
  D  <- HMAC-SHA256_B(C)
  ED <- Enc(PKs, D)        # RSA-OAEP SHA-256

Store locally:
  UserDB[U] <- S

Wipe: P, B, C, D           # OPENSSL_cleanse

Transmit: {U, E, ED} ─────────────────────────────> ServerDB[U] <- {U, E, ED}
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

                                    Retrieve: {E, ED} <- ServerDB[U]

                                    Compute:
                                      B  <- Dec(SKs, E)
                                      D  <- Dec(SKs, ED)
                                      D' <- HMAC-SHA256_B(C)

                                    Verify:
                                      D == D'  ->  SUCCESS  (CRYPTO_memcmp)
                                      D != D'  ->  FAIL
```

Server never receives `P`. Wrong password → wrong `C` → wrong `D'` → no match.

---

## Project Structure

```text
Auth/
├── include/auth/
│   ├── crypto_utils.hpp   # RAII wrappers: EvpMdCtxPtr, EvpPkeyPtr, EvpPkeyCtxPtr
│   ├── server_keys.hpp    # RSA-2048 keypair singleton (GetServerKeys())
│   ├── Registration.hpp   # RegisterUser()
│   └── Authentication.hpp # ComputeClientHash(), VerifyOnServer(), AuthenticateUser()
├── src/
│   ├── Registration.cpp   # Protocol 1 implementation
│   ├── Authentication.cpp # Protocol 2 implementation
│   └── main.cpp           # Demo: register + valid auth + invalid auth
├── tests/
│   └── test_auth.cpp      # GTest suite (14 tests)
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
Protocol 1: generates `S`, `B` via `RAND_bytes`; computes `C = SHA-256(S||P)` and `D = HMAC-SHA256_B(C)`; encrypts `B→E` and `D→ED` via RSA-OAEP SHA-256; stores `S` locally; wipes `P`, `B`, `C`, `D` via `OPENSSL_cleanse`.

### `Authentication.cpp`
Three functions with explicit client/server boundary:

| Function | Boundary | What it does |
|----------|----------|-------------|
| `ComputeClientHash()` | Client | `C = SHA-256(S\|\|P)`, wipes `P` |
| `VerifyOnServer()` | Server | Validates username, decrypts `E→B`/`ED→D`, recomputes `D'`, constant-time compare |
| `AuthenticateUser()` | Wrapper | `ComputeClientHash` + `VerifyOnServer` |

---

## Security Properties

| Property | How |
|----------|-----|
| Password never transmitted | Only `C = H(S,P)` crosses wire |
| Password never stored server-side | Server holds only `{E, ED}` |
| Asymmetric encryption | RSA-2048 OAEP SHA-256 (`EVP_PKEY_encrypt/decrypt`) |
| Timing-safe comparison | `CRYPTO_memcmp` |
| Memory wiped after use | `OPENSSL_cleanse` on all intermediates, using `kHashSize` constant |
| CSPRNG | `RAND_bytes` for `S` and `B` |
| Username mismatch rejected | `VerifyOnServer` checks `server_record.username == username` |
| Offline dict attack blocked | `S` is device-local; attacker cannot recompute `C` without it |

---

## Current Status

**Done**
- Phase 1 (Registration) + Phase 2 (Authentication) fully implemented
- Real RSA-OAEP encryption/decryption (no mock)
- Client/server boundary split into distinct functions
- RAII for all OpenSSL contexts
- Constant-time comparison, secure memory erasure

**Remaining**
- Persistent storage (currently in-memory `unordered_map`)
- Actual network separation between client and server
- Password change / re-registration flow
- Multi-user concurrency

---

## Building

**Prerequisites:** CMake ≥ 3.20, vcpkg (`VCPKG_ROOT` set), GCC ≥ 9 / Clang ≥ 10, OpenSSL via vcpkg.

```bash
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake
cmake --build build
```

---

## Testing

```bash
ctest --test-dir build --output-on-failure
# or verbose:
./build/AuthTests
```

| Test | Checks |
|------|--------|
| `PayloadUsernameCorrect` | `payload.username` matches input |
| `PayloadEncryptedFieldsNonEmpty` | `E` and `ED` non-empty after registration |
| `SaltStoredLocally_128bit` | `UserDB` salt = 16 bytes |
| `PasswordWipedAfterRegistration` | Password vector zeroed |
| `TwoRegistrationsSaltsDiffer` | Fresh `RAND_bytes` per registration |
| `CorrectPasswordSucceeds` | Full auth returns `true` |
| `WrongPasswordFails` | Wrong password returns `false` |
| `EmptyPasswordFails` | Empty password returns `false` |
| `PasswordWipedAfterAuth` | Password vector zeroed after auth |
| `MultipleCorrectAuthsSucceed` | Repeated valid auths all pass |
| `ClientHashDeterministic` | Same `S+P` → same `C` |
| `ClientHashDiffersForDiffPasswords` | `H(S,P1) != H(S,P2)` |
| `ServerRejectsWrongUsername` | `VerifyOnServer` rejects username mismatch |
| `ServerVerifyCorrectHashSucceeds` | `VerifyOnServer` passes with valid `C` |

---

## Running

```bash
./build/AuthApp
```

```text
[Registration] OK
[Auth valid]   PASS
[Auth invalid] PASS (correctly rejected)
```

---

## VS Code IntelliSense

Install **CMake Tools** extension, then `Ctrl+Shift+P` → `CMake: Configure`. IntelliSense syncs from the build system via `.vscode/c_cpp_properties.json`. Ensure `VCPKG_ROOT` is set and `vcpkg install` has been run.