# Auth: Cryptographic Registration & Authentication Protocol

C++17 implementation of a two-phase password authentication protocol using ML-KEM-768 + AES-256-GCM hybrid encryption (FIPS 203) and HMAC-based verifiers. Research prototype based on the cryptographic primitives from Kelsey et al. TMPS (NIST/KU Leuven, 2019).

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
| `E` | Encrypted masked secret: `E = HybridEnc(PKs, B⊕R)` |
| `ED` | Encrypted verifier: `ED = HybridEnc(PKs, D)` |
| `PKs / SKs` | Server ML-KEM-768 public/private keypair |

---

### Phase 1 — Registration

```text
User Device                                         Server
----------------------------------------------------------
Input: U                  ── U ─────────────────────────>

                                    Generate:
                          <── R ──  R <- RAND_bytes 128-bit nonce

Generate:
  S  <- RAND_bytes 128-bit salt
  B  <- RAND_bytes 128-bit secret

Compute:
  E  <- HybridEnc(PKs, B⊕R)   # ML-KEM-768 + AES-256-GCM (FIPS 203)
  C  <- SHA-256(S || P)
  D  <- HMAC-SHA256_B(C)
  ED <- HybridEnc(PKs, D)      # ML-KEM-768 + AES-256-GCM (FIPS 203)

Store locally:
  UserDB[U] <- S

Wipe: P, B, C, D, B⊕R    # OPENSSL_cleanse

Transmit: {U, E, ED} ─────────────────────────────> ServerDB[U] <- {U, R, E, ED}
```

### Phase 2 — Authentication

```text
User Device                                         Server
----------------------------------------------------------
Input: U, P

Retrieve: S <- UserDB[U]

Compute:
  C <- SHA-256(S || P)

Wipe: P                    # OPENSSL_cleanse

Transmit: {U, C} ─────────────────────────────────>

                                    Retrieve: {R, E, ED} <- ServerDB[U]

                                    Compute:
                                      B⊕R <- HybridDec(SKs, E)
                                      B   <- (B⊕R) ⊕ R
                                      D   <- HybridDec(SKs, ED)
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
| Encrypted value | `E = Enc(PKs, B)` | `E = HybridEnc(PKs, B⊕R)` |
| Server stores | `{U, E, ED}` | `{U, R, E, ED}` |
| Auth decryption | `B ← Dec(SKs, E)` | `B⊕R ← HybridDec(SKs, E)` then `B = (B⊕R) ⊕ R` |
| Device compromise | B recoverable from E alone | B unrecoverable without R |
| Offline dict attack | Possible with device+server breach | Requires simultaneous device+server breach |

**Security rationale:** In V1, an attacker who obtains `E` (server DB) and `S` (device DB) can mount an offline dictionary attack — decrypt `E` to get `B`, then brute-force `P` by computing `HMAC_B(H(S, P'))` for each candidate. In V2, decrypting `E` yields only `B⊕R`. Without `R`, which never leaves the server, `B` cannot be recovered. Split-knowledge is now enforced cryptographically: both the device and the server must be compromised simultaneously.

---

## Project Structure

```text
Auth/
├── include/auth/
│   ├── Authentication.hpp
│   ├── Registration.hpp
│   ├── crypto_utils.hpp
│   ├── kem_utils.hpp
│   ├── server_keys.hpp
│   └── vault.hpp          # Argon2id key derivation and AES-256-GCM vault functions
├── src/
│   ├── Authentication.cpp
│   ├── Registration.cpp
│   ├── main.cpp           # Console protocol demonstration
│   └── vault.cpp
├── ui/
│   ├── AuthTab.*
│   ├── MainWindow.*
│   ├── PasswordManagerTab.*
│   ├── PasswordVaultFileStore.*
│   └── QRSyncTab.*
├── android/               # Qt Android package manifest
├── triplets/              # x64-linux and arm64-android vcpkg triplets
├── tests/
│   ├── README.md
│   └── test_auth.cpp
├── CMakeLists.txt
├── Makefile
└── vcpkg.json             # OpenSSL, liboqs, Argon2; GTest for host builds
```

---

## Implementation Details

### `server_keys.hpp`
ML-KEM-768 keypair generated once via `liboqs`, stored in a static singleton `GetServerKeys()`. In production, load from HSM or persistent secure storage instead.

### `kem_utils.hpp`
Implements the hybrid KEM/DEM scheme used for all asymmetric encryption operations:

- **`MlKemEncrypt(plaintext)`** — ML-KEM-768 encapsulation produces a shared secret; AES-256-GCM encrypts the plaintext under that shared secret. Returns the concatenated KEM ciphertext + GCM ciphertext + GCM tag.
- **`MlKemDecrypt(ciphertext)`** — ML-KEM-768 decapsulation recovers the shared secret; AES-256-GCM decrypts and authenticates the payload.
- **`XorBytes(a, b, out)`** — constant-length XOR for `B⊕R` masking and recovery.

Conforms to FIPS 203 (ML-KEM) and provides post-quantum security against harvest-now/decrypt-later attacks.

### `Registration.cpp`
Protocol 1 (V2): server generates `R` before registration begins; user generates `S`, `B` via `RAND_bytes`; computes `B⊕R`, then `C = SHA-256(S||P)` and `D = HMAC-SHA256_B(C)`; encrypts `B⊕R→E` and `D→ED` via ML-KEM-768 + AES-256-GCM; stores `S` locally; wipes `P`, `B`, `B⊕R`, `C`, `D` via `OPENSSL_cleanse`. Server stores `{U, R, E, ED}`.

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
| `VerifyOnServer()` | Server | Validates username, decrypts `E→B⊕R` via `MlKemDecrypt`, recovers `B=(B⊕R)⊕R`, decrypts `ED→D`, recomputes `D'`, constant-time compare, wipes all intermediates |
| `AuthenticateUser()` | Wrapper | `ComputeClientHash` + `VerifyOnServer` |

---

## Security Properties

| Property | How |
|----------|-----|
| Password never transmitted | Only `C = H(S,P)` crosses wire |
| Password never stored server-side | Server holds only `{R, E, ED}` |
| Device compromise does not expose B | B unrecoverable from E without server-held R |
| Post-quantum asymmetric encryption | ML-KEM-768 + AES-256-GCM hybrid (FIPS 203) |
| Timing-safe comparison | `CRYPTO_memcmp` |
| Memory wiped after use | `OPENSSL_cleanse` on all intermediates |
| CSPRNG | `RAND_bytes` for `S`, `B`, and `R` |
| Username mismatch rejected | `VerifyOnServer` checks `server_record.username == username` |
| Split-knowledge | Offline attack requires simultaneous device + server breach |

---

## Current Status

The cryptographic registration and authentication protocol is implemented, and the Qt desktop application now includes Auth gating and a persistent Password Manager vault. Auth records remain in memory for the current application run; the application does not yet separate client and server over a real network.

### Authentication and feature access

- Registration rejects a username already registered in the current run.
- Registration passwords require at least eight Unicode characters, one ASCII uppercase letter, one ASCII lowercase letter, one digit, and one ASCII punctuation character.
- Password Manager and QR Sync stay hidden until a successful login. Registering alone does not reveal them.
- QR Sync source and behavior were not changed as part of this work.

### Password Manager

- The first visit asks the user to set a master password. After setup, the app shows the credential-add workflow.
- Credentials contain the entered website URL, username, and password. The vault is encrypted with the existing Argon2id and AES-256-GCM implementation and stored in the app-specific data directory as `password-vault.dat`.
- Website URLs are kept in a plaintext index so the site list remains searchable while locked. Usernames and passwords are encrypted.
- The first reveal in a session asks for the master password. Revealed credentials remain available for ten minutes from that first successful unlock; activity does not extend the session.
- Username and password have separate copy actions. The website action opens valid HTTP(S) URLs through the system handler. Clipboard contents are not cleared automatically.
- The vault is device-local and is not partitioned by Auth username. Auth accounts and records are still in-memory only.

### Android

The Qt Widgets application builds as an arm64-v8a debug APK. The Android minimum and target SDK versions are 30; this environment uses compile SDK 37. The package identifier is `org.tmps.auth`. The default Makefile build directory is `build_android_arm64`.

## Prerequisites

For a desktop build:

- CMake 3.20 or newer
- C++17 compiler
- vcpkg with the project manifest dependencies
- Qt 6 Widgets/Core/Gui for the desktop UI

For Android, also install a Qt 6.12 Android arm64 kit and matching Qt host kit, Android SDK/build tools, Android NDK, and Gradle. The example command below uses the paths installed in this development environment; override them for your machine.

## Build and run

Configure and build the desktop Qt app:

```bash
cmake -B build -S . \
  -DCMAKE_TOOLCHAIN_FILE="$HOME/vcpkg/scripts/buildsystems/vcpkg.cmake" \
  -DVCPKG_TARGET_TRIPLET=x64-linux
cmake --build build --target AuthQt -j2
```

Build all desktop targets with `make build`. Run the GUI with `make ui`, the console demonstration with `make demo`, and the existing GTest suite with `make test` or `ctest --test-dir build --output-on-failure`.

The test suite covers the protocol library; it does not currently exercise the Qt Auth or Password Manager flows.

## Build the Android APK

The Make target configures the arm64-v8a vcpkg triplet, builds OpenSSL, liboqs, and Argon2 for Android, then invokes Qt's APK packaging target:

```bash
make android \
  ANDROID_NDK=/opt/android-ndk/android-ndk-r30 \
  ANDROID_SDK_ROOT="$HOME/Android/Sdk" \
  QT_ANDROID_PREFIX=/home/s-uryansh/Qt/6.12.0/android_arm64_v8a \
  QT_HOST_PREFIX=/home/s-uryansh/Qt/6.12.0/gcc_64
```

`ANDROID_NDK` and `ANDROID_SDK_ROOT` are required. `QT_ANDROID_PREFIX` defaults to `/home/s-uryansh/Qt/6.12.0/android_arm64_v8a`, and `QT_HOST_PREFIX` defaults to `/home/s-uryansh/Qt/6.12.0/gcc_64`; override both when Qt is installed elsewhere. `VCPKG_ROOT` can also be supplied if vcpkg is not at `~/vcpkg`. Set `ANDROID_BUILD_DIR` to use a different build directory.

The debug APK is written to:

```text
build_android_arm64/android-build/build/outputs/apk/debug/android-build-debug.apk
```

This target builds a debug APK for local installation. A production release requires release signing configuration.

## Further documentation

- [Design spec](docs/superpowers/specs/2026-10-19-auth-password-manager-android-design.md)
- [Auth registration and feature gating plan](docs/superpowers/plans/2026-10-19-auth-registration-gating.md)
- [Password Manager vault plan](docs/superpowers/plans/2026-10-19-password-manager-vault.md)
- [Android APK plan](docs/superpowers/plans/2026-10-19-android-apk.md)
