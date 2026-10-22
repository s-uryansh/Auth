# Vault Salt, Protocol 1/2, and Authenticated Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Each task also names its required focused skill. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist and use a distinct per-website Protocol 1/2 salt, authenticate every credential reveal through the in-process demo records, and authenticate vault metadata with AES-256-GCM while migrating v1 vaults safely.

**Architecture:** Add a source-compatible caller-supplied salt path to the Auth registration API and a small in-process website-credential protocol store in `AuthLib`. Extend vault encryption with authenticated additional data, then make the Qt file store version-aware so v1 remains readable and v2 binds its metadata to its ciphertext. Integrate add, unlock, reveal, and migration in `PasswordManagerTab`; stage protocol records before disk writes and publish them only after the atomic vault save succeeds.

**Tech Stack:** C++17, OpenSSL AES-256-GCM, existing ML-KEM Auth Protocol 1/2 APIs, Argon2id, Qt 6 Core/Widgets, GoogleTest.

**Spec:** `docs/superpowers/specs/2026-10-22-vault-salt-protocol-authenticated-header-design.md`

## Global Constraints

- Use 16-byte per-website Protocol 1 salts, stored only inside encrypted `VaultEntry::salt`.
- Keep the master vault salt separate from per-website salts.
- Keep Argon2id at 64 MiB, 3 iterations, parallelism 4, and 32-byte output.
- Keep user-entered credential passwords; add no password generator.
- Keep the plaintext ordered website index searchable while locked and authenticate it as AAD.
- Keep Auth account state and website Protocol 1/2 demo records in process memory; they reset on app exit.
- Read v1 vaults, migrate only after successful decryption, and atomically save the new version.
- Keep Protocol 2 failure, missing records, invalid salts, wrong master passwords, corrupt metadata, and failed writes fail-closed.
- Do not modify QR Sync source or behavior.
- Do not create a git commit or push.

## Review Focus

- A supplied salt with any length other than 16 bytes must be rejected without changing registration state; pin this in Task 1.
- The same username on different normalized websites must produce distinct protocol identities, while a duplicate website/username pair must not overwrite; pin this in Task 2.
- Wrong passwords, a missing registration record, and a record for a different identity must not authenticate or reveal credentials; pin this in Tasks 2 and 5.
- Changes to version, KDF parameters, master salt, ordered website index, or nonce must fail GCM authentication before entries are returned; pin these in Tasks 3 and 4.
- A wrong master password or failed v1 migration write must leave the original v1 file byte-for-byte unchanged; pin this in Tasks 4 and 5.

---

### Task 1: Support caller-supplied Protocol 1 salts

**Required Superpowers skill:** `superpowers:test-driven-development`

**Files:**
- Modify: `include/auth/Registration.hpp`
- Modify: `src/Registration.cpp`
- Test: `tests/test_auth.cpp`

**Interfaces:**
- Consumes: existing `RegistrationPayload`, `RegisterUser`, and local salt map API.
- Produces: additive `RegisterUser(username, password, server_r, salt_s, local_db)` and `RegisterUserWithSalt(username, password, salt_s, local_db)` APIs accepting a 16-byte salt `S`; existing overloads continue generating `S` internally and remain source-compatible. The distinct `RegisterUserWithSalt` name is necessary because its parameter types would otherwise collide with the existing explicit-server-nonce overload.

- [x] **Step 1: Add failing API tests**

In `tests/test_auth.cpp`, add tests for both new APIs: register with an explicit server nonce and salt, and register with a supplied salt plus internally-generated server nonce. Assert the local salt map contains the exact supplied bytes and Protocol 2 authenticates. Add a test that rejects salts whose length is not 16 bytes without modifying the local map. Confirm an existing internally-generated-salt registration test still covers the original overload.

- [x] **Step 2: Run the focused test and confirm the new API tests fail**

Run: `cmake --build build --target AuthTests -j2 && ASAN_OPTIONS=detect_leaks=0 ./build/AuthTests --gtest_filter='RegistrationInputTest.*'`

Expected: compilation or assertions fail because the explicit-salt overload is not implemented.

- [x] **Step 3: Implement the additive overloads**

Add `RegisterUserWithSalt` for an internally-generated server nonce and an explicit-server-nonce overload that also accepts `salt_s`. Route all forms through one registration core. Validate `salt_s.size() == 16` before crypto work; preserve password wiping and the existing registration payload format. Existing overloads continue generating a random salt and call the shared core.

- [x] **Step 4: Run the focused tests**

Run: `cmake --build build --target AuthTests -j2 && ASAN_OPTIONS=detect_leaks=0 ./build/AuthTests --gtest_filter='RegistrationInputTest.*'`

Expected: both explicit-salt API forms preserve `S` and support Protocol 2; invalid salt length throws without writing the local map; existing registration tests pass.

---

### Task 2: Add an in-process website credential protocol store

**Required Superpowers skill:** `superpowers:test-driven-development`

**Files:**
- Create: `include/auth/WebsiteCredentialAuth.hpp`
- Create: `src/WebsiteCredentialAuth.cpp`
- Modify: `CMakeLists.txt` (`AuthLib` source list)
- Test: `tests/test_auth.cpp`

**Interfaces:**
- Consumes: Task 1's explicit-salt registration APIs and existing `AuthenticateUser`.
- Produces these exact interfaces:
  - `static std::string identity(const std::string& website, const std::string& username)`
  - `RegistrationPayload prepareRegistration(const std::string& website, const std::string& username, std::vector<uint8_t>& password, const std::vector<uint8_t>& salt) const`
  - `void commitRegistration(const RegistrationPayload& record)`
  - `void commitRegistrations(const std::vector<RegistrationPayload>& records)`
  - `bool authenticate(const std::string& website, const std::string& username, std::vector<uint8_t>& password, const std::vector<uint8_t>& salt) const`
  - `void clear()`
- `identity` uses a deterministic, unambiguous length-prefixed encoding of the already normalized website URL and username. `prepareRegistration` creates a `RegistrationPayload` without changing the active record map. `commitRegistration` rejects a duplicate identity. `commitRegistrations` validates the whole batch for existing and intra-batch duplicates before inserting any record. `authenticate` looks up the exact identity and returns false if absent.

- [x] **Step 1: Add failing protocol-store tests**

Test identity separation for the same username on two sites; identity stability; duplicate record rejection; successful registration and Protocol 2 authentication; wrong-password failure; missing-record failure; and record/identity mismatch failure. Assert the store has no record until `commitRegistration` is called.

- [x] **Step 2: Run the focused tests and confirm they fail**

Run: `cmake --build build --target AuthTests -j2 && env ASAN_OPTIONS=detect_leaks=0 ./build/AuthTests --gtest_filter='WebsiteCredentialAuthStoreTest.*'`

Expected: compilation fails until the store exists.

- [x] **Step 3: Implement the store and add it to `AuthLib`**

Implement canonical identity encoding and a record map keyed by the encoded identity. `prepareRegistration` calls `RegisterUserWithSalt` with the supplied 16-byte salt and a temporary local salt map, verifies the resulting identity, and returns the payload. `commitRegistration` inserts without replacing. `authenticate` passes a temporary password copy to `AuthenticateUser`, since that API wipes its password argument. `clear()` removes current-run demo records.

- [x] **Step 4: Run the focused tests**

Run: `cmake --build build --target AuthTests -j2 && env ASAN_OPTIONS=detect_leaks=0 ./build/AuthTests --gtest_filter='WebsiteCredentialAuthStoreTest.*'`

Expected: each identity, duplicate, registration, and authentication case passes; all temporary password copies are wiped after use.

---

### Task 3: Bind AES-GCM vault encryption to supplied metadata AAD

**Required Superpowers skill:** `superpowers:test-driven-development`

**Files:**
- Modify: `include/auth/vault.hpp`
- Modify: `src/vault.cpp`
- Test: `tests/test_vault_storage.cpp`

**Interfaces:**
- Consumes: existing `EncryptVault(key, entries)` and `DecryptVault(key, ciphertext)`.
- Produces: `std::vector<uint8_t> EncryptVault(const std::vector<uint8_t>& key, const std::vector<VaultEntry>& entries, const std::vector<uint8_t>& aad)` and `std::vector<VaultEntry> DecryptVault(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& aad)`. Preserve the existing two-argument overloads for callers and v1 ciphertext, using empty AAD.
- The AAD argument is the canonical metadata prefix; the crypto layer appends the exact generated/extracted GCM nonce bytes to that prefix for both encryption and decryption.

- [x] **Step 1: Add failing AAD crypto tests**

Add a round-trip test using non-empty AAD, a test that changing AAD causes `DecryptVault` to throw without returning entries, and a test that existing no-AAD round trips remain valid. Include malformed ciphertext/nonce rejection coverage.

- [x] **Step 2: Run the focused tests and confirm the new overload tests fail**

Run: `cmake --build build --target VaultStorageTests -j2 && ./build/VaultStorageTests --gtest_filter='VaultCryptoTest.*AAD*'`

Expected: compilation fails until the AAD overloads exist.

- [x] **Step 3: Implement GCM AAD handling**

Refactor the encryption/decryption internals to accept AAD bytes. After generating the nonce during encryption, authenticate `aad || nonce`; during decryption, parse the nonce from the existing `IV || tag || ciphertext` blob and authenticate the same `aad || nonce` bytes before releasing plaintext. Keep existing nonce/tag layout and make legacy overloads delegate with empty AAD.

- [x] **Step 4: Run vault crypto tests**

Run: `cmake --build build --target VaultStorageTests -j2 && ./build/VaultStorageTests --gtest_filter='VaultCryptoTest.*'`

Expected: matching AAD round-trips, changed AAD and tampered ciphertext fail, and old no-AAD tests pass.

---

### Task 4: Add vault file v2 metadata authentication and v1 compatibility

**Required Superpowers skill:** `superpowers:test-driven-development`

**Files:**
- Modify: `ui/PasswordVaultFileStore.h`
- Modify: `ui/PasswordVaultFileStore.cpp`
- Test: `tests/test_vault_storage.cpp`

**Interfaces:**
- Consumes: Task 3's AAD-aware vault encryption/decryption overloads.
- Produces: a `quint16 format_version` field on `PasswordVaultFile`; `std::vector<uint8_t> authenticatedData(const PasswordVaultFile& vault) const`; `load()` accepts v1 and current v2; `save()` writes only v2. `authenticatedData` returns empty bytes for v1 and deterministically encodes format version, Argon2 parameters, master salt, and ordered website URLs for v2 using fixed-width big-endian integers and length-prefixed byte strings.

- [x] **Step 1: Add failing format and tamper tests**

Test that save/load writes and returns v2; load a handcrafted v1 fixture; reject unsupported versions and malformed fields; and confirm changing each AAD field (version, each KDF parameter, master salt, website count/order/content) makes decryption fail. Confirm modifying the nonce also fails authentication.

- [x] **Step 2: Run the focused file-store tests and confirm v2 tests fail**

Run: `cmake --build build --target VaultStorageTests -j2 && ./build/VaultStorageTests --gtest_filter='PasswordVaultFileStoreTest.*'`

Expected: current store rejects v1/v2 expectations or does not provide authenticated metadata bytes.

- [x] **Step 3: Implement versioned metadata parsing and canonical AAD encoding**

Set the current format to v2 and preserve the existing v1 field layout for reads. Encode AAD independently of QDataStream using fixed-width big-endian numeric values, length-prefixed salt bytes, website count, and each URL's UTF-8 bytes with a length prefix. Do not encode nonce here; Task 3 appends the exact GCM nonce. `save()` validates and writes v2 only; `load()` records the decoded version and keeps current bounds checks.

- [x] **Step 4: Run file-store and metadata tamper tests**

Run: `cmake --build build --target VaultStorageTests -j2 && ./build/VaultStorageTests --gtest_filter='PasswordVaultFileStoreTest.*'`

Expected: v1 fixture loads as legacy; v2 round-trips; all metadata mutations fail GCM authentication; malformed/unsupported files are rejected.

---

### Task 5: Integrate Protocol 1/2, salt persistence, and v1 migration in Password Manager

**Required Superpowers skill:** `superpowers:test-driven-development`

**Files:**
- Modify: `ui/PasswordManagerTab.h`
- Modify: `ui/PasswordManagerTab.cpp`
- Modify: `ui/PasswordVaultFileStore.h` (introduce storage interface)
- Create: `ui/PasswordVaultWorkflow.h`
- Create: `ui/PasswordVaultWorkflow.cpp`
- Create: `tests/test_password_manager_workflow.cpp`
- Modify: `CMakeLists.txt` (add workflow source to `AuthQt` and a `PasswordManagerWorkflowTests` executable/CTest entry)

**Interfaces:**
- Consumes: Task 2's `WebsiteCredentialAuthStore`; Task 3's AAD-aware vault APIs; Task 4's v1/v2 `PasswordVaultFile` and metadata-AAD encoder.
- Produces a `PasswordVaultStorage` interface with virtual `PasswordVaultFile load() const`, `void save(const PasswordVaultFile& vault) const`, `std::vector<uint8_t> authenticatedData(const PasswordVaultFile& vault) const`, and a virtual destructor; `PasswordVaultFileStore` implements it. The metadata-AAD method is needed by the workflow to encrypt files through either the real or test storage implementation. It also produces a testable `PasswordVaultWorkflow` service with constructor `PasswordVaultWorkflow(PasswordVaultStorage&, auth::WebsiteCredentialAuthStore&)`, `std::vector<auth::VaultEntry> unlockAndMigrate(const std::vector<uint8_t>& key)`, `void saveNewCredential(const std::vector<uint8_t>& key, const QString& website, const std::string& username, const std::vector<uint8_t>& password)`, and `bool authenticate(const auth::VaultEntry& entry)`. The workflow stages registration records until the file save succeeds, rebuilds current-run records after unlock, and migrates v1 entries only after successful decryption. `PasswordManagerTab` delegates add/unlock/reveal protocol and storage operations to this service.

- [x] **Step 1: Add failing workflow tests**

Add test coverage for: adding a new credential assigns and encrypts a 16-byte per-site salt; the same username on two different websites succeeds; duplicate website/username is rejected without overwriting; every entry authentication required before reveal/copy succeeds only with a matching Protocol 2 record; wrong/missing/mismatched records fail; unlock rebuilds records without changing v2 vault bytes; valid v1 unlock creates salts for entries missing them and saves v2; wrong master password and a fake storage implementation that rejects save leave the original v1 file byte-for-byte unchanged. Keep the UI thin and testable by having it call the workflow service's `authenticate` result before creating credential labels or copy actions.

- [x] **Step 2: Run the focused workflow tests and confirm they fail**

Run: `cmake --build build --target PasswordManagerWorkflowTests -j2 && ./build/PasswordManagerWorkflowTests`

Expected: tests fail because Password Manager currently does not assign per-site salts, call Protocol 1/2, or migrate v1 vaults.

- [x] **Step 3: Integrate the add-credential transaction**

Generate the 16-byte protocol salt, derive the canonical website identity from the already normalized URL, prepare a Protocol 1 record using a temporary password copy, and store the salt in `VaultEntry::salt`. Encrypt with current metadata AAD, append the website URL to the plaintext index only if absent while preserving existing order, and atomically save. Commit the prepared record into the in-process store only after `save()` succeeds. Reject duplicate website/username identities before changing either the file or record store.

- [x] **Step 4: Integrate unlock, legacy migration, and record reconstruction**

On unlock, use empty AAD for v1 ciphertext and current canonical AAD for v2 ciphertext. Return no entries until decryption/authentication fully succeeds. For v1, assign salts only to entries with empty `salt`, prepare records for all entries, encrypt with v2 metadata AAD, and atomically save before replacing the loaded state or committing records. For v2, rebuild records from stored salts and entries in memory without rewriting the file. If preparing any record fails, expose no credentials; if v1 save fails, retain the original file and locked state.

- [x] **Step 5: Require Protocol 2 before exposing a selected entry**

Before rendering username/password labels or connecting copy actions, verify each selected entry with its canonical identity, stored salt, and matching demo record. Pass only a temporary password copy to Protocol 2. On failure, clear the selected credential cards and show a status; do not reveal or copy its secrets. Keep the existing master-password gate and ten-minute session behavior.

- [x] **Step 6: Run workflow, storage, and auth tests**

Run: `cmake --build build --target AuthTests VaultStorageTests PasswordManagerWorkflowTests AuthQt -j2`

Then run: `env ASAN_OPTIONS=detect_leaks=0 ctest --test-dir build --output-on-failure`

Expected: all three test executables pass and `AuthQt` compiles with the updated flow. The workflow tests cover vault and protocol outcomes; inspect the widget flow to confirm it calls `authenticate` before creating credential labels or copy actions.

---

### Task 6: Final verification and scope review

**Required Superpowers skill:** `superpowers:verification-before-completion`

**Files:**
- Review: `include/auth/Registration.hpp`, `src/Registration.cpp`, `include/auth/WebsiteCredentialAuth.hpp`, `src/WebsiteCredentialAuth.cpp`, `include/auth/vault.hpp`, `src/vault.cpp`, `ui/PasswordVaultFileStore.h`, `ui/PasswordVaultFileStore.cpp`, `ui/PasswordVaultWorkflow.h`, `ui/PasswordVaultWorkflow.cpp`, and `ui/PasswordManagerTab.cpp`

- [x] **Step 1: Run the full configured test suite**

Run: `env ASAN_OPTIONS=detect_leaks=0 ctest --test-dir build --output-on-failure`

Expected: all configured tests pass.

- [x] **Step 2: Build the desktop application target**

Run: `cmake --build build --target AuthQt -j2`

Expected: successful desktop link with no compiler warnings promoted to errors.

- [x] **Step 3: Review security and scope invariants**

Confirm no master password or plaintext per-site salt is serialized; no entry is returned before GCM authentication; Protocol 2 is required before display/copy; both registration and authentication temporary password buffers are wiped; atomic save failure preserves the prior file; Argon2id constants are unchanged; `git diff -- ui/QRSyncTab.cpp ui/QRSyncTab.h` is empty.

- [x] **Step 4: Report only observed verification results**

Record the exact commands and outcomes. Do not claim Android builds, tests, or security properties that were not verified. Do not create a git commit or push.
